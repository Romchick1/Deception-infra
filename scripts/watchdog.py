#!/usr/bin/env python3
import datetime
import fcntl
import json
import os
import sqlite3
import subprocess
import time
from pathlib import Path
from health_probe import probe_services
from task_queue import TaskQueue
from security_runtime import dispatch

ROOT = Path(__file__).resolve().parents[1]
INTERVAL = 10
FAILURE_THRESHOLD = 3
COOLDOWN = 120
SENSORS = {"opencanary": "opencanary-01", "cowrie": "cowrie-01"}


def inspect_containers():
    result = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
        "decoy", 'docker container ls --all --format "{{json .}}"'],
        capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise RuntimeError(result.stderr.strip()[:500] or "Docker unavailable")
    items = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    return {item["Names"]: item["State"] for item in items}


def main():
    os.umask(0o077)
    runtime = ROOT / "runtime"
    runtime.mkdir(mode=0o700, exist_ok=True)
    with (runtime/"watchdog.lock").open("a") as instance_lock:
        try:
            fcntl.flock(instance_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit("Watchdog уже запущен")

        def log(event, **fields):
            record = dict(timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                          event=event, **fields)
            line = json.dumps(record, ensure_ascii=False)
            print(line, flush=True)
            with (runtime/"watchdog.jsonl").open("a") as stream:
                stream.write(line+"\n")

        db = sqlite3.connect(runtime/"watchdog.sqlite3", timeout=30)
        db.execute("""CREATE TABLE IF NOT EXISTS sensors (
            name TEXT PRIMARY KEY, failures INTEGER NOT NULL DEFAULT 0,
            last_attempt REAL NOT NULL DEFAULT 0)""")
        for sensor in SENSORS:
            db.execute("INSERT OR IGNORE INTO sensors(name) VALUES (?)", (sensor,))
        db.commit()
        queue = TaskQueue(db, ROOT, log)
        queue.reconcile()
        log("watchdog_started", execution_path="queue_only")

        while True:
            try:
                states = probe_services(inspect_containers(), log)
            except (OSError, RuntimeError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
                db.execute("UPDATE sensors SET failures=0")
                db.commit()
                log("inspection_unavailable", error=str(exc)[:500])
                time.sleep(INTERVAL)
                continue

            for sensor, container in SENSORS.items():
                state = states.get(container, "missing")
                failures, last_attempt = db.execute(
                    "SELECT failures,last_attempt FROM sensors WHERE name=?", (sensor,)).fetchone()
                if state not in {"exited", "dead", "missing", "unhealthy"}:
                    db.execute("UPDATE sensors SET failures=0 WHERE name=?", (sensor,))
                    db.commit()
                    if state != "running":
                        log("state_requires_review", sensor=sensor, state=state)
                    continue
                failures += 1
                db.execute("UPDATE sensors SET failures=? WHERE name=?", (failures, sensor))
                db.commit()
                log("failure_observed", sensor=sensor, state=state, count=failures)
                if failures < FAILURE_THRESHOLD:
                    continue
                remaining = COOLDOWN-(time.time()-last_attempt)
                if remaining > 0:
                    log("recovery_deferred", sensor=sensor, reason="cooldown",
                        remaining_seconds=int(remaining)+1)
                    continue
                queue.enqueue(sensor, state)

            try:
                dispatch(ROOT, queue, states, log)
            except (OSError, RuntimeError, ValueError, KeyError, subprocess.TimeoutExpired, sqlite3.Error) as exc:
                # A security-feed outage must not prevent availability recovery.
                log("security_feed_unavailable", error=str(exc)[:500])
            queue.run_next(states)
            time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
