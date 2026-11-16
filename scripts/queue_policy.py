import argparse
import datetime
import fcntl
import getpass
import json
import sqlite3
import time
from contextlib import ExitStack
from pathlib import Path

SENSORS = ("opencanary", "cowrie")
MAX_ATTEMPTS = 3
WINDOW = 1800


class QueuePolicy:
    def __init__(self, db, log):
        self.db, self.log = db, log

        db.execute("""
            CREATE TABLE IF NOT EXISTS sensor_controls (
                sensor TEXT PRIMARY KEY,
                paused INTEGER NOT NULL DEFAULT 0,
                reason TEXT NOT NULL DEFAULT '',
                budget_since REAL NOT NULL DEFAULT 0
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS policy_audit (
                id INTEGER PRIMARY KEY,
                timestamp REAL NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                reason TEXT NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS recovery_attempts (
                id TEXT PRIMARY KEY, task_id TEXT NOT NULL,
                sensor TEXT NOT NULL, started REAL NOT NULL,
                finished REAL, exit_code INTEGER
            )
        """)
        # Preserve the previous budget: one historical start per legacy task.
        db.execute("""
            INSERT OR IGNORE INTO recovery_attempts
              (id,task_id,sensor,started,finished,exit_code)
            SELECT 'legacy:' || t.id,t.id,t.sensor,t.started,t.finished,t.exit_code
            FROM recovery_tasks t
            WHERE t.started IS NOT NULL AND NOT EXISTS
              (SELECT 1 FROM recovery_attempts a WHERE a.task_id=t.id)
        """)
        for sensor in SENSORS:
            db.execute(
                "INSERT OR IGNORE INTO sensor_controls(sensor) VALUES (?)",
                (sensor,),
            )
        db.commit()

    def audit(self, actor, action, target, reason):
        self.db.execute("""
            INSERT INTO policy_audit
            (timestamp, actor, action, target, reason)
            VALUES (?, ?, ?, ?, ?)
        """, (time.time(), actor, action, target, reason))

    def pause(self, sensor, reason, actor="watchdog"):
        if sensor not in SENSORS:
            raise ValueError("Unknown sensor")

        with self.db:
            self.db.execute("""
                UPDATE sensor_controls SET paused=1, reason=?
                WHERE sensor=?
            """, (reason, sensor))
            self.audit(actor, "pause", sensor, reason)

        self.log("sensor_paused", sensor=sensor,
                 reason=reason, actor=actor)

    def allowed(self, sensor):
        paused, since = self.db.execute("""
            SELECT paused, budget_since
            FROM sensor_controls WHERE sensor=?
        """, (sensor,)).fetchone()

        if paused:
            return False

        interrupted = self.db.execute("""
            SELECT 1 FROM recovery_tasks
            WHERE sensor=? AND status='interrupted' LIMIT 1
        """, (sensor,)).fetchone()

        if interrupted:
            self.pause(sensor, "interrupted_task")
            return False

        count = self.db.execute("""
            SELECT COUNT(*) FROM recovery_attempts
            WHERE sensor=? AND started>=?
        """, (sensor, max(time.time() - WINDOW, since))).fetchone()[0]

        if count >= MAX_ATTEMPTS:
            self.pause(sensor, "attempt_limit")
            return False

        return True

    def resume(self, sensor, reason, actor):
        if sensor not in SENSORS:
            raise ValueError("Unknown sensor")

        active = self.db.execute("""
            SELECT id FROM recovery_tasks
            WHERE sensor=? AND status IN ('running','interrupted')
            LIMIT 1
        """, (sensor,)).fetchone()

        if active:
            raise ValueError(
                "Review the running/interrupted task first: " + active[0]
            )

        with self.db:
            self.db.execute("""
                UPDATE sensor_controls
                SET paused=0, reason='', budget_since=?
                WHERE sensor=?
            """, (time.time(), sensor))
            self.audit(actor, "resume", sensor, reason)

        self.log("sensor_resumed", sensor=sensor,
                 reason=reason, actor=actor)

    def resolve(self, task_id, reason, actor):
        row = self.db.execute("""
            SELECT sensor FROM recovery_tasks
            WHERE id=? AND status='interrupted'
        """, (task_id,)).fetchone()

        if not row:
            raise ValueError("Task not found or status is not interrupted")

        with self.db:
            self.db.execute(
                "UPDATE recovery_tasks SET status='resolved' WHERE id=?",
                (task_id,),
            )
            self.audit(actor, "resolve", task_id, reason)

        self.log("task_resolved", sensor=row[0], task_id=task_id,
                 reason=reason, actor=actor)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "action", choices=("status", "pause", "resume", "resolve")
    )
    parser.add_argument("target", nargs="?")
    parser.add_argument("--reason")
    args = parser.parse_args()

    if args.action != "status" and (
        not args.target or not (args.reason or "").strip()
    ):
        parser.error("Specify a target and --reason")

    root = Path(__file__).resolve().parents[1]
    runtime = root / "runtime"

    def log(event, **fields):
        record = {
            "timestamp": datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat(),
            "event": event,
            **fields,
        }
        line = json.dumps(record, ensure_ascii=False)
        with (runtime / "watchdog.jsonl").open("a") as stream:
            stream.write(line + "\n")
        print(line)

    try:
        with ExitStack() as stack:
            if args.action != "status":
                for name in ("watchdog.lock", "recovery.lock"):
                    lock = stack.enter_context(
                        (runtime / name).open("a")
                    )
                    fcntl.flock(
                        lock, fcntl.LOCK_EX | fcntl.LOCK_NB
                    )

            db = sqlite3.connect(
                f"file:{runtime / 'watchdog.sqlite3'}?mode=rw",
                uri=True,
            )
            stack.callback(db.close)
            policy = QueuePolicy(db, log)

            if args.action == "status":
                for row in db.execute("""
                    SELECT sensor, paused, reason FROM sensor_controls
                """):
                    print(json.dumps(dict(zip(
                        ("sensor", "paused", "reason"), row
                    ))))

                for row in db.execute("""
                    SELECT id, sensor, status, operation_mode, security_session FROM recovery_tasks
                    WHERE status IN ('queued','deferred','running','interrupted')
                """):
                    print(json.dumps(dict(zip(
                        ("task_id", "sensor", "task_status", "operation_mode", "session"), row
                    ))))
            else:
                getattr(policy, args.action)(
                    args.target, args.reason, getpass.getuser()
                )

    except BlockingIOError:
        raise SystemExit(
            "Stop watchdog and wait for recovery to finish first"
        )
    except (ValueError, sqlite3.Error) as exc:
        raise SystemExit(str(exc))


if __name__ == "__main__":
    main()
