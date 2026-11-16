"""Observation compatibility plus explicitly armed automatic response."""
import argparse
import datetime
import fcntl
import getpass
import json
import os
import sqlite3
import time
from contextlib import ExitStack
from pathlib import Path

QUIET_SECONDS = 60
FRESH_SECONDS = 60


def assess(db, armed_at, now, instance_started=0, cfg=None):
    cfg = cfg or dict(quiet_seconds=QUIET_SECONDS, fresh_seconds=FRESH_SECONDS)
    latest = db.execute("SELECT MAX(event_time) FROM cowrie_events").fetchone()[0]
    if latest is None or now-latest > cfg["fresh_seconds"] or latest > now+30:
        return "feed_stale_or_clock_error", []
    # Old open-session records must not keep a replaced instance blocked forever.
    # Wazuh timestamps are only a coarse filter; raw Cowrie timestamps are checked
    # again on decoy before automatic execution.
    sessions = db.execute("SELECT * FROM cowrie_sessions WHERE first_seen>=?",
                          (instance_started,)).fetchall()
    if any(row["connected"] and not row["closed"] for row in sessions):
        return "active_sessions", []
    if any(not row["connected"] and row["last_seen"] >= armed_at for row in sessions):
        return "incomplete_sessions", []
    last_activity = max((row["last_seen"] for row in sessions), default=0)
    if now-last_activity < cfg["quiet_seconds"]:
        return "quiet_period", []
    candidates = []
    for row in sessions:
        if not (row["connected"] and row["logged_in"] and row["closed"]
                and row["commands"] > 0 and row["source_count"] == 1):
            continue
        closed_after_arm = db.execute("""SELECT 1 FROM cowrie_events
            WHERE agent_id=? AND session=? AND ignored=0
            AND event_type='cowrie.session.closed' AND event_time>=? LIMIT 1""",
            (row["agent_id"], row["session"], armed_at)).fetchone()
        if closed_after_arm:
            candidates.append(dict(row))
    return "eligible", candidates


def main():
    from security_runtime import DEFAULTS, settings
    from queue_policy import QueuePolicy
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("arm", "evaluate", "status", "enable", "disable"))
    parser.add_argument("--reason")
    args = parser.parse_args()
    if args.action in {"enable", "disable"} and not (args.reason or "").strip():
        parser.error("Specify --reason")
    os.umask(0o077)
    root = Path(__file__).resolve().parents[1]
    runtime = root / "runtime"

    def log(event, **fields):
        record = dict(timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      event=event, **fields)
        line = json.dumps(record, ensure_ascii=False)
        with (runtime / "watchdog.jsonl").open("a") as output:
            output.write(line+"\n")
        print(line)

    try:
        with ExitStack() as stack:
            if args.action in {"enable", "disable", "arm"}:
                for name in ("watchdog.lock", "recovery.lock"):
                    lock = stack.enter_context((runtime/name).open("a"))
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            cfg = settings(root)
            if args.action == "status":
                print(json.dumps(cfg, ensure_ascii=False, indent=2))
                return
            if args.action in {"enable", "disable"}:
                cfg["enabled"] = args.action == "enable"
                if cfg["enabled"]:
                    cfg["enabled_since"] = time.time()
                path = root / "configs/security-response.json"
                path.parent.mkdir(exist_ok=True)
                temporary = path.with_suffix(".tmp")
                temporary.write_text(json.dumps(cfg, indent=2)+"\n")
                temporary.replace(path)
                with sqlite3.connect(f"file:{runtime/'watchdog.sqlite3'}?mode=rw", uri=True) as db:
                    policy = QueuePolicy(db, log)
                    with db:
                        policy.audit(getpass.getuser(), args.action+"_security_reset", "cowrie", args.reason)
                log("security_execution_"+args.action+"d", sensor="cowrie", reason=args.reason)
                return
            with sqlite3.connect(f"file:{runtime/'security.sqlite3'}?mode=rw", uri=True) as db:
                db.row_factory = sqlite3.Row
                db.execute("CREATE TABLE IF NOT EXISTS observation_policy (id INTEGER PRIMARY KEY CHECK(id=1), armed_at REAL NOT NULL)")
                db.execute("""CREATE TABLE IF NOT EXISTS security_decisions (
                    agent_id TEXT, session TEXT, created REAL NOT NULL,
                    PRIMARY KEY(agent_id,session))""")
                if args.action == "arm":
                    db.execute("INSERT OR IGNORE INTO observation_policy VALUES (1,?)", (time.time(),))
                    print("Observation armed; automatic mode is controlled by enable/disable")
                    return
                row = db.execute("SELECT armed_at FROM observation_policy WHERE id=1").fetchone()
                if not row:
                    raise ValueError("Run arm first")
                reason, items = assess(db, row[0], time.time())
                print(json.dumps(dict(evaluation=reason, candidates=len(items))))
                for item in items:
                    inserted = db.execute("INSERT OR IGNORE INTO security_decisions VALUES (?,?,?)",
                        (item["agent_id"], item["session"], time.time())).rowcount
                    if inserted:
                        log("security_reset_candidate", sensor="cowrie", session=item["session"],
                            source_ip=item["source_ip"], mode="observe")
    except BlockingIOError:
        raise SystemExit("Stop watchdog and wait for recovery to finish first")
    except (OSError, ValueError, sqlite3.Error) as exc:
        raise SystemExit(str(exc))


if __name__ == "__main__":
    main()
