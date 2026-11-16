"""Authorization and revalidation called by recover.sh under recovery.lock."""
import hmac
import json
import os
import re
import sqlite3
import subprocess
import sys
from pathlib import Path
from security_runtime import preflight


def authorize(root, sensor, mode):
    task_id = os.environ.get("DECEPTION_TASK_ID", "")
    token = os.environ.get("DECEPTION_TASK_TOKEN", "")
    if not re.fullmatch(r"[0-9a-f]{32}", task_id) or not token:
        raise ValueError("Missing queued task authorization")
    path = Path(root) / "runtime/watchdog.sqlite3"
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as db:
        db.row_factory = sqlite3.Row
        row = db.execute("SELECT * FROM recovery_tasks WHERE id=?", (task_id,)).fetchone()
    if row is None:
        raise ValueError("Task does not exist")
    task = dict(row)
    if (task["status"] != "running" or task["sensor"] != sensor
            or task["operation_mode"] != mode or not task["lease_token"]
            or not hmac.compare_digest(task["lease_token"], token)):
        raise ValueError("Task authorization does not match the running operation")
    return task


def main():
    root = Path(__file__).resolve().parents[1]
    if len(sys.argv) != 4 or sys.argv[1] not in {"authorize", "revalidate"}:
        raise SystemExit("Usage: task_guard.py authorize|revalidate SENSOR MODE")
    try:
        task = authorize(root, sys.argv[2], sys.argv[3])
        if sys.argv[1] == "authorize":
            print(json.dumps({"authorized": True, "task_id": task["id"]}))
            return
        if sys.argv[2:] != ["cowrie", "reset-state"]:
            raise ValueError("Revalidation only supports Cowrie reset-state")
        verdict, reason = preflight(root, task)
        print(json.dumps({"verdict": verdict, "reason": reason}))
        if verdict == "cancelled":
            raise SystemExit(76)
        if verdict != "ready":
            raise SystemExit(75)
    except (OSError, ValueError, KeyError, RuntimeError, sqlite3.Error, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"verdict": "unavailable", "reason": str(exc)[:500]}))
        raise SystemExit(75 if sys.argv[1] == "revalidate" else 2)


if __name__ == "__main__":
    main()
