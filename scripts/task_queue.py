import fcntl
import os
import sqlite3
import subprocess
import time
import uuid
from pathlib import Path
from queue_policy import QueuePolicy

FAULTS = {"exited", "dead", "missing", "unhealthy"}
SENSORS = {"opencanary": "opencanary-01", "cowrie": "cowrie-01"}


class TaskQueue:
    def __init__(self, db, root, log):
        self.db, self.root, self.log = db, Path(root), log

        db.execute("""
            CREATE TABLE IF NOT EXISTS recovery_tasks (
                id TEXT PRIMARY KEY,
                sensor TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT NOT NULL,
                created REAL NOT NULL,
                started REAL,
                finished REAL,
                exit_code INTEGER
            )
        """)
        db.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS one_active_task
            ON recovery_tasks(sensor)
            WHERE status IN ('queued', 'running', 'interrupted')
        """)
        db.commit()
        self.policy = QueuePolicy(db, log)

    def reconcile(self):
        with (self.root / "runtime/recovery.lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return False

            rows = self.db.execute("""
                SELECT id, sensor FROM recovery_tasks
                WHERE status='running'
            """).fetchall()

            with self.db:
                self.db.execute("""
                    UPDATE recovery_tasks
                    SET status='interrupted', finished=?
                    WHERE status='running'
                """, (time.time(),))

            for task_id, sensor in rows:
                self.log("task_interrupted",
                         task_id=task_id, sensor=sensor)

        return True

    def enqueue(self, sensor, reason):
        if sensor not in SENSORS or reason not in FAULTS:
            raise ValueError("Unknown sensor or failure reason")

        if not self.policy.allowed(sensor):
            return None

        task_id = uuid.uuid4().hex
        try:
            with self.db:
                self.db.execute("""
                    INSERT INTO recovery_tasks
                    (id, sensor, reason, status, created)
                    VALUES (?, ?, ?, 'queued', ?)
                """, (task_id, sensor, reason, time.time()))
        except sqlite3.IntegrityError:
            return None

        self.log("task_queued", task_id=task_id,
                 sensor=sensor, reason=reason)
        return task_id


    def run_next(self, states):
        if not self.reconcile():
            return

        rows = self.db.execute("""
            SELECT id, sensor FROM recovery_tasks
            WHERE status='queued' ORDER BY created, id
        """).fetchall()

        for task_id, sensor in rows:
            state = states.get(SENSORS[sensor], "missing")

            if state == "running":
                with self.db:
                    self.db.execute("""
                        UPDATE recovery_tasks
                        SET status='cancelled', finished=? WHERE id=?
                    """, (time.time(), task_id))
                self.log("task_cancelled", task_id=task_id,
                         sensor=sensor, reason="service_recovered")
                continue

            if state not in FAULTS:
                continue
            if not self.policy.allowed(sensor):
                continue

            with self.db:
                self.db.execute("""
                    UPDATE recovery_tasks
                    SET status='running', started=? WHERE id=?
                """, (time.time(), task_id))
                self.db.execute("""
                    UPDATE sensors SET failures=0, last_attempt=?
                    WHERE name=?
                """, (time.time(), sensor))

            self.log("recovery_started",
                     task_id=task_id, sensor=sensor)

            env = os.environ.copy()
            env["DECEPTION_TASK_ID"] = task_id

            try:
                path = self.root / "runtime/recovery" / (task_id + ".log")
                with path.open("w") as output:
                    result = subprocess.run(
                        [str(self.root / "scripts/recover.sh"), sensor],
                        cwd=self.root,
                        env=env,
                        stdout=output,
                        stderr=subprocess.STDOUT,
                    )
                code = result.returncode
                status = "success" if code == 0 else (
                    "interrupted" if code < 0 else "failed"
                )
            except OSError as exc:
                code, status = 127, "failed"
                self.log("task_launch_failed",
                         task_id=task_id, error=str(exc))

            with self.db:
                self.db.execute("""
                    UPDATE recovery_tasks
                    SET status=?, finished=?, exit_code=? WHERE id=?
                """, (status, time.time(), code, task_id))

            self.log("recovery_finished", task_id=task_id,
                     sensor=sensor, task_status=status, exit_code=code)
            return
