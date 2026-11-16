"""Durable serial execution. Only this module launches automatic recovery."""
import fcntl
import json
import os
import re
import secrets
import sqlite3
import subprocess
import time
import uuid
from pathlib import Path
from queue_policy import QueuePolicy
from security_runtime import preflight, settings

FAULTS = {"exited", "dead", "missing", "unhealthy"}
SENSORS = {"opencanary": "opencanary-01", "cowrie": "cowrie-01"}
ACTIVE = "('queued','deferred','running','interrupted')"


class TaskQueue:
    def __init__(self, db, root, log):
        self.db, self.root, self.log = db, Path(root), log
        (self.root / "runtime/recovery").mkdir(parents=True, exist_ok=True)
        (self.root / "runtime/task-results").mkdir(exist_ok=True)
        db.execute("""CREATE TABLE IF NOT EXISTS recovery_tasks (
            id TEXT PRIMARY KEY, sensor TEXT NOT NULL, reason TEXT NOT NULL,
            status TEXT NOT NULL, created REAL NOT NULL, started REAL,
            finished REAL, exit_code INTEGER)""")
        existing = {r[1] for r in db.execute("PRAGMA table_info(recovery_tasks)")}
        additions = dict(operation_mode="TEXT NOT NULL DEFAULT 'replace'",
                         expected_id="TEXT", expected_started="TEXT",
                         security_agent="TEXT", security_session="TEXT",
                         expires="REAL", not_before="REAL NOT NULL DEFAULT 0",
                         request_key="TEXT", lease_token="TEXT", last_note="TEXT")
        for name, kind in additions.items():
            if name not in existing:
                db.execute(f"ALTER TABLE recovery_tasks ADD COLUMN {name} {kind}")
        db.execute("DROP INDEX IF EXISTS one_active_task")
        db.execute(f"CREATE UNIQUE INDEX one_active_task ON recovery_tasks(sensor) WHERE status IN {ACTIVE}")
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS unique_security_request ON recovery_tasks(request_key)")
        db.commit()
        self.policy = QueuePolicy(db, log)

    def rows(self, sql, args=()):
        cursor = self.db.execute(sql, args)
        names = [d[0] for d in cursor.description]
        return [dict(zip(names, r)) for r in cursor.fetchall()]

    def reconcile(self):
        with (self.root / "runtime/recovery.lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return False
            rows = self.rows("SELECT * FROM recovery_tasks WHERE status='running'")
            with self.db:
                self.db.execute("""UPDATE recovery_tasks SET status='interrupted',
                    finished=?, lease_token=NULL WHERE status='running'""", (time.time(),))
            for task in rows:
                self.policy.pause(task["sensor"], "interrupted_task")
                self.log("task_interrupted", task_id=task["id"], sensor=task["sensor"])
        return True

    def enqueue(self, sensor, reason):
        if sensor not in SENSORS or reason not in FAULTS:
            raise ValueError("Unknown sensor or failure reason")
        if not self.policy.allowed(sensor):
            return None
        task_id = uuid.uuid4().hex
        try:
            with self.db:
                self.db.execute("""INSERT INTO recovery_tasks
                    (id,sensor,reason,status,created,operation_mode)
                    VALUES (?,?,?,'queued',?,'replace')""", (task_id, sensor, reason, time.time()))
        except sqlite3.IntegrityError:
            return None
        self.log("task_queued", task_id=task_id, sensor=sensor, reason=reason, operation_mode="replace")
        return task_id

    def enqueue_security(self, item, current, cfg):
        now = time.time()
        last = self.db.execute("SELECT last_attempt FROM sensors WHERE name='cowrie'").fetchone()
        if last and now - last[0] < cfg["cooldown"]:
            return None
        if not self.policy.allowed("cowrie"):
            return None
        expires = item["last_seen"] + cfg["max_task_age"]
        if expires <= now:
            return None
        task_id = uuid.uuid4().hex
        # One security reset per observed instance/session, even after cancellation.
        key = f'{current["id"]}:{item["agent_id"]}:{item["session"]}'
        try:
            with self.db:
                self.db.execute("""INSERT INTO recovery_tasks
                    (id,sensor,reason,status,created,operation_mode,expected_id,
                     expected_started,security_agent,security_session,expires,request_key)
                    VALUES (?,'cowrie','completed_session','queued',?,'reset-state',?,?,?,?,?,?)""",
                    (task_id, now, current["id"], current["started"], item["agent_id"],
                     item["session"], expires, key))
        except sqlite3.IntegrityError:
            return None
        self.log("security_reset_candidate", task_id=task_id, sensor="cowrie",
                 session=item["session"], source_ip=item.get("source_ip", ""), mode="execute")
        self.log("task_queued", task_id=task_id, sensor="cowrie", reason="completed_session",
                 operation_mode="reset-state", session=item["session"])
        return task_id

    def transition(self, task, status, reason, delay=0):
        with self.db:
            self.db.execute("""UPDATE recovery_tasks SET status=?,last_note=?,
                not_before=?,finished=?,lease_token=NULL WHERE id=?""",
                (status, reason, time.time()+delay,
                 None if status == "deferred" else time.time(), task["id"]))
        self.log("task_"+status, task_id=task["id"], sensor=task["sensor"], reason=reason)

    def run_next(self, states):
        if not self.reconcile():
            return
        rows = self.rows("""SELECT * FROM recovery_tasks
            WHERE status IN ('queued','deferred')
            ORDER BY CASE operation_mode WHEN 'replace' THEN 0 ELSE 1 END, created,id""")
        for task in rows:
            mode, sensor = task["operation_mode"], task["sensor"]
            state = states.get(SENSORS[sensor], "missing")
            if mode == "reset-state":
                try:
                    cfg = settings(self.root)
                    if (not cfg["enabled"] or task["created"] < cfg["enabled_since"]
                            or time.time() >= task["expires"]):
                        self.transition(task, "cancelled", "disabled_rearmed_or_expired")
                        continue
                    if state in FAULTS:
                        self.transition(task, "cancelled", "availability_recovery_required")
                        continue
                    if state != "running" or time.time() < task["not_before"]:
                        continue
                    if not self.policy.allowed(sensor):
                        continue
                    verdict, reason = preflight(self.root, task)
                    if verdict != "ready":
                        self.transition(task, verdict, reason, cfg["retry_delay"])
                        continue
                except (OSError, ValueError, KeyError, RuntimeError, subprocess.TimeoutExpired, sqlite3.Error) as exc:
                    self.transition(task, "deferred", str(exc)[:500], 30)
                    continue
            else:
                if state == "running":
                    self.transition(task, "cancelled", "service_recovered")
                    continue
                if state not in FAULTS or not self.policy.allowed(sensor):
                    continue

            token = secrets.token_hex(32)
            attempt_id = uuid.uuid4().hex
            now = time.time()
            with self.db:
                self.db.execute("""UPDATE recovery_tasks SET status='running',started=?,
                    finished=NULL,lease_token=? WHERE id=?""", (now, token, task["id"]))
                self.db.execute("""INSERT INTO recovery_attempts(id,task_id,sensor,started)
                    VALUES (?,?,?,?)""", (attempt_id, task["id"], sensor, now))
                self.db.execute("UPDATE sensors SET failures=0,last_attempt=? WHERE name=?", (now, sensor))
            self.log("recovery_started", task_id=task["id"], sensor=sensor, operation_mode=mode)
            env = os.environ.copy()
            env.update(DECEPTION_TASK_ID=task["id"], DECEPTION_TASK_TOKEN=token)
            result_path = self.root / "runtime/task-results" / (task["id"]+".json")
            result_path.unlink(missing_ok=True)
            try:
                with (self.root / "runtime/recovery" / (attempt_id+".log")).open("w") as output:
                    result = subprocess.run([str(self.root / "scripts/recover.sh"), sensor, mode],
                        cwd=self.root, env=env, stdout=output, stderr=subprocess.STDOUT)
                code = result.returncode
                record = json.loads(result_path.read_text()) if result_path.exists() else {}
                matches = (record.get("task_id") == task["id"] and record.get("mode") == mode
                           and record.get("container") == SENSORS[sensor]
                           and record.get("exit_code") == code)
                if code < 0 or not matches:
                    status = "interrupted"
                elif code == 0 and record.get("status") == "success":
                    proven = (isinstance(record.get("new_id"), str)
                              and re.fullmatch(r"[0-9a-f]{64}", record["new_id"])
                              and record.get("old_id") != record["new_id"])
                    if mode == "reset-state":
                        proven = (proven and record.get("old_id") == task["expected_id"]
                                  and record.get("archive_verified") is True
                                  and record.get("gate_closed") is False)
                    status = "success" if proven else "interrupted"
                elif code == 75 and mode == "reset-state" and record.get("status") == "deferred":
                    status = "deferred"
                elif code == 76 and mode == "reset-state" and record.get("status") == "cancelled":
                    status = "cancelled"
                else:
                    status = "failed"
                if record.get("gate_closed"):
                    status = "interrupted"
                    self.policy.pause(sensor, "gate_closed")
            except OSError as exc:
                code, status = 127, "interrupted"
                self.log("task_launch_failed", task_id=task["id"], error=str(exc))
            except (ValueError, TypeError):
                code, status = 127, "interrupted"
            if status == "interrupted":
                self.policy.pause(sensor, "interrupted_task")
            delay = 30 if status == "deferred" else 0
            with self.db:
                self.db.execute("""UPDATE recovery_tasks SET status=?,finished=?,exit_code=?,
                    not_before=?,lease_token=NULL WHERE id=?""",
                    (status, None if status == "deferred" else time.time(), code,
                     time.time()+delay, task["id"]))
                self.db.execute("UPDATE recovery_attempts SET finished=?,exit_code=? WHERE id=?",
                                (time.time(), code, attempt_id))
            self.log("recovery_finished", task_id=task["id"], sensor=sensor,
                     task_status=status, operation_mode=mode, exit_code=code, attempt_id=attempt_id)
            return
