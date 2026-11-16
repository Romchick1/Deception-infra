"""Read-only event collection and final checks for a queued Cowrie reset."""
import datetime
import fcntl
import json
import re
import shlex
import sqlite3
import subprocess
import time
from pathlib import Path

DEFAULTS = dict(enabled=False, enabled_since=0, quiet_seconds=60,
                fresh_seconds=60, max_task_age=300, retry_delay=30, cooldown=120)


def settings(root):
    path = Path(root) / "configs/security-response.json"
    data = DEFAULTS | (json.loads(path.read_text()) if path.exists() else {})
    if not isinstance(data["enabled"], bool):
        raise ValueError("enabled must be boolean")
    for key in ("quiet_seconds", "fresh_seconds", "max_task_age", "retry_delay", "cooldown"):
        if type(data[key]) is not int or not 1 <= data[key] <= 86400:
            raise ValueError("Invalid setting: " + key)
    if not isinstance(data["enabled_since"], (float, int)) or data["enabled_since"] < 0:
        raise ValueError("Invalid enabled_since")
    if data["enabled"] and not data["enabled_since"]:
        raise ValueError("Use security_policy.py enable to arm execution")
    return data


def ssh(command, source=None, timeout=25):
    result = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "decoy", command],
        input=source, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(result.stderr.strip()[:500] or "Remote command failed")
    return result.stdout


def instance():
    item = json.loads(ssh("docker inspect cowrie-01"))[0]
    if not re.fullmatch(r"[0-9a-f]{64}", item["Id"]):
        raise ValueError("Invalid Docker ID")
    if not item["State"]["Running"] or item["State"].get("Paused"):
        raise RuntimeError("Cowrie is not running normally")
    started = item["State"]["StartedAt"]
    epoch = datetime.datetime.fromisoformat(started.replace("Z", "+00:00")).timestamp()
    return dict(id=item["Id"], started=started, epoch=epoch)


FEED_CODE = '''import fcntl,sys
with open("/var/lib/deception-feed/events.jsonl", "rb") as f:
    fcntl.flock(f,fcntl.LOCK_SH)
    data=f.read(16*1024*1024+1)
    if len(data)>16*1024*1024: raise SystemExit("Feed exceeds 16 MiB; incremental collection required")
    if data and not data.endswith(b"\\n"): raise SystemExit("Incomplete feed record")
    sys.stdout.buffer.write(data)
'''


def refresh(root):
    from collect_sessions import prepare, ingest
    root = Path(root)
    result = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "monitoring", "python3 -"],
        input=FEED_CODE, capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError(result.stderr.strip()[:500] or "Feed unavailable")
    with sqlite3.connect(root / "runtime/security.sqlite3") as db:
        prepare(db)
        return ingest(db, result.stdout.splitlines())


def candidates(root, cfg, current, now=None):
    from security_policy import assess
    now = time.time() if now is None else now
    path = Path(root) / "runtime/security.sqlite3"
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as db:
        db.row_factory = sqlite3.Row
        return assess(db, cfg["enabled_since"], now, current["epoch"], cfg)


# Executed by Python inside the exact queued container, never by a shell backend.
# Cowrie source timestamps, not Wazuh arrival timestamps, establish generation.
RAW_CODE = r'''
import datetime,ipaddress,json,sys,time
from pathlib import Path
session, started, quiet, age = sys.argv[1:]
started=float(started); quiet=int(quiet); age=int(age); now=time.time()
path=Path("/cowrie/cowrie-git/var/log/cowrie/cowrie.json")
events=[]; last_activity=0
with path.open("rb") as f:
    size=f.seek(0,2); offset=max(0,size-8*1024*1024); f.seek(offset)
    if offset: f.readline()
    for raw in f:
        e=json.loads(raw)
        source=e.get("src_ip")
        if not source: continue
        ip=ipaddress.ip_address(source); mapped=getattr(ip,"ipv4_mapped",None)
        if ip.is_loopback or (mapped and mapped.is_loopback): continue
        stamp=datetime.datetime.fromisoformat(e["timestamp"].replace("Z","+00:00"))
        if stamp.tzinfo is None: raise ValueError("Missing source timezone")
        t=stamp.timestamp()
        if t>now+30: raise ValueError("Source clock is in the future")
        if t<started: continue
        last_activity=max(last_activity,t)
        if e.get("session")==session: events.append((e["eventid"],t,str(ip)))
types={e[0] for e in events}
required={"cowrie.session.connect","cowrie.login.success","cowrie.command.input","cowrie.session.closed"}
closed=max((e[1] for e in events if e[0]=="cowrie.session.closed"),default=0)
if not required.issubset(types): verdict="stale_or_incomplete_source_session"
elif len({e[2] for e in events})!=1: verdict="source_conflict"
elif now-closed>age: verdict="source_session_expired"
elif now-last_activity<quiet: verdict="quiet_period"
else: verdict="ready"
print(json.dumps({"verdict":verdict,"closed_at":closed,"last_activity":last_activity}))
'''


def source_check(session, current, cfg):
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", session):
        raise ValueError("Invalid session ID")
    command = shlex.join(["docker", "exec", "-i", current["id"],
                          "/cowrie/cowrie-env/bin/python", "-", session,
                          str(current["epoch"]), str(cfg["quiet_seconds"]),
                          str(cfg["max_task_age"])])
    data = json.loads(ssh(command, RAW_CODE, timeout=30))
    if data.get("verdict") not in {"ready", "stale_or_incomplete_source_session",
                                  "source_conflict", "source_session_expired", "quiet_period"}:
        raise ValueError("Invalid source verdict")
    return data


def preflight(root, task, recollect=True):
    """Return ready, deferred or cancelled; no state changes on decoy."""
    cfg = settings(root)
    now = time.time()
    if not cfg["enabled"] or task["created"] < cfg["enabled_since"]:
        return "cancelled", "execution_disabled_or_rearmed"
    if not task["expires"] or now >= task["expires"]:
        return "cancelled", "task_expired"
    current = instance()
    if current["id"] != task["expected_id"] or current["started"] != task["expected_started"]:
        return "cancelled", "container_changed"
    if recollect:
        refresh(root)
    reason, items = candidates(root, cfg, current, now)
    if reason != "eligible":
        return "deferred", reason
    if not any(x["agent_id"] == task["security_agent"] and x["session"] == task["security_session"]
               for x in items):
        return "cancelled", "session_no_longer_eligible"
    raw = source_check(task["security_session"], current, cfg)
    if raw["verdict"] == "ready":
        return "ready", "ready"
    if raw["verdict"] == "quiet_period":
        return "deferred", "source_activity"
    return "cancelled", raw["verdict"]


def dispatch(root, queue, states, log):
    cfg = settings(root)
    if not cfg["enabled"] or states.get("cowrie-01") != "running":
        return
    refresh(root)
    current = instance()
    reason, items = candidates(root, cfg, current)
    if reason != "eligible" or not items:
        return
    # A reset consumes all eligible sessions from this container generation.
    item = max(items, key=lambda x: x["last_seen"])
    queue.enqueue_security(item, current, cfg)
