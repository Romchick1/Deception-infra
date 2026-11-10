import datetime
import json
import sqlite3
import sys
import time
from pathlib import Path

QUIET_SECONDS = 60
FRESH_SECONDS = 60


def assess(db, armed_at, now):
    latest = db.execute(
        "SELECT MAX(event_time) FROM cowrie_events"
    ).fetchone()[0]

    if latest is None or now - latest > FRESH_SECONDS or latest > now + 30:
        return "feed_stale_or_clock_error", []

    sessions = db.execute("SELECT * FROM cowrie_sessions").fetchall()

    if any(row["connected"] and not row["closed"] for row in sessions):
        return "active_sessions", []

    if any(
        not row["connected"] and row["last_seen"] >= armed_at
        for row in sessions
    ):
        return "incomplete_sessions", []

    last_activity = max(
        (row["last_seen"] for row in sessions), default=0
    )
    if now - last_activity < QUIET_SECONDS:
        return "quiet_period", []

    candidates = []

    for row in sessions:
        if not (
            row["connected"]
            and row["logged_in"]
            and row["closed"]
            and row["commands"] > 0
            and row["source_count"] == 1
        ):
            continue

        closed_after_arm = db.execute("""
            SELECT 1 FROM cowrie_events
            WHERE agent_id=? AND session=? AND ignored=0
              AND event_type='cowrie.session.closed'
              AND event_time>=?
            LIMIT 1
        """, (
            row["agent_id"], row["session"], armed_at
        )).fetchone()

        if closed_after_arm:
            candidates.append(dict(row))

    return "eligible", candidates


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in {"arm", "evaluate"}:
        raise SystemExit("Usage: security_policy.py arm|evaluate")

    root = Path(__file__).resolve().parents[1]
    db = sqlite3.connect(
        f"file:{root / 'runtime/security.sqlite3'}?mode=rw",
        uri=True,
    )
    db.row_factory = sqlite3.Row

    db.execute("""
        CREATE TABLE IF NOT EXISTS observation_policy (
            id INTEGER PRIMARY KEY CHECK(id=1),
            armed_at REAL NOT NULL
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS security_decisions (
            agent_id TEXT,
            session TEXT,
            created REAL NOT NULL,
            PRIMARY KEY(agent_id, session)
        )
    """)
    db.commit()

    if sys.argv[1] == "arm":
        with db:
            db.execute("""
                INSERT OR IGNORE INTO observation_policy
                VALUES (1, ?)
            """, (time.time(),))
        print("Observation armed; reset execution remains disabled")
        return

    row = db.execute("""
        SELECT armed_at FROM observation_policy WHERE id=1
    """).fetchone()

    if row is None:
        raise SystemExit("Run arm first")

    reason, candidates = assess(db, row[0], time.time())
    print(json.dumps({
        "evaluation": reason,
        "candidates": len(candidates),
    }))

    for item in candidates:
        with db:
            inserted = db.execute("""
                INSERT OR IGNORE INTO security_decisions
                VALUES (?, ?, ?)
            """, (
                item["agent_id"], item["session"], time.time()
            )).rowcount

        if not inserted:
            continue

        event = {
            "timestamp": datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat(),
            "event": "security_reset_candidate",
            "sensor": "cowrie",
            "session": item["session"],
            "source_ip": item["source_ip"],
            "mode": "observe",
        }
        line = json.dumps(event)

        with (root / "runtime/watchdog.jsonl").open("a") as output:
            output.write(line + "\n")

        print(line)

    db.close()


if __name__ == "__main__":
    main()

