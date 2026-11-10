import datetime
import ipaddress
import json
import sqlite3
import sys
from pathlib import Path

RULES = {
    "100202": "cowrie.login.success",
    "100203": "cowrie.command.input",
    "100204": "cowrie.session.closed",
    "100205": "cowrie.session.connect",
}


def prepare(db):
    db.execute("""
        CREATE TABLE IF NOT EXISTS cowrie_events (
            event_id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            session TEXT NOT NULL,
            event_type TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            event_time REAL NOT NULL,
            ignored INTEGER NOT NULL
        )
    """)
    db.execute("""
        CREATE VIEW IF NOT EXISTS cowrie_sessions AS
        SELECT agent_id, session,
            MIN(event_time) AS first_seen,
            MAX(event_time) AS last_seen,
            MAX(event_type='cowrie.session.connect') AS connected,
            MAX(event_type='cowrie.login.success') AS logged_in,
            SUM(event_type='cowrie.command.input') AS commands,
            MAX(event_type='cowrie.session.closed') AS closed,
            COUNT(DISTINCT NULLIF(source_ip,'')) AS source_count,
            MAX(source_ip) AS source_ip
        FROM cowrie_events
        WHERE ignored=0
        GROUP BY agent_id, session
    """)


def ingest(db, lines):
    inserted = 0

    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue

        try:
            event = json.loads(line)

            if (
                event.get("schema_version") != 1
                or event.get("agent_name") != "decoy"
                or event.get("sensor") != "cowrie"
            ):
                raise ValueError("Unexpected source or schema")

            if RULES.get(str(event.get("rule_id"))) != event.get("event_type"):
                raise ValueError("Unexpected event type")

            for key in ("event_id", "agent_id", "session"):
                value = event.get(key)
                if not isinstance(value, str) or not 1 <= len(value) <= 256:
                    raise ValueError("Invalid identifier")

            source = event.get("source_ip", "")
            ignored = False

            if source:
                address = ipaddress.ip_address(source)
                mapped = getattr(address, "ipv4_mapped", None)
                ignored = address.is_loopback or bool(
                    mapped and mapped.is_loopback
                )
                source = str(address)

            timestamp = datetime.datetime.fromisoformat(event["timestamp"])
            if timestamp.tzinfo is None:
                raise ValueError("Timezone is required")

            cursor = db.execute("""
                INSERT OR IGNORE INTO cowrie_events
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                event["event_id"],
                event["agent_id"],
                event["session"],
                event["event_type"],
                source,
                timestamp.timestamp(),
                int(ignored),
            ))
            inserted += cursor.rowcount

        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise ValueError(
                f"Invalid input at line {number}: {exc}"
            ) from exc

    return inserted


def main():
    root = Path(__file__).resolve().parents[1]
    db = sqlite3.connect(root / "runtime/security.sqlite3")
    db.row_factory = sqlite3.Row
    prepare(db)

    with db:
        inserted = ingest(db, sys.stdin)

    print(json.dumps({"new_events": inserted}))

    for row in db.execute("""
        SELECT * FROM cowrie_sessions
        ORDER BY last_seen DESC LIMIT 20
    """):
        item = dict(row)
        item["review_candidate"] = bool(
            row["connected"]
            and row["logged_in"]
            and row["closed"]
            and row["commands"] > 0
            and row["source_count"] == 1
        )
        print(json.dumps(item, ensure_ascii=False))

    db.close()


if __name__ == "__main__":
    main()
