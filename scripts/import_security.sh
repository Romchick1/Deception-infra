#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SNAPSHOT="$(mktemp "$ROOT/runtime/feed-XXXXXXXX.jsonl")"
trap 'rm -f "$SNAPSHOT"' EXIT

ssh -o BatchMode=yes -o ConnectTimeout=10 monitoring \
  'python3 -' > "$SNAPSHOT" <<'PY'
import fcntl
import sys

with open("/var/lib/deception-feed/events.jsonl") as stream:
    fcntl.flock(stream, fcntl.LOCK_SH)
    sys.stdout.write(stream.read())
PY

python3 "$ROOT/scripts/collect_sessions.py" < "$SNAPSHOT"
