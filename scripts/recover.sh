#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${2:-replace}"

case "${1:-}" in
  opencanary)
    RESOURCE="docker_container.opencanary"
    CONTAINER="opencanary-01"
    ;;
  cowrie)
    RESOURCE="docker_container.cowrie"
    CONTAINER="cowrie-01"
    ;;
  *)
    echo "Использование: $0 opencanary|cowrie [replace|reset-state]" >&2
    exit 2
    ;;
esac

case "$MODE" in
  replace) ;;
  reset-state)
    [[ "$1" == "cowrie" ]] || {
      echo "reset-state реализован только для Cowrie." >&2
      exit 2
    }
    if [[ -z "${DECEPTION_TASK_ID:-}" ]] && systemctl is-active --quiet deception-watchdog; then
      echo "Сначала останови deception-watchdog." >&2
      exit 2
    fi
    ;;
  *)
    echo "Неизвестный режим: $MODE" >&2
    exit 2
    ;;
esac

TF_DIR="$ROOT/terraform/$1"
mkdir -p "$ROOT/runtime/recovery"

exec 9>"$ROOT/runtime/recovery.lock"
flock -n 9 || {
  echo "Другая операция восстановления уже выполняется." >&2
  exit 1
}

RUN_DIR="$(mktemp -d "$ROOT/runtime/recovery/${1}-${MODE}-XXXXXXXX")"
START="$(date +%s)"
STATUS="failed"
ARCHIVE_VERIFIED=false
GATE_CLOSED=false

finish() {
  CODE=$?
  trap - EXIT

  jq -n \
    --arg status "$STATUS" \
    --arg mode "$MODE" \
    --arg container "$CONTAINER" \
    --arg task_id "${DECEPTION_TASK_ID:-manual}" \
    --arg resource "$RESOURCE" \
    --arg old_id "${OLD_ID:-}" \
    --arg new_id "${NEW_ID:-}" \
    --argjson archive_verified "$ARCHIVE_VERIFIED" \
    --argjson exit_code "$CODE" \
    --argjson gate_closed "$GATE_CLOSED" \
    --argjson duration_seconds "$(( $(date +%s) - START ))" \
    '{
      task_id: $task_id,
      status: $status,
      mode: $mode,
      container: $container,
      resource: $resource,
      old_id: $old_id,
      new_id: $new_id,
      archive_verified: $archive_verified,
      exit_code: $exit_code,
      gate_closed: $gate_closed,
      duration_seconds: $duration_seconds
    }' > "$RUN_DIR/result.json"
  jq -c \
    --arg run_dir "$RUN_DIR" \
    '. + {
      event: "operation_finished",
      timestamp: (now | todateiso8601),
      operation_status: .status,
      run_dir: $run_dir
    } | del(.status)' "$RUN_DIR/result.json" \
    >> "$ROOT/runtime/operations.jsonl"

  if [[ "${DECEPTION_TASK_ID:-}" =~ ^[0-9a-f]{32}$ ]]; then
    mkdir -p "$ROOT/runtime/task-results"
    cp "$RUN_DIR/result.json" "$ROOT/runtime/task-results/${DECEPTION_TASK_ID}.tmp"
    mv "$ROOT/runtime/task-results/${DECEPTION_TASK_ID}.tmp" \
      "$ROOT/runtime/task-results/${DECEPTION_TASK_ID}.json"
  fi
  echo "Результат: $RUN_DIR/result.json"
  exit "$CODE"
}
trap finish EXIT

if [[ -n "${DECEPTION_TASK_ID:-}" ]]; then
  python3 "$ROOT/scripts/task_guard.py" authorize "$1" "$MODE" \
    > "$RUN_DIR/authorization.json"
fi

# On uncertainty, keep ingress closed. Known deferral/cancellation reopens it.
revalidate_queued_reset() {
  local check_code=0
  python3 "$ROOT/scripts/task_guard.py" revalidate "$1" "$MODE" \
    > "$RUN_DIR/security-check.json" || check_code=$?
  if [[ "$check_code" != 0 ]]; then
    if [[ "$GATE_CLOSED" == true ]]; then
      "${SSH[@]}" sudo -n /usr/local/sbin/deception-cowrie-gate open
      GATE_CLOSED=false
    fi
    if [[ "$check_code" == 76 ]]; then
      STATUS="cancelled"
      exit 76
    fi
    STATUS="deferred"
    exit 75
  fi
}

SSH=(ssh -o BatchMode=yes -o ConnectTimeout=10 decoy)

CONTAINERS="$("${SSH[@]}" \
  'docker container ls --all --no-trunc --format "{{json .}}"')"

OLD_ID="$(printf '%s\n' "$CONTAINERS" |
  jq -sr --arg name "$CONTAINER" \
    '[.[] | select(.Names == $name) | .ID][0] // ""')"

REPLACE_ARGS=("-replace=$RESOURCE")
ALLOWED="$(jq -nc --arg resource "$RESOURCE" '[$resource]')"

if [[ "$MODE" == "reset-state" ]]; then
  [[ -n "$OLD_ID" ]] || {
    echo "Для архивирования нужен существующий контейнер Cowrie." >&2
    exit 1
  }

  REPLACE_ARGS+=("-replace=docker_volume.cowrie_state")
  ALLOWED='["docker_container.cowrie","docker_volume.cowrie_state"]'
fi

if [[ "$MODE" == "reset-state" && -n "${DECEPTION_TASK_ID:-}" ]]; then
  revalidate_queued_reset "$1"
fi

cd "$TF_DIR"

terraform plan -input=false -lock-timeout=30s \
  "${REPLACE_ARGS[@]}" \
  -out="$RUN_DIR/plan.tfplan"

terraform show -json "$RUN_DIR/plan.tfplan" > "$RUN_DIR/plan.json"

if ! jq -e --argjson allowed "$ALLOWED" --arg mode "$MODE" '
  [.resource_changes[]?
    | select(.change.actions != ["no-op"])] as $changes
  | (($changes | map(.address) | sort) == ($allowed | sort))
    and all($changes[];
      .change.actions == ["delete", "create"]
      or ($mode == "replace" and .change.actions == ["create"])
    )
' "$RUN_DIR/plan.json" > /dev/null; then
  echo "План отклонён: изменения не соответствуют выбранной операции." >&2
  exit 1
fi

if [[ "$MODE" == "reset-state" ]]; then
  if ! jq -e --arg expected "$OLD_ID" '
    [.resource_changes[] | select(.address == "docker_container.cowrie")][0] |
    .change.before.id == $expected
  ' "$RUN_DIR/plan.json" > /dev/null; then
    STATUS="cancelled"
    echo "Cowrie изменился во время планирования; сброс отменён." >&2
    exit 76
  fi
  "${SSH[@]}" docker volume inspect deception-cowrie-state \
    > "$RUN_DIR/volume.json"

  "${SSH[@]}" docker inspect "$CONTAINER" \
    > "$RUN_DIR/container.json"

  SNAPSHOT_IMAGE="$(jq -er '.[0].Image' "$RUN_DIR/container.json")"
  [[ "$SNAPSHOT_IMAGE" =~ ^sha256:[0-9a-f]{64}$ ]] || exit 1

  "${SSH[@]}" sudo -n /usr/local/sbin/deception-cowrie-gate close
  GATE_CLOSED=true

  "${SSH[@]}" sudo -n /usr/local/sbin/deception-cowrie-gate connections \
    > "$RUN_DIR/connections-before-reset.json"

  if ! jq -e '.external_connections == 0' \
    "$RUN_DIR/connections-before-reset.json" > /dev/null; then

    "${SSH[@]}" sudo -n /usr/local/sbin/deception-cowrie-gate open
    GATE_CLOSED=false
    STATUS="deferred"

    echo "Сброс отложен: отсутствие внешних соединений не подтверждено." >&2
    exit 75
  fi

  if [[ -n "${DECEPTION_TASK_ID:-}" ]]; then
    revalidate_queued_reset "$1"
  fi

  # Stop the instance inspected and planned, never a different container of the same name.
  "${SSH[@]}" docker stop "$OLD_ID"

  # Архиватор использует тот же локальный образ, без подключения к сети.
  # Том и журнал подключаются только для чтения.
  "${SSH[@]}" \
    "docker run --rm --network none --user 0:0 \
      --entrypoint /cowrie/cowrie-env/bin/python \
      --mount type=volume,source=deception-cowrie-state,target=/snapshot/state,readonly \
      --mount type=bind,source=/var/log/deception/cowrie,target=/snapshot/logs,readonly \
      $SNAPSHOT_IMAGE \
      -c 'import sys,tarfile; t=tarfile.open(fileobj=sys.stdout.buffer,mode=\"w|\"); t.add(\"/snapshot/state\",arcname=\"state\"); t.add(\"/snapshot/logs\",arcname=\"logs\"); t.close()'" \
    | gzip > "$RUN_DIR/evidence.tar.gz"

  tar -tzf "$RUN_DIR/evidence.tar.gz" > "$RUN_DIR/archive-files.txt"
  grep -q '^state/' "$RUN_DIR/archive-files.txt"
  grep -q '^logs/' "$RUN_DIR/archive-files.txt"

  (
    cd "$RUN_DIR"
    sha256sum evidence.tar.gz container.json volume.json > SHA256SUMS
    sha256sum -c SHA256SUMS
  )

  ARCHIVE_VERIFIED=true
fi

terraform apply -input=false -lock-timeout=30s "$RUN_DIR/plan.tfplan"

NEW_ID="$("${SSH[@]}" docker inspect "$CONTAINER" |
  jq -er '.[0].Id')"

[[ "$OLD_ID" != "$NEW_ID" ]] || {
  echo "ID контейнера не изменился." >&2
  exit 1
}

for attempt in {1..15}; do
  if python3 "$ROOT/scripts/health_probe.py" "$1" \
    > "$RUN_DIR/healthcheck.json" \
    2> "$RUN_DIR/healthcheck.log"; then
    if [[ "$MODE" == "reset-state" ]]; then
      "${SSH[@]}" sudo -n /usr/local/sbin/deception-cowrie-gate open
      GATE_CLOSED=false
    fi
    STATUS="success"
    echo "Операция $MODE завершена, проверки сервисов успешны."
    exit 0
  fi
  sleep 2
done

echo "Новый контейнер не прошёл проверку сервисов." >&2
exit 1
