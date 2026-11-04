#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TF_DIR="$ROOT/terraform/decoys"

case "${1:-}" in
  opencanary)
    RESOURCE="docker_container.opencanary"
    CONTAINER="opencanary-01"
    PYTHON="/opencanary/.venv/bin/python"
    PORT=80
    ;;
  cowrie)
    RESOURCE="docker_container.cowrie"
    CONTAINER="cowrie-01"
    PYTHON="/cowrie/cowrie-env/bin/python"
    PORT=2222
    ;;
  *)
    echo "Использование: $0 opencanary|cowrie" >&2
    exit 2
    ;;
esac

mkdir -p "$ROOT/runtime/recovery"

# Одна операция восстановления за раз.
exec 9>"$ROOT/runtime/recovery.lock"
flock -n 9 || {
  echo "Другая операция восстановления уже выполняется." >&2
  exit 1
}

RUN_DIR="$(mktemp -d "$ROOT/runtime/recovery/${1}-XXXXXXXX")"
START="$(date +%s)"
STATUS="failed"

finish() {
  CODE=$?
  trap - EXIT
  jq -n \
    --arg status "$STATUS" \
    --arg container "$CONTAINER" \
    --arg resource "$RESOURCE" \
    --arg old_id "${OLD_ID:-}" \
    --arg new_id "${NEW_ID:-}" \
    --argjson exit_code "$CODE" \
    --argjson duration_seconds "$(( $(date +%s) - START ))" \
    '{
      status: $status,
      container: $container,
      resource: $resource,
      old_id: $old_id,
      new_id: $new_id,
      exit_code: $exit_code,
      duration_seconds: $duration_seconds
    }' > "$RUN_DIR/result.json"
  echo "Результат: $RUN_DIR/result.json"
  exit "$CODE"
}
trap finish EXIT

SSH=(ssh -o BatchMode=yes -o ConnectTimeout=10 decoy)

OLD_ID="$("${SSH[@]}" docker inspect "$CONTAINER" |
  jq -er '.[0].Id')"

cd "$TF_DIR"

terraform plan -input=false -lock-timeout=30s \
  -replace="$RESOURCE" \
  -out="$RUN_DIR/plan.tfplan"

terraform show -json "$RUN_DIR/plan.tfplan" > "$RUN_DIR/plan.json"

# Разрешена только замена выбранного контейнера.
if ! jq -e --arg resource "$RESOURCE" '
  [.resource_changes[]?
    | select(.change.actions != ["no-op"])] as $changes
  | ($changes | length) == 1
    and $changes[0].address == $resource
    and $changes[0].change.actions == ["delete", "create"]
' "$RUN_DIR/plan.json" > /dev/null; then
  echo "План отклонён: есть изменения вне разрешённой замены." >&2
  exit 1
fi

terraform apply -input=false -lock-timeout=30s "$RUN_DIR/plan.tfplan"

NEW_ID="$("${SSH[@]}" docker inspect "$CONTAINER" |
  jq -er '.[0].Id')"

if [[ "$OLD_ID" == "$NEW_ID" ]]; then
  echo "ID контейнера не изменился." >&2
  exit 1
fi

# Проверяем сервис внутри контейнера.
CHECK="import socket; s=socket.create_connection(('127.0.0.1',$PORT),3); s.close()"

for attempt in {1..15}; do
  if "${SSH[@]}" \
    "docker exec $CONTAINER $PYTHON -c \"$CHECK\"" \
    > "$RUN_DIR/healthcheck.log" 2>&1; then
    STATUS="success"
    echo "Контейнер $CONTAINER заменён, сервис принимает соединения."
    exit 0
  fi
  sleep 2
done

echo "Новый контейнер не прошёл проверку готовности." >&2
exit 1
