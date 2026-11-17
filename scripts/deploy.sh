#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ansible=(
  ansible-playbook
  -i ansible/inventory.yml
  --ask-become-pass
)

printf '\n[1/4] Подготовка ВМ и настройка Wazuh\n'
for playbook in \
  bootstrap \
  prepare-paths \
  deploy-components \
  deploy-decoy-configs \
  prepare-event-feed \
  configure-wazuh
do
  "${ansible[@]}" "ansible/${playbook}.yml"
done

printf '\n[2/4] Включение сетевой изоляции на decoy\n'
ssh -t decoy 'sudo systemctl daemon-reload &&
  sudo modprobe br_netfilter &&
  sudo sysctl -p /etc/sysctl.d/99-deception-bridge.conf &&
  sudo systemctl enable deception-firewall.service &&
  sudo systemctl restart deception-firewall.service &&
  sudo iptables -C DOCKER-USER -j DECEPTION &&
  sudo iptables -C INPUT -i br-decoy -j DROP'

printf '\n[3/4] Развёртывание и проверка приманок\n'
(
  # Используем ту же блокировку, что и recover.sh.
  flock -n 9 || {
    echo 'Дождись завершения текущей операции восстановления и повтори запуск.' >&2
    exit 1
  }

  for module in shared opencanary cowrie; do
    tf_dir="$ROOT/terraform/$module"
    printf '\n--- Terraform: %s ---\n' "$module"
    terraform -chdir="$tf_dir" init -input=false
    terraform -chdir="$tf_dir" apply -lock-timeout=30s
  done

  for probe in \
    'opencanary-01 /opencanary/.venv/bin/python 80 21' \
    'cowrie-01 /cowrie/cowrie-env/bin/python 2222'
  do
    read -r container python ports <<< "$probe"
    ready=false

    for attempt in {1..10}; do
      if ssh -o BatchMode=yes -o ConnectTimeout=5 decoy \
        "docker exec $container $python -c 'import socket, sys
for port in sys.argv[1:]:
    with socket.create_connection((\"127.0.0.1\", int(port)), timeout=3):
        pass' $ports"
      then
        printf '%s готов, порты %s\n' "$container" "$ports"
        ready=true
        break
      fi
      sleep 2
    done

    if [[ "$ready" != true ]]; then
      printf '%s не прошёл проверку готовности\n' "$container" >&2
      exit 1
    fi
  done
) 9>"$ROOT/runtime/recovery.lock"

printf '\n[4/4] Запуск watchdog\n'
sudo systemctl daemon-reload
sudo systemctl enable --now deception-watchdog.service
systemctl is-active deception-watchdog.service
