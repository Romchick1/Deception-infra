#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $EUID == 0 ]]; then
  echo 'Запусти install.sh от labadmin без sudo. Ansible сам запросит повышение прав.' >&2
  exit 1
fi
if [[ $# != 2 ]]; then
  echo 'Использование: bash install.sh <GitHub URL> <тег>' >&2
  exit 2
fi
command -v git >/dev/null || { echo 'Установи git через prepare-vm.sh control.' >&2; exit 1; }
repo_url="$1"
release="$2"
project_dir="$HOME/deception-infra"
git check-ref-format "refs/tags/$release" >/dev/null

if [[ ! -e "$project_dir" ]]; then
  git clone --branch "$release" --single-branch -- "$repo_url" "$project_dir"
fi
if [[ ! -d "$project_dir/.git" ]] ||
   [[ "$(git -C "$project_dir" remote get-url origin)" != "$repo_url" ]]; then
  echo "Каталог $project_dir занят другой копией проекта." >&2
  exit 1
fi
if [[ -n "$(git -C "$project_dir" status --porcelain --untracked-files=no)" ]]; then
  echo 'Сначала сохрани изменения отслеживаемых файлов в коммите. Посмотри git status.' >&2
  exit 1
fi
# Получаем именно тег. Рабочие состояния Terraform и runtime остаются локальными.
git -C "$project_dir" fetch origin "refs/tags/$release:refs/tags/$release"
release_commit="$(git -C "$project_dir" rev-parse --verify "refs/tags/$release^{commit}")"
if [[ "$(git -C "$project_dir" rev-parse HEAD)" != "$release_commit" ]]; then
  git -C "$project_dir" switch --detach "$release_commit"
fi
cd "$project_dir"
exec bash scripts/deploy.sh
