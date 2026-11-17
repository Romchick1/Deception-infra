#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 2 ]]; then
  printf 'Использование: bash install.sh <GitHub URL> <тег>\n' >&2
  exit 2
fi

repo_url="$1"
release="$2"
project_dir="$HOME/deception-infra"

if [[ ! -e "$project_dir" ]]; then
  git clone --branch "$release" --single-branch -- "$repo_url" "$project_dir"
fi

if [[ ! -d "$project_dir/.git" ]] ||
   [[ "$(git -C "$project_dir" remote get-url origin)" != "$repo_url" ]]; then
  printf 'Каталог %s уже занят другой копией проекта.\n' "$project_dir" >&2
  exit 1
fi

release_commit="$(git -C "$project_dir" rev-parse --verify "refs/tags/$release^{commit}")"
current_commit="$(git -C "$project_dir" rev-parse HEAD)"
if [[ "$current_commit" != "$release_commit" ]] ||
   [[ -n "$(git -C "$project_dir" status --porcelain --untracked-files=no)" ]]; then
  printf 'Для установки нужна чистая копия версии %s в %s.\n' \
    "$release" "$project_dir" >&2
  exit 1
fi

cd "$project_dir"
exec bash scripts/deploy.sh
