#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
skill_source="$repository_root/skills/acc-engineer"
default_codex_root=${CODEX_HOME:-"$HOME/.codex"}
skills_root=${1:-"$default_codex_root/skills"}
skill_target="$skills_root/acc-engineer"

if [ -e "$skill_target" ]; then
  printf '%s\n' "Refusing to overwrite existing skill: $skill_target" >&2
  exit 1
fi

mkdir -p "$skills_root"
cp -R "$skill_source" "$skill_target"
printf '%s\n' "Installed ACC Engineer at $skill_target"
