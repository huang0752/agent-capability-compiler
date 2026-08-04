#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
commands_source="$script_dir/commands"
commands_root=${1:-"$HOME/.claude/commands"}

mkdir -p "$commands_root"
for source in "$commands_source"/*.md; do
  target="$commands_root/$(basename -- "$source")"
  if [ -e "$target" ]; then
    printf '%s\n' "Refusing to overwrite existing command: $target" >&2
    exit 1
  fi
done

for source in "$commands_source"/*.md; do
  cp "$source" "$commands_root/$(basename -- "$source")"
done
printf '%s\n' "Installed ACC commands at $commands_root"
