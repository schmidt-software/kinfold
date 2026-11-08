#!/bin/sh
# Print a Markdown command reference for the binary at a git ref (default:
# HEAD): the command overview from `help` and the options of every command
# from `<command> -h`. Used for the appendix of the user guides.
#
#   sh scripts/cli-reference.sh v0.5.0-alpha > reference.md
set -eu

ref=${1:-HEAD}
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/kinfold-cliref.XXXXXX")
cleanup() {
  git -C "$root" worktree remove --force "$work/src" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT HUP INT TERM

git -C "$root" worktree add --detach "$work/src" "$ref" >/dev/null 2>&1
(cd "$work/src" && CGO_ENABLED=0 go build -o "$work/bin" .)

echo '```text'
"$work/bin" help 2>&1 || true
echo '```'
# Command names are the first word of indented lines in the help output.
"$work/bin" help 2>&1 | sed -n 's/^  \([a-z][a-z0-9-]*\) .*/\1/p' | while read -r cmd; do
  echo
  echo "### \`$cmd\`"
  echo
  echo '```text'
  "$work/bin" "$cmd" -h 2>&1 | sed 's/[[:space:]]*$//' || true
  echo '```'
done
