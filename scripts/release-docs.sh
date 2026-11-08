#!/bin/sh
# Release documentation gate and release body (D-038).
#
#   scripts/release-docs.sh check <tag>   fail unless the release notes and
#                                          both user guides for <tag> exist and
#                                          the README links to the guides
#   scripts/release-docs.sh notes <tag> [ref]
#                                          print the release body: the release
#                                          notes plus links to the user guides
#                                          at <ref> (default: the tag itself;
#                                          main for releases older than D-038)
#   scripts/release-docs.sh links         fail if the README links to a user
#                                          guide that does not exist (CI)
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
repo_url=${KINFOLD_REPO_URL:-https://github.com/schmidt-software/kinfold}

guides() { echo "docs/user-guide/en/$1.md docs/user-guide/de/$1.md"; }

check() {
  tag=$1
  status=0
  for f in "docs/release-notes/$tag.md" $(guides "$tag"); do
    if [ ! -s "$f" ]; then
      echo "missing $f: every release needs release notes and the English and German user guide" >&2
      status=1
    fi
  done
  for f in $(guides "$tag"); do
    if ! grep -qF "($f)" README.md; then
      echo "README.md does not link to $f (the user guide of the newest release)" >&2
      status=1
    fi
  done
  links || status=1
  return $status
}

links() {
  link_status=0
  for f in $(grep -o '(docs/user-guide/[^)]*\.md)' README.md | tr -d '()' | sort -u); do
    if [ ! -f "$f" ]; then
      echo "README.md links to missing $f" >&2
      link_status=1
    fi
  done
  return $link_status
}

notes() {
  tag=$1
  ref=${2:-$1}
  [ -f "docs/release-notes/$tag.md" ] && cat "docs/release-notes/$tag.md"
  cat <<EOF

## User guide

- English: [$tag user guide]($repo_url/blob/$ref/docs/user-guide/en/$tag.md)
- Deutsch: [$tag Benutzerhandbuch]($repo_url/blob/$ref/docs/user-guide/de/$tag.md)

Both guides are also attached to this release as Markdown files.
EOF
}

case "${1:-}" in
  check) check "${2:?usage: release-docs.sh check <tag>}" ;;
  notes) notes "${2:?usage: release-docs.sh notes <tag> [ref]}" "${3:-}" ;;
  links) links ;;
  *) echo "usage: release-docs.sh check <tag> | notes <tag> | links" >&2; exit 2 ;;
esac
