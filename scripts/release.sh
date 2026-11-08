#!/bin/sh
# Builds reproducible release binaries and SHA-256 checksums.
#
#   scripts/release.sh v0.2.0-alpha [output-dir]
#
# The same commit and Go toolchain (pinned in go.mod) produce bit-identical
# binaries: paths are trimmed, cgo is off, the build ID is empty and the
# version is injected via -ldflags.
set -eu

version=${1:?usage: release.sh <version> [output-dir]}
out=${2:-dist}
case "$version" in
  v[0-9]*) ;;
  *) echo "version must start with v and a digit: $version" >&2; exit 1 ;;
esac

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
if [ -n "$(git status --porcelain)" ]; then
  echo "working tree is not clean; refusing to build a release" >&2
  exit 1
fi

rm -rf "$out"
mkdir -p "$out"
ldflags="-s -w -buildid= -X github.com/schmidt-software/kinfold/internal/app.Version=$version"
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
  goos=${target%/*}
  goarch=${target#*/}
  name="kinfold-$version-$goos-$goarch"
  CGO_ENABLED=0 GOOS=$goos GOARCH=$goarch go build -trimpath -ldflags "$ldflags" -o "$out/$name" .
  echo "built $out/$name"
done
cp packaging/systemd/*.service "$out/"
(
  cd "$out"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum kinfold-v* *.service > SHA256SUMS
  else
    shasum -a 256 kinfold-v* *.service > SHA256SUMS
  fi
)
echo "checksums in $out/SHA256SUMS"
