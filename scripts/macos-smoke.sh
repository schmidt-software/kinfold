#!/bin/sh
# End-to-end smoke test of the macOS client (utun) against a Linux client in
# Docker. Requires macOS, Docker, and sudo for the macOS client only:
#
#   sh scripts/macos-smoke.sh
#
# The controller runs on this Mac and is reached by both clients through the
# Mac's LAN address. Everything is temporary and removed on exit.
set -eu

[ "$(uname -s)" = Darwin ] || { echo "macOS only" >&2; exit 1; }
command -v docker >/dev/null
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/kinfold-macos.XXXXXX")
chmod 700 "$work"
lan=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || true)
[ -n "$lan" ] || { echo "no LAN address on en0/en1" >&2; exit 1; }
port=18443
image=${KINFOLD_TEST_IMAGE:-alpine/socat:latest}
controller_pid=
client_pid=
container=

cleanup() {
  [ -n "$client_pid" ] && sudo kill "$client_pid" 2>/dev/null || true
  [ -n "$controller_pid" ] && kill "$controller_pid" 2>/dev/null || true
  [ -n "$container" ] && docker rm -f "$container" >/dev/null 2>&1 || true
  case "$work" in "${TMPDIR:-/tmp}"/kinfold-macos.*) rm -rf "$work" ;; esac
}
trap cleanup EXIT HUP INT TERM

arch=$(docker info --format '{{.Architecture}}')
case "$arch" in aarch64|arm64) arch=arm64 ;; x86_64|amd64) arch=amd64 ;; esac
cd "$root"
go build -o "$work/kinfold" .
GOOS=linux GOARCH="$arch" go build -o "$work/kinfold-linux" .
"$work/kinfold" init -data "$work/state" -server "$lan:$port" -network 10.88.0.0/24 >/dev/null
"$work/kinfold" add-peer -data "$work/state" -id mac -ip 10.88.0.1 -out "$work/mac.json" >/dev/null
"$work/kinfold" add-peer -data "$work/state" -id linux -ip 10.88.0.2 -out "$work/linux.json" >/dev/null
"$work/kinfold" allow -data "$work/state" -from mac -to linux >/dev/null
"$work/kinfold" allow -data "$work/state" -from linux -to mac >/dev/null
"$work/kinfold" ipv6-network -data "$work/state" -network fd88::/64 >/dev/null
"$work/kinfold" ipv6-assign -data "$work/state" -id mac -ip fd88::1 >/dev/null
"$work/kinfold" ipv6-assign -data "$work/state" -id linux -ip fd88::2 >/dev/null

"$work/kinfold" serve -data "$work/state" -listen ":$port" >"$work/controller.log" 2>&1 &
controller_pid=$!
sleep 1
container=$(docker run -d --cap-add NET_ADMIN --device /dev/net/tun \
  --mount "type=bind,src=$work/kinfold-linux,dst=/kinfold,readonly" \
  --mount "type=bind,src=$work/linux.json,dst=/credential.json,readonly" \
  --entrypoint /kinfold "$image" run -credential /credential.json)

echo "Starting the macOS client (sudo needed for the utun interface)..."
sudo "$work/kinfold" run -credential "$work/mac.json" >"$work/mac.log" 2>&1 &
client_pid=$!

ok=false
for _ in $(seq 1 30); do
  if ping -c 1 -t 2 10.88.0.2 >/dev/null 2>&1; then ok=true; break; fi
  sleep 1
done
iface=$(grep -o 'interface=utun[0-9]*' "$work/mac.log" | head -1 | cut -d= -f2)
if [ "$ok" != true ]; then
  echo "FAILED: no ping from macOS (10.88.0.1) to Linux (10.88.0.2)" >&2
  echo "--- macOS client"; cat "$work/mac.log"
  echo "--- Linux client"; docker logs "$container" 2>&1 | tail -20
  echo "--- controller"; tail -20 "$work/controller.log"
  exit 1
fi
docker exec "$container" ping -c 2 -W 2 10.88.0.1 >/dev/null
echo "macOS client on $iface reaches the Linux client and back through the tunnel (IPv4): OK"
if ! ping6 -c 2 fd88::2 >/dev/null 2>&1 || ! docker exec "$container" ping6 -c 2 -W 2 fd88::1 >/dev/null; then
  echo "FAILED: no IPv6 ping between macOS (fd88::1) and Linux (fd88::2)" >&2
  echo "--- macOS client"; cat "$work/mac.log"
  ifconfig "$iface" || true
  netstat -rn -f inet6 | grep -i "$iface" || true
  exit 1
fi
echo "IPv6 through the tunnel in both directions: OK"
