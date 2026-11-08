#!/bin/sh
set -eu

# Creates an isolated, temporary Docker network. No existing containers are modified.
command -v docker >/dev/null
command -v go >/dev/null
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/kinfold-integration.XXXXXX")
suffix=$(basename "$work")
network="$suffix"
controller="$suffix-controller"
alice="$suffix-alice"
bob="$suffix-bob"
charlie="$suffix-charlie"
image=${KINFOLD_TEST_IMAGE:-alpine/socat:latest}
network_id=
controller_id=
alice_id=
bob_id=
charlie_id=

cleanup() {
  for id in "$alice_id" "$bob_id" "$charlie_id" "$controller_id"; do
    if [ -n "$id" ]; then docker rm -f "$id" >/dev/null 2>&1 || true; fi
  done
  if [ -n "$network_id" ]; then docker network rm "$network_id" >/dev/null 2>&1 || true; fi
  case "$work" in
    "${TMPDIR:-/tmp}"/kinfold-integration.*) rm -rf "$work" ;;
    *) echo "Refusing to remove unexpected temporary path: $work" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

arch=$(docker info --format '{{.Architecture}}')
case "$arch" in
  aarch64|arm64) arch=arm64 ;;
  x86_64|amd64) arch=amd64 ;;
  *) echo "Unsupported Docker architecture: $arch" >&2; exit 1 ;;
esac
cd "$root"
go build -o "$work/kinfold-host" .
GOOS=linux GOARCH="$arch" go build -o "$work/kinfold" .
"$work/kinfold-host" init -data "$work/state" -server controller:8443
"$work/kinfold-host" keygen -id alice -key "$work/alice.key" -request "$work/alice.csr"
"$work/kinfold-host" approve -data "$work/state" -id alice -ip 10.77.0.1 -request "$work/alice.csr" -out "$work/alice.crt"
"$work/kinfold-host" export-ca -data "$work/state" -out "$work/ca.crt"
"$work/kinfold-host" enroll -server controller:8443 -key "$work/alice.key" -cert "$work/alice.crt" -ca "$work/ca.crt" -out "$work/alice.json"
"$work/kinfold-host" add-peer -data "$work/state" -id bob -ip 10.77.0.2 -out "$work/bob.json"
"$work/kinfold-host" add-peer -data "$work/state" -id charlie -ip 10.77.0.3 -out "$work/charlie.json"
"$work/kinfold-host" allow -data "$work/state" -from alice -to bob
"$work/kinfold-host" allow -data "$work/state" -from bob -to alice
network_id=$(docker network create "$network")
controller_id=$(docker run -d --name "$controller" --network "$network" --network-alias controller \
  --mount "type=bind,src=$work/kinfold,dst=/kinfold,readonly" \
  --mount "type=bind,src=$work/state,dst=/state,readonly" \
  --entrypoint /kinfold "$image" serve -data /state -listen :8443 -metrics 127.0.0.1:9100)
for peer in alice bob charlie; do
  case "$peer" in alice) name=$alice ;; bob) name=$bob ;; charlie) name=$charlie ;; esac
  id=$(docker run -d --name "$name" --network "$network" --cap-add NET_ADMIN --device /dev/net/tun \
    --mount "type=bind,src=$work/kinfold,dst=/kinfold,readonly" \
    --mount "type=bind,src=$work/$peer.json,dst=/credential.json,readonly" \
    --entrypoint /kinfold "$image" run -credential /credential.json -direct-listen :51900)
  case "$peer" in alice) alice_id=$id ;; bob) bob_id=$id ;; charlie) charlie_id=$id ;; esac
done

success=false
for _ in $(seq 1 20); do
  if docker exec "$alice" ping -c 1 -W 1 10.77.0.2 >/dev/null 2>&1; then
    success=true
    break
  fi
  sleep 1
done
if [ "$success" != true ]; then
  docker logs "$controller"; docker logs "$alice"; docker logs "$bob"
  echo "Tunnel ping failed" >&2
  exit 1
fi
docker exec "$bob" ping -c 1 -W 2 10.77.0.1 >/dev/null
echo "Bidirectional ICMP over real Linux TUN and relay: OK"
if ! docker exec "$controller" wget -qO- http://127.0.0.1:9100/metrics 2>/dev/null | grep -q '^kinfold_relay_pairings_total [1-9]'; then
  echo "Controller metrics missing or no relay pairing counted" >&2
  docker exec "$controller" wget -qO- http://127.0.0.1:9100/metrics >&2 || true
  exit 1
fi
echo "Controller metrics on loopback: OK"
# Alice learns Bob's signed direct endpoint with a configuration fetch and
# upgrades from the relay within a few seconds.
direct_ok=false
for _ in $(seq 1 40); do
  if docker logs "$alice" 2>&1 | grep -q 'msg="peer connected" peer=bob path=direct'; then
    direct_ok=true
    break
  fi
  sleep 0.5
done
if ! "$direct_ok"; then
  echo "Alice did not reach Bob over the direct path" >&2
  docker logs "$alice" >&2
  exit 1
fi
docker exec "$alice" ping -c 2 -W 2 10.77.0.2 >/dev/null
echo "Direct path between clients: OK"

if docker exec "$alice" ping -c 2 -W 1 10.77.0.3 >/dev/null 2>&1 ||
   docker exec "$charlie" ping -c 2 -W 1 10.77.0.1 >/dev/null 2>&1; then
  echo "Default-deny policy failed" >&2
  exit 1
fi
if docker logs "$alice" 2>&1 | grep -q 'msg="peer connected" peer=charlie' ||
   docker logs "$charlie" 2>&1 | grep -q 'msg="peer connected" peer=alice'; then
  echo "Unauthorized peers established a relay connection" >&2
  exit 1
fi
echo "Default-deny for an unauthorized peer: OK"

docker exec -d "$bob" /bin/sh -c 'printf "vpn-ok\n" | nc -l -p 9090'
tcp_ok=false
for _ in $(seq 1 5); do
  if [ "$(docker exec "$alice" /bin/sh -c 'nc -w 2 10.77.0.2 9090' 2>/dev/null || true)" = "vpn-ok" ]; then
    tcp_ok=true
    break
  fi
  sleep 1
done
if [ "$tcp_ok" != true ]; then
  echo "TCP transfer failed" >&2
  exit 1
fi
echo "TCP transfer through the tunnel: OK"

"$work/kinfold-host" ipv6-network -data "$work/state" -network fd77::/64
"$work/kinfold-host" ipv6-assign -data "$work/state" -id alice -ip fd77::1
"$work/kinfold-host" ipv6-assign -data "$work/state" -id bob -ip fd77::2
"$work/kinfold-host" ipv6-assign -data "$work/state" -id charlie -ip fd77::3
ipv6_ready=false
for _ in $(seq 1 30); do
  if docker exec "$alice" ping6 -c 1 -W 1 fd77::2 >/dev/null 2>&1 &&
     docker exec "$bob" ping6 -c 1 -W 1 fd77::1 >/dev/null 2>&1 &&
     docker exec "$charlie" ip -6 addr show dev kf0 2>/dev/null | grep -q 'fd77::3/64'; then
    ipv6_ready=true
    break
  fi
  sleep 1
done
if [ "$ipv6_ready" != true ]; then
  docker logs "$controller"; docker logs "$alice"; docker logs "$bob"
  echo "IPv6 tunnel ping failed" >&2
  exit 1
fi
if ! docker exec "$alice" ping -c 1 -W 2 -s 1252 10.77.0.2 >/dev/null ||
   ! docker exec "$alice" ping6 -c 1 -W 2 -s 1232 fd77::2 >/dev/null; then
  echo "IPv4 or IPv6 packet at tunnel MTU failed" >&2
  exit 1
fi
if docker exec "$alice" ping6 -c 2 -W 1 fd77::3 >/dev/null 2>&1 ||
   docker exec "$charlie" ping6 -c 2 -W 1 fd77::1 >/dev/null 2>&1; then
  echo "IPv6 default-deny policy failed" >&2
  exit 1
fi
docker exec -d "$bob" /bin/sh -c 'printf "vpn6-ok\n" | socat - TCP6-LISTEN:9091,reuseaddr'
ipv6_tcp=false
for _ in $(seq 1 5); do
  if [ "$(docker exec "$alice" /bin/sh -c 'socat -T 2 - TCP6:[fd77::2]:9091' 2>/dev/null || true)" = "vpn6-ok" ]; then
    ipv6_tcp=true
    break
  fi
  sleep 1
done
if [ "$ipv6_tcp" != true ]; then
  echo "IPv6 TCP transfer failed" >&2
  exit 1
fi
echo "IPv6 bidirectional ICMP, default-deny, and TCP: OK"

docker restart "$controller" >/dev/null
reconnected=false
for _ in $(seq 1 20); do
  if docker exec "$alice" ping -c 1 -W 1 10.77.0.2 >/dev/null 2>&1; then
    reconnected=true
    break
  fi
  sleep 1
done
if [ "$reconnected" != true ]; then
  echo "Tunnel did not reconnect after controller restart" >&2
  exit 1
fi
echo "Reconnect after controller restart: OK"

cp "$work/state/state.json" "$work/state.saved"
sed '$s/}/, "config": null}/' "$work/state.saved" > "$work/state/state.json"
failed_closed=false
for _ in $(seq 1 10); do
  if docker logs "$controller" 2>&1 | grep -q 'controller configuration unavailable; relay closed'; then
    failed_closed=true
    break
  fi
  sleep 1
done
if [ "$failed_closed" != true ]; then
  echo "Controller did not fail closed on invalid state" >&2
  exit 1
fi
# Relay sessions end at once; direct sessions end when the clients' next
# configuration fetch is refused (one poll interval).
sleep 4
if docker exec "$alice" /kinfold status -credential /credential.json >/dev/null 2>&1 ||
   docker exec "$alice" ping -c 2 -W 2 10.77.0.2 >/dev/null 2>&1; then
  echo "Invalid state allowed traffic" >&2
  exit 1
fi
mv "$work/state.saved" "$work/state/state.json"
recovered=false
for _ in $(seq 1 20); do
  if docker exec "$alice" ping -c 1 -W 1 10.77.0.2 >/dev/null 2>&1; then
    recovered=true
    break
  fi
  sleep 1
done
if [ "$recovered" != true ]; then
  echo "Controller did not recover from invalid state" >&2
  exit 1
fi
echo "Ambiguous controller state fails closed and recovers: OK"

"$work/kinfold-host" renew-server -data "$work/state"
identity_changed=false
for _ in $(seq 1 10); do
  if docker logs "$controller" 2>&1 | grep -q 'controller TLS identity changed; restart required'; then
    identity_changed=true
    break
  fi
  sleep 1
done
if [ "$identity_changed" != true ]; then
  echo "Controller did not fail closed after certificate renewal" >&2
  exit 1
fi
if docker exec "$alice" /kinfold status -credential /credential.json >/dev/null 2>&1; then
  echo "Controller accepted requests after certificate renewal without restart" >&2
  exit 1
fi
docker restart "$controller" >/dev/null
renewed=false
for _ in $(seq 1 30); do
  if docker exec "$alice" ping -c 1 -W 1 10.77.0.2 >/dev/null 2>&1 &&
     docker exec "$alice" ping6 -c 1 -W 1 fd77::2 >/dev/null 2>&1; then
    renewed=true
    break
  fi
  sleep 1
done
if [ "$renewed" != true ]; then
  docker logs "$controller"; docker logs "$alice"; docker logs "$bob"
  echo "Tunnel did not reconnect after server certificate renewal" >&2
  exit 1
fi
echo "Server certificate renewal and restart: OK"

"$work/kinfold-host" deny -data "$work/state" -from alice -to bob
updated=false
for _ in $(seq 1 10); do
  if docker exec "$alice" /kinfold status -credential /credential.json 2>/dev/null | grep -q '1 directional allow rules'; then
    updated=true
    break
  fi
  sleep 1
done
if [ "$updated" != true ]; then
  echo "Controller did not load new policy" >&2
  exit 1
fi
# The running client applies the change with its next fetch (2 s poll);
# a direct session is not cut by the relay.
sleep 3
if docker exec "$alice" ping -c 2 -W 2 10.77.0.2 >/dev/null 2>&1; then
  echo "Active stale-policy session was not terminated" >&2
  exit 1
fi
if docker exec "$alice" ping6 -c 2 -W 2 fd77::2 >/dev/null 2>&1; then
  echo "IPv6 stale-policy session was not terminated" >&2
  exit 1
fi
echo "Policy update invalidates active sessions: OK"
"$work/kinfold-host" allow -data "$work/state" -from alice -to bob
updated=false
for _ in $(seq 1 10); do
  if docker exec "$alice" /kinfold status -credential /credential.json 2>/dev/null | grep -q '2 directional allow rules'; then
    updated=true
    break
  fi
  sleep 1
done
if [ "$updated" != true ]; then
  echo "Controller did not reload restored policy" >&2
  exit 1
fi
reconnected=false
for _ in $(seq 1 20); do
  if docker exec "$alice" ping -c 1 -W 1 10.77.0.2 >/dev/null 2>&1; then
    reconnected=true
    break
  fi
  sleep 1
done
if [ "$reconnected" != true ]; then
  echo "Updated clients did not reconnect" >&2
  exit 1
fi

"$work/kinfold-host" keygen -id bob -key "$work/bob-new.key" -request "$work/bob-new.csr"
"$work/kinfold-host" rotate-peer -data "$work/state" -id bob -request "$work/bob-new.csr" -out "$work/bob-new.crt"
"$work/kinfold-host" enroll -server controller:8443 -key "$work/bob-new.key" -cert "$work/bob-new.crt" -ca "$work/ca.crt" -out "$work/bob-new.json"
rotated=false
for _ in $(seq 1 15); do
  if ! docker exec "$bob" /kinfold status -credential /credential.json >/dev/null 2>&1; then
    rotated=true
    break
  fi
  sleep 1
done
if [ "$rotated" != true ]; then
  echo "Old device credential remained authorized after rotation" >&2
  exit 1
fi
docker rm -f "$bob_id" >/dev/null
bob_id=
bob_id=$(docker run -d --name "$bob" --network "$network" --cap-add NET_ADMIN --device /dev/net/tun \
  --mount "type=bind,src=$work/kinfold,dst=/kinfold,readonly" \
  --mount "type=bind,src=$work/bob-new.json,dst=/credential.json,readonly" \
  --entrypoint /kinfold "$image" run -credential /credential.json -direct-listen :51900)
rotated=false
for _ in $(seq 1 30); do
  if docker exec "$alice" ping -c 1 -W 1 10.77.0.2 >/dev/null 2>&1 &&
     docker exec "$alice" ping6 -c 1 -W 1 fd77::2 >/dev/null 2>&1; then
    rotated=true
    break
  fi
  sleep 1
done
if [ "$rotated" != true ]; then
  docker logs "$controller"; docker logs "$alice"; docker logs "$bob"
  echo "Rotated device could not reconnect" >&2
  exit 1
fi
echo "Offline device key rotation and dual-stack reconnect: OK"

cat > "$work/service-policy.json" <<'EOF'
{"allowed":[
  {"from":"alice","to":"bob","protocol":"icmp"},
  {"from":"bob","to":"alice","protocol":"icmp"},
  {"from":"alice","to":"bob","protocol":"icmp6"},
  {"from":"bob","to":"alice","protocol":"icmp6"},
  {"from":"alice","to":"bob","protocol":"tcp","port":9092},
  {"from":"bob","to":"alice","protocol":"tcp","port":12002},
  {"from":"bob","to":"alice","protocol":"tcp","port":12003}
]}
EOF
"$work/kinfold-host" service-apply -data "$work/state" -rules "$work/service-policy.json"
service_ready=false
for _ in $(seq 1 30); do
  if docker exec "$alice" /kinfold status -credential /credential.json 2>/dev/null | grep -q '7 directional service rules' &&
     docker exec "$alice" ping -c 1 -W 1 10.77.0.2 >/dev/null 2>&1 &&
     docker exec "$alice" ping6 -c 1 -W 1 fd77::2 >/dev/null 2>&1; then
    service_ready=true
    break
  fi
  sleep 1
done
if [ "$service_ready" != true ]; then
  echo "Service policy failed to allow dual-stack ICMP" >&2
  exit 1
fi
docker exec -d "$bob" /bin/sh -c 'printf "service4-ok\n" | socat -T 5 - TCP4-LISTEN:9092,reuseaddr'
tcp4_filtered=false
for _ in $(seq 1 5); do
  if [ "$(docker exec "$alice" /bin/sh -c 'socat -T 2 - TCP4:10.77.0.2:9092,sourceport=12002' 2>/dev/null || true)" = "service4-ok" ]; then
    tcp4_filtered=true
    break
  fi
  sleep 1
done
if [ "$tcp4_filtered" != true ]; then
  echo "IPv4 TCP transfer with explicit bidirectional service rules failed" >&2
  exit 1
fi
docker exec -d "$bob" /bin/sh -c 'printf "service6-ok\n" | socat -T 5 - TCP6-LISTEN:9092,reuseaddr'
tcp6_filtered=false
for _ in $(seq 1 5); do
  if [ "$(docker exec "$alice" /bin/sh -c 'socat -T 2 - TCP6:[fd77::2]:9092,sourceport=12003' 2>/dev/null || true)" = "service6-ok" ]; then
    tcp6_filtered=true
    break
  fi
  sleep 1
done
if [ "$tcp6_filtered" != true ]; then
  echo "IPv6 TCP transfer with explicit bidirectional service rules failed" >&2
  exit 1
fi
"$work/kinfold-host" service-deny -data "$work/state" -from alice -to bob -protocol icmp6
service_updated=false
for _ in $(seq 1 30); do
  if docker exec "$alice" /kinfold status -credential /credential.json 2>/dev/null | grep -q '6 directional service rules' &&
     docker exec "$alice" ping -c 1 -W 1 10.77.0.2 >/dev/null 2>&1 &&
     ! docker exec "$alice" ping6 -c 2 -W 1 fd77::2 >/dev/null 2>&1; then
    service_updated=true
    break
  fi
  sleep 1
done
if [ "$service_updated" != true ]; then
  echo "Service policy update did not deny IPv6 ICMP while preserving IPv4" >&2
  exit 1
fi
echo "Experimental service filtering and dual-stack update: OK"

"$work/kinfold-host" remove-peer -data "$work/state" -id bob
ready=false
for _ in $(seq 1 10); do
  if ! docker exec "$bob" /kinfold status -credential /credential.json >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 1
done
if [ "$ready" != true ]; then
  echo "Controller did not load peer removal" >&2
  exit 1
fi
if docker exec "$bob" /kinfold status -credential /credential.json >/dev/null 2>&1; then
  echo "Revoked peer still authorized" >&2
  exit 1
fi
# Alice drops the link with her next fetch; Bob closes his tunnel when the
# controller refuses his fetch (403). Both within one poll interval.
sleep 3
if docker exec "$alice" ping -c 2 -W 2 10.77.0.2 >/dev/null 2>&1; then
  echo "Revoked peer still reachable" >&2
  exit 1
fi
echo "Revocation without controller or client restart: OK"

docker stop -t 5 "$alice" >/dev/null
exit_code=$(docker inspect -f '{{.State.ExitCode}}' "$alice")
if [ "$exit_code" != 0 ]; then
  echo "Client did not shut down cleanly (exit $exit_code)" >&2
  exit 1
fi
echo "Graceful TUN shutdown: OK"
