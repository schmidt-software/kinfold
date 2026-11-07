<p align="center">
  <img src="docs/assets/logo.png" alt="Kinfold logo: a ring of six network nodes joined through a central relay core" width="256">
</p>

# Kinfold

An **experimental, self-hostable IPv4/IPv6 overlay network prototype**. It implements its own protocol and is not compatible with any other VPN or overlay product.

> **Do not use for production or to protect confidential data.** There has been no independent security audit, there is no high availability, and important limitations in operation and revocation remain. In particular, the controller is a complete trust anchor.

## Current state

- One private IPv4 network and optionally one IPv6 ULA network with up to 32 explicitly authorized devices; one Linux TUN interface per device.
- Self-hostable controller and TCP relay; no registration with an external service.
- Controller and device identities are certificates; the controller connection uses mutual TLS 1.3.
- An additional, mutually authenticated TLS 1.3 connection **between devices** runs through the relay. Certificates are checked against the member list delivered by the controller.
- Established peer connections get an I/O deadline at the earliest expiry of the device, controller and CA certificates involved; data already buffered by TLS is not delivered to the packet parser after expiry either. The connection is then re-established. This local deadline is neither a tamper-proof clock nor a revocation guarantee.
- IPv4 and optional IPv6 unicast packets only between the assigned device addresses; source and destination addresses are checked against spoofing. Automatic reconnection after connection loss.
- The fixed tunnel MTU is 1280 bytes. Larger outgoing packets are dropped; an incoming frame above this limit terminates the affected peer session.
- Reconnection attempts use exponential backoff with random jitter up to 30 seconds; after 30 seconds of stable connection the backoff is reset. A peer session ends when a single frame cannot be written within 10 seconds, and TCP keepalive detects a dead relay connection after about 30 seconds, so a broken path is replaced quickly.
- On a write error at the tunnel device the client terminates the tunnel with an error instead of only re-establishing the affected peer connection.
- On controller shutdown, relay sessions are terminated immediately and running HTTP requests are awaited for up to five seconds; on timeout the error is reported and the server is closed.
- Controller state, credentials and received configuration are parsed strictly: unknown or duplicate JSON fields, oversized documents and trailing data are rejected.
- Controller response headers are limited to 16 KiB when fetching the configuration and when establishing a relay connection.
- On load, the controller additionally checks the CA and server key pairs, the server certificate including hostname and validity, and the CA signatures of the registered device certificates.
- Different devices must not share a public key even with different certificates; inconsistent configurations are rejected.
- New networks deny traffic between devices by default; static directional allow rules can be set via the CLI.
- The relay and current clients only establish a peer session for device pairs with at least one directional allow rule; traffic is still checked separately per direction.
- CLI for creating, adding and removing devices and for showing the members.
- Optional offline enrollment: the device generates its private key itself; the administrator verifies and approves a signed certificate request.

The member list is loaded at startup over authenticated TLS and is **not separately signed**. The controller controls the member list and holds the CA key. With the older `add-peer` it additionally generates the device key; with the offline enrollment described below the key is created on the device. A compromised controller can admit devices and manipulate connections by swapping certificates. A relay that only forwards packets, and whose controller/CA is not compromised, does not see the content of the inner TLS connection; it does see metadata such as the devices involved and data volume.

There are **no** direct peer connections, NAT hole punching, UDP transport, Ethernet/bridging, multicast, subnet gateways, stateful ACLs, GUI or interoperability with other VPN products yet. `status` shows the authorized member list, not the live connection state. The architecture decisions are in [docs/DECISIONS.md](docs/DECISIONS.md); every non-trivial decision made during development is logged in [docs/DECISION-LOG.md](docs/DECISION-LOG.md).

The [security model](docs/SECURITY-MODEL.md) separates the properties of the prototype from the production requirements that are still open, in particular trust, policy and time-bound revocation.

## Note on the rename

Up to version `v0.1-copilot` the project was called `my-zerotier`. The rename to Kinfold changed the binary (`kinfold`), the default name of the TUN interface (`kf0` instead of `mzt0`), the variable `KINFOLD_TEST_IMAGE` and the internal HTTP header for the configuration revision. Because of the header, older clients are not compatible with a new controller and vice versa: update the controller and **all clients** together. Existing controller state and credentials remain valid; newly created CAs are named `Kinfold CA`.

## Quick demonstration with Docker

Requirements: the Go version pinned in `go.mod` (Go downloads it automatically), Docker with Linux containers, `NET_ADMIN` and `/dev/net/tun`. The script uses the Docker image `alpine/socat:latest` by default and can download it if needed. `KINFOLD_TEST_IMAGE` selects a suitable existing image with a shell, `ip`, `ping`, `ping6`, `nc` and `socat`.

```sh
sh scripts/integration-docker.sh
```

The script builds a Linux binary, creates temporary credentials and an isolated Docker network, starts three clients and checks IPv4/IPv6 ICMP and TCP, policy, reconnection and revocation. It removes its own containers, its network and the temporary files on exit. It does not modify existing containers.

## Manual setup

The controller runs on Linux or macOS; the VPN client currently requires **Linux**, `/dev/net/tun`, the `ip` command from iproute2 or BusyBox, and administrator rights or `CAP_NET_ADMIN`. The virtual network must not overlap with existing local networks or routes.

1. Build and initialize on the controller. Replace `vpn.example.com:8443` with the DNS name or IP address and TCP port of the controller reachable by all clients. The name is embedded in the server certificate and must match the name used.

   ```sh
   go build -o kinfold .
   ./kinfold init -data controller-data \
     -server vpn.example.com:8443 -network 10.77.0.0/24
   mkdir -m 700 credentials
   ./kinfold add-peer -data controller-data \
     -id alice -ip 10.77.0.1 -out credentials/alice.json
   ./kinfold add-peer -data controller-data \
     -id bob -ip 10.77.0.2 -out credentials/bob.json
   ./kinfold allow -data controller-data -from alice -to bob
   ./kinfold allow -data controller-data -from bob -to alice
   ./kinfold serve -data controller-data -listen :8443
   ```

2. Build a binary of the matching architecture for the Linux devices, for example:

   ```sh
   GOOS=linux GOARCH=amd64 go build -o kinfold-linux .
   ```

   Use `GOARCH=arm64` for Linux ARM64. Transfer the binary and **only the matching** credential file to each device over a trusted, encrypted channel. The file contains the device's private key and must remain confidential.

3. Start Alice and Bob with their own credential file:

   ```sh
   sudo ./kinfold-linux run -credential alice.json
   # On Bob instead: -credential bob.json
   ```

   After the connection is established, `ping 10.77.0.2` should work on Alice and `ping 10.77.0.1` on Bob. The local firewall must allow ICMP or the application ports used. The controller must be reachable from both devices over TCP. `Ctrl-C` stops the client; the non-persistent TUN interface is removed.

`./kinfold-linux status -credential alice.json` queries the configuration. `kinfold help` and `kinfold <command> -h` show the available options; `kinfold version` prints the build (version, commit, Go version, platform).

`serve` and `run` log to stderr via `log/slog`. `-log-format text|json` selects the format, `-log-level debug|info|warn|error` the minimum level (default `info`). Per-packet drop messages (MTU exceeded, peer queue full) are logged at `debug` level so they cannot flood production logs.

Administrators can use `./kinfold check-config -data controller-data -credential admin-peer.json` to check whether the authenticated controller has loaded the same configuration as a local snapshot of the state file. The credential must belong to a device that is still authorized. The command prints both configuration hashes and returns an error on mismatch or reachability failure. It does not prove that clients have already adopted the configuration.

## Optional IPv6

Before enabling, **update all clients and the controller**: older binaries with a strict JSON decoder may reject the additional fields. On the controller, configure a ULA `/64` that does not collide with other networks and unique device addresses:

```sh
./kinfold ipv6-network -data controller-data -network fd77::/64
./kinfold ipv6-assign -data controller-data -id alice -ip fd77::1
./kinfold ipv6-assign -data controller-data -id bob -ip fd77::2
```

After the asynchronous reload and reconnection, `ping -6 fd77::2` should work on Alice. IPv6 requires a working IPv4 overlay; a device without an IPv6 assignment stays IPv4-only. The existing directional allow rules apply to both address families. Use `ipv6-assign -id alice -ip none` to remove an assignment, and only after all assignments are removed, `ipv6-network -network none` to disable the IPv6 network. Changes take effect asynchronously; existing sessions are disconnected after adoption.

## Offline enrollment with a local key

As an alternative to `add-peer`, a device can generate its own private key. The procedure is **experimental and offline**: the request proves possession of the key but does not authenticate the person or the device. Request and CA must be authenticated and compared independently; there are no one-time tokens, request expiry or online approval yet.

When reading them, the CLI limits requests, private keys and certificate files to 64 KiB each; larger files are rejected.

1. On the device:

   ```sh
   ./kinfold-linux keygen -id alice -key alice.key -request alice.csr
   shasum -a 256 alice.csr
   ```

   Send only `alice.csr` to the administrator. Compare the SHA-256 of the request over an independent trusted channel and verify the device identity. **Never transfer `alice.key`.**

2. On the controller, after verifying identity and fingerprint:

   ```sh
   shasum -a 256 alice.csr
   ./kinfold approve -data controller-data -id alice \
     -ip 10.77.0.1 -request alice.csr -out alice.crt
   ./kinfold export-ca -data controller-data -out ca.crt
   openssl x509 -in ca.crt -noout -fingerprint -sha256
   ```

   Transfer `alice.crt` and `ca.crt` to the device and communicate the CA fingerprint independently and trustworthily. The controller file is modified as with `add-peer`; controller and current clients reload changes asynchronously.

3. On the device, compare the CA fingerprint and create the private credential file:

   ```sh
   openssl x509 -in ca.crt -noout -fingerprint -sha256
   ./kinfold-linux enroll -server vpn.example.com:8443 \
     -key alice.key -cert alice.crt -ca ca.crt -out alice.json
   sudo ./kinfold-linux run -credential alice.json
   ```

   `enroll` checks that certificate and private key match and that the certificate was issued by the given CA. The user's comparison of the CA fingerprint is still required. Both `alice.key` and `alice.json` contain private key material and must remain confidential; new files are created with mode `0600` and never overwritten.

## Changes and revocation

`add-peer`, `approve`, `rotate-peer`, `remove-peer`, `policy-enable`, `allow`, `deny`, `ipv6-network` and `ipv6-assign` modify the controller file. On Linux and macOS an advisory file lock prevents concurrent modifications by these CLI commands; a competing command fails and must be re-run. The file `.state.lock` must not be deleted during operation. Manual edits, older binaries and file systems without reliable `flock` bypass this protection; it does not replace a transactional database. The running controller checks the file about once per second and terminates all active relay connections on change. Current clients poll the configuration every 2 seconds over one reused connection and recreate the tunnel on change. If the controller cannot be reached, a client keeps its tunnel for up to 30 seconds and then closes it until the controller answers again; a failed tunnel restart after a change is retried instead of ending the client. The CLI only confirms that the file was written, **not** that it was loaded or fully enforced. If the file is corrupt, cryptographically inconsistent or unreadable, or if the server certificate is invalid, the controller closes connections and rejects new requests until the state is valid again. Changes to the CA or server certificate require a controller restart.

File and directory entry are synchronized; this requires a file system with a working `fsync`. If synchronization fails after the write, the change may already be visible but its durability is uncertain. Check state and output files before retrying. Multiple files are not written as a transaction.

New networks use a default-deny policy. Without the optional service filter, `allow -from alice -to bob` permits all IPv4 and IPv6 packets from Alice to Bob; reply packets need the reverse rule. `deny` removes a rule. The basic policy applies on sender and receiver but is not a stateful firewall and does not filter ports or protocols itself. A state file from before policy support (no `policy` section) denies all peer traffic, and `serve` refuses to start with it until `policy-enable -data controller-data` has added an empty default-deny policy; set the desired rules afterwards. Missing rules never mean allow-all.

### Experimental service filter

Optionally, `service-enable -data controller-data` adds an **additional default-deny filter for all directions** on top of the device rules; immediately after enabling, all traffic is dropped. Update the controller and **all clients** first: older strict decoders do not understand the additional field. Changes take effect asynchronously; existing sessions are disconnected after adoption.

Alternatively, `service-apply` enables or replaces the complete rule set in one atomic write. Example `services.json`:

```json
{"allowed":[
  {"from":"alice","to":"bob","protocol":"icmp"},
  {"from":"bob","to":"alice","protocol":"icmp"},
  {"from":"alice","to":"bob","protocol":"udp","port":53}
]}
```

```sh
./kinfold service-apply -data controller-data -rules services.json
```

The format contains only the required `allowed` array; `{"allowed":[]}` blocks all services. Invalid, duplicate rules or rules not covered by a device rule are rejected before writing. The atomic replacement only concerns the local file, not simultaneous enforcement on all clients.

For incremental changes:

```sh
./kinfold service-enable -data controller-data
./kinfold service-allow -data controller-data -from alice -to bob -protocol udp -port 53
./kinfold service-allow -data controller-data -from alice -to bob -protocol icmp
./kinfold service-allow -data controller-data -from bob -to alice -protocol icmp
./kinfold service-allow -data controller-data -from alice -to bob -protocol icmp6
./kinfold service-allow -data controller-data -from bob -to alice -protocol icmp6
```

Every service rule requires the corresponding device rule; at most 4096 rules are allowed. `service-deny` with the same parameters removes a rule; `deny` or `remove-peer` removes the associated service rules. TCP and UDP use exact **destination ports** (1–65535); `icmp` and `icmp6` allow all respective ICMP types without a port. Other protocols, IPv4 fragments and options, and IPv6 extension headers including fragments are dropped. There is no automatic return-traffic rule: TCP/UDP replies to changing client ports require explicit reverse rules and are therefore of limited practical use. ICMP errors are not filtered per connection. Operating system firewalls remain necessary.

The rules apply on current senders and receivers, not in the encrypted relay. A tampered endpoint can bypass its local rules; correct receivers check independently. There is deliberately no CLI switch to fall back to the less restrictive old policy. This experimental feature is not a production-grade replacement for a stateful firewall or a proof of revocation.

An updated relay rejects sessions between two devices when no allow rule exists in either direction; current clients do not attempt such connections. A rule in only one direction is enough for the shared session but does not allow return traffic. This additional relay check does not replace the direction check on the receiver and does not limit bandwidth.

**Important limit:** Older client binaries ignore the policy. The relay requires the hash of the current configuration on connection setup and rejects unmodified old clients and clients with an outdated configuration. The hash is **not** a proof of integrity for the client software: a tampered client can reproduce it. All participants must be updated; existing sessions are only terminated after the asynchronous reload. This policy does not yet meet the requirements for production-grade access control or time-bound revocation.

```sh
./kinfold remove-peer -data controller-data -id bob
# Controller and current clients adopt the change asynchronously.
```

Do not check in or share the controller state and the credentials. The folder `controller-data` contains in particular the CA private key; `credentials` contains the device keys. The default paths are listed in `.gitignore`, other paths are not. Back up the controller state encrypted. Deleting or losing the CA key requires re-creation and redistribution of all credentials.

`add-peer`, `approve` and `rotate-peer` first write the new credential or certificate file and then update the controller state. The two files do not form a transaction: on failure an output file may remain without a matching entry in the controller state. Check state and output file before retrying; do not assume that a created file is already authorized.

## Rotating a device key offline

An existing device can create a **new** local key and request with `keygen`. The administrator must verify identity and request fingerprint independently, as in offline enrollment. The certificate is then replaced on the controller; IPv4/IPv6 addresses and allow rules are preserved:

```sh
# On the device:
./kinfold-linux keygen -id alice -key alice-new.key -request alice-new.csr
# After identity and fingerprint verification, on the controller:
./kinfold rotate-peer -data controller-data -id alice -request alice-new.csr -out alice-new.crt
# On the device, after independent verification of the CA:
./kinfold-linux enroll -server vpn.example.com:8443 \
  -key alice-new.key -cert alice-new.crt -ca ca.crt -out alice-new.json
sudo ./kinfold-linux run -credential alice-new.json
```

After the state is adopted, the old certificate is no longer accepted and active relay sessions are terminated. The device must stop the old client and start with the new credential; there is no uninterrupted rotation or guaranteed revocation deadline. The controller adopts changes asynchronously; a write confirmation is not proof of enforcement. An old backup can re-authorize the previous key, since there is no rollback protection.

The controller stores fingerprints of public device keys that were already issued and rejects their reuse even after rotation or removal. For existing states the history starts with the devices still registered at the time of the first such change; keys removed or rotated earlier are unknown. It is limited to 32,768 entries; after that new keys are rejected. Requests themselves are neither time-limited nor single-use before their first approval. If an old backup is restored, the state is edited manually, or the history is lost, earlier keys can be accepted again. Administrators must continue to verify every request independently for freshness and authenticity.

After the first key issuance or migration, the controller state contains a new JSON field. **Update the controller and the administrative CLI before making changes:** older binaries with a strict JSON decoder cannot read the updated state. The new history contains public key fingerprints, no private keys.

## Known limits

- Controller and current clients check for changes periodically and close their connections on errors. The CLI does not confirm successful loading. There is no guaranteed revocation deadline and no protection by signed short-lived leases or a secured clock; a compromised controller or client can bypass the policy.
- The relay is a single point of failure. The TCP-based tunnel can add latency and head-of-line blocking under loss or overload. The listener accepts at most 1,152 concurrent TCP connections including TLS handshakes (`serve -max-conns`), at most 64 per source IP address (`-max-conns-per-ip`) and at most 20 new connections per second per source IP after a burst of 64 (`-conn-rate-per-ip`); connections over a per-source limit are closed immediately. Unauthenticated connections must complete the TLS handshake and send their request header within 5 seconds; idle keep-alive connections are closed after 60 seconds, and every error response closes the connection. Dead TCP peers are detected after about 30 seconds. Per relay at most 1,024 waiting or active connection endpoints are allowed, at most 32 per authenticated device and one per directional device pair. When the global listener limit is reached, new connections wait in the operating system backlog; when the relay is saturated they are rejected. Bandwidth quotas and operational metrics are missing.
- Waiting relay endpoints expire after 30 seconds. When a device reconnects for a peer, its previous session for that ordered pair (waiting or bridged) is closed and replaced, so a crash or a dropped NAT mapping no longer blocks the pair until TCP keepalive notices. Configuration changes close relay sessions without waiting for TLS close notifications.
- Only communication between the explicitly assigned IPv4/IPv6 addresses works. IPv6 is limited to a ULA `/64`; multicast, NDP, jumbograms, forwarding to other subnets and internet exit nodes are not supported.
- Server and device certificates are valid for at most one year and no longer than the CA; the CA is valid for ten years. Existing peer sessions are locally limited to the earliest expiry of the certificates used. With a wrong clock, time jumps, suspend or tampered clients this is not proof of a time-bound block; the relay does not enforce this expiry itself. Server certificates and device keys can be renewed manually; CA rotation and automatic renewal are missing. Changing the controller hostname currently requires a new setup and redistribution of credentials.
- The connection limits are not complete protection against resource abuse: an attacker with many source addresses can still exhaust the global connection limit, and bandwidth limiting is missing. No automatic backup, package installation, service management or hardened privilege separation.

## Renewing the server certificate

On the controller, `./kinfold renew-server -data controller-data` renews the server certificate and server key with the existing, still valid CA. The new certificate is valid for at most one year and no longer than the CA. The controller must be restarted afterwards; a running controller closes its relay sessions after detecting the changed identity and stays closed until restart. The CA key and the device certificates remain unchanged, so with an unchanged CA and address no new credentials need to be distributed. An already expired server certificate can be renewed; an expired CA cannot. The file lock and the other limitations of file storage still apply.

Even with an expired server certificate, `remove-peer` can remove devices from the state offline as long as the CA is valid and the rest of the state is consistent. This is only a local change, not a confirmed or time-bound revocation; the controller stays closed because of the expired certificate until the certificate is renewed and the controller restarted.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow.

```sh
go test -race ./...
go vet ./...
sh scripts/integration-docker.sh
# Time-boxed fuzz runs for packet parsers, framing, relay responses, service filter and configuration:
go test ./internal/agent -run '^$' -fuzz '^FuzzPacketAddresses$' -fuzztime 30s
go test ./internal/agent -run '^$' -fuzz '^FuzzPacketFraming$' -fuzztime 30s
go test ./internal/agent -run '^$' -fuzz '^FuzzRelayResponse$' -fuzztime 30s
go test ./internal/agent -run '^$' -fuzz '^FuzzServicePacket$' -fuzztime 30s
go test ./internal/core -run '^$' -fuzz '^FuzzDecodeConfig$' -fuzztime 30s
```

No external Go modules are required. The Docker integration test needs the rights listed above and uses temporary keys generated only for the test.
