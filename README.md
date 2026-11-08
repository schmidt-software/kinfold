<img src="docs/assets/banner.png" alt="Kinfold — self-hosted overlay network: a ring of six network nodes joined through a central relay core" width="100%">

# Kinfold

A **self-hostable IPv4/IPv6 overlay network** for small groups of Linux devices. A controller you run yourself admits devices explicitly, hands out fixed addresses and directional rules, and relays end-to-end encrypted sessions between them. Kinfold implements its own protocol and is not compatible with any other VPN or overlay product.

> **Status: alpha (`v0.2.1-alpha`).** The design is complete for its scope and has been reviewed and hardened, but it has **not been independently audited**. Use it for evaluation and non-critical networks, not to protect confidential data. The controller is a complete trust anchor and a single point of failure; all traffic passes through its relay. See [Known limits](#known-limits).

## Features

**Network**
- One private IPv4 network (RFC 1918 or 100.64.0.0/10) and optionally one IPv6 ULA `/64`, up to 32 devices, one Linux TUN interface per device, MTU 1280.
- Unicast only between assigned device addresses; source and destination are checked against spoofing on both ends.
- Default deny: traffic needs a directional allow rule; an optional experimental filter restricts it further to protocols and destination ports.

**Security**
- Device and controller identities are Ed25519 certificates from your own CA; the controller connection uses mutual TLS 1.3.
- A second, end-to-end mutual TLS 1.3 session runs between each pair of devices through the relay; certificates are pinned to the controller's member list and verified against the CA. The relay cannot read the traffic.
- Keys can be generated on the device (offline enrollment); device certificates are renewed online before they expire with a new key that never leaves the device.
- Strict parsing and size limits for all network and file input; the controller validates its whole PKI on every reload and fails closed on inconsistent state.
- Connection limits per source address, timeouts for every connection phase, and per-device relay limits protect the controller against exhaustion.
- Secrets are refused if other users can read them.

**Operations**
- Changes take effect within seconds without restarts; removing a device cuts it off immediately at the relay.
- Clients ride out controller restarts (30 s grace period), reconnect with backoff and detect dead paths in seconds.
- Structured logging (`log/slog`, text or JSON), `kinfold version`, hardened systemd units, reproducible release builds with checksums, and an [operator guide](docs/OPERATIONS.md).

**Not included:** direct peer-to-peer connections, NAT traversal, UDP transport, Ethernet bridging, multicast, subnet gateways, stateful firewalling, GUI, non-Linux clients, controller high availability. `status` shows the authorized members, not live connection state.

**Documentation:** [operator guide](docs/OPERATIONS.md) · [security model](docs/SECURITY-MODEL.md) · [architecture decisions](docs/DECISIONS.md) · [decision log](docs/DECISION-LOG.md) · [code review of the prototype](docs/review-v0.1-copilot.md) · [contributing](CONTRIBUTING.md)

### Trust model in one paragraph

The member list is delivered over authenticated TLS but is **not separately signed**. The controller holds the CA key and the member list, so a compromised controller can admit devices and manipulate connections by swapping certificates. With `add-peer` the controller also generates the device key; with offline enrollment the key is created on the device. A relay whose controller and CA are not compromised does not see the content of the inner TLS sessions, but it does see metadata such as which devices talk and how much.

## Note on the rename

Up to version `v0.1-copilot` the project was called `my-zerotier`. The rename to Kinfold changed the binary (`kinfold`), the default name of the TUN interface (`kf0` instead of `mzt0`), the variable `KINFOLD_TEST_IMAGE` and the internal HTTP header for the configuration revision. Because of the header, older clients are not compatible with a new controller and vice versa: update the controller and **all clients** together. Existing controller state and credentials remain valid; newly created CAs are named `Kinfold CA`.

## Quick demonstration with Docker

Requirements: the Go version pinned in `go.mod` (Go downloads it automatically), Docker with Linux containers, `NET_ADMIN` and `/dev/net/tun`. The script uses the Docker image `alpine/socat:latest` by default and can download it if needed. `KINFOLD_TEST_IMAGE` selects a suitable existing image with a shell, `ip`, `ping`, `ping6`, `nc` and `socat`.

```sh
sh scripts/integration-docker.sh
```

The script builds a Linux binary, creates temporary credentials and an isolated Docker network, starts three clients and checks IPv4/IPv6 ICMP and TCP, policy, reconnection and revocation. It removes its own containers, its network and the temporary files on exit. It does not modify existing containers.

## Manual setup

The controller runs on Linux or macOS; the VPN client currently requires **Linux**, `/dev/net/tun`, the `ip` command from iproute2 or BusyBox in `/usr/sbin`, `/sbin`, `/usr/bin` or `/bin` (`PATH` is not used), and administrator rights or `CAP_NET_ADMIN`. The virtual network must not overlap with existing local networks or routes.

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

`serve -metrics 127.0.0.1:9100` and `run -metrics 127.0.0.1:9101` expose Prometheus metrics in text format; the address must be a loopback address, because the metrics name devices and traffic volumes. Use a local collector or an SSH tunnel to scrape them.

`serve` and `run` log to stderr via `log/slog`. `-log-format text|json` selects the format, `-log-level debug|info|warn|error` the minimum level (default `info`). Per-packet drop messages (MTU exceeded, peer queue full) are logged at `debug` level so they cannot flood production logs.

Administrators can use `./kinfold check-config -data controller-data -credential admin-peer.json` to check whether the authenticated controller has loaded the same configuration as a local snapshot of the state file. The credential must belong to a device that is still authorized. The command prints both configuration hashes and returns an error on mismatch or reachability failure. It does not prove that clients have already adopted the configuration.

## Running as a service

`packaging/systemd/` contains hardened units; installation steps are at the top of each file.

- `kinfold-controller.service` runs `serve` as the dedicated system user `kinfold` with no capabilities, state in `/var/lib/kinfold-controller/state` (mode `0700`). Run administrative commands as the same user, e.g. `sudo -u kinfold kinfold allow -data /var/lib/kinfold-controller/state -from alice -to bob`.
- `kinfold-client@.service` runs one client per credential: `kinfold-client@alice` reads `/var/lib/kinfold-client/alice/credential.json` and creates the interface `kf-alice` (instance names are therefore limited to 12 characters). It uses a dynamic user with only `CAP_NET_ADMIN` and access to `/dev/net/tun`; the credential directory stays writable for automatic certificate renewal.

Both units restrict file system, kernel, device, address-family and system-call access (`systemd-analyze security` rates them 1.6 and 2.1, "OK"). They were verified under systemd 252 (Debian 12). Under the client unit `/proc/sys` is read-only, so IPv6 duplicate address detection stays enabled and a new ULA becomes usable about one second after the tunnel starts.

## Optional IPv6

Before enabling, **update all clients and the controller**: older binaries with a strict JSON decoder may reject the additional fields. On the controller, configure a ULA `/64` that does not collide with other networks and unique device addresses:

```sh
./kinfold ipv6-network -data controller-data -network fd77::/64
./kinfold ipv6-assign -data controller-data -id alice -ip fd77::1
./kinfold ipv6-assign -data controller-data -id bob -ip fd77::2
```

After the asynchronous reload and reconnection, `ping -6 fd77::2` should work on Alice. IPv6 requires a working IPv4 overlay; a device without an IPv6 assignment stays IPv4-only. The existing directional allow rules apply to both address families. Use `ipv6-assign -id alice -ip none` to remove an assignment, and only after all assignments are removed, `ipv6-network -network none` to disable the IPv6 network. Changes take effect asynchronously; existing sessions are disconnected after adoption.

## Online enrollment with a token

The quickest way to add a device: the administrator issues a single-use token bound to the device ID and address, and the device enrolls itself online. Its private key is generated on the device and never leaves it.

On the controller:

```sh
./kinfold token -data controller-data -id carol -ip 10.77.0.3 -ttl 1h
```

The command prints the token once, together with a ready-made `join` command containing the controller address and the SHA-256 fingerprint of the CA. Send token and command to the device over a confidential channel (anyone who has the token before it is used can enroll as `carol`). On the device, pass the token on standard input or in a file, so it does not show up in process lists:

```sh
./kinfold-linux join -server vpn.example.com:8443 -ca-sha256 <fingerprint> -id carol -token-file - -out carol.json
sudo ./kinfold-linux run -credential carol.json
```

`join` keeps its key and request in `carol.json.joining` until the credential is written; if the response is lost, running the same command again collects the certificate that was already issued (a used token stays valid for exactly that key until it expires).

`join` verifies the controller against the pinned CA fingerprint **before** it sends the token, so a machine in the middle cannot capture it. Tokens expire (default one hour, at most seven days), work once, and only for their ID and address; only a hash is stored. `token-list` shows pending tokens and `token-revoke -id carol` withdraws one; `add-peer`, `approve` and `remove-peer` drop the tokens of the device they handle, so a leftover token cannot re-enroll it later. Failed attempts are slowed down per source address. To accept enrollments without a client certificate, the controller's TLS handshake no longer requires one; every endpoint other than `POST /enroll` still does.

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

`add-peer`, `approve`, `rotate-peer`, `remove-peer`, `policy-enable`, `allow`, `deny`, `ipv6-network` and `ipv6-assign` modify the controller file. On Linux and macOS an advisory lock on the data directory prevents concurrent modifications by these CLI commands; a competing command fails and must be re-run. Manual edits, older binaries and file systems without reliable `flock` bypass this protection; it does not replace a transactional database. The running controller checks the file about once per second; a change closes only the relay sessions of device pairs whose certificates, addresses or rules changed. Each device receives only its own part of the configuration: itself, the devices it has a rule with, and those rules. Current clients poll the configuration every 2 seconds over one reused connection. A change that keeps the device's own addresses is applied to the running tunnel: unchanged peer sessions continue, changed ones reconnect; only a change of the device's own address or network recreates the tunnel. If the controller cannot be reached, a client keeps its tunnel for up to 30 seconds and then closes it until the controller answers again; a failed tunnel restart after a change is retried instead of ending the client. The CLI only confirms that the file was written, **not** that it was loaded or fully enforced. If the file is corrupt, cryptographically inconsistent or unreadable, or if the server certificate is invalid, the controller closes connections and rejects new requests until the state is valid again. Changes to the CA or server certificate require a controller restart.

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

Do not check in or share the controller state and the credentials. Kinfold refuses to read the controller data directory, `state.json`, credential files and private keys when they are accessible by group or others (use `chmod 700` for the directory and `chmod 600` for files); for container volumes that do not preserve file modes, `KINFOLD_INSECURE_PERMISSIONS=1` turns the refusal into a logged warning. The folder `controller-data` contains in particular the CA private key; `credentials` contains the device keys. The default paths are listed in `.gitignore`, other paths are not. Back up the controller state encrypted. Deleting or losing the CA key requires re-creation and redistribution of all credentials.

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
- The relay is a single point of failure. The TCP-based tunnel can add latency and head-of-line blocking under loss or overload. The listener accepts at most 1,152 concurrent TCP connections including TLS handshakes (`serve -max-conns`), at most 128 per source (`-max-conns-per-ip`; an IPv4 address or an IPv6 /64) and at most 20 new connections per second per source after a burst of 128 (`-conn-rate-per-ip`); connections over a per-source limit are closed immediately. Each device needs up to 32 connections, so the default fits four devices behind one NAT address; raise the limit for more. Unauthenticated connections must complete the TLS handshake and send their request header within 5 seconds; idle keep-alive connections are closed after 60 seconds, and every error response closes the connection. Dead TCP peers are detected after about 30 seconds. Per relay at most 1,024 waiting or active connection endpoints are allowed, at most 32 per authenticated device and one per directional device pair. When the global listener limit is reached, new connections wait in the operating system backlog; when the relay is saturated they are rejected. Bandwidth quotas and operational metrics are missing.
- Waiting relay endpoints expire after 30 seconds. When a device reconnects for a peer, its previous session for that ordered pair (waiting or bridged) is closed and replaced, so a crash or a dropped NAT mapping no longer blocks the pair until TCP keepalive notices. Configuration changes close relay sessions without waiting for TLS close notifications.
- Only communication between the explicitly assigned IPv4/IPv6 addresses works. IPv6 is limited to a ULA `/64`; multicast, NDP, jumbograms, forwarding to other subnets and internet exit nodes are not supported.
- Server and device certificates are valid for at most one year and no longer than the CA; the CA is valid for ten years. Existing peer sessions are locally limited to the earliest expiry of the certificates used. With a wrong clock, time jumps, suspend or tampered clients this is not proof of a time-bound block; the relay does not enforce this expiry itself. Device certificates are renewed automatically by running clients; server certificates are renewed manually with `renew-server`; CA rotation is a manual procedure (see the operator guide). The controller can move to a new address with `renew-server -server host:port`; devices then only need the new address in their credential (see the [operator guide](docs/OPERATIONS.md)).
- The connection limits are not complete protection against resource abuse: an attacker with many source addresses can still exhaust the global connection limit, and bandwidth limiting is missing. No automatic backup or package installation; systemd units are provided but no distribution packages.
- The controller state has no rollback protection. Restoring an older backup re-authorizes devices removed since, rejects devices renewed since and forgets key fingerprints recorded since (see the operator guide). Signed, versioned state is planned (#22).
- `add-peer`, `approve` and `rotate-peer` write the output file before the state. If the state write fails, a CA-signed certificate exists that is not in the member list; it is useless for traffic (the relay requires membership) but stays valid until it expires.
- Kinfold has not been independently audited. The code review of the prototype and the alpha hardening are documented in `docs/`, but they are no substitute for an external review.

## Automatic device certificate renewal

Device certificates are valid for one year. A running client (`run`, unless started with `-auto-renew=false`) checks its certificate every hour; once less than a third of its lifetime remains, it generates a **new private key locally**, sends a certificate request over its still-valid mutual-TLS connection, writes the new credential atomically to the same file (mode `0600`) and restarts its tunnel with the new identity. The private key never leaves the device.

The controller accepts a request only from the authorized device itself, only with the certificate currently on record, and only once at most half of that certificate's lifetime remains. It applies the same checks as `rotate-peer` (Ed25519, ID binding, key history) under the state lock and writes the state; the watcher then adopts it like any other change, which briefly reconnects relay sessions. If the state is locked by an administrator command, the device retries later.

`kinfold renew -credential alice.json` performs the same renewal once, e.g. for devices that run the client only occasionally; it does nothing while renewal is not due. The directory containing the credential file must be writable by the client.

Before sending a request, the client stores the new key and request in `alice.json.renewing` (mode `0600`). If the response is lost — connection drop, crash, timeout — the next attempt (at the latest when `run` starts again) resends the same request, and the controller hands out the certificate it already issued, even though the old certificate is no longer a member. Someone holding only the old credential cannot use this, because the request must be signed by the new key. After a failed attempt the controller makes that certificate wait 30 seconds before the next one. When a renewal would not extend the validity because the CA expires first, the controller refuses it and asks for a CA rotation instead.

Whoever holds a device's credential can renew it, as they could already impersonate the device; after such a renewal the legitimate device is locked out, which makes the theft visible. Remove the device with `remove-peer` in that case.

## Renewing the server certificate

On the controller, `./kinfold renew-server -data controller-data` renews the server certificate and server key with the existing, still valid CA. The new certificate is valid for at most one year and no longer than the CA. The controller must be restarted afterwards; a running controller closes its relay sessions after detecting the changed identity and stays closed until restart. The CA key and the device certificates remain unchanged, so with an unchanged CA and address no new credentials need to be distributed. An already expired server certificate can be renewed; an expired CA cannot. The file lock and the other limitations of file storage still apply.

Even with an expired server certificate, `remove-peer` can remove devices from the state offline as long as the CA is valid and the rest of the state is consistent. This is only a local change, not a confirmed or time-bound revocation; the controller stays closed because of the expired certificate until the certificate is renewed and the controller restarted.

## Releases

Tagged versions (`v*`) are built by `.github/workflows/release.yml`: tests, then `scripts/release.sh`, which builds `linux/amd64`, `linux/arm64`, `darwin/amd64` and `darwin/arm64` binaries with `-trimpath`, without cgo and with an empty build ID, plus the systemd units and a `SHA256SUMS` file. The same commit and the Go toolchain pinned in `go.mod` produce bit-identical binaries, so a release can be verified by rebuilding it:

```sh
git checkout v0.2.1-alpha
scripts/release.sh v0.2.1-alpha /tmp/verify
diff /tmp/verify/SHA256SUMS SHA256SUMS   # from the release page
```

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
