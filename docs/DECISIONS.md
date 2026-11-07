# Architecture decisions

As of 2026-11-07. The decisions describe the current prototype, not an
assurance of production readiness. Decisions made during further development
are logged chronologically in [DECISION-LOG.md](DECISION-LOG.md).

## 1. Standalone layer-3 MVP

**Decision:** One Linux TUN interface per device with IPv4 and optional IPv6. The implementation is standalone and not compatible with any other VPN or overlay product.

**Rationale:** IP unicast is much smaller than a virtual Ethernet with ARP/NDP, broadcast, multicast and bridging. This makes a verifiable first milestone possible.

**Consequences:** No layer 2 or subnet routing. macOS can run the controller but cannot provide a client tunnel.

## 2. Standard library and TLS instead of custom cryptography

**Decision:** Go without external modules; TLS 1.3 from the Go standard library for controller connections and additionally per device pair. Device certificates are checked exactly against the controller list and additionally validated against the own CA and the intended usage.

**Rationale:** No custom encryption or handshake protocol is designed. TLS 1.3 provides session keys with forward secrecy as long as the endpoints and the TLS implementation are not compromised.

**Consequences:** The relay transports encrypted inner TLS streams. Because the controller controls the CA and the member list, it can nevertheless replace identities and actively manipulate connections. The controller connection is mutually authenticated; the configuration has no independent signature. An external security audit and a more precise threat model are outstanding.

Established peer sessions get a local I/O deadline based on the earliest expiry of the device, controller and CA certificates used. This way they do not persist indefinitely under normal clock progression merely because of an earlier successful handshake. This deadline replaces neither revocation-bound leases nor a secured time source; in particular suspend, clock errors and tampered clients are not covered.

## 3. Central relay before NAT traversal

**Decision:** Devices connect over TCP to a self-hostable controller/relay. For each device pair there is a separate end-to-end TLS connection; the network is limited to 32 devices.

**Rationale:** The path is demonstrable, works without inbound client ports and can be tested with real virtual interfaces.

**Consequences:** No direct connections and no UDP-based NAT traversal optimization. A full mesh scales quadratically; TCP-over-TCP and the central relay cause performance and availability disadvantages. The relay path is not hardened against abuse by authorized devices.

On controlled shutdown, relay sessions are closed immediately; for running HTTP requests the controller waits up to five seconds and reports a timeout as an error. The configuration watcher is stopped and awaited. This is a local lifecycle mechanism, not an uninterrupted failover.

## 4. Explicit, offline-managed membership

**Decision:** The administrator creates the CA and assigns fixed device addresses. Devices can generate their key locally via `keygen`/`approve`/`enroll` and submit a signed request for manual approval. The original `add-peer` still generates the device key on the controller. A certificate alone is not sufficient: it must also be listed exactly in the started controller configuration.

**Rationale:** For the first milestone there are no public management endpoints, user accounts or automatic enrollment processes.

**Consequences:** With `add-peer` the controller sees private device keys; with offline enrollment it does not. A signed request only proves key possession, not device identity; its authenticity and the CA fingerprint must be verified independently. No one-time tokens, no request expiry and no online approval.

On load, the controller checks its key pairs, the valid server certificate matching the configured host, and the signature of the registered devices by its own CA. An invalid state closes the relay after detection. The check does not protect against an attacker with access to a valid CA key and controller state. `add-peer` synchronizes the credential file before the state change; both writes are still not transactional.

State files are synchronized before the atomic rename; the parent directory is synchronized afterwards. Newly created output and controller directory entries are synchronized as well. If synchronization fails after creation or replacement, the CLI explicitly reports an uncertain state: the change may already be visible and must be checked before retrying. This requires a file system with a working `fsync` and offers neither quorum nor atomic multi-file transactions nor rollback protection.

With `renew-server` the administrator can also replace an already expired server certificate under a still valid CA; the server key is regenerated and the lifetime limited by the CA. A running controller closes on detected identity change and must be restarted. This renews neither devices nor the CA and is not a highly available rotation.

For offline revocation, `remove-peer` may load an otherwise verified state with an expired server certificate; the service itself must not use it. The CA must still be valid. The file write confirms neither adoption by controller and clients nor compliance with a revocation deadline.

`rotate-peer` replaces the device certificate based on an independently verified offline request with a new local key. Addresses and policy are preserved; after asynchronous adoption the old identity is no longer accepted. Since there is no transaction between certificate issuance and state, no secure rollback and no guaranteed deadline, this is not a production rotation.

A bounded history of public device key fingerprints prevents their re-authorization via current CLI commands, even after removal and with different requests. Migration only captures keys still present; older backups or manual edits can reset the history. This is neither tamper-proof rollback protection nor time-limited single-use enrollment.

## 5. Packet mapping and restrictions

**Decision:** Outgoing packets are mapped to a peer solely by the exactly assigned IPv4 or IPv6 destination address. Incoming packets must carry the source assigned to the authenticated peer and the own address as destination. New networks additionally use static directional default-deny rules; old networks keep allow-all until the administrator enables the policy.

**Rationale:** This keeps the first tunnel simple to test and offers basic protection against address spoofing.

**Consequences:** No forwarding of foreign prefixes, no broadcasts or granular port rules. A reply needs its own rule. Old clients ignore policies; the relay rejects them when a policy is enabled because of the missing configuration hash, which however guarantees no protection against tampered clients. Updates happen asynchronously and without a binding revocation guarantee. Operating system firewalls remain necessary.

A device pair without a rule in any direction gets no relay session; current clients skip such connection attempts. A one-directional rule allows establishing the shared connection, not traffic in both directions. Old configurations without a policy keep allow-all.

Optionally, an additional experimental service policy can be enabled. It is default deny, requires existing directional device rules and allows TCP/UDP by exact destination port or all ICMP/ICMPv6 types. Both endpoints check independently. IPv4 options and fragments as well as IPv6 extension headers and fragments are rejected when the service policy is enabled; other traffic likewise. Rules are stateless, there is no automatic reply rule, and ICMP errors are not associated with a connection. TCP replies to variable client ports are therefore awkward to use. Changes invalidate sessions after asynchronous reload; old strict decoders do not accept the new fields. Not a production-grade firewall replacement.

`service-apply` adopts a complete, strictly parsed rule set checked against the current device policy, under the existing write lock, with an atomic file replacement. An empty array blocks all services; faulty input does not change the state. This prevents unintended intermediate states during the local write but guarantees neither atomic switch-over of all clients nor a quorum commit.

The fixed TUN MTU is 1280 bytes. Oversized outgoing packets are dropped; for incoming frames above the limit the session is closed right after the frame header. Automatic PMTU discovery and an adaptive MTU are thus not implemented.

Write errors and incomplete writes at the TUN device terminate the agent and are reported to the supervisor; network and peer errors, in contrast, still lead to reconnection attempts. Errors resulting from an already initiated agent shutdown are not reported as new TUN write errors.

The supervisor manages the lifecycle of the tunnel device: even on premature agent exit the device is closed exactly once, and a close error remains visible. Closing after an error guarantees no restoration of other operating system settings.

The periodic configuration fetch runs alongside agent monitoring; at most one fetch is active at a time and it is cancelled on shutdown. This way a slow controller does not delay reporting an already failed agent. Fetch timeouts are not a time-bound revocation guarantee.

## Next milestones

1. Prepare security model and independent audit: locally generated device keys, separate controller/relay roles, signed and versioned configuration, key rotation, expiry and time-bound revocation.
2. Authenticated online management with controlled configuration updates; binding tests for revocation, offline behaviour and restarts. Add quotas, limits, metrics and secure service management.
3. Evaluate a separate UDP data path with a proven transport implementation, rendezvous and NAT traversal; keep the relay as fallback. Test direct and relay paths and NAT scenarios automatically.
4. IPv6 beyond the experimental ULA unicast, routes and subnet gateways; macOS and Windows clients. Ethernet/multicast/bridging only as a separate, carefully bounded follow-up project.

## 6. Optional IPv6 over existing peer sessions

**Decision:** An optional ULA `/64` with an explicit, unique address per device complements the mandatory IPv4 network. Both address families share the same authenticated peer session and the same directional rules; packets are only allowed between the respective device addresses.

**Consequences:** The Linux client configures both addresses on the TUN and recreates it on changes. No multicast, NDP, routing of foreign prefixes or IPv6 jumbograms. Enabling requires updated controllers and clients because older strict JSON decoders may reject additional fields. This remains an experimental relay path without production approval.

## Preliminary review of direct transport

- WireGuard transports IP packets over UDP and authenticates peers by their keys. Key distribution and configuration are explicitly not part of the protocol. NAT traversal, relay selection and policy management must therefore be solved separately.
- wireguard-go is a possible Go implementation. Platform integration differs; on Linux the documentation points to the kernel data path. Licence and integration review are required before adoption.
- Pion ICE provides building blocks for candidate discovery and connection setup. Whether and how a datagram path negotiated this way can be combined with the chosen VPN transport, relay fallback, key binding and revocation has not been demonstrated in practice.
- The platform surfaces for Apple devices (Packet Tunnel Provider) and Android (VpnService) require their own integration and real device tests.

**Status:** Research, no selection or security approval. Before a productive transport decision, an end-to-end prototype with direct and relay path, NAT/mobility tests, performance measurements, licence review and independent security assessment are missing in particular.
