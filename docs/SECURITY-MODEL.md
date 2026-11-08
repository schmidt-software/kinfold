# Security model and production requirements

This document describes the state of `v0.2-alpha` and the requirements for a
production implementation. It is **not a security approval**. Protocol, transport,
consensus procedure, clock model and concrete lease duration are not yet
defined. An independent review and operational approval are outstanding.

## Scope of protection and trust boundaries

The goal is to protect payload between authorized devices, their keys, the
integrity of membership and policy, and the isolation between networks.
Availability is a goal, but not a guarantee against an attacker who completely
blocks network connections or resources.

| Actor or boundary | Assumption and security consequence |
| --- | --- |
| Network and relay | May read, delay, modify, duplicate or drop packets. A relay must not be able to decrypt payload; it sees at least the endpoints involved, timing and data volume. |
| Device | The local operating system kernel and the VPN implementation must be trustworthy for enforcement on that device. A compromised device can disclose its own keys and data and bypass local rules. Other correct devices must nevertheless reject it based on their own current authorization. |
| Controller and signer | Authorize membership and policy. A compromised authorized signer can issue malicious valid configurations; signatures alone do not prevent that. Separate roles, keys and auditable administration limit the risk but do not remove it. |
| Administrator and identity provider | A legitimately authorized but compromised admin or identity provider can authorize abusive actions. MFA, minimal roles, audit and controlled key rotation are required; they do not replace protection of compromised privileges. |
| Local operator | Whoever can read or modify the controller state or its CA key can, in the prototype, issue identities or replace the configuration. Access to credential files allows device impersonation. |
| Platform and time | Storage, secure key storage and clock trust depend on the platform. Manipulable clocks or rolled-back state must not enable longer authorization; without proven prerequisites the five-minute guarantee cannot be met. |

A compromised receiver can keep or forward data delivered to it. Neither
encryption nor local policy enforces deletion of such data. A compromised
device can also generate valid packets within its rights; their content is not
authorized by this VPN.

## Alpha hardening summary

Compared with the `v0.1-copilot` prototype, the alpha closes the findings of
the code review (`docs/review-v0.1-copilot.md`):

- The controller bounds every connection phase, closes rejected connections,
  limits connections per source address and speaks HTTP/1.1 only, so neither
  a removed device nor an unauthenticated client can pin its connection
  slots (decision D-011).
- A configuration without a policy denies all traffic; the relay always
  requires the current configuration revision (D-012).
- Device certificates in the state must be leaf, Ed25519, client+server
  authentication only, with the device ID as name; the overlay network must
  be private address space (D-014).
- Secrets readable by other users are refused; the state directory itself is
  locked against concurrent writers.
- Devices renew their certificates online with locally generated keys
  (D-015); a lost renewal response can be recovered only with the new key
  (D-018); the controller can move to a new address without re-enrollment
  (D-017).
- Service units run the controller without capabilities and the client with
  only `CAP_NET_ADMIN` (D-016).

Known residual risks are listed below and in the README's "Known limits".

## Current implementation

The Linux client obtains a member list from the controller over mutually
authenticated TLS. The additional TLS connection per peer checks certificates
against the delivered list and the CA. Since v0.4 the list is signed with a
dedicated configuration key and carries a lease and an issue time; devices
verify it against the key pinned in their credential, refuse older
configurations (the newest issue time is persisted next to the credential)
and close the tunnel when the lease ends (DECISION-LOG D-025). The controller
still controls the list, the CA key and the signing key. The older `add-peer` generates
device keys on the controller, offline enrollment generates them locally.

New networks have directional device rules with default deny. Sender and
receiver check the respective direction and exact peer addresses. An optional
experimental additional filter checks protocol and exact destination ports,
without a stateful return-traffic rule; fragmentation and IP extensions are
dropped there. ICMP rules cover all types. A tampered device can bypass its own
checks. A configuration without a policy section denies all traffic, and the
controller refuses to serve it. The relay
configuration hash is not proof of unmodified client software. The relay
rejects device pairs without a rule in either direction; as soon as at least
one direction is allowed, it cannot filter the encrypted stream by direction or
packet content. The direction check therefore remains the task of the
endpoints.

A watcher reads the state file about every second; clients poll every two
seconds and close their tunnel when the controller has been unreachable for 30
seconds. Because the relay requires the current configuration revision for
every new session and closes all sessions on change, a client with a stale
configuration cannot open or keep relay sessions in the meantime. Changes and broken state invalidate
relay sessions after detection. The CLI, however, only confirms the local
write, not the load or a consistent commit. Signed leases bound how long a
device acts on an outdated configuration when its clock is correct; there is
no rollback protection for the controller's own state, no quorum commit and
no proven time-bound revocation. The client limits
established peer sessions with a local I/O deadline at the earliest expiry of
the device, controller and CA certificates used. An additional check prevents
delivery of data already in the TLS buffer after locally detected expiry. This
does not protect against tampered clients and, with a wrong clock, time jumps
or suspend, is not proof of a real-time bound; the relay does not enforce it
itself. The existing implementation must therefore not be presented as the
basis for a five-minute assurance.

## Production contract: identity, policy and networks

- Every device generates and protects its private key locally; an enrollment
  proof is short-lived, single-use and bound to key possession, device
  identity and approval. Key rotation and revocation are explicit, audited
  operations.
- A network identifier is independent of IP addresses. Configuration, keys,
  sessions and policies bind it cryptographically; identical addresses in
  different networks must mix neither authorization nor routing.
- Default deny applies at the receiving device and at every gateway/exit. A
  rule binds at least network, source, destination, direction, protocol and
  port. Priority, group resolution, fragmentation, ICMP and return traffic must
  be specified bindingly before implementation. Missing, ambiguous or
  unverifiable rules do not lead to allow-all.
- An authenticated transport binds both device identities and the network
  identifier. Direct and relay paths receive the same authorization and meet
  the same revocation; a successful handshake alone is not a permanent
  entitlement.
- Configurations and authorizations are versioned, signed and bound to issuer,
  device, network and validity. A stored rollback protection must not be
  silently undone by restart or restoration of older backups. Key renewal and
  emergency rotation need a separate, verifiable trust transition.

These requirements are not yet an implemented message format or a complete
policy model. A cryptographic design must in particular define
canonicalization, algorithm binding, key distribution, replay protection and
version migration, and be reviewed independently.

## Revocation and time: binding proof conditions

A revocation counts as confirmed only after a durable, quorum-confirmed
commit. From that point on, correct receivers and gateways must accept no
packets from the revoked device after at most 300 seconds, even if they can no
longer reach the controller. This applies to existing and new sessions,
direct and relay paths, and gateway and exit traffic.

One possible mechanism is short-lived signed authorization leases,
complemented by immediate online invalidation. At least the following
properties must be proven for that:

1. After the commit, no quorum may issue a lease extending the old right.
   Leases issued earlier and delivered late must be included in the
   worst-case budget; a missing quorum majority must neither fake success nor
   extend new rights.
2. Acceptance is limited to the verified expiry also for already established
   sessions. A message with an old state must not establish a later deadline
   after revocation, reboot or snapshot rollback.
3. The sum of maximum remaining validity before commit, permissible clock
   error and all further provable delays until the last accepted packet
   processing must not exceed 300 seconds. The exact derivation depends on
   issuance and clock model; no unvalidated number is fixed here.
4. Clock regression, frozen clock, loss of protected state and unprovable
   clock accuracy must be detected or end authorization fail-closed. A
   monotonic clock alone does not necessarily survive restart or VM snapshot;
   a viable model and its failure behaviour must be demonstrated for every
   platform.
5. Tests measure from the confirmed commit to the **last accepted packet**,
   not only to the closing of a connection. They cover partition, delayed
   messages, replay, clock errors, restart, snapshot rollback, leader change
   and relay failover for all supported paths.

Without trustworthy time and rollback assumptions, unlimited offline
availability and a fixed real revocation deadline cannot be guaranteed at the
same time under arbitrarily long partitions. In doubt, the product requirement
decides for fail-closed and thus loss of availability.

## Privacy and operation

Expected data: device identifiers, public keys, network assignment,
administration events, connection times, endpoint addresses and error data.
Logs should contain neither payload nor private keys nor enrollment proofs.
Purpose, legal basis, access, storage location, retention, deletion including
backups and, where applicable, data processing agreements must be defined for
the concrete deployment and reviewed legally. This list is not a GDPR
approval.

Before production, traceable roles, auditable administration, tested
backup/restore, key compromise procedures, abuse limiting, privacy approval and
an independent security review are also required. SLOs and infrastructure must
be defined based on measurements. ISO 27001 certification is not part of the
project goal.

On load, the controller checks its key pairs, the valid server certificate matching the configured host, and the signature of the registered devices by its own CA. An invalid state closes the relay after detection. The check does not protect against an attacker with access to a valid CA key and controller state. `add-peer` synchronizes the credential file before the state change; both writes are still not transactional.

State files are synchronized before the atomic rename; the parent directory is synchronized afterwards. Newly created output and controller directory entries are synchronized as well. If synchronization fails after creation or replacement, the CLI explicitly reports an uncertain state: the change may already be visible and must be checked before retrying. This requires a file system with a working `fsync` and offers neither quorum nor atomic multi-file transactions nor rollback protection.

With `renew-server` the administrator can also replace an already expired server certificate under a still valid CA; the server key is regenerated and the lifetime limited by the CA. A running controller closes on detected identity change and must be restarted. This renews neither devices nor the CA and is not a highly available rotation.

For offline revocation, `remove-peer` may load an otherwise verified state with an expired server certificate; the service itself must not use it. The CA must still be valid. The file write confirms neither adoption by controller and clients nor compliance with a revocation deadline.

Devices can enroll online with single-use, expiring tokens bound to their ID and address (DECISION-LOG D-024). The device authenticates the controller against a CA fingerprint it received out of band before it reveals the token; the token itself is a bearer secret until it is used or expires, so it must travel over a confidential channel.

Running clients renew their certificate online before it expires (DECISION-LOG D-015): a new key is generated on the device and only a certificate request is sent over the existing mutual-TLS connection; the controller accepts it only from the device whose current certificate is on record and only in the second half of its lifetime. A thief holding a device credential can renew it, as they could already impersonate the device; the legitimate device is then locked out.

`rotate-peer` replaces the device certificate based on an independently verified offline request with a new local key. Addresses and policy are preserved; after asynchronous adoption the old identity is no longer accepted. Since there is no transaction between certificate issuance and state, no secure rollback and no guaranteed deadline, this is not a production rotation.

A bounded history of public device key fingerprints prevents their re-authorization via current CLI commands, even after removal and with different requests. Migration only captures keys still present; older backups or manual edits can reset the history. This is neither tamper-proof rollback protection nor time-limited single-use enrollment.
