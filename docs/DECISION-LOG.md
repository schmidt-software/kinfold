# Decision log

Every non-trivial decision made while developing Kinfold is recorded here, in
order, with its rationale and consequences. Entries are never deleted; a
reversed decision gets a new entry that references the old one. Architecture
decisions that shape the system long-term are additionally summarised in
`docs/DECISIONS.md`.

Format: `D-<n>` — date — status (`active`, `superseded by D-<m>`).

---

## D-001 — 2026-11-07 — active — Project name "Kinfold"

**Decision:** The project, Go module, binary, TUN interface prefix, HTTP header
and CA name are renamed from `my-zerotier` to **Kinfold**
(`github.com/schmidt-software/kinfold`, binary `kinfold`, interface `kf0`,
header `X-Kinfold-Config-Revision`, env prefix `KINFOLD_`, CA `Kinfold CA`).

**Rationale:** The owner required a name with no association to ZeroTier or any
other VPN product. "Kinfold" (kin + fold: a small, fenced group of explicitly
admitted members) matches the 32-device, default-deny design. A GitHub search
found no networking project with that name; trademark and domain checks were
not done.

**Consequences:** The relay header rename breaks compatibility between
pre-rename and post-rename nodes; controller and all clients must be updated
together. Existing state files and credentials remain valid. Tag
`v0.1-copilot` keeps the old name. Documentation no longer names other VPN
products.

## D-002 — 2026-11-08 — active — Repository language is English

**Decision:** Everything committed to the repository (code, comments, docs,
CLI output, commit messages, issues, PRs) is written in English. The three
German documents inherited from the prototype (`README.md`,
`ENTSCHEIDUNGEN.md`, `SICHERHEITSMODELL.md`) and the German CLI error prefix
are migrated to English during the alpha work. Communication with the owner
stays in German.

**Rationale:** The owner's global instruction for all repositories. One
language keeps docs, code and error messages searchable and reviewable by
anyone.

**Consequences:** `ENTSCHEIDUNGEN.md` → `docs/DECISIONS.md`,
`SICHERHEITSMODELL.md` → `docs/SECURITY-MODEL.md`. Until migrated, the German
files remain authoritative.

## D-003 — 2026-11-08 — active — Definition of the "alpha" milestone

**Decision:** `v0.2-alpha` means: the existing relay-based design is hardened,
operable and documented to a level just short of production. It does **not**
add new transport architecture.

In scope:
- Full code review of the `v0.1-copilot` baseline; every finding fixed or
  explicitly deferred with a reason.
- Open points from the security model that do not require a new architecture:
  bounded, controller-asserted configuration validity (lease) with fail-closed
  behaviour; abuse limits for unauthenticated connections and per peer;
  automatic peer certificate renewal; documented CA rotation procedure.
- Operability: `version` command, structured logging (`log/slog`), systemd
  units with capability-based hardening, configuration self-check.
- CI (GitHub Actions), reproducible release builds for linux/amd64 and
  linux/arm64, release tag `v0.2-alpha`.
- Documentation in English on alpha level.

Out of scope (tracked as `post-alpha` issues): direct peer-to-peer paths, UDP
transport and NAT traversal, layer 2, subnet gateways, GUI, non-Linux clients,
multi-controller/quorum, CA rotation automation.

**Rationale:** The architecture decisions (docs/DECISIONS.md §3) deliberately
chose a central relay first. Making that design trustworthy is the shortest
path to something deployable; a transport rewrite would restart the review
from zero.

**Consequences:** Alpha remains a relay-only product with the performance
and availability limits that implies. Those limits are documented, not
hidden.

## D-004 — 2026-11-08 — active — Git workflow

**Decision:**
- One GitHub issue per topic, labelled and assigned to the milestone.
- One branch per issue, named `<issue-number>-<short-slug>`.
- Atomic commits (one logical change each), English messages, imperative
  mood, body explains *why*.
- One pull request per issue, merged by **rebase** so the atomic commits are
  preserved and history stays linear; the branch is deleted after merge.
- No direct commits to `main` after this entry.
- The review of the baseline and all decisions are committed to the repo so
  they are traceable without GitHub.

**Rationale:** The owner asked for atomic commits and the
issue → branch → PR → merge → cleanup cycle without further confirmation.
Rebase merge keeps the per-commit granularity that squash would lose.

**Consequences:** More PRs than a solo developer would normally open; in
exchange each change is reviewable on its own.

## D-005 — 2026-11-08 — active — Code review method

**Decision:** The baseline is reviewed in two independent passes: a full read
by the lead (Claude Code) and three adversarial reviewer agents, one per
package group, briefed with the code and threat model but **not** with the
lead's findings. Findings are cross-checked against the code before they
become issues. The consolidated review is committed as
`docs/review-v0.1-copilot.md`.

**Rationale:** A second read that is not anchored on the first catches
different classes of errors. The local Unsloth model is not used for this:
the code base exceeds its context window and security judgements are
excluded from delegation by the owner's rules.

## D-006 — 2026-11-08 — active — CI scope

**Decision:** GitHub Actions runs on every push and pull request: `gofmt -l`,
`go vet`, `go test -race`, cross-compilation for linux/amd64 and linux/arm64,
and `govulncheck`. The Docker integration test (`scripts/integration-docker.sh`)
is **not** run in CI; it is run locally before every merge that touches the
network path, and the result is noted in the PR.

**Rationale:** The integration test needs `NET_ADMIN` and `/dev/net/tun`,
which hosted runners do not provide reliably. The repository is private; the
free Actions quota (2,000 min/month) is enough for the unit pipeline if it
stays small.

**Consequences:** End-to-end regressions depend on the local run discipline
documented in `CONTRIBUTING.md`.

## D-007 — 2026-11-08 — active — No external Go modules

**Decision:** The rule from docs/DECISIONS.md §2 stays: standard library
only, no third-party modules, including for logging, CLI parsing and testing.

**Rationale:** Smaller supply-chain surface for a security-sensitive tool;
everything needed (TLS 1.3, Ed25519, x509, slog, flag) is in the standard
library.

**Consequences:** Some conveniences (richer CLI, assertion libraries) are
foregone. Tooling that does not become a dependency (`govulncheck` in CI) is
allowed.

## D-008 — 2026-11-08 — superseded by D-009 — Go toolchain version

**Decision:** `go.mod` keeps `go 1.24` as the minimum; CI uses the version
from `go.mod` via `go-version-file`. Newer local toolchains may be used for
development but must not introduce APIs above 1.24.

**Rationale:** 1.24 is what the prototype was written against; raising the
floor gives no benefit for alpha.

## D-009 — 2026-11-08 — active — Pin the Go toolchain to the latest patch release

**Decision:** `go.mod` pins the exact toolchain (`go 1.26.10` at the time of
writing). Go's toolchain switching (`GOTOOLCHAIN=auto`, the default) downloads
it automatically for developers; CI reads it via `go-version-file`. The pin is
bumped to every new patch release of the supported Go line as part of regular
maintenance; `govulncheck` in CI fails when the pinned toolchain has known
vulnerabilities that the code reaches, which is the trigger.

**Rationale:** The first CI run with `go 1.24` resolved to Go 1.24.13 and
`govulncheck` reported 25 reachable standard-library vulnerabilities,
including a `crypto/tls` denial of service (GO-2026-4870) in exactly the
handshake and read/write paths Kinfold depends on. Go 1.24 is end of life.
Even the locally installed 1.26.5 had 15 reachable findings; 1.26.10 has
none. For a program whose entire security rests on `crypto/tls` and
`crypto/x509`, the toolchain patch level is part of the security posture and
must be explicit and reproducible, not "whatever is installed".

**Consequences:** Builds are reproducible across machines. Every Go patch
release requires a one-line `go.mod` change; CI makes forgetting it visible.
Supersedes D-008.

## D-010 — 2026-11-08 — active — Review disposition and issue plan

**Decision:** The consolidated review (`docs/review-v0.1-copilot.md`) is
turned into issues #7–#20 grouped by code area, so that each PR touches one
area and carries its own tests. All high and medium findings are fixed for
alpha. Low findings are fixed where local; C-10 (key history lost on backup
restore) and C-13 (orphan certificate after a failed state write) are
documented as known limits because both are consequences of the missing
rollback protection, which needs signed state (#22). R-09/R-10 (targeted
invalidation, per-peer config) are deferred to #20 because they change the
revision model shared by controller and client.

Order of work: security first (#7, #12), then availability (#8, #9, #10),
then validation and hardening (#11, #13, #14), then features and operations
(#15–#18), then the documentation pass and release (#19).

**Rationale:** R-01 is the only finding that lets a removed device take the
whole network down; it goes first. #12 removes the last fail-open path.
Availability fixes come before new features so that the renewal feature is
built on a stable session layer.
## D-011 — 2026-11-08 — active — Controller connection limits and timeouts

**Decision:** The controller's HTTP server sets every timeout: 5 s for the
TLS handshake and request header, 10 s read, 15 s write, 60 s idle. Every
error response closes the connection. Only HTTP/1.1 is offered. The
listener limits connections globally (1,152), per source IP (64 concurrent,
20/s with a burst of 64) and tunes TCP keepalive to 15 s + 3 × 5 s. The
global and per-source values are `serve` flags.

**Rationale:** Review finding R-01: without an idle timeout, any holder of a
CA-signed certificate — including a removed device — could pin all slots
forever. R-02: a 10 s handshake window let a single unauthenticated source
saturate the controller with ~115 connections/s. The per-source values are
derived from the mesh size: one client holds one control connection plus at
most 31 relay connections and opens them in a burst after a controller
restart; 64 covers two devices behind one NAT address. Hijacked relay
streams are unaffected because `Hijack` clears all deadlines.

**Consequences:** More than two devices behind one public address need a
higher `-max-conns-per-ip`. A distributed attacker can still exhaust the
global limit; that is accepted for alpha and documented.

## D-012 — 2026-11-08 — active — No allow-all without a policy

**Decision:** A configuration without a `policy` section denies all peer
traffic (`Config.Permits` returns false), the relay always requires the
configuration revision header, and `serve` refuses to start on such a state
with an instruction to run `policy-enable`. The prototype's legacy
allow-all behaviour is removed.

**Rationale:** Review finding C-01. Restoring a pre-policy backup or deleting
the section by hand silently turned the network into allow-all and disabled
the relay's revision check, contradicting the security model ("missing rules
never lead to allow-all"). Kinfold has no deployments that depend on the old
format; the rename (D-001) already requires updating all nodes together.

**Consequences:** Operators of a pre-policy state must run `policy-enable`
and add rules once. Clients that receive a policy-less configuration from an
old controller keep running but forward nothing and log a warning.

## D-013 — 2026-11-08 — active — Bounded grace period for controller outages

**Decision:** The client keeps its tunnel for up to 30 seconds while config
fetches fail and closes it after that (fail closed). A failed tunnel start
after a configuration change is retried on every poll instead of ending the
process. Polling reuses one mutual-TLS connection.

**Rationale:** Review findings A-02/A-03/A-04: a single failed poll tore
down every session on every client, so a 2 s controller restart or a short
network hiccup caused a full rebuild of the mesh; a transient
"interface already exists" ended the client permanently; every poll cost a
full TLS handshake.

The grace period does not extend revocation, because in the relay-only
design every data path passes through the controller:
- a removed device is rejected by the relay's identity check immediately;
- every configuration change closes all relay sessions, and a new session
  requires the *current* configuration revision, so a client that cannot
  fetch cannot reconnect with its stale view;
- direction and service rules are enforced by the receiving endpoint, which
  also cannot hold a session based on an outdated configuration.
What the grace period does allow is a client keeping an *idle* tunnel
interface up for 30 seconds while nothing can flow through it, which is the
availability trade-off it is meant to buy. This argument must be revisited
when a direct (non-relay) data path is added (#21).

**Consequences:** Clients survive controller restarts without dropping the
interface. The grace value is a constant for alpha.

## D-014 — 2026-11-08 — active — Stricter state validation

**Decision:** The controller rejects a state whose device certificates are
CA certificates, lack exactly the client+server authentication usages, use a
non-Ed25519 key, or whose common name differs from the peer ID. Expiry is
only reported (startup warnings, 30-day window), not rejected. The IPv4
network must be private (RFC 1918) or shared (RFC 6598) space. IPv6 values
must be canonical; the CLI canonicalises input. New certificates carry
explicit basic constraints, and new CAs have path length 0. Peer IDs must
differ from the controller host name.

**Rationale:** Review findings C-02/C-03/C-04. Each rule is defence in depth
against a state that the CLI would never produce but that a manual edit,
an old tool or a compromised writer could: a CA-capable "device" could mint
further certificates; a `0.0.0.0/0` network would route all host traffic
into the tunnel; non-canonical addresses produced spurious revision changes.
Rejecting an expired device would let one forgotten device take the whole
controller down, so expiry stays a warning (TLS rejects the device anyway).

**Consequences:** A hand-edited or very old state that violates a rule no
longer loads; the error names the peer and the rule.

## D-015 — 2026-11-08 — active — Online device certificate renewal

**Decision:** Devices renew their own certificates online via `POST /renew`
on the existing mutual-TLS controller connection. The device generates a new
Ed25519 key locally and sends only a CSR. The client requests renewal once
less than 1/3 of the lifetime remains (checked hourly); the controller
accepts once at most 1/2 remains, only from the device whose current
certificate is on record, under the state lock, with all `rotate-peer`
checks. The client writes the new credential atomically and restarts its
tunnel. `kinfold renew` does the same once.

**Rationale:** Review finding C-14 and alpha scope (D-003): with one-year
certificates and manual CSR exchange per device, every missed device means
an outage. Renewal over the authenticated channel needs no new trust
relationship: the controller already holds the CA key and already trusts the
current certificate. The 1/3–1/2 gap tolerates clock skew and retries while
preventing a device from churning certificates and key-history entries.

**Alternatives considered:** Offline renewal only (status quo; operationally
fragile). Keeping the old key and only extending the certificate (simpler,
but gives up regular key rotation, which the key history already supports).
Moving the CA key out of the serving process (better isolation, but then
online renewal is impossible; deferred together with signed configuration,
#22).

**Consequences:** `serve` writes the state file; administrators editing at
the same moment get a lock error and retry, devices retry after 503. A
renewal briefly reconnects all relay sessions because any change invalidates
them (until #20). Stolen credentials can be renewed by the thief, which
locks out the legitimate device and makes the theft visible.

## D-016 — 2026-11-08 — active — Service units and privilege separation

**Decision:** systemd units ship in `packaging/systemd/`. The controller
runs as a dedicated system user `kinfold` without capabilities; the client
runs per credential (`kinfold-client@<name>`) as a `DynamicUser` with only
`CAP_NET_ADMIN` (ambient, so the `ip` helper inherits it) and
`DeviceAllow=/dev/net/tun`. Both use `ProtectSystem=strict`, kernel and
namespace protections, an address-family allow list and the
`@system-service` system-call filter with `EPERM` for blocked calls.

**Rationale:** Review finding O-02: the client ran as full root. A
dedicated controller user (not `DynamicUser`) lets administrators run the
state-changing CLI under the same identity, which the directory lock and
the permission checks (review C-05) require. Blocked system calls return
EPERM rather than killing the process, because the Go runtime probes some
calls (e.g. `setrlimit`) at start-up.

**Verification:** `systemd-analyze verify` clean; `systemd-analyze security`
exposure 1.6 (controller) and 2.1 (client); both units started under
systemd 252 in a container, the client created its TUN interface with its
address.

**Consequences:** IPv6 DAD cannot be disabled under the client unit
(`ProtectKernelTunables`); accepted, see README. Instance names are limited
to 12 characters by the interface name `kf-<name>`.

## D-017 — 2026-11-08 — active — Controller address change and manual CA rotation

**Decision:** `renew-server -server host:port` moves the controller to a new
address by issuing a new server certificate under the existing CA; device
certificates stay valid and devices only update the `server` field of their
credential. CA rotation remains a documented manual procedure (new state,
re-enrollment of every device, parallel operation, cut-over) in
`docs/OPERATIONS.md`.

**Rationale:** Writing the operator guide showed that a DNS move required a
complete re-setup with re-enrollment of every device, although nothing
about the device trust changes. Automating CA rotation, by contrast, needs a
verifiable trust transition (two CAs trusted in parallel, signed hand-over),
which belongs with signed configuration (#22) and is out of alpha scope
(D-003).

## D-018 — 2026-11-08 — active — Renewal must survive a lost response

**Decision:** The controller records, per device, the fingerprint of the
certificate replaced by its last online renewal (`renewed_from` in the
state). A request authenticated with that previous certificate and signed
by the key of the *current* certificate returns the current certificate
again without changing the state; the relay passes `/renew` requests from
non-member certificates to the renewer for this purpose. The client stores
key and request in `<credential>.renewing` before sending and resends the
same request on the next attempt and when `run` starts. Failed renewal
attempts block the presented certificate for 30 s; a member outside its
window is refused before the state lock; renewals that would not outlive
the current certificate by a week (CA about to expire) are refused.

**Rationale:** The independent review of the alpha changes found that a
lost renewal response locked the device out permanently (finding 1, verified
by test): the controller had already replaced the certificate, and the
client discarded the new key. Requiring the new key's signature keeps the
retry useless to a thief of the old credential. Rate-limiting only failures
keeps lock contention bounded without delaying a legitimate retry.

**Consequences:** One more strict-decoded state field (`renewed_from`);
`remove-peer` and offline rotation clear it.

## D-019 — 2026-11-08 — superseded by D-020 — Republish v0.2-alpha after the reproducibility fix

**Decision:** The first `v0.2-alpha` release is withdrawn and the tag is
moved to the commit that fixes the release script (#56); the release is
published again under the same name.

**Rationale:** Verifying the release by rebuilding it locally showed that
three of four CI binaries were stamped `+dirty` (the script's output
directory inside the repository counted as an untracked change), so the
documented verification (`diff SHA256SUMS`) failed. The release was minutes
old, marked as pre-release and in a private repository without users, so
moving the tag misleads no one; a published release whose own verification
instructions fail would.

**Consequences:** Anyone who fetched the tag in those minutes must
`git fetch --tags --force`. Tags are not moved again once a release has
consumers; later fixes get new versions.

## D-020 — 2026-11-08 — active — Publish v0.2.1-alpha instead of moving the tag

**Decision:** `v0.2-alpha` stays published, marked as superseded. The fixed
release is published as `v0.2.1-alpha`.

**Rationale:** Deleting the release and moving a published tag (D-019) is a
destructive action the session was not permitted to perform; the owner chose
the non-destructive path. A new patch version also keeps the rule that
published tags never move.

**Consequences:** The alpha milestone ships as `v0.2.1-alpha`; the release
notes of `v0.2-alpha` point to it.

## D-021 — 2026-11-08 — active — Scope of v0.3.0-alpha

**Decision:** The post-alpha issues are implemented in this order and scope:

1. #20 — targeted relay invalidation (only sessions whose endpoints or
   pair rules changed), per-peer configuration (each device receives only
   the rules that concern it, with a per-peer revision), policy-only
   changes applied without recreating the TUN device.
2. #25 — Prometheus text-format metrics for controller and client on a
   separate, loopback-only listener.
3. #22 — configuration signed by a dedicated Ed25519 signing key (not the
   TLS CA key), carrying a lease (`not_after`) and a monotonically
   increasing serial. Clients verify the signature, persist the highest
   serial seen (rollback protection on the device) and fail closed when the
   lease expires. No quorum commit.
4. #23 — short-lived single-use enrollment tokens bound to device ID and
   address; online enrollment over TLS with the controller CA pinned by
   fingerprint.
5. #21 — a direct **TCP** path between devices using the same inner mutual
   TLS when a device is reachable (LAN or public address), with the relay as
   fallback. Revocation on the direct path relies on the signed leases of
   #22. UDP transport and NAT hole punching are deferred.
6. #26 — active/standby controllers: the standby replicates the signed
   state, clients know several controller addresses and fail over; an
   administrator promotes the standby. No quorum or automatic leader
   election.
7. #24 — a platform-neutral TUN interface and a macOS client (utun). Windows
   (requires the external Wintun driver) and mobile platforms are deferred.

**Rationale:** The rules from D-007 (standard library only) and
DECISIONS §2 (no custom cryptography) stay. An encrypted UDP transport
would require either an external module (QUIC/DTLS/WireGuard
implementations) or a self-designed datagram protocol; both contradict
those rules, so the direct path uses TCP+TLS. A replicated quorum needs a
consensus implementation that cannot be built and verified responsibly
within this milestone; active/standby removes the single point of failure
for availability while the revocation contract keeps documenting that a
quorum commit is missing. Signed leases come before the direct path because
the relay-only revocation argument (D-013) no longer holds once traffic can
bypass the relay.

**Consequences:** Each deferred part stays open as a follow-up issue.
v0.3.0-alpha changes the controller–client protocol (signed configuration);
controller and all clients must be upgraded together, as before.

## D-022 — 2026-11-08 — active — Split the post-alpha work into three releases

**Decision:** The work scoped in D-021 ships in three milestones, each with
its own release:

- **v0.3.0-alpha** — targeted session invalidation and per-peer
  configuration (#20), metrics (#25), enrollment tokens (#23).
- **v0.4.0-alpha** — signed configuration with leases (#22), then the direct
  TCP path (#21).
- **v0.5.0-alpha** — active/standby controllers (#26), macOS client (#24).

Deferred parts (#62 UDP/NAT traversal, #63 quorum, #64 Windows/mobile) carry
the label `future` and no milestone.

**Rationale:** The owner asked to split the work into releases where it
makes sense and to use milestones. The split follows dependencies and risk:
v0.3 changes operations without touching the trust model; v0.4 introduces
the new trust model (signed leases) together with the only feature that
requires it (traffic bypassing the relay); v0.5 builds high availability on
the signed state from v0.4 and adds a platform. Each release can be tested,
reviewed and rolled out on its own, and a problem in the riskier v0.4 work
does not hold back the operational improvements. The order inside v0.3
moves enrollment tokens (#23) before signed configuration, unlike D-021,
because it does not depend on it.

**Consequences:** Three protocol-compatibility boundaries instead of one;
each release notes its upgrade order. D-021 remains valid for the scope of
each issue.

## D-023 — 2026-11-08 — active — Per-device views and targeted invalidation

**Decision:** The controller serves each device only its view of the
configuration (itself, devices it has a rule with, those rules) and checks
the revision of that view on relay connect. A configuration change closes
only the relay sessions of pairs whose `PairSignature` (both certificates
and addresses, IPv6 network, rules and service rules between them)
changed. Clients apply changes that keep their own addresses to the running
agent, which keeps unchanged peer sessions.

**Rationale:** Review findings R-09/R-10 (#20): every change (including a
certificate renewal, D-015) used to reset the whole mesh and every member
learned the complete rule set. Per-device views make most changes invisible
to unrelated devices, so they need no reaction at all.

**Consequences:** The relay protocol changes (per-device revision); update
controller and clients together. `check-config` compares the view of the
credential's device. Revocation is unaffected: removing a device changes
the signature of every pair it belongs to.

## D-024 — 2026-11-08 — active — Online enrollment with single-use tokens

**Decision:** `kinfold token` issues a 256-bit random token bound to one
device ID and IPv4 address with a lifetime of at most seven days (default
one hour); the state stores only its SHA-256 hash. `kinfold join` generates
the key on the device and posts a CSR with the token to `POST /enroll`. The
controller now sends its CA certificate in the TLS chain and accepts
handshakes without a client certificate; only `/enroll` may be used
without one. The device verifies the server certificate against the CA
whose fingerprint it was given **before** sending the token. Enrollment
applies the `approve` checks (Ed25519, CN = ID, key history) and consumes
the token; failed attempts block the source address for 30 s.

**Rationale:** Issue #23: offline enrollment needs two manual file
transfers and an out-of-band hash comparison per device. A token reduces
this to one confidential message while keeping the key on the device. Pinning
the CA before revealing the token prevents a machine in the middle from
capturing it; binding it to ID and address limits the damage of a leaked
token to exactly the device it was meant for.

**Consequences:** Unauthenticated clients can now complete TLS handshakes,
which costs the controller more per connection than before; the listener
limits (D-011) bound that cost. A leaked unused token lets its holder enroll
as that device until it expires or is revoked.

## D-025 — 2026-11-08 — active — Signed configuration with leases

**Decision:** The controller holds a second Ed25519 key (`config_key` in the
state, generated on first start for older states) and signs every
configuration view it serves: device ID, issue time, lease end (2 minutes)
and the view. Devices pin the public key in their credential (new
credentials carry it; older ones fetch it once over the authenticated
connection and store it when the file is writable), verify every
configuration, refuse one issued before the newest they accepted (persisted
as `<credential>.seen`), refuse issue times more than 5 minutes in the
future, and close the tunnel when the lease of the last accepted
configuration ends.

**Rationale:** Issue #22 and the security model's production contract:
configuration must be bound to issuer, device and validity, and a device
must stop acting on authorization it can no longer confirm. This is the
prerequisite for the direct path (#21), where traffic no longer passes the
relay that enforced revocation so far (D-013). A separate key keeps the
option to move signing off the TLS-serving process later.

**Limits:** No quorum and no key rotation yet; the controller's own state
has no rollback protection; the lease depends on device clocks (forward
jumps fail closed, backward jumps extend at most to the issue-time check).
Pinning the key from the authenticated connection for pre-v0.4 credentials
trusts the controller exactly as before, once.

## D-026 — 2026-11-08 — active — Direct TCP path with relay fallback

**Decision:** Devices started with `-direct-listen` accept direct mutual-TLS
sessions. They advertise port and local addresses with each configuration
fetch; the controller adds the observed address, keeps registrations in
memory for 30 s and includes the peers' endpoints, signed but outside the
configuration (no revision change), in each device's envelope. The device
without a listener, or with the smaller ID, dials; otherwise the relay is
used, and relay sessions upgrade to a direct session when one becomes
available. An accepted direct session is preferred over a pending relay
pairing. The listener accepts only certificates of peers with a rule in the
current signed configuration; at most 16 handshakes are in flight. A
configuration request refused by an authenticated controller (403/503)
closes the tunnel immediately, without the grace period.

**Rationale:** Issue #21 within the D-021 scope: removes the relay as the
throughput bottleneck where devices can reach each other, without custom
cryptography or external modules. One dialing direction avoids duplicate
sessions and tie-breaking protocols. Immediate fail-closed on explicit
refusal restores the "ambiguous state fails closed" property that the relay
used to provide for all traffic.

**Consequences:** The D-013 revocation argument ("every path passes the
relay") no longer holds; revocation on the direct path is bounded by the
poll interval for reachable peers and by grace period and lease (D-025)
otherwise, both depending on correct clocks. Devices behind NAT on both
sides still need the relay. The direct listener is an additional
unauthenticated TLS endpoint on the device.

## D-027 — 2026-11-08 — active — Clock handling for signed configuration

**Decision:** A device measures the lease of a verified configuration from
the moment it received it on its own monotonic clock; its wall clock only
decides staleness (issue time at most 5 minutes in the future, lease end
plus 5 minutes not yet passed). Configurations must be strictly newer than
the newest accepted one. The controller issues strictly increasing issue
times within a process. `kinfold seen-reset` removes a device's watermark
for recovery after the controller's clock was set back.

**Rationale:** The pre-release review of v0.4 (findings 3 and 4) showed
that a device clock more than two minutes fast rejected every
configuration, and that the newest envelope could be replayed. Receipt-based
leases remove the dependency on device–controller clock agreement while
keeping the bound on how long a configuration is used.

**Consequences:** A replayed old envelope on a device with an empty
watermark can be used for at most the lease duration plus the clock
tolerance. Controller clock regressions across restarts still lock devices
out until fixed or reset; this is documented in the operator guide.

## D-028 — 2026-11-08 — active — Active/standby controllers

**Decision:** `replica-add` registers a standby controller (ID, address,
CA-signed client-only certificate) and writes a replica credential with
that client certificate and a server certificate for the standby's address.
`serve -standby` pulls the full state from `GET /replica/state` every two
seconds, checks it like `LoadState` (`State.Check`), stores it and serves
signed configuration and the relay under its own certificate; renewal,
enrollment and further replication are refused with a marked 503 (devices
keep their grace period). Signed configurations list the controller
addresses; devices remember them (`<credential>.controllers`), fail over to
the next controller on network errors, use the controller that answered
for relay connections and retry the primary every minute. Promotion is a
manual restart without `-standby`.

**Rationale:** Issue #26 within the D-021 scope: removes the controller as
a single point of failure for data-plane availability without implementing
consensus. Replicating the complete state (including keys) keeps the standby
able to sign configurations and keeps a promotion a restart, at the cost of
a second host with the same trust as the primary.

**Consequences:** No quorum, manual promotion, up to two seconds of
replication lag, and clocks of all controllers must be synchronised because
devices accept only strictly newer configurations. Devices on different
controllers cannot reach each other (corrected by D-032: direct-path
endpoints are not replicated either). The standby has no
systemd unit of its own; the controller unit with an added `-standby` flag
is used.

## D-029 — 2026-11-08 — active — macOS client via utun

**Decision:** The client supports macOS through a utun interface opened
with the kernel control socket `com.apple.net.utun_control`, using only
package `syscall` (no cgo, no external module). The 4-byte address family
header is added and stripped in the TUN wrapper, so the agent keeps seeing
raw IP packets. Addresses and routes are set with `/sbin/ifconfig` and
`/sbin/route` from fixed paths with a timeout, like `ip` on Linux. The
kernel chooses the interface name; `-interface` is ignored on macOS. CI
cross-compiles darwin/amd64 and darwin/arm64; `scripts/macos-smoke.sh` is a
manual end-to-end check (macOS client ↔ Linux client in Docker), because
CI runners cannot create utun interfaces without root.

**Rationale:** Issue #24. macOS is the most common second desktop platform
of the target group and offers a TUN-like interface without kernel
extensions or signed network extensions. Windows and mobile need driver or
app-store packaging and stay deferred (#64).

**Consequences:** The macOS client runs as root, has no launchd unit and no
automated test of the tunnel in CI; the smoke test must be run by hand
before releases that touch the TUN code. Behaviour above the TUN device is
identical to Linux.

## D-030 — 2026-11-08 — active — Explicit standby promotion

**Decision:** `replica-promote -data <dir> -standby <credential>` turns a
stopped standby's replicated state into a primary state: it checks that the
credential belongs to the state's CA and to a registered replica, sets the
controller address to the standby's address, issues a new server
certificate for it from the replicated CA and removes the standby's replica
entry, all under the state lock. The state is loaded like for offline
maintenance, because the old primary's server certificate may have expired.
`ChangeServerAddress` refuses a standby's address and validates the result
before it is written.

**Rationale:** Pre-release review of v0.5 (findings 1, 2): restarting a
standby without `-standby`, as D-028 documented, served the old primary's
address and certificate, so devices failed hostname verification, and
moving the primary onto a standby's address produced a state that no longer
loaded. Issuing a fresh certificate instead of reusing the standby's keeps
promotion working when the standby's own certificate is close to expiry.

Amended after the review of the fixes (#92): a running standby holds its
data directory lock for its whole lifetime, so `replica-promote` cannot be
overwritten by a live standby's next replication, and promotion (like
`replica-add`) refuses a host name equal to a device ID.

**Consequences:** Promotion stays manual and requires stopping the standby
briefly. Other standbys must be re-created after a promotion because their
credentials name the old primary.

## D-031 — 2026-11-08 — active — Bounded standby staleness

**Decision:** A standby serves its replicated state only while it is fresh:
- After a failed replication it keeps serving for at most
  `-standby-max-age` (default one hour). After that it answers
  configuration and relay requests with a marked 503 ("standby state is
  stale"), so devices keep their grace period and try other controllers.
- A 403 from the primary (the standby was removed) stops it at once.
- At startup it falls back to the stored state only when the primary is
  unreachable on the network and the state is younger than the maximum
  age. A refusal or an invalid state from the primary stops the start.
- The time of the last successful replication is the modification time of
  the stored state, touched on every successful pull. It is exported as
  `kinfold_standby_last_replication_timestamp_seconds`.
- The standby checks the primary's server certificate for signature and
  name but not for expiry.
- Registered standby certificates appear in the certificate warnings, and a
  standby warns about its own credential.
- Going stale also closes the relay sessions the standby carried (#92).
  Otherwise they would outlive the bound.

**Rationale:** Pre-release review of v0.5 (findings 4, 5, 7). An unbounded
standby kept signing fresh configurations from an arbitrarily old state, so
a cut replication link or `replica-remove` meant revocations never reached
it. Its devices dropped their tunnels at once when the primary's
certificate expired during an outage. One hour covers short outages and
maintenance. Longer outages call for promotion (D-030), and administration
needs the primary anyway.

**Consequences:** A revocation made while the standby cannot reach the
primary takes up to the maximum age to reach devices on the standby. A
standby that is down longer than the maximum age together with the primary
cannot be started until the primary is back or it is promoted.

## D-032 — 2026-11-08 — active — Failover on unavailable controllers

**Decision:** When fetching its configuration, a device treats any 503
(unmarked: no valid configuration; marked: shutting down or standby) as one
controller's condition and tries the remaining controllers. A 403 still ends
the search. Only when no controller serves does an unmarked 503 count as an
explicit refusal that closes the tunnel at once. Direct-path endpoints stay
per controller. Devices that use different controllers cannot reach each
other until they use the same controller again, and the documentation now
says so.

**Rationale:** Pre-release review of v0.5 (findings 3, 6). A primary whose
state failed to load answered with an unmarked 503, and every device closed
its tunnel although a healthy standby existed. The docs claimed that devices
on different controllers could still use the direct path, but endpoints are
registered only in the memory of the controller a device polls. Replicating
or forwarding endpoint registrations would add a write path from standby to
primary; that is out of scope for v0.5.

**Consequences:** A device whose primary is broken uses the standby within
one poll interval. A split between controllers can last up to the primary
retry interval (one minute) after the primary returns, or as long as some
devices cannot reach the primary.

## D-033 — 2026-11-08 — active — Scope of v0.6.0-alpha

**Decision:** v0.6.0-alpha is an operability release:
- a per-device relay bandwidth limit (#96);
- live device status metrics (#97);
- a macOS launchd service and an IPv6 smoke test (#98);
- the state-before-credential write order (#99);
- refreshed known limits (#100).

The `future` issues stay deferred: UDP/NAT (#62), quorum (#63) and Windows/mobile (#64).

**Rationale:** The owner asked to continue to the next release, with the
decisions left to me. The deferred issues need custom cryptography,
external modules or consensus, which D-007 and D-021 rule out at this
stage. The chosen items close gaps that the README itself lists as known
limits, and each fits into one PR.

**Consequences:** No protocol change for devices is planned. The relay
limit and the metrics are controller-side, and the controller and clients
remain compatible with v0.5.

## D-034 — 2026-11-08 — active — State before credential files

**Decision:** `add-peer`, `approve`, `rotate-peer` and `replica-add`
first check that the output path does not exist and that its directory
does. They then write the state, and only then the output file. If the
output write fails anyway:
- `approve` and `rotate-peer` print the certificate, which is public;
- `add-peer` and `replica-add` tell the operator to remove and re-add.

**Rationale:** In the old order, a failed state write left a CA-signed
certificate outside the member list (a known limit). The new order can only
fail the other way, with a member that has no credential. That is visible,
harmless and can be removed. The pre-check catches the usual causes, an
existing file or a missing directory, before anything changes.

**Consequences:** If the output write fails after the state was written, a
key from an `approve` is recorded in the key history. Its certificate is
not lost, because it is printed.
