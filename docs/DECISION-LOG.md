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

## D-019 — 2026-11-08 — active — Republish v0.2-alpha after the reproducibility fix

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
