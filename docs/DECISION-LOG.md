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
