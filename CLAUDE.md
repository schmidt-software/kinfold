# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Kinfold is an experimental, self-hosted IPv4/optional-IPv6 overlay network prototype with its own protocol (not compatible with any other VPN product). Do not reference other VPN/overlay products by name in code or docs. Go toolchain pinned in go.mod (see D-009), standard library only (no external modules — keep it that way; see docs/DECISIONS.md §2). Not production-ready; the controller is a full trust anchor.

Repository language is English (code, comments, docs, CLI output, commits, PRs). Docs that must stay accurate when behavior changes:
- `README.md` — feature list, CLI usage, known limitations
- `docs/DECISIONS.md` — architecture decision records
- `docs/SECURITY-MODEL.md` — threat model and open production requirements
- `docs/DECISION-LOG.md` — numbered log of every non-trivial decision; add an entry in the same PR as the change
- `docs/review-v0.1-copilot.md` — consolidated review of the baseline
- `docs/OPERATIONS.md` — operator guide (upgrades, backup/restore, CA rotation, incidents)
- `docs/user-guide/{en,de}/<tag>.md` — full user guide per release in English and German (D-038); never edit a released version's guide except for factual errors

## Workflow

Issue → branch `<issue>-<slug>` → atomic commits → PR → CI green → rebase merge → delete branch. No direct commits to `main`. Details in `CONTRIBUTING.md`. Run the Docker integration test locally before merging anything that touches `internal/agent`, `internal/relay` or the supervisor; note the result in the PR.

## Releases

Every release PR adds `docs/release-notes/<tag>.md` and the user guides `docs/user-guide/en/<tag>.md` and `docs/user-guide/de/<tag>.md`. Write them from the previous guide plus the changes in this release. Generate the appendix with `sh scripts/cli-reference.sh HEAD`. The PR also points the README's user-guide links and the index `docs/user-guide/README.md` at the new tag. `scripts/release.sh` and the release workflow refuse a tag without these files (`scripts/release-docs.sh check <tag>`). The workflow attaches the guides and links them in the release description.

## Commands

```sh
go build -o kinfold .
GOOS=linux GOARCH=amd64 go build -o kinfold-linux .   # client tunnel works on Linux and macOS
go test -race ./...
go vet ./...
go test ./internal/agent -run '^TestName$' -race           # single test
sh scripts/integration-docker.sh                            # end-to-end: 3 clients in Docker (needs NET_ADMIN, /dev/net/tun)

# Time-boxed fuzzing
go test ./internal/agent -run '^$' -fuzz '^FuzzPacketAddresses$' -fuzztime 30s
go test ./internal/agent -run '^$' -fuzz '^FuzzPacketFraming$'   -fuzztime 30s
go test ./internal/agent -run '^$' -fuzz '^FuzzRelayResponse$'   -fuzztime 30s
go test ./internal/agent -run '^$' -fuzz '^FuzzServicePacket$'   -fuzztime 30s
go test ./internal/core  -run '^$' -fuzz '^FuzzDecodeConfig$'    -fuzztime 30s
```

The integration script uses `alpine/socat:latest` by default (override with `KINFOLD_TEST_IMAGE`); it builds host + Linux binaries, creates temporary credentials and an isolated Docker network, and cleans up after itself.

## Architecture

Single binary (`main.go` → `app.Run`) acting as controller, relay and Linux client depending on subcommand. All subcommands are dispatched in one `switch` in `internal/app/app.go`.

**Packages**
- `internal/core` — shared model and persistence. `State` (pki.go) holds CA cert/key, server cert/key and `Config` (types.go: network(s), peers with fixed IPs and certs, directed `Policy` rules, optional per-service rules). `state.json` in the `-data` dir is the single source of truth; all mutating CLI commands go through `loadWritableState` (advisory flock on the data directory, unix only via `lock_unix.go`; `ErrStateLocked` when busy) and `core.WriteJSON` (atomic write + fsync of file and parent dir). `loadState` refuses group/world-accessible state (`perms.go`, override `KINFOLD_INSECURE_PERMISSIONS=1`) and validates the whole PKI, including the shape of every device certificate. `DecodeJSON` is a strict decoder (rejects unknown/duplicate fields, trailing data, oversize docs) — any new JSON field breaks older binaries, so document the upgrade order when adding one. `Config.Clone` gives alias-free copies (policy is a pointer). Also: offline enrollment (`keygen`/`approve`/`enroll`), key history against public-key reuse, server cert renewal and address change, online device renewal rules incl. idempotent retry via `RenewedFrom` (`renewal.go`).
- `internal/relay` — the controller's HTTPS server (mutual TLS 1.3). Peer identity = client cert fingerprint looked up in a map precomputed per config update (`derive`). Endpoints: `GET /config`, `CONNECT /relay?peer=<id>` (pairs two waiting peers and bridges raw byte streams; requires the current config revision header and an allow rule for the pair; a reconnect for the same ordered pair supersedes the stale session), `POST /renew` (CSR → new device cert via an injected `Renewer`). Every error response closes the connection. `Watch` reloads `state.json` every second; a config change bumps a generation counter and drops existing sessions, closed outside the lock without TLS close_notify (`forceClose`); a changed CA/server identity closes the relay until restart. `NewLimitedListener` caps connections globally, per source IP and by per-source accept rate.
- `internal/agent` — the client. `ConfigClient` polls `/config` over one reused mTLS connection and sends renewals; `Connect` opens a relayed stream with a second, end-to-end mutual TLS 1.3 session between the two devices, verified by exact pin against the controller's peer list plus CA chain and role EKU. `certificateConn` enforces an I/O deadline at the earliest cert expiry, clamps caller deadlines to it and closes the socket before the TLS layers. `Run` reads packets from the TUN device, validates source/destination (anti-spoofing), applies directed + service policy (`services.go`), and frames packets (`WritePacket`/`ReadPacket`, MTU 1280) to per-peer `link`s; each session gets a fresh send queue and a 10 s per-frame write deadline; reconnects use jittered backoff (`backoff.go`). TUN on Linux (`tun_linux.go`, `IFF_TUN_EXCL`, `ip` from fixed paths) and macOS (`tun_darwin.go`, utun via kernel control socket, 4-byte family header, `/sbin/ifconfig`+`/sbin/route`; D-029); `tun_other.go` stubs it out. The macOS tunnel is not testable in CI: run `sh scripts/macos-smoke.sh` (needs sudo, interactive terminal) when touching it.
- `internal/app` — CLI and lifecycle glue. `server.go` builds the production `http.Server` (all timeouts, HTTP/1.1 only) and listener (keepalive + limits); `controller.go` runs it with graceful shutdown. `supervisor.go` polls the config every 2 s, keeps the tunnel through 30 s of controller outage (D-013), retries failed tunnel starts, and restarts on change; its dependencies (`tunnelOpener`, `configFetcher`, `agentRunner`) are injected so it is testable without a real TUN. `renew.go` implements controller-side renewal under the state lock and the client renewal loop with a pending-request file (`<credential>.renewing`) for recovery; `runSupervised` waits for it and restarts the tunnel with a renewed credential. `logging.go` (slog flags) and `version.go` (`kinfold version`, ldflags `Version`).
- `packaging/systemd/` — hardened controller and per-credential client units. `scripts/release.sh` + `.github/workflows/release.yml` — reproducible release builds on `v*` tags (release notes from `docs/release-notes/<tag>.md`).

**Trust/security invariants to preserve** (see docs/SECURITY-MODEL.md): a certificate alone never authorizes — it must exactly match the currently loaded controller config; traffic is denied by default and checked per direction; size limits exist on all inputs (16 KiB headers, 64 KiB enrollment/renewal bodies, 4 MiB JSON, MTU frame limit); every connection phase has a timeout; secrets must not be readable by others; missing policy means deny. Tests that write controller state into a temp dir must make it mode 0700 (`privateTempDir` helpers). Tests are organized by concern (`*_limits_test.go`, `*_fuzz_test.go`, `rotation_test.go`, `ipv6_test.go`, …) — add tests next to the matching concern.
