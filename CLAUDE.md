# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Experimental, self-hosted IPv4/optional-IPv6 overlay network prototype, functionally inspired by ZeroTier but **not protocol-compatible** and not a clone. Pure Go 1.24, standard library only (no external modules — keep it that way; see ENTSCHEIDUNGEN.md §2). Not production-ready; the controller is a full trust anchor.

Project docs are in German and must stay accurate when behavior changes:
- `README.md` — feature list, CLI usage, known limitations
- `ENTSCHEIDUNGEN.md` — architecture decision records
- `SICHERHEITSMODELL.md` — threat model and open production requirements

User-facing CLI/error output is also German (e.g. `Fehler:` prefix in `main.go`).

## Commands

```sh
go build -o my-zerotier .
GOOS=linux GOARCH=amd64 go build -o my-zerotier-linux .   # client tunnel only works on Linux
go test -race ./...
go vet ./...
go test ./internal/agent -run '^TestName$' -race           # single test
sh scripts/integration-docker.sh                            # end-to-end: 3 clients in Docker (needs NET_ADMIN, /dev/net/tun)

# Time-boxed fuzzing
go test ./internal/agent -run '^$' -fuzz '^FuzzPacketAddresses$' -fuzztime 30s
go test ./internal/agent -run '^$' -fuzz '^FuzzPacketFraming$'   -fuzztime 30s
go test ./internal/agent -run '^$' -fuzz '^FuzzRelayResponse$'   -fuzztime 30s
go test ./internal/core  -run '^$' -fuzz '^FuzzDecodeConfig$'    -fuzztime 30s
```

The integration script uses `alpine/socat:latest` by default (override with `MYZT_TEST_IMAGE`); it builds host + Linux binaries, creates temporary credentials and an isolated Docker network, and cleans up after itself.

## Architecture

Single binary (`main.go` → `app.Run`) acting as controller, relay and Linux client depending on subcommand. All subcommands are dispatched in one `switch` in `internal/app/app.go`.

**Packages**
- `internal/core` — shared model and persistence. `State` (pki.go) holds CA cert/key, server cert/key and `Config` (types.go: network(s), peers with fixed IPs and certs, directed `Policy` rules, optional per-service rules). `state.json` in the `-data` dir is the single source of truth; all mutating CLI commands go through `loadWritableState` (advisory `.state.lock`, unix only via `lock_unix.go`) and `core.WriteJSON` (atomic write + fsync of file and parent dir). `DecodeJSON` is a strict decoder (rejects unknown/duplicate fields, trailing data, oversize docs) — any new JSON field breaks older binaries, which is why IPv6 rollout requires updating all nodes first. Also: offline enrollment (CSR via `keygen`/`approve`/`enroll`), key history to prevent public-key reuse across peers, server cert renewal.
- `internal/relay` — the controller's HTTPS server (mutual TLS 1.3). Peer identity = client cert fingerprint matched exactly against `Config.Peers`. Endpoints: `GET /config` (returns the config) and `CONNECT /relay?peer=<id>` (pairs two waiting peers and bridges raw byte streams). Only pairs with at least one directed allow rule get a session. `Watch` reloads `state.json` every second; a config change bumps a generation counter and drops existing sessions; a changed CA/server identity closes the relay until restart. `LimitListener` caps concurrent connections.
- `internal/agent` — the client. `FetchConfig` / `Connect` talk to the controller with the outer mTLS; inside each relayed stream a second, end-to-end mutual TLS 1.3 session runs between the two devices, verified against the controller's peer list and CA. `certificateConn` enforces an I/O deadline at the earliest expiry of involved certs. `Run` reads packets from the TUN device, validates source/destination against assigned addresses (anti-spoofing), applies directed + service policy (`services.go`), and frames packets (`WritePacket`/`ReadPacket`, fixed MTU 1280) to per-peer `link`s with jittered exponential backoff (`backoff.go`). TUN is Linux-only (`tun_linux.go`; `tun_other.go` stubs it out) and configured via the `ip` command.
- `internal/app` — CLI and lifecycle glue. `controller.go` runs the HTTP server with graceful shutdown (relay sessions closed immediately, HTTP requests drained up to 5 s). `supervisor.go` polls the config every 2 s and restarts the agent/tunnel on change; its dependencies (`tunnelOpener`, `configFetcher`, `agentRunner`) are injected function types so it is testable without a real TUN.

**Trust/security invariants to preserve** (see SICHERHEITSMODELL.md): a certificate alone never authorizes — it must exactly match the currently loaded controller config; traffic is denied by default and checked per direction; size limits exist on all inputs (16 KiB response headers, 64 KiB enrollment files, MTU frame limit). Tests are organized by concern (`*_limits_test.go`, `*_fuzz_test.go`, `rotation_test.go`, `ipv6_test.go`, …) — add tests next to the matching concern.
