# Code review of the `v0.1-copilot` baseline

Date: 2026-11-08. Baseline: tag `v0.1-copilot` (renamed to Kinfold in later
commits; line numbers refer to the code right after the rename). Method: see
decision D-005 — one full read by the lead plus three independent adversarial
passes (`internal/core`; `internal/agent`; `internal/relay` + `internal/app`).
Every finding below was cross-checked against the code; reviewer claims that
depend on standard-library behaviour were checked against the Go 1.26 sources.

## Overall verdict

The prototype is **carefully written and conservative**. No critical finding.
The cryptographic core (TLS 1.3 everywhere, exact certificate pinning plus
chain and role-EKU verification on the inner session, Ed25519-only
enrollment, strict JSON decoding, transactional state mutation, atomic durable
writes, fail-closed reloads) holds what the documents promise.

The weaknesses are concentrated in three areas:

1. **Abuse resistance of the controller's HTTP server** (one high finding):
   missing idle/read timeouts let any holder of a CA-signed certificate —
   including a removed device — pin connection slots forever, and an
   unauthenticated attacker can saturate the listener cheaply.
2. **Availability under ordinary faults**: a single failed config poll tears
   down every tunnel; stale relay sessions block reconnects for minutes; a
   failed TUN re-open terminates the client; peer sessions have no liveness
   check while data is in flight.
3. **Fail-open legacy paths and validation gaps**: `Policy == nil` still means
   allow-all; peer certificates in the state are only signature-checked;
   operator foot-guns (network `0.0.0.0/0`, world-readable secrets) are
   accepted silently.

Test coverage is good for the paths it targets (limits, fuzzing of parsers,
shutdown ordering) but thin for timer paths, the relay pairing state machine
and the production `http.Server` configuration.

## Findings

Severity: **H** high, **M** medium, **L** low. "Issue" is the GitHub issue that
fixes or defers the finding.

### Controller HTTP server and relay

| ID | Sev | Location | Finding | Issue |
|---|---|---|---|---|
| R-01 | H | app/app.go:631 | `http.Server` sets only `ReadHeaderTimeout`. With `IdleTimeout = ReadTimeout = 0`, `net/http` clears the read deadline between requests (`server.go:2116`), so an idle keep-alive connection holds a `LimitListener` slot forever. `http.Error` for 403/503 does not close the connection. Any holder of an unexpired CA-signed certificate — including a device removed with `remove-peer` — can open 1,152 connections, get 403 once each and stall the controller permanently; every client then fails its poll and closes its tunnel. | #7 |
| R-02 | M | app/app.go:627-631 | An unauthenticated client holds a slot for the full 10 s TLS handshake timeout (derived from `ReadHeaderTimeout`). ~115 new connections/s from one source saturate the controller; no per-source limit exists. Combined with the client's fail-closed polling this turns a cheap controller DoS into a network-wide outage. | #7 |
| R-03 | L | relay/server.go:145 | HTTP/2 is negotiated implicitly (`ServeTLS` adds `h2`); the design assumes HTTP/1.1 (CONNECT hijack). A peer can multiplex up to 250 `/config` streams per connection. | #7 |
| R-04 | L | app/app.go:623, agent/transport.go:107 | Dead peers are only detected by Go's default TCP keepalive (15 s idle, 15 s interval, 9 probes ≈ 2.5 min). | #7, #9 |
| R-05 | M | relay/server.go:86-90 | `invalidate()` closes `*tls.Conn`s while holding `s.mu`. `tls.Conn.Close` sends close_notify with its own 5 s write deadline, overriding the preceding `SetDeadline(now)`. A peer that stops reading can make a config update hold the global lock for 5 s per connection; every `/config` request blocks meanwhile. | #8 |
| R-06 | M | relay/server.go:216-228, 314-331 | A stale session for an ordered pair (peer crashed, NAT mapping dropped) blocks every reconnect of that pair with 409 until TCP keepalive kills the old connection (minutes). | #8 |
| R-07 | L | relay/server.go:149-161, 203-204 | `identity()` parses every peer certificate per request; `Revision()` (JSON marshal + SHA-256) runs under the global lock per CONNECT. | #8 |
| R-08 | L | app/controller.go:38-39 | `handler.Close()` runs before the watcher has stopped; a tick in that window logs a misleading "relay closed" error on every SIGTERM. | #8 |
| R-09 | L | relay/server.go:71-73 | Any config change invalidates all sessions, including unaffected pairs. | post-alpha (#20) |
| R-10 | L | relay/server.go:177-181 | `/config` returns every rule between third parties to every member. | post-alpha (#20) |

### Client (agent, supervisor, TUN)

| ID | Sev | Location | Finding | Issue |
|---|---|---|---|---|
| A-01 | M | agent/agent.go:234-247, transport.go:191 | Peer sessions have no write deadline; the only socket deadline is certificate expiry. When the path dies while data is queued, `WritePacket` blocks until TCP gives up retransmitting (~15 min on Linux), `connected` stays true and all packets to that peer are dropped. | #9 |
| A-02 | M | app/supervisor.go:139-147 | A single failed config fetch closes the tunnel and all peer sessions; an 11 s control-path hiccup or a 2 s controller restart causes a full rebuild of every session on every client. | #10 |
| A-03 | M | app/supervisor.go:156-161 | If re-opening the TUN fails after a config change (e.g. "interface already exists" while the kernel still tears down the old device, or a transient `ip` failure), the supervisor returns and the client process exits. | #10 |
| A-04 | L | agent/transport.go:35-42 | `FetchConfig` creates a new `http.Transport` and performs a full mTLS handshake every 2 s per client. | #10 |
| A-05 | L | agent/agent.go:129,144,155 | Per-packet and per-attempt log lines without rate limit. | fixed in #5 (debug level) |
| A-06 | L | agent/agent.go:165-169 | The queue drain after a session races with the TUN reader; a stale packet can survive into the next session. | #9 |
| A-07 | L | agent/agent.go:258 | Closing the double TLS stack can block up to ~10 s (two close_notify writes) during shutdown. | #9 |
| A-08 | L | agent/tun_linux.go:47 | `ip` is resolved through `$PATH` of a root process, without timeout. | #11 |
| A-09 | L | agent/tun_linux.go:24-34 | `InterfaceByName` check is a TOCTOU; without `IFF_TUN_EXCL` `TUNSETIFF` attaches to a concurrently created persistent TUN of the same name. | #11 |
| A-10 | L | agent/tun_linux.go:43 | IPv6 address added without `nodad`; the ULA is tentative for ~1 s after every (re)start. | #11 |
| A-11 | L | agent/transport.go:53,136 | Controller/relay status strings are logged unfiltered (control characters). | #9 |

### State, PKI and CLI

| ID | Sev | Location | Finding | Issue |
|---|---|---|---|---|
| C-01 | M | core/types.go:160-170, relay/server.go:203 | `Policy == nil` (legacy or hand-edited state) means allow-all, and the relay skips the configuration revision check. Contradicts the security model's "missing rules never lead to allow-all". | #12 |
| C-02 | L | core/pki.go:275-283 | Peer certificates in the state are only checked for the CA signature: expired, `IsCA`, wrong EKU and CN ≠ ID all load. Leaf certificates carry no BasicConstraints; the CA has no path-length limit; a peer ID equal to the controller host name is accepted. | #13 |
| C-03 | L | core/types.go:81-84 | Any IPv4 prefix is accepted, including `0.0.0.0/0`, loopback, multicast and link-local; the supervisor configures the TUN with it. | #13 |
| C-04 | L | core/types.go:108-117 | Non-canonical IPv6 text (`FD77::2`, `fd77:0:0:0:0:0:0:2`) is stored verbatim; revisions differ for the same address. | #13 |
| C-05 | M | core/pki.go:212, app/app.go:651 | `state.json` (contains the CA key) and credential files are read without checking their permissions. | #14 |
| C-06 | L | core/lock_unix.go:13-24 | The advisory lock is on a removable file; deleting `.state.lock` while a writer holds it allows a lost update. | #14 |
| C-07 | L | core/pki.go:342-354 | `init` leaves an empty data directory behind if the state write fails; a retry then refuses. | #14 |
| C-08 | L | core/enrollment.go:36-45 | PEM parsing rejects CRLF line endings and a trailing blank line with a misleading message. | #14 |
| C-09 | L | app/app.go:460, core/enrollment.go:118 | `enroll -server` is not validated as `host:port`; the error appears only at `run`. | #14 |
| C-10 | L | core/pki.go:26, key_history.go:33 | An absent `used_peer_keys` field is treated as legacy state, so restoring an old backup silently drops revoked key fingerprints. Inherent to the missing rollback protection. | documented (#19) |
| C-11 | L | core/types.go:252-259 | `Revision()` is sensitive to nil-vs-empty slices and rule order. All consumers round-trip JSON today, so no current bug. | #13 (test pins behaviour) |
| C-12 | L | core/types.go:193-201, 238 | `SetRule`/`SetServiceRule` mutate shared slice backing arrays through the `*Policy` pointer. No current bug; tests that copy `Config` cannot detect policy mutation. | #13 |
| C-13 | L | app/app.go:417-422 | If the state write fails after `approve` wrote the certificate, a valid orphan certificate exists outside the list (exploitable only via R-01, which #7 removes). | documented (#19) |
| C-14 | L | core/pki.go:181 | Device certificates expire after one year and can only be renewed by an out-of-band CSR exchange per device. | #15 |

### Operability (no defect, missing capability for alpha)

| ID | Finding | Issue |
|---|---|---|
| O-01 | No `version` command or build metadata; unstructured logging. | fixed in #5 |
| O-02 | No service units or privilege separation; the client runs as full root. | #16 |
| O-03 | No release builds or checksums. | #17 |
| O-04 | No documented CA rotation or backup/restore procedure. | #18 |

## Test coverage gaps

Addressed in the issue that touches the code:

- `Config.Revision()` has no tests (#13).
- Relay: 30 s pairing timer path, cancel-vs-match race, generation re-check
  after hijack, early-data rejection, "TLS identity changed" watcher path, and
  the production `http.Server` timeouts (#7, #8).
- Agent: no reconnect test for `link.run`, no test that a blocked
  `WritePacket` ends on cancel, no test that a device certificate presented as
  controller certificate is rejected, `TestRelayPeerTLSAndPinning` passes if
  either side fails (#9).
- Supervisor: no test for `start()` failure after a change, ID change, or
  repeated opens during an outage (#10).
- Core: `validatePKI` negatives, `onePEM` edge cases, CSR fields ignored and
  non-Ed25519 rejected, key-history migration cases, `Validate` limits,
  `NewState` address validation (#13, #14).

## What is done well (keep it)

1. Inner peer TLS: `InsecureSkipVerify` is fully compensated by
   `VerifyConnection` (exact pin + chain + role-dependent EKU); TLS 1.3 and a
   mandatory client certificate on both sides.
2. Two-level certificate deadline: a monotonic socket deadline plus a wall-clock
   check after each read, so TLS-buffered plaintext is not delivered after
   expiry.
3. Strict JSON decoding everywhere (size, depth, unknown fields, case-folded
   duplicates, trailing data) and `Validate()` before every write.
4. Transactional mutation (copy → validate → commit) for peers and key
   history; atomic, durable writes with explicit "durability uncertain" errors;
   O_EXCL/0600 for secrets.
5. Relay generation counter re-checked after hijack; admission limits matched
   to the 32-peer mesh; supervisor ownership (one fetch in flight, tunnel closed
   exactly once, agent failure not masked by a hanging fetch).

## Disposition

All H and M findings are fixed for `v0.2-alpha`. L findings are fixed where
the change is local; the rest are documented as known limits or moved to
`post-alpha` issues, with the reason recorded in the decision log.
