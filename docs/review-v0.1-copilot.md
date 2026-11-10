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

## Review of the alpha changes

Before the release, the complete diff from `v0.1-copilot` to the alpha
candidate was reviewed again by an independent reviewer that had the code
and the threat model but not the lead's reasoning. It confirmed the
authorization logic of the new renewal endpoint, the relay refactoring, the
permission checks and the grace-period argument (D-013), and found:

| # | Sev | Finding | Fix |
|---|---|---|---|
| 1 | M/H | A lost `/renew` response locked the device out permanently (verified by test). | #47: idempotent retry with the replaced certificate, pending request stored on the device (D-018). |
| 2 | L/M | The client could exit while a renewal was between request and storage. | #47: wait for in-flight renewal; resume at start. |
| 3 | M | A connection superseded while writing its 200 response could still register as waiter, orphan the live waiter and leak a goroutine (verified by test). | #45. |
| 4 | M | The listener's per-source map grew without bound. | #46: capped, idle sources swept. |
| 5 | M | IPv6 sources were counted per /128. | #46: aggregated by /64. |
| 6 | L/M | 64 connections per source broke three or more devices behind one NAT. | #46: default 128, documented. |
| 7 | L | Every `/renew` took the state lock. | #47: window pre-check before the lock, failed attempts rate-limited. |
| 8 | L | Renewals accelerated in the CA's last year. | #47: renewals that do not extend validity are refused. |
| 9 | L/M | v0.1 states with non-canonical IPv6 no longer loaded. | #48: normalised on load. |
| 10 | L | Controller unit install order failed (`useradd` without home). | #48. |
| 11 | L | Release notes file missing; actions and govulncheck unpinned. | #48, #19. |

## Review before v0.3.0-alpha

An independent review of `v0.2.1-alpha..60b8d8c` (per-device views, metrics,
token enrollment) found no critical or high issues and confirmed the
completeness of `PairSignature`, the revocation behaviour of targeted
invalidation and the controller authentication in `join`. Findings, all
fixed in #71:

| # | Sev | Finding | Fix |
|---|---|---|---|
| 1 | M | Unauthenticated `/enroll` took the state lock before checking the token; failure throttling was per /128 and skipped busy results. | Token hashes cached from the watcher are checked first; throttling per IPv4 address or IPv6 /64, busy results count. |
| 2 | L | `join` consumed the token before storing anything locally. | Pending file and idempotent retry with the same token and key. |
| 3 | L | CONNECT distinguished hidden from unknown devices. | Same 403 answer. |
| 4 | L | Pending tokens survived `approve`, `add-peer`, `remove-peer`; weak token validation. | Those commands drop matching tokens; validation checks address and lifetime. |
| 5 | L | Token on the command line. | `-token-file` (or `-` for stdin). |
| 6 | L | Go quoting instead of Prometheus label escaping. | Prometheus escaping. |
| 7 | L | Data race in a supervisor test. | Test clones the configuration. |

## Review before v0.4.0-alpha

An independent review of `v0.3.0-alpha..87ff094` (signed configuration,
direct path) found no critical or high issues and confirmed that the signed
payload is unambiguous, key pinning cannot be downgraded, a non-controller
cannot trigger the immediate fail-closed and the direct path cannot be
redirected to an impostor. Findings, all fixed in #79:

| # | Sev | Finding | Fix |
|---|---|---|---|
| 1 | M | The configuration that starts the tunnel ignored the persisted rollback watermark. | Start-up and post-renewal fetches honour and update `.seen`. |
| 2 | M | Peer IDs differing only in case broke signed payloads (case-folded duplicate keys). | IDs must be unique ignoring case. |
| 3 | M | Fast device clocks rejected every configuration; a controller clock stepping back locked clients out. | Lease measured from receipt on the device; staleness with ±5 min tolerance; strictly increasing issue times per controller process; `seen-reset` for recovery. |
| 4 | L | The newest envelope could be replayed. | Strictly newer issue time required. |
| 5 | L | The direct listener could be exhausted by one source. | At most two pending handshakes per source, 5 s handshake deadline. |
| 6 | L | A completed TLS 1.3 handshake counted as acceptance; session leaks while switching. | Acceptance marker from the acceptor; newest direct session wins; deliveries to stopped links refused; leaks closed. |
| 7 | L | `-direct-dial=false` ignored with `-direct-listen`. | Fixed. |
| 8 | L | Devices could make peers dial arbitrary addresses. | Advertised addresses must be private; public only as observed. |
| 9 | L | A controller restart made clients close at once (503). | Shutdown answers are marked and keep the grace period. |
| 10 | L | Token-enrolled credentials lacked the configuration key. | Sent with the enrollment response over the pinned connection. |

## Review before v0.5.0-alpha

An independent review of `v0.4.0-alpha..55b2f9d` (standby controllers, macOS
client) found the macOS utun code correct (kernel ABI constants and struct
layouts, descriptor handling, header translation) and confirmed that only
registered replica certificates receive the controller state and that a
standby refuses renewal, enrollment and further replication. Findings, fixed
in #84, #85 and #86:

| # | Sev | Finding | Fix |
|---|---|---|---|
| 1 | H | The documented promotion (restart without `-standby`) served the old primary's address and certificate; devices failed hostname verification. | `replica-promote` switches the state to the standby's address with a new server certificate and removes its replica entry (D-030). |
| 2 | M | `renew-server -server` to a standby's address wrote a state that no longer loaded. | Refused; the result is validated before writing. |
| 3 | M | Docs claimed devices on different controllers could use the direct path; endpoints are per controller. | Docs corrected (D-032). |
| 4 | M | A standby with broken replication (or after `replica-remove`) served its last state indefinitely; startup fell back on any error. | `-standby-max-age` (1 h), immediate stop on 403, startup fallback only when unreachable, replication age metric (D-031). |
| 5 | L | An expired primary server certificate made the standby close with an unmarked 503, dropping device tunnels. | Standby ignores that certificate's expiry. |
| 6 | L | An unmarked 503 from a broken primary ended the device's tunnel although a standby was healthy. | Devices try the other controllers on 503. |
| 7 | L | Standby certificates expired without warning or documented renewal. | Certificate warnings and documented renewal. |

A second review of the fixes found three more issues, fixed in #92: a
standby going stale kept the relay sessions it already carried,
`replica-promote` could be overwritten by a standby that was still running,
and promotion did not reject a host name equal to a device ID.

## Review before v0.6.0-alpha

An independent review of `v0.5.0-alpha..a28c91f` covered the relay bandwidth
limit, the device status metrics, the write order, the macOS changes and the
release tooling. It found no high or medium issues. It confirmed:
- the lock order between metric families and the relay mutex;
- the bandwidth accounting across concurrent sessions;
- the write-order recovery paths;
- that the release gate runs before anything is published.

Findings, fixed in #117:

| # | Sev | Finding | Fix |
|---|---|---|---|
| 1 | L | `-relay-rate`/`-relay-burst` accepted values that switched the limit off (Inf after suffix scaling, overflowing pauses below 1 B/s, a burst without a rate). | Refused; the log shows the effective values. |
| 2 | L | Buckets and throttle series of removed devices were never freed. | Freed with the device's status. |
| 3 | L | A configuration fetch racing with a removal re-created the device's status. | Only current members are recorded. |
| 4 | L | A throttled bridge outlived a superseded connection and kept its partner endpoint counted. | Per-bridge stop function, called by `supersede`. |
| 5 | L | `cli-reference.sh` failed silently on a bad ref. | Error message. |

A second review of the fixes found that `invalidate` and `invalidatePairs`
did not end paused bridges either (L). They now call the same stop function.

## Review before v0.6.1-alpha

v0.6.1-alpha ships the eleven findings of a review of the whole code base
at v0.6.0-alpha (#121 to #131): a controller certificate that expired
without a warning on a long-running controller, `join` dropping its
pending enrollment on any error text containing `403`, a grace period
longer than documented, a connection burst of 1 with the per-source limit
disabled, and seven duplications or dead code paths.

An independent review of `v0.6.0-alpha..6b16899` checked every commit
against its callers and the documentation. It found no correctness or
security issue. It confirmed:
- `/enroll` answers 403 only for an invalid token, so the pending
  enrollment is removed in exactly that case;
- the daily warning has no data race and does not log a standby's own
  credential twice at startup;
- the server certificate built by `init` is unchanged, and no existing
  state file is newly refused;
- pin, chain and role check of the relayed session are identical to
  before;
- the send queue has one producer and one consumer, and the byte counter
  still excludes the length prefix.

Finding, fixed in the release PR (#143):

| # | Sev | Finding | Fix |
|---|---|---|---|
| 1 | L | `TestSuperviseGraceCountsFromFetchStart` failed above 1 s although the correct code needs about 0.8 s; a stalled CI runner could fail it. | Bound raised to 1.15 s; the old logic cannot finish before 1.2 s. |

The fix changes one bound in a test. It was checked by running the test
against the old logic (fails) and the new one (passes) instead of a second
review (D-043).
