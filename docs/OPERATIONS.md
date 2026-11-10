# Operator guide

This guide covers running a Kinfold network day to day. Paths follow the
systemd units in `packaging/systemd/`: controller state in
`/var/lib/kinfold-controller/state`, client credentials in
`/var/lib/kinfold-client/<name>/credential.json`. Run controller commands as
the `kinfold` user (`sudo -u kinfold kinfold …`).

## What is where

| Item | Location | Secret | Notes |
| --- | --- | --- | --- |
| CA certificate + **CA private key** | controller `state.json` | **yes** | Whoever holds it can admit devices. |
| Controller certificate + key | controller `state.json` | yes | Renew yearly (`renew-server`). |
| Member list, addresses, rules, key history | controller `state.json` | no (integrity matters) | Changed only through the CLI and renewals. |
| Device key + certificate | device `credential.json` | **yes** | Renewed automatically by `run`. |

The controller refuses to read its state and the client refuses to read its
credential when they are accessible by group or others.

## Upgrades

Kinfold uses strict decoders: a newer binary may write fields an older one
rejects, and the relay protocol may change between versions (as with the
rename in v0.2). Always upgrade **the controller and all clients together**:

1. Read the release notes for compatibility remarks.
2. Verify the release (`SHA256SUMS`, or rebuild with `scripts/release.sh`).
3. Back up the controller state (below).
4. Stop clients, replace the controller binary, restart the controller,
   replace client binaries, start clients.

## Backup and restore

Back up the whole state directory while no administrative command runs, for
example with the controller stopped or under the state lock:

```sh
sudo -u kinfold flock /var/lib/kinfold-controller/state \
  tar -C /var/lib/kinfold-controller -czf - state | gpg --encrypt -r ops@example.com > kinfold-state-$(date +%F).tar.gz.gpg
```

Store backups encrypted; they contain the CA private key.

**Restoring an older backup rolls back authorization.** The state has no
rollback protection (see `SECURITY-MODEL.md`). After restoring:

- Devices removed after the backup are authorized again: remove them again
  with `remove-peer`.
- Devices whose certificate was renewed or rotated after the backup are
  rejected (their current certificate is not in the restored state):
  re-enroll them with `keygen` / `approve` / `enroll` or `rotate-peer`.
- Key fingerprints recorded after the backup are lost, so a key removed in
  that period could be approved again. Check new requests carefully.

Backups taken before v0.4 contain no configuration signing key
(`config_key`). A controller started from such a backup creates a new key,
and every device then rejects its configurations ("configuration signature
is invalid"). Re-enroll the devices, or restore a backup taken with v0.4 or
later.

Restore with the controller stopped, keep mode `0700` on the directory and
`0600` on `state.json`, then start the controller and check the startup log
for certificate warnings.

## Certificate lifetimes

| Certificate | Lifetime | Renewal |
| --- | --- | --- |
| CA | 10 years | Manual CA rotation (below). Plan it at least a year ahead. |
| Controller | 1 year, at most until CA expiry | `renew-server`, then restart the controller. |
| Device | 1 year, at most until CA expiry | Automatic in `run` once < 1/3 remains; `kinfold renew` once. |
| Standby (replication and server) | 1 year, at most until CA expiry | `replica-remove` and `replica-add` on the primary, then restart the standby with the new credential. |

`serve` logs a warning at startup, and then once a day while it runs, for
every certificate that is expired or expires within 30 days, including
registered standbys; a standby also warns about its own credential. Alert
on these messages: an expired controller certificate closes the relay and
with it every tunnel. Device renewals are logged on both sides
(`device certificate renewed`).

## Moving the controller to a new address

The controller host name is part of its certificate and of every device
credential. To move:

```sh
sudo systemctl stop kinfold-controller
sudo -u kinfold kinfold renew-server -data /var/lib/kinfold-controller/state -server vpn2.example.com:8443
sudo systemctl start kinfold-controller
```

Then set `"server": "vpn2.example.com:8443"` in every device credential and
restart its client. CA, device certificates and keys are unchanged. Devices
cannot connect between the controller restart and their credential update.

## Standby controller

Set up a standby with `replica-add` on the primary and `serve -standby` on
the standby host (see the README). Operational rules:

- Run administrative commands on the primary only; the standby overwrites
  its state with the primary's every two seconds.
- Monitor the standby's log for `replication from the primary failed` and
  its metric `kinfold_standby_last_replication_timestamp_seconds`. A standby
  that cannot replicate keeps serving its last state for `-standby-max-age`
  (default `1h`), then answers devices with "standby state is stale" until
  replication works again, closing the relay sessions it carried; a standby
  removed with `replica-remove` stops at once. It starts from its stored state only when the primary is
  unreachable and that state is younger than the maximum age. For a longer
  primary outage, promote the standby (below) instead of raising the limit.
- **Promotion** (primary lost): make sure the old primary cannot come back
  (power off, block its address), stop the standby (a running standby
  holds its data directory lock, so the command refuses to run) and run
  `kinfold replica-promote -data /var/lib/kinfold-controller/state -standby standby.json`
  on it. This sets the controller address in the state to the standby's own
  address, issues a server certificate for it and removes the standby's
  replica entry. Start it without `-standby`. Devices keep using it (it is
  already in their controller list); renewals and enrollment work again.
  Credentials of other standbys still name the old primary: remove and
  re-add them with `replica-remove` / `replica-add` on the new primary. When
  the old host returns, set it up as a new standby the same way. Starting a
  standby's state without promoting it makes it present the old primary's
  certificate, which devices reject.
- Never move the primary (`renew-server -server`) to an address held by a
  standby; the command refuses it.
- **Removing a standby**: `replica-remove -id standby` on the primary stops
  its replication; destroy its data directory and credential, they contain
  the CA key.
- Two controllers serving as primary at the same time give devices
  diverging configurations; devices accept whichever is newer, so changes
  can appear and disappear. Avoid it.

## CA rotation

There is no automated CA rotation in this version. Rotating the CA means
building a new network and moving devices over:

1. Initialise a new controller state with the same network settings on a
   new port or host: `kinfold init -data state-new -server vpn.example.com:9443`.
2. Recreate the rules (`allow`, `service-*`, `ipv6-*`) in the new state.
3. For each device: `keygen` on the device, `approve` against the new state,
   `export-ca`, `enroll` on the device into a new credential file, verifying
   fingerprints out of band as for a first enrollment.
4. Run the new controller next to the old one; switch each device's client
   to the new credential (one systemd instance per credential makes this a
   matter of starting a new instance and stopping the old one).
5. When all devices have moved, stop the old controller and destroy its
   state and backups securely.

Device IP addresses can stay the same as long as a device does not run both
clients at once.

## Clocks and signed configuration

Devices accept only configurations newer than the newest one they have
seen, and remember it across restarts in `<credential>.seen`. Within one
controller process issue times always increase, but if the controller host's
clock is set back by more than a few seconds between restarts (or the
controller moves to a host with a slower clock), devices reject its
configurations until the clock catches up and close their tunnels after 30
seconds. Fix the clock; if that is not possible, run `kinfold seen-reset
-credential <file>` on each device and restart the client. Device clocks may
be up to five minutes off without effect.

## Incident response

**Lost or stolen device**

1. `remove-peer -id <device>` — the relay rejects the device within about a
   second and closes its sessions.
2. If the device should return later, re-enroll it with a new key; its old
   key can never be approved again (key history).

**Device credential copied (device still in your hands)**

Remove and re-enroll as above. If the thief renewed the certificate first,
the legitimate device is already locked out (`not authorized` in its log),
which is a signal of theft.

**Controller host compromised**

Assume the CA key is known to the attacker. The attacker can admit devices
and impersonate any member. Treat the network as untrusted until a CA
rotation (above) on a clean host is complete; do not restore backups taken
after the suspected compromise.

**Controller unreachable**

With a standby controller, clients switch to it within one poll interval
(see "Standby controller"). Without one, clients keep their tunnel for 30
seconds, then close it and reconnect as soon as the controller answers.
During those 30 seconds, direct sessions keep carrying traffic, but relayed
traffic stops, because the relay is part of the controller.

## Relay bandwidth

By default a device may use as much relay bandwidth as the controller has.
`serve -relay-rate 2M` limits every device to 2 MB/s of relayed traffic it
sends, summed over all its sessions; `-relay-burst` sets the bucket size
(default one second at the rate, at least 16 KiB; it requires `-relay-rate`, and the rate must be 0 or at least one byte per second). The limit applies to
sessions bridged after the start and does not affect direct sessions. A
throttled device's TCP sessions slow down; nothing is dropped. Watch
`kinfold_relay_throttle_delay_milliseconds_total{peer}` to see which devices
hit the limit.

## Monitoring

### Metrics

Start the controller with `-metrics 127.0.0.1:9100` and clients with
`-metrics 127.0.0.1:9101` (loopback only). Useful series:

| Metric | Component | Meaning |
| --- | --- | --- |
| `kinfold_config_available` | controller | 0 while the state is invalid and the relay is closed. Alert on 0. |
| `kinfold_config_reloads_total{result}` | controller | `applied`, `unchanged`, `failed` reloads of `state.json`. |
| `kinfold_relay_endpoints`, `kinfold_relay_waiting` | controller | Current relay load. |
| `kinfold_relay_sessions_closed_total{reason}` | controller | `config_change`, `unavailable`, `superseded`, `stale` (standby). |
| `kinfold_relay_throttle_delay_milliseconds_total{peer}` | controller | Time relayed reads of a device were paused by `-relay-rate`. |
| `kinfold_relay_rejections_total{status}`, `kinfold_listener_rejected_total` | controller | Rejected requests and connections over per-source limits. |
| `kinfold_device_last_seen_timestamp_seconds{peer}` | controller | Last configuration fetch of each device from this controller (0: not since start). A device that is online fetches every 2 s; alert when it is older than a minute for devices that should be up. |
| `kinfold_device_relay_endpoints{peer}` | controller | Relay endpoints of each device, waiting or bridged. |
| `kinfold_renewals_total` | controller | Device certificates issued by online renewal. |
| `kinfold_standby_last_replication_timestamp_seconds` | standby | Last successful replication. Alert when older than a few minutes. |
| `kinfold_controller_reachable` | client | 0 while config fetches fail; the tunnel closes after 30 s. |
| `kinfold_peer_connected{peer}`, `kinfold_peer_bytes_total{peer,direction}` | client | Session state and traffic per peer. |
| `kinfold_packets_dropped_total{reason}` | client | `mtu`, `invalid_source`, `no_route_or_policy`, `queue_full`, `inbound_policy`. |
| `kinfold_certificate_expiry_timestamp_seconds` | client | Alert when less than 30 days remain and renewal does not happen. |

### Log messages

Useful log messages (`-log-format json` makes them machine-readable):

| Component | Message | Meaning |
| --- | --- | --- |
| controller | `controller configuration unavailable; relay closed` | State invalid or unreadable; all sessions closed until fixed. |
| controller | `certificate … expires on …` / `expired on …` | Renew before it lapses. |
| controller | `certificate renewal rejected` | A device asked for renewal with an invalid request. |
| standby | `standby stopped serving devices` | Replication failed for longer than `-standby-max-age`, or the primary removed the standby. |
| client | `controller unreachable beyond grace period; tunnel closed` | Control path down for > 30 s. |
| client | `certificate renewal failed; will retry` | Renewal will be retried every 10 minutes. |
| client | `peer connection failed; retrying` | A peer cannot be reached (offline, no path). Logged once per outage; the retries continue with backoff and appear at `-log-level debug`. |
| client | `peer disconnected` (repeated) | Path problems to that peer; sessions reconnect with backoff. |
