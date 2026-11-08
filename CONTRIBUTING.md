# Contributing

Kinfold is developed in small, traceable steps. This file describes the
mechanics; the reasoning behind each rule is in `docs/DECISION-LOG.md`.

## Workflow

1. Every change starts with a GitHub issue (label it, assign the milestone).
2. Branch from `main`: `<issue-number>-<short-slug>`, e.g. `12-relay-supersede`.
3. Commit atomically: one logical change per commit, English, imperative
   subject line (≤ 72 chars), body explains *why*. Reference the issue
   (`Refs #12` or `Closes #12`) in the PR, not in every commit.
4. Before opening the PR: `gofmt -l .`, `go vet ./...`,
   `go test -race -count=1 ./...`. If the change touches the network path
   (`internal/agent`, `internal/relay`, the supervisor or the relay protocol),
   also run `sh scripts/integration-docker.sh` locally and note the result in
   the PR description.
5. Open a PR, wait for CI, merge with **rebase** (not squash), delete the
   branch.
6. Non-trivial decisions made along the way get an entry in
   `docs/DECISION-LOG.md` in the same PR.

No direct commits to `main`.

## License of contributions

Kinfold is licensed under the PolyForm Noncommercial License 1.0.0, and the
licensor also grants commercial licenses (see README.md, "License"). By
submitting a contribution you agree that it is licensed under the same
noncommercial license, and you grant the licensor a perpetual, worldwide,
royalty-free right to also license your contribution under other terms,
including commercial licenses. Only submit work that you have the right to
license this way.

## Rules

- Standard library only. No external Go modules (see D-007).
- Repository language is English, including CLI output and comments.
- Do not reference other VPN or overlay products by name.
- Fail closed: ambiguous or unverifiable state must deny, never allow.
- Every input from the network or from files has a size limit and a strict
  parser; keep that property when adding fields or endpoints.
- New JSON fields break older strict decoders. Document the upgrade order
  (controller and all clients together) in the README when adding one.
- When behaviour changes, update the README, the security model and the
  decision records in the same PR.

## Running the test suite

```sh
go test -race -count=1 ./...
go vet ./...
sh scripts/integration-docker.sh        # needs Docker, NET_ADMIN, /dev/net/tun
go test ./internal/agent -run '^$' -fuzz '^FuzzPacketAddresses$' -fuzztime 30s
```

See `CLAUDE.md` for the full list of fuzz targets.
