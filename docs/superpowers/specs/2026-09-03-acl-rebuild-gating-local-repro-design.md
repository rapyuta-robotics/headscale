# ACL rebuild gating + local end-to-end reproduction — design

Date: 2026-09-03. Branch: `perf/gate-updateaclrules` (off `rr-release-0.22.3` @ 96be963).

## Problem

io-prod headscale (image `perf-iter7`) pinned its 8-core limit on 2026-09-03.
30s CPU profile: 90% of samples in `UpdateACLRules`, called from
`handlePollCommon` on every MapRequest (`hscontrol/protocol_common_poll.go:46`),
99.8% of that in `generateFilterRules`. Per-call cost ~540 ms at the current
fleet (2593 ACL rules, ~800 live machines, 1236 in DB) × 11.8 ACL-triggering
polls/s ≈ 6.4 cores baseline. Any throttling slows map responses → clients
re-poll (full-update) → more rebuilds → pinned at the limit (feedback loop).
Endpoint-only updates never affect ACL output, so almost all of this work is
wasted.

## Goal

1. Reproduce the saturation locally, end to end, against a copy of the prod
   database with simulated tailscale clients speaking the real ts2021 protocol.
2. Fix it (Option B from the May analysis), prove the fix on the same harness.
3. Hand `perf-iter8` to QA for staging.

## Components

### 1. Prod DB snapshot → local PostgreSQL 15
- `pg_dump -Fc --exclude-table-data=policies` of `headscale` (policies holds
  ~97k historical versions, 5.8 GB); latest policy row copied separately and
  loaded so `policy.mode: database` behaves as in prod.
- Restored into `postgres:15-alpine` (prod is 15.18). Kept under
  `ignored/proddb/` (gitignored). Contains pre-auth keys and API-key hashes:
  never leaves this machine, never committed.
- Local-only tweak: none required; 1212/1236 machines have zero-time expiry.

### 2. Local headscale
- Fork binary built from this branch. Prod `config.yaml` with DB host/pass
  replaced, `server_url` → `http://127.0.0.1:8080`, TLS off, metrics on 9090.
- Run under `systemd-run --scope -p CPUQuota=800%` to mirror the k8s 8-core
  CFS limit so throttling and the re-poll loop reproduce.

### 3. Client fleet simulator `hack/loadgen/`
Go program, committed. One goroutine per simulated machine:
- Identity from the DB dump: `node_key` (public), `host_info` JSON, user.
  Machine key is random — headscale 0.22 looks machines up with
  `machine_key = ? OR node_key = ?`, so the node key alone suffices.
- Real protocol path: `GET /key` → Noise IK handshake via
  `tailscale.com/control/controlhttp` → h2c over the Noise conn →
  `POST /machine/map`.
- Per client: one `MapRequest{Stream:true}` held open (drained), plus periodic
  `MapRequest{Stream:false, OmitPeers:true, Endpoints:…}` endpoint updates.
  Fleet-wide endpoint-update rate is a flag (default 11.8/s). Optional
  reconnect-storm mode drops and re-opens the stream every N seconds.
- Live set: N most-recently-seen machines (default 800).

### 4. Measurement
`process_cpu_seconds_total` rate, 30s pprof, `UpdateACLRules` share and ms/call.
Repro proven at ≥6 cores demand, ~90% in `UpdateACLRules`, ~500 ms/call, and
pin-at-limit under storm mode. Fix proven when the same run stays ≤1.5 cores.

### 5. Fix (Option B)
- `handlePollCommon`: snapshot `machine.HostInfo.RequestTags` before
  overwriting `HostInfo`; call `UpdateACLRules` only when they differ.
  (1185/1236 prod machines advertise RequestTags, identical every poll.)
- Wire `UpdateACLRules` (ignoring `errEmptyPolicy`) into the invalidation
  points the per-poll call was masking: machine register (auth key, OIDC
  callback), delete, expire.
- Unit tests: tags change → rebuild; endpoint change → no rebuild;
  register/delete/expire → rebuild.

## Out of scope
Per-call cost of `generateFilterRules` itself; traefik STUN endpoint flapping
(input rate); `edge01` reconnect behaviour; the machine-key/node-key
impersonation weakness noted above (tracked separately).

## Results (2026-09-03)

Local harness: prod DB copy (1236 machines, 2603 users, policy v97144 with
2593 rules), headscale under `CPUQuota=800%`, 800 simulated clients.

| scenario | binary | cores (60 s) | CFS throttled | endpoint-update p50 / p99 | streams |
|---|---|---|---|---|---|
| steady, 11.8 endpoint-updates/s | v0.22.7-rr | 7.06 | 72% | 2.0 s / 5.0 s | 800 |
| steady, 11.8 endpoint-updates/s | fixed | 1.37 | 0% | 9 ms / 58 ms | 800 |
| storm, 6.4 endpoint/s + 6.7 reconnects/s | v0.22.7-rr | pinned (794% sampled) | 43% | 31 s / 39 s | ~213 (collapsing) |
| storm, 6.4 endpoint/s + 6.7 reconnects/s | fixed | 1.05 | 0% | 10 ms / 79 ms | 800 |

`UpdateACLRules` was 71–95% of CPU before and is absent from the profile
after. Packet filter served to nodes is identical (2593 rules, 1217 source
entries, same peers). hscontrol test failure set unchanged (8 pre-existing).
