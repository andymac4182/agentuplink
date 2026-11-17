# Deployment readiness review and work list — 2026-11-17

Reviewed at `origin/main` `626ba936` (merge of #284, 2026-11-02). The goal reviewed
against: run the relay as a stateless web service, and install the client on a fleet
of Mac laptops.

Evidence labels: **code** = read in source, workflow or script at that commit;
**docs** = read in the repository's documents only; **gh** = GitHub query on
2026-11-17. Nothing in this review was run against a live deployment. Row ids such as
`M6-C82` refer to `docs/tasks.md`.

## Where the project stands

- `docs/production-readiness.md` says production readiness is not established; all
  eight of its completion criteria are unchecked (docs).
- Main has not moved since 2026-11-02. Every workflow on main is green at that commit
  (gh). About 147 of 655 task rows are not verified; 53 of them are in M6.
- The Fly cluster work that followed the merge sits on draft PRs #296 and #297
  (about 26.8k lines, CI red at the formatting step, never built locally according to
  its own description). Five older PRs (#175, #247, #249, #251, #253) conflict with
  main.
- The only thing deployed is one relay and one Redis on Fly. The three-relay profile
  has never been deployed (docs).
- The latest release is a pre-release with unsigned macOS archives (gh).

## The main finding: the relay is not a stateless web server

A relay holds long-lived mutually authenticated device sockets, the ordering state for
every stream, and the replay buffers. None of that is in Redis, by design
(`docs/cluster.md`). What can be made true is narrower: **any replica can be killed
and replaced, with no local disk, and devices reconnect within a stated time.** Main
does not meet that today, for the reasons in S1 to S6.

A decision is needed first (S0), because it changes half of the list below.

### S0. Decide the deployment shape

| Option | What it is | Cost |
|---|---|---|
| A. Fixed three-node set | Three named relays, each with a volume, plus the authority and Redis. This is what the cluster design supports. | Not stateless. Needs a platform with per-node volumes and private UDP (Fly, Kubernetes StatefulSet, ECS with EBS). No autoscaling. |
| B. One relay, hardened | What is live now, with restart recovery and a drain. | Every deploy and every crash is an outage of about 30 s per device. About 21 to 32 devices at the default listener cap. |
| C. Replaceable replicas | Remove the local files and the baked identity so a replica can start on an empty disk under a fresh identity. | Design work on the anti-rollback fence (S2) and the node inventory (S3). The result is still a fixed approved set, not an autoscaling group. |

Recommendation: B now for the first Mac users, A as the production target, and take
S2 from C so that A stops needing volumes. The work list assumes that order.

## Server work list

### Blockers for more than one replica

- **S1. Node identity is baked into the image.** `node_id`, `deployment_incarnation`
  and `redis_namespace` are in `deploy/fly/relay/relay.toml:26,36-37`, copied in at
  `deploy/fly/relay/Dockerfile:55` (code). The relay reads no environment variables
  (code). Without `[cluster]` a relay treats every device as local
  (`crates/tunnel-relay/src/http.rs:2767`), so a second replica cannot reach the
  first one's devices. *Work:* take node identity from the environment at start; add
  a cluster deploy profile.
- **S2. Each cluster relay needs a file that must never be lost.**
  `membership_version_state_path` and `recovery.fence_path` are anti-rollback fences.
  `serve` refuses to start if the first is missing
  (`crates/tunnel-relay/src/main.rs:1079-1089`); creating it is a separate
  `initialize` command (code). A replacement replica on an empty disk cannot start.
  *Work:* either accept per-node volumes (option A), or move the version floor to a
  fence held in Redis or by the authority. The second is a security design change and
  needs its own design note and review.
- **S3. Replicas are a signed static inventory.** The authority lists every node's id,
  peer endpoint, server name and key fingerprints
  (`crates/tunnel-authority/src/online_config.rs:141-159`), up to 32 nodes. Each relay
  needs its own peer certificate, checkpoint client certificate and signer trust.
  *Work:* per-node secret provisioning and an inventory revision procedure.
- **S4. The authority has no deployment.** It is a single stateful process with a
  durable local directory (`docs/authority.md`). Only `deploy/authority/Dockerfile`
  exists: no app config, volume, secrets or private listener wiring. Relays need it
  at every start, and membership records live 60 s. *Work:* authority app, volume,
  private mutual-TLS listener, Redis ACL user, and a runbook for its loss.
- **S5. A restarted cluster relay can fail to start.** Startup is one pass and exits
  if membership is not ready (`main.rs:1155-1165`). #296 and #297 add a planned-restart
  wait; they say crash-start waiting is still open. *Work:* land #296/#297 (rebase,
  fix formatting, run locally for the first time), then add crash-start waiting.
- **S6. Replicas need a private UDP mesh.** Relay-to-relay traffic is HTTP/3 over QUIC
  with no TCP fallback (`main.rs:1116-1118`, `docs/cluster.md`). This rules out Cloud
  Run and any HTTP-only platform. *Work:* encode per-node peer endpoints in the
  inventory; prove the mesh on the chosen platform.

### Required before production, in any shape

- **S7. Redis is a single point of failure.** One machine, one volume
  (`deploy/fly/redis/fly.toml`). No Sentinel or cluster client code exists. In cluster
  mode a Redis restart needs operator recovery under a new incarnation, which today
  means an image rebuild (S1). Open rows: `M6-C82` (single relay cannot resume
  unattended after a Redis restart), `M6-C125` (a 5 s Redis pause ends device
  sessions for 24 to 43 s). *Work:* decide between an accepted outage with a tested
  runbook and a fenced failover design; state the recovery time.
- **S8. A killed relay strands its devices for about 30 s.** Owner leases default to
  30 s; devices get `OWNER_BUSY` until expiry (`M6-C40`). In-flight operations end
  ambiguous. *Work:* decide `M6-C40`; publish the number as the service level.
- **S9. Shutdown has no lame-duck phase.** SIGTERM is handled and the drain is bounded
  at 10 s plus 5 s (code), but a single relay's `/readyz` never goes unready, and a
  cluster relay closes sessions the moment it does. *Work:* fail readiness, wait one
  load-balancer check interval, then drain. Related: `M6-06`, `M6-C157`.
- **S10. The load balancer must pass TCP through.** The relay terminates consumer TLS
  and device mutual TLS itself; there is no plaintext listener. An HTTP-terminating
  balancer cannot be used. Idle timeouts must allow long-lived WebSockets with 10 s
  pings and a 300 s rotation that briefly holds a third socket. Sticky routing is not
  needed in cluster mode (code). *Work:* write this down as the platform contract.
- **S11. Capacity.** The listener cap defaults to 64 connections and the Fly config
  does not raise it, so a relay serves about 21 to 32 devices (`M6-C198`). Fairness
  under flood is open (`M6-C126`, `M6-C183`, `M6-C192`). The 100-device, 24-hour soak
  is outstanding (`M6-03`). *Work:* raise and measure; run the soak.
- **S12. Configuration is a file read once.** Certificates and the token keys are read
  at startup; rotating them is a restart. The Fly config still has
  `oidc_issuer = "https://issuer.example.test/"` (`relay.toml:18`). Unknown config
  keys are refused, which makes rollback fragile. *Work:* real issuer, a certificate
  rotation procedure, and a rollback rule for config changes.
- **S13. Nothing watches it.** `/metrics` exists but is not enabled on Fly; there is
  no scraper, alert, retention or owner (`M6-C154`, `M8-C49`). *Work:* enable the
  listener privately, scrape, alert on readiness, lease failures, refusals and Redis.
- **S14. Deploys are manual.** CI builds images and runs a local proof; nothing
  deploys. First deploy is an ordered manual sequence. *Work:* a deploy workflow with
  the echo check and a recorded rollback image.
- **S15. Security rows that gate a real deployment.** `M6-C15` (owner credentials not
  rotated since the repository went public), `M5-C28` (CUA grant covers every
  operation; keep CUA off), `M4-53`/`M4-70`/`M6-C87` (authorization refresh and lapse),
  `M4-21` (advertised limits not enforced), `M3-42` (token audience).
- **S16. Licence and notice rows.** `M6-C241`, `M6-C253`, `M3-50` are blocked on owner
  decisions.

## Mac client work list

### Blockers

- **C1. The binaries are unsigned and not notarized.** There is no signing step in
  `.github/workflows/release.yml` or `scripts/` (code). The join guide tells users to
  strip the quarantine attribute (`docs/join-relay.md:98-105`). Gatekeeper will block
  a browser or MDM delivery, and macOS privacy permissions need a stable signing
  identity. There is no task row for this. *Work:* Developer ID certificate, hardened
  runtime signing on both macOS legs, notarization and stapling, and a Gatekeeper
  check in `scripts/verify_release_archive.py`.
- **C2. There is no installer.** The artifact is a tar archive per architecture. The
  launchd property list is an example that is not shipped and has never been loaded
  (`docs/operator.md:1510-1527`); it hard-codes `/usr/local`. No uninstall, no log
  rotation, no minimum macOS version. *Work:* a signed universal package that installs
  the client, a per-user launch agent, config under `~/Library/Application Support`,
  logs under `~/Library/Logs`, and an uninstaller. The Mac archive should not carry
  the relay and authority binaries (`scripts/package_release.py:16-28`). Add a CI job
  that loads the agent on a macOS runner.
- **C3. Enrollment is by hand.** The operator issues two UUIDs and a CA file; the user
  edits TOML, creates a key and request, sends it; the operator signs it with
  `openssl` and adds catalog records; the user imports the result
  (`docs/join-relay.md`, `docs/operator.md:373-375`). There is no `enroll` command
  (`crates/tunnel-client/src/main.rs:23-66`). *Work:* an enrollment token flow that
  fetches the trust root, ids and relay address, submits the request, and has the
  relay or authority record the credential.
- **C4. Certificates cannot be renewed.** The device half exists
  (`crates/tunnel-client/src/renewal.rs`); no shipped relay command can add a
  credential to an existing device (`M6-C56`, deferred). The operator guide says to
  re-enrol as a new device. **The dogfood credential expires on 2026-12-22.** A
  running client pins its credentials, so a renewed pair needs a restart. *Work:*
  close `M6-C56`, then automate renewal over the enrollment channel.

### Required before a fleet

- **C5. Private keys are files.** Mode 0600 in a 0700 directory
  (`crates/tunnel-client/src/credentials.rs:448,478`); no Keychain use. *Work:* decide
  between a Keychain-held key and a written acceptance of file keys.
- **C6. No proxy support, and the device port is 9443.** No CONNECT handling anywhere
  in client or transport (code). Corporate and captive networks will block it and the
  client will back off forever. *Work:* CONNECT proxy support, a 443 listener, and a
  diagnosis in `status`.
- **C7. No update path, and versions must match.** Upgrade is stop, replace, start;
  mixed versions are unsupported (`docs/operator.md:161`). Every relay deploy would
  force a fleet update. *Work:* a tested one-version-back compatibility promise, a
  version-skew diagnostic, and an update channel through the package.
- **C8. No managed configuration.** Relay address and ids live only in a per-device
  TOML file. *Work:* installer-written profile, or managed preferences.
- **C9. Laptop conditions are untested on macOS.** The logic for suspend, backoff and
  heartbeats exists (code). The rotation and reconnect gates run on Linux only; macOS
  CI runs unit tests and the first milestone's acceptance. Only one of four targets
  passes the maintainer gate (`M6-01`). *Work:* a macOS lane for those gates and a
  real-laptop soak: lid close, Wi-Fi change, VPN toggle, under launchd.
- **C10. launchd will restart a broken client forever.** A bad config or credential
  exits and is retried every 30 s into one unrotated log. *Work:* a "park on fatal
  error" mode and log rotation.
- **C11. One device identity per macOS user.** A second connection for the same device
  gets `OWNER_BUSY`. *Work:* document it and install per user, not as a system daemon.
- **C12. Filesystem export and macOS privacy prompts.** A launch agent exporting
  `~/Documents` or `~/Desktop` will hit permission prompts or denials; there is no
  guidance or preflight. Computer use is not in shipped builds and must stay off.
  *Work:* a permission preflight in `doctor`; an MDM privacy profile once signed.

### Smaller

- Stable (non pre-release) channel and a "latest" pointer.
- Homebrew tap for developer machines.
- `M6-C217`: a main release is owed for the Windows checksum fix.
- `docs/operator.md` contradicts itself on renewal (lines 157 and 404).

## Repository housekeeping that blocks the above

- **H1.** Rebase and land, or close, #296/#297. They carry the cluster deploy guide and
  rows `M6-C259` to `M6-C266`.
- **H2.** Close or rebase #175, #247, #249, #251, #253. #249 is probably superseded by
  the authority work in #284 (not diffed).
- **H3.** Five dependabot PRs have failing CI.
- **H4.** Stale documents: `docs/continuation-handoff.md` (last checkpoint
  2026-09-12), `docs/decisions.md` (says the repository is private),
  `docs/production-readiness.md` (says main is still `c749a784`),
  `deploy/fly/relay/fly.toml:19` (says the drain has no deadline).
- **H5.** Main has no branch protection.
- **H6.** Outstanding reruns: `M4-64`, `M4-42`, `M6-C127`/`C130`, `M7-C80` hosted,
  `M5-C21`.

## Suggested order

1. Decide S0. Rotate the owner credentials (`M6-C15`).
2. Client: C4 before 2026-12-22, then C1 and C2 together, then C3.
3. Server, single relay: S9, S12, S13, S14, S7 runbook, S11.
4. Land H1, then S1, S4, S5, S6 for the three-node set; design S2.
5. C6, C7, C9 before widening beyond the first laptops.

## Code-structure work done in this pass

Done on 2026-11-18 and merged with this document. Ledger rows: `M6-C270` to `M6-C279`
and `M6-C290` to `M6-C292` in [tasks.md](tasks.md).

### Locks

Every `Mutex` and `RwLock` in `crates/` is gone, in production code and in tests.
`vendor/` (third-party quinn and h3) is unchanged. `clippy.toml` now rejects the four
lock types, so CI fails if one comes back; the guard was checked by adding a lock and
watching clippy fail.

What replaced them, in order of preference:

1. Plain ownership: the state moved into the one task that uses it.
2. Atomics, for counters, flags and high-water marks that are independent.
3. `OnceLock` for set-once values.
4. An owning task with a bounded command queue and oneshot replies, for shared maps
   and multi-field state that must change together. This covers the relay peer pool,
   route cache, membership and rekey, peer readiness, admission registries, the
   catalog lane and binding, the authority engine, and the ACP, MCP and CUA registries
   and supervisors.
5. A single-writer `watch` for published snapshots.

One place needed more: the relay's payload-free diagnostics are recorded from
synchronous code on request paths, so they use a lock-free structure
(`crates/tunnel-relay/src/diagnostics_cells.rs`) with a fixed memory budget of about
30 MB worst case. Records past the budget are refused and counted. This is the most
intricate new code in the change and went through three review rounds.

### State machines

About 70 flag-and-Option combinations became one enum with one transition function
each, with tests for legal and refused transitions. The list is in `M6-C271`. No wire
format, status output or log name changed.

Left implicit on purpose (`M6-C290`): the protocol's top-level rotation phase,
sequence terminal pairs and owner-fence state; the relay's per-phase rotation runtime
and stream terminal; the client's rotation fences. Each needs its own reviewed change.

### What review found

Nine independent reviews (Opus, read-only) were run against the conversion. They
found one fail-open and several liveness regressions that the conversion itself
introduced; all were fixed before merge with regression tests (`M6-C273`). The
fail-open: the MCP HTTP backend could hand a client a session id before recording it,
so a revocation could miss it.

Reviews also confirmed defects that were already on main and are NOT fixed here
(`M6-C274` to `M6-C279`). The one that matters most for the Mac clients: if the client
loses its active socket in the middle of a rotation and recovers, leftover rotation
state is never cleared and the next scheduled rotation fails (`M6-C274`).

### Behaviour that changed

Thirteen differences were accepted and are listed in `M6-C272`. The ones an operator
could notice: requests on one peer connection are no longer serialised, so the
`sender_lock` fault stage is never reported; several catalog and relay calls became
async; a second re-binding scope that differs is now refused instead of silently
replacing the first.

### What was run, and what was not

Run locally on the merged tree, on macOS, against Redis 8.4:

- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`,
  and clippy for `tunnel-client --features cua,test-hooks` and
  `tunnel-acp-fixture --features interop`.
- `cargo test --workspace --locked` and the two feature-gated test sets.
- Harness gates: `verify`, `verify-m2`, `verify-m2-faults`, `verify-m2-default` (three
  real 300-second rotations), `verify-m7-cluster`, the M3 HTTP forward and MCP
  cloud-client gates, the M7 rotation, rotation-fault and recovery-attempt gates, and
  the M4 filesystem data-recovery gates. Results are in `M6-C270`.
- Site: docs build twice with no diff, release tests, and browser verification at four
  widths in light and dark.

Not run (`M6-C291`): the ignored process tests (28 relay, 4 authority, 51 catalog), the
fan-out, fragmentation and C11 window gates, the full 98-row M7 edge-case matrix, soak,
and anything on Fly. Nothing was deployed to Fly and no credential was touched.
