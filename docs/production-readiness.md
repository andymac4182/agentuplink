# Production deployment goal

Status: active; production readiness is not yet established.

Goal: make Agent Uplink deployable with a repeatable release, verified recovery,
and evidence for every production blocker. Requested by the owner on 2026-10-31.
Review baseline: `c749a78432c2d863572a601a7935abf73fa193a2`.

Reviewable changes are stacked draft pull requests, in dependency order:
[hardening #260](https://github.com/andymac4182/agentuplink/pull/260),
[offline authority #261](https://github.com/andymac4182/agentuplink/pull/261),
[authenticated authority transports #263](https://github.com/andymac4182/agentuplink/pull/263),
the [replacement-process canary #262](https://github.com/andymac4182/agentuplink/pull/262),
[trust-expiry classification #264](https://github.com/andymac4182/agentuplink/pull/264),
[credential replacement drill #265](https://github.com/andymac4182/agentuplink/pull/265),
[online authority #266](https://github.com/andymac4182/agentuplink/pull/266),
[actual CLI reconnect #267](https://github.com/andymac4182/agentuplink/pull/267),
and [stale authorization #268](https://github.com/andymac4182/agentuplink/pull/268),
followed by [clean-EOF expiry #269](https://github.com/andymac4182/agentuplink/pull/269),
[placeholder scan correction #270](https://github.com/andymac4182/agentuplink/pull/270)
and [Redis AOF headroom #271](https://github.com/andymac4182/agentuplink/pull/271),
then [container notices #272](https://github.com/andymac4182/agentuplink/pull/272)
and [integrated acceptance #273](https://github.com/andymac4182/agentuplink/pull/273),
then [filesystem confirmation #274](https://github.com/andymac4182/agentuplink/pull/274).

Integrated candidate `8c8c14fc9f6bb164daad224ad7300c04389a296f` now passes
complete local Rust checks (2,922 tests), all 90 frozen M1/M2/M7 stages, all
14 hosted CI jobs, packaging, and all five optimized release builds/native
archive verifiers. Hosted checkout `f2945e8196187bc7aec1d4415a58d3dde19b4e8b`
has the identical tree `d6969b5a8e13cf09ade1cf6b410848f7ced2851f`.
Fresh hosted full M4 includes all four installed frameworks across a real
300-second rotation. Four separate drills with unchanged original Linux
archive binaries pass: authority lifecycle, older-backup/operator recovery,
actual CLI reconnect and three synthetic CLI rotations. The current actual
authority image separately passes its lifecycle, notices and startup checks.
The [exact-candidate evidence](m6-final-candidate-2026-10-31.md) records hashes,
commands, timings, fixture boundaries and local/hosted distinctions.

Earlier full-M7, hosted, framework, recovery and disk-reserve failures remain
in the [acceptance history](production-acceptance-2026-10-31.md). The earlier
mixed-binary OG-02 result remains inconclusive. No unchanged retry or narrower
continuation converts those attempts to passes. C240's expected-green valid
queue-boundary tests now pass without a runtime change; its broader claim
remains open. C244 [real-endpoint fid confirmation](m6-fid-confirmation.md) now passes its
positive and meaningful premature-release controls at source8804, with restored
source passing again. The invalid first clunk control is retained and excluded.
These follow-up tests do not change the accepted8c runtime identity; their
integrated86fb workspace checks pass2,931tests. PR #274 at head
`107d94a2e331f850bcc70a2b9406bc79ccfa1cbf` has a successful full hosted M4
run, including C244, but its Ubuntu Rust job failed before the authority
permission-refusal test could begin: reopening state returned `authority state
is already open` (M6-C251). The hosted M7 job is still running at this review.
The [follow-up evidence](m6-final-candidate-2026-10-31.md#hosted-follow-up-at-107d94a2)
preserves the actual checkout and failed log. No overall CI pass is claimed.

Mastra depth enforcement (M4-75) now rejects descriptor-ceiling overrides and
incomplete default listings, preserving explicit bounded views. Its 610 offline
and 34 installed-peer checks pass; actual relay/device rotation integration
is pending. The separate M4-47 valid-state reproduction demonstrates that
ordinary in-credit DATA can exhaust the response budget and fence all 33
streams. That production correction and its complete acceptance remain open.

The universal MCP dependency policy still requires owner disposition of
MIT-0, PSF-2.0 and Windows bundled LGPL obligations; seeded checker tests are
not a live-policy pass. Actual target inventory, credential/PKI/OIDC setup,
off-host capacity and soak, monitoring/alerts and recovery ownership remain
unverified. The [separate default-UID mounted-secret/state proof](m6-authority-default-user-2026-10-31.md)
now passes with the actual image as UID 10002, retaining its first fixture
provisioning failure. It does not prove readiness or production provisioning.
The three-relay requirement
is unchanged. The C131 diagnostic feature remains outside this candidate;
its [causal evidence](m7-c131-diagnostic-evidence-2026-10-31.md) is separate.
No changes have been merged or deployed, and release publication/attestation
were skipped for the draft PR.

Existing task IDs in `tasks.md` retain their acceptance criteria. A historical
green gate is not evidence that the current release is production ready. The
three-relay requirement remains in scope; validating the shipped single-relay
Fly profile is an intermediate step. This document is a persistent work tracker,
not itself a background scheduler. A separately enabled hourly continuation
task, "Agent Uplink production readiness", resumes available work and checks
this goal. It must report unavailable execution access honestly and stop once
these completion criteria are evidenced; scheduling is not verification.

## Completion criteria

- [ ] A clean build and the required Rust, TypeScript, packaging and dependency
  checks pass at the candidate revision.
- [ ] The shipped deployment image starts from fresh configuration and
  enrollment; an authenticated consumer reaches a device over verified TLS.
- [ ] Tenant isolation, revocation, reconnect, scheduled rotation and bounded
  shutdown pass through the deployed topology.
- [ ] Backup restoration, simultaneous relay/Redis restart, credential rotation
  and rollback have tested operator procedures preserving revocations.
- [ ] Cluster authority, membership refresh, device liveness and key rotation
  have production implementations and regression evidence.
- [ ] Supported MCP, filesystem and ACP flows pass using real clients; CUA
  remains disabled until its operation-level authorization and VM gates pass.
- [ ] Capacity limits, monitoring, alerts, secret handling and incident ownership
  are configured for the actual target.
- [ ] A release artifact and deployment plan are ready for review; live
  deployment verification is recorded separately from local tests.

## Prioritized work

| Priority | Work | Evidence / existing tasks | Closure condition |
| --- | --- | --- | --- |
| Verified at 8c | Ship the cluster and recovery authority | M6-C22/C234; offline signer and authenticated transports verified. Online service, durable independent approvals/counters and mandatory-mTLS checkpoints pass native and actual-container three-relay lifecycle, lost-reply and real Redis-restart gates. Final 8c combined acceptance and original packaged operator recovery pass; actual deployment provisioning remains separate | Shipped services, packaged operator execution and three-relay startup, rotation and recovery procedures |
| P0 | Verify deployed credential replacement before expiry | M6-C56 remains owner-deferred for same-device renewal. M6-C233 locally verifies the approved new-device workaround, including migrated grants, revocation, restart and actual expiry | Execute the procedure against the real deployment inventory before expiry; deliver same-device renewal separately when taken up |
| P0 | Prove durable recovery | M6-C82; the single-relay continuity witness is process-local | Simultaneous restart recovers with an independent witness; rollback remains refused; restore drill completed |
| Verified at 8c | Vanished-device CLI recovery | M6-C68; remote owner release and fresh library reconnect pass complete cluster acceptance. M6-C229 quiet-session fix is verified. Actual CLI through the cut-client/held-relay proxy and all three negative controls pass; same PID regains readiness in 30.643 s after owner release at 30.021 s. Final 8c combined and original packaged CLI acceptance pass | Same CLI PID reaches a fresh ready session after remote owner cleanup within the stated bounds, with real echo and negative controls; full combined acceptance |
| P1 | Stabilize cluster membership and key changes | M7-C06/C80/C81/C83/C86/C131/C150; M8-C46/C47/C48/C61; M6-C232 passes prior combined acceptance. C235 identifies an additional clean-EOF path; C238 has deterministic regressions and a completed fixed20/20 versus control19/20 comparison; final 8c full local and hosted M7 pass | Repeatable re-sign, trust-expiry, rotation and restart acceptance; retain intermittent failures |
| P1 | Finish limits and real adapter acceptance | M4-21/47/68/70/72/73/74/75; M3-12/13/37/41/42/44 | Enforced advertised limits, long-lived streams and framework clients across peer hops/rotation/revocation |
| P1 | Resolve authority state test bootstrap lock collision | M6-C251; PR #274 Ubuntu Rust failure occurs before permission-refusal assertions | Causal regression, correction without weakened lock checks, required and hosted candidate checks |
| P1 | Establish load and recovery budgets | M6-03/C125/C126/C183/C192/C201/C239 | Off-host multi-tenant load and soak at declared capacity, explicit latency/error/recovery targets, Redis peak-memory/AOF rewrite evidence |
| P1 | Close release and operator verification gaps | M6-01/C217/C220/C241; M3-50 | Exact final-candidate checks, clean-machine archives and executed deployment guide |
| P1 | Configure operations | M6-C218; private metrics exist, privileged-change audit is deferred | Scraper, alerts, retention, certificate/JWKS rotation and incident/restore ownership verified |
| Restricted | CUA is not eligible for ordinary production enablement | M5-C28/C29 and remaining OS/backend gates | Per-operation caller grants, revocation, lease expiry and dedicated-VM acceptance |

## Verification ledger

- **Current integrated evidence:** [8c8c14fc final-candidate report](m6-final-candidate-2026-10-31.md)
  supersedes the pending-verification statements in the dated entries below.
  It supplies final local/hosted acceptance, exact original release archives,
  packaged operator drills and current actual-image lifecycle evidence.
  The following entries retain earlier attempts and scope; their failed
  results and unidentified historical causes have not been rewritten.

- Filesystem client deadline/fid work passes the official SHA-256-verified
  Node 24.21.0 check: 598 offline tests and 25 installed-framework tests, plus
  lint, type checking and build. The actual relay/device filesystem demo with
  frozen `20b92455` companions passes 22 host checks, live revocation in
  221 ms and complete namespace cleanup. A blocked JavaScript event loop can
  process a final acknowledged reply before its delayed expiry callback;
  this is documented completion ordering, not a hard wall-time guarantee.
  Later composite dispatch still refuses after the monotonic deadline.
- M6-C245's corrected exact stale-refresh assertion passes seven focused tests
  and one actual timing gate in 53.614 seconds. M6-C247 reproduces the original
  queue-margin assumption and replaces it with controlled timer barriers
  around real signing/fsync: all twenty authority tests and scoped strict
  Clippy pass, with unchanged production budgets. These local corrections
  still require combined and hosted acceptance.
- The exact historical guide-placeholder correction passes local controls and
  hosted dependency/license/secret jobs 124447394040 and 124447619897. M3-50 is
  a separate unresolved policy gap: its universal MCP test lock inspection
  finds MIT-0, PSF-2.0 and a Windows wheel with bundled LGPL obligations outside
  the current policy. [The prepared gate](mcp-test-dependency-gate.md) keeps all
  platforms and has no active exceptions. The owner's platform/license
  disposition remains pending; seeded checker tests are not a live-policy pass.
- Current combined runtime `20b92455`: fmt and strict workspace/all-target
  Clippy pass; locked workspace tests pass with 2,889 passed, zero failed and
  107 ignored across 174 suite results. M1 passes in 80.63 seconds, accelerated
  M2 with faults in 32.27 seconds, and three actual 300-second rotations in
  912.67 seconds with 18,987 records and zero replayed records. Full M7 fails
  after 1,273.73 seconds at EC-055's authorization cause assertion. Earlier
  gates in that run pass, including actual CLI reconnect (same PID ready in
  30.415 seconds) and clean-EOF trust expiry (10.059 seconds). Hosted runtime
  CI also fails that timing assertion, plus an authority serializer test;
  earlier authority CI fails GOAWAY cleanup within OG-02. These are retained
  blockers, not waived flakes. Detailed evidence and limits are in the
  [current report](production-acceptance-2026-10-31.md).
- Accepted runtime candidate `89552a1f` includes hardening, offline authority,
  authenticated transports, replacement canary and M6-C232. Later `fd03cdee`
  changes only verification documents. This is the pre-online-service stack.
  Rust 1.95.0 formatting, strict workspace/all-target Clippy and locked workspace
  tests pass: 2,848 passed, zero failed, 102 ignored, across 173 suite results.
  Separate required-mTLS HTTPS tests (3), authority CLI tests (10), actual
  CLI-to-Redis recovery (1), publisher Redis TLS/ACL (1), and replacement-process
  SPKI/canary (1, 24.35 seconds) pass. Complete local M1 passed in 22.19 seconds,
  accelerated M2 plus faults in 32.68 seconds, and the entire M7 script in
  1,784.40 seconds, including expiry, forwarded liveness, replacement, all fault
  gates, C11 and OG02. Binaries/logs were preserved with SHA-256 hashes before
  cache reuse. New service/barrier changes need their own combined acceptance.
  The environment has a non-reaping PID 1, so process tests run under a child
  subreaper; assertions are unchanged. Ignored real-Redis gates run separately.
- Full local M7 at `89acdcad` failed existing M7-C131: the expired target was
  removed and the owner event said PeerMembershipExpired, but ingress recorded
  `(IngressReceive, Closed)` instead of TrustExpired. A separate continuation
  passed every remaining gate, including OG02's ten correlation rows. That is
  not a full M7 pass. M6-C232 fixes a separately reproduced classification
  defect; the earlier failure cannot be attributed to it without a correlated
  event timeline. The predeclared, interleaved comparison completed all forty
  runs: fixed 20/20; unchanged control 18/20, with the same Closed-at-ingress
  failure in pairs 2 and 17. No run was retried or discarded. The immutable
  hashes, all outcomes and limitations are recorded in the
  [comparison report](m7-c131-expiry-comparison-2026-10-31.md).
  The subsequent complete M7 run passed; its expiry gate took 10,016 ms.
  The later M6-C235 capture establishes one exact failure: clean EOF arrived
  after ingress admission expiry but before its expiry reason was latched.
  Its separate instrumented comparison was control 19/20 and fixed 20/20,
  with 37 complete analyses and three inconclusive intervals. This explains
  that observed EOF ordering, not all historical failures or C232 efficacy.
  M6-C238 changes only clean-EOF classification after decoder validation,
  preserving actual earlier non-expiry reasons and malformed-record errors.
  Its own unchanged, uninstrumented 20-pair comparison is now complete:
  fixed20/20, control19/20, with the sole failing control preserving the exact
  ingress Closed/owner membership-expiry mismatch. All forty outcomes, unique
  namespaces and final source/tool/binary hashes are retained in the
  [C238 comparison report](m6-c238-clean-eof-comparison-2026-10-31.md).
  There were no retries or timeouts. Final combined acceptance remains required.
- Hosted CI at `89acdcad` passed every job, including M7:
  [41156405921](https://github.com/andymac4182/agentuplink/actions/runs/41156405921).
  Offline-authority candidate `8997e7f6` also passed every job:
  [41156556356](https://github.com/andymac4182/agentuplink/actions/runs/41156556356).
  Both built and verified all five release platforms; draft publication and
  provenance attestation were skipped. Hosted success does not erase local
  intermittent failure. Latest combined hosted checks remain required.
- Authority transports at `6a304214` and replacement canary at `ba120f71` also
  passed every hosted CI job, including full M7, in runs
  [41158151084](https://github.com/andymac4182/agentuplink/actions/runs/41158151084)
  and [41158468116](https://github.com/andymac4182/agentuplink/actions/runs/41158468116).
  Their five-platform optimized build/archive matrices passed in release runs
  41158151070 and 41158467654; draft attestation/publication were skipped.
- The actual optimized Linux CI archive from offline-authority release
  [41156556410](https://github.com/andymac4182/agentuplink/actions/runs/41156556410)
  passed all seven archive checks and planted negative controls. Its documented
  flat-archive operator path passed 65 commands, 78 output assertions and 14
  shape checks without Cargo available. Eleven documented Redis commands then
  passed with real TLS echo, unauthorized-user refusal, unprovisioned-start
  refusal and orderly shutdown. Recovery/rebind operations requiring an
  independently approved restart were not executed in that session. These are
  CI-archive checks, not a maintainer provenance-bundle or live-Fly proof.
- M7-C06 was reopened after full-history inspection found the claimed
  replacement-process application canary had never been committed. PR #262
  now proves a fresh device's different relay boot/session and higher owner
  epoch, exact public canary through a peer, stable owner/generation and clean
  stop. Two isolated whole-fixture runs and four intentional negative controls
  validate the new checks; the combined candidate passes once. Complete local
  M7 at `89552a1f` and hosted M7 at `ba120f71` subsequently passed, completing
  the corrected C06 scope.
- M1 real-socket acceptance and M2 accelerated rotation/fault gates passed.
  Three actual 300-second rotations passed with 18,913 records; hosted runs at
  `89acdcad` and `8997e7f6` subsequently passed M2. Earlier configured fixture
  failures caused by inherited error-only RUST_LOG are fixed (M6-C230); SPKI,
  bootstrap and M8 rekey now pass under an explicitly error-only parent.
- The actual Fly Dockerfiles built, and the candidate image/client passed
  `deploy/fly/local-proof.sh`, nonce `m6c60-proof-20261031T010953Z-132985`:
  verified TLS, enrollment, echo, all seven catalog commands, revocation,
  bounded shutdown, relay restart, Redis-down refusal, AOF recovery with real
  device traffic within 60 seconds and fresh relay startup. Serving containers
  were capped at 256 MiB. That earlier proof tested the 160 MiB/noeviction dataset bound, not rewrite
  headroom. A subsequent M6-C239 test reproduced an OOM kill at the shipped
  256 MiB VM limit during AOF rewrite and existing-key churn: Redis exited 137
  after 4,512 acknowledged overwrites. The predeclared 96 MiB comparison
  completed the same rewrite overlap, 45,344 writes and intact canary with
  zero OOM kills and no swap. A lower-limit profile and reproducible image
  gate are in progress. This bounded workload is not a capacity guarantee;
  off-host soak, cache pressure and AOF disk budgeting remain required.
- Node 24 checks passed: 573 core tests, 25 real-framework peer tests, lint,
  typecheck, build and distribution lint. MCP SDK direct-loopback interoperability
  passed 12 cases; full relay conformance passed all 76 SDK cases. External
  conformance passed 30/31, retaining accepted M3-49 for authenticated non-browser
  DNS-rebinding behavior; Origin refusal passes. Packaging tests and the command
  inventory pass. Final-source and supported-platform acceptance still apply.
- Fresh RustSec checks pass after rustls/webpki/Tokio/root updates and the JWT
  AWS-LC backend change, preserving RS256/EdDSA policy. No advisory exception was
  added; existing test-only RSA and unmaintained PEM-parser exceptions remain.
  Python test dependencies audit clean after OpenTelemetry API 1.45.1; Python
  3.10 conformance passes with its exception-group backport. Both npm trees
  audit clean. Mastra 1.65 behavior is retained with a scoped MCP-server 2.3.0
  override, verified by real SDK positive/negative controls; downstream apps
  need that root override. These branch results do not close default-branch
  dependency alerts.

## Implemented slices and remaining integration

- M6-C68/C229: ingress WebSocket heartbeat plus absolute inbound timeout, and
  compatible owner protocol heartbeat. Real three-relay proof stays healthy
  for 70 quiet seconds, releases a blackholed device's owner within 30.05 seconds
  and restores fresh same-device echo within 30.15 seconds. Removing the owner
  fix closes the healthy session at 59.99 seconds; removing the ingress timeout
  leaves OWNER_BUSY beyond 35 seconds. The registered M7 gate passes locally
  and hosted. The subsequent actual-CLI gate proves same-process automatic
  retry and exact public canaries; all three controls fail as intended.
  Restored CLI/raw gates pass 2/2 in 205.76 s, and barrier/H3 cleanup
  regressions pass. The registered new gate awaits combined M7 acceptance.
- M6-C22: offline authority key generation and self-verified recovery approval
  signing, protected owner-only files and Unix server-archive integration.
  Actual Redis recovery preserves revoked grants/credentials and rejects stale
  digest, run, nonce and replay. It does not publish membership or checkpoints.
- M6-C231: strict paired checkpoint client identity without anonymous fallback,
  and explicit publisher Redis TLS. Real mTLS/ACL tests cover correct identity,
  wrong trust/name/credentials, denied authorization and unrelated writes.
- M6-C233: the complete new-device workaround passes locally through shipped
  commands. Two users retain their grant operations/expiry; old revocation is
  observed before actual certificate expiry, replacement epochs increase across
  client/relay restarts, and exact canaries still pass beyond the old expiry.
  Full provisioning acceptance passes 8 catalog, 3 Redis-stage and 9 process
  gates. Four intentional controls fail correctly. Full workspace tests pass
  2,848/0 failed/103 ignored with strict Clippy. This is single-relay local
  evidence; M6-C56 remains deferred for same-device renewal.
- M6-C234: the online service has independent durable approvals and separate
  membership/checkpoint counters, exclusive writer locking, required client
  identity/pins, and fixed confirmed expiry during refresh failures. Initial
  actual-service acceptance passed in 115.80 seconds, including exact traffic
  through a non-owner relay, two refreshes and authority restart without
  replacing the device session. Independent review then reproduced a publisher
  queue-starvation schedule; the bounded queue fix passes its regression while
  retaining the I/O watchdog. Actual owned-daemon lost-reply/restart paths pass in 67.14 s. Native
  three-relay lifecycle passes in 119.01 s and the actual Docker authority
  passes the same unchanged lifecycle in 127.44 s: two confirmed refreshes,
  restart, persisted checkpoint/all-node floors, exact non-owner canaries and
  unchanged device session/socket. Authority outage becomes unavailable at
  the original expiry (53.052 s in the container run). The image default
  UID 10002 and missing-config refusal pass separately; the lifecycle uses
  non-root fixture UID 1000 to read its owner-only synthetic files. These are
  local fixtures, not live deployment. Full Rust at `cd509527` passes
  2,868 tests, zero failed, 106 ignored, plus strict Clippy. Build-layer disk
  exhaustion was corrected with a read-only source bind; the runtime image
  is unchanged. Combined newer-runtime acceptance remains owed. Never restore older authority
  volume state: whole-volume rollback cannot be detected from that same volume.
  M6-C236 records the retained directory's 32 historical node-ID slots.
- M6-C232: reconciliation preserves TrustExpired when the admitted stream's
  existing deadline has already passed. Two regressions fail without the fix;
  pre-expiry revocation retains its original reason. Admission lifetime, retry
  permissions, EOF handling and acceptance predicates are unchanged. M7-C131
  remains open.
- M6-C222/C223/C224/C225: bounded Redis memory without eviction, restoration
  requiring reconciliation of later revocations, CI dependency/TypeScript/Fly
  gates, and compatible dependency updates with interoperability evidence.

## Deployment-specific work still required

The checked-in Fly configuration is one relay and one Redis in one region,
with immediate replacement and no automatic failover. It cannot provide
uninterrupted upgrades or high availability. Do not scale it to two relays
without cluster configuration and the external authority.

The configuration still contains an example OIDC issuer. Actual Fly identity,
deployed image, JWKS, TLS certificates, catalog provisioning, backups and
monitoring are unverified. Repository notes are historical evidence. JWKS load
at relay startup; coordinate overlapping IdP keys and restarts. Monitor and
exercise consumer, device and Redis certificate rotation before expiry.

Establish scraper/alerts/retention and incident ownership. Monitor readiness,
reconnects, owner/authority failures, admission refusals, clock offset, queue
pressure, memory, AOF disk headroom and certificate expiry. Record acceptable
outage, data-loss and recovery budgets; single-primary Redis has no supported
automatic promotion. The 100-device/24-hour off-host soak and per-user fairness
proof remain outstanding.

Credential-rotation attestations M6-C15 remain open. This review did not prove
credentials outside the repository were exposed; reconcile the inventory with
provider evidence. A clean source pattern scan does not attest deployed secrets.
OS signing/notarization is separate from release provenance. The TypeScript
package is private and exports source; settle its supported distribution method
before offering an npm-installed SDK. CUA remains disabled pending grants,
lease cleanup and dedicated-guest acceptance.

## Next action

Run complete Rust, M1, both M2 plans and M7 on the combined runtime candidate,
then the predeclared clean-EOF-only 20-pair comparison. Complete the Redis
rewrite profile/image proof, test-dependency license/advisory gate and container
notices without silently widening license policy. Execute packaged three-relay
recovery and rotation procedures, then establish actual hosting identity,
certificates, monitoring, capacity and operational ownership. Keep this goal
active while any completion criterion or deployment input remains unresolved.
