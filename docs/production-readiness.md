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
then [filesystem confirmation #274](https://github.com/andymac4182/agentuplink/pull/274)
and [Mastra depth / authority lock #275](https://github.com/andymac4182/agentuplink/pull/275),
then [terminal retirement observer #276](https://github.com/andymac4182/agentuplink/pull/276)
and [client matcher correction #277](https://github.com/andymac4182/agentuplink/pull/277).

The next C240 implementation is locally verified at
`bf21e353ede811088cf31b64f8b9076d28378f11` (tree
`2b3aa8f155d65c4ac07b327e835fbf440216de78`): all six new real actor-loop tests
and four existing handler controls pass on the first compiled run,10/0/0 in
2.78s. A separate full workspace format check passes. The first overall
attempt remains **failed before Clippy** because tmp capacity was138,395,648B
below its required startup reserve; no lint process or automatic retry ran.
[Exact actor evidence and retained failure](m6-c240-queue-boundary.md#first-real-actor-loop-run-and-retained-validation-failure)
keep public C240 scope B and full candidate validation open. A new stacked
draft will carry this tested implementation plus documentation; the prior
hosted and image results below retain their exact original identities.

Latest fully successful hosted baseline [#277](https://github.com/andymac4182/agentuplink/pull/277)
head `bd93cfbd828a2d23415e5e406120f9a70e9e92c0` and actual runner checkout
`3615d7a2ff4ffb5837a8e0f894f353ea68115ac4` share tree
`00fcf8d247642d9ace69b6223c7500858385e6d3`.
[CI run 41202356267, attempt 1](https://github.com/andymac4182/agentuplink/actions/runs/41202356267)
completed successfully at 2026-10-31T23:22:58+10:00: all 14 jobs pass, including
all Rust platforms, TypeScript 610 offline / 40 installed peers, actual consuming-root
resolver controls and audit 0, full M4 and full M7. M7 retains 10 complete OG-02 rows
and zero incomplete rows. The hosted framework gate preserves the 300-second
schedule, 8 completed exchanges / 20,480 bytes, 1546 ms resumption, 465 ms revocation,
zero replay/recovery/forced retirement and joined cleanup. Packaging passes;
no new optimized-release workflow or live deployment is claimed.

C252's scoped just-bash/minimatch correction is verified within its declared
advisory and compatibility scope. The separate local clean `95eb2d83` actual framework
gate passed 309.108 s, alongside pinned Node checks, matcher negatives, resolver
controls and a fresh zero-finding audit. [Exact local input binding and proof](m6-client-followup-2026-10-31.md#c252-actual-framework-integration)
distinguishes the older frozen Rust driver from the actual new TypeScript graph.
The distinct [C253 client license coverage gap](m6-client-license-coverage-2026-10-31.md)
remains blocked on owner policy and artifact-aware enforcement; neither advisory
checks nor successful CI grant a license exception. New dependency evidence
remains separate from older frozen trees and optimized archives.

The previous PR #276 (`2f3686b7` / `2f30edff`) candidate shares tree `736c7bbc`; its full M4 and Rust
platform results established C244's narrow confirmation scope. Its earlier
13-pass/M7-pending observation remains in the dated evidence report. The current
PR #277 pass adds the corrected dependency graph's own hosted evidence; it does
not rewrite any earlier failed run or close broader M4-21.

Actual authority image
`sha256:52606609ffc52ed3206fd7dbe26b34fdf8d213368983a556beff338ff480f956`
built from clean `2f3686b7` in the second guarded attempt. The optimized build and
212-package / 389-file notice staging pass. A conservative 713-tracked-input
comparison confirms the authority Docker build inputs match `bd93cfbd`, while the
whole trees differ; no rebuild at `bd93cfbd` or byte-reproducibility claim follows.
The first build attempt remains failed before build launch because Buildx did
not support its inspection flag. The reviewed correction validates the actual
plugin and exact BuildKit cache records while keeping pinned FROM digests and
all resource guards.

The current image now passes its separate lifecycle and mounted default-UID
proofs. Lifecycle attempt 3 runs the selected decc native test in 130.74 s
(command 130.794 s; total controller 140.000 s), with the original5909 relay's
explicitly unchanged runtime/build closure. Four inspection and ten runtime
containers are absent, all 53 owned process groups are gone, and 51 protected
inputs are unchanged. Extracted authority bytes and the 212-package / 389-file
normal/build Cargo notice manifest are verified; OS package coverage is separate.
The lifecycle fixture uses UID1000, while startup UID/help/missing-config checks
and the following independent proof exercise the image's default user.

The first mounted default-UID attempt passes in 42.200 s at UID10002/GID999
without --user, with no network, read-only root/secrets and writable whole state
directory. It verifies exact initialization, revision1→2, changed state inode,
stable lock, temporary collision preservation, seven exact refusals and clean
stop/reopen. All 15 containers and 218 owned groups are absent; 56 protected
inputs are unchanged and synthetic material is removed. This default-UID proof
expects pending/publication-unavailable startup; it does not establish successful
publication, recovery, target deployment or crash/fsync durability.

Both earlier lifecycle attempts remain **failed**: malformed inspection JSON
before creation, then an absent optional HostConfig.Init projection that also
blocked automatic cleanup of one stopped inspection container. Separate cleanup
receipt31550cf3 succeeds without relabelling either failed attempt. The reviewed
v4 correction passed 135 pure controls and used the measured197787648B first-
container allocation to set2271084544B startup headroom with unchanged active
bounds. Older8c image and5909 archive successes retain their original scope.
C251's proven descriptor-lifetime correction and current checks are verified;
its exact historical PR274 failure remains unattributed, so that full diagnosis
row stays open.

Previous hosted candidate [#275](https://github.com/andymac4182/agentuplink/pull/275)
head `b13f43cd38c356863dfdd9a99a4573c191d58965` and actual checkout
`5909dc38ec843275e81dd2c73116b91ded575934` share tree
`2bf1832d3554b1c9aba2f9478d2f980fc10b2ed8`. CI is **failed**:13 jobs pass,
including all three Rust platforms and complete M7; M4 passes its actual
300-second framework gate, then fails the C244 grouped terminal witness.
The failed scalar was not retained and is not retrospectively attributed.
[Current follow-up evidence](m6-production-followup-2026-10-31.md) records
exact runs, logs, artifacts and the subsequent fixture correction.

All five release builds/native archive verifiers pass. All original uploaded
ZIPs were downloaded and independently verified. The new original Linux
archive authority/relay pass local lifecycle120.539s and older-backup recovery
117.204s, with all C243 witnesses and joined cleanup. These use the native880
test driver with1082 identical non-document inputs; they do not execute the
packaged device CLI or establish current actual-image/default-user operation.

Locally tested `88083555ffec868012938e0d253e9090177deec2` still supplies the
required2,932-test Rust result and native authority lifecycle/fault/recovery
proofs. The [C251 report](m6-c251-authority-lock-2026-10-31.md#integrated-checks-at-88083555)
retains failed artifact selection, separate selection recovery, first disk-guard
setup failure and successful recovery-only run. PR275 now passes Ubuntu's
original permission test and all21 authority tests; the historical PR274
failure's exact cause remains unattributed. M4-75 closes only its Mastra
traversal-depth/framework scope. Current PR #277 CI and C252 integration now pass as recorded above. Current image proofs now pass at their declared scopes. Exact historical C251
attribution, M4-47 and C253 license policy/enforcement remain explicit follow-up
work.

Earlier integrated candidate `8c8c14fc9f6bb164daad224ad7300c04389a296f` passes
complete local Rust checks (2,922 tests), all 90 frozen M1/M2/M7 stages, all
14 hosted CI jobs, packaging, and all five optimized release builds/native
archive verifiers. Hosted checkout `f2945e8196187bc7aec1d4415a58d3dde19b4e8b`
has the identical tree `d6969b5a8e13cf09ade1cf6b410848f7ced2851f`.
Fresh hosted full M4 includes all four installed frameworks across a real
300-second rotation. Four separate drills with unchanged original Linux
archive binaries pass: authority lifecycle, older-backup/operator recovery,
actual CLI reconnect and three synthetic CLI rotations. The actual authority
image built from 8c separately passes its lifecycle, notices and startup checks.
The [exact-candidate evidence](m6-final-candidate-2026-10-31.md) records hashes,
commands, timings, fixture boundaries and local/hosted distinctions.

Earlier full-M7, hosted, framework, recovery and disk-reserve failures remain
in the [acceptance history](production-acceptance-2026-10-31.md). The earlier
mixed-binary OG-02 result remains inconclusive. No unchanged retry or narrower
continuation converts those attempts to passes. C240's expected-green valid
queue-boundary tests now pass without a runtime change; its broader claim
remains open. The new C240 actor-loop draft is source-only;
no actor-level test pass or public-close acceptance is claimed. C244 [real-endpoint fid confirmation](m6-fid-confirmation.md) now passes its
positive and meaningful premature-release controls at source8804, with restored
source passing again. The invalid first clunk control is retained and excluded.
These follow-up tests do not change the accepted8c runtime identity; their
integrated86fb workspace checks pass2,931tests. PR #274 at head
`107d94a2e331f850bcc70a2b9406bc79ccfa1cbf` has a successful full hosted M4
run, including C244, but its Ubuntu Rust job failed before the authority
permission-refusal test could begin: reopening state returned `authority state
is already open` (M6-C251). The hosted M7 job has now passed, including all ten
OG-02 correlation rows; the final CI result is failure with thirteen successful
jobs and that one failed Ubuntu job.
The [follow-up evidence](m6-final-candidate-2026-10-31.md#hosted-follow-up-at-107d94a2)
preserves the actual checkout and failed log. A separately reproduced duplicate-
descriptor lock-lifetime defect now has an independently reviewed correction
and 21 passing authority tests; [C251 evidence](m6-c251-authority-lock-2026-10-31.md)
keeps historical causation unproven. Integrated required checks and affected
native lifecycle/fault/recovery now pass at880. That earlier statement left new-candidate hosted checks, optimized artifacts
and image verification pending. The current PR277 hosted pass and separate
2f image build/lifecycle/default-UID proofs above update only their named scopes;
no deployment or historical-causation claim follows.

Mastra depth enforcement (M4-75) now rejects descriptor-ceiling overrides and
incomplete default listings, preserving explicit bounded views. Its 610 offline
and 34 installed-peer checks pass. Separate actual relay/device integration
passes the unchanged 300-second framework rotation gate in311.020s, with
zero replay, live revocation and joined cleanup; [exact evidence](m4-mastra-depth-2026-10-31.md)
retains the prelaunch diagnostic failure. PR275 and PR276 hosted framework checks also pass for their respective dependency graphs. The separate M4-47 valid-state reproduction demonstrates that
ordinary in-credit DATA can exhaust the response budget and fence all 33
streams. That production correction and its complete acceptance remain open.

The universal MCP dependency policy still requires owner disposition of
MIT-0, PSF-2.0 and Windows bundled LGPL obligations; seeded checker tests are
not a live-policy pass. Actual target inventory, credential/PKI/OIDC setup,
off-host capacity and soak, monitoring/alerts and recovery ownership remain
unverified. The earlier [default-UID mounted-secret/state proof](m6-authority-default-user-2026-10-31.md)
passed with the actual 8c image as UID 10002, retaining its first fixture
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
| P1 | Finish limits and real adapter acceptance | M4-21/47/68/70/72/73/74; M4-75 is verified at its narrow depth/integration scope; M3-12/13/37/41/42/44 | Enforced advertised limits, long-lived streams and framework clients across peer hops/rotation/revocation |
| P1 | Resolve authority state test bootstrap lock collision | M6-C251; duplicated-descriptor regression/correction, required/native/original-packaged/hosted checks and current image lifecycle/default-UID proofs pass. Exact PR274 cause remains unattributed; both failed lifecycle controllers stay retained | Preserve the proven mechanism and current verification; establish the exact historical diagnosis before closing the full row |
| Verified at declared scope | Correct current dependency advisory | M6-C252; scoped 11.0.1 correction passes local 610/40, matcher/resolver controls, audit 0 and actual 309.108 s framework gate. PR #277 same-tree `bd93cfbd` / `3615d7a2` passes all 14 CI jobs including affected TypeScript/full M4 and full M7; completed 2026-10-31T23:22:58+10:00. C253 license policy remains separate and open | Compatible graph correction, fresh audit, real framework checks and explicit consumer override contract; no broader license or production approval |
| P1 | Define and enforce client dependency license coverage | M6-C253; separate client graph is outside Cargo/MCP gates; existing BlueOak/LGPL declarations plus one new BlueOak dependency remain unapproved | Owner-reviewed client policy, artifact-aware alias-capable gate, unchanged universal scope and complete graph result |
| P1 | Establish load and recovery budgets | M6-03/C125/C126/C183/C192/C201/C239 | Off-host multi-tenant load and soak at declared capacity, explicit latency/error/recovery targets, Redis peak-memory/AOF rewrite evidence |
| P1 | Close release and operator verification gaps | M6-01/C217/C220/C241; M3-50 | Exact final-candidate checks, clean-machine archives and executed deployment guide |
| P1 | Configure operations | M6-C218; private metrics exist, privileged-change audit is deferred | Scraper, alerts, retention, certificate/JWKS rotation and incident/restore ownership verified |
| Restricted | CUA is not eligible for ordinary production enablement | M5-C28/C29 and remaining OS/backend gates | Per-operation caller grants, revocation, lease expiry and dedicated-VM acceptance |

## Verification ledger

- **Current PR #277 candidate:** run 41202356267 attempt 1 passes all 14 jobs at `bd93cfbd` / same-tree `3615d7a2`, including full M7 with 10 complete OG-02 rows. C252 closes at its declared advisory/compatibility scope; local, hosted, image-build and live deployment remain separate evidence.

- **Current authority image:** actual2f image52606609 has713tracked build inputs matchingbd93 and now passes lifecycle130.74s plus separate mounted default-UID42.200s proof. Exact image/binary/notice identities and owned cleanup are retained; both earlier failed controllers remain failed. The default-UID network-none proof does not claim publication, recovery or crash durability.

- **New C244 local correction:** clean `decc5b58` passes its controlled negative, eleven fixed controls, required Rust checks (2938/0/108/174), and one actual gate13.0765s. The real run observes handler completion before stream/replay retirement and then reaches the unchanged terminal assertions. PR276 full M4 and all Rust platforms now pass, closing the declared C244 scope; [local evidence](m6-production-followup-2026-10-31.md#verified-observer-correction-at-decc5b58) and [hosted evidence](m6-client-followup-2026-10-31.md) preserve their separate identities.

- **Prior PR275 follow-up:** [exact evidence](m6-production-followup-2026-10-31.md) records the failed13-pass/1-fail CI, successful five-platform original archives, and new Linux packaged lifecycle/recovery. Older complete acceptance below remains bound to8c.

- **Prior complete acceptance baseline:** [8c8c14fc final-candidate report](m6-final-candidate-2026-10-31.md)
  supersedes the pending-verification statements for that source in the dated entries below.
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

Settle C253's client license policy and artifact-aware enforcement without
silently granting exceptions. PR #277 full CI, C252's declared advisory scope,
and the current authority image's lifecycle/default-UID fixture proofs are
complete within their stated bounds. C251 retains an unattributed historical
failure; no further image-pending claim remains. Keep the new six-test C240
actor-loop draft at source-only status until actual compilation and acceptance;
public-close proof remains separate. complete M4-47 when its recorded account-security requirement is
satisfied. Resolve universal-license decisions, actual deployment inventory/
PKI/OIDC, simultaneous-restart recovery, off-host capacity/soak and operational
ownership before any deployment claim. Preserve all failed attempts and older
artifact identities. Keep this goal active while any criterion or deployment
input remains unresolved.
