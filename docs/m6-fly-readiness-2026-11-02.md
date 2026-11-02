# Fly readiness failure and recovery-path follow-up

Status: production goal active. PR #287 is not eligible to merge because its
actual-image Fly rehearsal failed. Its regular CI remains separately tracked;
no successful source, packaging or native-archive check waives the runtime failure.

## Exact hosted candidate and failure

[PR #287](https://github.com/andymac4182/agentuplink/pull/287) freezes head
`753aeb5ca006889ce23b59be157342d4e72b6083`. Its actual Actions checkout is
`e99f2c1829a4838b5fb0faaa185cb00fd67251d9`, with parents main
`626ba9365b5d3e1faf8265f0b6ff50cc9111b749` and that head. Both candidate and
checkout have tree `48a61c1d8bc3c4656ecda3d67c4a171104bd77cc`.

[Fly run 41404982490, attempt 1](https://github.com/andymac4182/agentuplink/actions/runs/41404982490)
(job 125144864322) builds all four images and verifies their five executable
and notice manifests. All eight host publications pass the exact single IPv6
loopback/valid-port predicate: Redis, authority and both ports on each of three
relays. This is actual hosted evidence for C261's binding correction, not a
successful complete cluster rehearsal.

Redis TLS and durable configuration checks, catalog provisioning, initial
authority publication/checkpoint and all three relay starts complete. The next
step fails `cluster_readiness_deadline` during bootstrap. The total attempt is
144.118 seconds **including cleanup**. No clients, nine-route acceptance,
scheduled rotation, revocation or restart gate is reached. The old readiness
loop retries both HTTP 503 and connection/OS errors without recording which;
TLS errors are included in that missing distinction. Its retained last command
`docker_container_inspect` is stale context, not a diagnosed cause. All five
service containers were still running before cleanup, which does not establish
application readiness.

Cleanup passes with zero errors/interruptions/OOM observations: all 40 containers
have removal plus exact absence checks, all 40 private log captures succeed,
all 12 volumes are removed with a final empty owned inventory, the network is
absent, and all 532 command groups are absent. Source and images remain unchanged.
This does not erase #285's five log-capture failures, #286's binding failure or
C256's local quarantined cleanup failure.

Artifact 13123087912 is 29,973 bytes, SHA256
`7f1a2dc1f96239069df279de57abdddf492eebecb1fb6bb49dae228fd4eb05a5`.
The result SHA256 is
`6c0c522a6e6dabf34150f974a174d50c1b99c1e48930f6556ac8c836ce463c50`;
events `7393b160179c13f711b0b5d69614fdeb671d5360098dd74ff02024032c23c57c`;
image receipt `481e16a852930e811fcc8615445792dd9810c10d85ffc547878a47e221abcbae`.
Independent failure review SHA256 is
`7e8328c2563910234e2e181a4723bd3c9cc0c92329e8139be8d0f0bb573ef76d`.
A running-job log lookup was unavailable. A later artifact-transfer helper also
failed without retaining its stderr; that diagnostic limitation remains recorded.
The connector-supplied bounded download then matched the artifact digest. Neither
failure triggered a runtime rerun or cancellation.

### Actual image and executable identities

These are Linux amd64 Docker configuration IDs, not registry manifest digests.
Every revision label is the actual checkout above. No local execution of these
images or release archives is inferred.

| Role | Docker configuration ID |
| --- | --- |
| authority | `sha256:22d7cf8082a3a0aa55bba42257403b497a98da7e6881b19137cf4f60d77de925` |
| client | `sha256:80c8f8814a4625a1f0650300ce0aa9142ce4bc06aa5f669f6063a2a1503b3bf0` |
| redis | `sha256:40a51e58945991fee97d8ffa1d5a63ffb2818aec0a05a7f922ce32a951e5f4d8` |
| relay | `sha256:bb76ca31368f45b69f6a6429802a416efe6a1c78874a9877e4ed2bcd091919ee` |

| Executable | SHA256 | Notices manifest SHA256 |
| --- | --- | --- |
| tunnel-authority | `75a244f6896da55b1944aa539ecac1c15b54a219bc2f828aacfc896674ac7fc7` | `4250fff00009a1f4bd69106420e5765221b3d5be69f1b8d124cc70bd2bdc6179` |
| tunnel-client | `a24aa004e4007379b49878bc9d84f9aa2aabe47229864bfde8c82a6f53c3feb1` | `840b983679b12322eeb689ca4cf09ce54612ba7b01ff827ae2af09422a271da4` |
| tunnel-deadman | `a14944fd2fa8e262faeaee911ac6a0b5f3289cf2c98ecdb72d7297eb31ded3b7` | `8551e47327bf9454b12e354730e018721415f472f53f39b5a70876692baba136` |
| redis-server | `a775ade32bc71fc06684b1cfae8ef4a68c7aa57fb402c836cf5d0063333719ab` | `a77b6beef70547c4caf8ecc362dcdb5f8fa536c6ca0cd914485066e36c98b3db` |
| tunnel-relay | `6dd97259169a37bdea722a53e3b91379ea48711f0a97ae7fafeca91ff37c9e8c` | `ea6da5fd8febbb71ca628a1bf20527c02f659c796351577f73d4e8bdbe5a87fe` |

## Separate ordinary checks

At the same actual checkout, three-OS packaging and all five optimized builds
plus five native archive verifiers pass. Attestation/publication are skipped.
All three Rust OS jobs explicitly pass the four M3-53 handler regressions; full
M3 passes the real HTTP harness, SDK conformance and MCP demos. M0 passes all 21
real gates and 21 declared negative witnesses, and M2 passes three actual
300-second rotations in 903.346210725 seconds. Regular CI
41404982454 completes at 2026-11-02T17:54:59+10:00 with all 14 jobs passing,
including the full implemented M7 suite. These results remain
bound to #287; a changed successor needs its own required checks.

Final ordinary-CI receipt SHA256:
`b71d0237faad691b21c05f8db727d066d612c94d60944acac4da7ad526831b33`.
All 27 retained job logs bind the same actual checkout.

Packaging receipt SHA256:
`9e6f78925009cefb812aaba06eb773334601ee629f1231a998dc8ace264ededf`.
Optimized archive receipt:
`dfc08d0a0e75b130639ff0d02bef405294d8492e067adf66386c0c5e628a665e`.
Three Rust OS receipt:
`c7dde204e87ab7a67fe55e720c1866b317a66153305d5ec3167cce385575240b`.
M0/M2 receipt:
`9814d60608aecd5e84cb308851de4a62e85b83aca81b2ddbe7bbec24dabaa4c0`.

## M6-C262: incarnation-specific membership state

The old Fly template and entrypoint require one fixed membership filename.
The Rust membership envelope binds its deployment, incarnation and node, so a
new recovery incarnation cannot reuse that file. Deleting it or resetting its
high-water is not a valid remedy. This is a source defect in the documented
recovery path, not attribution of #287's same-incarnation readiness failure.

The isolated correction derives a flat membership filename from the complete
SHA256 of the validated incarnation. Renderer, entrypoint and passive observer
independently enforce the exact path. Same-incarnation restarts/image updates
keep the path. Old membership files/locks, the stable recovery-approval fence
and authority state/counters remain preserved. Startup adds no initialization,
copy, rename or permission repair. Operators with legacy same-incarnation state
need a separately reviewed, exact-state-preserving offline migration; initializing
an empty replacement is prohibited. That migration has not been exercised.

The original renderer deterministically fails the different-incarnations/
different-paths assertion. Corrected source passes 111 pure/mock/temp controls.
An auxiliary receipt check initially expected the wrong unittest wording; that
failure and the correction against the same retained log are preserved. No native
service, Docker, Redis, Cargo or cache operation ran locally. Source receipt
`5a2c444867ead8a388b75118b020bb74753b5a9df15dac32595133866e9aa00f`
binds nine changed files and patch
`abde4b3751908e3a6869c35ad66678bf3c958facada14480d3f82ba3ea677d55`.
Independent source review
`cc316dda5550c804da2e258a06d510cc60b76a49700490fe13d711832b21e9b1`
finds no remaining concrete blocker in this minimal contract. Rebuilt-image
startup/restart and actual recovery remain required.

## M6-C263: closed readiness diagnostics

The isolated successor preserves bounded HTTP outcome classes and adds a
strictly container-loopback private metrics observation for failed readiness.
It retains the 60-second readiness bound, exact 200 body and 503 retry behavior.
The rendered relay binds metrics only at `[::1]:9100`, enforced independently
by its entrypoint; no Fly service or Docker host port exposes it. A failure-only
helper runs as the relay's default UID/GID, with an absolute five-second bound,
64 KiB body cap and fixed metric projection. All three diagnostic attempts share
at most 30 seconds within the original overall budget and cleanup reserve.
Strict parent-side schema validation prevents raw bodies, errors, labels or
logs from escaping. Secondary failures cannot replace the original exception
or its saved readiness/node context.

The initial missing-observation control fails against the original loop. The
first correction passes 119 controls, then a separate deep-JSON 503 control
reveals that diagnostic classification could itself raise RecursionError and
change retry behavior. That failure is preserved; the corrected boundary passes
120 pure/mock/temp controls, including all 104 pre-existing cases unchanged.
Leading-whitespace malformed selected metrics are refused, and the per-attempt
context now identifies the actual readiness request before diagnostics run.
Source receipt `89c5d393de936287e760f778dd6266f68987348af8274558781d7463fa5180a7`
binds patch `578609ed92774de5dd32e0f729d31da9ab11e647b16b628c821b6471b17106b7`.
This is diagnostic work, not a claimed repair of the unknown readiness cause.
Independent review `aaf591d3d7e3f36f54e0d26c941ddea07c5900d6d8a1c562210ee78cfa959121`
confirms 87 existing controller functions and 104 tests unchanged and the exact
Rust metric/enum bindings. Its auxiliary AST-extractor error is preserved
separately; correcting that read-only extractor did not change source. New
source-bound image verification remains required.

## Integrated source validation

The combined C262/C263 source passes 127 pure/mock/temp controls, changed-Python
AST checks, a 52-file declared-format secret scan, `git diff --check` and the
unchanged evidence guard. Every C262 test/helper AST and each new C263 test
function is preserved. Receipt SHA256:
`a319516bb3ba67a8e24ca390c7169abbd9abe856923e083b4ef2a37f0b2587d1`.

The first combined attempt remains failed: 126 controls pass and one errors
because the sparse checkout omitted the unchanged Rust membership enum source
needed by its binding test. That attempt is
`61d67b2ba2860520c7ab9595b05b58640abf9d01891ad015403013a04f7333e4`.
Materializing the exact base source corrects the environment; no test or
assertion changes. A preceding patch applicability check also failed where two
new test insertions shared C262's context; the final integration preserves both
sets of methods exactly. No local native/image/service execution occurred.
Fresh hosted checks and the actual-image rehearsal are still required for the
publication candidate. A successful local diagnostic test does not diagnose
#287's missing readiness cause.

## Separate authorization and recovery work

M4-76 records a source-derived gap in already handed-off HTTP/9P work: an
unanswered refresh replaces the old confirmation deadline, HTTP read expiry is
gated on confirmation, and the filesystem dispatch snapshot has only an
actor-updated freshness bit. Existing new-DATA, queue and periodic-expiry guards
remain effective within their stated scopes. A separate reviewed source plan
retains independent dual-clock confirmation and operation bounds and the exact
provider-observed cause. Local freshness lapse must remain retryable 4006/1011;
explicit invalidation remains 4001/1008. Cadence, quotas, replay and M4-47's
recorded account-security block are unchanged. No new timing reproduction or
current Rust verification is claimed. A bounded atomic snapshot proposal also
needs explicit contention/availability controls and independent implementation
review; contention must not be misreported as revocation or elapsed freshness.

M6-C264 separately tracks an actual-image recovery rehearsal being prepared for simultaneous
all-role stop and same-AOF Redis restart, independent higher-version approval,
new incarnation, preserved revocations/counters and fresh clients. Physical
older-backup restoration is a different required scenario; the older native
RDB procedure cannot be copied into the AOF-only image unchanged. Neither
scenario has run on these images. Its initial source draft passes 45 pure
controls, but independent review finds observed JSON integer/schema strictness
gaps; those controls and the unverified draft remain retained while corrections
are prepared. External Fly inventory, account access,
PKI/OIDC, independent backup/revocation custody, capacity/soak and operational
ownership remain unresolved. No license exception or live deployment is approved.

## Superseded PRs and retained limitations

PR #286 closes unmerged only after regular CI passed all 14 jobs, three-OS
packaging passed and its failed Fly run was terminal. #287 includes its source;
neither Fly failure is waived. Final #286 evidence receipt is
`f2fc9ab5b403a1b5355ae732ea481725f42b7329636382c774f94dd462a2d770`.
Dependency PRs #279/#280/#281 also close unmerged: their exact three-field
updates already exist in main. Each old failed and cancelled run remains
historical; no branch was deleted or run cancelled. Other old PRs with
unincorporated or deliberately held scope remain open.

The publication checkout's first sparse materialization left an empty index;
its clean-status postcondition correctly failed before any source integration.
Explicit initialization of that new worktree's index corrected it. Other frozen
sources and all quarantined native/cache resources remain untouched. All eight
production-readiness criteria remain open and the continuation goal stays active.

## PR288 hosted readiness and diagnostic failure

[PR #288](https://github.com/andymac4182/agentuplink/pull/288) freezes
`0ee715d0a942042c69d6fd4010c62bd4374c3b90`, tree
`40e3cb34a8883ca0a423874a299e7db31c457f8f`. Actual checkout
`802ee4ac4f3c6e8f2d7a8c67adb7fbe7f897de38` has that tree and parents
`626ba9365b5d3e1faf8265f0b6ff50cc9111b749` plus the candidate head.

[Fly run 41410567831, attempt 1](https://github.com/andymac4182/agentuplink/actions/runs/41410567831)
(job125162415810) builds all four images and passes their binary/notice checks.
It fails `cluster_readiness_deadline` at bootstrap, `https_readiness/readyz`.
The new observation establishes 111 verified-context HTTPS replies from relay-a,
all HTTP503 with the exact unready body. It records no transport error for those
requests. Relay-b/c have zero readiness polls because the original short-circuit
behavior remains unchanged. No client, routes, rotation, revocation or restart
acceptance is reached. Total 145.873 seconds includes cleanup.

All three metrics helpers return `metrics_identity` before opening their HTTP
connection. The helper asserted UID10001 and GID10001, but the Dockerfile pins
only the UID and lets `useradd --system --user-group` allocate the named group.
That numeric GID assumption is unsupported. The result does not identify which
identity assertion failed or retain the actual GID; no exact historical GID or
primary readiness cause is claimed. The previous source review's claim that the
helper runs as10001:10001 is corrected, with its original review retained.
Correction receipt SHA256:
`e6fbbfdebcde348ec2cbc525426e1a9445831418926d723e1104a1ed6397f65a`.

Cleanup verifies all40 containers removed and individually absent, all40 private
logs captured, all12 volumes removed with a final empty owned inventory, the
network absent and all541 command groups absent. Every recorded command exits0,
no OOM/interruptions/cleanup errors are observed, and source/images are unchanged.
All preceding failures and C256 quarantine remain retained.

Artifact13125538859 is30,308bytes, ZIP SHA256
`f13a8b3442a817a7947f4ad2f1b04e4ee876d96f96554406756b429125f6d4db`.
Result SHA256 `87887ba9cd2bf4fc6ab7a12e61b24f89787a2d117682e72ca0d6a56dcdbeaaed`;
events `bf6081eb3374c9c06dd5d1269c2ed2d5e34bc0dca9ec11a8caa07bfc715186ef`;
images `0d95a56b8aeb8fa83959aeb56dfe89cdf2beff408342bd44daf5d2d390813010`.
Independent failure receipt SHA256
`657b27ddf976742f582364d09a9f336b4830e80b6161c8e7ab84a6aaccd4121e`.

All four images are Linuxamd64 at the actual checkout above. These are Docker
configuration IDs, not registry manifest digests:

| Role | Docker configuration ID |
| --- | --- |
| authority | `sha256:cfe38fd3e3f55e69b7e5c0d83ac64799caaef00825738fdd50af1a8838d53adf` |
| client | `sha256:6530518bf69745cc17011d5f503308d45c9a919dc6c5f6aa3d2949bf74069171` |
| redis | `sha256:e2fff915767eb3041607c6f9b244fdac707f57ed18040ad63cad597253f8af36` |
| relay | `sha256:c308ec83122eafedb30ceee4769fcbdc089f7ad87ca0b3daeb21489ac21eb763` |

The independently verified binary and notice hashes equal the corresponding
#287 entries above; this identity comparison does not transfer runtime success.
Three-OS packaging, all three Rust OS jobs, full M3 and all five optimized
build/native archive verifier pairs pass at #288. Ordinary CI remains active at
this checkpoint. None waives the Fly failure or verifies later M4-76 source.

### Named-account diagnostic correction

The successor resolves the image's named `relay` account, requires its UID and
its effective UID to equal10001, and requires the effective primary GID to match
the account's positive, non-root GID. It adds no user override, image-account
mutation or permission repair. The timer, private loopback request, strict metric
projection, byte limits and closed failure output are unchanged.

Two targeted controls first run against the old helper fail three assertions;
those results remain retained. The corrected helper passes16 focused mocked
controls, including a synthetic nonmatching UID/GID number and root, foreign,
mismatched and missing-account refusals before HTTP. Ninety-eight other controller
functions and79 existing test methods remain unchanged. Source receipt SHA256
`d481d1bf1d3715f992e9b8b47912dcca96de441bdcafc4f1704b59ddb0964f5c`
binds patch `dc12ed3a537ea2bf9c4ac158a12ef66f6a964ab34a30d8f50b6b877b0199c63c`.
Independent review SHA256
`50548b3bf13ec103c1b7c8a90ac7486d08736caddd16a044895559d79fecea78`
finds no remaining concrete blocker in this diagnostic correction. It does not
establish the old runtime GID or repair/diagnose the primary503 readiness cause.
New hosted image execution is required.

At a later #288 CI observation, M0 passes all21 real gates and21 negative
witnesses, and M2 completes three actual300-second rotations in903.313751879s.
Regular CI has13 successful jobs with M7 still running. M0/M2 receipt SHA256:
`21d6377e446a03763c63c80adec8c872739464f59e799ab8e08d11a57875f602`.

## Combined authorization and recovery successor

The next isolated source combines the reviewed ten-file M4-76 correction,
C264 same-AOF controller/workflow and named-account metrics fix without editing
frozen #288. All191 pure/mock/temp Fly controls pass, including the62 recovery
controls. Five workflow execution controls pass: valid immutable build receipts
select the exact images, while wrong source, mutable tag, wrong role and missing
receipt refuse before dispatch. No previous baseline assertion or budget changes.
Changed Python ASTs, declared-format source scan, whitespace and the unchanged
evidence guard pass. Receipt SHA256:
`85a9d2bee429d57d5063868a1cd4de838756d8e9dbebf7bb2615a9d9b7184385`.
The prior189-control integration remains retained separately as
`7ad9306b870b509720989032c939dfdc0bb63f5b52875f45aeeb20098815ffc5`.

Two preparation failures remain recorded. A create-only evidence-directory guard
refuses an accidentally reused output path before any test executes; the prior
receipt remains unchanged. A source scan then flags two unchanged Redis URL
f-string placeholders. Exact match hashes, unchanged baseline bytes and AST
formatted-value bindings establish that these contain source expressions rather
than credential values. Both matches are explicitly classified, with zero
unclassified matches in the declared formats; the failed scan receipt
`8b20ac88fb4d206976e0289996374af6e0d9ddb2a396a4a85ade768c7b4cf680`
remains failed. No raw credentials, license exception or weakened runtime
assertion is involved. This limited-format scan is not a universal secrecy proof.

M4-76's20 Rust regressions, fresh formatter/compiler/Clippy/full native acceptance,
behavioral mutation witnesses and both image rehearsals remain pending. A separate
hosted witness plan binds nine exact API-preserving mutations and named assertion
failures; compilation errors, missing matches, zero tests and timeouts cannot
count as RED. Older physical-backup recovery, actual Fly inventory and live proof
remain separate. The production goal and hourly automation remain active.
