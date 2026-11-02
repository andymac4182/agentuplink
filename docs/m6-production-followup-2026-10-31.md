# Production follow-up after PR #275

The production goal remains active. Current PR #275 CI is **failed**, with
13 successful jobs and the M4 filesystem confirmation failure retained. This
report separates the exact hosted candidate, original release artifacts and
subsequent local fixture work. No merge, release publication or deployment is
authorized or claimed by these results.

## Candidate and hosted results

Draft [#275](https://github.com/andymac4182/agentuplink/pull/275) head
`b13f43cd38c356863dfdd9a99a4573c191d58965` and actual hosted checkout
`5909dc38ec843275e81dd2c73116b91ded575934` share tree
`2bf1832d3554b1c9aba2f9478d2f980fc10b2ed8`. Actual checkout appears in saved
job logs, independently compared with GitHub commit metadata. The source
identity receipt SHA256 is
`3e2d853d0c92adf6b76f8c366bb31067b813d34149a3103e6139f8ba7a63a881`.
Head b13 changes only four documentation files after locally tested
`88083555ffec868012938e0d253e9090177deec2`; its required checks, failed
post-test selector, separate selection recovery and native drill histories
remain in [C251 evidence](m6-c251-authority-lock-2026-10-31.md).

| Evidence | Result and limit |
| --- | --- |
| [CI 41193644443](https://github.com/andymac4182/agentuplink/actions/runs/41193644443) | Final failure: 13 jobs pass, M4 fails. No rerun or waiver. |
| Ubuntu Rust job124515625715 | Original unsafe-permission test and all21 authority tests pass; authority suite1.02s. Parsed hosted all-target totals2925 passed/0 failed/108 ignored across150 summaries. This differs in scope from local workspace2932/174, including doc tests; counts are not interchangeable. macOS and Windows Rust jobs also pass. |
| TypeScript job124515625904 | 610 offline/34 installed-peer tests, nine Mastra depth controls and installed Workspace regression pass on hosted Node24.22.1. Local Node24.21 evidence remains separately identified. |
| M4 job124515625939 | Actual four-framework300-second rotation passes at10:49:49.414Z; standalone log span311.346s, host295030ms before scheduled lower300398ms, resume1354ms,8 exchanges/20480B, zero replay/recovery/forced retirement, socket peak3→2. Revocation422ms, exact refusal/no extra stream13→14, independent grant/non-owner/cleanup witnesses pass. Later C244 fails; no whole-M4 pass. |
| M7 job124515625714 | Passes including all ten OG02 rows; suite completion11:19:21Z. |
| Fly job124515625845 | Relay/Redis mTLS profile, catalog/enrolment/revocation/reconnect/AOF gate pass. Relay SIGTERMexit0 in177ms. Current authority image sha256:a401890b52ce90ebee133d1f4871d745012e9f1c43351d22d39c527edc957a7c passes startup/default-UID/help/refusal boundaries. This job does not prove current actual-authority lifecycle or mounted-secret operation. |
| [Packaging 41193644397](https://github.com/andymac4182/agentuplink/actions/runs/41193644397) | Pass; separate push packaging41193638278 also passes. |
| Push CI41193638319 | Cancelled with14 cancelled jobs; retained separately. No manual cancellation or retry. |

M4's C244 command starts10:49:51.419Z, device attachment is logged10:49:55.478Z,
and the grouped final check fails10:49:59.865Z with
`filesystem fid confirmation: independent device/host/session/cleanup witness differs`.
Both held-response cases and refusal controls reached their earlier checks.
The failing scalar was not recorded; no particular scalar, Mastra regression
or historical cause is invented. The prior PR274 full-M4 pass remains valid
for its own candidate. Saved M4 log SHA256:
`9187f86018b42c111b24bbec73453e15a042c942f76a9cbcb7876a2b71ab97c5`.
Ubuntu log SHA256:
`bd282317afb7e4629a39e518ea2f51815aea299b09669e874a98db3f5fe07e27`.
TypeScript log SHA256:
`c5bf2c593fa585b6ffda94432a34fede4de267c859d6e9eb65d017f4da8b28fa`.
M7 log SHA256:
`dc4f3e98167c9df4ff166f90c48e56b4ff92a52923836ca7fb9566f669328e6b`.

### Hosted Redis rewrite artifact

Original hosted artifact13040097951 (`redis-aof-headroom`, CI41193644443)
was downloaded and verified against GitHub ZIP SHA256
`6d6b3a14d1f2b01e433ce533a00a21df33c72e830f961554aa02e85ed2604557`.
Its bounded TLS1.3 rewrite fixture passes in23.062s (23.478s including cleanup)
with shipped96MiB maxmemory inside256MiB/no-swap,1CPU/64PID limits. It records
44224 acknowledged writes, zero refusals,726809600 wire-input bytes,141 memory
samples and no OOM/OOM-kill/group-kill events; the owned container is cleaned.
Redis image identity is
`sha256:af0cbef80ec5d8947816b4f5bcad5e0f1f8a7a4746a65e2c4b6be507cb6e5977`.
The268677120-byte cgroup peak includes reclaimable AOF file cache, kernel memory
and observers; separate sampled anon197386240/file156737536 maxima need not
coincide. These figures are neither Redis RSS nor unallocated application
headroom. They do not establish live capacity or the100-device/24-hour soak.
The raw original ZIP, member hashes and source/image provenance are retained
in `production-limits-hosted-275/hosted-redis-aof-review.json`.

## Original release archives

[Release41193644429](https://github.com/andymac4182/agentuplink/actions/runs/41193644429)
passes all five builds and all five native archive verifiers:35 checks,
74 CLI probes and55 applicable planted negatives; five platform-inapplicable
negative cases remain explicit. Attestation and publication are skipped.
No supported platform is removed. Release metadata is
`v0.1.0-main.41193644429.5909dc38ec84`, source5909, development channel.

All five original uploaded ZIPs were downloaded via the GitHub artifact tool.
Independent read-only inspection verifies the GitHub ZIP digest, inner archive
checksum sidecar, exact release metadata, expected emitted binary set and
hashes. Download verification itself executes no binary. A first ad-hoc read
incorrectly expected a containing directory and raised StopIteration; the
flat archive layout was then inspected correctly, without an extraction or
execution in that failed inspection.

| Target | Artifact | Original uploaded ZIP SHA256 |
| --- | --- | --- |
| x86_64-unknown-linux-gnu |13040191730|75671c4ab830e082c3a26b55db9f2c6635d9d8103fc81a19ef5d10da8121b8f1|
| aarch64-unknown-linux-gnu |13039479044|05e204d2e8fc181180167201dd15e3949371399d04ec6742a0b97d0a6330bb6b|
| aarch64-apple-darwin |13040177113|734f2467a9eecfa2fdbc32645d8fa454fa48528f3f931b6329eb2e967d4d0329|
| x86_64-apple-darwin |13040122507|552f129f65295d0a00ed7bb4e3b1d1cd792b7b98ae99bf350cbddb322cd773f1|
| x86_64-pc-windows-msvc |13039858548|3b47aee587cfb6d42a0d2613df40386d564fb293b22b433281d2828d054c3a27|

The original Linux binaries have SHA256:

- authority: `f3d2b435ef0580e15e46baf516414eaf3a46bac521ec42793fa4ee694fbcfabe`
- relay: `03e6a21fcaa3e018143e8f6de8fb06c67807ca631f34e268462e827ff1507b53`
- client: `d2a7bcbcfa794ab4ff3868c04a787a79fb10d9c033d1bfa634d8a2cc5424d69b`
- deadman: `f4d29032763f9c0e12222547296824c39ad83ad1ed2120d60d8cc85498970405`

The five-archive receipt is
`44c354091adfe2551a059774fe81ec80a3519db2c586b9cc7ba875a710b9ac46`.
Original ZIPs remain in workspace attachments. Extracted Linux execution copies
under `/tmp/agentuplink-release-5909dc38` are temporary, independent regular
mode0555 files; they are not repackaged or replaced by old matching binaries.

## Current original Linux packaged authority drills

The original5909 authority and relay pass a new three-relay lifecycle drill
in120.539s and older-backup/operator recovery in117.204s. The native integration
driver remains explicitly attributed to88083555, SHA256
`7907920bc66d34773efdcb6dfa04fe95e094a72c5792e4e8e0e872d065447bf8`.
All1086 tracked paths match in file-set identity between880 andb13; only four
explicit documentation files differ, and all1082 other runtime/test/script/
fixture/build inputs are identical. No older manifest or proof is rewritten.
The device connector is the test library; packaged client/deadman were hash
verified but not exercised by these two scenarios.

Recovery verifies the older backup omits newer revocations, old processes are
fenced, old startup refuses the changed Redis run, missing fence/wrong nonce/
stale digest fail, the actual recovery CLI consumes approval version1 and rejects replay,
revoked credential/grant remain denied, and fresh session plus two confirmed
refreshes preserve allocators and independent fences. The exact non-owner
canary succeeds through the designated non-owner, and all three relays adopt
the recovered checkpoint. No scenario retry or weakened assertion.

Lifecycle performs no Docker probe. Recovery uses two owned UUID-scoped Redis
fixtures with existing pinned image778c3ea6; no pull/build/shared Redis restart
or flush. Both immutable IDs and names are independently absent afterwards,
both stage groups623865/624096 are absent, exact selected process scans are
clean, and all protected source/archive/binary/helper inputs remain unchanged.
Container IDs are1065f76cf728267c0814424d111e311451baafd87e624b93cfafd2931bd181d0
andc2703c0af7b76e5f32d913fc8a62d3445a9446298107cb36db18dcf9f13a0284.

Recovery retains stronger workspace startup minimum2296885248B at both
preflight boundaries and unchanged active workspace/tmp/memory guards.
Its workspace minimum is2003390464B, tmp2367102976B, nonreclaimable-memory
estimate9141886544B; OOM counters are unchanged. Thirteen inactive compiler
libraries were temporarily copied and hash-verified under a coordinated cache
lease; all701810110B were restored to regular original paths after the run.
No frozen executable or dependency tree was relocated. Restore receipt SHA256
`75289b19e03755c8e99dbdbbde8065f2658bcfe3fe7fc8eba115c85aa80a75d6`.

| Private proof | SHA256 |
| --- | --- |
| Aggregate |cc1dbe78a2cb6d5b9ed5323781808eb246c2f9704c9ea641bff1bf3de039423f|
| Lifecycle |a1ee4381e8a9073ebccf7912584ddc30df108f58473fb0e963f3d848a3934b38|
| Recovery |e22dfca5d93bc7c911465cd95b61a887dc3c3fc7e539f6f66a5cc1cc231d823a|
| Inner recovery result |5bdcb53ba074adb3e8c4cc3cc0c10e04c20118eac0c33f5707c394d8927405c2|
| Exact C243 log |42ea06dfaff1cb3f3500083b92ec41343c831a9320deb1bb67c1ae20f1aa8e46|
| Independent final handoff |9a545d7df9b4362a34e41a9ebedd215017424df738388132b4684b4d327d35a3|

Evidence is under `agentuplink-review-artifacts/packaged-authority-5909dc38/v1`.
Controllerc6771f66 and preparationae98bc2a passed independent review and113
read-only controls before one exclusive execution. This is original Linux
archive evidence, not current actual-image/default-UID, other-platform runtime,
full current CI or deployment acceptance.

## Follow-up scope

C244 source review distinguishes completed-handler counters from subsequent
STREAM_FORGET and carrier-barrier retirement. The fixture-only observer
waits for all final predicates in one status snapshot under the existing
30-second ledger budget and90-second scenario deadline. It immediately rejects
observed identity, epoch, phase, accounting, rotation or recovery contradictions.
No deadline, session, request, replay, product runtime or final acceptance
predicate is relaxed. Bounded scalar diagnostics preserve a future refusal's
observed state. The historical lost scalar remains unknown. The local verification below supplies the focused negative control, fixed tests
and actual gate; new hosted integration remains pending.

The current audit reports two moderate affected nodes for
GHSA-g3hv-75wg-m249 (minimatch10.2.6 and parent just-bash3.4.2).
The configured high-severity gate passing is not a zero-vulnerability result.
M6-C252 tracks a compatible correction; no force-upgrade or license exception
is approved. M4-75 can close only its depth/framework-integration scope;
broader M4-21 and the failed full-M4 candidate remain open.

The existing actual8c authority image/default-user proofs retain their own
identity. Current image lifecycle/default-user verification, M4-47 correction,
universal license decisions, deployment inventory/PKI/OIDC, operational owners,
off-host capacity and soak evidence remain separate requirements. The goal
automation remains enabled.

### Verified observer correction at decc5b58

Local source `decc5b58dd4c91a417a61e09e47e3e35e4d30b38`, tree
`8df38cd8c6ce766147ae47870474d2da8237e9d3`, is verified at 2026-10-31T21:54:50+10:00.
The old-count-only negative overlay changes exactly one return predicate.
Its real Cargo build succeeds and the selected regression fails with exit101,
0 passed/1 failed and `handler completion alone must not end observation`.
The78.364s includes compilation; the failed libtest remains a failed result,
with a separate expected-negative witness. Exact helper bytes are restored.
All eleven focused controls then pass (46.601s including compilation),
formatting passes4.519s, strict workspace/all-target Clippy passes94.193s,
and locked workspace tests pass300.677s:2938 passed,0 failed,108 ignored,
174 final suite summaries. An earlier progress observation counted172 summaries;
final stdout and the immutable receipt both contain174, with matching log hash.

The final actual harness-bin compiler-JSON build passes61.480s after Clippy
and tests. Exact package/manifest/source/target/profile selection freezes a new
independent regular0555 binary, SHA256
`f510526b88cf1b5f18128a626537aee3736dab71d5de3f1a31f521db28013fc2`.
The RED and fixed unit copies retain SHA256
`d9d11f42f516a35e59445235132b77774160cfceed7fd1b6b928b73724aff412`
and `7ff32b81057a9f36c6bf6bcdaef10423e880d6d788f577298a274e9924520f7a`.
Unit copies are proof bytes on temporary shared memory; they were executed
from actual compiler paths before copying. The actual gate uses the independent
new harness copy under `/tmp`, not a guessed target path or an older binary.

The first and only new real `verify-m6-ts-fid-ordering` run passes13.0765s.
It directly observes one pending snapshot: exchanges3,streams1,replay1, with
valid identity/lifecycle and zero mutation/write. It then observes the same
session/epoch active with3 exchanges,0 streams,0 replay,0 rotations and no
recovery. Both real walk/clunk hold cases, actual provider probes, surviving
parallel fid2, confirmed reuse of fid1, refusal/pre-abort controls, unchanged
host and joined cleanup pass. The owned process group639107 is absent and
namespace scans are0 before/after. This establishes the ordering gap in this
run; PR275's discarded historical scalar remains unknown. The prior real
premature-walk/clunk negatives and invalid first clunk overlay remain separately
retained; this slice does not claim flushed-before-dispatch clunk or broader
M4-21 acceptance.

All tracked source,22 protected files, Node24.21,16798 dependency entries,
new frozen copies and driver inputs remain unchanged through the run. All
six preparation groups and the actual gate group are absent. Minimum estimated
available memory is6052488448B; new OOM/kill/group-kill deltas are0. Final/minimum
free space is2229571584B in/tmp and approximately1682042880B in/workspace.
The58 inactive earlier integration-test cache outputs were independently
byte-archived (1192673184B) before compilation; missing mutable outputs rebuilt
normally. No frozen source/executable or immutable dependency tree was moved,
and no Cargo output symlink was used. The original compiler cache may change;
the six independent880 proof copies and original receipts remain intact.

Private runner versions1/2 were never executed. Pre-execution review identified
missing outer deadlines, memory/OOM guards, residual-group cleanup and setup
failure capture; reviewed version3 adds those controls while preserving the
fixture's30s ledger/90s scenario deadlines and all acceptance predicates.
The first root lease-file creation inside the frozen plan directory was refused
with PermissionError; `set -e` stopped before execution. An external lease path
corrected only that setup error, without changing plan permissions or files.
There was no scenario retry. Source and artifacts in the worker worktree remain
frozen; the subsequent integration worktree adds documentation only.

| Local immutable receipt | SHA256 |
| --- | --- |
| Preparation |dd8896646473f0b9686b6571dee4188645e67e8e3c6b9cfbc92a2b0a7c1320da|
| Final gate and preparation |82559eefdf13ef34b3def2abacb7bad39a61f9554451b7734ce7e12b64893a44|
| Gate stdout |ca09de68249229039fa53483e3d3dd605a1f324759cba09528f600c8107a9db8|
| Gate stderr |f320e1d8f0eca063015f09df15224eef873ae14cb7562e90d8e2fe00ad3d38d5|
| Cache archival |61fc11ec7f7a0e8f95edb8ce7a774f1f5e0d6118dc6967556336d1b169dec473|

Hosted integration of this correction remains separate and pending. Original
PR275 CI remains failed; neither these local checks nor its successful release
artifacts close the production goal.
