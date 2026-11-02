# Filesystem completion accounting follow-up

The production goal remains active. The corrected f12 source now passes the
focused continuation and unchanged actual local C244 gate; full final-candidate
hosted and release checks remain pending. C244's current-candidate acceptance is
reopened; earlier successful runs retain their original identities. C254 tracks
the separate source-derived loss of completed provider accounting at valid
stream retirement. The correction now passes focused local native checks at
fixed source `f12c9d81`, including the exact provider cases and existing regression
groups. The unchanged real C244 gate also passes locally as detailed below.
Required whole-workspace checks and hosted verification of the final candidate,
plus live deployment evidence, remain outstanding.

## Exact hosted candidate and retained failure

[Draft #278](https://github.com/andymac4182/agentuplink/pull/278) has head
`a2a6a62a68cf44ee4c5e0f3a1c39a7456fb4bc4b`. The actual runner checkout is
`cf344feb652f0ecf04fd8965e814082eb9bd4f1d`; both share tree
`6c53ff202096731bff744709539452b4d1ec7d4a`. This is distinct from the fully
successful #277 head `bd93cfbd` / runner `3615d7a2`.

[CI 41210255323, attempt 1](https://github.com/andymac4182/agentuplink/actions/runs/41210255323)
has passed all three Rust platform jobs. Each includes required workspace
formatting, strict Clippy and tests, with all six new C240 actor cases and four
existing handler controls successful. TypeScript passes 610 offline / 40 peer
tests and audit zero. Both packaging runs pass. These hosted results do not
relabel the earlier local attempt that failed its disk guard before Clippy.

M4 job [124563800626](https://github.com/andymac4182/agentuplink/actions/runs/41210255323/job/124563800626)
fails after its actual 300-second installed-framework rotation succeeds:
8 exchanges / 20,480 bytes, 1554 ms resumption, 490 ms revocation, zero
replay/recovery/forced retirement and joined cleanup. The later fid-ordering
gate reaches its unchanged terminal deadline at
`2026-11-01T00:38:39+10:00` with:

```text
exchanges=2; mutations_dispatched=0; bytes_written=0
active=true; session_matches=true; epoch_matches=true
streams=0; replay_frames=0; rotations_completed=0
recovery_attempt=None; recovery_successor_generation=None
reason=deadline
cleanup failed: driver cleanup: I/O error: Broken pipe (os error 32)
```

The required third completed exchange is missing. All three Node cases reached
the terminal-observation stage, but the trace does not identify the missing
provider or its internal ordering. The later `CONTROL_CLOSED` cleanup message
is not causal evidence. Node's 10-second exit-command wait and the Rust
observer's 30-second wait are distinct; the secondary broken pipe is retained.
No retry, reduced exchange count or extended acceptance deadline was used.

Original decoded failure-log SHA256:
`6473c266e263646a8501aefb3cbd0cc816756e8fc1d1090eab78aa9f7365595a`.
Rust Linux / Windows / macOS decoded-log SHA256 values, respectively:

- `d9cd74c05adcbb7aba264a90f964afa5d065c98e47ee3a7ecc64a3ea00aa4916`
- `2c2ef92a3fc9effa09171b9a2fc4c0448d8d817919886ce53df574ac668280f7`
- `5ff3db68c3c60a4e089eced27b078412387777d34b66eef7399780949117105a`

The final run completes at `2026-11-01T01:07:24+10:00` with 13 jobs passing
and M4 failing. Full M7 passes all ten OG-02 correlation rows, none incomplete.
M2 passes three actual 300-second rotations in 903.311 seconds with 17,985
records and zero replay. M0 passes all 21 gates and 21 declared negative witnesses.
This is not a whole-candidate CI pass. Prior #276/#277 C244 successes
and #275's unattributed grouped-witness failure remain unchanged.

## C254: completed report can outlive its stream owner

The actual filesystem provider returns its payload-free report after queuing a
terminal frame. The exchange task then waits for both carrier pumps and sends
`HttpActorRequest::Done` through a bounded channel. The actor can first process
the real FIN, owner ACK, valid `STREAM_FORGET` and carrier barrier. Stream removal
drops `DeviceHttpState`, aborting the task before its report is enqueued.

The correction gives each filesystem stream one bounded completion
slot. The provider synchronously publishes its actual returned report before
the same task polls the outbound pump again. The actor consumes that report
exactly once on Done or immediately before validated stream removal. The two
paths share one private atomic claim. A late Done can therefore count a real
report even after stream removal, while an already collected report cannot be
counted twice. Public diagnostics remain unchanged. There are no new awaits,
tasks, deadlines, authorization exceptions or relaxed FORGET predicates.

Independent review rejected the first one-shot-only draft: retirement could
read an empty slot, then a provider on another worker could enqueue Done before
removal. That draft would lose an actual late report previously counted by Done.
The shared claim corrects this proposed regression; the rejected source and
separate formatting receipts are preserved. Three additional direct claim/slot
controls cover ownership ordering. They are distinct from the five real-provider
regressions and do not execute the complete concurrent reset schedule.

Five regressions drive real OPEN/authorization, a real temporary-root
provider, FIN/ACK/FORGET and the carrier barrier: retirement before Done,
Done first, queued late Done, a full bounded actor channel, and an incomplete
provider reset control. No report, ledger counter or sequence snapshot is
fabricated. The final reviewed fixture establishes the exact baseline regression
and the fixed executable passes all five provider cases plus 36 existing/direct
claim controls. Exact identities, retained failures and the focused result are
recorded below; this does not replace broader candidate acceptance.

An independently received peer RESET can retire a provider before it completes.
The completion slot does not invent a report for that distinct case. It also does
not establish awaited joins for all filesystem tasks. The three public C244
cases use normal close, which maps to FIN, but this source-valid schedule is
not proof of the exact hosted failure's cause.

## Separate current-authority image recovery

The current image
`sha256:52606609ffc52ed3206fd7dbe26b34fdf8d213368983a556beff338ff480f956`
built from `2f3686b7` passes its first older-backup recovery drill. It is not an
image rebuilt from #278 or the proposed accounting correction. The exact
selected decc driver is
`455108a49f93be28a00621234c955518a877fcb5d35a8a4896392892baea0a00`;
the original optimized 5909 relay is
`03e6a21fcaa3e018143e8f6de8fb06c67807ca631f34e268462e827ff1507b53`.
The relay's 427-file unchanged source closure is explicit.

The original recovery wrapper and all three binary overrides pass one native
test, zero failures, in 132.38 seconds (141.495 seconds overall). The drill
restores the stale RDB, observes 65.067 seconds of quiescence, refuses old
authority/relay startup before approval, reconciles revocations, checks missing
fences/wrong nonce/stale digest/consumed approval, preserves allocation high
water and independent fences, and establishes fresh sessions with two refreshes
across all three relays. Revoked credentials and grants remain denied.

All 11 authority and two owned Redis containers, 29 command groups and both
private fixture roots are absent afterward. All 91 protected inputs remain
unchanged; resource floors hold and OOM counters do not increase. The original
handoff timestamp-field error is retained separately from the corrected report;
the actual scenario was not rerun.

Result SHA256:
`67540b2b60108122e27144fe7d885e02f995beb27eb84cd9da58dbacf7a38020`.
Boundary SHA256:
`bb30063e2277b5ffedfe2c976130cc7e0e23b6c88277618ece531ad6ac0715e4`.
Handoff SHA256:
`87677861a17975003189dc9b22987250193f1bc0a9354cb14c32840aaf946550`.

This is local fixture UID 1000 / GID 1000 evidence. It does not establish
default UID 10002 recovery, live or off-host disaster recovery, or crash/fsync
durability. The separate default-user startup proof and earlier failures retain
their original scope. C251's exact historical hosted cause remains unattributed.

C240 public scope B, C253 license policy/enforcement, deployment inventory and
access, off-host capacity/soak and operational ownership remain open. The
hourly goal remains enabled. No merge, release publication, license exception
or deployment is authorized by these results.


## Continuation after the execution interruption

The exact 26-output cache preservation/release operation completed successfully
in 27.520 seconds, reclaiming 402,636,800 bytes. Every released executable was
already preserved as a byte-identical independent read-only copy; no new binary
archive was needed. Result SHA256:
`87433cd10f1c63087c158c778fa809cf5d59561966f9e7b88288edf86e9dd1fc`.
After the interruption, root independently reverified all 26 backups, their
metadata manifest, all 26 source-path absences, protected inputs, frozen source
and the absent controller/process group before releasing the stale reservation.
The cache operation was not repeated. This establishes capacity preparation,
not product verification or a guarantee that subsequent links fit.

The five-regression baseline is frozen separately at
`2b314fedd0fd452d70c8cd6efb9032852cd1c8c9`, tree
`b23bf6b09f677618831b13dfa16c280cecf8477b`; the reviewed correction is
`83b48bdabf9cc142d188f940b2e1905a291f1a69`, tree
`f814116a070315f6fe75b1a03469eee9c27dbf5b`. Both sources remain clean.
The interrupted private test controller was incomplete and had not launched
Cargo. Review also identified a private helper named `selectors.py` shadowing
Python's standard library, and a panic-location classifier that accepted only
absolute paths despite Rust's relative paths. These preparation defects are
preserved separately; they are not a product regression or a valid baseline
failure. A new controller revision must pass review before execution.

The November 1 Dependabot PRs #279–#281 target older main, not this stack's
current dependency graph. Both current locks already contain fast-uri 3.1.9
and undici 7.30.1; the three proposed target entries match version, registry URL
and integrity exactly. This read-only comparison adds no dependency change,
fresh whole-graph audit, installed-artifact verification or license approval.
Main's outstanding PRs remain untouched.


## First focused run: invalid baseline, retained

At the original tests-only `2b314fed`, the first actual locked/offline build
succeeds and Cargo selects a default-feature library test executable listing
263 tests. Its independent frozen SHA256 is
`155ec5048fcaf34eebfd3697aaf76383c0d7912f515ce9f1cad33e37deecdbb9`
(46,058,760 bytes). All five new cases fail at the shared fixture assertion on
line 232, before the intended ledger assertion on line 350. The original tests
expected `EACCES` for a `Tmkdir` without Write capability; they did not include
the actual reply in their failure output.

This is **not a valid regression RED**. The controller refuses the unexpected
five-failure set and stops without building or testing the fixed source,
running Clippy, or running formatting. Aggregate attempt time is 29.801 seconds.
Result SHA256:
`5bb8cb5cefb05cf85be8d967d52ff0f85e82a0af89df86b1c790f42ff9cd3b4e`.
All 176 source/protected/tool checks remain unchanged. The controller and three
owned process groups are independently absent. Tmp stays above 2,372,059,136
bytes, available-memory estimate above 6,114,805,960 bytes, with no OOM increase.

Source review establishes the exact fixture contract: Tmkdir needs Write,
missing Write returns NotPermitted, and NotPermitted maps to `EPERM`. The provider
counts that real refused mutation before emitting the reply. This is source
evidence, not a claim that the first run recorded EPERM. The proposed fixture
correction requires the exact EPERM reply and includes the actual reply in
failure diagnostics. It leaves grants, features, host-unchanged checks, exact
ledger counters, retirement proofs and deadlines intact. Original source roots,
failed logs and executable remain frozen; corrected baseline and fixed roles
must have separate identities and a reviewed new attempt.


## Second focused run: actor regression reached, status fixture still invalid

The following chronology preserves the earlier review points and later attempts
without reclassifying either failed aggregate as successful RED/GREEN
verification.

At `2026-11-02T12:56:49+10:00`, the identical strict EPERM fixture correction
was frozen in separate source roles:

- Baseline `fd912a6b3081bf6d7ec50a9fc3882c1248d4746f`, tree
  `b7f6a6b614bceddc8ebd0dd40b2257abd33cf545`.
- Fixed `d0e0e11294b765b368d298fd917aa2e173c85f18`, tree
  `10c88b7fd2d2a40e532994e2db700939856661be`.

Attempt 2 builds the baseline successfully and lists exactly 263 tests. Its
independent frozen executable is 46,068,808 bytes, SHA256
`9304e2ec93b20534bc2c7ba24095381087d80e6cf40ac697f19ad6283fd2af1a`.
All five cases pass the corrected exact EPERM fixture assertion. Three expected
regression cases then fail the exact actor-ledger assertion on line 355:
retirement before Done, queued Done after retirement, and the full Done channel.
Each observes zero counters where one completed exchange and one refused
mutation are required. The incomplete-provider reset control passes.

Done-first also fails: its actor-ledger assertion on line 355 passes, but its
published watch-status assertion on line 356 still reads zero. Consequently,
there are four failed cases and one passed case, rather than the required
three-failure/two-control baseline. The unchanged classifier rejects this
**invalid aggregate RED** and stops. This exposes the intended actor regression
in three cases but does not complete baseline acceptance. No fixed build, fixed
tests, scoped Clippy or full-format stage runs. Aggregate time is 27.068 seconds.

Attempt 2 result SHA256:
`3356479f457c356f690371720c021de734bf5077e1b3ca3835ffaf654b4244b7`.
At `2026-11-02T13:05:04+10:00`, root independently confirms controller 679120
and owned groups 679135, 679450 and 679452 are absent via ESRCH. All 256
source/protected/tool checks remain unchanged; independent frozen and current
compiler-origin bytes both match `9304e2ec`. Tmp stays above 2,371,923,968
bytes and the available-memory estimate above 6,105,210,264 bytes. The failed
result and logs remain intact; the lease is released after this observation.
Root-final observation SHA256:
`8aff92451fa571e974bb086ff7641c6c4abb3825966e7eb162584639b87289bc`.

## Status-receiver diagnosis and isolated third-attempt preparation

Source review confirms a fixture lifetime defect. The shared
`test_actor_with_control_capacity` helper creates `_status_receiver` in
`crates/tunnel-client/src/m2_runtime.rs:9765` but returns only the actor,
carrier key, carrier receiver and control receiver. Its local watch receiver
is dropped on return. `publish_status` uses `self.status.send(status)` at
line 2719. Pinned Tokio 1.53.3's `sync/watch.rs:1046–1071` documents and
implements the exact behavior: with zero receivers, `Sender::send` returns
`SendError(value)` without replacing the stored value. `subscribe()` reopens
the channel. This explains why Done-first's real actor counters advance while
the receiverless watch snapshot remains at its default; it does not change
the three separately observed actor-ledger failures.

At `2026-11-02T13:05:20+10:00`, a second fixture-only correction is frozen in
new isolated worktrees. Exactly five lines are added to each identical test
file: a retained `_status: watch::Receiver<ConnectionStatus>` field, two comment
lines explaining watch semantics, `actor.status.subscribe()` immediately after
helper creation and before OPEN, and the receiver's struct initializer. The
receiver remains owned throughout the exchange. There is no seeded counter,
manual status publication, sender API replacement or production-code change.
Every actor/status ledger, host-absence, retirement, deadline and incomplete-
provider assertion remains unchanged. The exact ledger/status assertions move
to lines 360/361 solely because of these additive fixture lines.

- Fixed `f12c9d81198ecc296de1808e91a93ebba95654bb`, tree
  `21cd9b576e4b2821c6c9e1a2139b166acb739fab`, parent `d0e0e112`.
- Baseline `f23094826b464439c901b5f342167f977fb5c17c`, tree
  `cf06c1026f2b5de806876ef17a389e3d012e4c66`, parent `fd912a6b`.

Both source roles have 1,094 tracked files and identical test-file SHA256
`13276efbb373a2c46930ef9d7e089c83ca8fce2cc3cfacc26ab45ae83210037a`.
The source-freeze receipt SHA256 is
`eecd070d2f093264fc3083c1ba03f98adf630009dc23892e2705332624d1a25e`.
Only the new fixture file was formatted; this is not the required whole-workspace
format/check/test result. All four earlier source roots remain unchanged.

Controller V4 is prepared at `2026-11-02T13:06:47+10:00`, SHA256
`b926bcc3cf567ffc3304b821a9681763593ce53565a7dab39901ca77fb1481c8`.
Its six Python files are byte-identical to reviewed V2/V3. The new plan binds
the source identities, exact ledger line and current mutable compiler origin
`9304e2ec`; it keeps the independently frozen `9304e2ec`, first failed `155ec504`
and earlier C240 `da37b1f8` binaries protected. All logs, failed results and root
observations from both attempts remain in its 311-entry protection inventory.
The new source/protected/tool inventory passes all 322 checks; all 4,376 tracked
files across the four preceding roots remain unchanged.

All 121 pure controller controls pass with the new bindings, and both actual
failed transcripts are rejected as valid aggregate RED. The unchanged 11
memory-only terminal controls and import evidence are reused by exact hashes.
These preparation controls are not real-provider acceptance. Existing capacity,
OOM, process ownership, cleanup, deadline and exact test-count predicates are
unchanged. The historical cache receipt retains its original candidate identity;
it is not relabelled as verification of the new sources.

Following review, root starts attempt 3 exclusively under its separate lease.
The preparation above does not assert a native result; the terminal evidence
is recorded next. No parallel native work is started. A focused pass must retain both
prior failures and its exact baseline/fixed executable identities. It cannot
establish unchanged real C244 acceptance, a whole-workspace or hosted candidate
pass, live deployment readiness, incomplete-provider accounting, or awaited
joins for every filesystem task. M4-47 remains blocked and excluded.


## Third focused run: exact baseline RED, fixed artifact rejected

Attempt 3 on baseline `f23094826b464439c901b5f342167f977fb5c17c` builds
and lists exactly 263 tests. Its actual provider run reaches the required
three-failure/two-control classification: retirement before Done, queued Done
after retirement and the full Done channel each fail the exact actor-ledger
assertion at line 360, with zero counters versus one completed exchange and one
refused mutation. Done-first and the incomplete-provider reset control both
pass. This is accepted baseline regression evidence, with all original libtest
failures retained. It does not make the overall attempt successful.

The baseline's independent frozen executable is 46,069,496 bytes, SHA256
`7bef92c4ca5a2cf71a2248f4c06dc926196542ae3da6dec8c75d7298abd7d53f`.
The subsequent nominal fixed build names the correct fixed-source package,
manifest and library path in Cargo's JSON but reports `fresh: true`. Its
selected executable is byte-identical to that baseline binary. The nominal
fixed copy lists 263 tests, rather than the required 266 including the three
fixed ownership-claim controls. The unchanged exact-list guard rejects it.

The aggregate therefore **fails at fixed-list** after 26.434 seconds. A
successful Cargo exit and source-shaped JSON metadata do not prove this binary
contains the fixed implementation. The file labelled fixed remains preserved
as an independently frozen copy of the observed artifact, not as a proven
fixed-source executable. No fixed tests, scoped Clippy or full-format stage
runs. Fingerprint/source-provenance review is required before another native
attempt; no assertion reduction or unreviewed retry follows this failure.

Attempt 3 result SHA256:
`52b86431739dd2003c160145b8aad8bb19d9d09f2e95598c0344389f1cdac6f4`.
At `2026-11-02T13:14:20+10:00`, root independently confirms controller 679776
and all five owned command groups absent via ESRCH, all 322 input checks
unchanged, and both frozen copies/current compiler bytes unchanged. The root
observation SHA256 is
`e5f348db002b08613d5c4145ace14024363fa1ce2da9863155d3ccd8a3e4bfe0`.
The distinct outcomes of all three attempts remain preserved: first invalid
fixture RED, second invalid aggregate RED with a watch-lifetime fixture defect,
and third valid baseline RED followed by rejected fixed-artifact provenance.
These three failed aggregates do not establish GREEN verification or
deployability. The separate continuation below supplies the later focused result.


## Fixed-only continuation: focused local checks pass

The separately leased fixed-only continuation succeeds at exact source
`f12c9d81198ecc296de1808e91a93ebba95654bb`, tree
`21cd9b576e4b2821c6c9e1a2139b166acb739fab`. Its status is explicitly
`passed-focused-fixed-continuation-prior-failure-retained`, result SHA256
`4cbc927e2e786784cc7bef69956fe09f77eea36975d6580392ecbf6ad0b85ca7`.
It reuses attempt 3's accepted exact baseline RED on `f2309482`, including the
original three ledger failures and two successful controls; it does not rerun
the baseline or rewrite any of the three failed aggregate results. The first
fixture failure, second status-fixture failure and third fixed-artifact failure
remain preserved with their original logs, source identities and binaries.

The continuation first preserves all four b800502f fingerprint files and the
executable dep-info file: five independent single-link `0400` backups totalling
4,816 bytes. Every backup and its directory is fsynced and verified before the
manifest and unlink intent are durably recorded. Only the exact 16-byte
`test-lib-tunnel_client` marker is unlinked. Marker absence and the other four
unchanged origins are verified before Cargo runs. No other cache invalidation
or automatic restoration occurs. Backup-manifest SHA256:
`dfeb634a58422a0cda9b12ea03bd2e654d3b2d35ec65a6f1493c50c4939b70a7`.
All five preserved backups still verify after Cargo updates the mutable cache.

The actual fixed Cargo artifact reports `fresh: false`. Its independently
frozen single-link `0555` executable is 46,100,608 bytes, SHA256
`4e1f8cf3854f33c43b663dba9b095e00dd5f297edbc915dc0eb480297e1e1deb`,
distinct from accepted baseline `7bef92c4`. It lists exactly 266 tests and
passes the exact five provider cases, ten m2_http cases including all three
direct claim controls, eight existing fs_export cases and eighteen
STREAM_FORGET cases: 41 fixed test executions, zero failures and zero ignored.
The carrier/retirement, ledger/status, refusal and host-absence assertions
remain unchanged.

| Owned command stage | Verified result | Stage elapsed seconds |
| --- | --- | ---: |
| Fixed library-test build | Actual fixed artifact, `fresh: false` | 13.043 |
| Fixed executable listing | Exactly 266 tests | 0.509 |
| Five provider cases | 5 passed, 0 failed, 0 ignored | 0.510 |
| m2_http and direct claim controls | 10 passed, 0 failed, 0 ignored | 0.529 |
| Existing fs_export cases | 8 passed, 0 failed, 0 ignored | 10.535 |
| STREAM_FORGET cases | 18 passed, 0 failed, 0 ignored | 0.507 |
| Scoped strict Clippy | Exit 0; both library roles checked fresh | 32.599 |
| Full workspace format check | Exit 0 | 5.023 |

These are owned-command wall times, rounded to milliseconds. Libtest reports
0.02 / 0.00 / 10.02 / 0.01 seconds for the four test groups, respectively.
Overall continuation elapsed time is 68.150 seconds, including preservation,
resource/integrity checks and final recording.

The Clippy command is `cargo clippy --locked --offline -p tunnel-client --lib
--tests --message-format=json -- -D warnings`. Its source/package-bound normal
library and test-library metadata artifacts both report `fresh: false`, with
a unique successful build-finished message. This proves scoped strict Clippy
on the fixed source; it is not `cargo clippy --workspace --all-targets --locked
-- -D warnings`. `cargo fmt --all -- --check` passes. Required whole-workspace
strict Clippy and `cargo test --workspace --locked` for the final candidate,
followed by hosted verification, remain outstanding.

The controller's 37 preparation controls are separate evidence. They include
pure baseline/freshness/lease refusals and four tiny private synthetic-file
preservation drills, covering successful preservation, fsync failure, corrupt
backup and final guard refusal. They do not count as provider/native tests.
The continuation's 41 executions above are actual tests from the independently
frozen fixed binary. All earlier private-controller preparation failures and
unchanged cleanup-control receipts remain retained.

At `2026-11-02T13:29:34+10:00`, root independently confirms controller 680469
and all eight owned command groups absent via ESRCH, all 369 source/protected/
tool checks unchanged, and the fixed compiler origin, independent binary and
five fingerprint backups unchanged. Root observation SHA256:
`139b94d67ac6417f8033990fb44845ff89e082a4578436b286785d00a80dc21a`.
Minimum free tmp/workspace bytes are 2,338,086,912 / 2,739,687,424; minimum
available-memory estimate is 6,076,797,232 bytes. Historical OOM counters remain
unchanged; the observed OOM delta is zero. The same resource floors, process
ownership, bounded cleanup and exact acceptance assertions are preserved.

The five new real-provider tests are `#[cfg(unix)]`, matching the existing
Unix filesystem-provider support boundary. This does not reduce Windows
support for other functionality or substitute for the supported-platform CI
matrix on the final candidate.

The unchanged real C244 gate has not run on this fixed candidate. This focused
result neither attributes PR278's exact hosted failure nor establishes a whole-
candidate hosted pass, incomplete-provider accounting, awaited joins for every
filesystem task, or live deployment readiness. M4-47 remains blocked and
excluded. The production-readiness goal stays active; owner decisions and
external deployment access remain explicit.

## Actual local C244 gate at the corrected source

After the focused continuation, frozen `f12c9d81198ecc296de1808e91a93ebba95654bb`
(tree `21cd9b576e4b2821c6c9e1a2139b166acb739fab`) receives a separate
locked/offline default-feature harness build. Actual Cargo JSON requires both
the normal client library and harness to be freshly compiled at that root.
The build command completes in about 75 seconds; the complete guarded build
attempt takes 90.562 seconds. Selected and independent `0555` harness bytes:

- SHA256 `3ab944000155a1c88c27853971a59f41e5dc220bc3f714fe0d8641ad9820fb72`,
  137,397,192 bytes.
- Build result `cf6684d82d285dcb978955c4dcc3bd5dbb15979e170da9a1267e66b0be5d791e`;
  root observation `8199000d09a6e44c158cf357c9c3ebe708918eda1e579fe587e8cd2df094d53a`.
- The previous ordinary compiler harness `40a53b3562a6a46965032e735480c227d00249efbe9d0d0c700675cca28907ca`
  was independently preserved before its two Cargo output paths were released
  for normal rebuilding. This is byte preservation, not inferred source identity
  or new acceptance evidence; earlier frozen harnesses remain untouched.

The first separately leased `verify-m6-ts-fid-ordering` invocation passes in
9.146 seconds (21.547 seconds including input verification and cleanup). It uses
this exact harness, the actual source-relative driver/client module and pinned
Node 24.21.0 (`7fde7b8afa198da66257f42ee2001d874c7355631e6d1579a5fb5ef1f246df4c`).
The launcher preserves inherited trust/proxy/guard settings and includes the
fixture CA with verification enabled. Independent process observation sees the
actual pinned Node executable, driver and owned process group. Neither dependency
tree is installed, aliased or claimed exercised by this core-client gate; both
historical frozen trees are checked unchanged.

All unchanged gate predicates pass: three relays; both held walk/clunk cases;
actual provider probes; a distinct surviving parallel fid; confirmed reuse;
refusal and pre-abort controls; unchanged host and session; zero dispatched
mutations/bytes written; and joined cleanup. The terminal snapshot reports
three completed exchanges, zero streams/replay, an active matching session/epoch,
zero rotations and no recovery attempt. The ledger 30-second and scenario
90-second deadlines remain unchanged.

At `2026-11-02T13:35:26+10:00`, root independently confirms controller and Node
PID absence, owned-group ESRCH, absent private runtime/fixture root and zero keys
in the unique Redis namespace. Shared Redis is not flushed or restarted.
All 677 source/protected/tool checks pass; both dependency inventories are
unchanged and OOM counters do not increase. Minimum free bytes are 2,337,828,864
on tmp and 2,463,309,824 on workspace; minimum available-memory estimate is
6,726,351,664 bytes. Gate result SHA256:
`2ec2ee45dc3381b16f4cdb5cd2e2fb5e8240ce5dc73119038cca30a93864a2be`;
independent root observation:
`cf164913bb1c5ae4a98a0f6c1e48ff6e2706681a639e1142e1e6f1619b3c5af2`.

This is local C244 acceptance for f12. It does not retrospectively attribute the
exact PR278 failure, convert any earlier failed attempt to a pass, establish all
filesystem task joins or replace full candidate/platform/hosted checks. The
publication worktree preserves these runtime bytes and adds only this report,
tracker/readiness updates and the release workflow change below. No live
service is deployed and the production goal remains active.

## C255: include Rust library changes in optimized archive checks

Source review finds that the release workflow's pull-request path filter covered
client and relay `src/main.rs`, authority and deadman, but omitted other Rust
libraries, crate manifests, vendored code and the compiler pin. All four C254
changed paths missed the old filter. Main's existing post-successful-CI release
trigger is separate and was not broken by this omission.

The publication-only workflow correction replaces those four crate-specific
filters with `crates/**` and adds `vendor/**` and `rust-toolchain.toml`. All other
paths remain. The complete suffix from `permissions:` onward is byte-identical:
five build/verification targets, concurrency, same-repository PR guards and
workflow-run-only attestation/publication conditions are unchanged. Updating the
toolchain file now triggers verification; this does not automatically rewrite
the workflow's pinned compiler-install commands.

Twelve static old/new path witnesses pass, including the four previously omitted
C254 paths and an unrelated readiness-document non-trigger. The existing packaging
check passes agreement among four advertised targets, the additional CI-only ARM
Linux target, packager and public download metadata. This is static configuration
evidence, not a claim that hosted matrix jobs have run. Witness SHA256:
`cbb998bf313ee9870a75c42ba5d35b7f84d253c7f5f1beb304056e1cc21a33ae`.
Workflow SHA256 changes from
`ebfc23908a30c342f813c24c64cda153a4acdfc443878d05c7e9ca6c7ce19257` to
`8feaa133c4d1c078c1fa51ff5d43b1600526123d3f473f599db6d944c4ae4939`.
Five-platform optimized build/archive verification remains pending for the final
publication candidate. PR artifacts are not published release assets.

The first publication documentation guard fails because a blank line before the
new completion-history rows left them outside a Markdown table. A header and
separator are added without changing any historical row. The failed guard log
is retained separately; this formatting correction changes no acceptance scope.
