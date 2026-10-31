# Real-endpoint fid confirmation acceptance (M6-C244)

Status: PR #275 failed the final terminal witness after earlier focused and
PR #274 hosted passes. A fixture observer correction is prepared but unverified;
the first failure and earlier evidence remain retained below. M6-C244 stays
open. M4-21's broader deadline and descriptor acceptance remains open.

The command is `tunnel-test-harness verify-m6-ts-fid-ordering`, registered in
`scripts/m4-harness-verify.sh`. It uses the existing three-relay, disposable-Redis
filesystem fixture, an actual device connector with synthetic host files, and
the shared TypeScript client's exported discovery, verified-TLS upgrade,
`ConsumerSession`, and `RemoteFilesystem` implementation. Its owner-local route
does not claim filesystem forwarding through a non-owner.

The driver holds a real `Rwalk` or `Rclunk` received from the endpoint and
every subsequent reply in arrival order. It never fabricates a reply, changes
provider state, or allows `Rflush` to overtake an earlier original reply. The
hold is limited to 16 messages/64 KiB, all event collections to 128 entries,
and protocol output to 16 KiB per line. Node observations are bounded at 10 seconds and Rust driver/stream waits at
15 seconds; existing startup, owner, completed-exchange and cleanup helper
bounds remain unchanged. The scenario is bounded at 90 seconds. The
public operation's explicit two-second deadline is an ordinary supported
caller option. Descriptor quotas, single-request deadlines, and the device's
300/10/30 rotation policy remain unchanged.

| Case | Actual device witness | Required client ownership witness |
| --- | --- | --- |
| First walk reply unobserved at the operation deadline | Received `Rwalk`, followed by a real `Tgetattr` probe of that exact fid returning the independently seeded host-file size while all replies remain held | The deadline returns `DEADLINE_EXCEEDED`; the fid remains charged, no early `Tclunk` is sent, and a concurrent directory operation uses another fid. After ordered settlement and real `Rclunk`, the original numeric fid is reused successfully. |
| Applied clunk reply unobserved when cleanup stops waiting | Received `Rclunk`, followed by a real probe of the same fid returning `Rlerror(EINVAL)`, independently proving that the device has released it | The known stat result remains successful, but its fid stays charged until the client receives the held `Rclunk`. A concurrent directory operation uses a different fid; confirmed cleanup permits exact numeric reuse. |
| Definite refusal and pre-dispatch abort | Real missing-path refusal, followed by a successful host-backed stat | Definite refusal releases the number without an unnecessary clunk; the next walk reuses it. An already-aborted operation sends no request. |

Both held cases exercise a real `Tflush`/`Rflush`: walk expiry issues its normal
flush, and the clunk case explicitly cancels the still-unconfirmed cleanup
request. Original replies remain first in the ordered hold and are delivered
before their flush replies. **The clunk case proves an applied clunk with an
unobserved response. It does not prove a clunk flushed before dispatch.** No
existing provider scheduling hook established that second schedule, so the
gate does not invent one or claim it from the first.

At each hold, Rust independently checks the real connector stream and its
unchanged control session/epoch and Redis owner before releasing Node. A
directory iterator keeps the parallel fid live across the fault, making the
later exact reuse of the original number unambiguous. Wire tag/fid identifiers
and monotonic event ordinals establish receive, delivery, cancellation and
cleanup ordering. The caller settlement ordinal is captured by its own promise
observer, so a delayed provider probe cannot fabricate an earlier ordering. After all three consumer sessions close, the device must
record exactly three completed exchanges, no mutation dispatch and no written
bytes. Host files and directory membership must remain unchanged; the device
session must remain active without rotation or recovery.

The Node child remains owned outside the timed scenario. Driver, connector,
relay and catalog cleanup are bounded and attempted even after an earlier
failure. The connector handle survives a timed-out first stop through relay
and catalog teardown, followed by one bounded final join; the first timeout
remains a failure. A forced or unsuccessful cleanup cannot make a run pass. Reports
contain closed labels, identifiers, counters and host-comparison results;
tokens live only in the private fixture plan and no file contents are logged.

## Verification and remaining integration

Preserve source hashes, exact Node/dependency identity, immutable Rust
executables and all first failures. The existing full M4/Node result on the
previous candidate remains evidence for that earlier scope; it does not
include this new gate. The following declared sequence was run locally:

1. Compile the new Rust gate and type-check the new driver under the pinned
   toolchain after the coordinator grants an exclusive lease. Run its focused
   evidence controls, including seeded missing provider, ordering, resource,
   same-session, host and cleanup witnesses.
2. Run the real gate once with current client behavior and retain the exact
   wire/host/device evidence.
3. In an isolated test-source copy only, restore the original premature
   first-walk release behavior. Run the identical real fixture and require
   rejection at early fid reuse/resource ownership, with an actual already
   bound device fid. Restore exact source bytes regardless of outcome.
4. Separately restore only the original premature clunk release after the
   caller stops waiting. Require the same fixture to reject unconfirmed
   numeric reuse; preserve the actual applied-clunk probe. Restore exact bytes.
5. Re-run the fixed focused gate after both restorations. Record required
   integration checks separately; do not substitute a retry or a mock-peer
   success for this actual endpoint proof.

No production implementation, automatic mutation replay, whole-session close,
fid quota, or runtime deadline is changed by the acceptance fixture.

### Recorded local evidence (2026-10-31T18:48:24+10:00)

The five focused Rust evidence controls, strict harness Clippy, workspace
format check, Node 24.21.0 direct strict typecheck and client lint passed.
The final actual harness build ran after Clippy; compiler JSON identified
its package, binary target, source and profile before an independent mode-0555
copy was made outside Cargo. Its SHA-256 is
`0a93a9e8b8cbb7482431b66f062f2078f49b8a8b7547d6b2bf091fa7898d4190`.
The frozen Node SHA-256, all 16,798 dependency file/symlink identities and
modes, and 1,078 tracked source hashes were bound before the live gate.
No dependency installation or production runtime change was made.

| Run | Result | Attribution |
| --- | --- | --- |
| Original fixed source | Passed, 9.005 s | Both real provider probes; original fid 1, parallel fid 2, then confirmed reuse of fid 1. Three completed exchanges, unchanged host and device session, zero mutations/writes, joined cleanup. |
| Original premature-walk release only | Expected failure, 4.002 s | Real provider still reports size 97 for fid 1, while the client reserves zero fids after the deadline and reuses 1 for the parallel walk. |
| First clunk control overlay | Invalid control failure, 15.511 s; excluded | The overlay accidentally released confirmed fids twice and failed in the preceding walk case. Its patch and first failure remain retained; this does not count as clunk evidence. |
| Corrected original single premature-clunk release | Expected failure, 7.504 s | Real provider returns EINVAL for the applied clunk, but the client reserves zero fids and reuses 1 before observing the held response. |
| Exact restored fixed source | Passed, 8.507 s | Same immutable harness/driver/timing/assertions; both probes, parallel operation, confirmed numeric reuse and cleanup pass again. |

Each negative is the clean commit plus its separately hashed runtime overlay,
not a pristine-commit run. Every overlay restored the exact original file
SHA-256 `853da5b434935207236af38c28cc75dc588300554fa65c0f9244bde8d7a56edd`
in cleanup before the next variant. All five live attempts left zero keys
in their unique namespace and no remaining owned process group. The negative
runs also retain the driver's exit-handshake error after the rejecting Rust
rendezvous; those errors never converted a failure into a pass.

Two pre-execution review corrections are source findings, not failed live
attempts: keeping the device supervisor handle through outer teardown, and
capturing caller settlement in its own promise observer. Two private evidence
command errors are also retained: an initial dependency checker omitted the
manifest's mode field, and a namespace baseline command lacked redis-cli.
The corrected exact metadata check and bounded read-only RESP cleanup scans
passed; the unavailable baseline's shell count is not accepted as evidence.

Exact commands, compiler JSON, source/tool/dependency receipts, patches, first
logs, both complete positive reports and cleanup checks are retained under
`agentuplink-review-artifacts/c244`. The verification summary SHA-256 is
`ab467bccf48b6894744c616b74a6409cd36458e32c50e7c80e49ae4448ebf841`.
Required aggregate/hosted checks on the integrated source remain separate;
these focused results do not claim a full M4 rerun, clunk flushed before
dispatch, or completion of M4-21.

### Integrated local checks

At integrated source `86fb4d70`, formatting, strict workspace/all-target Clippy
and locked workspace tests pass (2,931passed, zero failed,108ignored). No
production filesystem behavior changed. The real-endpoint results above remain
bound to their original8804 source and immutable executable; the integrated
checks do not pretend to rerun that gate. See the [combined receipt and scope](m6-final-candidate-2026-10-31.md#integrated-test-follow-up).
New-head hosted full M4 acceptance remains pending, so C244 stays open.

### Hosted follow-up failure and terminal observation correction

PR #275 head `b13f43cd` / actual merge `5909dc38` (identical tree `2bf1832d`)
failed M4 job `124515625939` at C244's final grouped predicate, after the
300-second framework gate passed. The complete first log is retained with
SHA-256 `9187f86018b42c111b24bbec73453e15a042c942f76a9cbcb7876a2b71ab97c5`.
The earlier PR #274 full M4 pass remains historical evidence. No unchanged
retry is treated as a fix. The failure's exact scalar cannot be recovered:
its generic error discarded the completed count, session, host and retirement
values. Case/refusal validation and cleanup had already completed before that
final rejection, but that does not establish which grouped scalar failed.

Source inspection identifies a reachable fixture race. The connector folds
filesystem completion and publishes its ledger in `HttpActorRequest::Done`
(`m2_http.rs`); stream removal requires a separate validated `STREAM_FORGET`
and carrier barriers (`m2_runtime.rs`). A completed handler is therefore not
proof that its transport state has already retired. C244 previously awaited
only the completed-exchange count and immediately demanded zero retained
streams/replay from a separate snapshot. The relevant production lifecycle
and this fixture path are unchanged from the prior passing source. This is
a source-derived timing defect in the observer, not proof that the lost
hosted scalar was a retained stream or that the product regressed.

An isolated fixture-only correction is prepared, **not yet compiled or run**.
One watch observation now requires the exact count and every original final
session/retirement predicate together, under the same existing 30-second
ledger deadline and outer 90-second scenario bound. Only incomplete exchange
count or pending streams/replay can wait. Extra exchanges, mutation/write,
wrong phase/session/epoch, rotation and recovery reject as soon as observed;
no retry, grace period, application request or deadline reset is added.
Every rejection preserves the scalar snapshot; final host/cleanup errors
preserve all original grouped values. At most one pending-retirement line
records whether the new run actually observed handler completion before
transport retirement. A watch channel coalesces snapshots: this does not
claim exhaustive observation of every transient state.

The declared next narrow regression uses a deterministic status sequence:
three completed handlers with a retained stream and replay, final ACK, then
stream retirement. Restoring only the old count-only return condition must
fail its first pending assertion. The corrected observer must pass that
sequence, while wrong mutation/session/epoch/phase/rotation/recovery, extra
exchange, persistent replay/stream, missing completion, closed observation
and the unchanged absolute deadline remain failures. These are observer-unit
inputs, not synthetic replacements for the actual relay/device gate. An
independent review and coordinator resource lease precede compilation and
any focused real endpoint run. C244 remains open pending the correction's
proof and integrated hosted acceptance; M4-21 remains open.

### Verified observer correction at decc5b58

At 2026-10-31T21:54:50+10:00, clean source
`decc5b58dd4c91a417a61e09e47e3e35e4d30b38` passes the old-count negative,
exact-restored eleven controls, formatting, strict workspace/all-target Clippy,
and locked workspace tests:2938 passed,0 failed,108 ignored,174 summaries.
The final compiler-selected harness SHA256 is
`f510526b88cf1b5f18128a626537aee3736dab71d5de3f1a31f521db28013fc2`.

The first actual gate passes13.0765s. One pending snapshot directly reports
3 exchanges/1 stream/1 replay; the same session subsequently reaches3/0/0
with every original terminal predicate intact. Walk/clunk provider probes,
parallel fid2, confirmed fid1 reuse, refusal/pre-abort controls, unchanged host
and joined cleanup pass. The owned group is absent and namespace scans are0.
All source, Node24.21,16798 dependency entries and protected binary inputs
remain unchanged; no retry or deadline extension. The historical PR275 scalar
remains unknown, and flushed-before-dispatch clunk/broader M4-21 remain outside
this fixture's claim.

[Exact current evidence](m6-production-followup-2026-10-31.md#verified-observer-correction-at-decc5b58)
retains commands, timings including compilation, independent output identities,
controller-review corrections, the prelaunch lease-path error and resource/cache
provenance. Final receipt SHA256
`82559eefdf13ef34b3def2abacb7bad39a61f9554451b7734ce7e12b64893a44`.
Hosted integration of this correction remains pending; PR275 CI stays failed.
