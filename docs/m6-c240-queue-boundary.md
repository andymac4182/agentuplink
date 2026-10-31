# Connector input quota boundary evidence

M6-C240 began as a source-derived suspicion that pending-input pressure could
produce authorization reset 4001. Review found an earlier aggregate guard that
rejects valid accounted input as `ClientError::QueueLimit` before that fallback.
The hypothesis remains unproven. This slice adds tests only, based on exact
`8c8c14fc9f6bb164daad224ad7300c04389a296f`; the first run passed as expected.
No runtime policy, fallback classification, wire code, quota or replay rule is
changed. No intentionally inconsistent counters or guard bypass is used to
manufacture a failing baseline.

The tests live in
`crates/tunnel-client/src/m2_runtime/tests/c240_queue_boundary.rs`, included only
by the existing `#[cfg(test)]` module. The fixture validates the minimum allowed
256 KiB queue configuration before any traffic and gives the empty carrier
budget that same ceiling. Its actual reserved critical capacity is 64 KiB,
leaving 192 KiB for bulk. Authorization has a live five-second challenge and a
separate live operation deadline. All pending and sequence byte counts begin
at zero. A normal sender `StreamState` validates every generated DATA frame's
sequence, receive credit and replay limits before encoding it.

| Case | Required observation |
| --- | --- |
| Contiguous DATA, normal and frozen writes | Three valid 64 KiB echo-record payloads reach the real bulk ceiling through `handle_carrier_message`. One additional byte returns `QueueLimit` through the event/carrier/frame chain. Pending bytes and payloads, sequence/credit snapshots, ready frames, authorization identity/flags/deadlines, feedback, record parsing and terminal state remain unchanged. No reset4001 or application output appears. |
| Gap and zero-payload closure | Sender-generated frames2–4 fill actual reorder bytes before frame1 arrives. Additional DATA is rejected without mutation. The legitimate empty frame1 then moves the accounted records through ready into pending, with unchanged total192KiB, exact payload order, no rejected sequence5 and no invalidation. |
| Accepted input | A small real record remains buffered with no output until matching `AuthorizationConfirmed`; then exactly one DATA response carries the expected record and sequence. |
| Explicit invalidation, normal and frozen writes | Real accepted input is cleared by `AuthorizationInvalidated`, which emits exactly one4001RESET. While writes are frozen that terminal stays queued and consumes no outbound sequence until unfreeze. No buffered DATA is replayed. After writer drain only the two-byte RESET reason remains as bounded transport replay; later DATA is acknowledged without retaining or dispatching it. |

Every no-output assertion requires `TryRecvError::Empty`; a disconnected
carrier or control channel cannot satisfy it. The rejection snapshot captures
pending payload bytes, ready frames and the sequence fields it names. Its
`DirectionSnapshot` contains reorder frame/byte counts, not private reorder
payload bytes; the gap case independently checks those payloads in exact order
after legitimate closure.

These are handler/event-level regressions with real protocol encoding and
sequence accounting, using bounded channels rather than sockets. The freeze
control exercises the writer latch; it is not another complete rotation proof.
They do not independently measure full session teardown, relay WebSocket close
1008, consumer execution certainty, or full three-relay deployment behavior.
The existing actor loop propagates a carrier error to session shutdown; the
existing `QueueLimit` public code is `RESOURCE_EXHAUSTED` and is not automatically
retryable. Pending work must remain `not_dispatched`, work already dispatched
must retain `unknown` when its outcome is unavailable, and no ambiguous effect
may be automatically replayed. This test-only slice does not change or broaden
those contracts.

Under the exclusive coordinator lease, the first focused run at clean
`7b1ab7ee259c042c99c85aee1f35284c862a2ced` passed all four tests: zero failures,
zero ignored and 248 filtered out. The contiguous-quota and explicit-invalidation
tests each exercise normal and frozen writes, giving six scenario executions.
Test execution took 0.07 seconds; compile plus wrapper took 19.294 seconds.
Scoped strict Clippy passed in 24.549 seconds and formatting in 4.967 seconds.
No failing baseline was manufactured; this is valid-state evidence against the
original source-derived hypothesis, not a repaired runtime defect.

The exact commands were:

```sh
cargo test --locked -p tunnel-client --lib c240_ --message-format=json -- --test-threads=1 --nocapture
cargo clippy --locked -p tunnel-client --lib --tests -- -D warnings
cargo fmt --all -- --check
```

Each used Rust 1.95.0 through `python3 /tmp/agentuplink-subreaper.py`, with
`CARGO_TARGET_DIR=/workspace/agentuplink/target`, `CARGO_BUILD_JOBS=2`,
`CARGO_PROFILE_DEV_DEBUG=0`, `CARGO_PROFILE_TEST_DEBUG=0` and
`CARGO_INCREMENTAL=0`. No extra workspace build, broad test, Docker, Redis or
Node command ran. The target lease was released after preserving the exact
test artifact; subsequent evidence edits do not change the validated Rust.

Local evidence is retained outside the repository in
`/workspace/agentuplink-review-artifacts/c240-boundary-proof-7b1ab7ee`.
`inputs.json` records the clean source, exact commands, environment and protected
relay executable. `validation-result.json` records all command receipts and log
hashes. Cargo JSON identified `tunnel_client-b800502f004801af`; its SHA-256 was
identical before Clippy, after Clippy and after the create-only copy to
`binaries/tunnel-client-unit-tests`:
`90b3921372ef816b003e311a322eb4273d52524951fe52e12e6a86bb23e9f0ce`.
The protected C94 relay test executable also remained unchanged.

| Validated input | SHA-256 |
| --- | --- |
| `crates/tunnel-client/src/m2_runtime.rs` | `af1e5044565239e0a9222d744ea67005a8ebd3a2f6313d182d7f777e5a883271` |
| `crates/tunnel-client/src/m2_runtime/tests/c240_queue_boundary.rs` | `cd80088048f1b4fdb8056ff3eba1852972ea7cdf53f975a4927adb41854140a5` |
| `Cargo.lock` | `e255f401d45e150b41b86cb69094366fcc9b0ffc4f420caabc52fb02630e0399` |
| `rust-toolchain.toml` | `97aab3493c1fb14fe9a21c760433577f434714f5725bbb176e67048dde581afe` |

The parent full frozen candidate at8c remains independently scoped. This closes
the missing handler-level valid-state proof; it does not independently establish
the wider actor/public-close or complete production-readiness claims described
above. The misleading later fallback is unchanged and has not been reached by
valid accounted input.


## Actor-loop preparation observation before execution

A separate source-only continuation from exact `bd93cfbd828a2d23415e5e406120f9a70e9e92c0`
adds six `c240_actor_` tests in
`crates/tunnel-client/src/m2_runtime/tests/c240_actor_loop.rs`. The earlier
handler proof and its recorded run are unchanged. At this preparation
observation the new tests were **not compiled or executed yet**. Pinned-toolchain formatting of the two changed
Rust files and diff whitespace checks are source checks only.

The new fixture starts `run_m2_session` empty with a validated256KiB queue,
two stream slots and negotiated128KiB credit. Encoded OPEN and actual
OPENED/AUTHORIZATION_CHALLENGE exchanges admit each stream. A peer
`StreamState` assigns all DATA sequences, validates credit/replay, and consumes
real ACK/window updates. Three64KiB record payloads fill the192KiB aggregate;
one further legal byte crosses it. No stream, retained-byte counter,
authorization flag or writer-freeze latch is injected.

| Prepared case | Required oracle, not yet a result |
| --- | --- |
| Normal and real-frozen quota | Natural QueueLimit/RESOURCE_EXHAUSTED/nonretryable before fixture cancellation; exact live wall/monotonic authorization and operation deadlines, stable synthetic grant identity and unchanged rejected-frame sequence/pending state; no DATA/FIN/RESET4001/4006 or recovery/replay request. |
| Omitted crossing | Actual192KiB stays live; the quota predicate rejects the control. No timer sleep or EOF substitutes for an empty live path. |
| Matching confirmation | One previously buffered record executes once and produces exactly one sequence1 DATA, including the final joined-peer transcript. |
| Matching invalidation, normal and frozen | Exactly one RESET4001, no application dispatch, live actor and no QueueLimit. A frozen terminal retains its place without consuming sequence or changing either fence until bilateral abort/closure; after drain only its unacknowledged two-byte replay reason may remain. |

The frozen cases use the actual candidate dial: generated, pinned synthetic
credentials, a device-role URI SAN, mandatory mTLS, the exact fixture ticket
and data subprotocol, and a real third WebSocket. PREPARE/DATA_READY/QUIESCE and
both immutable sequence fences precede delivery of frames already assigned
before quiesce. The invalidation control closes and joins that candidate peer
before sending the owner's final ROTATE_ABORTED. It does not set
`writes_frozen` or use the old state-seeding helper. Initial control/active
sockets use the existing loopback WebSocket pair helper; the synthetic owner
is not an authoritative production catalog or public admission proof.

Passive, task-local `#[cfg(test)]` observations capture rejection state,
application dispatch counts, lifecycle publications and actual task-join
results. The tests retain a Weak reference to the queue budget created by the
real session, require its owners to be gone after the actor/peer joins, and
require the returned actor future to have released its owned stream state.
This is ownership evidence, not RSS measurement; the copied Closed status's
queue_bytes is deliberately not treated as post-drop accounting. No HTTP
exchange-task cleanup is inferred from an echo fixture.

Setup, the live-window scenario and cleanup are independently bounded. A
scenario timeout is a failure, not quota evidence. Product five-second
authorization/write/close bounds are unchanged; acceptance also rejects
cleanup reaching a product close timeout, carrier-task panic or forced-join
fallback. Test-owned timed-out tasks are aborted and joined, and later cleanup
still runs after earlier failure. No fixture cancellation precedes collection
of the natural quota result. No successful execution result is claimed until
the separately coordinated compiler/artifact/resource plan runs.

C240 remains open. Actor scope A cannot establish the relay/public close code,
a filesystem consumer's `unknown`/`not_started`, a pending unary call's
`not_dispatched`, or reconnect policy. Those require the separately planned
public endpoint scope B. The original quota-to-authorization hypothesis is
still unproven; this expected-green acceptance slice changes no runtime policy,
quota, reset mapping, grant semantics or automatic replay behavior. M4-47
response-budget work is explicitly excluded.


Source-only review correction (2026-10-31T23:43:55+10:00): draft v2 encloses the
control-writer await result and passive join observation in a local block.
This preserves destruction of the non-Copy result before Closed publication,
as in the original runtime. Draft v1's private patch and receipt are retained.
The six tests and their assertions are unchanged and remain uncompiled and
unexecuted. Formatting/whitespace checks do not close actor scope A, public
scope B or C240; no cache or frozen artifact is moved by this correction.


## First real actor-loop run and retained validation failure

At clean implementation `bf21e353ede811088cf31b64f8b9076d28378f11`, tree
`2b3aa8f155d65c4ac07b327e835fbf440216de78`, the first actual compile and
focused run passed all six new actor cases and all four unchanged handler
controls: **10 passed, 0 failed, 0 ignored, 248 filtered out**, in 2.78 seconds
(3.010 seconds including the command wrapper). The compiler ran once in
55.618 seconds; listing the selected executable established 258 tests and
zero benchmarks before execution. This is the expected-green valid-state
proof described above, not a reproduced or repaired quota-to-revocation bug.

Rust1.95 Cargo JSON selected the default-feature client library test executable,
which was copied independently as a regular0555/single-link file outside the
mutable target. Its45,942,416 bytes have SHA-256
`da37b1f8b9ac24e3c6d0b371734904ed788973c39c1b4f1e4449676ecaa81e14`.
The actual compiler output and frozen copy remained byte-identical after the
attempt. Exact commands were:

```sh
cargo test --locked --offline -p tunnel-client --lib --no-run --message-format=json
# The independent copy of the one Cargo-selected executable:
tunnel-client-c240-tests --list
tunnel-client-c240-tests c240_ --test-threads=1 --nocapture
```

The first overall validation attempt is **failed**, not passed: immediately
before Clippy, free tmp capacity was2,009,088,000 bytes, above the unchanged
1.5GiB active floor but138,395,648 bytes below the2,147,483,648-byte startup
requirement. Neither Clippy nor formatting launched in that attempt; no retry
or source edit followed. Required full workspace Clippy/tests and hosted
acceptance remain pending for the publication candidate. Passing ten tests
cannot replace those checks.

The controlled cache-preservation step before compilation retained all25 exact
inactive integration outputs, round-tripped17 new archive members and reverified
8 existing independent copies before removing the mutable outputs. It reclaimed
672,796,672 bytes. This is local derived-cache maintenance, not a production
backup drill. All frozen/protected inputs, fingerprints and both dependency
trees remained unchanged; no Docker or Redis action occurred.

The failed test-controller result is
`084d6bd4c0b243f742ecc27fdb019a533b9c5c1aec1b23d99b9b126071cb1b6f`;
its final handoff is
`4a1cd84e67f28d6c93003df17fb08471874e39f42abd3a92b35b6b1af8eb85f1`.
All88 source/protected/tool checks passed, including the entire1093-file tracked
source. All three started command groups and the controller were independently
absent; the OOM counters did not increase. Earlier controller review findings
and the failed archive-control source-order assertion are retained separately;
none is relabelled product acceptance.

A separately authorized, read-only `cargo fmt --all -- --check` then passed in
5.015 seconds (7.262 seconds total controller), without recompilation or fixture
execution. All92 source/protected/tool checks passed, including both selected
executable copies and the first failed result; the command group and controller
were independently absent. Format result SHA-256:
`9d72aff487170e6e133261b334d915e2943cf9f155e9008c7a70851357efd3b9`.
This separate pass does not change the original failed attempt.

These observations establish actor scope A at the named implementation only.
Public endpoint scope B, actual filesystem consumer `unknown`/`not_started`,
unary `not_dispatched`, the full C240 row and production readiness remain open.
No claim about current-image recovery, live deployment, license approval or
M4-47 follows from this run. Publication documentation changes are separate
from the frozen tested implementation; hosted verification must name its own
final candidate and actual checkout.
