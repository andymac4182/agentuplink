# Connector input quota boundary evidence

M6-C240 began as a source-derived suspicion that pending-input pressure could
produce authorization reset 4001. Review found an earlier aggregate guard that
rejects valid accounted input as `ClientError::QueueLimit` before that fallback.
The hypothesis remains unproven. This slice adds tests only, based on exact
`8c8c14fc9f6bb164daad224ad7300c04389a296f`; current runtime is expected to pass.
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

Source formatting and `git diff --check` can run without a build lease. The
coordinator must release an assigned target before Cargo or any live tests:

```sh
cargo test --locked -p tunnel-client --lib c240_ -- --test-threads=1
cargo clippy --locked -p tunnel-client --lib --tests -- -D warnings
```

The parent full frozen candidate at8c remains independently scoped. Compilation,
execution and any closure claim for these new tests are pending; no red result
or complete production readiness is claimed.
