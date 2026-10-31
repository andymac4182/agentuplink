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
