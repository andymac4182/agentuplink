# M6-C235: isolated C131 diagnostic capture

This is temporary evidence instrumentation based on `fd03cdee`, guarded by the non-default `c131-diagnostic` feature in `tunnel-relay` and `tunnel-test-harness`. It is not a production fix or a C131 completion. M6-C232 remains unchanged. The source patch may be retained as an evidence artifact without merging the temporary tap into runtime.

## Scope and activation

Build the harness with `cargo build -p tunnel-test-harness --bin tunnel-test-harness --features c131-diagnostic --locked --offline`. Set `TUNNEL_TEST_C131_TRACE_PATH` to a new file only for `verify-m7-trust-expiry`. The executable reserves the output with create-only semantics and mode 0600 before starting the gate; an existing path or symlink is refused. Without the feature the tap does not exist; without the explicit output environment variable no collector is installed. Neither gate predicates nor public outcomes change. In particular, an expired admission's `Ok(None)` still returns `Ok(None)`.

The gate result and capture quality are separate: `gate_passed` records the original gate result, while `capture.valid` reports only bounded collector completeness before stop. Exit 2 means setup, output or capture validity failed; it must never be counted as a gate pass or silently retried. Gate failure remains in the ordinary log and the artifact. Source and plan were reviewed before the separately gated smokes and fixed series; see [retained evidence](m7-c131-diagnostic-evidence-2026-10-31.md).

## Bounded passive mechanism

One process-wide `std::time::Instant` origin starts before the fixture creates its relays. These three fixture relays run in the same process; this does not make clocks from separate deployed relay processes comparable. Every timestamp and deadline uses nanoseconds relative to that one origin, including negative offsets if necessary. No wall-clock conversion is used for ordering.

A synchronous queue accepts at most 8,192 events with `try_send`; there is no event consumer, file write, network call, await, sleep, or extra membership snapshot poll during the gate. Each event has fixed scalar fields and bounded identifiers (maximum 256 bytes each). No payloads, consumer tokens, raw transport messages or private key material enter the capture. Queue overflow or a rejected identifier invalidates evidence. Stop disables emission before draining; an in-flight writer, an empty capture or an inconsistent second gate target also makes the artifact invalid. Tests exercise overflow, an in-flight stop, disabled emission and signed origin offsets.

**Collector validity is necessary, not sufficient.** It does not prove that every target phase occurred before capture stopped or that no background task could attempt a later disabled emission. Analysis must identify the exact affected request/admission, require its necessary raw observation, terminal classification and cancellation/deadline events, and refuse an incomplete or ambiguous path. Do not infer a missing event from later teardown or another request sharing the edge. Queue insertion order is not a cross-thread happens-before proof: compare the recorded action intervals and treat overlapping intervals as unresolved.

## Phases and field meaning

Each actual admission gets a process-local numeric `edge`, retained across clones and successful rebinds. Each request receives its own clone of the cancellation context with the existing bounded `request_id`; pooled requests sharing an edge remain distinguishable. `admission_created` carries local node, authenticated peer node and boot, and the exact monotonic deadline. `request_admission` binds that edge to the request. Final diagnostic events with edge 0 join through the exact request ID and role, never by recency alone.

| Phase | Evidence and limits |
|---|---|
| `gate_target` | One-time identity copied from the sole terminal event selected by the unchanged gate's existing owner/session/stream/operation filter, including its request ID and owner-identity predicate. The gate performs no extra snapshot or poll. Repeated identical samples emit nothing; any inconsistent second target invalidates the capture. Analysis starts from this target rather than choosing a convenient expired event. |
| `deadline_expired_sample` | Exact result of the existing `AdmissionDeadline::is_expired` comparison, with `deadline_ns`, `sampled_now_ns` and `deadline_expired`. A diagnostic-only thread-local scope supplies the synchronous revalidation's edge. The method's one comparison is factored into locals identically in both arms; its call stays at the fixed arm's cached assignment or the control arm's original `RebindCheck` field. No second expiry comparison is introduced. |
| `revalidate` | Bounds around the existing rebind decision and its `permitted` result in `decision`; this is distinct from the exact expiry sample. |
| `admission_rebound` | Old/new deadlines and bounds around the existing deadline updates, including the shared deadline used by streams. |
| `reason_cas` | Bounds immediately around the original compare-exchange, attempted reason, actual retained reason and CAS success. Successful CAS means previous value 0; failed CAS reports the actual previous reason returned by the atomic operation. No later read substitutes for that result. |
| `token_cancel` | Bounds around the original token cancellation. Both CAS/cancel records are emitted after cancellation, rather than adding queue operations between these actions. |
| `trust_expired_decision` | The exact cached reason and its read bounds. Only the original unclassified-reason branch consults a deadline/current time; those exact values appear as `deadline_ns`/`sampled_now_ns`. Typed reasons leave those fields absent. `decision` is the unchanged returned boolean. |
| `ingress_receive_raw` | EOF, H3/QUIC error, transport cancellation, timeout, other bounded transport error, or the selected local cancellation path. `at_ns` is raw observation time. Extra passive reason/deadline reads have their own `before_ns`/`after_ns` interval and do not establish what the earlier classifier saw. For a received transport result those reads and emission occur after the original attribution result is cached. They cannot rewrite it. |
| `owner_outer_cancel` | The existing outer admission-cancellation branch won. Destruction may also occur without this branch, so absence is not evidence of a normal finish. |
| `owner_handler_ready`, `owner_handler_drop_before/after` | A safe wrapper preserves `Poll` output and brackets destruction of the owned future in declared field-drop order. Tests cover pending, never-polled and completed futures, including a `!Unpin` inner future. These are destructor bounds, not observed wire RESET/FIN. An async future can drop resources while becoming ready. |
| `owner_loop_result` | The owner loop returned `ok`/`error`; this alone says nothing about FIN. |
| `owner_finish_started/completed` | Bounds around the existing `send.finish().await`, with a closed completion category. A start without completion can be interrupted by outer cancellation. Local successful finish is not proof that the peer received FIN. |
| `owner_explicit_cancel` | Bounds around the existing owner send/receive cancel calls. It does not prove when the peer received a reset. |
| `ingress_receive`, `ingress_send`, `owner_receive`, `owner_send` | Existing final consumer diagnostic classification, with exact request ID and bounded outcome. |
| `owner_terminal_event` | The owner's first terminal event after the existing duplicate guard, before bounded retention; joins by exact request ID and local node. |

Reason codes are the existing private enum encoding: 1 trust expired, 2 membership revoked, 3 membership changed, 4 authority unknown, 5 persistence unavailable, 6 runtime cancelled. An absent reason remains unclassified; it is not evidence of expiry.

## Remaining instrumentation limits

On EOF there is intentionally no `trust_expired_decision`: the existing code passes EOF through. Its later passive reason/deadline sample must not be treated as a policy read at `ingress_receive_raw.at_ns`. Reconstruct the state at that earlier observation from the admission creation, rebind and CAS action bounds; overlapping or missing transitions remain inconclusive.

No pin-watcher connection-close tap or actual QUIC packet/reset/FIN acknowledgement is captured. A cancelled owner's future can drop a Quinn send stream, whose destructor attempts finish and may reset if already stopped; an existing connection error can instead make it a no-op. The capture must distinguish these possibilities rather than label every owner drop as RESET.

The additional timestamp reads, bounded queue operations, diagnostic-only deadline reads, request-ID allocations and pinned owner-future wrapper can affect scheduling. Both comparison arms must contain identical instrumentation and build settings; their only runtime difference is the pre-existing nine-line M6-C232 fix. The earlier uninstrumented comparison (fixed 20/20, control 18/20) remains separate evidence. A captured path may establish a particular ordering, but it does not explain all historical failures by itself.

## Validation and review boundary

Source-only implementation, including the exact gate-target join, passes targeted feature-enabled strict all-target Clippy and all nine collector/lifetime/target tests. Default targeted strict all-target Clippy also passed before the feature-only gate-target addition. All 18 membership re-sign regressions and the original classification test extended to preserve EOF passed with instrumentation enabled. These are focused checks, not a new full-workspace acceptance claim. Matched binaries were frozen and fixed source restored. Two complete quality smokes and all 20 alternating pairs completed: control 19/20, fixed 20/20, all collectors valid, 37 complete analyses and three inconclusive intervals. The [evidence report](m7-c131-diagnostic-evidence-2026-10-31.md) preserves the EOF failure, every result, frozen hashes and limits. M7-C131 remains open pending production correction and fresh acceptance; no full-workspace claim is added for temporary instrumentation.
