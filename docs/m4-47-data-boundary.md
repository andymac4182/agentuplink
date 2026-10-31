# Legitimate response DATA at the relay budget boundary

This tests-only M4-47 slice starts from exact
`107d94a2e331f850bcc70a2b9406bc79ccfa1cbf`. The existing contract chooses a
per-stream overload for DATA within advertised credit; malformed or over-credit
frames must still fence the session. Source review identifies a budget refusal
before sequence validation, currently reported as `INVALID_SEQUENCE`. Arithmetic
alone is not a reproduction, and no runtime correction is part of this slice.

This document preserves the separately executed local leaf at `b8d951e6`.
Its failing regression is not integrated into the Mastra follow-up candidate;
the source and executable remain in the isolated local evidence worktree.
The command below applies to that exact leaf, not an assertion that the test
file is present in the documentation follow-up. No production fix is claimed.

`crates/tunnel-relay/src/actor_data_budget_boundary_tests.rs` starts with the
ordinary admitted-control fixture, a live bounded carrier, a real in-memory
catalog owner claim and unchanged validated default relay limits. All stream
admission, authorization, request dispatch, DATA receipt, ACK and consumer-read
charges use production methods. No budget is seeded, manually filled or
released; no sequence or retained-byte counter is changed to force refusal.

The four tests require:

| Case | Observation |
| --- | --- |
| Aggregate boundary | 33 ordinary HTTP registrations each complete OPEN/OPENED, real catalog-backed challenge/CONFIRMED and a codec-valid GET request plus FIN. The connector consumes and ACKs each request; control/writer/replay charges return to zero. Thirty-one consumers leave their response windows unread, retaining exactly 31 × 131,072 = 4,063,232 encoded bytes. Every accepted frame passes the normal connector sequence/credit state and an independent copy of the actual receiver state, then enters the encoded `inbound_data` path. The next target frame is also legal but cannot fit the ordinary data budget. The session and independent sibling must survive a scoped refusal. |
| Actual consumption | At that same boundary, reading one actual 65,536-byte chunk emits WINDOW_UPDATE and frees exactly that charge, allowing the target's legal frame. A second read provides room for the independently consumed sibling to continue. |
| Credit violation | One stream fills its 131,072-byte window while ample aggregate room remains. One extra payload byte is refused by both independent sender and receiver sequence checks; delivering that invalid frame must still close `INVALID_SEQUENCE`. |
| Malformed frame | Corrupt only the magic of an otherwise encoded DATA frame. The decoder must reject it and the live session must close `INVALID_FRAME`, before retaining application bytes. |

The response bytes include a real RESPONSE_HEAD and two BODY records, encoded
by `tunnel-http-forward` and checked by its incremental reader. An unfinished
streaming response has no fabricated END. The 64-byte outer frame header is
measured separately from the inbound retained payload charge. The sibling
consumes the first response chunk before saturation through `read_http_stream`;
its second chunk can continue after real consumption makes room. Merely keeping
a channel receiver alive is not credited as sibling application progress.

The fixture asserts that session charges equal the sum of actual unread HTTP
chunks; each stream's charged bytes match its buffer, its request replay is
empty, and it has no parked request bytes. Receive cursors reach 2, bytes remain
within each advertised window, and no ready/reorder bytes remain after delivery
to the HTTP queue. Authorization must remain live at every legal send. The
actual 2-second challenge, 30-second request/owner bounds and queue limits are
not increased to make a slow-consumer setup pass.

This is actor/channel plus MemoryCatalog evidence. It does not run sockets,
Redis, a public HTTP adapter or a device-side HTTP handler. Freeze/recovery,
terminal/reset/FORGET settlement, public error mapping and dispatched `unknown`
versus pending `not_dispatched` remain required before a production correction
can close M4-47. No ambiguous operation may be automatically replayed.

Scoped reproduction:

```sh
cargo test --locked -p tunnel-relay --lib actor::data_budget_boundary_tests::m4_47_ --message-format=json -- --test-threads=1 --nocapture
```

Use pinned Rust 1.95.0, the assigned shared target, two jobs, debug information
disabled and incremental compilation disabled through the existing subreaper.
Retain the first result and exact compiler-JSON executable outside Cargo. A
failed survival assertion counts only if all valid accounting and protocol
preconditions completed; earlier guard or fixture failures must be reported
without calling them the hypothesized runtime defect.

## First observed result

The first actual execution at clean
`b8d951e66acd02d1911965c76909ed921a999f4a` reproduced the defect. All three
controls passed; only the required session-survival assertion failed:
**3 passed, 1 failed, 0 ignored, 714 filtered out**, in 1.08 seconds (41.819
seconds including compilation and the subreaper/monitor wrapper).

Immediately before the failing DATA, the fixture observed:

| Field | Observed value |
| --- | --- |
| Admitted, confirmed HTTP streams | 33 |
| Unread full response windows | 31 |
| Actual retained response bytes / data ceiling | 4,063,232 / 4,063,232 |
| Total configured session ceiling | 4,194,304 bytes |
| Next DATA payload / encoded frame | 65,536 / 65,600 bytes |
| Target sequence / ACK | 1 / 2 |
| Target prior received bytes / advertised credit | 0 / 131,072 |
| Independently consumed sibling bytes | 65,536 |
| Actual result | Session removed; `INVALID_SEQUENCE`; all 33 registrations cancelled |

The normal-read control reached that same ceiling, released actual chunks
through the consumer API, and then accepted both target and sibling DATA. The
other controls retained `INVALID_SEQUENCE` for a genuine credit violation with
ample aggregate capacity, and `INVALID_FRAME` for corrupted frame magic.
Thus the failing case reached the budget boundary through valid accounted
traffic; it was not an earlier guard failure or an inconsistent seeded state.
Each executed case completed ordinary teardown with zero remaining budget
charge. No production runtime change or corrected-result claim follows from
this reproduction. Freeze/recovery and public socket/consumer mapping remain
outside this first witness.

The first build attempt, before this execution, was deliberately stopped by a
compiler-output guard: Cargo selected the protected C94 test executable's path.
The guard refused before the relay compiler ran (guard126, Cargo101, 13.795
seconds), so that attempt ran no tests and has no product result. It is retained
separately rather than counted as a failing regression.

The accepted second configuration used the same source, codegen flags, target,
two jobs, disabled debug/incremental settings and subreaper. A transparent
`RUSTC_WORKSPACE_WRAPPER` gave the workspace unit a distinct Cargo artifact
identity. Both wrappers forward exact compiler arguments and environment; they
change no assertion or compiler option. The outer `RUSTC_WRAPPER` continued to
refuse writes to the protected C94 path. Six inert outer-wrapper and two nested
forwarding/refusal controls passed; these are configuration evidence only.
The workspace wrapper SHA-256 is
`13470f567b6998196ae0c579dad914ddbbf92515eafcb8226d9fca9ec7965912`; the guard's is
`26e65b206a9645aa0d424f62fbf4a1c80a98320ff55e4e1cee8841d7edc41e7d`.

Evidence is retained outside the repository under
`/workspace/agentuplink-review-artifacts/m4-47-valid-data-proof-b8d951e6`.
The first attempt has `first-test-receipt.json` and its stdout/stderr captures.
The actual execution is under `workspace-wrapper-attempt`; `inputs.json` and
`frozen-result.json` retain source/command/environment identities, the original
compiler JSON, all counts, and log hashes. Cargo identified
`tunnel_relay-c341127d7df48521`; its create-only frozen copy at
`workspace-wrapper-attempt/binaries/tunnel-relay-unit-tests` has SHA-256
`1379cd9e35e712f136999f9559227ca05431f9bd40f16e533b80107148056dc9`.
The minimum free disk was 1,953,325,056 bytes; the 1.5 GiB guard did not trigger.
The protected C94 executable remained
`bf3b1248f6a39ad5b76efbf7dc2f385dc6afa29bd7294bb5868ebdc7fe371bff`.
No cache was removed, no Docker or Redis command ran, and the native build
lease was released after freezing the result.
