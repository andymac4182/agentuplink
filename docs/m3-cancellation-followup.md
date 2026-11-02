# M3-53: cancellation when a connector abandons an HTTP exchange

Recorded at 2026-11-02T16:46:01+10:00. Status: **implemented awaiting verification** for the current-main adaptation. No current-candidate tests have run.

PR [#251](https://github.com/andymac4182/agentuplink/pull/251) contains a cancellation fix that is absent from main `626ba9365b5d3e1faf8265f0b6ff50cc9111b749`. The two affected Rust files on that main revision are byte-for-byte equal to their pre-PR versions. This follow-up applies only the reviewed Rust changes and records the remaining verification against current main. It does not incorporate the old branch's unrelated task-history edits.

## Source identity

| Source | Identity |
| --- | --- |
| Follow-up base | main `626ba9365b5d3e1faf8265f0b6ff50cc9111b749`, tree `1e985753f9faa86fbd766b131240b5ca7099719c` |
| Original PR head | `84aa6bcec3a591ad4604bb483f766337dbb77e02` |
| Original PR base and merge base with current main | `11a32e61fee12b86504f384e7f2233c87f3689ae` |
| Original hosted PR checkout | `2f1ff78bc215ce2cb8b172ddbdc57d07097bdacf`, tree `35045f5bccdd354f50238a2c9264dd18f1a18643`; parents are the original base and head above |

The follow-up's `crates/tunnel-http-bridge/src/device.rs` and `crates/tunnel-http-bridge/tests/streaming.rs` exactly reproduce the original PR head's blobs `de73c097c7dde95d40aef90b103f6ce89ccb4369` and `5dbdffeeb3bf21fce98d16dcfac60ef413bd29ef`. There is no dependency, wire-format, queue-bound, deadline or supported-platform change.

## Ownership race and obligations

The device HTTP bridge creates a handler cancellation token and joins its request pump, response pump and watchdog. The watchdog cancels the token when the exchange stops before its response completes. Dropping a cancellation token alone does not cancel its clones.

The connector removes a completed stream only after verifying its terminal proofs. Removing the stream drops `DeviceHttpState`, which aborts its exchange task. After a RESET this can happen before the watchdog runs again. A handler or SSE producer holding a token clone can then miss cancellation entirely. A handler still waiting to return a response also used to be a plain spawned `JoinHandle`; dropping the exchange detached that handler and removed its deadline owner.

The change gives the exchange two drop obligations:

- `CancelIfAbandoned` cancels the handler token if the response has not completed. Its predicate is shared with the watchdog. A completed response never becomes cancelled merely because the upload later fails.
- `AbortOnDrop` aborts a handler that has not answered when the response pump is dropped. This also covers handlers that do not observe the token, including the ACP bridge. Normal explicit cancellation still awaits the aborted handler before producing its terminal report. Abandonment requests abortion; it does not synchronously join the child task.

The first-failure record, execution-knowledge rules, FIN/RESET proof validation, STREAM_FORGET ordering, bounded replay and the two-socket/temporary-third-socket invariant remain unchanged. This patch does not provide a new exchange-report or process-wide cleanup proof. In particular, the separate M4-47 refusal/backpressure work and the completed filesystem-report behavior already present on current main are outside this change.

## Regression tests

The original patch adds these four real Tokio task-ownership tests:

| Test in `tunnel-http-bridge/tests/streaming.rs` | Assertion |
| --- | --- |
| `an_exchange_task_aborted_before_its_response_completed_cancels_the_handler` | Start an SSE response, abort the actual exchange task and observe its handler token become cancelled. |
| `an_exchange_task_aborted_after_its_response_completed_does_not_cancel_the_handler` | Complete the response while keeping the upload open, abort the exchange task and keep the token uncancelled. |
| `an_abandoned_exchange_drops_a_handler_that_never_answers` | Abort an exchange whose pending handler ignores the token, then observe that handler future's drop witness. |
| `a_reset_upload_after_a_completed_response_does_not_cancel_the_handler` | Cancel the open upload after response completion; preserve the completed-response/aborted-request report and uncancelled handler token. |

These tests cover both positive cancellation paths and the completed-response exceptions. No assertions or supported platforms are reduced. Current-source execution of all four is still required.

## Retained historical evidence

The original PR describes a real-path cancellation failure at main `ef7d6e93`, [run 36390849369, job 108826092697](https://github.com/andymac4182/agentuplink/actions/runs/36390849369/job/108826092697): `cancelled exchange 10: the handler never observed its cancellation`. Its local instrumented/stress results and completion timestamps are historical author-reported evidence, not new local observations. The old task history records a first local completion at `2026-09-28T19:53:10+10:00`, review reopening at `2026-09-28T20:44:56+10:00`, local re-verification at `2026-09-28T21:03:09+10:00`, and a hosted-evidence update at `2026-09-28T22:09:16+10:00`. Those dates do not close the current follow-up.

Read-only inspection on 2026-11-02 independently confirmed these later hosted results for the exact original PR head:

- [PR CI 36420593078](https://github.com/andymac4182/agentuplink/actions/runs/36420593078), attempt 1: all 11 then-required jobs succeeded. The Linux Rust job [108923846556](https://github.com/andymac4182/agentuplink/actions/runs/36420593078/job/108923846556) records all four new tests as `ok`. The full M3 job [108923846788](https://github.com/andymac4182/agentuplink/actions/runs/36420593078/job/108923846788) records the implemented M3 suite passing at `2026-09-28T12:28:12.5842486Z`. Both logs identify actual checkout `2f1ff78bc215ce2cb8b172ddbdc57d07097bdacf`.
- PR packaging [36420593178](https://github.com/andymac4182/agentuplink/actions/runs/36420593178) and push packaging [36420586521](https://github.com/andymac4182/agentuplink/actions/runs/36420586521) succeeded.
- The separate push CI [36420586588](https://github.com/andymac4182/agentuplink/actions/runs/36420586588) was **cancelled**, including all 11 jobs. The successful PR run does not replace or erase it.

This historical checkout predates the current main and proves no current-candidate result. The original PR remains unmerged at the review observation; the current source is an isolated adaptation.

## Current verification and remaining gate

Only source inspection, exact-blob comparison and whitespace checks are available locally. C256's failed local native cleanup and quarantine are retained; no Cargo, native process, package install, Docker or Redis execution is claimed for this adaptation.

Before marking M3-53 verified, record the final publication head, actual hosted merge checkout and tree, then obtain:

1. The repository's required locked Rust checks: full formatting, strict workspace Clippy and workspace tests on all three supported CI operating systems, including the four exact tests above.
2. The full M3 acceptance job at that candidate: real HTTP forwarding, rotation, MCP cloud/isolation, SDK conformance and demo coverage. Historical stress-loop counts are not a substitute for this rerun.
3. The remaining normal candidate CI, including authenticated/rotation/routing coverage and M0's ACP real-path/cluster exercises, because both MCP and ACP use this bridge.
4. All five optimized release archive build/verification jobs and the three packaging jobs, preserving the existing platform matrix and publication guards.

Any failed or cancelled new attempt must be retained with its exact source identity. Licensing policy, production readiness and live Fly deployment remain separate open gates. No license exception or deployment approval is implied by this source change.
