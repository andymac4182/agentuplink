# Planned relay restart: source and validation boundary

This source slice prepares a planned same-incarnation relay restart and adds a
closed diagnostic for the initial membership bootstrap pass. It does not add
production startup retries. The implementation is based on PR294 commit
`d55ffcfe0c1357bb4fa95b30ba0e2b45e729204b`, tree
`668827ea79c2e89e8bffda0947b80f9b11734ae0`.

## Contract

Restoring a membership fence deliberately does not restore verified signed
bytes. An equal record version is therefore rejected after process restart,
even if Redis still contains the same signed bytes. A fresh nonce-bound
checkpoint for that old round does not remove the membership-version fence.
The earlier [relay restart evidence](m6-fly-relay-restart-2026-11-02.md) remains
failed. PR293 and PR294 logs identify `membership_rejected` but do not preserve
the underlying verifier variant; this source analysis does not establish their
exact cause or attribute combined log lines to a particular process lifetime.

The revised rehearsal stops the relay successfully, then reads its final durable
envelope. It requires the exact deployment, incarnation, stable node and all
three positive node-version floors plus checkpoint floor. Both independently
observed authority allocators must already cover the stopped floors. Rollback,
exhaustion, malformed state or incompatible identity is refused without reset.
It waits for a current confirmed membership round strictly above every final
node floor, starts once, requires unchanged readiness, and observes strictly
advanced durable checkpoint and membership fences. Unsigned authority state is
preparation evidence; the relay still performs the actual signature, nonce,
identity and expiry checks.

Preparation, bounded reads, the single start, readiness and durable-adoption
observation share one absolute 60-second deadline after successful stop. Runner
and HTTP use the same minimum of their existing deadlines and that phase bound.
Confirmation expiry is checked before start and after the final read. No failed
start is retried. Existing revocation, fresh owner/session, unaffected routes and
authority restart assertions remain. New-incarnation and physical-backup
recovery remain distinct acceptance scopes.

The existing runtime handle now retains a bounded, payload-free classification
of its one initial bootstrap result. The terminal diagnostic adds a closed
`bootstrap_cause`; legacy output remains recognized with that cause absent.
`initial_ok` means that initial call returned success, not that a later snapshot
must be ready. Dynamic error text, signed records, endpoint values and key data
are excluded. No task, await, retry or ownership policy is added to startup.

A separate P1 source predicate, `is_restored_membership_floor`, checks an
`EqualVersionConflict` against the exact retained node and version and requires
both `signed_bytes` and `verified` evidence to be absent. The intended caller
uses the error from that same verifier before changing its state. This is a
read-only classification, not unforgeable verification evidence: it neither
verifies an arbitrary supplied error, accepts an equal record nor authorizes a
retry. Existing signed verification and restore implementations are unchanged.
Independent source review found no blocker; its five prepared Rust tests have
not run. The broader startup-wait/cancellation implementation remains separate.

## Retained validation

| Boundary | Result and limit |
| --- | --- |
| Original rehearsal | A pure model invoked the actual original `restarts()` method with a final-stop fence advancement. Its early start failed the explicit newer-confirmed-round assertion. This is an orchestration regression control, not a native reproduction. |
| First prepared source | 356 pure/mock/temp controls passed, including 18 new controls. Earlier preparation failures remain: an incorrect new source-binding regex and a missing sparse-checkout fixture file. The regex was corrected and the exact unchanged tracked fixture was materialized. |
| Shared-budget correction | A separate control against retained v1 failed because non-network work could continue after an already earlier HTTP deadline. V2 gives both the same minimum; the normal controller previously entered with equal bounds. No historical hosted failure is attributed to this seeded edge case. |
| A/B final prepared source | 357 pure/mock/temp controls passed, including 19 new controls. All existing Fly Python test files remain byte-identical to the base. `git diff --check` passed. |
| Independent review | Both the full A/B source and narrow v2 correction were reviewed without running native code. No remaining source blocker was found within this scope. |
| Rust and actual images | Four new A/B Rust tests and five separate P1 tests are prepared; one existing terminal expectation is updated. Rust formatting, strict locked Clippy, workspace tests and actual image restart/recovery acceptance have **not run for this slice**. |

A root integration helper subsequently reported one raw pattern match in an
existing synthetic endpoint-rejection test. The exact value was already covered
by the repository's declared path/pattern/digest allowlist. Applying unchanged
`scan_bytes` policy passed (receipt
`b8afb0e47d660950742f5cbfae49651a9c0c54e36158565626a2378546330981`).
The preliminary helper refusal is retained as a preparation error; no fixture,
allowlist, scan policy or v2 source changed, and no new exception was granted.

The prepared A/B Rust tests cover distinct record/checkpoint/signature causes,
redaction, and real signed-record/store behavior: an initial successful handle,
exact equal signed bytes remaining fenced after persisted restart, joined
refusal, and a strictly newer signed round becoming ready. Their source is not
passing execution evidence.

A later dated checkpoint records PR294's dedicated M7 suite passing at
2026-11-02T14:17:02.1853540Z, with ordinary CI terminal at 11 passing jobs and
three formatting failures. Receipt
`c76704ea8b0f230f54366acad68777fbc097f6fc75354d0436af122a95723089`
retains that exact `475ac05c` / `668827ea` source and the independent failed Fly
result. The draft was subsequently closed unmerged, superseded by the separate
format/archive successor. That earlier M7 pass does not run or verify this
planned-restart slice or P1; their native and actual-image checks remain owed.

## Immutable review identities

The retained private receipts contain the complete source manifest, changed-file
copies, exact test logs and both failed controls. These SHA-256 identities name
artifacts, not Git commits:

| Artifact | SHA-256 |
| --- | --- |
| Original A/B source receipt | `7127b5739ecfb590ec793b8b97c05f42c08b5fd8c0c7ca5b865390e8e9d314c4` |
| Final v2 source receipt | `4f51261ce4d157b5997f822b81103277e641a6fc8deae11dc5801ac39619ef2c` |
| Final source patch | `21e0d186dcbd38df8a12bfc8d3a55f5d13141064641467a8430d66de8a306f1e` |
| V1 to v2 correction | `a7ea2ed3750ef6ab8fbd651d8a5090bdeda38df5494eb555d2d249e450694665` |
| Final full source manifest | `cc90b77c43d7a67a877ce92cb49d31d7b7bdceee41fba16ec41d83f6e381a9f0` |
| Final independent review | `8376f39ca776e3c0533f7c233035713bfd878cc62f4d692d24268e31800a3995` |
| Separate P1 source receipt | `dbfe284fe107e82d2d9cc974afc5cbc5ba4f8bc9e212bab29fcf30ba6443c8fe` |
| Separate P1 source patch | `ea3756c92df9e33789c020e6db72f54eaee5e41ec65a1ed31567ff0adc17ff55` |
| Separate P1 independent review | `cb0f306d40cb3f82a2bcee60535b5350ac56b8a1f491885b2f28a40cb9286d7e` |

General crash-restart availability between publication rounds remains open.
The planned barrier does not prove Fly retry timing or replace a production
startup ownership design. In particular, cancellation must retain and join
outstanding persistence work; a hard finish bound cannot also guarantee a join
of indefinitely hung blocking filesystem I/O. This slice changes none of those
semantics and does not close production readiness or physical-backup acceptance.
