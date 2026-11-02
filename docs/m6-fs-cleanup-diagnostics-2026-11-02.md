# Filesystem rotation cleanup diagnostics (M6-C256)

The current production goal remains active. Draft #282 has a new hosted M4
failure; its exact connector error was discarded. The follow-up preserves a
closed error code and retryability without changing cancellation, join ownership,
cleanup ordering, deadlines or acceptance assertions. This is a diagnostic fix,
not an established fix for the original hosted failure.

## Exact failed candidate

Draft [#282](https://github.com/andymac4182/agentuplink/pull/282) is head
`cb619ee16bd14110389fc0e6fd589902bfae653a`, tree
`2150db4a2d2f1c6b4d51f3b78caac5da387b72a9`, based on #278
`a2a6a62a68cf44ee4c5e0f3a1c39a7456fb4bc4b`. The actual checkout is
`bdb17f6d0d6a31410ea02b0bc0d8d25bd4b6ef5d`, with that same tree. The
TypeScript, failed M4 and native archive-verifier checkout logs independently
record the full checkout identity.
Its runtime files match the locally verified frozen `f12c9d81` source from
[C254](m6-fs-ledger-retirement-2026-11-01.md); only documentation and the
release trigger workflow differ.

[M4 job 125081943933](https://github.com/andymac4182/agentuplink/actions/runs/41384345334/job/125081943933)
fails at 2026-11-02T03:48:43.978Z (13:48:43+10:00). The earlier filesystem,
write-path and actual TypeScript client gates pass. The M4-68 four-framework
gate enters its actual 300-second rotation at 03:43:35.709Z. Native rotation
results appear at 03:48:40.235Z and expected revocation outcomes at
03:48:42.385Z. Cleanup then reports:

```text
tunnel-test-harness: managed process error: cleanup failed: connector cleanup: managed process error: fs adapters rotation: connector cleanup failed
```

This exact label originates from a completed `client.stop()` returning
`Err(ClientError)`, not the separate 30-second cleanup timeout arm. The first
error is accumulated. The completed supervisor handle is consumed, so the
subsequent stop can return success without undoing that first failure. No
scenario, final-join, proxy, relay or catalog error was additionally reported.
The source aggregation therefore indicates successful exercise results, but
the final evidence validator and `cleanup_joined=true` were never reached.
M4-68 is **failed**, and the later C244 fid-ordering gate **did not run**.

The preceding Draining warnings and CONTROL_CLOSED event do not establish
causation. C254 introduces accounting without a new transport/shutdown/error
path; timing effects remain possible. Neither review identifies the discarded
variant or proves a production fix. The prior #278 C244 failure and all three
failed local C254 attempts retain their original identities and outcomes.

The decoded M4 log is retained privately with SHA-256
`c869a21406fdf20aa88ba466578a6c9aee75c5ecd1e06448d11f2c68dde86b21`.
No unchanged hosted rerun, manual cancellation or acceptance waiver was used.

The separate M2 job 125081943913 passes accelerated/fault/default plans.
Its actual default three-rotation run takes 903.313354102s and round-trips 17,985
records with zero replay. The decoded log SHA-256 is
`2c2d051cf4ae8d377f51c5c5be6edce1d3be10b048f9b1ce85e17c2398d78246`.
M0 job 125081944053 passes 21 gates / 202 streams / 1,668,911 bytes, with all 21 declared
negative witnesses RED; its explicit unscanned scopes remain unchanged.
Its decoded log SHA-256 is
`d801934773e39661c1021a6e200ae050fddba9f504aa5dbee8640bb603b0c19d`.
These are separate hosted checks and do not turn the failed M4 gate green.
The open stack beginning #260 remains draft/unmerged; dependency PRs #279–281
remain separate from the production stack.

Full CI run 41384345334 is completed/failure, updated at
2026-11-02T04:17:54Z (14:17:54+10:00): 13 jobs pass and M4 is the sole failure.
M7 job 125081943855 passes full acceptance; its OG-02 source is git-bdb17f6d0d6a,
with 10 complete correlation rows and 0 incomplete. All three Rust platform checks pass
on this predecessor candidate; that does not substitute for successor checks.

## C255 optimized release coverage verified

[Release-check run 41384345319](https://github.com/andymac4182/agentuplink/actions/runs/41384345319)
attempt 1 reports completed/success, updated at 2026-11-02T03:53:33Z.
All five optimized builds and five native archive verifiers pass; attestation
and publication are skipped. Each verifier reports seven of seven checks:
checksums, layout, targets, notices, assets, CLI and portability. The archive
version names the actual `bdb17f6d0d6a` checkout. The decoded logs and artifact
IDs/digests were inspected; the archives were not downloaded or exercised
locally in this continuation.

| Target | Artifact ID | Native verifier job | Artifact ZIP SHA-256 |
| --- | --- | --- | --- |
| aarch64-apple-darwin | 13115100984 | 125085087409 | `9b520562929338f93373e43e8c5b109d07df0cd03da14b3cc717e1cd480c9534` |
| aarch64-unknown-linux-gnu | 13114352574 | 125085087425 | `39367ab299b74edb46683b36431971d24be9903039478d5e7bd11bb914af5e2f` |
| x86_64-pc-windows-msvc | 13114394289 | 125085087438 | `86efb5621e32565ae441e443f99db1920e70201366fc04f17c05e7a90e1a72ff` |
| x86_64-apple-darwin | 13115176894 | 125085087457 | `3fed97d82d888eb1b7e64854e0ad1731c4ae599205e8d0d790f6297c14b405e2` |
| x86_64-unknown-linux-gnu | 13114708231 | 125085087493 | `914cc8cbef223cb47ee9bf158555f9877505d460dc3aa0d696c079d052a3f612` |

The ZIP digests identify Actions artifacts, not the internal release archive
checksums. Native verifiers explicitly exclude per-file checksums, a
PROVENANCE.txt, notice-to-lockfile reconciliation and a launched relay/device
operation or rotation. Skipped attestation is not successful provenance
verification. The local retained summary SHA-256 is
`5a63a8751a06b4655057e87939e2dc706ca5a88373a360180538cdb28fb7bec6`.
This closes C255's trigger and five-platform build/archive-check scope at
#282, not release publication or production readiness.

## Diagnostic candidate and preparation

The source-only correction is frozen at
`e3842fc537fa41a3a747e94cce24e6b4f21cd8e7`, tree
`73cf73b148e547f9e196e11279b961a02c04fbc0`. It changes only
`crates/tunnel-test-harness/src/production_cluster/fs_adapters_rotation.rs`,
SHA-256 `bed2ff86b40a4f5706121f953d7fb49289bd5e80736412d914cb97312d08373c`.
The 1,095-file source manifest is
`98706d154e918022434666628940e89352fc46c744f53293e54ce8588912f53c`.

Before normal compiler-origin reuse, the prior 82,175,488-byte harness unit
executable `7ff32b81057a9f36c6bf6bcdaef10423e880d6d788f577298a274e9924520f7a`
was independently copied, fsynced and protected as single-link 0555. Its original
was not deleted. Root independently checks the unchanged 137,397,192-byte
C254 CLI `3ab944000155a1c88c27853971a59f41e5dc220bc3f714fe0d8641ad9820fb72`
and its separate immutable proof before/after scoped validation. The shared
Redis/Docker fixtures are outside this diagnostic test scope.

One private preparation generator failed its stale-output-label assertion before
writing a driver or launching any native command. That receipt remains failed;
the corrected preparation keeps the original resource floors, exact artifact
freshness requirement and owned-process cleanup. Both the preparer and root
independently verify all 500 input/source/tool bindings before execution.

## Local validation: partial passes, aggregate failed

The single local attempt at frozen `e3842fc5` remains **failed**. Full workspace
formatting passes, followed by an actual fresh unit build. The independently
frozen single-link `0555` executable is 82,228,496 bytes, SHA-256
`ee2d94390f045e0f1ca7e5d1960abbf16b27f9a5d83d1ed374e8ed2dee415ff9`.
It lists 435 tests and executes exactly eight focused cases: 8 passed, 0 failed,
0 ignored, 427 filtered. Five existing host-oracle/refusal cases and the three new
redaction/first-failure/timeout controls pass; the timeout test uses paused
Tokio time, not a real connector shutdown. These checks do not execute the
real framework rotation or C244 gates.

Strict scoped Clippy then crosses the unchanged 3 GiB available-memory floor:
minimum 3,202,311,128 bytes versus 3,221,225,472 required (18,914,344 bytes below).
The guard stops the owned group. There is no Clippy build-finished record or
harness metadata artifact, so no Clippy pass is claimed. Minimum free tmp is
2,199,318,528 bytes and workspace 2,250,461,184 bytes; OOM counters have zero delta.
The total attempt takes 179.756543s. It is not retried, and the memory/resource
floors remain unchanged.

The pinned subreaper exits on SIGINT with KeyboardInterrupt. Subsequent bounded
termination leaves three zombie children reparented to PID1 in group 687144:
687150,687263,687264. Root and an independent reviewer confirm no runnable
members, but **group absence and successful cleanup are not verified**. The
controller and four earlier owned groups are absent with ESRCH. All 500
protected/source/tool checks pass after the attempt; the C254 CLI origin and
both old/new independent unit proofs remain unchanged. The local native/cache
lease is quarantined, not released as successfully cleaned. No signal is sent
to PID1 and no existing frozen helper is edited.

The immutable result SHA-256 is
`52528619de48db15241679181d2c3b86b189451ce22e312ad29a8869a8937d37`;
root's independent observation at 2026-11-02T14:17:29+10:00 is
`e9b43ccab3eefe0008283db48d4455593f237a72eaf07ef927a641717240d89b`.
Preparation is `4ff802335ed73b85ef840084adcf9daaae0c6773463276fcd4ce6d4cadc5d750`.
Hosted CI on a separate candidate/runner remains necessary for required Rust
checks and real M4 acceptance. A hosted pass would not relabel this local
failed attempt or its failed cleanup.

## Follow-up scope and remaining work

Only the filesystem rotation harness diagnostic changes. Both stop results
retain fixed cleanup-stage labels, the existing `ClientError::code()` and
`retryable()` values. Raw Debug/Display messages, transport scope/details and
protocol strings are excluded. Tests must demonstrate sentinel redaction,
distinct deadline handling and retention of the first error despite a later
successful cleanup. The real hosted cleanup cause remains unknown until new
evidence classifies it; no product cancellation change is justified yet.

The final candidate still needs required checks and successful affected M4
acceptance. Earlier local C244 and authority-image recovery proofs remain bound
to their recorded sources and artifacts. C253 and other owner license decisions,
deployment access/inventory, PKI/OIDC, off-host backup, operational ownership,
capacity and soak requirements remain open. M4-47 remains excluded under its
recorded account-security block. No merge, release publication or deployment
is included; the hourly production goal stays enabled.

The final hosted review receipt is `f8a13a78a06afb9b344fefe524c9cf087a22938051939f460a1a7494c6099304`; decoded M7 log is `be9ace145a275581dad0808c73713dc1adac75209a0ce19bd02d78c2e31f7f69`.
