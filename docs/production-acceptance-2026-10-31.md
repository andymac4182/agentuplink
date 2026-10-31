# Combined production-candidate acceptance

Status at 2026-10-31T16:03:54+10:00: **not accepted for deployment**.

This report records runtime `20b92455706baaacc1f2329c26afba41c48f906a`,
tree `79d6e525a79f5b26cf2437e7c1a8a1d2dc14b61e`. The source remained clean
through the complete attempt. It contains the online authority, actual CLI
forwarded reconnect, stale-authorization distinction and clean-EOF expiry fix.
The later Redis profile, image notices and TypeScript deadline work need their
own evidence. No change has been merged or deployed.

## Local attempt

Rust 1.95.0, locked dependencies, debug information/incremental compilation
disabled, two build jobs, explicit `RUST_LOG=warn`, and dedicated loopback
Redis were used. A child subreaper handles this environment's non-reaping PID 1;
test assertions are unchanged. M2 default ran concurrently with accelerated
M2 followed by M7. Later Docker compilation and comparison-binary preparation
also overlapped portions of M7. This was not a quiet timing comparison.

| Gate | Result | Evidence |
| --- | --- | --- |
| Formatting | Pass | 4.482 s |
| Strict workspace/all-target Clippy | Pass | 82.518 s |
| Locked workspace tests | Pass | 370.659 s; 2,889 passed, zero failed, 107 ignored; 174 suite results |
| M1 | Pass | 80.631 s including compilation |
| Accelerated M2 and faults | Pass | 32.271 s |
| Default M2 | Pass | 912.673 s; three actual 300-second rotations, 18,987 records, zero replayed records |
| Full M7 | **Fail** | 1,273.728 s; EC-055 timing evidence could not establish authorization invalidation cause |
| Supplemental packaging/docs | Pass | 37 tests; the first invocation lacked PYTHONPATH and failed import, then the corrected invocation passed |

M7 had passed the actual online-authority and configured-process gates, CLI
reconnect, trust expiry, re-sign, capacity, partition, pressure, side-effect and
owner-loss gates before stopping. Actual CLI owner release took 30.011 seconds
and the same PID regained readiness in 30.415 seconds, with 38 bounded
OWNER_BUSY refusals, three exact canaries and clean stop. The signed peer trust
expiry gate passed in 10.059 seconds. These narrow successes do not complete
M6-C68, M7-C131 or full combined acceptance.

A separate continuation starts with pending-owner admission. The first 16
remaining gates pass with the original executable unchanged, including C11
in 153.060 seconds. OG-02 then exits zero in 241.696 seconds with ten complete
correlation rows, but its artifact identity is inconclusive: an authorized
integration-test no-run compile implicitly replaced Cargo's top-level harness
path while this gate spawned children. The coordinator's assumption that this
compile would leave that binary untouched was wrong. The parent kept the old
inode; at least one child used the replacement. The before/after hashes and
complete run are retained, and this result is not counted as exact-artifact
acceptance. The original executable was captured from the still-running parent
and matched the pre-run SHA-256
`3ab527f69de07fc2b2d1ff8711b5541d2a35082ae45aaf903c346aa547741abb`.
A single separate repeat now uses this create-only immutable copy and frozen
companions outside Cargo's output tree. It passes in 232.393 seconds with ten
complete rows and all artifact hashes unchanged (log SHA-256
`09a89b0c418e29496237f78839abfcf6151f5c6a2711bea9df3ce78921119bf1`).
Its outer bound is 1,550 seconds,
covering the existing 1,500-second OG-02 bundle timeout and cleanup. The
continuation's arbitrary 300-second outer bound did not fire but was shorter
than the harness contract. Neither continuation nor repeat replaces the failed
timing-boundaries gate. The predeclared 20-pair clean-EOF comparison subsequently completed with
fixed20/20 and control19/20. Pair15 control reproduces the exact expiry
classification mismatch; all forty outcomes and final integrity checks are
retained in the [separate report](m6-c238-clean-eof-comparison-2026-10-31.md).
No retry, timeout or diagnostic feature was used. This focused comparison
does not turn the failed combined M7 attempt into a pass.

Local artifacts are retained privately under
`/workspace/agentuplink-review-artifacts/combined-runtime-20b92455`, including
the source/driver manifest, fsynced results, logs and copied image companions.
These paths are local evidence, not published downloads. SHA-256:

| Artifact | SHA-256 |
| --- | --- |
| Acceptance driver | `68627882cb2fa4bd935288c47ede0ec3e9264e51d77ac87d23fb45aaa8845cac` |
| Workspace log | `af07d866008b55c1b174cdb74896991e55826513b1712438fe8acbe82d35277c` |
| M2 default log | `91bbb3e8fb94b2a28f33bc157b5fdc09a824625a106aa8419803a9c920faf505` |
| Full failed M7 log | `a7c419e05656e6e438fe48e2d04833ab23b1178a6b83af949a86bb652a37aad7` |

## Hosted failures retained

At `20b92455`, [CI run 41169353427](https://github.com/andymac4182/agentuplink/actions/runs/41169353427)
fails three jobs:

- M7 job 124443737869 fails the same EC-055 authorization-cause assertion.
  M6-C245 tracks the distinction between a missed refresh deadline and actual
  credential/grant invalidation. The gate must assert the correct exact cause
  without accepting arbitrary failures or weakening correlation.
- Linux Rust job 124443738026 fails
  `publisher_survives_three_admitted_durable_checkpoint_operations`:
  an HTTP operation gets `state allocator is busy`. The other 19 authority
  tests pass. M6-C247 investigates the test's queue residence and the actual
  one-second HTTP bound separately from publisher fairness.
- Dependency/secret job 124443737877 retains the known authority-guide
  placeholder finding. Downstream #270 fixes only the exact placeholder;
  hosted verification now passes on that descendant (job 124447394040) and on Redis descendant 9866a671 (job 124447619897).

Other jobs in that run pass, including M1, M2, MCP, filesystem, TypeScript,
macOS/Windows Rust and the image smoke test. Packaging run 41169353260 passes.
Those do not override the failed jobs. Release workflow path filters do not
trigger the optimized matrix for the isolated clean-EOF patch.

Earlier authority head `7b787f8f` has a separate M7 failure in
[run 41168247474](https://github.com/andymac4182/agentuplink/actions/runs/41168247474),
job 124440640000: OG-02's GOAWAY child fails cleanup with relay-b peer transport
failure and relay-a `H3_FRAME_UNEXPECTED`. M6-C246 tracks this evidence; there
is no causal attribution to the clean-EOF patch. That head's other jobs pass
except the known secret scan, and optimized release run 41168247771 passes all
five build/archive targets. Publication and attestations remain separate.

At placeholder-only descendant `d8b4e6c`, M7 job 124447394195 in run
41170475768 has a distinct failure: the online-authority lifecycle canary is
refused after 31.04 seconds, during the continuous-publication portion. The
first exact non-owner canary passed. The current error discards its phase,
HTTP status and typed failure code, so no product cause is asserted. M6-C248
tracks payload-free diagnostic attribution; no retry or weaker continuity
predicate is permitted. Local native and actual-image successes do not erase
this hosted failure.

At Redis-profile descendant `9866a671`, M7 job 124447619983 in run
41170584446 fails the retained C245 timing assertion; every other CI job passes.
At notice descendant `a81e3b9f`, Ubuntu job 124452672186 and macOS job
124452672144 in run 41172225687 fail C247's old publisher-queue fixture with
`fixture did not exercise a queue longer than the HTTP wait budget`. Its
replacement has only local evidence so far. M7 job 124452672134 also fails
the retained C245 timing assertion; all other jobs in this CI run pass.
Earlier CLI descendant `c8f51416` has the same old publisher-fixture failure
on macOS (job 124442370671), alongside the historical placeholder scan;
its M7 and five-target release pass. Stale-authorization descendant `58e15d4`
has the C245 M7 failure (job 124443232189) and historical placeholder scan;
its other CI jobs and packaging pass. None of those histories is erased by
downstream local corrections.

Release run 41172225676 builds all five targets, then **all five native archive
verifiers fail**: the checksum sidecar is named for the final notice supplement,
rather than the archive. Its Linux artifact 13031099996 is downloaded and its
ZIP SHA-256 `144f6c9db9f8438dc00a309051a3f4b2611ae88b820e182104c133cbe94a402a`
matches GitHub. It contains the archive and `yasna-LICENSE-APACHE.sha256`; the
sidecar also states the wrong filename. The source's supplemental-notice loop
shadows the archive filename. M6-C249's renamed loop binding passes a new
five-target regression that first failed six assertions, plus all 43 focused
packaging/archive/notice checks. A corrective local repack of the actual CI Linux binaries now passes all seven
native checks, eighteen CLI probes and twelve planted defects. Every original
archive member byte, including notices and documents, is unchanged; the old
checksum remains preserved. The original merge tree equals `a81e3b9f` exactly.
The 372 original package identities were selected from the cached source
inventory without running Cargo. This is a local packaging experiment, not a
new runtime build, final coherent candidate or hosted success. Corrected
archive SHA-256 is
`48cdd2d8cdeca36729c0613d3b384193ed775965f1fd622e3599c1c0fff1f9ad`;
verification log SHA-256 is
`0043ab7a14cf68192e46d65124fa16667e176ffb0631ff89b21ca111cba7bae7`.
Private inputs and detailed provenance remain under
`/workspace/agentuplink-review-artifacts/c249-release-checksum`.
Final hosted proof remains pending. Nothing was published or attested by this
failed PR run.

## Historical placeholder verification

The exact authority-guide placeholder exception in #270 has one document path,
one pattern and the complete 23-byte SHA-256, with no wildcard credential
allowance. Eight seeded controls pass, including removal of the exception,
different password bytes at the same path and identical bytes at other paths.
The local full-accessible-history scan visits 1,998 commits and 6,661 blobs,
with zero findings and no oversized/skipped blobs. Hosted dependency/license/secret jobs 124447394040 and 124447619897 also pass; the wider CI runs retain separate M7 failures. Its five suppressed hits
are the inspected literal placeholder. This does not attest to a credential
provider, rotate a real secret or claim coverage of all GitHub-only refs.

## Outstanding deployment proof

The next integration candidate contains the C245 exact stale-refresh matcher
(seven focused tests and one live timing pass, 53.614 seconds) and C247's
deterministic queue-budget fixture (twenty tests and scoped strict Clippy pass;
production timing unchanged).

C243 has two retained **failed** local optimized-artifact attempts. Source
`3d092deb` fails before restore because three relays plus the authority occupy
28 of the fixture proxy's 32 TLS slots, while the operator CLI requires seven
more. The fixture repair at `7c9c24fc` gives operator commands a separate bounded
verified TLS proxy to the same owned Redis; it passes all seven focused controls
and strict scoped Clippy. Its frozen test executable is
`1be64fb1c693baa9297dbf2b3b3f478daa8df400336e981aeb7819ce966dff10`,
with the unchanged C241 optimized authority and relay copies.

That second attempt fails in 82.60 seconds (wrapper 83.452 seconds), after
actual older-RDB restoration, both live revocations, 65.023 seconds of quiescence,
wrong-nonce/missing-fence/stale-digest refusal, signed approval, consumed fence
version1 and replay refusal. After three replacement relays start, a canary
returns `503 CLUSTER_UNREADY/not_dispatched` in 1ms. Both exact owned Redis
containers are removed. This does not verify the recovery drill. Independent
review also requires old-config changed-run refusals before reconciliation and
approval; post-activation incarnation refusals cannot prove that earlier boundary.

C248's bounded diagnostics and retained ingress log establish the second
attempt's readiness transition: relay-a reports `Authority(HttpStatus(429))`
at `2026-10-31T05:50:50.863787Z`, before teardown. The fixture observer polls
checkpoints with that serving relay's identity; the authority permits one
simultaneous connection per node. The competing observer can consume its slot,
causing the legitimate relay to fail closed. Later persisted floors and
confirmation timestamps are not event-time readiness snapshots. This is a
source-backed fixture-contention explanation for this occurrence, not proof
of the exact cause in the older hosted31-second failure. A passive observer
with independently verified adoption by all three actual relays is in progress;
no authority limit or canary predicate is relaxed.

The TypeScript deadline and fid work passes pinned Node24.21.0, 598 offline
tests,25 installed-framework tests and the existing real-path filesystem demo.
The separate four-framework scheduled-rotation gate is being implemented;
its preflight does not establish real-relay rotation acceptance.

C246's unresolved-request cancellation and capacity refusal reproduce real
HTTP/3 connection errors that interrupt siblings. The narrow fix now resets
only the unresolved request and transfers request-end accounting correctly.
Source `29897889` passes seven focused real-H3 cases, all83 transport tests,
strict scoped Clippy, formatting and vendor provenance replay. An initial
malformed-frame fixture wrongly expected delivery of the server's error code
to the client; that failed control is retained, and its corrected assertion
checks the exact server protocol error. Full aggregate acceptance and exact
historical hosted-stream attribution remain separate. No production change
has been merged or deployed.

The final combined candidate still needs all required gates passing, corrected image traffic/recovery and
headroom checks, and hosted release checks. The unchanged predeclared expiry
comparison is complete and remains a separate fixed-source measurement. The real deployment inventory,
certificate and OIDC configuration, monitoring/alerts, backup ownership,
off-host capacity/soak, license disposition and operator recovery remain
explicit in the production-readiness goal and task tracker.
