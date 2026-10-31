# Combined production-candidate acceptance

Status at 2026-10-31T15:12:00+10:00: **not accepted for deployment**.

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

A separate continuation starts with pending-owner admission and runs the
remaining 17 gates against the same binary. Its results are tracked separately;
it neither retries nor replaces the failed timing-boundaries gate. The
predeclared 20-pair clean-EOF comparison is prepared but has not run.

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
  it needs hosted verification on that descendant.

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

## Historical placeholder verification

The exact authority-guide placeholder exception in #270 has one document path,
one pattern and the complete 23-byte SHA-256, with no wildcard credential
allowance. Eight seeded controls pass, including removal of the exception,
different password bytes at the same path and identical bytes at other paths.
The local full-accessible-history scan visits 1,998 commits and 6,661 blobs,
with zero findings and no oversized/skipped blobs. Its five suppressed hits
are the inspected literal placeholder. This does not attest to a credential
provider, rotate a real secret or claim coverage of all GitHub-only refs.

## Outstanding deployment proof

The final combined candidate still needs all required gates passing, the
unchanged predeclared expiry comparison, corrected image traffic/recovery and
headroom checks, and hosted release checks. The real deployment inventory,
certificate and OIDC configuration, monitoring/alerts, backup ownership,
off-host capacity/soak, license disposition and operator recovery remain
explicit in the production-readiness goal and task tracker.
