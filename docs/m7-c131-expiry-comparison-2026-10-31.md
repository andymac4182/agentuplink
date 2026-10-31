# M7-C131 expiry comparison, 2026-10-31

Recorded at 2026-10-31T12:34:26+10:00. On the combined candidate, the fixed arm passed **20/20** and the control passed **18/20**. Control pairs 2 and 17 failed with the same known C131 ingress attribution signature. No run was retried or discarded. **M7-C131 remains open:** this comparison did not capture the correlated close/latch/deadline timeline its acceptance requires, and does not establish the cause of every earlier full-M7 failure. M6-C232 remains verified only for its bounded positive-deadline classification fix.

## Candidate and predeclared protocol

The fixed source was `89552a1f1eb5a0c1aa5ff354039a2f9ceaaef7be`, based on the coherent hardening, offline authority, authority transport and replacement-canary stack at `ba120f71dfd27d9b744f4d890b1b5952808bc904`. The control differs only by removing M6-C232's runtime change from `crates/tunnel-relay/src/membership_runtime.rs` (nine inserted lines, two removed); the new regressions, harness, gates, dependency lock and every other source file are identical. There is no EOF handling change or assertion relaxation.

Before measurement, both arms were built with the pinned Rust toolchain, `cargo build -p tunnel-test-harness --bin tunnel-test-harness --locked --offline`, the same target directory, and `CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0`. These are unoptimized diagnostic binaries, not release artifacts or a performance benchmark. Copies were made read-only, the fixed runtime source was restored, and a third fixed build reproduced the captured fixed binary's hash. The worktree was clean at measurement startup. During measurement only the separately owned production-readiness document was edited; HEAD and runtime source were unchanged.

The plan was fixed before the series: 20 pairs, control/fixed on odd pairs and fixed/control on even pairs; direct execution of each captured binary's `verify-m7-trust-expiry` command; `RUST_LOG=warn`; a 120-second per-run timeout; dedicated Redis at `redis://127.0.0.1:16379/`; no external proxy override; and a unique `TUNNEL_TEST_REDIS_NAMESPACE_PREFIX` of `test-c232-ee477f348e15-pNN-ARM` for each of the 40 runs. A pass requires exit 0 and exactly one unchanged `M7 signed peer trust expiry passed:` result line, which the harness emits only after its complete exact-stream acceptance predicates. A test failure does not stop the series or trigger a retry.

No Cargo/rustc/Clippy process ran during the series by coordination with the other workers; the driver also checked for active build processes before and after every run. It verified the selected immutable binary's hash before every execution and recorded both load-average samples, full combined stdout/stderr and the result before proceeding. After all 40 runs, both captured binaries, restored runtime source, HEAD and the ordinary target's fixed harness were verified again. There were no timeouts and all 40 namespace prefixes were distinct.

## Immutable identities and retained evidence

| Item | SHA-256 |
|---|---|
| Fixed harness | `744513fc87fd444b00566dfe2a58b853f398e3027d240cf8974106ac3cb9204f` |
| Control harness | `f8e8d09bbb945a6dab71d5d48b097ce907d350420e3fbfd001053fa92f20559f` |
| Fixed runtime source | `89bfdd85204ef5cac466951781967cc3137495d7ecbefc72d22a895265ab04a8` |
| Control runtime source | `264451d78422d46df6792a6fe7b6601f28e2bb468b33421ba2b059045680cf03` |
| Runtime-only patch | `434f06b88d399d086df1c8bb872fea2121c3d78aaa675ea7451f7b31119915f4` |
| Full-precision result records | `4c5657eff7cffc5497ed9353ce07e76a359c92a76fa1d564280b27be1cff5b83` |
| Manifest | `0cf8f5678fa6958073fb5ec21a8fddbed8f460537bebf0090ce5e430f27e8456` |

The local evidence directory is `/workspace/agentuplink-c232-measurement/`: `manifest.json`, `runtime-fix.patch`, both runtime source copies, `fixed-tunnel-test-harness`, `control-tunnel-test-harness`, three build logs, `prepare.py`, `measure.py`, `results.jsonl`, `summary.json`, and all 40 `pair-NN-POSITION-ARM.log` files. These local files are retained for review; this document carries the complete run table and common failure sample without publishing raw diagnostics.

## All 40 results

The series ran from `2026-10-31T02:23:46.629261+00:00` to `2026-10-31T02:33:01.634045+00:00`. Times below are UTC on 2026-10-31. Durations and the 1/5/15-minute load-average triples are rounded to three decimal places here; the hashed JSONL preserves their full precision. Position records actual execution order within each pair.

| Pair | Position | Arm | Started UTC | Result | Exit | Seconds | Load before (1/5/15) | Load after (1/5/15) |
|---|---|---|---|---|---|---|---|---|
| 1 | 1 | control | 02:23:46.629261 | pass | 0 | 12.705 | 0.570/0.893/1.360 | 0.482/0.863/1.346 |
| 1 | 2 | fixed | 02:23:59.503414 | pass | 0 | 12.152 | 0.482/0.863/1.346 | 0.590/0.869/1.340 |
| 2 | 1 | fixed | 02:24:11.824331 | pass | 0 | 13.556 | 0.590/0.869/1.340 | 0.459/0.826/1.318 |
| 2 | 2 | control | 02:24:25.539990 | **fail (C131)** | 1 | 14.508 | 0.459/0.826/1.318 | 0.536/0.831/1.315 |
| 3 | 1 | control | 02:24:40.204145 | pass | 0 | 12.609 | 0.573/0.834/1.313 | 0.484/0.806/1.298 |
| 3 | 2 | fixed | 02:24:52.967917 | pass | 0 | 15.267 | 0.484/0.806/1.298 | 0.444/0.782/1.282 |
| 4 | 1 | fixed | 02:25:08.399578 | pass | 0 | 11.953 | 0.444/0.782/1.282 | 0.414/0.760/1.266 |
| 4 | 2 | control | 02:25:20.527170 | pass | 0 | 12.855 | 0.414/0.760/1.266 | 0.350/0.734/1.252 |
| 5 | 1 | control | 02:25:33.564873 | pass | 0 | 12.757 | 0.350/0.734/1.252 | 0.340/0.714/1.237 |
| 5 | 2 | fixed | 02:25:46.495756 | pass | 0 | 12.705 | 0.340/0.714/1.237 | 0.287/0.690/1.223 |
| 6 | 1 | fixed | 02:25:59.365390 | pass | 0 | 13.965 | 0.287/0.690/1.223 | 0.291/0.672/1.208 |
| 6 | 2 | control | 02:26:13.497782 | pass | 0 | 12.501 | 0.291/0.672/1.208 | 0.294/0.655/1.193 |
| 7 | 1 | control | 02:26:26.156667 | pass | 0 | 13.962 | 0.294/0.655/1.193 | 0.248/0.633/1.179 |
| 7 | 2 | fixed | 02:26:40.282743 | pass | 0 | 14.005 | 0.309/0.640/1.178 | 0.261/0.618/1.166 |
| 8 | 1 | fixed | 02:26:54.451511 | pass | 0 | 13.413 | 0.261/0.618/1.166 | 0.338/0.620/1.158 |
| 8 | 2 | control | 02:27:08.035770 | pass | 0 | 11.851 | 0.338/0.620/1.158 | 0.286/0.599/1.145 |
| 9 | 1 | control | 02:27:20.047231 | pass | 0 | 12.255 | 0.286/0.599/1.145 | 1.072/0.751/1.186 |
| 9 | 2 | fixed | 02:27:32.508532 | pass | 0 | 11.962 | 1.072/0.751/1.186 | 0.907/0.726/1.173 |
| 10 | 1 | fixed | 02:27:44.630959 | pass | 0 | 12.155 | 0.907/0.726/1.173 | 0.774/0.707/1.159 |
| 10 | 2 | control | 02:27:56.943361 | pass | 0 | 12.305 | 0.774/0.707/1.159 | 0.735/0.700/1.152 |
| 11 | 1 | control | 02:28:09.435489 | pass | 0 | 12.861 | 0.735/0.700/1.152 | 0.640/0.682/1.138 |
| 11 | 2 | fixed | 02:28:22.496918 | pass | 0 | 13.214 | 0.640/0.682/1.138 | 0.566/0.664/1.125 |
| 12 | 1 | fixed | 02:28:35.912970 | pass | 0 | 15.123 | 0.566/0.664/1.125 | 0.508/0.647/1.111 |
| 12 | 2 | control | 02:28:51.216474 | pass | 0 | 13.254 | 0.508/0.647/1.111 | 0.430/0.625/1.098 |
| 13 | 1 | control | 02:29:04.641679 | pass | 0 | 12.653 | 0.430/0.625/1.098 | 0.402/0.610/1.085 |
| 13 | 2 | fixed | 02:29:17.508318 | pass | 0 | 13.005 | 0.402/0.610/1.085 | 0.313/0.580/1.067 |
| 14 | 1 | fixed | 02:29:30.677032 | pass | 0 | 20.131 | 0.313/0.580/1.067 | 0.354/0.574/1.055 |
| 14 | 2 | control | 02:29:50.977485 | pass | 0 | 21.334 | 0.354/0.574/1.055 | 0.383/0.569/1.042 |
| 15 | 1 | control | 02:30:12.475394 | pass | 0 | 11.402 | 0.383/0.569/1.042 | 0.324/0.549/1.030 |
| 15 | 2 | fixed | 02:30:24.045468 | pass | 0 | 14.015 | 0.324/0.549/1.030 | 0.319/0.539/1.018 |
| 16 | 1 | fixed | 02:30:38.274876 | pass | 0 | 12.358 | 0.319/0.539/1.018 | 0.316/0.528/1.006 |
| 16 | 2 | control | 02:30:50.819838 | pass | 0 | 13.807 | 0.316/0.528/1.006 | 0.267/0.510/0.995 |
| 17 | 1 | control | 02:31:04.789389 | **fail (C131)** | 1 | 15.064 | 0.267/0.510/0.995 | 0.356/0.518/0.990 |
| 17 | 2 | fixed | 02:31:20.026064 | pass | 0 | 19.930 | 0.356/0.518/0.990 | 0.385/0.517/0.980 |
| 18 | 1 | fixed | 02:31:40.138662 | pass | 0 | 15.616 | 0.385/0.517/0.980 | 0.337/0.499/0.965 |
| 18 | 2 | control | 02:31:55.927676 | pass | 0 | 14.263 | 0.337/0.499/0.965 | 0.285/0.482/0.954 |
| 19 | 1 | control | 02:32:10.363433 | pass | 0 | 13.855 | 0.285/0.482/0.954 | 0.290/0.474/0.944 |
| 19 | 2 | fixed | 02:32:24.387458 | pass | 0 | 12.350 | 0.290/0.474/0.944 | 0.293/0.466/0.934 |
| 20 | 1 | fixed | 02:32:36.903373 | pass | 0 | 12.605 | 0.293/0.466/0.934 | 0.247/0.451/0.923 |
| 20 | 2 | control | 02:32:49.683230 | pass | 0 | 11.951 | 0.247/0.451/0.923 | 0.260/0.444/0.913 |

Both failed runs had this identical final observation:

```text
AffectedObservationSample { target_deadline_passed: true, matching_terminal_events: 1, stream_removed: true, baseline_owner_identity_matches: true, event_owner_identity_matches: true, reason: Some("STREAM_CLOSED"), cause: Some(PeerMembershipExpired), authorization_failure_code: None, closed_after_deadline: true, cursors_monotonic: true, carrier_transition_verified: true, event_request_id_present: true, ingress_receive_count: 1, ingress_last_receive: Some((IngressReceive, Closed)), ingress_owner_identity_matches: true, ingress_request_id_matches: true }
```

The owner terminal event, exact owner/request identity, cursor ordering, post-deadline close, carrier transition and stream removal all matched. The failing predicate was the ingress receive cause: `Closed` instead of `TrustExpired`. The two failures reproduce the known signature on the control arm. Twenty fixed passes provide bounded regression evidence, not proof that every ordering or the earlier full-M7 failure is explained. No correlated observation of the ingress's own deadline, cancellation latch and transport close was added in this slice; that C131 requirement remains outstanding.

## Other checks on this combined runtime

Before building the comparison artifacts, the fixed candidate passed formatting, strict workspace/all-target Clippy with `-D warnings`, and the locked workspace suite under the environment's process subreaper: **2,848 passed, 0 failed, 102 ignored across 173 suite results**. The explicit focused checks passed real required-mTLS checkpoint HTTPS (3), authority CLI (10), ignored real-Redis signer-to-recovery (1), publisher TLS with restricted Redis ACL (1), and full SPKI replacement including its public service canary (1, 24.35 seconds).

Those logs are `/tmp/agentuplink-c232-combined-{clippy,tests,https,authority,publisher,spki}.log`. The earlier deterministic tests-only red run still establishes the narrow C232 defect: an expired existing admission was mislabeled `MembershipChanged` after renewal or `MembershipRevoked` after its key expired; all 18 focused re-sign tests passed after the fix. Prior revocation stays latched and an unexpired unchanged-key admission still rebinds. Earlier evidence and the original full-M7 failure remain in [the task history](tasks.md#completion-history). Full acceptance of the combined candidate and a real production deployment are separate gates; neither is claimed by this comparison.
