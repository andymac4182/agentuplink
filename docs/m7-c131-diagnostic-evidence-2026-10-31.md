# M6-C235 / M7-C131 diagnostic evidence, 2026-10-31

Recorded at 2026-10-31T13:41:04+10:00. The frozen instrumented comparison completed all 20 alternating pairs: **control 19/20, fixed 20/20**. The sole gate failure, control pair 2, has a complete exact-request trace of clean EOF after the ingress admission's own deadline but before its expiry reason was latched. This observed ordering differs from the historical pre-deadline reset hypothesis and does not exercise C232's wrong-reason mechanism. **M7-C131 remains open** pending a production correction and its acceptance; this trace does not explain all earlier failures.

All 40 collectors were valid. Exact-path analysis was complete for 37 and inconclusive for three: both arms of pair 6 and fixed pair 15 passed their gates but have overlapping ingress-observation/owner-destruction intervals. They remain inconclusive, not upgraded to ordered evidence. Gate outcome and capture quality are separate.

[Path-independent source reconstruction and analysis instructions](m6-c235-capture-reproduction.md) preserve this evidence without merging the temporary runtime instrumentation.

## Frozen source and protocol

Reviewed diagnostic source: `7c0b4576c8fb1e82ab2c6ddf85ac893029d88d39`, based on `fd03cdee51e6ecfeb252677a2360f2dfda658457`. The non-default `c131-diagnostic` feature is identical in both arms. The control removes only C232's runtime change in `membership_runtime.rs` (nine inserted/two deleted lines); all other source, instrumentation, dependencies and assertions are identical. The [capture contract](m6-c235-c131-diagnostic-capture.md) specifies bounded events, exact target selection and inference limits. This temporary feature is an evidence artifact, not the production correction.

Both immutable native binaries were built with the pinned Rust toolchain, `--locked --offline`, two jobs, incremental disabled and development/test debug information disabled. Fixed source was restored and a third build reproduced the captured fixed binary's hash. These are unoptimized diagnostic builds, not release artifacts or performance measurements.

The predeclared plan required exactly one control then one fixed quality smoke, each with a valid collector, no timeout, consistent original gate/log/exit and complete exact-path analysis, regardless of gate pass/fail. Both qualified; neither was replaced. The separate comparison then ran exactly 20 pairs, control/fixed on odd pairs and fixed/control on even pairs. Each immutable binary ran `verify-m7-trust-expiry` with unchanged acceptance predicates, `RUST_LOG=warn`, no proxy override, dedicated Redis `127.0.0.1:16379` and unique namespace `test-c235-3487319e10c0-pNN-ARM`. The timeout was 120 seconds. No attempt was retried or discarded.

Other workers explicitly held builds and live fixture work. The driver checked for Cargo/rustc/Clippy before/after each run, checked binary and frozen plan/analyzer hashes, and retained full precision result/load records and private captures. Final checks verified source/HEAD, both binary hashes, plan and analyzer again. All 42 stage namespaces are unique and captures are mode 0600. There were no timeouts, missing captures or protocol violations. Source stayed clean and unchanged throughout both stages.

## Frozen identities and retained evidence

| Item | SHA-256 |
|---|---|
| Instrumented source patch | `fb287e9ca2cecc35419bcb74e92312919f74ed8c1ca6b7f66be441835eb0418c` |
| Runtime-only control difference | `a5aaa400ddab73bce6f571f5214b1a55f98478963b47a10f9d72d5b72430affe` |
| Fixed harness | `7afc188f760571644aa7904da1f64a0e8d79c58fe13268a4da86a5708054695f` |
| Control harness | `411e1d605691a53f5bd7ab40fa465177a79b3608b1f691936f49b270ce6e91a4` |
| Measurement plan | `13f5a9f9178965c8771810d3a1f78249ecda175b3443d1fbcbcafcc5cf469193` |
| Driver | `eb9d4e290e25bac8139d70accf6b1a9565caa0d3c264f4a16c3c61a29bcf22a3` |
| Analyzer | `1d7ab3467bfa53f23f643649c1d28bc1de3f4d3fb55d7865cc6a5f8b64b1a076` |
| Binary manifest | `9abf2045068ba828325fea2b4055e322ae2921d545faa38eb7a0aeab5b4fae1f` |
| Comparison records | `9c16802d7d35fb48fade80e6df7324f2e8d9e6da7ad856a4d43ac0f25c74b768` |
| Quality-smoke records | `83a38c12930e14d0187331fc3d8ed7c4dec892923c8db06499289eeaa7910ff1` |
| Pair 2 control capture | `a4987dd24f3c77ceef9825aef708f87e27622fdd414a6e4127c92880118a1610` |

The local directory `/workspace/agentuplink-c131-diagnostic-artifact/` retains source/control patches and manifests, fixed/control source copies, immutable executables, three build logs, frozen driver/analyzer/plan, and all 42 raw synthetic logs/captures under `quality-smoke/` and `comparison/`. Raw identifiers and diagnostics are not published here. The analyzer's 30 offline controls and three executable setup-refusal controls (existing output, symlink, wrong command) passed before measurement. Focused feature Clippy, nine collector/lifetime/target tests, 18 re-sign tests and the unchanged classification control passed. No new full-workspace acceptance is claimed for this temporary diagnostic branch.

## Separate quality smokes

Both collectors and analyses were valid/complete. These attempts are excluded from the 40-run comparison.

| Order | Arm | Gate | Exit | Seconds |
|---|---|---|---|---|
| 1 | control | pass | 0 | 15.111 |
| 2 | fixed | pass | 0 | 12.405 |

## All 40 outcomes

Starts are UTC on 2026-10-31. Every collector is valid. Durations and 1/5/15-minute load averages are rounded to three decimals; the hashed JSONL retains full precision. Position records execution order within the pair. Complete analysis does not mean gate success.

| Pair | Position | Arm | Start UTC | Gate | Exit | Analysis | Seconds | Load before (1/5/15) | Load after (1/5/15) |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 1 | control | 03:27:35.499666 | pass | 0 | complete | 15.062 | 0.095/0.349/0.771 | 0.142/0.347/0.764 |
| 1 | 2 | fixed | 03:27:50.777518 | pass | 0 | complete | 11.098 | 0.142/0.347/0.764 | 0.119/0.335/0.755 |
| 2 | 1 | fixed | 03:28:02.072292 | pass | 0 | complete | 18.822 | 0.119/0.335/0.755 | 0.215/0.346/0.750 |
| 2 | 2 | control | 03:28:21.089141 | **fail (C131)** | 1 | complete | 19.321 | 0.215/0.346/0.750 | 0.216/0.339/0.738 |
| 3 | 1 | control | 03:28:40.621903 | pass | 0 | complete | 17.419 | 0.216/0.339/0.738 | 0.236/0.338/0.730 |
| 3 | 2 | fixed | 03:28:58.290956 | pass | 0 | complete | 12.099 | 0.297/0.350/0.732 | 0.251/0.338/0.723 |
| 4 | 1 | fixed | 03:29:10.587537 | pass | 0 | complete | 17.367 | 0.251/0.338/0.723 | 0.263/0.337/0.717 |
| 4 | 2 | control | 03:29:28.159400 | pass | 0 | complete | 15.660 | 0.263/0.337/0.717 | 0.319/0.347/0.713 |
| 5 | 1 | control | 03:29:44.007831 | pass | 0 | complete | 16.062 | 0.319/0.347/0.713 | 0.315/0.346/0.708 |
| 5 | 2 | fixed | 03:30:00.275466 | pass | 0 | complete | 14.862 | 0.315/0.346/0.708 | 0.313/0.345/0.702 |
| 6 | 1 | fixed | 03:30:15.341164 | pass | 0 | inconclusive | 17.766 | 0.313/0.345/0.702 | 0.312/0.344/0.696 |
| 6 | 2 | control | 03:30:33.295986 | pass | 0 | inconclusive | 13.207 | 0.312/0.344/0.696 | 0.310/0.343/0.690 |
| 7 | 1 | control | 03:30:46.703091 | pass | 0 | complete | 16.617 | 0.310/0.343/0.690 | 0.383/0.359/0.690 |
| 7 | 2 | fixed | 03:31:03.526377 | pass | 0 | complete | 11.349 | 0.433/0.370/0.692 | 0.366/0.357/0.684 |
| 8 | 1 | fixed | 03:31:15.071341 | pass | 0 | complete | 13.654 | 0.366/0.357/0.684 | 0.353/0.355/0.678 |
| 8 | 2 | control | 03:31:28.916412 | pass | 0 | complete | 13.409 | 0.353/0.355/0.678 | 0.298/0.343/0.670 |
| 9 | 1 | control | 03:31:42.527989 | pass | 0 | complete | 11.949 | 0.298/0.343/0.670 | 0.299/0.342/0.665 |
| 9 | 2 | fixed | 03:31:54.669576 | pass | 0 | complete | 15.612 | 0.299/0.342/0.665 | 0.300/0.341/0.659 |
| 10 | 1 | fixed | 03:32:10.487172 | pass | 0 | complete | 16.064 | 0.300/0.341/0.659 | 0.301/0.340/0.653 |
| 10 | 2 | control | 03:32:26.741200 | pass | 0 | complete | 11.346 | 0.301/0.340/0.653 | 0.254/0.329/0.645 |
| 11 | 1 | control | 03:32:38.287523 | pass | 0 | complete | 15.814 | 0.254/0.329/0.645 | 0.244/0.322/0.635 |
| 11 | 2 | fixed | 03:32:54.298212 | pass | 0 | complete | 11.599 | 0.244/0.322/0.635 | 0.206/0.312/0.628 |
| 12 | 1 | fixed | 03:33:06.089791 | pass | 0 | complete | 13.653 | 0.206/0.312/0.628 | 0.228/0.312/0.624 |
| 12 | 2 | control | 03:33:19.941179 | pass | 0 | complete | 12.658 | 0.228/0.312/0.624 | 0.192/0.302/0.617 |
| 13 | 1 | control | 03:33:32.790512 | pass | 0 | complete | 11.603 | 0.192/0.302/0.617 | 0.217/0.303/0.613 |
| 13 | 2 | fixed | 03:33:44.613139 | pass | 0 | complete | 13.412 | 0.217/0.303/0.613 | 0.184/0.292/0.606 |
| 14 | 1 | fixed | 03:33:58.216622 | pass | 0 | complete | 12.454 | 0.184/0.292/0.606 | 0.278/0.310/0.607 |
| 14 | 2 | control | 03:34:10.956592 | pass | 0 | complete | 12.553 | 0.278/0.310/0.607 | 0.216/0.294/0.597 |
| 15 | 1 | control | 03:34:23.697897 | pass | 0 | complete | 16.419 | 0.216/0.294/0.597 | 0.236/0.295/0.592 |
| 15 | 2 | fixed | 03:34:40.319053 | pass | 0 | inconclusive | 16.564 | 0.236/0.295/0.592 | 0.251/0.296/0.588 |
| 16 | 1 | fixed | 03:34:57.077535 | pass | 0 | complete | 16.114 | 0.251/0.296/0.588 | 0.263/0.297/0.583 |
| 16 | 2 | control | 03:35:13.386067 | pass | 0 | complete | 12.252 | 0.263/0.297/0.583 | 0.272/0.298/0.579 |
| 17 | 1 | control | 03:35:25.855008 | pass | 0 | complete | 12.204 | 0.272/0.298/0.579 | 0.230/0.288/0.572 |
| 17 | 2 | fixed | 03:35:38.276359 | pass | 0 | complete | 16.768 | 0.230/0.288/0.572 | 0.295/0.301/0.570 |
| 18 | 1 | fixed | 03:35:55.232860 | pass | 0 | complete | 13.405 | 0.295/0.301/0.570 | 0.310/0.303/0.566 |
| 18 | 2 | control | 03:36:08.826866 | pass | 0 | complete | 11.047 | 0.310/0.303/0.566 | 0.262/0.292/0.559 |
| 19 | 1 | control | 03:36:20.064518 | pass | 0 | complete | 12.508 | 0.262/0.292/0.559 | 0.295/0.299/0.558 |
| 19 | 2 | fixed | 03:36:32.781361 | pass | 0 | complete | 13.658 | 0.295/0.299/0.558 | 0.297/0.300/0.554 |
| 20 | 1 | fixed | 03:36:46.649057 | pass | 0 | complete | 12.009 | 0.297/0.300/0.554 | 0.305/0.301/0.549 |
| 20 | 2 | control | 03:36:58.850109 | pass | 0 | complete | 12.203 | 0.305/0.301/0.549 | 0.258/0.290/0.542 |

## Pair 2 control: complete ordering

The unchanged gate selected exactly one terminal event by owner/session/stream/operation and supplied its request ID to the one-time target tap. This target joins both admission edges, ingress raw/final observations and the owner's terminal event. Every original gate predicate except ingress receive outcome matched, including owner identity, exact stream/request, cursor ordering, post-deadline close and removed stream. Owner reported `PeerMembershipExpired`; ingress reported `Closed`.

All times are nanoseconds on one process-wide `Instant` origin. Brackets are measured action bounds, not point events or queue ordering.

| Observation | Time or interval (ns) |
|---|---|
| Ingress admission's own deadline | 11,222,524,219 |
| Owner admission's own deadline | 11,222,526,292 |
| Owner first successful reason CAS: `TrustExpired` | [11,272,643,630, 11,272,644,701] |
| Owner handler destruction | [11,272,726,632, 11,272,990,951] |
| Owner retained terminal event: `PeerMembershipExpired` | 11,273,018,726 |
| Ingress raw receive: EOF | 11,273,722,837 |
| Ingress final classification: `Closed` | 11,273,733,803 |
| Ingress first successful reason CAS: `TrustExpired` | [11,273,871,080, 11,273,871,370] |

EOF was observed **51.198618 ms after ingress's own deadline**, **148.243 µs before its first expiry CAS**, and **0.731886 ms after owner handler destruction completed**. Final `Closed` followed EOF by 10.966 µs, still before the latch. Both actual retained reasons were `TrustExpired`, with no earlier membership-revocation/change reason. Revalidation's four existing expiry comparisons were false before each edge's deadline, so this failure did not exercise C232's wrong-reason mechanism.

There was **no ingress trust-expiry policy decision** on this EOF path: generic error attribution leaves every successful result, including `Ok(None)`, unchanged; decoder finish succeeded and the receive loop returned clean EOF. State at raw observation is reconstructed from actual admission/CAS bounds, deliberately ignoring the raw event's later passive state reads. This establishes that clean EOF bypassed local deadline attribution in this ordering, not that a particular wire RESET or FIN caused it.

## Limits and next correction

Collector validity proves bounded completeness before stop, not absence of later background attempts. Exact target phases and non-overlapping action bounds remain necessary; three overlapping intervals stay inconclusive. No pin-watcher close or actual wire RESET/FIN acknowledgement was tapped. Owner destruction/local finish are not wire-delivery evidence. The relays share one fixture process and monotonic origin; no deployed cross-host clock claim follows. Instrumentation can affect scheduling despite matching both arms. This 19/20 versus 20/20 instrumented series is separate from [the earlier uninstrumented 18/20 versus 20/20 series](m7-c131-expiry-comparison-2026-10-31.md); neither proves C232 resolves C131.

The next production slice will classify **clean** EOF using the actual admission state at the existing EOF classification point, after decoder validation succeeds. It must preserve truncated-frame errors and bounded-reservation cleanup, earlier explicit non-expiry reasons, unexpired/no-admission EOF, successful chunks/sends/finishes and unrelated typed errors. Deterministic real-transport red/green regressions and fresh acceptance are required, on a separate branch without this feature. The captured raw-EOF ordering is evidence for this defect; it is not a sample taken by the later production classifier. M7-C131 and historical evidence remain open/intact.
