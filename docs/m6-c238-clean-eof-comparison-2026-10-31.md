# C238 clean-EOF comparison — 2026-10-31

Exactly 20 predeclared alternating pairs completed: **fixed 20/20; control 19/20**. The sole failure was pair 15 control. No warmups, retries, substitutions, timeouts, launch errors or protocol violations occurred. All 40 result/log hashes and all 1,008 source hashes passed final verification; the fixed target still matches its initially reproduced artifact.

This uninstrumented comparison changes only C238: the control removes the 16-line clean-EOF helper and its two receive substitutions. C232, dependencies, build flags, tests and all other source stay identical. Both binaries came from the same detached worktree at `20b92455706baaacc1f2329c26afba41c48f906a`; default unoptimized builds, no diagnostic feature.

Preparation overlapped ordinary acceptance activity and has separate concurrency records. The live series ran only after the coordinator explicitly confirmed all other builds/fixtures were held. Boundary process checks are not continuous monitoring; retained before/after load snapshots are observations, not proof of isolation by themselves.

The unchanged `verify-m7-trust-expiry` gate ran once per unique Redis16379 namespace with `RUST_LOG=warn`, no proxy override and a 120-second bound. Pass required exit 0, exactly one expected pass marker and no harness error marker. Odd pairs ran control then fixed; even pairs ran fixed then control.

The failing control retained the same target owner/session/request correlation, passed deadline, monotonic cursors, carrier transition and `PeerMembershipExpired` owner cause, but ingress recorded `(IngressReceive, Closed)`. Exit was 1, with no timeout. Its fixed pair passed. This run supplies no new raw EOF/latch timeline and does not establish remote wire causation. The separate C235 trace and C238 real-H3 red/green matrix supply mechanism evidence.

The earlier full20b M7 timing-boundary failure, C245 correction/live pass, and mixed-artifact OG02 incident plus clean frozen repeat remain separate evidence. This focused comparison does not turn those attempts into a complete successful full-M7 run or establish deployment readiness.

| Identity | SHA256 |
|---|---|
| Frozen plan | `4e20d4d22b27e7e624376e259796927cadd5fcc21b91a8b0993894c76cbcc2be` |
| Binary manifest | `d79116f00faac5e912183f139e1feb1e5feb18b12efbb47f660d297862305a36` |
| Fixed binary | `95fe2a9561e20bfb5602c3712144d533d3570c3e07cfee9f2b0fdd61e8ace7db` |
| Control binary | `ab874520f35d6716d57bc6a343d62c57e33d6bfa0a45b4df60bca9a7d6055d4a` |
| Runtime-only fix patch | `c06535dfa11bf3e63cd33961920ffe44644b55896faef4d1214eb0a964ca2dd9` |
| Results JSONL | `f9d17b5c39117e3d6a67cbf23cd0b1a6c233048868595a103a941f870e3ee2c7` |
| Attempt starts JSONL | `aea0441fc8948c56f1110a955784811bde1edfe2677c82f3ff12d04598f5e0d8` |
| Summary JSON | `54c547c41fe97c705a848ef58b389aaae1f95334e2abf1290eaa01100dd3651e` |
| Pair15 control log | `69a9ed330051bc46b1c80cc3cce147680e0335715867fcf67460b65392da4f9a` |

Every outcome follows in actual execution order. Elapsed seconds are process measurements, rounded to three decimals; all unrounded durations, 1/5/15-minute loads, namespace identifiers and individual log hashes remain in `results.jsonl`. Times are not a throughput comparison.

| Run | Pair | Position | Arm | Outcome | Exit | Seconds | Load1 before | Load1 after |
|---|---|---|---|---|---|---|---|---|
| 1 | 1 | 1 | control | PASS | 0 | 16.311 | 0.191 | 0.216 |
| 2 | 1 | 2 | fixed | PASS | 0 | 14.160 | 0.279 | 0.236 |
| 3 | 2 | 1 | fixed | PASS | 0 | 12.753 | 0.236 | 0.251 |
| 4 | 2 | 2 | control | PASS | 0 | 13.955 | 0.251 | 0.263 |
| 5 | 3 | 1 | control | PASS | 0 | 13.118 | 0.263 | 0.272 |
| 6 | 3 | 2 | fixed | PASS | 0 | 13.509 | 0.272 | 0.311 |
| 7 | 4 | 1 | fixed | PASS | 0 | 13.860 | 0.311 | 0.309 |
| 8 | 4 | 2 | control | PASS | 0 | 17.467 | 0.309 | 0.653 |
| 9 | 5 | 1 | control | PASS | 0 | 11.498 | 0.653 | 0.552 |
| 10 | 5 | 2 | fixed | PASS | 0 | 13.052 | 0.552 | 0.498 |
| 11 | 6 | 1 | fixed | PASS | 0 | 13.759 | 0.498 | 0.455 |
| 12 | 6 | 2 | control | PASS | 0 | 18.381 | 0.455 | 0.717 |
| 13 | 7 | 1 | control | PASS | 0 | 11.552 | 0.740 | 0.625 |
| 14 | 7 | 2 | fixed | PASS | 0 | 13.154 | 0.625 | 0.555 |
| 15 | 8 | 1 | fixed | PASS | 0 | 11.479 | 0.555 | 0.469 |
| 16 | 8 | 2 | control | PASS | 0 | 12.601 | 0.469 | 0.433 |
| 17 | 9 | 1 | control | PASS | 0 | 12.352 | 0.433 | 0.366 |
| 18 | 9 | 2 | fixed | PASS | 0 | 14.659 | 0.366 | 0.353 |
| 19 | 10 | 1 | fixed | PASS | 0 | 12.053 | 0.353 | 0.342 |
| 20 | 10 | 2 | control | PASS | 0 | 13.556 | 0.342 | 0.289 |
| 21 | 11 | 1 | control | PASS | 0 | 11.549 | 0.346 | 0.292 |
| 22 | 11 | 2 | fixed | PASS | 0 | 12.552 | 0.292 | 0.247 |
| 23 | 12 | 1 | fixed | PASS | 0 | 13.756 | 0.307 | 0.259 |
| 24 | 12 | 2 | control | PASS | 0 | 11.097 | 0.259 | 0.269 |
| 25 | 13 | 1 | control | PASS | 0 | 12.000 | 0.269 | 0.227 |
| 26 | 13 | 2 | fixed | PASS | 0 | 16.365 | 0.227 | 0.244 |
| 27 | 14 | 1 | fixed | PASS | 0 | 11.900 | 0.305 | 0.258 |
| 28 | 14 | 2 | control | PASS | 0 | 14.106 | 0.258 | 0.268 |
| 29 | 15 | 1 | control | FAIL: ingress Closed | 1 | 14.862 | 0.268 | 0.208 |
| 30 | 15 | 2 | fixed | PASS | 0 | 12.904 | 0.208 | 0.229 |
| 31 | 16 | 1 | fixed | PASS | 0 | 14.358 | 0.229 | 0.268 |
| 32 | 16 | 2 | control | PASS | 0 | 13.203 | 0.247 | 0.208 |
| 33 | 17 | 1 | control | PASS | 0 | 20.381 | 0.208 | 0.279 |
| 34 | 17 | 2 | fixed | PASS | 0 | 12.201 | 0.279 | 0.353 |
| 35 | 18 | 1 | fixed | PASS | 0 | 16.024 | 0.353 | 0.342 |
| 36 | 18 | 2 | control | PASS | 0 | 17.567 | 0.342 | 0.375 |
| 37 | 19 | 1 | control | PASS | 0 | 13.654 | 0.375 | 0.359 |
| 38 | 19 | 2 | fixed | PASS | 0 | 13.956 | 0.359 | 0.304 |
| 39 | 20 | 1 | fixed | PASS | 0 | 13.255 | 0.360 | 0.304 |
| 40 | 20 | 2 | control | PASS | 0 | 19.931 | 0.304 | 0.348 |

Private local artifacts: `/workspace/agentuplink-c238-measurement/comparison/`. Raw synthetic fixture logs remain local; this report includes no application payloads or credentials. The series satisfies the fixed-arm 20/20 measurement requirement only; task closure requires the coordinator’s review of the full declared scope.
