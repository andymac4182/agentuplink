# Reproducing the C235 diagnostic source and analysis

This procedure reconstructs the reviewed temporary source from a pinned repository base plus evidence files. It does not require merging the diagnostic feature into the production branch or retaining a particular local worktree path. [The report](m7-c131-diagnostic-evidence-2026-10-31.md) records the original results and hashes; [the contract](m6-c235-c131-diagnostic-capture.md) defines what the capture can establish.

The required evidence files are retained locally in `/workspace/agentuplink-c131-diagnostic-artifact/`: `instrumentation.patch`, `runtime-fix.patch`, `source-manifest.json`, `binary-manifest.json`, `measurement-plan.json`, `analyze_capture.py` and `measure.py`. Publication of those source artifacts is a separate review step; copying this document alone does not make them publicly available. Historical raw synthetic captures remain private/local. The original manifests and plan were frozen before execution, so their preparation-status strings are historical, not current run status.

## Reconstruct the matched source

Use a fresh checkout of base `fd03cdee51e6ecfeb252677a2360f2dfda658457`. Verify each supplied file against the SHA-256 identities in the report before applying anything. Choose independent local paths for the source, artifacts and target directory; no existing production worktree is required.

```sh
# C235_SOURCE is a fresh checkout of the exact base above.
# C235_ARTIFACTS contains the verified evidence files; C235_TARGET is independent.
cd "$C235_SOURCE"
git apply --check "$C235_ARTIFACTS/instrumentation.patch"
git apply "$C235_ARTIFACTS/instrumentation.patch"
```

Verify every entry in `source-manifest.json`'s `source_files` map against the corresponding reconstructed file. There are 12 entries. `membership_runtime.rs` must hash to `bfe37cb9d9c792e9eaff0feb7ea5f90b948258d671f348f6a072535bb2e8f753` in the fixed arm. These checks were actually replayed from a `git archive` of the pinned base after the series: all 12 hashes matched.

Build with the repository's pinned Rust 1.95.0 toolchain and lockfile, with identical settings for both arms:

```sh
export CARGO_TARGET_DIR="$C235_TARGET"
export CARGO_BUILD_JOBS=2
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
cargo build -p tunnel-test-harness --bin tunnel-test-harness --features c131-diagnostic --locked --offline
```

`--offline` requires the locked dependencies already cached; prepare the cache before the quiet measurement window. Preserve a read-only copy of the fixed binary outside the target directory. Reverse only the runtime fix, build again with identical settings and preserve the control binary:

```sh
git apply --reverse "$C235_ARTIFACTS/runtime-fix.patch"
cargo build -p tunnel-test-harness --bin tunnel-test-harness --features c131-diagnostic --locked --offline
```

The control runtime source hash must be `e47eba89625ef37710288a06938c7eb765721097bf1a29e73b7253a4eb23bf32`. This patch removes only C232's nine inserted/two deleted runtime lines; instrumentation and all other source stay identical. Restore it, rebuild and verify that this third fixed build reproduces the first fixed binary's hash:

```sh
git apply "$C235_ARTIFACTS/runtime-fix.patch"
cargo build -p tunnel-test-harness --bin tunnel-test-harness --features c131-diagnostic --locked --offline
```

The reverse/forward source reconstruction and both runtime hashes were also replayed successfully after the original series. Binary hashes can differ in a new build environment or path; record new immutable identities and never claim those are the original executables merely because source matches.

## Replay analysis or conduct a new series

The analyzer is path-independent:

```sh
python3 "$C235_ARTIFACTS/analyze_capture.py" --self-test
python3 "$C235_ARTIFACTS/analyze_capture.py" /path/to/retained-capture.json
```

Its frozen self-test has 30 cases. Exit 0 means complete exact-path analysis, exit 1 inconclusive and exit 2 invalid. These statuses are separate from `gate_passed`; a complete trace can document a gate failure. Hash the capture first and use the original report/JSONL identity when reviewing historical evidence. Do not substitute a new capture for a historical failed or inconclusive attempt.

For a new experiment, create a new manifest/plan/driver with that experiment's own absolute paths, source identity, binary hashes and unique namespace prefix. The frozen original driver intentionally pins its original paths and HEAD; editing it creates a new driver with a new hash. Preserve the original files and results. Before execution, freeze/review the new hashes, exact-target completeness criteria and no-retry policy. Coordinate a quiet window with no builds or unrelated fixture work.

Follow the original protocol exactly if making a comparable diagnostic series: one control then one fixed quality smoke, both collector-valid, complete analysis, no timeout and consistent original gate/log/exit, independently of original gate pass/fail. Stop on smoke quality failure without replacement. If both qualify, run exactly 20 alternating pairs (control/fixed on odd pairs, fixed/control on even pairs) using immutable binaries, dedicated Redis, unique namespace per attempt, `RUST_LOG=warn`, no proxy override and the unchanged `verify-m7-trust-expiry` command. Each capture path must be new and privately created. Preserve every result, load sample, log and capture; do not retry failures or discard inconclusive analysis. Timeout is 120 seconds per run. Verify final source, binaries, driver, plan and analyzer hashes. Do not mix these new results with the historical 40-run table.

This reproduction has no bearing on whether the later clean-EOF production correction passes. That requires its own deterministic regressions and a separately pinned comparison that removes only that correction while retaining C232 in both arms. M7-C131 remains open until its declared acceptance is met.
