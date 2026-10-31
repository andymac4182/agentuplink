# Authority writer-lock lifetime correction

PR #274 Ubuntu Rust job
[124496648961](https://github.com/andymac4182/agentuplink/actions/runs/41187171852/job/124496648961)
failed before its unsafe-permissions assertions. `Fixture::coordinator` reopened
freshly initialized state and received `authority state is already open`.
Actual checkout `20c57e323dbac23a7fb00893ea5a34b1390f2ba3` has the same tree as
head `107d94a2`. The failed CI run remains failed; no retry or waiver is used.

Review found a lock-lifetime mechanism that can produce this refusal: closing
the owning file descriptor alone can leave its lock held while a duplicate of
the same open file description remains open. Descriptor inheritance during a
concurrent process spawn is a plausible source of such a duplicate. The hosted
log does not establish that this caused the observed failure. The deterministic
regression below proves the mechanism and correction, not historical attribution.

`LockedPath` now explicitly unlocks its held descriptor when its owning guard
drops. The private guard is created only after successful acquisition; neither
`StateStore` nor `Engine` is cloned. Active blocking workers retain their
`Arc<Mutex<Engine>>`, so caller cancellation cannot release an active writer's
guard. No lock file is deleted or recreated, no pathname-based unlock is used,
and no lock acquisition check is weakened. Unlock errors are ignored during
destruction, followed by normal file close; a surviving duplicate may then keep
the state conservatively unavailable until its own final close.

## Exact focused experiment

Reviewed leaf source is `92010d878f16cfb2202185e279b33da725baaeb3`, based on
`4df856ec`. It changes only `state_store.rs`: the ten-line owning-guard destructor
and one regression. Integrated equivalent is `00a51fe5`.

The negative control removes only that destructor while retaining the new test.
It keeps an actual duplicated lock descriptor open, proves a concurrent writer
is refused while the first guard lives, drops that guard, then requires a new
writer to open. The control fails exactly at this successor-open assertion with
`authority state is already open`: exit 101, zero passed, one failed, twenty
filtered. Its source identity is the leaf plus the exact recorded patch, not
the pristine leaf.

After exact source restoration, all 21 authority binary tests pass. The new
regression proves successor acquisition while the old duplicate remains open,
continued writer exclusion after that old duplicate closes, stable lock inode
through state replacement, and reopening the persisted new bytes. The original
unsafe-permissions test is unchanged and also passes separately. No unsafe code,
retry, sleep, test-serialization change or timeout extension was introduced.

| Focused stage | Result and elapsed time |
| --- | --- |
| Negative-control test build | Pass, 55.778 s |
| Negative-control regression | Intended failure, 0.354 s |
| Restored corrected test build | Pass, 3.117 s |
| Complete authority binary suite | 21 passed, 1.381 s |
| Unchanged permissions test | One passed, 0.387 s |
| Workspace formatting check | Pass, 4.948 s |
| Scoped all-target authority strict Clippy | Pass, 54.648 s |

Both builds use Rust 1.95.0, locked/offline dependencies and the exclusively
released temporary Cargo target. Actual compiler JSON selects each executable;
independent mode-0555 copies preserve both variants outside Cargo on temporary
storage. All eight owned process groups are absent. Source restoration is exact;
the prior C94 executable, Mastra source and independent Mastra harness remain
unchanged. No Redis, Docker, Node or cache-deletion operation was performed.
Minimum free workspace/tmpfs space was 1,803,108,352/5,686,587,392 bytes;
the cgroup OOM counters did not change.

| Private evidence under `agentuplink-review-artifacts/c251-authority-lock-drop/` | SHA-256 |
| --- | --- |
| `attempt-1/result.json` | `771a07bc9330c4fb0e093e2502f1b1d4908ed7b680b05c13fb6596929b5b0ccc` |
| `handoff.json` | `903552483b19efafe82767f1713ba4331e58722410b3836d4d1535c664c80293` |
| `red-only.patch` | `9619601b43fd6c5b3467d8d7bb5c622a9c02e0fc23f0a1081605b40a39701e1b` |
| Negative-control frozen executable | `1485de89ab1b555d146f6a8d583ad62b9e01f4bfc0bb41ca8809b5ff344d1dcd` |
| Corrected frozen executable | `b9cdba83616dc9b7ab2aa61a1b92f70b8e3b4a74b40df99b38d1297a8b6e93e7` |

The focused experiment above left integrated required Rust checks, hosted
checks and affected authority lifecycle/recovery as separate requirements.
The subsequent sections record the integrated local results. Earlier successful images and release binaries retain
their original source identities; they do not contain this correction.

## Integrated checks at 88083555

Clean source `88083555ffec868012938e0d253e9090177deec2`, tree
`1ae1fccdd1204713dd98f8ef31b290b04b33da35`, integrates the C251 correction
and Mastra depth enforcement. Required checks use pinned Rust 1.95.0 and
locked, offline dependencies in an exclusively assigned temporary Cargo target.

| Integrated command | Result and elapsed time |
| --- | --- |
| `cargo fmt --all -- --check` | Pass, 5.033 s |
| Strict workspace/all-target Clippy | Pass, 122.112 s |
| Locked workspace tests | 2,932 passed, zero failed, 108 ignored across 174 suite results; 382.459 s |
| Actual authority integration-test compiler JSON | Pass, 0.531 s |
| Actual workspace runtime-binary compiler JSON | Pass, 65.142 s |

The aggregate preparation controller nevertheless exited 1 **after** all five
commands passed. Its artifact selector encountered the ordinary harness binary
in both compiler outputs and raised `AssertionError('tunnel-test-harness')`.
That failed receipt is retained unchanged. A separate reviewed recovery selects
the integration test only from the test command and five runtimes only from the
runtime command. It verifies the original receipts and logs, exact source and
compiler roles, and independently copies the six executables outside Cargo.
No build or test was rerun, and the original aggregate is not relabelled a pass.
The copies are mode 0555 on temporary storage, not a durable evidence archive.

| Private evidence under `agentuplink-review-artifacts/production-limits-followup/required-88083555/` | SHA-256 |
| --- | --- |
| Original failed `result.json` | `81ccc5324a108311881ae85b18f72e777415e0ff9a1ca62e74902fb4a10a97e2` |
| Separate `freeze-recovery-1/result.json` | `5ae04219a7fea91361e5e56c691f8c48df129c3f3d05f8136a54f0811c9e0113` |
| Workspace-test stdout | `f6fbd7c79b896e22cacaf13d2d0b55809d4269f613483f0b586791d04e64b6aa` |
| Test compiler JSON | `a3813f97f0556f6356f3dda2ef982f0e8c7c6049bffc84544e34903f706f2e6b` |
| Runtime compiler JSON | `55ee6d80f7f140389cd85bfb317adb2e54b9e07a0c4515bf4325e4010414480c` |

| Independently frozen executable | SHA-256 |
| --- | --- |
| `m6_online_authority` | `7907920bc66d34773efdcb6dfa04fe95e094a72c5792e4e8e0e872d065447bf8` |
| `tunnel-authority` | `ee9a90fe702ccfc7e29d6338faac39c88dc700665031cbde72e18a18df786f60` |
| `tunnel-relay` | `f2f63844878b30a01621d56ac741460d85fa7599be7d28a502ec6cbf47a342dc` |
| `tunnel-client` | `06ac01a56d741394d76f33ba41836ae6d03f6372577f38847e9edfd01249a0bf` |
| `tunnel-deadman` | `d385132c1532d12edae403c2bced260246e9e0454a5dd7051970bfd95eba08d9` |
| `tunnel-test-harness` | `1d3760fe064a1ccfff2bf1b3f564a0f72612dc78ae53d4bf4701ba6f98114000` |

## Native authority acceptance at 88083555

The first actual native run passes the unchanged three-relay lifecycle in
120.103 s and both fault cases in 66.854 s: lost publication reply and actual
restart of its dedicated disposable Redis. The shared Redis instance is never
restarted or flushed. These drills execute the new authority/relay and selected
integration test with a library connector; they do not execute an actual CLI
client or an authority container image.

Older-backup/operator recovery stops during creation of its second disposable
Redis container, 2.021 s into setup, at the unchanged workspace-space guard.
Its native recovery scenario never executes. The Docker observer is interrupted
before returning that container's immutable ID, so the aggregate also reports
an identity mismatch. The unchanged recovery wrapper resolves the exact owned
name to its ID and removes it. Independent inspection confirms all three owned
IDs and names absent; owned process groups are absent and all source/binary
hashes remain unchanged. This is a retained failed setup, not a failed product
recovery assertion and not a recovery pass.

Workspace free falls 384,282,624 bytes during creation of the two vfs containers,
exceeding the original estimate from the image's reported size. This is a
workspace observation, not isolated container-block accounting. Sampling observes a minimum of 1,593,462,784
free bytes, briefly 17,149,952 below the nominal 1.5 GiB floor despite the
32 MiB stop margin. Cleanup restores space. The initial temporary cache
relocation is restored with identical bytes, size and mode. A separate
recovery-only preparation requires 2,296,885,248 free workspace bytes before
execution: the existing active stop threshold plus observed two-container
allocation plus 256 MiB. Active guards, timeouts and recovery assertions stay
unchanged; successful lifecycle/fault stages are not repeated.

| Private evidence under `agentuplink-review-artifacts/c251-authority-native-88083555/v2/attempt-1/` | SHA-256 |
| --- | --- |
| Failed aggregate `result.json` | `35df1f55ad0a97a6b0a801a02edd95bfcbbeda9f995013303921162879d1d472` |
| Final cleanup/integrity `handoff.json` | `131b881bbe6cefe882fb1c79ae65b1ac05abe4227a38db261268ddf735fb1637` |
| Lifecycle proof | `b9c9bc338c84ed43edbfcbd2fc207ffba38b9e4e152ea54fbda350a072fd4d0e` |
| Fault proof | `8ff7dbf5f74627091925600983b00b1fc7bb6b022430bcad2655fbbb890b32aa` |
| Recovery wrapper's failed setup/cleanup result | `a74034f1a1153e27e94c561faf951cd89ebdbce9269ca52b4e0ea2e4a003b12f` |

The separately prepared recovery-only run passes in 115.420 s (112.94 s for
the exact native case). It executes the shipped operator commands against an
older RDB, with three relay processes and an independent revocation witness.
Old startups refuse the changed Redis run before approval; missing fences,
wrong nonce and stale digest remain refusals. Explicit recovery consumes its
approval once and refuses replay. The final exact non-owner canary, revoked
credential/grant denial, fresh session, two confirmed refreshes, allocator and
independent-fence preservation all pass. The device uses the production library
connector. Both owned Redis IDs are absent after cleanup.

For this separate run, eight inactive compiler libraries were temporarily
copied to shared memory, verified byte for byte, and left readable at their
original paths through atomic symlinks. No frozen executable or proof was
relocated. Measured free workspace at native-stage start is 2,404,675,584 bytes;
the minimum is 2,017,861,632, above the unchanged active reserve. The cgroup
OOM counters do not change. The first failed attempt remains failed.
After independent process/container absence checks and lease release, all eight
cache files are restored as regular files with their original bytes, sizes and
modes; temporary staged copies are removed. Protected executables remain
unchanged. Restoration receipt SHA-256 is
`a776e8b99e6f70d16131966da884b87f3375738cefb63fe8e76666e13bf311fa`.

An auxiliary prelaunch receipt check also failed with `TypeError`: it expected
a mapping where the root lease supplied a receipt path string plus separate
digest. That shell nevertheless launched the already-authorized controller.
The corrected read-only check immediately verified the exact receipt, and the
controller independently enforced its lease, source, binaries and stronger
startup guards. The auxiliary error and sequencing are retained separately;
there was no controller change, runtime retry or scenario-assertion waiver.
The auxiliary receipt SHA-256 is
`eed5c366d8f1b9fcba04066a64f5401ce39a153110c7bd432a790c1bd1299a80`.

| Private evidence under `agentuplink-review-artifacts/c251-authority-native-88083555/v3-recovery-only/attempt-1/` | SHA-256 |
| --- | --- |
| Successful separate `result.json` | `b29bb21b0f6e7f501bf91312ba0bcbc24164248327fe6723c6f06b459adaee80` |
| `operator-recovery-proof.json` | `60b5d8dedc399d6d2af0bd7c00c1485b4b2c596e8b198f155ab7bca3facd9e4a` |
| Inner operator wrapper result | `38de5edc5e2c389ea371c6371479e60f95f2c66656dd8ecbe6fdcf09711a7982` |
| Actual recovery case log | `769663eea710f380c24e24bde826c936a18a8e6d4df1938df0c72359eeeaf839` |
| Final independent cleanup/integrity handoff | `de29e58c328b41c82e7ad5496a7b9c00d0cf33cb951f27c848edc3225c991b10` |

The six frozen inputs, original C94 executable and clean source remain
unchanged. No full M1/M2/M7 rerun, new release archive, new authority image,
hosted acceptance or live deployment result is implied by these local checks.
Earlier `8c8c14fc` images and optimized archives retain their original identity
and do not contain C251. The goal remains active.
