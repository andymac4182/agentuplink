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

This is focused local verification. Full integrated required Rust checks,
new-candidate hosted checks and affected authority lifecycle/recovery remain
separate requirements. Earlier successful images and release binaries retain
their original source identities; they do not contain this correction.
