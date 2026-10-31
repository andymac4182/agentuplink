# Authority image default-user provisioning proof

The actual previously built authority image passes a separate synthetic
mounted-secret/state proof as its configured `authority:authority` user.
Observed identity is UID 10002, GID 999. This fills the default-user mount
layout gap; it does not establish deployment readiness or successful Redis
publication. The earlier full lifecycle used an explicitly overridden UID
1000 and remains a separate result.

## Immutable candidate

| Input | Identity |
| --- | --- |
| Source | `8c8c14fc9f6bb164daad224ad7300c04389a296f` |
| Tree | `d6969b5a8e13cf09ade1cf6b410848f7ced2851f` |
| Actual image | `sha256:c9058e7d9a35727b242618d6b88b116996b0d8af9beabbbf3031903b91b98fac` |
| Image authority binary SHA-256 | `f3c1e48bf2adb3b7e8ad3ed450d6c134b1479114375a0db75e9289eff7370c04` |
| Executed corrected controller SHA-256 | `faba46efdfef3a272230943ef9bd359706d5e181e7233247c29dabce0434f58e` |
| Corrected attempt result SHA-256 | `aaa9711c6917b581948520c3fe8aca04a455710a73befa831cd4b95bd2c4da43` |
| Corrected attempt commands SHA-256 | `9327698278087d9847965a54c32fae90ff640773a2384cd8199b732546a0e0e6` |
| Corrected attempt containers SHA-256 | `b394bc4e2323b910398f6ed5f6e2a0c65ec35888a775b3b0f971612f812f6ff2` |

Private receipts are under
`agentuplink-review-artifacts/authority-default-user-8c8c14fc/`.
No image build, pull, real credentials or Redis mutation was involved.
The invocation was the child subreaper running Python on `run-proof-v4.py`;
the controller and all actual CLI invocations are pinned in the receipts.

## First actual attempt: failed before authority initialization

The original execution of v3 failed generating the synthetic membership key:
`tunnel-authority: directory is inaccessible or a symlink`.
The helper staging directory was mode 0733, owned by UID 1000. UID 10002 could
traverse it and create owned children, but `PrivatePath::open` opens each
ancestor read-only with directory/no-follow checks. The helper's `/fixture`
ancestor therefore failed before key generation or any authority initialization.
This is a fixture provisioning-path failure; none of the later acceptance
checks ran. Its one owned container was removed and synthetic material cleaned.

The failed result remains at `attempt-1/result.json`, SHA-256
`a536256f2c7c46674017be84b193e5ecfd9ff7852a35c803b06a9ab156c9d759`;
exact stderr SHA-256
`157c8961dd480555877429a09d016241aa9c5a35cb0440ce630f2387f2506341`.
The failed v3 controller SHA-256 is
`4ad5fb6873d1c91825109172222195723fd5b68a57e951c608f2e3bbed6a1451`.

The reviewed v4 correction mounts only the already-owned secrets child into
a separate default-user key-provisioning container, at the normal
`/var/lib/agentuplink-authority/secrets` path. That provisioning mount is writable;
the key-provisioning container is removed before acceptance continues. Every
acceptance runtime still mounts secrets read-only. Positive runtimes mount
the whole state directory writable; the read-only-state negative deliberately
uses a read-only state mount.
The staging permissions, image, user, runtime restrictions and assertions are
unchanged. Fifty-seven pure controller controls and syntax checks passed before
execution. Earlier review also made initial state independently equal the
constructed inventory and used whole-second fixture timestamps to avoid
Python/Chrono fractional serialization differences, without normalizing observed
state. These were preparation corrections, not successful live attempts.

## Corrected actual attempt: passed

Attempt 2 passed in 24.044 seconds including cleanup. Initialization produced
exactly the independently constructed inventory and expected schema, Redis run,
known-node set, zero allocation counters and absent confirmation. Check, approval
from revision 1 to 2, and reopening succeeded. State inode replacement preserved
the stable lock inode and the planted `.authority-state-1-0.tmp` collision
sentinel; no unexpected temporary files remained. This observes replacement
behavior, not crash or fsync timing durability.

The captured default-startup observation with networking disabled showed
`readiness=pending_publication` and publication unavailable, with no
publication-confirmed marker. The approved state remained unconfirmed after
shutdown. SIGTERM exited cleanly with code 0; a subsequent check reopened the
state successfully. This is a bounded startup observation, not continuous log
capture proving absence of every readiness marker.

| Refusal exercised | Exact cause |
| --- | --- |
| Write output into read-only secrets | `output already exists or cannot be created` |
| Input mode 0640 | `file must be owned by this user with mode 0600` |
| Foreign UID 1000 input | `input is missing, inaccessible or a symlink` |
| Read-only state mount | `authority state lock is missing, inaccessible or a symlink` |
| Default startup before initialization | `authority state lock is missing, inaccessible or a symlink` |
| Duplicate initialization | `authority state already exists` |
| Concurrent held state lock | `authority state is already open` |

The foreign-owner case proves access refusal, not execution of the post-open
UID validator. Uninitialized startup left the state directory empty. Every
refusal preserved the approved state and secret hashes.

All 15 owned containers used network `none`, a read-only root filesystem,
no capabilities, no-new-privileges, 256 MiB memory, one CPU and 32 PIDs. All
were removed and absence checked; zero owned IDs remained, no cleanup errors
occurred, and post-run input integrity was unchanged. Synthetic keys/state
were removed. The CA private key existed only in memory, and no recovery
signing key was generated.

No live target inventory, successful Redis publication, readiness, off-host
access, actual storage crash recovery, production secrets delivery or deployment
is claimed. Those remain under the [active production goal](production-readiness.md).
