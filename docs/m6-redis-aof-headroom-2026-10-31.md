# Redis AOF rewrite headroom: bounded local evidence

M6-C239 found a real availability failure in the former Fly profile:
`maxmemory 160mb` inside 256 MiB was OOM-killed while an AOF rewrite overlapped
existing-key writes. Redis had acknowledged 4,512 updates, about 57% of one pass
over the filled keys, without returning a Redis OOM refusal. The approved
candidate is `maxmemory 96mb`, retaining the 256 MiB VM and `noeviction`.

This is a local workload result. It does not establish worst-case production
capacity, Fly host equivalence, recovery after this OOM, long-term AOF disk
headroom, or an off-host soak result. M6-C222's earlier noeviction/refused-write
proof remains narrower than rewrite memory safety.

## Declared experiment

The protocol was recorded before load on 2026-10-31. All outcomes, including
setup and observer failures, were retained. The only candidate comparison
allowed was 96 MiB after a genuine 160 MiB headroom failure.

- Actual Fly Redis image `sha256:87aa7b1586b04bd3378511f2c4defee3ce44d99affd626f6c9f4151e13df07b4`, with its entrypoint hash checked against source `c029ff35` before writing data.
- New unique container name and ownership label per attempt; immutable container
  ID checked before removal. No shared Redis or deployed system was contacted.
- 256 MiB container memory, memory-plus-swap also 256 MiB, one CPU, 64 PIDs and
  1,024 file descriptors. Actual cgroup `memory.max=268435456`,
  `memory.swap.max=0` and `memory.swap.current=0` were verified.
- Generated synthetic TLS credentials, verified server identity and password
  authentication. Private fixture files were removed after every attempt.
- Durability remained `appendonly yes`, `appendfsync always`,
  `no-appendfsync-on-rewrite no`, `aof-load-truncated no`; policy remained
  `noeviction`. Only automatic AOF rewrite scheduling was disabled, so one
  explicit `BGREWRITEAOF` could be attributed without competing rewrites.
- Fill 16 KiB synthetic values, seeded with 239, until Redis `used_memory`
  reached within 4 MiB of the selected maximum. Bounds: 12,000 keys and
  90 seconds. Values for churn used seed 240; neither payload was printed.
- Identify the AOF child by its exact Redis child title and parent PID 1,
  stop only that child for at most eight seconds, rewrite existing values
  for at most two full passes, and always resume it in `finally`, backed by
  an independent timer. Continue churn for at most 15 seconds after resuming.
- Require rewrite completion within 45 seconds, total trial within 180 seconds
  and at most 1 GiB of input value bytes. Record acknowledgements/refusals,
  canary and key count, persistence state, cgroup memory/peak/events and swap.

The execution environment cannot access sibling Docker cgroups through its
own cgroup mount. Samples therefore read the verified container's own cgroup
files through Docker exec. The sampler's small process overhead is included.
Files are sampled sequentially rather than as an atomic snapshot. Peaks include
reclaimable AOF file cache and can briefly exceed `memory.max` during accounting;
a high peak alone is not an OOM. If the whole container dies, final cgroup files
can disappear; terminal Docker OOM state must then be reported separately from
the last readable counter sample.

## Every exploratory outcome

| Attempt ID | Limit | Outcome |
|---|---:|---|
| `0bb193d957bd4d11bcc7d554b1d3df9f` | 160 MiB | Preflight stopped in 0.426 s: sibling cgroup path inaccessible. Zero writes; container removed. |
| `6958b13d6ff241a19106c86d36c355b1` | 160 MiB | 7,936 values filled; rewrite completed without the intended paused overlap. Observer failed; inconclusive, 11.725 s. |
| `21d4d4048da742fca1b26017bb30b218` | 160 MiB | Same bounded fill/rewrite, 11.045 s; diagnostics found this kernel omits `/proc/PID/task/TID/children`. Inconclusive. |
| `cca2f7ad010c42ccb76aab19b7beb4e3` | 160 MiB | Corrected observer found the exact AOF child by scanning bounded `/proc` status entries. Redis was OOM-killed during paused-child churn; exit 137. |
| `8d4e1767f0694ae09de4f2de8a87e0f3` | 96 MiB | Same corrected script and bounds: two paused churn passes, further churn and successful rewrite; 23.160 s. |

All five owned containers were removed. The two observer failures are not
counted as capacity passes. The corrected comparison script SHA256 is
`fb206eee1ee8a207f48ead0c652f1ca0ce9ed71b5e4a58cc0a5c934a4d2f49b4`.
The protocol, each script revision, all result JSON, cgroup samples and Redis
logs are retained in the review workspace's `c239-redis-headroom` artifact set.

## Measured comparison

| Measurement | Former 160 MiB profile | 96 MiB candidate |
|---|---:|---:|
| Filled 16 KiB values | 7,936 | 4,672 |
| Existing-value updates during paused child | 4,512 acknowledged before OOM | 9,344; two complete passes in 4.793 s |
| Further acknowledged updates | None after container death | 31,328 in 15.009 s |
| Total acknowledged fill/update writes | 12,448 | 45,344 |
| Redis OOM refusal replies | 0 | 0 |
| Recorded cgroup peak | 268,603,392 bytes | 268,685,312 bytes |
| Terminal OOM observation | Docker `OOMKilled=true`, exit 137 | Final cgroup `oom=0`, `oom_kill=0`; process running |
| Rewrite result | No completion before OOM | One rewrite, 5 s, status `ok` |
| AOF last write / delayed fsync | Unavailable after process death | `ok` / 0 |
| AOF reported copy-on-write | Unavailable after process death | 76,218,368 bytes |
| Canary / final key count | Unavailable after process death | Intact / 4,673 |

At 160 MiB, filled `used_memory` was 163,964,376 bytes and RSS was 188,416,000.
The last readable cgroup event sample preceded death: `max=751`, `oom_kill=0`;
final events are unavailable. The terminal Docker OOM flag establishes the kill;
the earlier zero is not evidence of no OOM.

At 96 MiB, the final cgroup reported `max=2869` with zero OOM events and zero
swap. Reclaim pressure therefore remained substantial. Input value bytes were
742,916,096 and final AOF size was 745,110,621 bytes with automatic rewrite
scheduling disabled. This deliberately bounded experiment does not establish a
safe sustained write rate or disk budget for the shipped 1 GB volume.
The local kernel reported `vm.overcommit_memory=0` and Redis emitted its fork
warning. Both comparison trials did fork; host overcommit behavior was not
changed or established for Fly.

## Reproducible gate and remaining scope

Build the current Fly Redis Dockerfile, then run the owned-container gate:

```sh
redis_base=$(awk '$1 == "FROM" { print $2; exit }' deploy/fly/redis/Dockerfile)
docker pull "$redis_base"
docker build -t agentuplink-redis:headroom deploy/fly/redis
python3 scripts/m6-redis-aof-headroom.py \
  --image agentuplink-redis:headroom --output /tmp/agentuplink-redis-headroom
```

The gate checks the actual image/source identity and shipped configuration,
requires meaningful paused-child churn and measured copy-on-write, and retains
results on failure. Hosted CI runs it against the image produced by the existing
Fly proof. Generated keys and passwords are excluded from its output artifacts.
Its independent in-container controller arms before `BGREWRITEAOF`, checks the
child's parent, exact title and process start time, and has a six-second watchdog.
Paused churn is limited to five seconds, must cover at least one complete dataset
pass, and must end while the child is still stopped; actual stopped duration must
remain below eight seconds. Final AOF copy-on-write must cover at least 75% of
the filled raw payload. This tightens the exploratory pause protocol without
claiming two full passes on slower hardware.

Final profile-image validation and hosted verification are recorded separately
from the exploratory candidate above. No live deployment has been changed.
Before increasing capacity, measure the intended key shapes, client buffers,
module usage, fragmentation, slow-disk behavior and backup/recovery workload on
the target platform. Keeping 160 MiB would require a larger VM and its own
accepted headroom test; that alternative has not been measured here.

The new profile image is
`sha256:37f647ac4f72b8e42ce64f092e92fd99af2c6d7d7f195964e5710907263f9d38`.
The updated existing Fly proof passed with nonce
`m6c60-proof-20261031T043427Z-377304`: actual 96 MiB configuration, noeviction
refusal with preserved canary, TLS enrollment and exact traffic, all seven
catalog commands, day-2 revocation, orderly SIGTERM in 147 ms, relay restart,
Redis-down refusal, AOF recovery preserving 43 keys and exact traffic, and a
fresh relay startup. Cleanup removed its containers, network, volume and keys.
This proof used the previously built relay image
`sha256:defd8ce28241019aa44f76d8392ff6dbd2ee6fc4f28150b5c3e7c82a8237407f`
and frozen C232 client/deadman binaries; their SHA256 values are respectively
`7e2572f0ec1a163f164c8fdf0561212246969f9bef494f9ecfe186dcdd288914` and
`d385132c1532d12edae403c2bced260246e9e0454a5dd7051970bfd95eba08d9`.
It validates the changed Redis profile, not later relay/client or container
notice changes; final combined-image acceptance remains separate.

The first hardened gate passed in 25.500 s on that exact profile image:
4,672 filled values, 7,296 paused updates (1.562 passes), 5.35 seconds stopped,
23,200 further updates, 35,168 total acknowledged writes and 76,288,000 bytes
of measured AOF copy-on-write. Refusal, eviction, OOM and swap counters stayed
zero; cleanup was verified. Peak cgroup memory was 268,558,336 bytes with repeated
cache-reclaim pressure. The independently recorded maximum anonymous memory was
195,985,408 bytes; separate sample maxima need not occur at the same instant.

An independent control replaced only the caller's churn function with a false
claim that a full pass occurred, leaving production gate source unchanged. The
otherwise healthy rewrite failed in 19.446 s at the intended copy-on-write
predicate: 1,269,760 bytes measured versus 76,546,048 filled raw bytes. This
demonstrates that an unchurned quick rewrite cannot pass the gate. Its owned
container was removed. Nine focused Python regressions also pass for bounded
RESP, provenance, actual resource limits, write refusals and false-green outcome
rejection. Hosted results remain pending.

After adding an explicit cleanup-inclusive 180-second outcome bound, the final
source passed again in 24.197 s: two complete paused passes (9,344 updates),
5.03 seconds stopped, 28,256 further updates, 42,272 total acknowledged writes
and 76,234,752 bytes of actual AOF copy-on-write. Final OOM, refusal, eviction,
swap and process-admission-failure counters remained zero, and cleanup left no
owned container. Cgroup peak was 268,701,696 bytes; maximum sampled anonymous
memory was 196,521,984 bytes and the `max` event count was 3,227. These numbers
retain the cache/reclaim qualification above. Final gate source SHA256:
`8439905e4fd793e54e151676d46602edc931392b87a9982e436635dcd787d69a`.
