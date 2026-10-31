# Container notice acceptance, 2026-10-31

M6-C241 now has local proof for the actual relay, authority and Redis images.
The broader distribution task stays open: Redis external-module provenance and
notices, operating-system obligations, eight non-host archive omissions, the
chosen Redis license/distribution model and hosted packaging remain unresolved.
No production deployment, published release or license-policy approval is
claimed. [Notice scope and source identities](../deploy/notices/README.md)
describe what the implementation covers.

## Frozen inputs and actual images

All three images were built from clean source
`a1d6a2a632ee77dd340139c83a7549d83a5b408e`. Its Cargo manifests, lockfile,
toolchain, crates and vendor inputs are byte-identical to runtime candidate
`20b92455706baaacc1f2329c26afba41c48f906a`. The retained source archive has
9,835,871 bytes and SHA-256
`5ca4695d4d4563e66cf67ad37dfd479c9184e84b8359024eb72d005f83b338c7`.
The later evidence-only documentation commit changes no build input.

| Image | Actual image ID | Extracted executable SHA-256 |
| --- | --- | --- |
| Relay | `sha256:f51c2828874c147d9545e8a201bdc669fe3ee85207a927128414c9557fe08506` | `2827f610c4c553fe9ece6bf0040ad27c8170a692a95e98cd76e058eb8842206c` |
| Authority | `sha256:2bbce5cfed3a09611d19b64d436600f4cd1cc379dd670acb5fd9aad888ab1f9a` | `cc7420062204c7f0d6ce6ad551c7d203ef16c3430a955b21c5d78b47762336f2` |
| Redis | `sha256:1fc6c24afae54cbff99ef022019456491c1049d41a6159f0a128dd02b5b829b9` | `a775ade32bc71fc06684b1cfae8ef4a68c7aa57fb402c836cf5d0063333719ab` |

The Docker build used the existing allowlisted contexts, locked release Cargo
builds, two build jobs and the host CA through the existing BuildKit secret
mount. Runtime keys were generated separately. The pinned Rust base already
provided the required Python standard library; the conditional Python install
did not run. Python was not added to either runtime image.

The first attempt is retained as a disk-guard stop, not a build pass. After the
previously uncached Rust base was extracted, free space crossed the predeclared
2 GiB floor; the wrapper sent SIGINT and exited 130 after 25.527 seconds, before
an executable was produced. No ENOSPC occurred. The coordinator then released
only an inactive native proof cache after validating its retained evidence.
The unchanged retry built relay, authority and Redis sequentially in 302.108,
68.042 and 2.001 seconds. Minimum free space including each final measurement
was 3,645,382,656 bytes, above the guard floor.

After image export and all build activity ended, only the two new unshared,
reclaimable regular build RUN records were removed using exact cache-ID filters:
`2fq3z6622kpzhoxj3y6uye8xe` and `pxhfmmr36j21x65bd2ij294mo`.
Before/after inventories confirm every other cache ID and every image were
preserved, including compiler/registry cache mounts and pinned base layers.
Free space rose from 3,534,438,400 to 7,020,290,048 bytes: the local `vfs` driver
retains whole-filesystem copies despite the small logical RUN diff sizes.

## Extracted notice and startup checks

Eleven actual-image checks passed. Each extraction used a uniquely labelled
container and checked its immutable image ID. The verifier checked the extracted
manifest against the extracted executable, source lockfile and project license.

| Image | Verified bundle | Manifest SHA-256 |
| --- | --- | --- |
| Relay | 289 packages, 505 notice files | `dad93379d6d5cd0a37878474e55f7643e436ca2058fb04522b41ee578f95a7b9` |
| Authority | 212 packages, 389 notice files | `78ba8c4d702bacf72b5559cf6879734685cc3a6e09749288e380f0c2658da142` |
| Redis | 10 core/project notice files, exact source-archive pin | `a77b6beef70547c4caf8ecc362dcdb5f8fa536c6ca0cd914485066e36c98b3db` |

Relay and authority report their default UIDs 10001 and 10002, and their help
commands exit zero. Default startup with missing required inputs exits one with
the intended missing-secret/configuration diagnostic. Redis reports version
8.4.0 and refuses missing TLS input. Redis intentionally begins as root to
prepare ephemeral files; the full deployment proof observes its serving PID 1
with real/effective/saved/filesystem UIDs all 999 after TLS startup.

The first inspection wrapper removed containers without `--volumes`, leaving
three anonymous Redis `/data` volumes. This was a wrapper cleanup defect, not
an application failure. Retained Docker events tied each exact volume ID to an
owned labelled container; only those three unattached volumes were removed.
The unrelated pre-existing volume was preserved. The wrapper now uses
`docker rm -fv`; a fresh Redis version case verified that both its owned
container and anonymous volume disappeared. Both the original wrapper and the
correction are retained. No inspected container remains.

## Traffic, lifecycle and bounded rewrite acceptance

The unchanged `deploy/fly/local-proof.sh` passed in 89.429 seconds using the
exact relay and Redis image IDs above and frozen native `20b92455` client and
adjacent deadman. It verified TLS-only Redis, the password, 96 MiB maxmemory,
noeviction/AOF settings, the write-refusal canary, enrollment and traffic,
day-2 changes, live revocation, secret exclusion from image layers and output,
graceful relay SIGTERM (157 ms), reconnect, fail-closed Redis outage and exact
traffic after AOF restart. All owned containers, network, volume and temporary
keys were removed. Companion SHA-256 values:

- Client: `521d7aaea1555f7e08378dfa63e5b578d22de34643d77ee4a313fabb325f1b84`.
- Deadman: `d385132c1532d12edae403c2bced260246e9e0454a5dd7051970bfd95eba08d9`.

The coordinator separately ran
`online_authority_publishes_for_three_relays_and_fails_closed_across_lifecycle`
against the actual authority image and frozen native `20b92455` relay/test
companions: pass, 127.028 seconds, zero residual containers. The copied launcher
changed only the image and ownership label. This fixture uses UID 1000 for
host-owned test paths; default UID 10002 is established by the separate startup
check above. The extracted optimized authority executable is byte-identical to
the earlier C234 image executable. Companion hashes:

- Relay: `1706c096f3d3cf6fdd30899133c9790ff8ea241ce0cce10c651a1a55bf69d48b`.
- Test: `d9bbe00b70df4c2d773486e4c615b3c31612d57fc646aabdd4f28991474ca01a`.

The checked-in `scripts/m6-redis-aof-headroom.py` also passed on the new Redis
image in 24.037 seconds, including cleanup. It checked exact pinned-base layer
ancestry and source entrypoint bytes, TLS/configuration, 256 MiB cgroup memory,
zero swap, one CPU and 64 PIDs. At 4,672 keys / 76,546,048 raw payload bytes, the
rewrite child was paused for 4.94 seconds while two full existing-key passes
completed, then observed through 15 seconds of further writes. Results:

- 45,056 writes acknowledged; zero refusals, evictions, OOM events or swap use.
- Successful rewrite with 76,234,752 bytes actual AOF copy-on-write.
- Cgroup peak 269,152,256 bytes; sampled anonymous-memory maximum 200,613,888
  bytes and file-cache maximum 158,826,496 bytes, which need not coincide.
- Final direct scan/reclaim counters 124,903 / 124,422 and 4,585 limit events.
- Verified owned-container and anonymous-volume cleanup; shared Redis untouched.

The peak includes reclaimable AOF file cache, kernel memory and observers. This
is a bounded local workload pass, not spare-memory or production-capacity
evidence. The original 160 MiB OOM, C239 controls and earlier observer failures
remain recorded in [the headroom report](m6-redis-aof-headroom-2026-10-31.md).

## Retained evidence

Artifacts are local, outside the repository, under
`/workspace/agentuplink-review-artifacts/c241-image-proof/`. Source construction
checks remain 13 notice controls, 22 packaging and 17 adjacent tests (52 pass).
They were not rerun for this documentation-only evidence update. No native
Cargo target was used by the container-notices worker.

| Relative artifact | SHA-256 |
| --- | --- |
| `relay-build.log` (first guard-stopped attempt) | `f62493af15632132a9abb9ac4bfcd9c2d62bb24fbbd42012443f6030fb9e0bf7` |
| `attempt-2/build-results.json` | `6ee3449779de79955c09df6490f2a90a4e03fe3fd3effc93f6a7e14cba466873` |
| `inspection/results.json` | `e8008be0616ab0d0695eaec17bf4a95d2e3af1305086744ed8c5fbf2ca47c802` |
| `inspection/volume-cleanup-correction.json` | `25617b20b1dad3da7f6b3a74bd1c2c78c6b72e4ea98738edf18c43b07dbb127c` |
| `inspection/volume-cleanup-regression.json` | `dd3b631a4c2ca3927d6593a29cd5d59196b95e5b6c1fc850623ea04a7d0362c3` |
| `fly-proof.log` | `03d119d448839a569e49547f812dacd51ace767ddd72e362449f3fba5aa04200` |
| `fly-proof-result.json` | `7d7c3add47d757d461fe87393ae8ea17e7053813fcaae30b4ea1e8dd0481441e` |
| `redis-headroom/face9f0057cd465f88374b72f32f4739/result.json` | `92948b6c442d527bcaf14ee8229c32d2126c78bcabee2282d921b9379c9ae499` |
| `redis-headroom/face9f0057cd465f88374b72f32f4739/samples.json` | `8ce1a621de45b927577f8adb309210e332964a18a5c4215f6d51ec2d2bc034cd` |
| `cache-reclaim-result.json` | `67b4f6e75236351340aa4dca8735e4c6130a9b58a445d51c12b7f3d44824d6da` |

The authority lifecycle artifacts are in the adjacent
`c241-authority-lifecycle/` directory: `manifest.json`, `result.json`, copied
launcher and `lifecycle.log` (SHA-256
`b7529d701c0c441016ce17b721a64dcd75d6e563a208618fe3422db2bb4f841d`).
Per-build logs, disk samples, cache inventories, image inspect records,
extracted bundles/binaries and source archive remain alongside these summaries.

These results establish local image notice retention and the stated runtime
checks only. Other independent frozen-runtime gates could run concurrently;
these elapsed times are observations, not an isolated performance comparison.
They do not close the unresolved distribution work listed at the
start of this report or the project's other production-readiness tasks.
