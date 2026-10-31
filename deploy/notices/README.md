# Container distribution notices

M6-C241 stages verbatim notice files; it does not choose a license or establish
that all distribution obligations have been satisfied. The existing Cargo
license policy in `deny.toml` remains unchanged. It does not govern the inherited
operating system or Redis distribution.

The relay and authority images carry `/usr/local/share/licenses/agentuplink/`.
`scripts/container_notices.py` reads locked Cargo metadata for the native build
target, follows normal/build dependency edges, and retains matching notice files
recursively so bundled native libraries are included. The closure may include
optional features unified elsewhere in the workspace; it is not an assertion
that every listed dependency is linked into the executable. The manifest binds
the binary, lockfile, package manifests and every notice's exact bytes. Only
actual MIT workspace members may use this repository's root `LICENSE`.
Missing notices, declared files outside a package, symlinks, changed supplements
and incomplete bundles fail. Python is a build-stage tool only.
Both Rust image builds bind the allowlisted source read-only at `/source` and
retain `/src/target` as their compiler cache. This applies the previously proven
authority build layout to the relay: under Docker's `vfs` storage driver,
intermediate source layers copy the whole Rust base filesystem, and the earlier
authority build exhausted local disk. The change avoids those extra relay
layers without changing runtime inputs; its new image still needs a build and
runtime proof.

Eight locked crates omit standalone notice files from their crates.io archives:
`asn1-rs-impl` 0.2.0, `agent-client-protocol`, `agent-client-protocol-derive` and
`agent-client-protocol-http` 2.1.0, `agent-client-protocol-schema` 1.7.0 and
`defmt-parser` 1.0.0, plus the test graph's `rmcp` 3.4.0 and `yasna` 0.5.2.
`rust/supplements.json` binds their upstream notice files
to each locked crate checksum, packaged `.cargo_vcs_info.json` commit and
declared license. File URLs and SHA-256 hashes are retained. These are copied
upstream bytes, not replacement license text or policy exceptions. A package
upgrade must match a newly reviewed supplement or fail.

Release archives use the same recursive collector and pinned supplement lookup.
Their dependency inventory records the notice paths and supplement source URLs;
an unresolved entry now carries `notice_status: "unresolved upstream notice
text"`. The archive dependency scope remains its existing Cargo metadata graph,
including test and non-host dependencies. Unlike the container build, archives
retain their existing expression-only allowance for unresolved upstream notice
files. This is explicit remaining work, not complete archive notice coverage.
Source inspection found additional omissions in `eventsource-stream` 0.2.3,
`jni` and `jni-macros` 0.22.4, `jni-sys-macros` 0.4.1, `r-efi` 5.3.0 and
6.0.0, `rustls-platform-verifier-android` 0.1.1 and `valuable` 0.1.1. The Android
crate has no packaged VCS commit. These are outside the host-filtered notice
smoke, and the full all-target graph must be reconciled separately. This change
does not alter the platform or binary selection.

The Redis image carries `/usr/local/share/licenses/agentuplink-redis/`. Its
pinned base identifies the Redis 8.4.0 source archive using
`REDIS_DOWNLOAD_SHA=b947d9015622669b5bee8ec954f658b3278d42dbefae23a92d9b7704bfe143f9`.
That exact archive was independently downloaded and verified before its nine
notice files were copied. `redis-8.4.0/LICENSE.txt` offers RSALv2, SSPLv1 or
AGPLv3; `REDISCONTRIBUTIONS.txt` retains the historical contribution terms.
The manifest identifies the archive, commit, image index and exact files. The
project's MIT license covers this repository's Redis entrypoint wrapper.

**Redis distribution remains an open obligation.** The inherited image's build
history downloads external modules recursively from version tags, installs them,
and removes the source trees. The core archive does not contain those modules'
complete source or their transitive notices. The image pins bytes, but its
metadata does not attest the exact module source commits used to build them.
No generic license approval, complete corresponding-source offer, or complete
module/OS notice inventory is claimed by this change. The deployment's actual
distribution model and chosen Redis license need an explicit disposition before
publishing a production image. Existing Debian/Alpine files are retained; this
change never deletes upstream copyright files.

Tests: `python3 scripts/test_container_notices.py`. To verify a notice directory
extracted from a built Rust image against the extracted executable:

```sh
python3 scripts/container_notices.py verify /path/to/notices \
  --binary /path/to/tunnel-relay
```

The Redis bundle's `SHA256SUMS` is checked during its image build. Source tests
also check every declared file, the pinned Dockerfile identity, the root project
license copy and the inherited source-archive checksum. Actual image extraction
and verification is a separate acceptance step; a local source check is not an
image proof.
