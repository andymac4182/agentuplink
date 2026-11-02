# Archive notice and Redis provenance follow-up, 2026-10-31

This M6-C241 follow-up adds six exact archive notice supplements on source
`a81e3b9f9d9ba3defcce94843db4155045dd98a2`. No collector rule, license policy,
dependency, runtime code or Docker recipe changes. Source edits were prepared
during the coordinator's quiet comparison window; focused checks passed after
that window ended. No Cargo or Docker command ran. The earlier
[actual-image acceptance](m6-container-notices-2026-10-31.md) used the initial
eight supplements; this follow-up verifies the new fourteen-entry registry
and compares its emitted host bundles against those actual-image extractions.

## Six supported supplements

Every cached crate archive's SHA-256 matched `Cargo.lock`. Each source commit
below comes from that archive's `.cargo_vcs_info.json`. Fetched notice text was
checked against GitHub's exact Git blob hash before copying; byte counts and
SHA-256 values are retained below and in `deploy/notices/rust/supplements.json`.
Declared SPDX alternatives are copied unchanged from the packaged manifests.

| Package | Crate checksum | Packaged VCS commit | Files |
| --- | --- | --- | --- |
| `jni` 0.22.4 | `5efd9a482cf3a427f00d6b35f14332adc7902ce91efb778580e180ff90fa3498` | `5ae9458a4ec44c5318f37ddc7569c1d4ae8a69e7` | [MIT](https://github.com/jni-rs/jni-rs/blob/5ae9458a4ec44c5318f37ddc7569c1d4ae8a69e7/LICENSE-MIT), [Apache](https://github.com/jni-rs/jni-rs/blob/5ae9458a4ec44c5318f37ddc7569c1d4ae8a69e7/LICENSE-APACHE) |
| `jni-macros` 0.22.4 | `a00109accc170f0bdb141fed3e393c565b6f5e072365c3bd58f5b062591560a3` | `33045a124105c939d1e2cbdcb5a39e5d868ffa03` | [MIT](https://github.com/jni-rs/jni-rs/blob/33045a124105c939d1e2cbdcb5a39e5d868ffa03/LICENSE-MIT), [Apache](https://github.com/jni-rs/jni-rs/blob/33045a124105c939d1e2cbdcb5a39e5d868ffa03/LICENSE-APACHE) |
| `jni-sys-macros` 0.4.1 | `38c0b942f458fe50cdac086d2f946512305e5631e720728f2a61aabcd47a6264` | `64d77b7a5f119d7b55b4e2c169a4668067ff59e6` | [MIT](https://github.com/jni-rs/jni-sys/blob/64d77b7a5f119d7b55b4e2c169a4668067ff59e6/LICENSE-MIT), [Apache](https://github.com/jni-rs/jni-sys/blob/64d77b7a5f119d7b55b4e2c169a4668067ff59e6/LICENSE-APACHE) |
| `valuable` 0.1.1 | `ba73ea9cf16a25df0c8caa16c51acb937d5712a8429db78a3ee29d5dcacd3a65` | `9efc29b6e58cef28f6566a47aa7e142a55fead77` | [LICENSE](https://github.com/tokio-rs/valuable/blob/9efc29b6e58cef28f6566a47aa7e142a55fead77/LICENSE) |
| `r-efi` 5.3.0 | `69cdb34c158ceb288df11e18b4bd39de994f6657d83847bdffdbd7f346754b0f` | `97b55bed1c2c91dcbf787674849f05337ff80b33` | [AUTHORS](https://github.com/r-efi/r-efi/blob/97b55bed1c2c91dcbf787674849f05337ff80b33/AUTHORS) |
| `r-efi` 6.0.0 | `f8dcc9c7d52a811697d2151c701e0d08956f92b0e24136cf4cf27b57a6a0d9bf` | `7e1b0322d31d625f81a5656096330934f9cd835d` | [AUTHORS](https://github.com/r-efi/r-efi/blob/7e1b0322d31d625f81a5656096330934f9cd835d/AUTHORS) |

| Retained file | Bytes | SHA-256 |
| --- | --- | --- |
| `jni-LICENSE-MIT` | 1104 | `fea1d5bf3dd71605ce5d7d2ff695c1837e914c77195e523a86b5391716477960` |
| `jni-LICENSE-APACHE` | 10847 | `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2` |
| `jni-sys-LICENSE-MIT` | 1071 | `1d85bd754b04ceec93e98e890edd1fa3c6a22e81bcb32135806beeccefa51cd1` |
| `jni-sys-LICENSE-APACHE` | 11358 | `c6596eb7be8581c18be736c846fb9173b69eccf6ef94c5135893ec56bd92ba08` |
| `valuable-LICENSE` | 1065 | `ed60d479b8fd1f64e9cbc3de449a16a53ac1b3d1b6aeb9bf9d190a8e93061b44` |
| `r-efi-5.3.0-AUTHORS` | 3693 | `ff92bed461f50338dd703a9ba9aee496a425957873df1d91192776e4bdf5dda7` |
| `r-efi-6.0.0-AUTHORS` | 3733 | `d027e91dbc9cdbb2f1190068e498bd6b61cff022b6a032b191021ba658d96111` |

The two `r-efi` cases refine the earlier omission diagnosis: licensing bytes
were already present in the crate under a filename the collector does not
recognize. In both files, line 1 starts `LICENSE`, line 6 starts `AUTHORS-MIT`
(full MIT permission/warranty text), line 26 starts `AUTHORS-ASL` (Apache 2.0
grant and URL), line 39 starts `AUTHORS-LGPL` (LGPL 2.1+ grant and URL), line 53
starts `COPYRIGHT`, and line 58 starts the contributor list. The whole file is
retained verbatim. These exact supplements do not make arbitrary `AUTHORS`
lists acceptable; the new seeded refusal test protects that boundary.
The declaration remains `MIT OR Apache-2.0 OR LGPL-2.1-or-later`. No license is
selected, and full terms for every offered alternative are not claimed.

## Two unresolved archive entries

`eventsource-stream` 0.2.3 has crate checksum
`74fef4569247a5f429d9156b9d0a2599914385dd189c539334c625d8099d90ab` and packaged
commit `3d46f1c758f9ee4681e9da0427556d24c53f9c01`. Its
[exact repository root](https://github.com/jpopesculian/eventsource-stream/tree/3d46f1c758f9ee4681e9da0427556d24c53f9c01)
contains no standalone license file; packaged README/Cargo metadata only state
`MIT OR Apache-2.0`. No invented copyright or generic replacement grant is added.

`rustls-platform-verifier-android` 0.1.1 has checksum
`f87165f0995f63a9fbeea62b64d10b4d9d8e78ec6d7d51fb2125fda7bb36788f` and no
packaged VCS record. Release commit
[`da3d9c36f48fb9f8f97e94f132fdab67ab0fc75b`](https://github.com/rustls/rustls-platform-verifier/commit/da3d9c36f48fb9f8f97e94f132fdab67ab0fc75b)
bumps the Android package to 0.1.1; its manifest and `src/lib.rs` match packaged
source bytes. The generated AAR is 9,287 bytes, SHA-256
`667292cadd8fa589229dd0f716541236a761f29b774930868d218175633830fd`, and lacks
source-commit or license metadata. Matching manifest/doc source is not proof of
the compiled Kotlin input. The current exact packaged-VCS requirement remains
unchanged; no Android supplement is accepted.

## Redis module source candidates and remaining linkage gap

Read-only Docker Registry HTTP responses bind the existing pinned image index
`sha256:4eec4565e45aa0b3966554c866bc73211e281b0b3d89fe9a33c982e6faca809d`
to linux/amd64 manifest
`sha256:e9a8794f6d9d48751f76eeff9b8402405e208d043b35602a33ea415e7cff347c`
and config/image ID
`sha256:cad4195a4376c1018dd6fdadbe7dc9febb799402851a014f006cc77eb27b3e46`.
Its exact [Dockerfile source](https://github.com/redis/docker-library-redis/blob/de8bb5f3e3ead8584e76834816b9e7e332d2bd49/alpine/Dockerfile)
enables modules on amd64/arm64 and builds them from source, not official module
binary archives. The checksum-verified Redis core source's
[common module recipe](https://github.com/redis/redis/blob/60ba86f3c8b4e1ec96451171753a0a38e5c45a0c/modules/common.mk)
uses `git clone --recursive --depth 1 --branch $(MODULE_VERSION)`.

| Module | Tag in pinned core recipe | Current tag resolution; source candidate only |
| --- | --- | --- |
| RedisJSON | `v8.4.0` | [`21a2b4dd37b21f23684795f6f2d8282c224f2b01`](https://github.com/RedisJSON/RedisJSON/tree/21a2b4dd37b21f23684795f6f2d8282c224f2b01) |
| RedisTimeSeries | `v8.4.0` | [`3520a1568ad69076d60885c70711fbdc9b448749`](https://github.com/RedisTimeSeries/RedisTimeSeries/tree/3520a1568ad69076d60885c70711fbdc9b448749) |
| RedisBloom | `v8.4.0` | [`e1f913a1046f0d715ca755824bb1d468f05e6d75`](https://github.com/RedisBloom/RedisBloom/tree/e1f913a1046f0d715ca755824bb1d468f05e6d75) |
| RediSearch | `v8.4.2` | [`9e2b676313f417209c3464fe21ae166ef931b770`](https://github.com/RediSearch/RediSearch/tree/9e2b676313f417209c3464fe21ae166ef931b770) |

Each source candidate has `LICENSE.txt` offering RSALv2, SSPLv1 or AGPLv3 and a
`licenses/` directory containing all three texts. Their source trees also have
separate dependencies/submodules and bundled third-party code. Current tag
resolution does not establish the commits used by the January image build.

The pinned index references an amd64 attestation manifest with digest
`sha256:f5c53f3551e363c56f869d9a807dd6a99d1627091d11741e08933c4842030fc7`.
Two attached JSON blobs were fetched by digest and their bytes verified:

- SPDX SBOM `sha256:ebd6c5d8564a450f176267966faa8be0460344b174f671f321a6dee7982dd423`:
  30 packages (28 APK packages, generic Redis and the document root), 690 files;
  no module packages or `/modules/` file entries.
- SLSA provenance `sha256:2e23e43196528cfc575fa36e793b247860c23fe4e5fd2e73feca248bfab4cec2`:
  identifies Dockerfile commit `de8bb5f3e3ead8584e76834816b9e7e332d2bd49`,
  Alpine base, BuildKit and SBOM tooling; no external module source commits.
  It records `reproducible: false`. Its materials-complete flag does not turn
  unlisted downloads inside a RUN command into module source evidence.

These source notices are candidates only. No module notices are added to the
image, no recipe is changed, and no chosen Redis license or complete module/OS
distribution compliance is asserted. The module-binary/source linkage gap
remains open.

## Focused verification after the quiet window

All 53 checks pass: 14 notice controls, 22 packaging tests and 17 adjacent
archive/artifact/docs tests. An independent in-memory control adding `AUTHORS`
to the generic collector makes the new refusal test fail exactly with
`ValueError not raised`; the tracked collector was never changed. Table,
evidence and whitespace guards pass; complete prior history is retained.

The source-only packaging smoke reuses the existing 325-package native Cargo
metadata and adds 67 lock-derived records from cached crate sources whose
archive checksums match the lock. All 392 identities are accounted for, all six
new supplements have their exact bytes and source URLs in the archive, both
`r-efi` files equal the packaged `AUTHORS` bytes, and exactly the two unresolved
entries above retain explicit status. Synthetic non-executable placeholders
were used; this is not a release, new all-platform resolution or binary proof.

Staging the native normal/build closure against the already-extracted actual
image executables produces byte-identical complete bundles: relay 289 packages,
505 notice files plus manifest; authority 212 packages, 389 files plus manifest.
Every relative path and byte hash matches the earlier actual-image extraction.
The manifest hashes remain respectively
`dad93379d6d5cd0a37878474e55f7643e436ca2058fb04522b41ee578f95a7b9` and
`78ba8c4d702bacf72b5559cf6879734685cc3a6e09749288e380f0c2658da142`.
No image was rebuilt, and no native Cargo target was used.

**Separate hosted release defect retained (C249, coordinator-owned).** Run
`41172225676` built all five target archives, but their native verification jobs
failed because `package_release.py` reused the archive `filename` variable in
the supplement loop, producing a checksum sidecar named after the last notice
instead of the archive. This notice-inventory smoke did not validate checksum
sidecar naming. The coordinator reproduced that failure and owns its fix and
regression; neither packaging implementation nor its tests are changed by this
supplement patch. The local notice checks do not establish hosted release
acceptance or supersede the failed run.

Evidence is retained outside the repository in
`/workspace/agentuplink-review-artifacts/c241-archive-followup/`: the three test
logs, `authors-refusal-control.log`, `verify_cached_notice_inventory.py`,
`cached-inventory-result.json`, extracted-comparison bundles and source-only
archive. `cached-392-metadata.json` has SHA-256
`c787f907964ec64ae14b834ab13f9672ed011c524021f94742dc67a377d096f7`;
its extra records are packaging inventory only, not new Cargo resolve nodes.
The final candidate commit and evidence hashes are bound by the retained
`verification-summary.json`. Hosted packaging, the two unresolved archive
entries and module/OS distribution qualification remain separate.
