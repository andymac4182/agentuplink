# Client dependency license evidence gate — M6-C253

The prepared checker **fails on five unresolved policy entries**. It verifies the
complete 324-node client lock, including all dev, optional and platform entries,
and all seven npm aliases. Five declarations are outside the unchanged
`deny.toml` allowlist. Two additional archives omit their MIT text; exact reviewed
upstream supplements now supply those texts in a verified companion bundle.
Artifact coverage is not policy approval. Neither passing planted controls nor
a zero-advisory result closes C253. No license exception or platform reduction
is implemented, and this gate is not yet enforced in CI.

## Current result

The 2026-11-02 offline replay rehashed the existing compressed artifacts with
the new supplement implementation. All 324 artifact records and seven aliases
verified; **319 entries passed, five declarations failed, and the process
exited 1**. The unchanged blockers are the four BlueOak packages and optional
LGPL package in the table below. This was an offline replay, not a fresh
registry collection or a new dependency audit.

The failed report is retained privately under
`c253-mit-notice-offline-replay-attempt2`, SHA256
`40133712127d841fb0a5cd93e83aeda8bd912b31d0b1539ff3e3ff8ba7e28804`.
It binds the then-uncommitted gate SHA256
`34829c1223d5b2870c1deb102bc1bb176ea52760a8be1aa2c9f555cbeca1f00f`
and supplement verifier SHA256
`9814e7f12e4baf0d81baa842989b76954d1df4c70e5e7abb61d6c64ec2960025`
based on `d343d21c1b1e6f753a60c2a862de89e8762698de`; this is not relabeled as
a run at a later commit. The exact source manifest is retained as
`c253-mit-notice-source-v2/receipt.json`, SHA256
`67f573f149d53703a0db23d885cd270dfb31342d6b04fa9ba6da3ec8ba78977f`.

The two complete MIT texts were actually written and independently verified
in a companion directory, manifest SHA256
`dda721b837e2a5f0c4715f10d9e73f8fd3bbccaaca8597251599b3310c84b582`.
The original archives' `notice_files` remain empty; separate
`supplemental_notice` records identify the supplied texts. This proves only
the two-notice companion, **not an SDK release or all 324 dependencies'
distribution obligations**. The private client currently has no publication
pipeline that establishes downstream inclusion. A future distributor must
include and verify the complete notices alongside the relevant software.

The replay read 58,841,861 compressed bytes, retained at least 1,642,672,128
free filesystem bytes and a 6,774,901,472-byte available-memory estimate,
and observed no OOM-counter increase. Existing OOM counters were nonzero;
the assertion is unchanged counters during this replay. All source inputs
were unchanged. These measurements do not promise capacity elsewhere.

## Preserved seven-blocker result

The local 2026-11-02 run used the client lock SHA256
`8c7c738ea4db1ac5237d1c42e756a04f3b3690f6c7d2b6aa7fc6d1da058d24ba`
and policy SHA256
`02ff20bc1ddcadd52b895c68f249314c19fcb06e60f5104f09a92a7cde49af62`
from base `46a19cce1ce457943f80a2d134145ae386f2a0c5`. It verified 324 artifact
records from 320 distinct SHA512-verified compressed archives and seven complete
parent/alias/target bindings. **317 entries passed; the process exited 1.**

| Package | Version | Refusal |
| --- | --- | --- |
| @isaacs/nonrecursive-glob-match | 1.0.3 | BlueOak-1.0.0 outside policy |
| @isaacs/ttlcache | 2.1.5 | BlueOak-1.0.0 outside policy |
| lru-cache | 11.5.3 | BlueOak-1.0.0 outside policy |
| minimatch | 11.0.1 | BlueOak-1.0.0 outside policy |
| node-liblzma | 2.2.0 | LGPL-3.0 outside policy; optional node remains included |
| @nodable/entities | 3.0.0 | Historical missing text; now covered by the exact companion supplement |
| files-sdk | 2.4.0 | Historical missing text; now covered by the exact companion supplement |

The exact failed report is retained privately under
`c253-client-license-artifacts-20261102-attempt3`, SHA256
`e08d94430e03a343852bb45bdf1e852e4c6b2fed0a1370b77a9ed3503ade7882`.
Its input receipt records the then-uncommitted checker bytes; this historical
run is not relabeled as a run at a later commit. Every input and tool source was
rechecked at completion. It read 58,841,861 compressed bytes, retained at least
1,992,085,504 free filesystem bytes and a 6,788,477,704-byte available-memory
estimate, and observed no OOM-counter increase. These are local measurements,
not promised capacity on another machine.

## Evidence and boundaries

`scripts/client-license-gate.py` reuses the existing MCP gate's strict unique-key
JSON parser and SPDX evaluator, with the same pinned `packaging==26.3` identifier
catalogue. It does not call that gate's graph collector or advisory commands.
No MCP scope, lock, license policy or installed dependency tree changes.
The publication continuation added the original 55 seeded client controls to the existing
Python-checker CI environment. The test selector now includes the supplement
controls as well; their hosted execution remains pending. It does not run or waive the failing real graph
gate, and therefore does not establish production license enforcement.
The checker itself performs no npm invocation, installation, package script or
native execution. It does not scan advisories; existing advisory gates remain
separate.

The expected 324 nodes and seven aliases are explicit review boundaries. Every
resolved lock key is checked, with no host, dev or optional filtering. Empty
root dependency maps and absent empty maps are equivalent; nonempty manifest
and lock maps must match. Direct root dependencies must be exact pins. The root
`SEE LICENSE IN ../../LICENSE` reference must lead to the reviewed complete
repository LICENSE, SHA256
`e7a62762fe3dccd3c9e1a1fa3d2a0a2850b07a48ca48072542f3e5f2b66450ea`.
Changed graph counts or root license bytes need review, not a silent count or
license inference.

For each npm alias, the checker resolves the nearest enclosing `node_modules`
edge, validates its exact or stable `~major.minor.patch` range, and requires the
canonical name/version of the target archive. Other alias-range syntax fails
pending implementation and review. The parent archive's actual `package.json`
must contain the same alias edge. Reports bind the edge to both parent and
target archive and metadata hashes. An installed directory's name alone is
never alias evidence. Publisher-only `devDependencies` in dependency archives
are recorded separately: npm does not install that upstream development graph
as part of this consumer lock. This does not omit any root dev dependency or
any of the 324 lock nodes.

Every archive URL must identify its canonical package/version at the HTTPS npm
registry. Redirects are refused before following them. SHA512 integrity is
checked before parsing, including for cached archives. Package name, version
and SPDX license declaration must agree with the lock. Unknown SPDX identifiers
and custom license references fail even inside an otherwise allowed OR branch;
AND/OR/WITH retain their proper semantics. No exception file is read.

Archives are not extracted into package directories. Parsing rejects traversal,
links, special files, duplicate paths, oversized metadata and multiple roots.
The ordinary root is `package/`; legacy `@types` archives may instead use their
exact unscoped package name. Files named LICENSE, LICENCE, COPYING or NOTICE,
including suffixed forms, and files within a `licenses/` directory are hashed.
At least one archived notice or a verified exact companion supplement is
required. This records publisher declarations and notice
bytes; it does **not** classify every notice's terms, prove that an archive has
no other bundled components, or establish redistribution compliance.

One reviewed embedded notice is narrowly pinned: `@tokenizer/token` 0.3.0 has
its complete MIT grant, copyright and disclaimer in `package/README.md`,
not in a separate LICENSE file. Its archive SHA256 is
`911758ceca239c8e5372700eedfbbd514f16d3c117b5af0a648f6e720487c209`
and README SHA256 is
`a88c936c259cc261d5b37a2433735e9819e01f824bdc26e644d46ccd3055c8d7`.
The checker requires that exact package, version, archive and README, then
retains the entire README text and hash in the report. This is notice collection
under the existing MIT policy, not an exception. A label-only README, altered
text or artifact, another package, or another version is not covered.

## Running it

Use Python 3.11+ with the existing hash-pinned parser dependency from
`scripts/m3-test-dependency-gate-requirements.txt`. The checker requires
`packaging==26.3`; it does not install it. From the repository root, choose new
private evidence paths, create an empty artifact directory, and run:

```sh
mkdir -p /tmp/client-license-review/artifacts
python3 -B scripts/client-license-gate.py \
  --cache /tmp/client-license-review/artifacts \
  --notice-bundle /tmp/client-license-review/mit-companion \
  --report /tmp/client-license-review/report.json
```

The expected current result is **exit 1**, with five policy blockers.
Reports use exclusive creation: choose a new report pathname for every attempt.
The companion directory is also create-only. A failed partial directory is
retained and cannot be silently overwritten. Independently verify its exact
file set, full notice bytes, provenance and current lock binding with:

```sh
python3 -B scripts/client_license_notices.py /tmp/client-license-review/mit-companion
```

That verifier reports its two-supplement scope explicitly and cannot turn the
failed policy gate into a successful SDK or full-distribution result.
To repeat parsing against the same verified compressed artifacts without
network access, use `--offline`, a new report pathname and a new companion
directory. Missing or changed
cached archives fail; a previous report cannot stand in for the archives.
Offline mode does not rewrite existing compressed cache entries. Bounded
anonymous spool files may be used while parsing; no extracted tree is retained.

Requests are sequential, preserve inherited proxy/CA configuration, and have a
30-second socket timeout. The operation checks a 900-second deadline between
bounded reads; a currently blocked socket read can additionally consume its
socket timeout. Limits are 64 MiB per compressed archive, 512 MiB total compressed
reads, 256 MiB expanded per archive, 100,000 members, and 2 MiB per metadata or
notice file. Disk guards retain 1.5 GiB in the evidence filesystem and existing
`/workspace` and `/tmp` filesystems. Linux memory guards use the existing local
reclaimable-file estimate, requiring 4 GiB initially and 3 GiB thereafter, with
no cgroup OOM-counter increase. Non-Linux runs explicitly lack that Linux memory
measurement. These conservative bounds may refuse a larger future graph.

Run the deterministic controls separately:

```sh
python3 -B -m unittest discover -s scripts -p 'test_client_license*.py' -v
```

The 85 local controls pass: the original 55 plus 30 supplement and bundle
controls. They use actual synthetic compressed archives and
exercise canonical alias/parent binding, nearest-parent resolution, exact
integrity and cache rehashing, nonhost optional inclusion, root provenance,
unknown/disallowed/conflicting licenses, missing notices, embedded-text pins,
unsafe archives, source drift, graph-count guards, and bounded-resource/network
refusals. The added controls cover exact source/registry/blob/applicability
bindings, the disclosed version and root-license scope differences, actual
bundle creation, missing/altered/symlinked notices, final source and bundle
drift, and unchanged refusal of BlueOak/LGPL. Registry transport is mocked for
those controls; no npm or package
code runs. Their success is independent of the failed real graph result.

## Preserved correction history

The first control run had 44 passes and one error: the checker initially treated
an absent dependency map as different from an empty map. That source and failure
are retained; the corrected comparison has a dedicated control.

The first full artifact attempt is retained with report SHA256
`7a38c5e188d895258dfe6c80f3c9f4946a9ef27c4ff9157518724de906860aec`.
It exposed two collector assumptions: five `@types` archives use their unscoped
root, and upstream development aliases are not consumer lock edges. After those
corrections, a cached offline run verified all 324 nodes but retained eight
blockers, report SHA256
`7df3ab2cb7f96f6277e629e84fe1f832d8527ef74e3eadec0883ba7fe8fed4ef`.
That report's tokenizer notice failure is preserved. The exact full-README
collector correction then produced the seven-blocker result above. None of
these failures was changed into an approval or discarded as a retry.

The first supplement replay also exited 1 with the same five policy failures,
report SHA256
`f8293a75885231544d80445a9739b964a3ea6ed68b3f94e645a8df51ad0d310a`.
Its verifier SHA256 was
`7a5567a94798c1a2b6f8de92d6be71f67f4c499b1d552a3fca219c0e7b5f352f`,
with source receipt SHA256
`7fdc680f4b1db17f7e61ead6e83352b4c37bb63da9dad6b30dce7846c3adbede`.
Review then found that Python dictionary equality accepted boolean `true` and
floating `1.0` as the expected integer bundle schema. Both negative assertions
failed on that preserved verifier. Requiring exact canonical manifest bytes
closes the gap; all 85 controls pass, and the separate second offline replay
above binds the corrected source. The canonical companion bytes are unchanged.

## Reviewed source-bound MIT supplements

Exact-version npm registry metadata for the two remaining notice gaps matches
the lock tarball URL and SHA512 integrity, and supplies these `gitHead` values.
The GitHub file responses were fetched at those exact commits; their returned
Git blob SHA1 values were independently recomputed from the returned bytes.
The initial candidate lookup is preserved. The following exact notices now
have reviewed applicability records and a pinned supplement manifest under
`deploy/notices/npm`; no license allowlist was changed.

| Package | Registry gitHead | LICENSE Git blob SHA1 |
| --- | --- | --- |
| @nodable/entities 3.0.0 | d2070d76a8ba07e6c7fa142caeb51ffd756e47eb | 561468f111a66df52cc0f1934642bb9fdd22a212 |
| files-sdk 2.4.0 | a56c91381343ee017becf70c46b66c72cf9c1b09 | e653e969fe5a0288ea892ddf1a219d9066d8bfbc |

The candidates are repository-root `LICENSE` files in `nodable/val-parsers`
and `haydenbleasel/files-sdk`, respectively. Their text SHA256 values are
`750cb3fb6362804957ef52caaf9b5c824015be44d494637330d7cd8834d31d40`
and `e76b3f525b681b119e7284939032d1fd66e41d0d41b9e24dbe0170683562335c`.
Registry `gitHead` remains a publisher assertion, not proof that an archive
was built from that commit. Additional read-only source comparisons establish
the narrower applicability reasons:

- `@nodable/entities` lives in `Entity/`. All seven shipped source files and
  README match the pinned Git blobs. Its source manifest says `2.2.0`, whereas
  the published manifest says `3.0.0`. Replacing the source manifest's `2.2.0`
  version with `3.0.0` reproduces the published manifest byte-for-byte.
  The complete root MIT grant is
  preserved for the matching software. No exact-version source-manifest or
  full-package byte-parity claim is made.
- `files-sdk`'s published manifest is byte-identical to
  `packages/files-sdk/package.json` at its pinned commit and declares MIT.
  All 192 embedded source-text instances (141 distinct package paths) match
  pinned source-tree blobs. The root private `files-sdk-monorepo` manifest
  declares ISC, while the root LICENSE/README and the published package
  declare MIT. That scope discrepancy is retained explicitly; the supplement
  applies the complete MIT grant to the matching published package, not a
  universal root-manifest inference. Generated JavaScript equivalence,
  SLSA provenance and complete bundled-component obligations remain unverified.

The retained tokenizer
root-LICENSE lookup returned 404; its actual notice is already in its archive.

The supplement schema separately binds exact lock path, canonical
name/version, lock integrity, archive SHA256, package-metadata SHA256,
exact-version registry response SHA256, repository and package directory,
40-hex commit, notice path, Git blob identity, complete text SHA256, and an
explicit reviewed applicability reason. The module pins the reviewed manifest
itself; changing the records requires review. Controls reject changed package,
version, archive, registry binding, commit, blob, notice text and missing review.
The loader makes no network request, does not fetch a default branch's latest
LICENSE, and does not expand the license allowlist. Acceptance requires an
actually written and verified companion; source presence or a JSON claim alone
is insufficient. Final checks revalidate the source file set and bundle.
The BlueOak packages and optional LGPL package still require their separate
policy decisions described in the [coverage review](m6-client-license-coverage-2026-10-31.md).
