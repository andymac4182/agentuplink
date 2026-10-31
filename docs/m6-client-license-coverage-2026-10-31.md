# Client dependency license coverage — M6-C253

The shared TypeScript client graph has no enforced license gate. Its existing
323-entry lock contains four declarations outside the current Cargo/MCP
allowlist. C252's advisory correction adds one more. This is a separate policy
and coverage gap, not a regression in an existing client license gate.
No license exception or SDK/platform reduction is approved.

## Exact inputs and findings

The clean baseline is PR276 head
`2f3686b7615e74000a65be8a805e64b8060ffe28`, tree
`736c7bbc8247e89ec41b19313d05f2d997903a65`. Its client lock SHA256 is
`bc3ea35fb09fe49c10fe366f057d289f303d8d30329b6dbc92925732c459e645`.
The initial review captured dirty C252 bytes at2026-10-31T22:23:56+10:00;
that historical capture is not relabeled as a clean commit. The same lock is
now present in clean C252 commit
`95eb2d83db9bd5cd2c30e84e950398600b7df76e`, tree
`2d4e64bad7570490ecd2537ebd30d6ed8c7caab0`, SHA256
`8c7c738ea4db1ac5237d1c42e756a04f3b3690f6c7d2b6aa7fc6d1da058d24ba`.

| Package | Baseline | C252 | Declared license | Introduced through |
| --- | --- | --- | --- | --- |
| @isaacs/ttlcache |2.1.5|2.1.5|BlueOak-1.0.0|@mastra/core1.65.0|
| lru-cache |11.5.3|11.5.3|BlueOak-1.0.0|@mastra/core1.65.0|
| minimatch |10.2.6|11.0.1|BlueOak-1.0.0|just-bash3.4.2; C252 root override|
| node-liblzma |2.2.0|2.2.0|LGPL-3.0|just-bash3.4.2 optional dependency|
| @isaacs/nonrecursive-glob-match |absent|1.0.3|BlueOak-1.0.0|minimatch11.0.1|

The existing `allowed_expression` evaluator, pinned packaging26.3 and unchanged
12-entry allowlist find319 satisfying declarations in each graph: four outside
the allowlist in323 baseline entries, five in324 C252 entries. Every declaration
parses. Compound alternatives pass only through their allowed MIT/BSD branches.
All324 installed C252 version/license declarations match the lock, with seven
legitimate npm aliases resolved to their canonical names. Installed notice text
agrees with the five listed declarations. This is metadata/evaluator evidence,
not independent tarball-integrity verification, a bundled-component audit or
approval of redistribution terms.

## Enforcement boundary

`deny.toml` and M6-04 cover the Cargo graph. The
[MCP dependency gate](mcp-test-dependency-gate.md) explicitly excludes the
separate client graph; M3-50 covers its two specified fixture locks. Client CI
runs checks and advisory audits, with no client license gate. A zero-advisory
result does not resolve C253.

The private client package has no direct runtime dependencies, but frameworks
are optional peers as well as development dependencies. Dev/optional flags do
not establish downstream absence. The universal lock and this installed graph
include node-liblzma. No optional or platform branch was omitted from review.

A future checker must handle the seven explicit @mastra/core `npm:` aliases:
two @a2a-js SDK aliases, two @ai-sdk/provider-utils aliases and three
@ai-sdk/provider aliases. Merely pointing the MCP checker at the client lock
would incorrectly reject their path-name/canonical-name differences. Bind the
alias edge, canonical artifact identity, exact version and integrity-verified
archive, and retain root LICENSE provenance and mismatch refusal controls.

## Owner decision and remaining verification

The owner must settle the client policy before license readiness can be claimed.
One option is narrowly scoped acceptance of exact BlueOak package/version/
artifact identities, with node-liblzma's LGPL component/use/distribution reviewed
separately. Another is compatible dependency replacements or an upstream fix;
none is established by this review. An older package approval would not silently
cover a new version or package. Neither option authorizes removing an SDK,
supported platform or optional branch from acceptance.

After that decision, implement artifact-aware alias-capable enforcement, verify
positive and planted-negative controls, and run the complete graph. C252's
functional/advisory verification can continue independently. The existing MCP
license decisions remain separate and unresolved.

Private evidence is retained under `client-license-coverage-2026-10-31`:
report SHA256`fd7d38696349f368a8f5f085768ba784bce67216b174c3e6eefb2d8b88ec6aab`,
inventory`6e6da184a6938eca5d8f2be4825d09d6d077d4d63ea7deb5ebe9cd0dfd93ac7d`,
manifest`ec8b8430e8745ee105c85afc9c0cfdff26f52fd1d12c5e1f9d6aa39a092c4768`.
The private historical input snapshots and review are unchanged.
