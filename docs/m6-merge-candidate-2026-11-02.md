# Consolidated merge candidate, 2026-11-02

The owner has authorized merging and selected Fly as the initial deployment
target. This authorization does not approve license-policy exceptions or a
live deployment. The production-readiness goal remains active.

## Candidate lineage and merge boundary

Main was independently observed at
`c749a78432c2d863572a601a7935abf73fa193a2`. It is the merge base of the
complete draft stack ending at #283,
`8c531ad4b2b922a0362709d7ca8cf037a58b94e3`, tree
`0515595c1dc0eb9aab2c33e2de9ba130006e0eaa`.
All 21 stack PR heads (#260 through #278, plus #282 and #283; #263 precedes
#262 in dependency order) are ancestors of that tip: 99 commits, 215 changed
files, 38,779 insertions and 966 deletions. Dependency PRs #279–281 remain
separate. Historical commit identities and failed runs are preserved.

The separate `codex/production-merge-candidate` branch starts at exact #283
and adds only the C257 workflow path correction and current documentation.
The original #283 source and active run are untouched. A merge commit will
preserve the full stack history. Before merging, verify the final head, main
base and proposed merge tree, all 14 CI jobs, three-OS packaging checks, all
five optimized builds and five native archive verifiers, and reviewer state.
Use GitHub's expected-head condition and verify the resulting parents/tree.
The expected-head condition does not pin main, so refresh main immediately
before merging as well. Do not merge an intermediate failing stack candidate.

Main reports `protected:false` and no effective branch rules. Detailed classic
protection inspection returned HTTP403; that access limitation is retained.
All 21 existing stack PRs had zero submitted reviews and zero inline threads
when inspected. This is not an approval or evidence about future comments;
refresh the consolidation PR before merge. Do not rely on repository protection
to enforce the acceptance boundary.

## #283 hosted evidence and retained local failure

The actual #283 checkout is
`b3e011e0f465c581d191e7e2e88e775a1719cee1`, with the same tree as its head.
The TypeScript checkout log independently confirms this identity. CI run
[41388058330](https://github.com/andymac4182/agentuplink/actions/runs/41388058330)
has 13 passing jobs at the observation recorded here; full M7 remains running.
All three Rust platforms pass their required formatting, strict Clippy and
workspace checks. TypeScript passes 610 offline and 40 peer tests with zero
failures and zero reported vulnerabilities; this is not C253 license approval.

[M4 job 125093435350](https://github.com/andymac4182/agentuplink/actions/runs/41388058330/job/125093435350)
passes the complete registered filesystem gate chain. Its actual 300-second
four-framework rotation retains the 10-second handshake and 30-second overlap,
eight completed exchanges, 20,480 written bytes, 1,550 ms resumption, 444 ms
revocation, zero replay/recovery/forced retirement and joined cleanup. The later
fid-confirmation gate also passes: three completed exchanges, zero streams and
replay, surviving parallel fid and confirmed reuse, refusal/pre-abort controls,
unchanged host/session and joined cleanup. The real provider controls are retained.
Decoded M4 log SHA-256:
`806fdfdc76648d26d4b8200d55fa265b00003878eab585893cf012d873f19622`.
Parsed evidence SHA-256:
`9a9aa75c306ba9f6c6617c6bc3781fa70851ce5432710a92cf03e13f453e4247`.

[Release check 41388058291](https://github.com/andymac4182/agentuplink/actions/runs/41388058291)
is completed/success, updated at 2026-11-02T14:33:25+10:00. All five optimized
builds and five native archive verifiers pass; PR attestation/publication are
skipped. PR packaging run41388058316 and push packaging run41387993280 pass.
The initial push CI run41387993322 was cancelled by existing branch concurrency
when PR CI started, with no manual cancellation or rerun.

These are #283 results, not verification of the later consolidation candidate
or of a live service. #282's discarded connector-cleanup error remains
unattributed; a passing diagnostic-only successor does not establish its cause.
The #278 accounting failure and every earlier failed attempt remain failed.

The separate local C256 attempt at `e3842fc5` passed formatting and eight focused
tests using fresh executable `ee2d9439`, but failed the unchanged Clippy memory
floor and left three PID1-owned zombies in group687144. Its result
`52528619de48db15241679181d2c3b86b189451ce22e312ad29a8869a8937d37`
is still failed. Native/cache execution remains quarantined; no PID1 signal,
frozen-helper edit or false ESRCH claim is permitted. The current hosted pass
does not relabel that failure. See the [complete C256 record](m6-fs-cleanup-diagnostics-2026-11-02.md).

## C257: notice inputs must trigger release checks

`scripts/package_release.py` now imports `scripts/container_notices.py` and
reads `deploy/notices/rust/**`, but the optimized-release PR paths and packaging
push/PR paths omitted those inputs and the collector's tests. Changes confined
to them could skip all archive checks. #283's executed matrix was unaffected
because it changed other covered files. C255's completed Rust-source trigger
scope remains separate.

Add exactly these three patterns to all three affected path lists:

- `scripts/container_notices.py`
- `scripts/test_container_notices.py`
- `deploy/notices/rust/**`

Eighteen static witnesses pass: twelve newly covered input/event combinations,
three retained matches and three retained nonmatches. Removing only these
additions reconstructs the original files exactly. Permissions, concurrency,
jobs, target matrices, fork/event guards and publication behavior are byte-identical
after the path lists. Static result SHA-256:
`3c347794cafa0c1806602cb0642d85af69bf696b638c2d1c6729008bf25e5b31`.
New workflow digests are
`faff982957f046da5a545119982a618b72bb16f2beef4f1cc8d2303fa196387d`
and `798420c05610d128bdbc648689d413990091b282aefd75c2847138639205f890`.
The final candidate still requires its own hosted matrix and packaging results.

## Development publication and production limitations

After a successful CI push on main, the existing release workflow builds and
verifies all five targets, attests the artifacts and publishes a development
prerelease containing four advertised archive/checksum pairs. ARM Linux remains
the declared CI-only target. The downloads page can select this new development
release. This normal merge consequence was explicitly communicated to the owner;
it is not a live Fly deployment or a production certification. No committed
workflow invokes a live deployment; external App/webhook settings were not
fully inspectable. Record post-merge CI, artifact/attestation and publication
identities independently; never transfer PR success to them.

License policy and platform declarations remain unchanged. M3-50's universal
MCP decisions, C253's four BlueOak declarations and node-liblzma LGPL component,
and C241's unresolved archive notices/Redis provenance and distribution scope
remain open. Rust archives do not contain the TypeScript peer graph or Python
fixtures. Their all-target notice inventory still explicitly records unresolved
eventsource-stream0.2.3 and rustls-platform-verifier-android0.1.1 notice text;
neither a metadata expression nor a passing archive verifier is full notice or
legal approval. No exception is silently accepted by merging this source.

M4-47 retains its account-security block. C240 public-endpoint/task-join scope,
C254 broader concurrent-reset/task-join scope, C251's historical causation,
the deployment inventory/PKI/OIDC, recovery ownership, capacity/soak, monitoring
and operations evidence remain separate from this source merge.

## Initial Fly target

The owner selected Fly. Existing `deploy/fly/` files describe a historical
single-relay setup in Sydney (`syd`) with `agentuplink-relay` and
`agentuplink-redis`. They are an intermediate profile, not the required
three-relay private-alpha deployment. The old document's historical live image
and app observations are not a current API inventory.

M6-C258 tracks a separate Fly cluster profile using the shipped relay, online
authority and durable Redis, retaining stable per-relay identity/state, private
HTTP/3 peers, verified public/device TLS, owner fencing, publication/checkpoint
authentication and tested startup/recovery/rollback procedures. Do not scale
the existing non-cluster relay profile into an unconfigured cluster.

No Fly connector, CLI, token environment setting or local Fly account config
was available when checked. Account/organization, actual app ownership, domain,
PKI/OIDC and live access remain unverified. Sydney is the existing configuration
default for planning, not a newly approved live-resource change. Prepare and
test the profile before any request to perform a live deployment. The hourly
goal remains enabled until every production completion criterion is evidenced.
