# Client production follow-up after PR276

The goal remains active. This report keeps the hosted C244 correction separate
from C252's subsequent dependency graph. It does not authorize merge, deployment,
publication or a license-policy exception.

## PR276 hosted observer verification

Draft [PR276](https://github.com/andymac4182/agentuplink/pull/276) head
`2f3686b7615e74000a65be8a805e64b8060ffe28` and actual runner checkout
`2f30edffc45cb430f822ee76e3d7d9a011fef15f` share tree
`736c7bbc8247e89ec41b19313d05f2d997903a65`. GitHub Git-data and completed
job checkout logs independently agree. Source-identity receipt SHA256:
`66d05707366c43752c5ed77b536ad4ab353b9ed1745975dede5b0be0ea71984d`.
The tested code commit is decc5b58;2f adds only five documentation changes.

At2026-10-31T22:31:58+10:00,
[CI41199271719](https://github.com/andymac4182/agentuplink/actions/runs/41199271719)
has13 successful jobs and M7 remains running. No final whole-CI pass is claimed
at this observation. Saved jobs receipt SHA256 is
`fc8666d8f19631ef27b4559bd61ba1a8b16e8f765c01264a5cc0ffb4ebbe4999`.
PR packaging41199271752 and push packaging41199216502 pass.
Push CI41199216554 is cancelled and retained separately; no manual cancel/retry.
No new optimized-release workflow is observed. The original5909 release proofs
remain bound to their original candidate.

Full M4 job124531842192 passes. At12:10:18.059Z, C244 observes3 completed
exchanges,1 retained stream and0 replay frames, with the expected identity,
phase and zero mutations/writes. At12:10:18.088Z it accepts3/0/0 with every
original provider-probe, held-response, parallel-fid, confirmed-reuse, refusal,
pre-abort, unchanged-host/session and joined-cleanup assertion. The real pending
snapshot confirms why handler completion alone is insufficient. It does not
identify the discarded scalar in the historical PR275 failure.

The same job's four-framework actual300-second gate passes: host checked295031ms
before scheduled lower300405ms, resumption1403ms,8 completed exchanges/20480B,
zero replay/recovery/forced retirement, socket peak3→2, revocation440ms and
next-ID13→14 with no extra allocation. Independent grant/non-owner and cleanup
checks pass. Framework pins and Node24.21.0 match the prior graph; this is not
evidence for C252's new dependency tree.

All three Rust platforms pass. Ubuntu's hosted all-target scope is2931 passed,
0 failed,108 ignored across150 summaries; local decc workspace2938/0/108/174
includes doctests and is a distinct count. The original authority permission
test passes. The last relevant Rust platform completes12:14:20Z. Together with
the retained causal controls, required local checks and actual local gate,
this closes C244's declared confirmation/integration scope at
2026-10-31T22:14:20+10:00. Broader M4-21 and the expressly unclaimed
flushed-before-dispatch clunk schedule remain separate.

Fly job124531842303 passes its current relay/Redis smoke checks. Its authority
image is sha256:33d498971eb2a2aeb1b57f1f9c793e299356cd3e76183a05f205b838e8e6f521.
Hosted startup/default-user/help/refusal checks do not establish current actual
authority lifecycle or mounted-secret/state acceptance. The historical8c
image proofs retain their own identity.

| Saved decoded job log | SHA256 |
| --- | --- |
| M4 124531842192 |e6418cc6a4054b7efd8802f397e7e2a98d4c3e962b0273b7ae00d6f3460e942e|
| Ubuntu 124531842331 |72d6d50470a997c9ba203d8bd32ece0544892b5bd6dbea5c11c331ba9ef3293d|
| Fly 124531842303 |a91c9f893e1e2fb67f2cf5bdf7fbd813a580e5a6c1f3874f3dfc3bca0c04cc17|
| TypeScript 124531842265 |c8b538db7f8198ddc2f87afac02f61f37952086dade0a3067b07dea6a910f1ad|

These identify saved decoded-text copies, not original compressed log archives.
Review receipt SHA256 is
`5ec1d334824d877d02013fd6234e526878490a07fe7fde04657f421f3debc0df`.

## C252 dependency candidate

Clean `95eb2d83db9bd5cd2c30e84e950398600b7df76e`, tree
`2d4e64bad7570490ecd2537ebd30d6ed8c7caab0`, changes the scoped just-bash
override to minimatch11.0.1. Direct framework pins and adapter/Rust implementation
are unchanged. The lock changes minimatch10.2.6→11.0.1 and adds
@isaacs/nonrecursive-glob-match1.0.3; brace-expansion stays5.0.12.
The [separate C253 report](m6-client-license-coverage-2026-10-31.md) retains
the unresolved client license policy and coverage gap. Advisory correction is
not licensing approval.

GHSA-g3hv-75wg-m249 requires optimizationLevel>=2. The actual just-bash matcher
normally uses the default two-argument call. The bounded dependency controls
demonstrate upstream split/deduplication behavior; they do not claim a reproduced
exploit through the remote adapter's default configuration.

Local pinned Node24.21 validation passes610 offline and40 installed-peer tests,
lint/typecheck/build/dist lint in20.445s. Six focused matcher/Bash controls pass;
the final old-matcher negative has three intended failures and three ordinary
compatibility passes. Two earlier fixture mistakes remain recorded separately.
A fresh audit changes from two moderate graph nodes to zero findings.
The high-severity CI threshold is unchanged.

An actual npm pack plus two consuming-app lock-only resolutions passes20.230s:
the package's override alone leaves minimatch10.2.6, while the consuming root's
override resolves11.0.1. This explicit CI gate needs registry access, runs no
package scripts and creates no consumer node_modules. Offline checks remain
offline. The remote printf-glob control covers readdir expansion; separate
native quoted-ls controls exercise minimatch. Neither is mislabeled as the other.

The checked source was dirty during these runs. Independent comparison binds
72 checked inputs to the clean commit, with only subsequent README license
prose differing; no tested code, lock, workflow or fixture changed. New installed
dependencies are isolated at16809 entries, then frozen by removing write bits.
Canonical final tree SHA256 is
`3f2292d81614da9e77227568ec14d43940fec1643ddea2483819bfbe29d8aa12`;
the pre-freeze manifest preserves the deliberate mode change. Original Node
and16798-entry dependency proof remain unchanged. Actual300-second integration
and hosted verification for this new graph are still pending at this report's
initial preparation.


## C252 actual framework integration

The first actual gate at clean95eb passes in309.108s, exit0, completing
2026-10-31T22:40:24+10:00. Product300/10/30-second bounds and all assertions
are unchanged. Host state is checked295032ms before scheduled lower300374ms;
resumption1460ms,8 exchanges/20480B, no replay/recovery/forced retirement,
sockets peak3→2, revocation486ms and exact next-ID13→14/no extra allocation.
All native outcomes, independent grant/non-owner and joined-cleanup predicates
pass. This tests the installed graph on the real framework path; the separate
peer matcher controls remain the evidence for the particular glob algorithms.

The Rust driver is explicitly the older decc-compiled harness SHA256
`f510526b88cf1b5f18128a626537aee3736dab71d5de3f1a31f521db28013fc2`.
All556 tracked Rust/build/e2e inputs are byte-identical to95eb. The binary
embeds its original TypeScript checkout path, so ordinary reuse would test the
wrong dependency graph. A private checked launcher accepts only that exact
original driver argument/hash and redirects it to95eb's identical driver bytes
and new dependency root. It restores inherited proxy/guard variables removed by
the older fixture, combines inherited trust with the synthetic fixture CA and
keeps TLS verification enabled. No frozen source is edited. Fifteen fake-exec,
source, path, environment and process-membership controls pass before execution.
Earlier unexecuted controller revisions remain retained. Process inspection
was corrected before the run to retain zombies/unreadable metadata and require
independent process-group ESRCH; that review correction is not a test retry.

All four actual Node processes are observed executing95eb's driver with
minimatch11.0.1, not the original checkout. Before/after checks preserve1090
source files,16809 new dependency entries, original Node and28 protected proof
inputs. The original16798-entry dependency tree is also rehashed unchanged. Owned group649207 is independently absent without cleanup signals;
completed namespace scans are zero before/after, no fixture children remain and
its private root is removed. Minimum nonreclaimable-memory estimate is
6909541576B; minimum workspace/tmp free are1673379840B/1824985088B. OOM counters
are unchanged. Shared Redis is neither flushed nor restarted.

| Private native proof | SHA256 |
| --- | --- |
| Result |e71cf197396fc6d1bb1137681f7d0a9cf8160a9b0197bdbee5a543f3e4282b2b|
| Gate stdout |ea19d812c627d68bd6c2596a72954a04b9e5609ed1e3689b275be1f143963058|
| Gate stderr |cb5165a2ad162a5a9638e7a52313b0884c523f2e6c5cbc654b35adbcce6497aa|
| Reviewed launcher/controller handoff |1ec4369c3b84236e3a6669f7123778d1032ba40674f6b7bc0e9ff39fed3531ea|
| Root execution lease |4cc9ed4163301ed731a4a11dda302295e2efdd9ceac423e30817e9d484d1d3eb|
| Final native handoff |eaa30c749a682d77d3298857a0c071fe6dbe2c94075a8a47d7d5647371b96275|

Private receipts are in `c252-minimatch` and the retained
`/dev/shm/agentuplink-minimatch-evidence/native-attempt-1` attempt. They are local
workspace artifacts, not hosted or live-deployment evidence. Hosted C252 and
C253 licensing/enforcement remain open; no merge or deployment follows.
