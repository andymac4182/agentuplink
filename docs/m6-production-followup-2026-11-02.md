# Current-source follow-up after the Fly correction

Production readiness remains open. This successor preparation starts from
reviewed Fly candidate #286, head `1da066dd61f6535fe11f160e63d674aaa27faff7`,
tree `36c9597ff65fe41523a15d05d5b05e9cac93c959`, which includes main
`626ba9365b5d3e1faf8265f0b6ff50cc9111b749`. Its own source remains frozen
while hosted verification proceeds. The actual #286 checkout
`02ce5072dc845da3f1e877bb66a09a81c1fc99a1` has the same tree and parents
main `626ba936` and head `1da066dd`. New changes here need their own final
candidate checks; an older candidate's success cannot verify them.

## M6-C261: IPv6 rehearsal port publishing

[Fly run 41402204064](https://github.com/andymac4182/agentuplink/actions/runs/41402204064),
job `125136258412`, builds all four Linux amd64 images, verifies their five
executables/notices and completes preparation. It starts Redis, then fails
`published_port_scope` during bootstrap after 44.192 seconds. This is a new
failure after the earlier logger correction; both failed candidates remain
failed. Authority/relay startup, routes, rotation, revocation and restart proof
are unreached.

The last acceptance command is ordinal 174, `docker container inspect` on
owned Redis container
`bfa4ec0729bc43d61a04c7814c399b94c39249333b4372583423dcab49598bf4`.
It exits zero with empty stderr and 12,249 stdout bytes, SHA256
`b8ca759bd6bd558625e4df4ad1e4123ff5f716fc962fb631850d255bb6cdd08e`.
The subsequent assertion requires exactly one `6379/tcp` binding whose host
address is `127.0.0.1`. Source requests that IPv4 loopback address on an
IPv6-only Docker bridge (`--ipv4=false --ipv6`). The actual raw inspect value
is deliberately not uploaded: absence, null, wrong cardinality and wrong host
address are **not distinguished** by the retained failure. Do not infer one.

| Role | Actual Docker config SHA256 |
| --- | --- |
| relay | 55096d2687e1e3fcac7438c170ceb85943bd753ee3554e8925eb32f31aa40784 |
| authority | 3aeb3ec7aae920e0ba6705c57143905f6a83c1c839fa59be13cd478f45a40ba3 |
| redis | 318bfef08daf4b26937c8f0727080c2f0cc6194aef8c3a3484b8ff82c0f0a228 |
| client | ea4bb62c52b0463bfeb364c93025390573e4f6183938d3813530ef00e4644476 |

These are Docker config identities labeled with actual checkout `02ce5072`,
not published registry manifest digests. Full executable and notice identities
are retained in the image receipt, SHA256
`3225c32ebfabe7d4697a1b9f97631c0e912789d6d2274fa3a42c0edfcb792d10`.
The sanitized nine-file artifact is `13122172190` (18,811 bytes), ZIP SHA256
`6a52e57635e15ae1dd098a4d1ea35682c1946057abb01da02ecf8b74d3950c66`.
Result SHA256 is
`97098856be061408cc6814a58ad24b665656324818952d7073cb64acd393b57f`;
combined failure/identity receipt SHA256 is
`b995a06039eb76dacc6d2491e44e90023cb8afe16350eb285bc9eb2bb5cf6f01`.

Cleanup has zero errors: all 20 owned containers, 12 volumes and one network
are removed and independently absent; all 321 recorded command groups are
absent. Final source and image identities are unchanged. This cleanup pass is
specific to #286 and does not change #285's five log-capture failures or C256's
local unjoined-process quarantine.

The successor correction preserves the IPv6-only network and exactly one
loopback mapping, using bracketed IPv6 loopback publishing and the same IPv6
address for controller connections. TLS names, certificate verification,
bootstrap assertions and timeouts stay unchanged. Closed binding-shape
metadata will distinguish future failures without exposing raw inspect data.
Source controls and a new actual-image run are required; no local Docker run
or successful hosted correction is claimed here.

Canonical Docker documentation supports bracketed IPv6 loopback publishing,
omitting the host port for ephemeral assignment, and IPv6-only user-defined
bridges. Docker's parser tests include `[::1]::6000/udp`. Current Moby source
omits IPv4 publication when the container has no IPv4 address and does not use
its IPv6 path for an explicitly IPv4 host address. Six retrieved source files
are pinned by Git blob and SHA256 in design-review receipt
`dd98dfbdfd913e0c00985a4be0726c34deedafc6ab40e07d45907cb634699e39`.
This supports the correction's design without identifying the historical
daemon source version or reconstructing the omitted inspect value.

The corrected controller SHA256 is
`80e4f31df9ffec744f02bb39b6709327d15b60e3abe88dbdb2b3466264d8cfa8`;
its tests are
`4e20657665e386d08153f495a4768b7bd5d71c34e2a4fcb9a61d1bc455a86f38`.
Four targeted original-source controls fail at six intended assertions. The
corrected suite passes 64 pure/mock/temp controls; all 57 prior tests remain
byte-identical after removing the new class. Source handoff SHA256 is
`e73a930062d1abd2da34a341216714dc67f48d5fa326f59a60d5af6635318f06`.
Independent review finds no source blocker, verifies the constrained AST delta,
strict canonical host port, closed diagnostics and preserved TLS/HTTP names;
review SHA256 is
`0b0665369ca4a52833f8dbf5c56fbbbc99149c731f8e4783bc6b1c7dafa1d295`.
No new Docker or native execution is included in these local checks.

## M3-53: abandoned HTTP handler ownership

The [open-PR audit](m6-fly-continuation-2026-11-02.md#current-open-pr-review)
finds #251's handler-lifecycle correction absent from current main. The two
Rust files exactly match its pre-change blobs. The isolated adaptation restores
the reviewed patch: abandoning an exchange cancels an unfinished response's
handler token and aborts a still-pending spawned handler. A completed response
remains uncancelled. Explicit cancellation still awaits its handler; a drop
requests abortion and does not synchronously join the child.

The [M3 report](m3-cancellation-followup.md) records both exact Rust blobs,
four regression tests and original hosted checkout
`2f1ff78bc215ce2cb8b172ddbdc57d07097bdacf`. Its historical PR CI passed
all 11 then-required jobs, including all four tests and full M3; its separate
push CI was cancelled. Those results remain historical. Current Rust/M3/full
CI and all five optimized archive verifiers are still required. No local Cargo,
native, container or package execution was performed under C256's quarantine.

The source preparation receipt has SHA256
`cc134deb1b1da024fd4c79a35c2e2533f5bb390f273ad5835c30c3b0f77ec01e`.
An overbroad documentation-link check also found an unchanged pre-existing
`docs/tasks.md` link to missing `tcp-connect.md`; that failed check is retained
separately from the new-link checks. M4-47's recorded security rejection,
filesystem report semantics, wire framing and queue/deadline bounds are unchanged.

Independent source review finds no concrete blocker, verifies both Rust blobs
and all four tests, and confirms compatibility with the current connector's
abort ownership. Review receipt SHA256 is
`c3886bee46c588a0c6e55cba98c45c8ea33b10cb08151e4d3f35bd2b18dea164`.
That review does not execute current native tests or establish process-wide
cleanup from test-runtime teardown.

## M0-11: closed diagnostics for failed witnesses

#253's proposed failed-witness diagnostics are absent from main. The current
mocked journey fails one missing-diagnostic assertion. Its original proposed
tail-based diagnostics separately fail two synthetic disclosure assertions:
unrecorded private-key body bytes and arbitrary payload text can survive even
when required sentinel domains are nonempty. This is evidence against that
proposed path, not a claim of a new observed disclosure by current main.

The adaptation emits only fixed diagnostic labels, byte counts and SHA256 for
bounded stderr; captured text is withheld. Classification examines at most
16 KiB. Incomplete domains, unavailable data, over-bound data and unclassified
output remain explicit. Witness acceptance, failure status, capture and cleanup
behavior are unchanged. Pre-existing clean-run tail/error behavior is outside
this narrow change; no whole-scanner secrecy completion is claimed.

Eleven mocked diagnostics tests, the same two disclosure controls and existing
scanner unit probes pass. Both baseline failures remain retained. Independent
review verifies all three source hashes and 22 evidence hashes, normalizes the
whole module AST to prove prior acceptance/capture/cleanup functions unchanged,
and reconstructs the original CI workflow after removing the new test step and
comment edit. The new hosted M0 journey is still required; these mock checks
do not diagnose the historical ACP witness failure.

| Evidence | SHA256 |
| --- | --- |
| Source handoff | dc2c5499be8989b22e80d661d489742866fd3a580bb39397b2f6feee3f4d628c |
| Independent review | 30799de042cf625191923e6fad7055cf10c0df78baa5cad04422053ddc12e1f3 |
| Scanner | c1df671edef7c62a72d479b39c15ff838bb01e70af181046468788eb156fe8b3 |
| New tests | 5d7bb8bff958e00df8bbd02fda1a2df344cb7293c49a3fdac094199bc1e51c80 |

## M6-C253: two source-bound MIT notice supplements

The complete initial client artifact gate failed on five license-policy entries
and two archives without complete notice text. The new slice supplies the two
exact MIT texts, source/registry provenance and a companion-bundle verifier.
It does not alter the allowlist, SPDX evaluation, lockfile, aliases or supported
platforms. The original archived `notice_files` remain empty; the report uses
distinct supplemental-notice evidence only after the actual companion files
have been staged and independently verified.

The [checker guide](m6-client-license-gate.md) preserves two applicability limits.
Nodable's published 3.0.0 archive has eight source/README files matching its
pinned commit, but that commit's package manifest still says 2.2.0; its other
metadata bytes match after the explicit version substitution. files-sdk's
package manifest matches 2.4.0 exactly, and 192 embedded source instances over
141 paths match its pinned subtree. Its private monorepo root manifest says
ISC while the package metadata and root README/LICENSE identify MIT. That
scoped discrepancy is explicit; generated JavaScript and build provenance are
not claimed verified from embedded sources.

The final module passes 85 pure/temp controls: all 55 previous test ASTs remain
unchanged, with 30 additions. An earlier manifest comparison incorrectly
accepted JSON `true` or `1.0` as schema `1`; its RED is retained, and the
correction requires the exact canonical manifest bytes. The second bounded
**offline** artifact replay verifies all 324 lock entries and seven aliases,
with 319 passes and exactly five unchanged policy failures: four BlueOak
declarations and optional node-liblzma's LGPL-3.0 declaration. No fresh registry
query, collector installation or package execution occurs. The initial
seven-blocker report and first five-blocker replay remain retained separately.

The actual two-text companion bundle verifies. This is not proof that an SDK
package, release archive or downstream distributor ships it, nor complete
distribution compliance for all 324 dependencies. C253 remains open on policy
disposition, full enforcement and distribution integration; no exception was
granted to turn a failure into a pass.

| Evidence | SHA256 |
| --- | --- |
| Final publication slice | 6f9ab58463a17cff452af542ec50dbd895c09cab5fab6f91b2d26f0aa84bbc6b |
| Independent final review | 0ff6c1f6572970fd78bc11b2e6e4fa3a9544300b8a4fc3fb136dbf2bec071245 |
| Exact second offline report | 40133712127d841fb0a5cd93e83aeda8bd912b31d0b1539ff3e3ff8ba7e28804 |
| New notice module | 9814e7f12e4baf0d81baa842989b76954d1df4c70e5e7abb61d6c64ec2960025 |

CI's quoted `test_client_license*.py` selector now includes both original and
new controls. It does not run or waive the still-failing real policy gate.

## Integrated local verification

The successor checkout passes 236 pure/mock controls: 64 Fly, 85 client-license,
76 CUA-audit and 11 failed-witness cases, plus the existing scanner unit probes.
All reviewed source hashes match. Changed-Python AST, the 51-file declared-format
secret scan, whitespace checks and the evidence guard pass; the guard checks
606 verified rows with zero findings. Exact integration receipt SHA256 is
`f90d8ef27a4993cd6c253a69e31a1c5c998d44496d666bca5cd6b8fd5ffc1311`.
No current Rust binary, real M3/M0 fixture or Docker cluster is executed locally.
Hosted checks, optimized archives and the next actual-image rehearsal must bind
the final publication head and its actual runner checkout before any merge.

These source fixes do not grant license-policy exceptions or authorize live Fly
deployment. Account/inventory/PKI, independent recovery, capacity/soak and
operational ownership remain separate. The goal and continuation remain active.
