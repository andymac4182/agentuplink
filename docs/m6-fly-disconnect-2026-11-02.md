# Fly disconnect continuation after the authorization checks

Production readiness remains open. Candidate #291 supplies fresh authorization
mutation evidence and reaches the two distinct HTTP refusal contracts in its
actual image rehearsal. That rehearsal then fails during client disconnect;
relay/authority restart and both recovery scenarios remain unverified. The
proposed helper correction has independent source review and pure/mock evidence;
actual hosted execution remains unrun.

## Exact candidate and ordinary checks

| Identity | Value |
| --- | --- |
| PR | [#291](https://github.com/andymac4182/agentuplink/pull/291) |
| Head | `bad8a26c4eacbe7d25e90c5106d08098c08c5105` |
| Actual hosted merge checkout | `3e63fdd12b1dd37f0b0cc43a3992f79c68e75429` |
| Shared tree | `18ac0514619a83833963496aeabf58145eb79613` |
| Base/main | `626ba9365b5d3e1faf8265f0b6ff50cc9111b749` |

[Ordinary CI 41437447489](https://github.com/andymac4182/agentuplink/actions/runs/41437447489)
completes all 14 jobs successfully at 2026-11-02T12:14:11Z. M7 job
`125251271156` records the implemented suite passing at
2026-11-02T12:14:06.6039403Z. The earlier 13-pass/M7-active snapshot is retained
separately. All three Rust jobs pass formatting,
strict locked Clippy, workspace tests and example checks. The named M4-76 tests
pass 20 on Linux/macOS and 19 on Windows, retaining the original Unix-only
provider case; all four M3-53 regression names pass on each platform. Full
M1/M2/M3/M4, TypeScript, regular container smoke and M0 pass. M0 records 21 gates
and 21 declared RED witnesses; M2 completes three actual default 300-second
rotations. Regular container smoke is separate from the failed cluster rehearsal.

[Packaging 41437447065](https://github.com/andymac4182/agentuplink/actions/runs/41437447065)
passes on three OSes. [Optimized validation 41437447143](https://github.com/andymac4182/agentuplink/actions/runs/41437447143)
passes five builds and five native archive verifiers; attestation/publication
are skipped. These checks do not execute a complete operation and rotation from
each archive. Artifact ZIP digests remain distinct from inner archive checksums;
no large release archives were downloaded locally. The separate push CI has 14
cancelled jobs, while push packaging passes all three jobs; those outcomes do
not replace PR evidence.

| Ordinary evidence receipt | SHA256 |
| --- | --- |
| Three Rust platforms and named tests | b0c918d6b00f0bf212b4a97f23639321ece3ddfbbb4ac1f346cc4c6b2218a063 |
| Full M3 and M4 | 7f4427a91cd02e928757c5d23b2fb89305fc3518ce0c50b9d95edac007680c84 |
| M0 and M2 | e05eb74763150ba5c182ce0a695f09df1c45e8619ca6f1dd47089cc954681373 |
| Three-OS packaging | eade8e386a7380774b5f11509de7dc744e25f86a3dca22c32482e03ee5ef4f84 |
| Five optimized build/verifier pairs | eb9914e9d101b4a5b60f957ec2c1bba44cd85bff8f65ea636568ba7fde055d3d |
| Earlier ordinary job snapshot, M7 active | d76cda4e4c2564482b4f681fe1249c87a33b93479860ce9ae6e061dfe81f9c11 |
| Final M7 and all-14 ordinary CI success | 45cf2211d8a4edcedb98a63c43a0a2f7b5a93a49fd01cf40d5d7e32dedfb38ad |
| Final regular-check aggregate, all eight head runs terminal | 0fe886e1233b4052a47adc975ed445a175369b295e97852dd907f33e1865423e |

## Fresh authorization mutation proofs

[Nine-mutant run 41437447129](https://github.com/andymac4182/agentuplink/actions/runs/41437447129),
job `125250689575`, passes 20 initial GREEN tests, nine successfully compiled
mutants with ten intended assertion failures, and 20 restored GREEN tests.
Eleven compiled artifact identities and 13 exact launch/pre/post hash bindings
are retained, with 85 normal direct-child reaps and absent owned process groups.
The original and restored binary SHA256 is
`a45f61ee40a056b5362615031e936ac7d164d963f41d2e59e6127ae43eecd927`;
all nine mutant binary hashes are distinct. Artifact `13138165232` has ZIP
SHA256 `d3cc5eae14a473321b45d40f1418c559617f6170fb5615b56ed92e584c37a1b4`.

[Original gate4 run 41437447286](https://github.com/andymac4182/agentuplink/actions/runs/41437447286),
job `125250690877`, passes the unchanged original dispatcher witness, compiles
the exact original whole freshness-guard deletion, observes exactly its intended
closure-helper assertion failure at `tests/support/mod.rs:219`, then restores
the source, freshly compiles and passes the same witness again. The original
`GATE4_CASES` declaration, `WITNESSES`, test and helper assertions are unchanged.
Three artifact identities and three exact launch/pre/post hash bindings are
retained, with 25 normal child/group cleanup observations. Artifact `13136334250`
has ZIP SHA256
`35a7acfa7612311cc1246e5a1c2f68052c02ab783a9e7226aacd93b869a7f331`.
Original/restored binary SHA256 is
`0d01e9a7e428352ced03126c6dc14785e6c8bef627a41ed9484d9c7fa5f90560`;
the compiled mutant is
`c262e1eebc479a50fa67c7fc5714e118bbecce82a1d5f70681c33baa02259d07`.

This satisfies the focused original mutation/witness property previously
missing from #290. It does not execute or claim the literal broad four-crate
`fs-guard-deletion.py --suite gate4 --case ...` wrapper. Neither compile failure
nor zero selected tests is accepted as RED. Both workflows restore exact source
and preserve their test hashes. Independent review checks the closed receipts
against the immutable controller/source contracts; raw compiler/test logs and
executable bytes were deliberately not uploaded or independently re-read.
Forced timeout/TERM/KILL and uncertain-cleanup paths remain mock-tested only;
escaped descendants are not observed or claimed joined.

| Authorization evidence | SHA256 |
| --- | --- |
| Nine-mutant closed hosted receipt | 93503e695fb9461f3c575326a3597470788da8d4ab78a4cd1c9174dc160191a6 |
| Nine-mutant independent review | ed26e602359c6460b01017bb2d660096703aaa219f76c6d4882cfba13978be8a |
| Original gate4 closed hosted receipt | 0d7bd006c805103e11d531f81bdff9aa83ed07a420ac42b7697a8649715a1eed |
| Original gate4 final handoff | bbef4712fa2ca9a5aa6eeb885f3bc122dca1dc35f379758206fbb46a6b554d80 |
| Original gate4 independent review | b680f4b5a37e13d5da422c4748ba987e7a366dd946da56558a2ffc9236eda907 |
| Combined independent review manifest | 52fa5e32199f25972959ef9c488d2b08639069b5c46b582a252b68c611584b5e |

The reviewer's initial auxiliary AST validator omitted annotated-assignment
support. That failure and source are retained; the corrected validator accepts
the original annotated declaration. This was not a hosted failure, source
change or rerun. The older #290 proof and its original-case gap remain historical
evidence, rather than being rewritten with #291's result.

## Actual image failure after scope and revocation checks

[Fly run 41437447273](https://github.com/andymac4182/agentuplink/actions/runs/41437447273),
baseline job `125250690889`, builds four Linux/amd64 images from actual checkout
`3e63fdd1`. All three relays become ready and nine exact routes pass. One
under-scoped-token response is exactly 403/`FORBIDDEN`/`not_dispatched`, with
discovery, active grant and positive echoes before/after. After actual grant
revocation from active revision 1 to inactive revision 2, three responses, one
per ingress, are exactly 404/`DEVICE_NOT_FOUND`/`not_dispatched`. The other six
routes remain positive. These are distinct fixed contracts, not a 403-or-404
accepted set. They do not reconstruct #290's omitted unexpected response.

Each of the three clients completes a configured 300-second rotation to
generation 2. The recorded 297.39-second observation starts after the clients
connected and is not itself a 300-second observation interval. The run records
57 route rounds before continuing to restart/revocation work.

The first unexpected failure is command ordinal 1018, `docker_container_exec`
for client-0 in `restart_revocation`: exit 137 after 0.186 seconds, with empty
stdout/stderr. Immutable source/order identifies the explicit
`tunnel-client disconnect` before any Docker stop or relay restart; the recorded
subcommand `connect` is stale metadata, not proof of a failed connect. The client
main process is separately observed exited with code 0, PID 0, no OOM flag and
empty error before cleanup. Exit 137 and those observations do not establish
its signal origin, an OOM, a particular Docker race or a successful disconnect
acknowledgement. Its mechanism remains unknown.

Cleanup completes after a total 397.368 seconds. All 45 removed containers and
the network have successful exact-identity absence checks. All 12 volume
removals succeed, and the final namespace-wide volume inventory is empty;
intermediate namespace-wide inventories are not each claimed empty. All 1,296
owned command groups are observed absent, with empty command-cleanup failure
lists and no cleanup errors. Of these commands, 1,295 satisfy their declared
expectation, including the intentional exit-3 credential negative; ordinal 1018
is the sole unexpected failure. All 45 log captures pass. Final source/images
are unchanged and sampled OOM-kill counters remain zero. Cleanup success does
not repair the failed acceptance or C256's separate local cleanup quarantine.

Relay restart, authority restart and same-AOF recovery are unreached. The
dependent physical older-backup job `125257618540` is skipped; no physical
capture/restore/recovery result follows from its source controls.

The nine-file artifact `13139180087` is 56,708 bytes, ZIP SHA256
`a3f8e40c3fbbd53e9aa3d563a36f40e68d0296ea333cdf76fa3769c3e4c8241b`.
Result SHA256 is
`0d3444bcba71fb922e28bd2c4e604d2aa6e98e5dc993f9c0eb972edd76d412fa`;
failure review is
`16d4acc523e737f38ff5247de186a643bc25b0ad1c4ce16492c5444b0fbfdd66`.
Image receipt SHA256 is
`a8ceddc7be14d4b474ddc71e43a52c0723dee0c69bfb4ccebfbc115220d94e4a`.
It retains all five executable and notice hashes. The four image config IDs
below are not registry manifest digests and do not prove live Fly deployment.

| Image role | Docker config SHA256 |
| --- | --- |
| Relay | 2d06de3777a61894a2cdf8e1ab13cff155319bbff9516ef6a9f63cd424835b72 |
| Authority | 00ec7c17d56b9ca7495705c25396662ce8bad1e7939956755c5350317cd8f6a4 |
| Redis | 36febf4a9cfaedd018dc735df659ce877db69c16799479cb7e98e17429407368 |
| Client | 57ad82209c69889d279f7fce716ecccc611c302de0f77a4562100567c76ab36c |

## Proposed helper and remaining verification

An isolated, uncommitted helper proposal sends one real disconnect request from
a distinct owned client-image container as default `client:client` (source UID
10003), with no network and only the exact original profile volume mounted
read-only. It binds strict CLI JSON, `error: null`, the stopped result and
namespace-local supervisor PID to the pre-request device/status and original
container/profile. Setup and inspection stay inside the original 30-second
command bound. It then observes the original container's exit 0/PID 0/no OOM/
empty error under the existing 25-second bound, without issuing a second stop.
The separate nine-second owned-command cleanup reservation is unchanged.
Base restart, spare-client and both recovery paths share the helper. It changes
no Rust, image, authorization, rotation, workflow or resource policy.

The proposal passes 17 new focused pure/mock controls and 298 combined controls,
with all 281 existing test methods unchanged. A retained modeled baseline RED
runs the exact old disconnect method against a model where target PID 1 exits
and ends the reporting exec. It is not a live reproduction or attribution of
the historical exit 137. The first combined attempt failed because the sparse
leaf lacked two unchanged Rust files used by static checks. That failure stays
retained; materializing the existing source enabled the separate passing repeat
without weakening assertions. Composition evidence pins 174 unchanged existing
function ASTs and the permitted helper/container-validation changes.

| Proposed helper evidence | SHA256 |
| --- | --- |
| Source patch | 0f1ab37ef770c5d1954602b0be133cbb8f8b94ce575b5c9d420eb3af94b037d0 |
| Source/control receipt | 7509d7961beab81713b5b1df5ab953bc130665f81f994b0c9eb35f45ff2912ce |
| Independent source review | 7adb97b2010ae7819b771a5523d3f61d566a8ec589f291cb84b280fbee40836c |
| Modeled baseline RED receipt | bc246838d6d2ca60bc4ce50a503bd4a6ae6c01a927c394ef5d64b5952ddd3e36 |
| Retained failed combined setup | 58456787467af8534aa26d6402fdefc1ef6cd593a225d0ab73a64e7a956f85cb |
| Passing combined control receipt | 51d6dd089f6593714377382869c223790fd1cbd26a5bddbc9d27b249f2be7476 |

Actual cross-container pathname-socket access over the read-only mount, exact
default UID, one successful disconnect receipt and clean original process exit
remain unrun for this proposal. Independent review finds no concrete source
blocker and verifies the unchanged assertions, bounds, default account and
exact profile binding. A new complete hosted baseline/restart/same-AOF/physical-
backup chain is required. Connector
stop ordering does not prove every unrelated task or supervised child was
reaped; the existing CLI bounded child-reap warning remains unchanged, and this
fixture exports echo only.

All production completion rows remain open. Synthetic physical custody still
does not provide a production reconciliation CLI, an independently trusted
revocation ledger, allocator high-water custody or operator backup custody.
Actual Fly account/app/machine/volume inventory, registry digests, PKI/OIDC,
operations, capacity/24-hour soak and deployment authorization remain unresolved.
Five C253 license-policy refusals, C259 advisory findings, M4-47's recorded
security block and C256's local native/cache quarantine remain. No license
exception, platform reduction, live deployment or local native/compiler/
formatter/Docker/Redis/cache execution is part of this update. Earlier failed
attempts and completion history remain intact.
