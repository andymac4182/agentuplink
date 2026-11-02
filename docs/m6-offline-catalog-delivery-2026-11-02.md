# Offline catalog delivery and retained #294 failures

This is evidence for [#294](https://github.com/andymac4182/agentuplink/pull/294)
and its reviewed successor, not production acceptance. The candidate is
`d55ffcfe0c1357bb4fa95b30ba0e2b45e729204b`; actual hosted checkout
`475ac05ce9fcf46a203ff2951a99471620fdd95c` has the same tree
`668827ea79c2e89e8bffda0947b80f9b11734ae0`. Main remains
`626ba9365b5d3e1faf8265f0b6ff50cc9111b749`. The continuous goal is active;
hourly automation is disabled. Prior [#293 evidence](m6-offline-catalog-reconciliation-2026-11-02.md)
and all earlier failures remain preserved.

## Current hosted checks and missing native coverage

At 2026-11-02T13:58:35.992623Z, ordinary CI run `41454503047` has ten passing
jobs, three Rust formatting failures and M7 job `125308210709` still active.
Snapshot SHA-256 is `cc5cc322fe479ceca02628f60ccd4d7b0014ebc6a969aee00d7a9a898652ec71`.
All three OS logs contain the same 24 formatting hunks across seven Rust files;
Clippy, workspace tests and example checks in those jobs were skipped.
The failure receipt is `01ad3fea45902dae5f0a317e1f7c1816b5c996f970dd96894c8e3a3262887f6e`.
The newly prepared offline catalog unit/debug CLI assertions therefore remain
unrun in those jobs. Other successful workflows do not replace this coverage.

M0 passes 21 gates and 21 declared RED witnesses; these are not 21 compiled
source mutations. M2 passes its actual three default rotations in
903.312918057 seconds with a 300-second interval, plus accelerated and fault
sequences. Their receipt is `7fce8107cfd8e27614fdbb69bddd38a887b06a377c583cd30e57ebf99566353f`.
M3/M4 pass, bound by `5a8d815ad5aa7db77564bd2b1a2a58e665aa5979ae166adce692a4e35484984f`.
Three-OS packaging run `41454502870` passes, receipt
`8cc363c3df45762cf1c7572967ea43f0d1a5ce92cc0710c5564542c9e3a74687`.

Optimized release run `41454502916` passes all five builds and five native
archive verifiers. Receipt `669fbaebf0201fecd1050177761bf457dbbea97d24df6c04ecb50ab1cb7957e0`
binds the five uploaded artifact identities and ZIP digests. These existing
verifiers execute 18 curated CLI probes on each of the three relay-bearing
archives and ten on Windows and the CI-only Linux ARM device archive.
They build the new offline code but do not execute its semantic commands.
No per-platform operation/rotation, release publication or new optimized
catalog semantic proof follows from those passes.

Fresh authorization receipts pass independent review
`fd64f75b6eaf91a9b8fe4433ab00e555e13d49d11d9a4acd34452496da9daa2e`:

| Workflow run / artifact | Actual proof | Receipt SHA-256 |
| --- | --- | --- |
| `41454502906` / `13146128347` | 20 GREEN, nine compiled mutants, ten intended assertion REDs, 20 restored GREEN; 11 compile hashes / 13 run bindings / 85 normal cleanup observations | `1a27a52c6b8c0c9974776b74f2ea9f0e94f7b1b22e39a327c1f7d2efd69ffe9f` |
| `41454502743` / `13145328504` | Original gate4: one GREEN, compiled whole-guard-deletion intended helper-line-219 RED, restored fresh-compile GREEN; three compile/run bindings / 25 normal cleanup observations | `376aa0304a13c052f04e924bf76162e9fb31b4341304c6f70157654d9be242b7` |

Exact current source, assertion/mutation identities and restoration are checked.
Raw compiler/test logs and executable bytes were not uploaded. Forced cleanup
paths retain mock-only coverage; escaped descendants and the literal broad
four-crate gate4 CLI are not claimed. These focused passes do not clear the
ordinary formatting failure or establish the new offline semantics.

## Actual Fly restart failure

Fly run `41454502878`, baseline job `125307625846`, fails at
`restart_revocation` with `service_not_running` after 397.072 seconds.
Artifact `13146034802` has ZIP SHA-256
`665523897812b4d02e4e4ac516e0088b3d94613b67c549c6ad99799a7d8520c4`;
result SHA-256 is `4e04bff4eda084e5846be956fa4659c08b7e137cabba6587412c7f4048eaad74`.
Independent failure receipt `5a11d2a56d8ba9564fc046935a381f310c9126249651739378c06a05857071b1`
binds source, binaries/notices, images, observations and cleanup.

All four actual Linux amd64 images record checkout `475ac05c`. These are
Docker image configuration IDs, not registry manifest digests:

| Role | Image configuration ID |
| --- | --- |
| Relay | `010d94cff0d4f34bf6f579c66c8f3849576e6e8074c4f345a27baea352eb32e7` |
| Authority | `cf995a1b83538f546c1c01b30814145ddab1b33f6391dd90349cb61a72f7a0f2` |
| Rehearsal client | `6ebbcd93864da6010906b58649ca5c2aac974fdbe2c840f6adef2a2e1183c3b9` |
| Redis | `2e8e88fc58e20c4bea319f1f6a97114c0a1e43cad9a7a945cda1b1ae71ee739b` |

Relay binary SHA-256 is `e0b117ceca39f5a51a59f64c81eca7b1e72098de6495cab3bde17c76f1c1eb5c`,
notice manifest `656536cf0a751aa8947016cb14d5bcc17d18713da425c612beb5a2b347e01e52`.
Authority binary is `25fefd442fed0971afda61edabbe599bc91a6b903a163461997cc75b8a8733a0`,
notice manifest `c94d787630e954cdb549e7b85d07edd674912d6725e517d9d818b2c136e723ec`.
Both differ from #293; old image proof is not substituted.

The run passes 338 hosted pure controls, bootstrap with all three relays ready,
nine routes, the exact scope-denial `403/FORBIDDEN/not_dispatched` with its
active-grant/positive controls, and configured 300-second rotation on all three
clients. The observed rotation monitoring loop is 296.864 seconds because the
clients were connected before it began. Grant revision 1 to 2 / active false
then produces three exact `404/DEVICE_NOT_FOUND/not_dispatched` responses.
Six unaffected positives follow the successful immutable control flow; they
are not individually logged. The distinct same-image helper's actual disconnect
passes, with a strict stopped acknowledgement and independent original-client
exit 0, PID 0 and no OOM.

The later relay-a stop/start commands succeed, but the same relay container
exits 1. Its combined lifecycle log is 3,324 bytes, SHA-256
`923d381e78af406cf3a982fc5847bb561442faa633e79a2a8d1b3778b9379dda`.
Exactly one closed observation reports `membership_bootstrap_not_ready`,
category `membership`, readiness `unready`, reason `membership_rejected`.
Lifecycle attribution is `none`; the underlying rejection variant remains
unknown. This does not identify which lifecycle emitted the observation,
attribute earlier failures or prove a repair.

Post-restart readiness/owner/session/epoch/membership comparisons and authority
restart are unreached. Same-AOF recovery and physical older-backup job
`125314775966` are skipped. Cleanup independently observes all 47 exact
containers absent, twelve volumes removed with an empty final inventory, and
the exact network absent. There are 1,347 normal command/owned-group cleanup
observations, no cleanup failure, interruption or OOM. Successful cleanup does
not turn the failed baseline into acceptance. This is a synthetic Docker IPv6
fixture with a fixture CA/echo, not an actual Fly deployment, production capacity
or backup durability proof.

## Reviewed successor: hosted execution still required

The exact format/Windows patch is
`c6090ccb5829dfc4a8db8bcb7047e0f1eda8433be3c1ce25225ef3c02be7afd0`,
independent review `b1bac00e22a277a4cee81222d6e6a63e2fd6a134e7cb070f393571fd74119d2f`.
It applies those 24 hosted hunks and adds an explicit Windows step for two
portable relay-library CLI argument/unsupported-platform refusal tests.
Existing workspace exclusions and all supported target scopes are unchanged;
this does not enable Windows relay serving. The formatting delta preserves
quoted literals and other tokens except optional trailing commas and relocation
of one unchanged import block; it is not claimed to be wholly token-identical.
Twenty synthetic text controls pass. No local formatter/compiler/native run
occurred. The source inventory is 22 applicable Unix / 14 current Windows
cases; the additive Windows step supplies two further cases, still unrun.

The archive witness v2 patch is
`7ba96097f0b25e81df886091f852b80e351ce7a7be857b84175098b78dde9dae`,
independent review `90764c5a56c29e47cd06258e0b9dd1dbb51608de98c9a8bf3e113a06cb3c9151`.
It adds bounded positive bundle validation/no-change reconciliation-draft and
negative wrong-hash/existing-output probes using the actual unpacked optimized
relay. Binary, repository fixture, private input and output hashes are bound;
fixtures come from the exact source checkout and are not shipped in archives.
All five existing target scopes/checks remain. The new commands apply to the
three relay-bearing archives; two device-only archives explicitly remain
inapplicable. Temporary inputs are create-only private files; macOS resolves
the trusted temporary root before strict path checks. Closed receipts exclude
raw records, paths and command output. Bounds are 30 seconds per command,
120 seconds for the stage, five seconds for owned cleanup and 64 KiB captured
output. No Redis, export, apply, activation, trusted custody, live-network
isolation or escaped-descendant proof is claimed.

There are 36 new pure/mock controls and seven unchanged verifier controls.
Retained negative controls reject late-finalization interrupts and cleanup
inspection errors that previously prevented scheduled KILL escalation; the
first failure remains recorded. These are mocked process controls, not actual
native supervision. Integrated receipt
`76ba9bccdd6ea0725fc5a0149e0972d70825c6d5cb6027f125060c2de307e4c1`
records all 36 passing and an initial five-error existing-verifier setup failure
because sparse examples were absent. After materializing unchanged HEAD
examples, all seven pass, receipt
`bd4b5a8c26474e8bd6a75da4ad1f81c908e5f524a8e9c2807992a13e8c1fa47e`.
Static checks of the exact thirteen integrated source/workflow files pass,
including unchanged Cargo.lock and the evidence guard, receipt
`302423859909de7c5f6a8812885cf46bfc1b001ab3a7cf948cae03e9ffe2f200`.
Preparation, normalization and review-helper failures remain retained separately;
none is relabeled as a hosted product failure or silently erased.

Fresh hosted formatting, strict Clippy, workspace/platform/native CLI tests and
actual optimized archive semantic execution are required on the successor.
The relay restart failure and both recovery scenarios remain open. This report
includes no unreviewed restart change. Production reconciliation/apply tooling,
independent complete revocation/backup custody and external counter floors are
still missing. C256 quarantine, M4-47's security block, C253/M3-50 policy refusals,
C259 advisories, actual Fly access/inventory/PKI/OIDC, operational ownership and
capacity/24-hour soak remain unchanged. No completion cell, platform assertion,
license policy or production criterion is waived; live deployment remains
a separate unauthorized action.
