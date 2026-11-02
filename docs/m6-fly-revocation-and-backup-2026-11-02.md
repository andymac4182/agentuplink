# Fly authorization and physical-backup continuation

Status: production goal active. The successor combines reviewed source and
345 passing pure/mock/temp controls; its hosted image and recovery checks remain
unrun. The owner selected a continuous Codex goal and disabled the hourly
automation at 2026-11-02T11:07:33Z. Merge authorization persists for a fully checked candidate; live
deployment and license exceptions remain unauthorized.

## Exact preceding candidate

| Identity | Value |
| --- | --- |
| PR | [#290](https://github.com/andymac4182/agentuplink/pull/290) |
| Head | `43ff240cc3e9598936445251cd13353b53a3ebae` |
| Actual hosted merge checkout | `f599b3da14d8af08764d5a8b1ac41930f7522c2a` |
| Shared tree | `edd49363032ac79132ea7e68ef6bd832c76f20ec` |
| Base/main | `626ba9365b5d3e1faf8265f0b6ff50cc9111b749` |

[Ordinary CI 41419300448](https://github.com/andymac4182/agentuplink/actions/runs/41419300448)
finishes all 14 jobs successfully at 2026-11-02T09:55:50Z. All three Rust jobs
pass formatting, strict Clippy, workspace tests and example checks. Named M4-76
tests execute 20 on Linux and macOS, 19 on Windows: the queued-provider test has
its original `cfg(unix)` and passes on both Unix hosts. All four M3-53 regression
names pass on each platform. Full M1/M2/M3/M4/M7, TypeScript, existing container
smoke and M0 also pass. M0 observes 21 actual gates and 21 declared RED witnesses;
M2 observes three actual default rotations over 903.349610792 seconds.

[Packaging 41419300334](https://github.com/andymac4182/agentuplink/actions/runs/41419300334)
passes on three OSes. [Optimized validation 41419300536](https://github.com/andymac4182/agentuplink/actions/runs/41419300536)
passes all five builds and five native archive verifiers. Attestation/publication
are skipped. Workflow artifact ZIP digests are distinct from inner archive
checksums; native CLI/portability verification does not execute a full operation
and rotation from each archive. No large archives were downloaded locally.

The separate push CI remains cancelled, with 13 cancelled jobs and one advisory
job success; this is preserved independently from PR success. All seven known
head-associated runs are terminal. Final ordinary-check receipt SHA256:
`95f96d5e1d8b6da06eef5903f89d8c3762e4ace833a19091cbb601157b7994e9`.
Earlier #289 formatting failures and all prior image failures remain evidence.

## Fly failure and C266 contract correction

[Fly run 41419300581](https://github.com/andymac4182/agentuplink/actions/runs/41419300581),
job 125190720607, builds four source-bound images. All three relays become ready,
all nine routes and a configured 300-second rotation progress. The baseline then
fails `authorization_negative_status` at `restart_revocation`, operation
`https_echo`, after 394.363 seconds including cleanup. Its recorded
`failure_subcommand: connect` is stale last-command metadata, not evidence
that the connect command failed. The real grant-revocation command exited 0;
the first subsequent negative echo failed its expected-status assertion.
The actual unexpected response status/body was not retained. Source inspection
does not reconstruct it. Same-AOF recovery is skipped.

Cleanup retains 45 removed containers, 12 volumes, one network and 1277 owned
command/group observations, including one intentional exit 3 credential-negative
command. These cleanup results do not turn the failed baseline into a pass.
The owner review receipt is
`13427878653e3c589a8ae6523741325221de795951c2ba176b38abea1c1ad4f8`.

The uploaded closed-proof artifact is 13129349449, 55,011 bytes, with ZIP SHA256
`9f66dd32cc639679093b1e1efccc52d5256563bf3fccb4ab432f1b48306dea22`.
Its `result.json` SHA256 is
`b64bf1ac377781cda13fe0504f46938f874d3e02a53fffb17d2a9ec0a10e8e71`.
The following identities are retained in the repository so their values do not
depend on artifact retention. All four images are Linux/amd64 and carry revision
`f599b3da14d8af08764d5a8b1ac41930f7522c2a`. Image IDs identify Docker image
configurations, not registry manifest digests.

| Image role | Docker image config ID |
| --- | --- |
| Relay | `sha256:995735229071f9995328cc583461a466ff691d65f8553edd5e26839c077db126` |
| Authority | `sha256:cc3235256e7a424c18acbccc5c42143fef6600d5852b867ec5882bc7414fc97a` |
| Redis | `sha256:5cb25061f3ec744d2d0c13a44ccc4daf42bdf072822cec41f73ad9916841e444` |
| Rehearsal client | `sha256:0876729f339d4fc5a8d3e07562ae9aedb4e0c94eb4b9f2afdfd69eb43952f760` |

| Executable | Binary SHA256 | Notices manifest SHA256 |
| --- | --- | --- |
| `tunnel-relay` | `6dd97259169a37bdea722a53e3b91379ea48711f0a97ae7fafeca91ff37c9e8c` | `ea6da5fd8febbb71ca628a1bf20527c02f659c796351577f73d4e8bdbe5a87fe` |
| `tunnel-authority` | `75a244f6896da55b1944aa539ecac1c15b54a219bc2f828aacfc896674ac7fc7` | `4250fff00009a1f4bd69106420e5765221b3d5be69f1b8d124cc70bd2bdc6179` |
| `redis-server` | `a775ade32bc71fc06684b1cfae8ef4a68c7aa57fb402c836cf5d0063333719ab` | `a77b6beef70547c4caf8ecc362dcdb5f8fa536c6ca0cd914485066e36c98b3db` |
| `tunnel-client` | `3b49a9ad41195ef31953ad11275ddfd7983685b501b7cafef5a4db1c44c778db` | `d9c2ec1251ae47b15492052529ba6c3b16f6ab8989fb4574d9e6d6deebae43df` |
| `tunnel-deadman` | `a14944fd2fa8e262faeaee911ac6a0b5f3289cf2c98ecdb72d7297eb31ded3b7` | `8551e47327bf9454b12e354730e018721415f472f53f39b5a70876692baba136` |

The reviewed successor separates two API contracts with fixed expectations:

- A correctly signed JWT from the same key has insufficient consumer scope.
  The target remains discoverable, its grant remains active, and exact echoes
  succeed before and after the negative. The negative requires precisely 403,
  `FORBIDDEN` and `not_dispatched`.
- Revoking the fixture's sole grant hides that device from the principal under
  the existing privacy contract. The real revoke command must change catalog
  `active` from true to false and strictly increase its revision. Each later
  check requires that exact inactive state and precisely 404,
  `DEVICE_NOT_FOUND` and `not_dispatched`, with no successful echo. The other
  six primary routes remain positive; secondary recovery-principal checks keep
  all nine primary routes positive.

This is not an accepted 403-or-404 set. It changes no product authorization or
privacy behavior. The historical unexpected response remains unknown. Closed
response diagnostics retain status, bounded body size/hash and fixed field
classifications before refusal, without raw bodies, credentials or error text.
`not_dispatched` and absence of echo are protocol assertions; no independent
backend invocation counter is claimed.

C266 patch `51c8d8a7a1740a981ad105322bc8dc670e8b90a45ce0887ffe5924c5eff1b5a5`
and independent review
`f6b8d0badfb6cd5cd4d8db5a74b54c789789d8a5f6767be114ff492aae61ec9e`
retain 235 source controls and their earlier failures. New actual-image
baseline, restart, revocation and recovery evidence is required.

## Two recovery scenarios and physical custody limits

The same-AOF controller remains a separate required scenario. The reviewed
physical-backup source adds `--scenario older-backup` in a separate workflow job
which requires the baseline and same-AOF job to succeed first. It builds fresh
images from the same immutable workflow commit and uses exact build receipts.
Its private copies are synthetic Docker fixtures, not backups of a live Fly
deployment.

The physical fixture captures the complete bounded multipart-AOF tree while
Redis is paused after persistence checks and before relays, authority or clients
serve, with independent file copies and manifest/hash/ownership checks. The
original primary resumes with the same process/run identity and unchanged
catalog; its volume is preserved. It then records later real
revocations and retains the latest bounded catalog independently. Restoring the
older physical tree must demonstrate the older active records before explicit
reconciliation from that retained latest catalog. Unavailable, partial,
ambiguous or inconsistent custody fails closed before approval/serving.

Physical setup now records the exact secondary grant proof returned by the
reviewed real-revoke path. Inherited recovery assertions compare that proof
after reconciliation and across recovered publication/adoption rounds. The
primary/secondary principals and grant proofs remain separate. Existing fencing,
fresh incarnation/session, approval-counter, revocation and cleanup assertions
are retained. The 1500-second main, 180-second cleanup and 30-second adoption
bounds and resource floors remain unchanged.

Physical patch
`6767fc7fd3108ac21f0faacca9e53cd2c6f515208e043bb680c6ac991af943f7`
has independent source review
`897ddedf87b714670e8212fa985f630849434430634b060635dde7cfbed7976c`.
Its 198 source controls include 44 physical controls. The workflow retains exact
reviewed bytes
`f185cb26e7ac745f9101b458dea882d860ac884baaee13017720ac7d25c2fa6d`;
only closed JSON/event receipts are uploaded, never AOF files, catalog snapshots
or private signing material.

This fixture does not supply a production reconciliation CLI, a complete
independently trusted revocation ledger, allocator high-water custody or
operator backup custody. Those operational and implementation gaps remain
explicit. Neither synthetic restoration nor the single-primary durability
profile authorizes promotion, automatic recovery, a second writer or live Fly
deployment. Both actual-image recovery scenarios remain unrun for this source.

## Authorization mutation evidence and original gate4 scope

[The nine-mutant workflow 41419300538](https://github.com/andymac4182/agentuplink/actions/runs/41419300538)
passes on #290: 20 initial GREEN tests, nine successfully compiled mutants with
ten intended assertion failures, and 20 restored GREEN tests. Eleven compiled
artifacts, 13 launch bindings and 85 normal child/group cleanup observations are
retained. Owner handoff
`67f5055335ed33c82791355decd958ad7b0120afc81c66c2dfe7584edb0cd9d5`
and independent review
`3045837e69cd7cea2048dd31c46c4d57640b40b89c0167b912be497343c24740`
establish that scope.

The original filesystem gate4 expired-snapshot mutation is a separate obligation.
Full M4 runs `verify-m4-fs-real-path`; it does not run that guard-deletion command.
Its ordinary named provider test passes on Linux/macOS, which proves only the
unmutated positive. The retained gap receipt is
`983a4e3a605ca8f350102516d1415cba7e0f4b002cb6ab9a1ab2c18fc450f733`.

The successor adds a focused controller bound to the exact original mutation
declaration and `WITNESSES`: one named dispatcher GREEN, successfully compiled
whole freshness-guard deletion, one exact intended helper-panic RED, exact
restoration/fresh compilation, then one named GREEN. It binds three compiled
artifacts and all three executions. This does **not** run or claim the literal
broad four-crate `fs-guard-deletion.py --suite gate4 --case ...` command, nor
repeat the separate 20-test gate. The shared artifact selector gains only the
reviewed explicit provider-dispatcher kind; its client-library default remains.

Patch `df9cc657044ef41297863166893b6c4815a5504121a4f6767b32e13d2981f18a`
and review `d07ad68262de352b0daefcc3f59c5da2fe0c52c055035d49ec5a5ba6f43ffcdd`
retain 64 fake/synthetic controls. The dedicated workflow uses a 60-minute outer
job and the unchanged 48-minute controller step, substantive push/PR paths,
read-only permissions and no cancellation of an active proof. Only its closed
receipt is uploaded. Actual GREEN/RED/restored-GREEN execution remains pending.

## Composition and remaining acceptance

All three exact reviewed patches apply cleanly from #290. The physical
secondary-proof assignment is the only manual controller composition. Recovery
`main` combines disjoint reviewed scenario-selection/reserve and diagnostic
receipt hunks. Two new mock composition controls fail on the uncomposed source
at two assertions, then pass after the assignment; that RED is preserved as
`151116dd978c83c53f70555e8e566b1d60370aa54d6320be215597c0412a216c`.
The combined 281 Fly, 42 shared-witness and 22 original-witness controls pass
without source mutation; receipt
`3494f75a911fdfc34fb0cb81599eb8e731dc000617c9ce7736616bc8842b7eca`.
An initial reviewer-only AST checker incorrectly assumed a function could come
from only one input and rejected the deliberately combined `main`; that failure
is retained separately from project tests. The corrected comparison records
the overlap explicitly and verifies all other reviewed functions unchanged.
Two independent combined reviews verify all 13 frozen source/workflow files,
the exact patch composition and retained control results without rerunning them:
`3a7f964a5b99177743b0b5ae7dc663a3efc198ec321422b24ec74ce692db220e`
and `e67ce05484f43758abb68163b4c069ca4803b521968ae676bde880ac34f7c08c`.
No hosted result is inferred from these controls.

The final candidate still requires fresh applicable CI, all supported platform
checks, exact-image baseline/same-AOF/physical-backup acceptance, and the focused
original mutation proof. Intended Fly account/app/machine/volume inventory,
registry digests, PKI/OIDC, trusted recovery custody, operator responsibilities,
capacity/24-hour soak and live access remain unresolved. Five C253 license-policy
refusals and C259 advisory findings remain; no exception is approved. C256's
failed cleanup/native-cache quarantine and M4-47's security block are preserved.
No local Rust/compiler/formatter/native/Docker/Redis/cache execution or deployment
occurred for this integration. No production row or milestone is completed here.
