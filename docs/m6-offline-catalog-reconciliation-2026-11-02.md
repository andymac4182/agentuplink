# Offline catalog proposal and retained #293 evidence

Status: production goal active; hourly automation remains disabled. Main remains
`626ba9365b5d3e1faf8265f0b6ff50cc9111b749`. The failed Fly rehearsal blocks
merge and production readiness. The successor below supplies offline source
work, not production recovery or deployment authorization.

## Exact #293 hosted checkpoint

[Draft #293](https://github.com/andymac4182/agentuplink/pull/293) has head
`867fd212f814c334c626f57ff8da837fc2a2b9ce`, actual hosted checkout
`b71a13e228ae46b30e0f3738cbb1da19029f3dba`, and shared tree
`db414265ca5ff657c1d52ad17c56b377d0447728`. At the retained
2026-11-02T13:28:17.372389Z observation, ordinary CI has 13 of 14 jobs successful;
M7 is still active. M0 proves 21 gates and 21 declared RED witnesses; M2 proves
three default rotations over 903.31128729 seconds. Three-OS packaging, all five optimized
build/native archive verifier pairs, all three Rust jobs, full M3 and full M4
pass. This dated observation does not claim M7 passes. Snapshot receipt SHA256
`7754d2aab47c0a070933c270b135447295b1d1208436afb1fd1027ce830f6681`;
M0/M2 source-bound receipt SHA256
`5cfaebcb77ee8b205d2894d195cc2846227645dd1912766f98a0b26d4b27b227`.

Both fresh authorization workflows pass independent review on that exact tree:
20 GREEN / nine compiled mutants / ten intended assertion RED / 20 restored
GREEN, and the original gate4 dispatcher GREEN / compiled whole-guard-deletion
RED / restored GREEN. The receipts bind 14 compiled artifacts, 16 launches,
source restoration and 110 normal child-group cleanup observations. Compiler
failures, absent matches and zero tests are not RED. Forced cleanup remains
mock-tested; escaped descendants and the literal broad four-crate CLI are not
claimed. Independent final receipt SHA256:
`705c3273ef4e62394b79495010b4ab01be14457bb58122b1f60b1b54e0376ff0`.

## Fly restart failure and diagnostic limit

[Fly run 41449999935, attempt 1](https://github.com/andymac4182/agentuplink/actions/runs/41449999935),
baseline job 125292562073, passes 338 hosted pure controls and builds four
source-bound images. It reaches three ready relays, all nine routes, and one
configured 300-second rotation on each of three clients. One exact
403/FORBIDDEN/not_dispatched scope refusal preserves the active grant and
positive controls. Revocation advances revision 1 to 2 with active=false;
all three ingresses return exact 404/DEVICE_NOT_FOUND/not_dispatched. The six
unaffected positive routes complete through the immutable successful control
flow, rather than individual success log events.

The helper disconnect passes: its strict stopped acknowledgement is followed
by independent original-client exit 0, PID 0 and no OOM indication. The later
relay-a restart fails `service_not_running` at `restart_revocation`, operation
`docker_container_inspect` / `serve-or-inspect`. Cleanup observes the same relay
container exited with code 1 and PID 0, without OOM. Combined container logs
contain the exact closed tuple `membership_bootstrap_not_ready`, category
`membership`, readiness `unready`, reason `membership_rejected`. Their
`lifecycle_attribution` is `none`: the underlying rejection variant and the
emitting lifecycle remain unknown. This observation does not diagnose the
historical #292 failure or establish a repair.

Post-restart readiness, fresh owner/session/epoch and persisted-membership
comparisons, and authority restart are unreached. Same-AOF recovery is skipped;
the dependent physical older-backup job 125300544489 is skipped. Successful
cleanup does not rescue acceptance. Artifact 13145725467 is 63,380 bytes,
ZIP SHA256 `30e558951a109957c841cb8e842faf3e5c64db92de32eaf3db17926e6facaad8`.
Result SHA256 `86a1c26b54e35422e192fd44da455ab8433077de4852c637c1b4a8944b0ba38e`;
failure-review SHA256
`f08baffd31d20e1c95a8c2911a3ce2d635c86f34aac7c1084efe82361b1d4c16`.

All four Linux amd64 images carry the actual checkout revision above. These are
Docker configuration IDs, not OCI registry manifest digests:

| Role | Docker configuration ID |
| --- | --- |
| authority | `sha256:490b40ca9b483ab96552ac6cc9f31a20405c5ebe0baafa25642a228c38775609` |
| client | `sha256:f8094ce11abd4bcc634d7b2c2bea8c63d5bd313b3d3e111ab68036dea1da9223` |
| redis | `sha256:7b649f402af026ed85cfef76e11ce6422d6d8111f010857b1078eb6e3f20348f` |
| relay | `sha256:c6bfe25b1624bcd7c7097407dc1034ba0d130f5f8329bd3f5456d2b596363207` |

The relay executable SHA256 is
`6dd97259169a37bdea722a53e3b91379ea48711f0a97ae7fafeca91ff37c9e8c`.
The failure receipt binds every executable and notice manifest. Cleanup records
47 removed containers with individual exact-ID absence and private log capture,
12 removed volumes with per-removal name checks and an empty final inventory,
one absent network, and 1,323 absent owned process groups. All commands satisfy
their expected status, including one intentional exit 3; there are no cleanup
errors, interruptions or OOM observations. Source and image identities remain
unchanged. This is synthetic Docker IPv6/fixture-CA evidence, not actual Fly
routing, public trust, capacity, backup custody or crash/fsync acceptance.

## Reviewed offline successor; native evidence pending

The separate source proposal adds only `catalog-bundle-check` and
`catalog-reconcile-plan`; the [command guide](catalog-offline-reconciliation.md)
states their precise offline limits. Checked local configuration selects the
deployment and Redis namespace. Bounded, hash-bound private inputs use the
existing recovery schema; the comparison refuses known rollback and writes
one private, create-only draft. Closed summaries always leave custody,
historical completeness and quiescence unproven, with `apply_authorized=false`.
There is no Redis connection, live exporter, apply command, approval consumption
or activation. The new file operations preserve existing Unix private-file
protections and refuse unsupported platforms; existing platform support is
unchanged.

The 16-file source freeze has receipt SHA256
`333c2d98a991461b3a4af343b88104c65ebb1682898bb8580a6b89623e212c9e`
and patch SHA256
`ef62d12990d5febea649e2acb446e6821c740681a8c0ab4d7efb1a8eaa3503a5`.
Independent core review is
`babfad592229fa203d553e9a5038ae36fbe14522806373bc9277f15a87b1adf1`;
independent CLI/private-file review is
`3175f38e056dd9eab0ea24dc902b203a6b6cffd72fade0b6db75b697b80796de`.
Both are source reviews. All 23 prepared Rust test functions, Rustfmt, strict
Clippy and native CLI execution remain unrun. Existing 338 pure/temp controls
pass against the integrated source bindings, with all 555 materialized files
unchanged; receipt SHA256
`6e66745ce0f4efba8a2471a25db002f766c67811dc0fd5d96143aeacbf9b43f1`.
Those local controls neither compile nor execute the new commands and are
distinct from #293's hosted 338-control run.

An optimized archive semantic witness is separate work in progress, pending
independent review and hosted execution. The existing curated archive help
probes do not prove these new commands. Required fresh evidence includes
formatting, strict locked Clippy, workspace tests, all applicable platform and
archive checks, and the complete required acceptance gates on the successor.
No native toolchain or quarantined runtime was executed locally.

The CLI reviewer's initial full-index-versus-abbreviated patch comparison is
retained; the corrected comparison required exact whole-patch equality. That
auxiliary review failure is not a product runtime failure. Earlier preparation
and hosted failures remain in their dated reports.

## Open production obligations

The production reconciliation adapter, complete independent backup/revocation
custody and externally anchored counter floors are still missing. Future apply
needs a durable pending/unknown interlock enforced by apply, recovery activation
and serving; this offline draft supplies none. Real Fly inventory/access,
PKI/OIDC, fencing, rollback and operational owners, alert delivery,
capacity/24-hour soak, C259 advisory work, five C253 and three M3-50 policy
refusals, C256 quarantine and M4-47's security block remain open. No license
exception, platform reduction, completion row or live-deployment authorization
is introduced. The [#292 report](m6-fly-relay-restart-2026-11-02.md) and earlier
failures remain dated evidence.
