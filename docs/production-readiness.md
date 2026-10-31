# Production deployment goal

Status: active; production readiness is not yet established.

Goal: make Agent Uplink deployable with a repeatable release, verified recovery,
and evidence for every production blocker. Requested by the owner on 2026-10-31.
Review baseline: `c749a78432c2d863572a601a7935abf73fa193a2`.
Reviewable hardening changes: [draft PR #260](https://github.com/andymac4182/agentuplink/pull/260).

This document tracks the deployment review and its next actions. Existing task
IDs in `tasks.md` retain their acceptance criteria. A historical green gate is
not evidence that the current release is production ready. The existing
three-relay requirement remains in scope; validating the shipped single-relay
Fly profile is an intermediate step, not a reduction of that requirement.

## Completion criteria

- [ ] A clean build and the required Rust, TypeScript, packaging and dependency
  checks pass at the candidate revision.
- [ ] The shipped deployment image starts from a fresh configuration and
  enrollment; an authenticated consumer reaches a device over verified TLS.
- [ ] Tenant isolation, revocation, reconnect, scheduled rotation and bounded
  shutdown pass through the deployed topology.
- [ ] Backup restoration, simultaneous relay/Redis restart, credential rotation
  and rollback have tested operator procedures preserving revocations.
- [ ] Cluster authority, membership refresh, device liveness and key rotation
  have production implementations and regression evidence.
- [ ] Supported MCP, filesystem and ACP flows pass using real clients; CUA
  remains disabled until its operation-level authorization and VM gates pass.
- [ ] Capacity limits, monitoring, alerts, secret handling and incident ownership
  are configured for the actual target.
- [ ] A release artifact and deployment plan are ready for review; live
  deployment verification is recorded separately from local tests.

## Prioritized work

| Priority | Work | Evidence / existing tasks | Closure condition |
| --- | --- | --- | --- |
| P0 | Deliver the external cluster and recovery authority | M6-C22; no `tunnel-authority` workspace member | Shipped signing/publishing/checkpoint commands and executed recovery/cluster procedures |
| P0 | Verify the credential-rotation procedure before expiry | M6-C56; same-device renewal remains owner-deferred because the relay cannot register its new SPKI. Re-enrolment as a new device is the approved workaround | Execute re-enrolment, grant migration, old-device revocation and restart; deliver same-device renewal separately when taken up |
| P0 | Prove durable recovery | M6-C82; the single-relay continuity witness is process-local | Simultaneous restart recovers with an independent witness; rollback remains refused; restore drill completed |
| P0 | Preserve quiet forwarded sessions across peer idle expiry | M6-C229; compatible owner heartbeat fix and real positive/red controls pass; full acceptance pending | Real quiet-session proof beyond the production idle window, compatible heartbeat and vanished-device controls |
| P0 | End vanished forwarded device sessions | M6-C68; ingress timeout implemented; real positive/red controls pass | Real cluster network-cut test releases ownership and reconnects within the declared bound |
| P1 | Stabilize cluster membership and key changes | M7-C80/C81/C83/C86/C131/C150; M8-C46/C47/C48/C61 | Repeatable re-sign, trust-expiry, rotation and restart acceptance |
| P1 | Finish limits and real adapter acceptance | M4-21/68/70/72/73/74; M3-12/13/37/41/42/44 | Enforced advertised limits, long-lived stream behavior and framework clients across peer hops/rotation/revocation |
| P1 | Establish load and recovery budgets | M6-03/C125/C126/C183/C192/C201 | Off-host multi-tenant load and soak at declared capacity, with explicit latency/error/recovery targets |
| P1 | Close release and operator verification gaps | M6-01/C217/C220; M3-50 | Exact candidate checks, clean-machine archives and executed deployment guide |
| P1 | Configure operations | M6-C218; private metrics exist, privileged-change audit is deferred | Scraper, alerts, retention, certificate/JWKS rotation and incident/restore ownership verified |
| Restricted | CUA is not eligible for ordinary production enablement | M5-C28/C29 and remaining OS/backend gates | Per-operation caller grants, revocation, lease expiry and dedicated-VM acceptance |

## Current verification

- Repository cloned and pinned to the review baseline; no live deployment changed.
- Baseline hosted CI passed: [run 36727171198](https://github.com/andymac4182/agentuplink/actions/runs/36727171198).
  A development release exists for the same source SHA. This does not prove
  the deployed relay uses that image or that unresolved production gates pass.
- Local Node 24 candidate checks passed: 573 core tests and 25 real-framework
  peer tests, plus lint, typecheck, build and distribution lint.
- Packaging unit checks passed: 19 package tests, 5 artifact CLI tests and
  7 archive verifier tests; the documentation inventory check passed.
- MCP SDK 1.32.0 direct loopback interoperability passed 12 cases. The full
  `scripts/m3-sdk-conformance.sh` run passed all 76 SDK cases through the
  relay (nonce `m3sc-1793407048-83802-aa69ec`). Of 31 external conformance
  scenarios, 30 pass through the relay; the existing DNS-rebinding exception
  M3-49 remains explicit, rather than being counted as passing. It is an accepted
  exception for authenticated non-browser endpoints; Origin refusal is checked.
- Rust 1.95.0 formatting and strict workspace/all-target Clippy passed after
  the dependency/provider changes. Locked workspace tests passed: 2,825
  passed, zero failed, 99 ignored, across 168 suite results. The workspace
  uses a non-reaping PID 1, so the unchanged suite ran under a child-subreaper
  wrapper to reap exited orphan children; no test assertion was weakened.
  Ignored real-Redis gates are executed separately by M7 acceptance.
- Fresh RustSec advisories pass the existing policy after updating rustls,
  rustls-webpki, Tokio and webpki-roots and replacing the JWT RustCrypto backend
  with AWS-LC. RS256/EdDSA allowlisting and key validation are unchanged. The
  old dependency graph had eight new advisory findings; none was ignored to
  make the update pass. Existing test-only RSA and unmaintained PEM-parser
  exceptions remain in `deny.toml`.
- Python MCP test dependencies audit clean on Linux after the minimal
  OpenTelemetry API 1.45.1 patch. The full SDK conformance run also passes on
  Python 3.10 after fixing its missing exception-group backport import (M6-C228).
- Both npm trees audit with zero vulnerabilities. Mastra's existing 1.65.0
  Agent behavior is retained; a scoped MCP-server 2.3.0 override is verified
  by four real SDK tests, including two tests shown failing on version 2.0.0.
  Consuming applications must apply that override in their root manifest too.
- The actual Fly Dockerfiles built successfully. Candidate image plus rebuilt
  candidate client passed `deploy/fly/local-proof.sh`, nonce
  `m6c60-proof-20261031T003837Z-85148`: verified TLS, enrollment, echo, all seven
  catalog commands, revocation, 169 ms orderly shutdown, relay restart,
  Redis-down refusal, AOF recovery with real device traffic within 60 seconds
  and a fresh relay startup. Serving containers were capped at 256 MiB.
  This proves a local container deployment, not the live Fly machines.
- M1 real-socket acceptance and M2 accelerated rotation/fault gates passed.
  Three actual 300-second rotations also passed with 18,913 records. The full
  M7 is being rerun for the final heartbeat change. An earlier local attempt
  stopped at an absent uuidgen utility after its Redis integration tests passed;
  a local Python UUID helper supplies that test-environment prerequisite.
- Actual Fly credentials, deployed image, certificates, Redis backup state and
  monitoring are not available through the environment's configured identities.
  Repository deployment notes are historical evidence, not a live inspection.

## Changes under validation

- M6-C68: forwarded device control now sends heartbeats and expires silent
  devices, cancelling both peer halves on exit. Three deterministic scheduler
  tests cover silence, continuing owner output and a Pong at the deadline.
  A real three-relay test now proves 70 seconds of healthy idleness followed
  by remote owner release within 30.05 seconds of a control-path blackhole and
  fresh same-device echo within 30.15 seconds. Disabling just the ingress
  timeout leaves OWNER_BUSY beyond 35 seconds. Full acceptance is still owed.
- M6-C229: the owner now sends existing protocol PING/PONG heartbeats while
  retaining an absolute inbound-only peer deadline. Without this fix, the
  regression closes a healthy session at 59.99 seconds despite answered WS
  Pings. With both fixes, 70-second quiet sessions and subsequent network-cut
  recovery pass. The combined real gate is registered in the M7 script.
- M6-C222: the Fly Redis image now limits the dataset to 160 MiB with
  `noeviction`; the container proof exercises refusal without eviction.
- M6-C223: the restore procedure requires reconciliation of later revocations
  before constructing a new namespace. Reusing an old provisioning file alone
  is explicitly unsafe.
- M6-C224: CI now includes the full TypeScript checks, high-severity npm audit,
  current RustSec advisories, and the actual Fly image proof. These new jobs
  must pass on hosted CI before the candidate is eligible for release.
- M6-C225: compatible SDK/test dependency updates and direct interoperability
  checks pass locally, including the scoped Mastra override. No advisory
  ignore was added to pass the gate.
- Current Rust dependency advisories are addressed and the candidate OIDC and
  transport unit/integration suites pass locally; all advertised platform builds
  remain a hosted gate.

## Deployment-specific work still required

The checked-in Fly configuration is one relay and one Redis in one region,
with immediate replacement and no automatic failover. It cannot provide
uninterrupted upgrades or high availability. Do not scale it to two relays
without the cluster configuration and external authority.

The serving configuration still contains an example OIDC issuer and requires
real JWKS, TLS identities and catalog provisioning. JWKS are loaded at startup
(`tunnel-relay/src/main.rs`, `start_serving`); coordinate overlapping IdP keys
and relay restarts before issuer key rotation. Consumer, device and Redis TLS
certificate expiry need monitoring and an executed rotation procedure.

Private metrics and readiness exist, but a scraper, alert routing, retention,
capacity alarms and privileged-change audit are not a complete checked-in
production deployment. Monitor readiness, device reconnects, owner/authority
failures, admission refusals, clock offset, queue pressure, memory, AOF disk
headroom and certificate expiry. Record acceptable outage, data-loss and
recovery budgets; single-primary Redis has no supported automatic promotion.

The tracker contains outstanding credential-rotation attestations (M6-C15).
This review did not establish that credentials outside the repository were
exposed. Reconcile that inventory using provider evidence; never infer that a
clean source scan proves the state of deployed credentials.

Desktop archives have GitHub provenance attestations and checksums, but OS
code signing/notarization remains separate. The TypeScript package is private
and exports source; decide its supported distribution mechanism before offering
an npm-installed SDK. CUA stays behind its non-default opt-in until operation
grants, lease cleanup and dedicated guest acceptance are complete.

## Next action

Complete M7 real-cluster acceptance and the quiet-forwarded-session fix, then package the
reviewed candidate. A focused vanished-device regression and the accepted
M6-C22 offline recovery-signer slice are in progress; neither closes the broader
cluster-authority and recovery goal on its own. Do not mark this goal complete while required
gates or deployment inputs remain unresolved.
