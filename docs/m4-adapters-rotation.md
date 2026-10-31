# Installed framework rotation gate (M4-68)

`verify-m4-fs-adapters-rotation` is being implemented against the production
three-relay fixture. Its first Rust build and real-resource run are pending.
The TypeScript driver preflight is not rotation or relay acceptance evidence.

The gate uses the installed Files SDK 2.4.0, Mastra 1.65.0, AI SDK 7.0.94
with `@ai-sdk/provider` 4.0.11, and just-bash 3.4.2. Four isolated Node children
use the shared client sources and verified consumer TLS. Mastra uses its real
Agent/Workspace tool loop; the AI upload uses `ai.uploadFile` and the real
FilesV4 instance supplies download. Scripted models require no model service.

## Running it

Use Node **24.21.0**, pinned in `packages/client/.node-version`, Rust **1.95.0**
and the committed lockfiles. Install dependencies before starting the fixture:

```sh
cd packages/client
npm ci
npm run check
cd ../..
export TEST_REDIS_URL=redis://127.0.0.1:6379/
export TUNNEL_CATALOG_REDIS_URL="$TEST_REDIS_URL"
cargo run --locked -p tunnel-test-harness -- verify-m4-fs-adapters-rotation
```

The Redis endpoint must be an authorized test primary. The harness creates
an isolated namespace and removes only its own catalog data. The gate is
registered in `scripts/m4-harness-verify.sh`; its Linux CI job installs the
exact framework dependencies first. Existing platform checks remain present.
Allow a quiet fixture/build window: the scenario has a 480-second bound plus
bounded setup and joined cleanup. A missed staging window is a failure, not
a reason to retry mutations, force rotation, or accelerate the policy.

## What the checker requires

1. **Real policy and live authority.** Both peers use the unchanged default
   300-second interval, 10-second handshake and 30-second overlap. The fixture
   runs its existing 15-second membership re-signer. Its synthetic consumer
   token explicitly lasts 900 seconds; the fixture's default 300-second token
   would otherwise confound rotation with expiry. Authorization freshness,
   request/composite deadlines and idle bounds remain unchanged.
2. **A known scheduler origin.** Actor snapshots bracket initial session
   insertion within one second. The timer starts there, not at `wait_ready`.
   Short completed canaries keep the framework sessions live. Operations
   rendezvous near 285 seconds, before their selected request allocates a tag
   or dispatches bytes. A ready-to-send event is never dispatch evidence.
3. **Host effects before freeze.** Near 295 seconds the fixture pauses only
   the identified old carrier's connector-to-relay direction. The actual
   framework requests are released. Every write must reach its exact host
   image before the earliest possible scheduled freeze, while its reply is
   still unobserved. Four read and four write sessions have separate owner
   stream IDs, so one stream's fence cannot stand in for the other adapters.
4. **Immutable fences and bounded completion.** Every selected response must
   be sequenced within the connector fence but beyond the owner's received
   cursor. Repeated samples retain the same attempt, snapshot, digests and
   complete per-direction fence maps. After release, both fence sets must be
   acknowledged, commit accepted and the old carrier retired. The same
   session, epoch, tags and fids complete through each real framework; the
   AI reference and all client sessions remain reusable. Two steady sockets
   and a temporary third are required. Recovery, replay and forced retirement
   fail this clean-rotation case.
5. **Independent effects and replay checks.** The host checker compares the
   entire synthetic file/directory set and exact contents. A real one-byte
   tamper must turn that checker red before the original fixture is restored.
   After the eight rotation sessions close, their completed exchange reports
   must total exactly 20,480 written bytes: four 4,096-byte test writes plus
   the AI reference's preparation upload. Identical positioned writes can
   leave an unchanged checksum; the host-write counter and observed Twrite
   counts supply the additional evidence. Missing reports do not count as zero.
6. **Revocation preserves ambiguity.** Four explicit new framework instances
   send another held write each. Their host effects must exist before grant
   revocation. Consumers must close 1008 with an unknown, non-retryable native
   outcome and no held acknowledgement or replay. Files SDK retries remain
   enabled; Mastra's public tool error content must retain `[unknown]`; the
   AI upload must retain its incomplete path without returning a reference;
   just-bash must expose its structured failure. An independently granted
   control continues reading, and fresh revoked admission is denied. The
   ambiguous outputs are neither retried nor rolled back.

The non-owner consumer path remains a **refusal**: 503
`BACKEND_UNAVAILABLE` with `DEVICE_NOT_OWNED_HERE`. This gate implements no
filesystem peer forwarding. It also does not close three-rotation framework
compatibility, multi-user isolation or M4-21's complete boundary suite.

## Evidence so far

At the source implementation stage on 2026-10-31, official Node 24.21.0 passed
the full package check: lint, strict typecheck, build, distribution lint,
**601 offline tests and 33 installed-framework peer tests**. Eight new peer
checks exercise the driver's actual framework calls and synthetic unknown
outcomes. Three new offline checks cover undispatched rendezvous, cancelled
producer release and deterministic host data. These use the loopback provider,
not a relay or the confined device filesystem.

A preliminary Mastra driver projection was red because `toolResults` excludes
failed calls. Its public `steps[].content` does preserve
`AUTH_EXPIRED (writeFile) [unknown]`. Reading that actual error surface made
the driver preflight green; no production adapter change was needed.

The Rust validator includes deliberate invalid witnesses for accelerated
timing, late host checks, undispatched writes, missing/changing fences,
uncorrelated replies, duplicate write counts, replay, incorrect revocation,
collateral grant loss and detached cleanup. Those Rust controls and the real
300-second scenario still require compilation and execution at an identified
candidate. Separate local evidence will not substitute for final combined
production acceptance.
