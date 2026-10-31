# Installed framework rotation gate (M4-68)

`verify-m4-fs-adapters-rotation` passed locally against the production
three-relay fixture at `3ebe8b48`: all four real frameworks crossed the actual
300-second scheduled rotation with writes in flight, then preserved unknown
outcomes under grant revocation. The first failed attempt and its gate-only
contract correction remain recorded below. This local result does not replace
final aggregate or hosted acceptance.

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
   control continues reading, and fresh revoked admission must return exactly
   `404 EXPORT_NOT_FOUND`: revocation makes that service undiscoverable under
   the [endpoint contract](filesystem-api.md). The nested `error.code` is parsed
   exactly; message substrings cannot satisfy it. Before/after owner snapshots
   must show no new stream, and a subsequent independently granted control
   socket must receive the immediately next actor stream ID. The actor allocates
   with `checked_add(1)` without reuse, so even a transient forbidden allocation
   fails. That control sends no 9P attach or data and is closed before teardown.
   The ambiguous outputs are neither retried nor rolled back.

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
collateral grant loss and detached cleanup. The first Rust build and all five gate controls passed. Independent review
then found unbounded consuming proxy/catalog shutdown calls in this new gate.
All branches now use the existing deadline cleanup APIs, retain errors while
continuing later teardown, and retain the connector join through transport
cleanup. The five controls pass again after correction. The first scoped
strict Clippy run found one collapsible-if style error; its log is retained
and the corrected strict rerun passed. A subsequent bin check caught three E0277
errors from the new dispatch arm using `?` inside `main` returning `ExitCode`.
The arm now uses the existing explicit async Result boundary. Scoped all-target
strict Clippy, the harness build and final format check passed at `29d91713`.
Both failed compile logs remain retained. Separate local evidence will not
substitute for final combined production acceptance.

## First actual attempt: failed, retained

Source `29d9171366a3aa81280901894c6f91f5601601ff` ran once on Linux through
the subreaper against a unique shared-Redis namespace at
`2026-10-31T06:29:31.294880+00:00`, exiting 1 after **308.540 seconds**.
The frozen harness SHA-256 was
`2e899a5631588661279226eb7ce5011aab34a2dbce64f3f1f4d270a9e311f678`.

The host writes were checked at 295.030 seconds, before the scheduled freeze
observed at 300.401 seconds. All four native read/write results succeeded,
immutable fences drained and committed with generation 1 to 2, and resumption
took 1.506 seconds. Recorded completed exchanges were 8 with exactly 20,480
written bytes; the one-byte host tamper was red; replay remained zero and
sockets settled from three to two. The subsequent four revoked writes each
reported native unknown/non-retryable outcomes, 1008, one sent write and no
Rwrite; the independent grant survived. These are completed subphases of a
**failed gate**, not full acceptance.

The final `revoked_admission_refused` predicate was false. The original helper
discarded the actual response status/body, so **the first wire status is
unavailable**. Source review found its expectation wrong: the catalog filters
revoked grants from discovery, the shared resolver cannot find that service,
and the filesystem endpoint translates the refusal to `404 EXPORT_NOT_FOUND`,
as required for an undiscoverable export. The gate had expected the
discoverable-but-disallowed case's `403 ACCESS_DENIED`. Only the gate expectation
is corrected; no authorization or production response changed. A new regression
first reproduced the old helper accepting malformed text that merely contained
the expected label. The replacement uses bounded structured matching and
failure-only closed-label diagnostics. Seven focused controls, scoped all-target
strict Clippy, the harness build, formatting and documentation guards passed
after correction, before the separately recorded second attempt.

After the first attempt, all 1,063 tracked source hashes, frozen harness/Node
hashes and 16,798 dependency entries were unchanged; the six owned processes
were gone and a bounded namespace scan found zero remaining keys. Its log
SHA-256 is
`7665f061c74fab0720bd3cd9e156138676ee3c961d29ec82344399128d9463b6`.
The failed attempt, runtime freeze and integrity receipts remain retained.
This leaf does not include every final aggregate correction and cannot replace
final combined or hosted acceptance.

## Corrected actual attempt: passed locally

Source `3ebe8b483d94b2062dcdd1952defcfc1d0250e50` ran once after the reviewed
gate correction, from `2026-10-31T16:42:52.684339+10:00` to
`2026-10-31T16:48:05.139533+10:00`, exiting 0 after **312.455 seconds**.
This was another full scheduled 300-second run, not a replay of the first
attempt's observations or mutations. The original failed log remains unchanged.

- All four writes reached the exact host image at **295.032 seconds**, before
  the scheduled freeze observed at **300.387 seconds**. Eight separate read/write
  streams crossed immutable per-direction fences. Every native call completed,
  the AI reference survived, and the same session/epoch advanced generation
  1 to 2 with **1.382-second** bounded resumption, zero replay, no recovery and
  no forced retirement. Socket peak was three and final steady state was two.
- The independent host oracle passed its complete file/directory comparison;
  its one-byte tamper control failed as required. Eight completed exchanges
  accounted for exactly **20,480 written bytes**, including AI preparation.
- All four subsequent revoked writes were dispatched and observed on the host
  before revocation. Within **468 ms**, each framework preserved a native
  unknown/non-retryable result with close 1008, exactly one Twrite and no Rwrite.
  The quiet observation window and exact host images found no replay.
- Fresh revoked admission matched exactly **404 EXPORT_NOT_FOUND** in the
  nested error code. No new actor stream appeared, and the next independent
  control received ID **14** after the last revoked stream's **13**, excluding
  a transient forbidden allocation. The independent grant continued working;
  non-owner filesystem admission remained the explicit 503 refusal.
- Joined cleanup completed. At `2026-10-31T16:48:28.072649+10:00`, all six owned
  processes were gone, a bounded namespace scan found zero keys, and all 1,063
  tracked source hashes plus the frozen Node and 16,798 dependency entries were
  unchanged. Both attempt binaries and the original receipt were preserved.

The corrected harness SHA-256 is
`06ebd4ad901fd5a8e5a76cad763d7d198da72698266ce8b3921127d8bcddfd4d`;
its log SHA-256 is
`0a3675931e6bc719ebfc5913a7a9363fde42e5648cbcfa9570b33e66e8501c88`;
the parsed evidence SHA-256 is
`56bfcb04ef91e681870bb0ea34c9dc7aed2de65bdc2bf5cacfb83074b26185f9`.
Pinned Node 24.21.0 has SHA-256
`7fde7b8afa198da66257f42ee2001d874c7355631e6d1579a5fb5ef1f246df4c`;
the retained dependency-tree digest is
`d6ce3dcf3876f8f86e52f24b8531dae0f8c6457ab87e7bc3243b81a26f4bce61`.

The full package check (601 offline and 33 installed-peer tests) was run at
`41746cf5`; all 58 recorded Node source/config inputs were byte-identical at
this live run. Seven focused Rust controls and scoped all-target strict Clippy,
build and formatting were run on the corrected gate source. This evidence
update changes documentation only. The Linux CI registration has not yet been
verified on a hosted runner, and the final aggregate must run its own acceptance.
M4-21's remaining boundaries, three-rotation framework compatibility, multi-user
isolation and filesystem peer forwarding are not covered by this result.
