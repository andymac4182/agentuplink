# Three-relay operator recovery drill

M6-C243 adds a bounded, test-only local acceptance drill for the existing
M6-C22 recovery contract. **The corrected local optimized-artifact recovery
drill passes, along with a separate native authority lifecycle attempt.** The
source, prior failures and exact evidence scopes are recorded below. No
production service behavior changes, deployment or automatic reconciler are
included. Keep M6-C22 open beyond this local drill; combined-candidate and
hosted acceptance remain separate.

The test uses the shipped `tunnel-authority` commands and service and the
shipped `tunnel-relay` recovery commands and three serving relay processes.
The device uses the production Rust connector library compiled into the test
harness. The public HTTP consumer sends exact binary canaries through relay-a
while the device is owned by relay-b. This is not a device-CLI artifact claim.

## Independent operator inputs

The operator supplies a reviewed candidate incarnation, an independently
checked live Redis run ID, a complete approved membership inventory, a recovery
nonce, offline recovery signing authority, and evidence that every old writer
and relay is fenced. A restored Redis database cannot attest that its own
authorization records include every later revocation.

This synthetic drill retains an older physical RDB backup and, separately, a
bounded snapshot of the latest durable catalog after two acknowledged
revocations. The latter represents independently retained and reconciled
operator records. It is an in-memory test fixture captured before restoring
Redis, not a production backup format, revocation journal or automatic trust
source. A real operator must establish that equivalent external evidence is
complete; the drill cannot establish an actual deployment's revocation history.

Ordinary `revoke-*` commands deliberately require the active incarnation and
Redis run. They cannot replay revocations onto an unapproved changed-run
candidate. Reconciliation therefore occurs through explicit, isolated fixture
administration while all serving processes are stopped. The helper preserves
catalog revisions, epochs and generation; it never restores or deletes run and
incarnation metadata, owner leases, attachment tickets or signed membership
directory entries. It only replaces durable keys inside its exact random test
namespace. No `rebind-redis-run`, premature activation, authority-state rollback
or recovery-fence reset is permitted.

The recovery signing key and unsigned approval inputs live in a separate
private fixture directory from online authority material. Only public recovery
trust is copied to the relay fixture. The online authority root never contains
the recovery private key, including when a binary override is a container
launcher that mounts only the command's private input directory.

## Predeclared sequence and refusal controls

1. Save the older RDB before any device connection. Start the real authority
   and all three relays. Require exact non-owner traffic and successful use of
   the separate credential and consumer grant targeted by the controls.
2. Revoke that credential and grant through actual relay commands. Require
   credential rejection and HTTP authorization denial next to a successful
   independent canary. Stop and reap the device, authority and all three relays;
   verify release of every listener. Retain the independent latest catalog and
   the authority counters and relay-state hashes.
3. Stop the verified old Redis container, prove its PID is gone and endpoint
   released, and retain it stopped. Load the older RDB into a separate verified
   candidate container on the same loopback endpoint. Require a different run
   ID, restored AOF-always persistence, and direct evidence that both revoked
   records are active again in the old backup. Wait at least 65 seconds after
   the last successful process fence, covering the 60-second membership trust
   lifetime plus the shared five-second clock-skew bound.
4. Before reconciliation or any recovery/approval, start each old relay and
   the old authority against the restored stale backup. Require exact
   `stage=authority_identity class=run_changed` for all three relays and the
   authority's independently pinned-run refusal. After every attempt require
   byte-identical authority/recovery state, unchanged hashes of all three old
   relay states, unchanged old Redis incarnation/run binding, still-stale
   revocation flags and the original Redis still stopped. Then apply the
   independent reconciled catalog. Run actual `recovery-observe` and
   offline `sign-recovery-approval`. Missing fencing acknowledgements and a
   wrong nonce must refuse with the expected cause and byte-identical fence.
   Restore the stale durable records after signing: actual `recover` must
   refuse the changed digest without consuming the approval version.
5. Reapply the independently reconciled records, observe again and sign a
   fresh output. Actual `recover` must consume version 1 and activate exactly
   the reviewed new run/incarnation. Replaying that approval must refuse and
   leave the consumed fence unchanged. Old relay configurations and the old
   authority inventory must fail with their specific identity/run causes.
6. Run actual `approve-membership` with revision 2, the reviewed run and new
   incarnation. Preserve both independent high-water counters and clear old
   confirmation. Start a newly confirming authority and initialize separate
   membership-state paths for all three candidate relays. Require higher
   allocations, all three persisted checkpoint/node-floor adoptions, a fresh
   device session and exact non-owner traffic across two further publications.
   Both revocations must remain enforced. Old relay state and the recovery
   fence remain unchanged; the old Redis container remains stopped.

No generic connection failure counts as an authorization or recovery refusal.
Every failure and control output is retained. The drill does not retry a failed
scenario, reset a spent fence or repair state to obtain a pass.

## Bounds and container ownership

The wrapper creates two uniquely named/labeled containers from the pinned
Redis 8.4 image, each limited to 256 MiB with no swap, one CPU, 64 PIDs and a
96 MiB noeviction dataset. Only one Redis process serves at a time. These are
synthetic loopback fixtures, not the Fly production TLS image or a capacity
test. Authority and relay Redis connections use the existing verified TLS
proxy; only fixture administration accesses its owned plaintext upstream.

Before lifecycle, copy or cleanup operations, immutable container IDs, owner
labels, exact image and loopback port bindings are checked. The wrapper also
checks resource settings. Shared port 16379 is always refused. Cleanup never
removes containers by a discovered name alone; it rechecks and uses a pinned
immutable ID. Signal cancellation enters bounded cleanup, and a child process
group is cleaned even when its immediate harness process has already exited.

The scenario has a 360-second deadline; the wrapper gives the test process
420 seconds including cleanup. CLI operations have 20-second deadlines;
Redis operations have two-second bounds. Namespace snapshots allow at most
256 keys, 64 KiB per record and 4 MiB total, with bounded RESP allocations and
scan rounds. The physical RDB is limited to 8 MiB. Partial or uncertain restore
outcomes abort the drill. Setup/build deadlines are separate and occur before
the recovery scenario. No Rust build cache is created by artifact mode.

## Run and retain evidence

After an assigned build/process window is available, source acceptance is:

```sh
python3 -m unittest discover -s scripts -p test_m6_authority_recovery_verify.py
bash scripts/m6-authority-recovery-verify.sh --output /tmp/c243-source-evidence
```

The evidence directory must be new. It is private and retains the result JSON,
input executable hashes, exact Redis identity, bounded subprocess logs,
per-phase assertions and checked cleanup results. Private managed-process
captures may contain synthetic test identifiers; do not publish them without
review. RDB, ACL and signing material are temporary private fixture inputs and
are not included in the report.

For a previously built compatible test executable and optimized shipped
artifacts, supply all three overrides. Partial overrides fail before building
or touching Docker:

```sh
TUNNEL_AUTHORITY_BIN=/bundle/tunnel-authority \
TUNNEL_RELAY_BIN=/bundle/tunnel-relay \
TUNNEL_C22_RECOVERY_HARNESS_BIN=/proof/m6_online_authority \
  bash scripts/m6-authority-recovery-verify.sh --output /tmp/c243-artifact-evidence
```

The wrapper requires the exact ignored test and exact one-test pass count plus
its final phase marker. The unchanged earlier authority lifecycle/fault gates
remain registered alongside this drill in the M7 script. Full workspace,
hosted/platform checks, optimized-archive proof and real off-host operator
acceptance remain separately reported requirements.

## First artifact attempt retained

At source `3d092deb`, the targeted integration test compiled in 3.62 seconds;
both diagnostic projection tests and all four snapshot controls passed. Scoped
strict Clippy passed in 48.70 seconds. The frozen harness SHA-256 is
`41f556e3f959aad4acadf35a353ecfc8c8a4881b7bbf018064381c993de67e2f`.

The first artifact-mode attempt used copies of the C241 image-extracted
optimized authority (`cc7420062204c7f0d6ce6ad551c7d203ef16c3430a955b21c5d78b47762336f2`)
and relay (`2827f610c4c553fe9ece6bf0040ad27c8170a692a95e98cd76e058eb8842206c`).
Their hashes were checked against the container-notice report and again after
the attempt. The test failed in 5.83 seconds (6.806 seconds including wrapper
cleanup), before restoring Redis. Both exact owned containers were removed.

The first revocation command returned a real nonzero exit with
`stage=connection_establishment lane=4/6 class=io`; the PEM output detector did
not trigger. The existing serving TLS proxy has 32 slots. Three relays and the
authority each retain seven catalog connections, using 28. A separate actual
CLI needs seven more: its primary and first three lanes fill 32, then its
fourth lane is refused. This is fixture capacity, not evidence of a production
Redis or authorization defect. An independent bounded verified-TLS operator
proxy/config to the same owned Redis is the approved fixture repair. It is now
implemented separately from the retained attempt: the serving proxy limit and
all acceptance predicates remain unchanged. A pure exact-config/endpoint
control and actual read-only observation plus wrong-CA refusal check endpoint
identity and retained TLS verification. Independent proxy cleanup joins its
connections and verifies listener release. The corrected artifact run is retained below as a separate failure.

Evidence is retained privately under
`/workspace/agentuplink-review-artifacts/c243-c248-artifact-proof-3d092deb/`,
including immutable executable copies, validation logs, source/image manifests,
`run-first/result.json`, bounded command captures and post-run hash checks.
The failed run has not been retried, and it does not verify the recovery drill.


## Corrected operator-channel attempt retained

At exact `7c9c24fc`, the targeted compile passed in 3.82 seconds, all seven
nonignored controls passed, and scoped strict Clippy passed in 2.24 seconds.
Frozen harness SHA-256
`1be64fb1c693baa9297dbf2b3b3f478daa8df400336e981aeb7819ce966dff10`
used the same optimized authority and relay copies as the first attempt.
The test **failed** in 82.60 seconds (83.452 seconds including wrapper cleanup).
Both exact owned containers were removed. Evidence is retained privately at
`/workspace/agentuplink-review-artifacts/c243-operator-proof-7c9c24fc/`.

The independent operator TLS channel and wrong-CA refusal passed. The run then
proved live three-relay traffic and both revocations, fenced the old processes,
loaded the visibly stale backup into a new Redis run after 65,023 ms of
quiescence, rejected missing fencing/wrong nonce/stale digest, and completed
actual signed recovery with replay refusal. It failed during the subsequent
`waiting-next-publication` canary with HTTP 503, `CLUSTER_UNREADY`,
`execution=not_dispatched`. Those earlier phases do not make the drill pass.

Ingress relay-a PID 498654 logged `Authority(HttpStatus(429))` at
`2026-10-31T05:50:50.863787Z`, immediately before its shutdown capture at
05:50:50.870. The membership reconcile error withdraws membership readiness
and invalidates peer admissions before logging. The authority permits one
concurrent connection per approved node. The fixture was polling every 200 ms
using the serving relay-a identity, competing with relay-a's own serialized
reconciliation. This supplies a concrete current-run observer collision; it
does not establish the cause of the earlier hosted C248 failure.

The failure-only local reads showed authority confirmation version 2 with
51,846 ms remaining, checkpoint high-water 50, and relay checkpoint floors
38/39/40 with every node floor at 2. These are subsequent snapshots, not
request-time readiness or peer-probe evidence. No request-time pin generation
or route-probe snapshot was retained. The observed membership error alone
makes the public readiness conjunction false, regardless of those other gates.
The retained ingress log SHA-256 is
`7688905ca94c87cd22ab4e935d6210ec50657ee6bc20e3ef4e31628d37ee509a`.

## Passive live publication observations

The fixture now observes the bounded atomic authority state while relays are
active. It requires the entire independently supplied inventory, its exact
revision/deployment/incarnation, the expected Redis run and exact three node
identities to match. Only a valid confirmed publication with its original
future expiry can advance the observation; a spent reservation is insufficient.
Both allocators and confirmed membership versions must not roll back, and the
same confirmation cannot change its expiry. An ordinary restart retains the persisted confirmation but resets only the
process-local freshness deadline. The observer must wait until a newly
confirmed version exceeds the pre-restart membership high-water, then require
all three real relays to adopt the fixed target. Unexpected confirmation
clearing fails in every live continuity phase.

This is an unsigned **test observation**, never a runtime trust source or a
manufactured signed checkpoint. A fixed target captures confirmed membership
version V and checkpoint high-water H and requires every actual relay to
persist a checkpoint at least H+1 and every approved node record at least V.
Each real relay performs the existing signature, nonce and identity checks
before those fences are persisted. All three identities are checked in their
bounded version envelopes. Exact non-owner canaries and identical owner,
session, epoch, generation, socket and relay PIDs remain mandatory at every
observation. A canary failure still immediately fails the scenario. The fixed
target is not moved while waiting, and the existing 25-second publication and
55-second two-refresh bounds remain.

Every fixture checkpoint HTTP request now refuses before dispatch if any
serving relay process is owned. The active-call audit covers healthy refreshes
and authority restart in the lifecycle test, plus both post-recovery refreshes.
Direct nonce-bound signed-response, mTLS negative, failed-publication expiry,
restart freshness, recovered publication and inventory/client-revocation checks
remain in phases before relay startup or after all relays stop. The isolated
lost-write and Redis-run fault scenarios never start relays. No direct HTTP
coverage was dropped; only the concurrent continuity observation changed.
The corrected observation controls and the two serial process attempts pass
at the sources and scopes recorded below.


The preapproval old-startup witness was missing from both retained attempts:
the earlier refusals occurred only after successful activation of the new
incarnation. The new control runs before the first reconciliation, signing,
recovery or inventory approval. Generic connection, TLS, timeout and later
incarnation-mismatch failures cannot count as changed-run refusal. This is
additional missing acceptance coverage, not a reproduced runtime defect.
Its source and pure cause-selection control pass in the focused validation
below; all four actual startup witnesses pass in the corrected recovery run.


A reviewer initially inferred that startup clears persisted confirmation and
proposed a special pending-clear observer mode. Source review disproved that:
`Engine::open` retains `state.confirmed` and resets only `fresh_deadline`; offline
inventory approval is the operation that clears confirmation. The mode was
removed before any process run. Superseded source `3cd898a1` compiled in 58.83 s,
passed 13 nonignored controls and scoped Clippy in 42.71 s, but those results do
not validate the corrected source. Their logs and executable are retained at
`/workspace/agentuplink-review-artifacts/c243-passive-superseded-3cd898a1/`.
A replacement pure control requires unchanged old confirmation and a spent
unconfirmed reservation to wait, a genuinely new confirmation to yield a fixed
target, and any unexpected clearing to fail. No runtime defect is inferred.


## Corrected passive fixture validation

Exact clean source `7a522bead3e0b40e25586f27daa351f0a969be26` compiles the
integration target in 4.28 seconds. All 13 nonignored controls pass (including
five passive observation controls and the preapproval refusal selector); four
actual-process tests remain ignored. Strict Clippy for this integration target
passes in 2.34 seconds. Six Python wrapper guards also pass. These are focused
fixture checks, not a workspace or recovery-drill pass.

The test executable is frozen outside Cargo at
`/workspace/agentuplink-review-artifacts/c243-passive-proof-7a522bea/binaries/m6_online_authority`,
SHA-256 `f0d36173fb4750dc44e3cdfb098f65bd789c33a8068656e9dc637ecb1059468c`.
The adjacent `execution-inputs.json` pins the clean source, all five Rust
fixture input hashes, validation logs and the unchanged C241 optimized
executable copies, whose hashes were rechecked against the image report.
The wrapper manifest now also records the passive observer and diagnostic
module hashes. All earlier failed attempts remain retained. The subsequent corrected
recovery/lifecycle evidence follows; historical hosted attribution and the
combined-candidate/hosted checks remain open.


## Two serial optimized-artifact attempts

On 2026-10-31, a declared quiet local build/fixture window ran exactly one
corrected recovery attempt, then exactly one native lifecycle attempt. Both
used frozen harness `f0d36173…59468c` from clean Rust source `7a522bea` and the
unchanged image-extracted C241 authority `cc742006…36f2` and relay
`2827f610…206c`. The recovery wrapper checkout was `a78e2be6`: its only changes
from the harness source were evidence documentation and the source-hash input
list. All five Rust fixture hashes matched before and after execution. No
Cargo build, runtime modification, relaxed canary, or scenario retry occurred.

| Attempt | Result | Test / wrapper duration | Exact cleanup |
| --- | --- | --- | --- |
| Three-relay recovery | PASS, one test | 116.23 s / 117.109 s | Both owned Redis container IDs proven absent |
| Native authority lifecycle | PASS, one test | 118.31 s / 119.096 s | Its separate owned Redis container ID proven absent |

Recovery retained an older physical backup, independently captured 93 later
catalog records, fenced all old processes and waited 65,076 ms. Before any
reconciliation or approval, all three old relays refused the changed Redis run
and the old authority refused the run outside its durable approval; every
attempt preserved the old bindings, full authority/fence bytes, relay-state
hashes and visibly stale revocation flags. Missing-fence, wrong-nonce and
stale-digest controls refused without consuming the fence. Actual CLI signing
and recovery consumed version 1; replay refused. New membership approval
preserved both allocators. All three new relays adopted verified checkpoint and
node floors, a fresh device session carried exact non-owner traffic through two
further confirmed publications, and both credential and consumer-grant
revocations remained enforced.

The separate lifecycle test preserved the exact owner/session/epoch/generation,
data socket and three relay PIDs through two publications, authority stop and
restart, and all-three persisted adoption. Direct nonce/signature and mTLS
controls stayed outside the live relay phase. Failed publication responses
retained their original expiry and became unavailable after 53,113 ms; startup
freshness, revoked client pin, pending inventory and wrong-run checks all
passed their existing predicates. This is native executable acceptance with a
production-library device, not a new device-CLI, full-container, off-host or
hosted-CI claim.

Evidence is private under
`/workspace/agentuplink-review-artifacts/c243-c248-quiet-a78e2be6/`:
`inputs.json`, `recovery-first/result.json`,
`recovery-first/012-actual-recovery-drill.log`, `lifecycle-predeclared.json`,
`lifecycle-driver.py`, `lifecycle-first/result.json`,
`lifecycle-first/007-actual-native-lifecycle.log` and
`post-run-integrity.json`. The lifecycle driver reuses the reviewed bounded
wrapper's ownership, immutable-ID/image/loopback/resource checks and process
group cleanup for its separate disposable Redis. Shared port 16379 was never
used. Its frozen driver SHA-256 is
`7e26d3b77aa37c25d87c8fea1de07b07802c176ed9eb35ee4c12c6179c8521ca`.
Post-run hashes prove all source/executable inputs unchanged. None of the nine
retained serving-relay stderr captures contained the earlier authority-429
warning. That observation and these local passes do not establish the cause of
the historical hosted failure. Both failed earlier attempts remain retained;
C22, combined-candidate acceptance and hosted validation remain open.

The exact harness source is `7a522bead3e0b40e25586f27daa351f0a969be26`;
the executed wrapper source is `a78e2be67c3c00dcf9d796fa0e47c0af70d0adfe`.
The service executables are unchanged C241 optimized artifacts, not rebuilt
from this fixture branch or from later combined runtime changes.

| Artifact | SHA-256 |
| --- | --- |
| Frozen test executable | `f0d36173fb4750dc44e3cdfb098f65bd789c33a8068656e9dc637ecb1059468c` |
| Optimized authority executable | `cc7420062204c7f0d6ce6ad551c7d203ef16c3430a955b21c5d78b47762336f2` |
| Optimized relay executable | `2827f610c4c553fe9ece6bf0040ad27c8170a692a95e98cd76e058eb8842206c` |
| Predeclared input manifest | `c856a8541cbb7ed64896192d0fb33b2a447c2a023facecf2064349675b1c108e` |
| Recovery result JSON | `f695075650c66b5256db04f46a99736b67e525d7419c4cfee2bf3d833ed8ff72` |
| Recovery test log | `0dad7c472e36044fd86ac74fa81ded9b0f5d798f60f921a364726c7e4801ac8d` |
| Native lifecycle result JSON | `404db87d7c93a3d35335647a163abedd34f1376165fb71e0e4803204d32a1c71` |
| Native lifecycle test log | `81beed160eebf1cd41d4f037d09d1463d0ca311cbe24e4989c7e29b030768046` |
| Post-run integrity manifest | `3722e295d4b900ff7d1aacc03fbedba99f24dce30ee2f924282c880750e122a5` |
