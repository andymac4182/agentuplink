# Fly image recovery rehearsal

Status: same-AOF rehearsal implemented and reviewed; current-image execution is
pending. Physical older-backup restoration is a separate required scenario and
has not been implemented in this controller. Neither result establishes actual
Fly deployment readiness.

The controller uses the four images built from the exact checkout in the Fly
workflow. It starts only after the ordinary three-relay topology rehearsal
succeeds. Immutable Docker configuration IDs come from the build receipts and
must name that checkout. The controller independently verifies revision labels,
default users, binary hashes, notices and a clean source tree. No tag lookup,
build, pull or host-binary fallback is used by the recovery step.

## Scenario and acceptance

1. Start three relays, the online authority, durable TLS Redis and three real
   CLI clients. Require exact echoes on all nine owner/ingress routes. Separately
   prove a spare device credential and another principal's grant work, revoke
   them using the real commands, then require credential refusal and grant
   refusal through all three ingress relays while the nine primary routes pass.
2. Stop clients, all relays and the authority. Verify removal and absence of old
   listeners; preserve membership files, recovery fences, authority allocators,
   catalog digest/generation, device epochs and revocations. Stop and restart
   the same Redis container using its same AOF volume. Require a new Redis run,
   unchanged durable catalog/counters and exact old-startup refusals.
3. After the existing source-bound 60+5-second fencing interval, require old
   ephemeral owner/ticket/index keys absent. Choose a new incarnation and a
   higher authority inventory revision independently. The real observation must
   still report quiescence as unproven; operator declarations provide fencing.
4. Sign a strictly higher approval version and fresh nonce offline, using a
   network-none authority container. Signing keys never enter the online
   serving containers. Missing fencing acknowledgements, a wrong nonce and a
   stale catalog digest must refuse without consuming the durable fence.
5. For the stale-digest negative only, a scoped atomic Lua compare-and-set
   changes one synthetic tenant display name and increments catalog generation.
   Every old-value, identity, key-type and overflow check precedes writes. Restore
   only a known successful change with another generation increment. An ambiguous
   command outcome stops the attempt without retry, restoration or new signing.
   This is not backup restoration or external revocation reconciliation.
6. Take a fresh observation, sign a fresh approval and recover once. Verify the
   exact new run/incarnation and consumed fence; reject replay and old startup
   configurations. Approve the new authority inventory while stopped, preserving
   both allocators. Explicitly initialize the new incarnation-specific membership
   paths while preserving old files and stable recovery fences.
7. Require three real publication/adoption rounds, each within the unchanged
   30-second bound. Fresh clients must have new owner boot/session/connection
   identities and increasing device epochs. All nine positive routes and both
   revocation negatives must pass after each round. Preserve old membership
   bytes, approval fences and old-ephemeral absence through completion.

## Bounds and evidence

The main bound remains 1500 seconds, cleanup 180 seconds, commands 30 seconds and
network operations five seconds. Startup requires 4 GiB available memory, active
operation 3 GiB, no swap/OOM increase and 1.5 GiB free on the relevant filesystems.
The recovery controller also checks Docker's actual data filesystem and a
conservative image-copy reserve. That estimate is not a guaranteed peak.
Finished owned helper containers are removed promptly with identity and absence
receipts; no foreign container, volume, network or shared Redis is touched.

Cleanup continues after failure and preserves the first failure. Observed
resource violations during cleanup remain latched even if the final sample
recovers. Source/image identities, process-group absence, all owned containers,
volumes and network absence are checked before a pass. A failed readiness wait
inherits the existing closed C263 diagnostics and records secondary diagnostic
failures separately.

Only `source.json`, `images.json`, `events.jsonl` and `result.json` from the
recovery output are uploaded. Raw commands, credentials, keys and approvals stay
in the separate private temporary directory. No raw-directory upload is allowed.

The workflow invokes:

```sh
python3 scripts/fly_cluster_recovery_rehearsal.py \
  --scenario durable-restart \
  --relay-image "$RELAY_IMAGE_ID" --authority-image "$AUTHORITY_IMAGE_ID" \
  --redis-image "$REDIS_IMAGE_ID" --client-image "$CLIENT_IMAGE_ID" \
  --output "$NEW_CREATE_ONLY_OUTPUT"
```

This is a synthetic hosted Docker rehearsal. Actual Fly routing, inventory,
PKI, backup custody, incident ownership and live deployment need separate
evidence and authorization.

## Source review and retained failures

The initial controller passes 45 pure/mock controls. Independent review finds
two acceptance-validator gaps: Python equality accepts boolean/float values as
integers, and a missing old connection ID can look different from a new ID.
The original implementation and results remain preserved. The first added
regression run against it records 45 failed assertions. A test-only subtest
scoping correction exercises all outcome variants and records 47 failures;
neither run executes a product process or Redis script.

The corrected controller requires exact observed schema/types, required fields,
u64 counters and node inventories, and nonempty old/new connection IDs. All 62
controls pass, with the original 45 test ASTs unchanged. Source receipt SHA256
`e633e62c80fccfe5d68bf8bb04b66346692605c7db6af6da94609f106c279d2a`
binds controller `92ac00c98f43bd23fa8c59ee6a3ff0e3371e0db8d0499f0971ec752c928058fb`
and tests `a9e18f985b6b88239ca0d23b7a9690eda0f23c13fd669d320cba60b7d3797e08`.
Independent review `643cbabe1bd68d7bf8e0c5081daecb4ec571b2d50a7d78ca5955040e75445b44`
finds those corrections complete. Integration on #288 adds only the existing
readiness-diagnostic failure list to the final result, plus the workflow and
documentation. Combined-source checks and hosted execution remain separate.

No local native, Docker, Redis, Cargo or cache execution occurred. Actual Lua
atomicity, CLI refusals, same-AOF persistence, convergence and full runtime
cleanup remain unverified until the new hosted scenario finishes successfully.

The combined successor additionally passes191 Fly pure/mock/temp controls and
five workflow receipt-dispatch controls, including refusal before invocation for
wrong source, mutable tag, wrong role and a missing build receipt. Receipt
`85a9d2bee429d57d5063868a1cd4de838756d8e9dbebf7bb2615a9d9b7184385`
is local source evidence only; runtime recovery remains pending.
