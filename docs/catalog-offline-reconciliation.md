# Offline catalog bundles and reconciliation drafts

These two `tunnel-relay` commands check operator-supplied files. They do not
connect to Redis, export a catalog, restore records, consume a recovery approval
or activate an incarnation. A successful check means that the supplied graph and
identity passed the existing recovery schema. It does not establish that the
records are the latest complete catalog or that revocation history is complete.

The initial implementation is source-only until its hosted Rust checks and CLI
tests have run. No production restoration or optimized-image delivery is claimed
by this guide.

## Files and commands

Use the intended cluster's full serving configuration. Its checked
`cluster.deployment_id` and `redis_namespace` select the trust domain. The bundle
cannot redirect that selection. Configuration validation reads no referenced TLS,
OIDC, membership or recovery files and opens no endpoint.

On the existing Unix relay targets, each input and output parent must be owned by
the invoking user with mode `0700`; input files must be regular, single-link,
owned by that user and mode `0600`. Every ancestor and final component is opened
without following symlinks, through pinned directory handles. Parent traversal
is refused. The pure catalog API remains portable; these new CLI file operations
fail closed on other platforms. No existing `serve` or recovery file behavior is
changed.

`catalog-bundle-check --config CONFIG --bundle BUNDLE --expected-bundle-sha256 HASH`
checks one private file. Its redacted JSON stdout reports `schema_valid_only`,
file/durable hashes and counts. `historical_completeness`, `custody` and
`quiescence` are always `unproven`, and `apply_authorized` is always `false`.

`catalog-reconcile-plan --config CONFIG --baseline BASELINE --expected-baseline-sha256 BASELINE_HASH --target TARGET --expected-target-sha256 TARGET_HASH --output NEW_PLAN`
compares two separately hash-bound files in the same trust domain. The private
output is canonical JSON containing the two file and durable hashes, their
untrusted source observations, and sorted changed-key classifications. Stdout
contains only the draft hash, count and explicit unproven/unauthorized status.
The output is create-only, mode `0600`, and synced with its parent before success;
existing files are never replaced. On interruption or a file-system error,
retain and inspect any output independently; an absent success receipt is not a
reason to overwrite a path. A partial draft cannot be applied by this tool.

These commands have no `--force`, repair, import, apply, retry or activation flag.
An expected hash is an integrity binding selected by the operator, not a trusted
signature or custody attestation. Never publish the input files or private plan:
catalog records can contain private identities and policy even without keys.

## Bundle version 1

The file is canonical UTF-8 JSON, without a trailing newline, at most 8 MiB.
Its object fields, in order, are `schema_version` (integer `1`),
`snapshot_schema_version` (integer `1`), `deployment_id`, `redis_namespace`,
`source`, `catalog_digest`, and `entries`. `source` fields, in order, are
`incarnation`, `redis_run_id` (40 lowercase hex characters),
`catalog_generation` (u64) and `captured_at` (RFC 3339). These are supplied
observations; neither later wall time nor higher generation proves freshness.
Generation is a concurrency counter, not a historical completeness checkpoint.

Each sorted entry has `key` and `value`; `value` has `type` followed by `value`.
Types are `hash` (sorted string-pair arrays), `set` (sorted strings), and `string`.
The exact existing recovery schema validates the namespace, types, field shapes,
identities, indexes and relationships. Its 16,384-key, 8,192-member, 256-KiB value
and 4-MiB input/canonical limits still apply. Unknown/duplicate fields or keys,
noncanonical encoding/order, foreign namespaces, metadata, expiring/transient
records and inconsistent or missing index relationships are refused. Expected
indexes are checked against the supplied complete graph; no index is silently
reconstructed or repaired. `catalog_digest` is the existing canonical durable
recovery digest, not the JSON file hash. Signed recovery schemas are unchanged.

There is deliberately no production bundle exporter in this slice. The checked-in
CLI fixture is synthetic test data, not a recommended way to construct a real
backup. A separately reviewed read-only exporter must establish its bounded live
observation consistency and must still label historical completeness and custody
unproven.

## Conservative comparison and limits

A known durable record or index member cannot disappear. Coordination epochs,
device versions, service versions and grant revisions cannot decrease or reach
u64 exhaustion. Comparisons use exact integers, including values above 2^53;
equal numeric versions with changed content are conflicts. A previously inactive
record cannot become active, and a known nonempty revocation timestamp must be
retained exactly with the record inactive. Credential identity/lifetime,
principal mapping, device ownership and existing membership role changes are
refused. Tenant, membership and credential records have no uniform revision;
the planner never invents one or performs a generic maximum-version merge.

An ordinary device `last_seen_at_us` update does not increment device version.
That source-supported difference is labelled `operational_last_seen_only` when
all other same-version fields match. The target's bytes and canonical digest
remain untouched. Higher-version policy changes and newly added valid records
can appear in a draft; the draft still authorizes no write.

The initial interface can refuse legitimate removals, regrants or role changes.
Such a refusal is a tool limit, not an instruction to undo the legitimate change
or choose an older target. The operator-supplied baseline may itself omit a later
revocation; two mutually consistent bundles cannot detect that missing history.

Actual restoration still requires independently retained complete catalog
custody and subsequent acknowledged changes, externally anchored epoch and
recovery/authority counter floors, the approved node inventory, PKI and actual
old-primary/relay fencing. The planner verifies none of those external anchors.
Future apply needs a durable pending/unknown interlock enforced by apply,
recovery activation and serving. Partial writes, lost replies, cancellation and
crash windows must remain fenced without automatic retry. Redis remains the only
authoritative catalog; a draft is neither a second store nor recovery approval.
