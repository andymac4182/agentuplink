# Three-relay Fly profile

This is the separate Fly starting profile for the production-readiness goal.
It renders three identified relays, one Redis primary and one online authority.
The earlier [single-relay Fly deployment](deploy-fly.md) stays unchanged.
Scaling that old relay app does not create this cluster.

Status: source and static preparation. Rendering does not contact Fly, inspect
images or certificates, create resources, provision a catalog, or prove runtime
readiness. Hosted image rehearsal and an authorized deployment need their own
exact-candidate evidence. The local C256 native/cache quarantine is unrelated
and remains in force. Selecting Fly did not authorize a live deployment.

## Topology and explicit inventory

Use five apps in one approved Fly organization/private network and region,
with exactly one intended machine and one independent durable volume per app.

| Role | External listeners | Private listener | Volume content |
| --- | --- | --- | --- |
| `relay-a`, `relay-b`, `relay-c`, each a separate app | TCP 443 to consumer 8443; TCP 9443 to device 9443, both TLS passthrough | IPv6 UDP 7443, peer mTLS H3 | Membership-version state and recovery approval fence |
| Redis | None | TLS TCP 6379 | Redis AOF/data directory |
| Authority | None | IPv6 TLS TCP 8444, mandatory checkpoint-client mTLS | Approval state, both monotonic counters and stable sibling lock |

App names, region, volume names/sizes, memory, source-bound image digests,
deployment ID, durable namespace, incarnation, OIDC settings, public hostnames, each relay's private IPv6,
publisher public key and relay/checkpoint public pins are explicit inputs.
There is no default live account, app, namespace, PKI or resource purchase.
The example's `syd`, 512 MiB machines and 1 GiB volumes are synthetic planning
values, not approved sizing or measured capacity. Retain the 96 MiB Redis dataset
ceiling and measure the actual workload/AOF rewrite headroom before increasing it.
The required off-host 100-device/24-hour acceptance is not reduced by this profile.

Copy [inventory.example.json](../deploy/fly/cluster/inventory.example.json) to a
private operator workspace. It contains no credentials and is deliberately
marked `purpose: "example"`. For an actual configuration, set `purpose` to
`deployment` and replace every synthetic value from independently reviewed
inventory. The renderer rejects example-only hostnames in deployment mode.
The initial profile fixes stable node IDs to `relay-a`, `relay-b`, `relay-c`;
machine/process replacement keeps these IDs and generates a fresh boot ID.

`evaluation_time` is a UTC instant for deterministic key-window checks, not a
claim that the inventory is presently authorized or its keys remain valid.
The authority independently verifies current windows, key material and approved
scope at startup/publication. `membership.revision` starts at 1 for explicit
initialization; later approvals require the current revision plus one.

All three production image references must have the form
`registry.fly.io/APP@sha256:DIGEST`, using actual registry manifest digests.
Mutable tags, unknown fields, duplicate JSON keys, node/app/volume collisions,
inactive key windows at the supplied instant, unsafe endpoints and credential
URLs are refused. Each relay requires an explicit canonical private IPv6
`peer_ipv6` from its reviewed machine inventory. The renderer signs
`[peer_ipv6]:7443` as its peer endpoint and keeps that app's `.internal` name
as the separate certificate server name. Every relay and the authority receive
the same three literal-address and three DNS-server-name allowlists. This
matches the current peer transport, which dials numeric socket addresses and
does not resolve peer DNS names. Authority and Redis service discovery continue
to use their separate verified DNS names. General peer-DNS dialing is not
implemented by this profile correction. Private binds remain IPv6, including
the outbound QUIC address family selected by `peer_bind`.

The renderer accepts only distinct, unscoped, canonical IPv6 literals in the
unique-local range `fc00::/7`; that syntax check does not establish that an
address belongs to the approved Fly organization or machine. After account and
resource approval, retrieve the actual machine inventory read-only, for example:

```sh
fly machine list --app "$RELAY_APP" --json > "$PRIVATE_INVENTORY/relay-machines.json"
fly machine status "$RELAY_MACHINE_ID" --app "$RELAY_APP" --json > "$PRIVATE_INVENTORY/relay-machine.json"
```

Match the intended app, exact machine and volume IDs, region and returned 6PN
`private_ip` against the deployment plan before entering `peer_ipv6`. Never copy
the synthetic example's addresses or infer an address from its app name. Keep
these account-specific inventory files private. A machine replacement may have
a different 6PN address: stop/fence the old machine, review the new address for
the same stable node, and approve the next authority inventory revision with
that new signed endpoint before serving. Preserve certificate-name/SPKI checks,
all membership/recovery state and authority high-water counters. Require fresh
publication, all-peer readiness and real cross-relay traffic; do not reset state
or silently rebind an old approval. Even a same-incarnation upgrade from the
earlier DNS-endpoint profile needs this explicit inventory/config approval.

No inventory field accepts a password, private key, certificate body, JWT or
Redis URL. Public key and SPKI fields are public hex values only; operators
remain responsible for supplying public material, not private key bytes.
Unknown credential fields are refused without echoing their values.

## Render and validate

The renderer uses Python 3.11+ standard-library modules and writes only a new
directory. It refuses symlink input/output paths and existing output. All inputs
are checked before creation; an I/O failure can leave an incomplete directory,
whose manifest is absent because the manifest is written last. Inspect and
preserve a failed output; choose a new path for a subsequent attempt.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 deploy/fly/cluster/render.py \
  --inventory deploy/fly/cluster/inventory.example.json \
  --output /tmp/agentuplink-fly-example --example
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts -p test_fly_cluster.py -v
```

Before handing a rendered directory to another operator or to Fly's validator,
check it against the same reviewed inventory and the exact renderer/templates:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 deploy/fly/cluster/render.py \
  --inventory deploy/fly/cluster/inventory.example.json \
  --verify-output /tmp/agentuplink-fly-example --example
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts -p test_fly_cluster_preflight.py -v
```

For deployment inputs, use the private reviewed inventory and output paths and
omit `--example`. `--output` creates a new directory; `--verify-output` reads an
existing one and cannot be combined with it. Verification regenerates all eleven
expected files from the supplied inventory, current renderer and templates. It
requires the exact five-directory layout, exact file bytes including the
manifest, and single-link regular files. Missing, extra, changed, hardlinked,
symlinked or nonregular entries are refused. Updating a mutable manifest to
match edited configuration does not make it pass. Files are capped at 128 KiB
each and 512 KiB in total; enumeration and reads stop at their fixed bounds.
The verifier writes nothing and never repairs or removes a refused output.

**The new verification mode requires POSIX no-follow directory-descriptor
operations.** On unsupported hosts, including Windows, it returns
`safe-output-verification-unavailable` without opening the output. Existing
rendering remains supported there; no Rust, archive or other platform gate is
removed. Use a supported operator host for this additional check. The verifier
anchors every path component without following symlinks and checks observed
file/directory identities for observed changes during reading. It is a bounded
check, not an atomic snapshot or a lock against another writer: retain the private, exclusively controlled
output, recheck after transfer and immediately before platform validation/use.
Independently verify filesystem ownership and private permissions; byte
verification does not attest them.

Use the same reviewed renderer revision for verification. An intentional input,
template or renderer change needs a newly reviewed rendering, not an edited
manifest or an override. A passing check binds the supplied artifacts to each
other; it does not establish who approved them, current certificate validity,
registry provenance, real app/machine/volume custody, platform acceptance or
deployment authorization. Keep the supplied `evaluation_time` and actual
deployment-time key/certificate checks distinct.

For reviewed deployment inputs, omit `--example`. Output contains
`relay-a/`, `relay-b/`, `relay-c/`, `authority/` and `redis/` Fly configurations,
nonsecret application configurations, the authority's public inventory and
`manifest.json`. The manifest records file, input, renderer and template hashes,
image identities, exact volume names, mount paths and the one-machine requirement.
It never grants live deployment authorization.

The synthetic image rehearsal may use immutable local `sha256:CONFIG_ID` values
only with both `purpose: "example"` and `--example`. The manifest labels them
`docker-config`, distinct from `registry-manifest`. Such outputs are not
deployable Fly profiles and cannot establish registry provenance. Example
certificates also cannot prove Fly's public CA trust-store readiness check.

Static TOML parsing and these controls do not replace Fly's own validator.
Fly CLI v0.5.1 `config validate --strict` requires an authenticated platform
session; it is not an offline check. With approved account access, validate
each rendered file, for example:

```text
fly config validate --strict --config RENDERED/relay-a/fly.toml
```

The [current Fly configuration reference](https://docs.fly.io/reference/configuration)
specifies `[[vm]].memory` (integer MB), `cpu_kind`, `cpus`, and the volume mount
source/destination fields used here. The renderer's input name `memory_mb` is
converted to Fly's `memory` key. It omits automatic volume creation. A mount
source name can match an unmounted same-name volume in that region: before any
start/deploy, independently bind the exact app, machine and volume IDs and refuse
zero/multiple/changed matches. A TOML source name alone is insufficient custody.

## Images, secrets and persistent files

Build the separate cluster images described in
[images/README.md](../deploy/fly/cluster/images/README.md) from the final reviewed
source revision. Record each image's immutable identity, source label, executable
and notice evidence. A historical single-relay image or earlier authority-image
proof does not verify these entrypoints or this final candidate.

The rendered base configuration and public inventory travel in
`AT_CLUSTER_CONFIG_B64` and, for authority approval commands,
`AT_CLUSTER_INVENTORY_B64`. Those values are nonsecret. The renderer also supplies
the exact Redis host and named publisher user; Redis receives the common
namespace. Actual credentials are separate Fly secrets, never renderer inputs,
image layers, committed configuration or command output.

Relay secrets materialize under `/var/lib/agent-tunnel/secrets`, with the
validated runtime Redis URL prepended by the entrypoint. The relay's state
volume is `/var/lib/agent-tunnel/state`. Its membership filename is
`membership-version-<digest>.json`, where `digest` is the complete lowercase
SHA256 of the validated `deployment_incarnation` UTF-8 bytes. The renderer and
entrypoint independently require that exact path; arbitrary state paths are
not accepted. A same-incarnation restart retains the same file, while an
approved new incarnation gets a separate explicitly initialized file. Preserve
the old file and lock. The recovery fence remains
`state/recovery-approval-fence.json`, independent of incarnation.
Authority secrets/configuration live
under `/var/lib/agentuplink-authority/secrets`, and its whole state directory
is mounted at `/var/lib/agentuplink-authority/state`. Provision owner-only 0700
directories and 0600 regular files for UID 10001 (relay) or 10002 (authority)
explicitly while stopped. Mount the whole state directory so atomic replacement
and the stable lock remain on the same durable filesystem. Ordinary startup
does not initialize state, approve Redis, reset counters or repair ownership.

Separate peer identity, checkpoint client identity, device/consumer TLS identity,
membership signing and offline recovery/CA roles. Only the authority receives
the membership private key. Recovery-signing and CA private keys remain offline,
outside all serving apps. Keep the public trust files on relays and preserve
identity/key custody across a machine replacement. Do not clone a volume or
run two machines with the same stable identity.

Redis remains a single primary with AOF `appendfsync always`,
`no-appendfsync-on-rewrite no`, `aof-load-truncated no` and `noeviction`.
The named publisher user has only `PING INFO EVAL HGET HLEN HSET EXPIRE` on the
exact namespace's `membership:operator:*` keys. Its password differs from the
default user's password and survives restart through the cluster image's
configuration. The default user stays password-protected and enabled:
[operator section 2.4](operator.md#24-redis-credentials) records Redis 8.4.0 AOF
replay/data loss with `default off`. A least-privilege relay ACL is still
underived/unverified; this profile does not claim to close that boundary or
silently give the publisher the relay's broader credential.

## TLS and readiness

Both public services have no Fly TLS/HTTP handler. The relay performs consumer
TLS and device mTLS itself; an edge TLS terminator would hide the device
certificate. Public consumer certificates must be trusted by Fly's health-check
trust store and name each relay's explicit public hostname. The renderer requires
`consumer_certificate_trust: "public"` and emits a service-level HTTPS `/readyz`
check with that `tls_server_name` and `tls_skip_verify = false`. It refuses
private-CA consumer inputs instead of adding a verification bypass. Supporting
private-CA consumer certificates needs a separately reviewed routing-health
solution; it is not provided by this first profile.

The [Fly health-check contract](https://docs.fly.io/reference/health-checks)
distinguishes service checks, which gate routing, from top-level checks.
The device service's TCP check and the private Redis/authority TCP checks prove
only listener liveness. Authority readiness needs an approved, CA/name-verified
checkpoint-client identity; do not add a public or certificate-bypass authority
endpoint. Private UDP H3 goes directly over the organization network, without a
public UDP service. Exactly one intended running machine per relay app remains
required. Its independently inventoried 6PN address is the signed dial target;
the `.internal` name remains its certificate identity, not a DNS dial fallback.

Verify actual Fly private DNS/IPv6 connectivity, every H3 route, certificate
hostname/pin refusals and readiness-aware public routing. The rendered family
choices and synthetic container-network proof are not live Fly verification.

Each relay's private metrics listener is fixed to container loopback
`[::1]:9100`. Neither the Fly services nor the rehearsal's Docker publications
expose it. A local operator/agent can read it inside the owned machine or
container; this is not a configured external scraper, alerting system or public
health endpoint. The rehearsal reads only a bounded, closed readiness projection
on failure. Real monitoring access, retention and ownership remain to be defined.

## Private operator handoff before first start

Maintain a private handoff record alongside the reviewed inventory and rendered
manifest. For every row below record a named accountable operator, a backup
contact, the observation/decision time, and the private evidence reference and
digest. Record unresolved items explicitly. A missing owner, evidence or
required decision blocks the affected start/recovery step; filling a record is
not evidence that a live check ran. Do not put credentials, key material,
tokens, catalog snapshots or account-specific inventory in this public repository.
The renderer intentionally does not accept these handoff fields.

| Boundary | Required evidence and decision | Refusal or incident action |
| --- | --- | --- |
| Account and resources | Approved organization/network/region/budget; exact five app, machine and volume identities; intended single writer/node; independent 6PN address observations and custody | Refuse unknown, duplicate or changed resources; stop and review replacement rather than selecting a same-name volume |
| Release and configuration | Reviewed source/tree, required CI, registry manifest digests, executable/notices and compatible forward/rollback versions; exact inventory/rendered hashes; offline verification and authenticated Fly validation results | Refuse a mismatch or failed gate; preserve failed artifacts and do not substitute an older candidate's proof |
| PKI and identity | Named issuer/secret custodians for consumer, device, peer, checkpoint and Redis identities; SAN/SPKI/trust verification; expiry inventory and approved renewal lead time; IdP/JWKS key-overlap and restart procedure | Keep admission stopped for missing/expired/unapproved trust; never bypass hostname, chain, pin or mTLS checks to start |
| State and backup custody | Owner-private state layout and exact volume bindings; independent approval/allocator high-water and later-revocation custody; backup age/completeness/integrity and an authorized restore rehearsal | Fence serving writers before recovery; unknown custody or reconciliation keeps service unavailable; never treat image rollback as state rollback |
| Monitoring and response | Named on-call and escalation owner; approved private scrape/access method for loopback metrics; alert delivery/acknowledgement test, retention, and workload-based thresholds for readiness, authority/owner failures, clock, queues, memory/AOF headroom and certificate expiry | Treat absent telemetry as unknown; use the incident owner and existing fencing/refusal contract rather than clearing counters or suppressing alerts |
| Outage and recovery acceptance | Approved outage/data-loss/recovery budgets, rollback stop conditions, 100-device/24-hour off-host acceptance evidence, and a named operator empowered to halt rollout | Stop the rollout at the first unmet condition; no automatic Redis promotion, unknown-outcome retry or inferred approval |

These are required handoff inputs, not selected production owners, thresholds,
regions, domains or recovery budgets. The current loopback metrics listener is
not an installed scraper or alert route. Public Fly health routing is not a
substitute for private authority/readiness monitoring. Test delivery to the
actual responsible operator before relying on an alert; do not expose the
private metrics or checkpoint listener publicly to make collection convenient.

The backup/reconciliation entry is particularly important: the synthetic
older-backup rehearsal's retained latest-catalog fixture is not a production
reconciliation tool or trusted external revocation ledger. Until the production
procedure and its independent custody are available and verified, the handoff
must mark that boundary unresolved. Image, configuration and PKI rollback must
preserve newer membership/recovery fences, authority counters and revocations.
The next sections retain the actual startup and recovery ordering; this record
does not authorize an additional command or a live deployment.

## First start, after explicit deployment authorization

Create new approved app names and an empty deployment namespace; do not silently
reuse the historical single-relay apps or their state. Each billable resource
and public address allocation needs the approved inventory/budget. Inspect exact
machine/volume IDs before commands that could attach, replace or start them.

1. Bind the final source SHA/tree, complete CI and image digests. Complete the
   private handoff, verify the rendered bytes against the reviewed inputs, and
   validate every Fly profile under the intended authenticated account. Provision the five
   volumes and their owner-private layouts while application services are stopped.
2. Install real PKI/OIDC/JWKS and Redis credentials. Start only Redis and verify
   its TLS/persistence profile. Independently record its current 40-character
   run ID through the trusted operator boundary.
3. Explicitly initialize each stopped relay's own membership state and recovery
   fence. Run `activate-first-incarnation` once for the empty namespace, then
   `provision-catalog --records PATH` with the reviewed tenant/device/service/grant
   records. The records file must be a mode0600 regular file directly under the
   relay's separately mounted, owner0700 `/var/lib/agent-tunnel/operator` directory.
   No relay `serve` or authority publishing process runs before provisioning
   succeeds. Authority membership writes would make first activation or initial
   provisioning refuse an occupied namespace.
4. Initialize authority membership state once with revision 1 and the independently
   reviewed run ID. Run `check-config` while stopped, then start the authority
   and require a new acknowledged publication round. Saved confirmation alone
   cannot make a restarted authority ready.
5. Start all three relays before waiting for cluster-wide peer readiness. Do not
   wait for relay a to reach all-peer readiness before starting absent b/c.
   Distinguish machine-running from application-ready in the startup orchestration.
   Stop/remove temporary bootstrap machines before serving the same node; the
   signed address must identify the intended serving machine, not a temporary one.
6. Verify external consumer/device TLS, exact authenticated cross-relay echo,
   identity/grant refusal controls, revocation, reconnect, an actual 300-second
   device data-socket rotation and bounded shutdown. Run supported MCP/ACP/filesystem acceptance;
   CUA remains disabled. Record per-role image, source, config and receipt identities.

All application bootstrap/recovery commands and their refusal semantics are in
[the operator guide](operator.md#33-a-cluster), [authority guide](authority.md)
and [recovery CLI](recovery-cli.md). The image entrypoint adds no automatic
approval. Never derive a trusted expected Redis run or recovery nonce from the
untrusted value being checked.

## Peer-key rotation limit

This initial profile renders one approved peer key and one checkpoint-client pin
per node. It does not render `peer_tls_next_cert_chain` or
`peer_tls_next_private_key`; the image rejects those unmanaged credential paths
and has no successor-secret inputs. Sending `SIGHUP` therefore cannot stage a
successor with this configuration. The application's supported live rotation
procedure in [operator section 3.4](operator.md#34-rotating-a-relays-peer-key-without-a-restart)
still requires its own acceptance evidence on the final deployment profile.
Device data-socket rotation in a synthetic image rehearsal does not verify
peer-key rotation, certificate renewal or membership-publisher key rotation.

An operator-approved stopped replacement is the bounded option to assess for
this first profile. It requires a planned outage, stopped/fenced affected relay
processes, an independently reviewed successor identity for the same stable node
and private server name, and an explicit next authority inventory revision.
Update the current peer certificate/key secrets only while that relay is stopped;
preserve all state/fence files and authority counters. Restart the authority
through its stop/approve/restart contract, require a fresh confirmed publication,
then start the relays and verify the new identity and refusal of the retired key.
Do not restore a retired key or old authority state as an image rollback. This
procedure has not been demonstrated on Fly or by the bounded image rehearsal;
its inventory, downtime decision and runtime proof remain open.

Supporting live replacement in this profile would require a coordinated schema
and entrypoint change: a bounded predecessor/successor public-key inventory,
fixed managed successor-secret files, explicit staging/approval/withdrawal steps,
and genuine convergence/retirement tests. Do not add arbitrary secret paths or
claim that profile complete from the existing single-key controls.

## Upgrade, rollback and Redis recovery

Upgrade relay images one stable node at a time, preserving its exact state
volume, credentials and approved inventory. Require a fresh boot/session and
restored readiness before continuing. Record both forward and rollback image
digests and compatible configuration/state versions. Existing sessions may be
interrupted; this profile does not promise uninterrupted upgrades.

For a planned same-incarnation relay restart, first stop the old process
successfully, then read its **final** persisted membership envelope. A read while
it is running can miss its last checkpoint or node-version advance. Retain the
exact deployment/incarnation/node identity, all three positive node-version
floors and checkpoint floor. The authority's durable membership and checkpoint
allocators must already be at least those independently known floors; refuse a
rollback or an exhausted counter rather than resetting state. Before one new
start, require a current confirmed authority membership round strictly above
**every** final node floor, with the exact approved inventory and Redis run.
A higher allocator without a confirmed round, a fresh checkpoint for the old
round, or sleeping for a publication interval is insufficient. The authority
state is unsigned preparation evidence; the restarted relay must still verify
its nonce-bound checkpoint and signed memberships, become ready, and durably
advance its checkpoint and every node floor before accepting the restart.

The synthetic image rehearsal gives this preparation, single start, readiness
and durable-adoption observation one shared 60-second deadline after successful
stop, including bounded reads and HTTP requests. It does not retry a refused
start. The shipped relay intentionally rejects an equal restored membership
version because the persisted file does not retain the verified signed bytes.
General crash-restart availability between publisher rounds remains open;
neither this planned-restart procedure nor Fly's configured process retries
proves it. The additional `bootstrap_cause` diagnostic names only the initial
typed pass and does not attribute a line in combined container logs to one
process lifetime or establish the exact cause of earlier hosted failures.

Image rollback never restores an older membership, recovery or authority state
volume, resets a counter, or revives a retired key. The legacy single-relay image
is not a cluster rollback image. Authority upgrades stop the sole writer, replace
the image and restart with the same durable state, requiring a new publication
confirmation. Its `check-config` takes the same lock and cannot be a concurrent
health command. A valid whole-volume rollback cannot be detected using that same
volume alone; preserve independent approval/high-water custody and remain
unavailable when reconciliation is missing.

Earlier versions of this profile used the fixed filename
`membership-version-state.json`. If that profile has already initialized a
volume, changing the filename for the **same incarnation** is a migration,
not a reason to run `initialize` again. Stop and independently fence the relay;
preserve the original file and lock; independently verify the existing
deployment/incarnation/node identity and all version high-waters. Through a
separately reviewed offline procedure, create the new deterministic file with
those exact bytes and owner-private permissions, durably sync the file and
parent, and verify its contents before startup. Refuse an existing destination
or uncertain copy; do not overwrite either state. This profile provides no
automatic migration or runtime migration proof. The entrypoint never renames,
copies or resets the old file, and the legacy path is refused by the new image.
Keep the stable recovery fence and authority state/counters unchanged.

Cluster mode intentionally omits `redis_restart_continuity_seconds`; the relay
refuses that single-relay setting alongside `[cluster]`. After a Redis restart,
restore or changed run, do not call `rebind-redis-run` and do not create an empty
namespace to discard durable revocations. Fence old relays/primary and stop
admission, reconcile durable catalog and later revocations, then select a new
externally approved incarnation. Obtain a fresh `recovery-observe` result and
offline approval with independent nonce and higher version; execute `recover`
once with the existing fence and explicit fencing acknowledgements. An unknown
result spends that version and needs fresh observation/approval.

While authority is stopped, approve the next inventory revision for the recovered
incarnation/run, preserving its counters. For each stopped relay, use the new
rendered configuration to explicitly `initialize` its absent incarnation-specific
membership file. Preserve the earlier membership files and their locks; never
call `recovery-initialize` again or replace the stable approval fence. Start
authority, then all relays with the new approved membership state and fresh
sessions. Volume snapshots alone do not prove
catalog freshness or monotonic counter custody. Simultaneous restart and
older-backup recovery on the intended Fly topology remain required separately
from source checks and the bounded image rehearsal.

## Synthetic recovery rehearsal

The [same-AOF image rehearsal](m6-fly-recovery-rehearsal.md) exercises explicit
operator-approved recovery after all relays and the authority stop and the same
Redis AOF volume restarts. CI runs it after successful baseline topology, with
immutable image IDs from the exact checkout. The owned IPv6-only Docker network
assigns the three relays explicit, distinct high-suffix addresses from its own
private subnet. Those same numeric addresses appear in signed membership and
are checked against each running container; recovery retains them when it
recreates the relays. Helpers use separate automatic addresses. This synthetic
allocation is not a source of actual Fly machine addresses. It verifies preserved revocations,
higher approval fences, new incarnation membership files, unchanged authority
allocators and fresh sessions across three publication/adoption rounds. Source
controls and review pass; current-image execution is pending. This does not
replace physical older-backup restoration, independent later-revocation custody
or execution against actual Fly inventory.

The separate `older-backup` fixture now captures a bounded multipart AOF while
the owned primary is paused, restores it into a distinct volume after fencing,
and reconciles later catalog state from independently retained synthetic custody.
Its workflow job requires successful baseline and same-AOF acceptance first.
Both recovery executions remain pending. The [source continuation and limits](m6-fly-revocation-and-backup-2026-11-02.md)
do not provide production reconciliation tooling or trusted operator custody.
Exact consumer-scope 403 and sole-grant-revocation 404 checks preserve separate API
contracts; the historical #290 unexpected response remains unknown.

## Evidence still required

Rendering and static controls do not settle account access, actual app/volume
inventory, certificates, OIDC/JWKS, catalog grants, credential rotation,
registry/notice qualification, owner license decisions, Redis/authority recovery,
off-host capacity/soak, alerting or incident ownership. Retain M4-47 and other
open production rows and all prior failed attempts. The profile adds no license
exception, unsupported-platform omission, deployment approval or production
completion claim.
