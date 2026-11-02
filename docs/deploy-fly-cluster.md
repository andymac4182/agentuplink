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
deployment ID, durable namespace, incarnation, OIDC settings, public hostnames,
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
URLs are refused. The renderer derives each approved peer endpoint and TLS
server name as that relay app's `.internal` name; its exact three-name allowlist
is identical in every relay and the authority. Private binds are explicitly
IPv6, including the outbound QUIC address family selected by `peer_bind`.

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
volume is `/var/lib/agent-tunnel/state`. Authority secrets/configuration live
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
public UDP service. Exactly one intended running machine per relay app is
required for the `.internal` name to identify that node unambiguously.

Verify actual Fly private DNS/IPv6 connectivity, every H3 route, certificate
hostname/pin refusals and readiness-aware public routing. The rendered family
choices and synthetic container-network proof are not live Fly verification.

## First start, after explicit deployment authorization

Create new approved app names and an empty deployment namespace; do not silently
reuse the historical single-relay apps or their state. Each billable resource
and public address allocation needs the approved inventory/budget. Inspect exact
machine/volume IDs before commands that could attach, replace or start them.

1. Bind the final source SHA/tree, complete CI and image digests. Validate every
   Fly profile under the intended authenticated account. Provision the five
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
   Stop/remove bootstrap machines before relying on a one-machine app's DNS.
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

Image rollback never restores an older membership, recovery or authority state
volume, resets a counter, or revives a retired key. The legacy single-relay image
is not a cluster rollback image. Authority upgrades stop the sole writer, replace
the image and restart with the same durable state, requiring a new publication
confirmation. Its `check-config` takes the same lock and cannot be a concurrent
health command. A valid whole-volume rollback cannot be detected using that same
volume alone; preserve independent approval/high-water custody and remain
unavailable when reconciliation is missing.

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
incarnation/run, preserving its counters. Start authority, then all relays with
their preserved state and fresh sessions. Volume snapshots alone do not prove
catalog freshness or monotonic counter custody. Simultaneous restart and
older-backup recovery on the intended Fly topology remain required separately
from source checks and the bounded image rehearsal.

## Evidence still required

Rendering and static controls do not settle account access, actual app/volume
inventory, certificates, OIDC/JWKS, catalog grants, credential rotation,
registry/notice qualification, owner license decisions, Redis/authority recovery,
off-host capacity/soak, alerting or incident ownership. Retain M4-47 and other
open production rows and all prior failed attempts. The profile adds no license
exception, unsupported-platform omission, deployment approval or production
completion claim.
