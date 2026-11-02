# Online membership authority

`tunnel-authority serve` runs the membership publisher and HTTPS checkpoint
responder together, under one independent operator identity (M6-C234). It uses
the existing signed membership and checkpoint formats. It does not provision
catalog users/devices, issue certificates, reconcile a restored catalog or
activate recovery. M6-C22 records the shipped-authority/operator verification
at `8c8c14fc`. New-candidate authority validation is tracked in M6-C251; actual
deployment provisioning and the production goal remain separate (M6-C221).

Use one authority process and a durable local filesystem on Linux or macOS.
The Windows workspace builds, but this service refuses its unsupported private
filesystem boundary. There is no active/active mode, network administration
API, automatic initialization or automatic state repair. Recovery and CA
private keys must remain offline; do not mount them into this service.

## Provision the independent host

Start with [the example configuration](../examples/authority/authority.toml)
and [three-node inventory](../examples/authority/inventory.json). All example
identifiers, addresses, digests and dates are placeholders. Provision actual
values independently from the intended deployment, never by trusting Redis's
membership directory. Inventory approval covers the deployment ID, durable
Redis namespace, incarnation, publisher public key, each stable node ID,
private peer endpoint/name, peer key windows and checkpoint client SPKIs.

Keep these credentials separate:

| Material | Location and use |
| --- | --- |
| Membership Ed25519 private key | Authority only; signs records/checkpoints |
| Membership public trust JSON | All relays; verify the publisher |
| Authority HTTPS server key/chain | Authority only; a name in the authority endpoint URL |
| Checkpoint client CA | Authority public trust; required client authentication |
| Checkpoint client key/chain | Its relay only; peer SAN for that node, client-auth usage, SPKI separately approved in inventory |
| Redis named publisher ACL password and optional client key | Authority only; membership namespace writes |
| Redis server CA | Authority public trust; hostname verification stays enabled |
| Recovery signing and CA private keys | Separate offline operator boundary; never supplied to `serve` |

All authority input files, including configuration, inventory and public trust,
must be regular files owned by the service UID with mode 0600, inside an owned
0700 parent. State and the stable sibling lock have the same restrictions.
Symlink components, parent traversal and hard links are refused. Run the offline commands as that same service UID while the service is stopped.
Use canonical absolute paths; `/var/run` and some macOS temporary paths are symlinks. The
service does not chmod, create directories or repair unexpected files.

The Redis credential file contains a single `rediss://<user>:<password>@HOST:PORT/0`
URL. Use a named ACL user with a nonempty password, percent-encoded as required
by URL syntax. The client verifies the explicit Redis CA and server name. If
Redis requires mTLS, configure both Redis client identity paths. Grant only
`PING`, `INFO`, `EVAL`, `HGET`, `HLEN`, `HSET`, `EXPIRE` and access to
`tunnel-catalog:<namespace>:membership:operator:*`; do not grant catalog,
ownership, recovery or ACL administration. The publisher needs `INFO server`
to verify the Redis process run ID. Configure the account outside this process.

The authority's HTTPS listener must be reachable privately by all three relays.
It requires TLS 1.3 mTLS, with HTTP/1.1 and no TLS resumption or early data. The
client certificate must also identify an approved peer node and match one of
that node's checkpoint client pins. A same-CA but unapproved identity gets 403;
having a trusted CA chain alone never authorizes a checkpoint. Peer-key approval
and checkpoint-client approval are separate inventory fields, even when an
operator deliberately uses the same certificate for both.

## Initialize explicitly, then start

Generate a dedicated membership key on the authority host. This is separate
from the default recovery-key output format:

```sh
tunnel-authority generate-key --purpose membership --key-id membership-1 \
  --private-key /var/lib/agentuplink-authority/secrets/membership.der \
  --public-keys /var/lib/agentuplink-authority/secrets/membership-public.json
```

Install the emitted public trust JSON on the relays. Copy its public key and
key ID into the reviewed inventory. Independently verify the intended Redis
primary's 40-character run ID through the trusted operator control plane.
Initialization performs no network reads and cannot discover or approve it:

```sh
tunnel-authority initialize-membership \
  --config /var/lib/agentuplink-authority/secrets/authority.toml \
  --inventory /var/lib/agentuplink-authority/secrets/inventory.json \
  --expected-redis-run-id "$REVIEWED_REDIS_RUN_ID"
tunnel-authority check-config --config /var/lib/agentuplink-authority/secrets/authority.toml
tunnel-authority serve --config /var/lib/agentuplink-authority/secrets/authority.toml
```

The first inventory revision is exactly 1. Initialization creates state only
when absent. `check-config` validates local state, signing identity, required
HTTPS identity/trust and credential-file configuration without contacting Redis;
it does not prove Redis credentials, DNS, reachability or deployment readiness.
It takes the same exclusive lock, so run it while `serve` is stopped.

Every process start requires a newly reserved and acknowledged publication
round. Persisted confirmation cannot make a restarted process ready. Each
new Redis publisher connection, including reconnections, must match the
independently approved run ID. A changed run or version conflict sets the fatal
latch and exits for operator review. It never adopts the observed run or derives
approved inventory or counters from Redis.

For each relay, set the cluster endpoint to
`https://authority.example.internal:8444/v1/checkpoint`, the authority server
CA path and both `checkpoint_authority_client_cert_chain` and
`checkpoint_authority_client_private_key`. The relay's deployment/incarnation,
node ID, peer endpoint/name and membership signer trust must match approval.
Initialize each relay's own membership state and recovery fence explicitly as
described in [operator.md section 3.3](operator.md#33-a-cluster). Those relay
volumes are separate from the authority volume and from Redis persistence.

## Durable allocation and failure behavior

The private schema-1 state contains the exact inventory, expected Redis run,
global membership high-water counter, separate checkpoint high-water counter,
all previously approved node IDs and the last confirmed round. It is bounded
at 256 KiB. An exclusive stable sibling lock remains locked across atomic state
replacement. Replacement writes a private temporary file, fsyncs it, renames
it atomically, then fsyncs the directory before reporting success. Missing,
corrupt, unsafe or externally changed state is refused. A persistence error or
one-second operation timeout latches fatal; no subsequent successful checkpoint
or publication reservation is released in that process.

A publication round validates every inventory entry, allocates one globally
higher record version, and durably reserves it before attempting any Redis
write. All nodes in that round use that version. Up to four writes run at once;
the round is bounded at ten seconds. A lost reply, partial write or process
crash spends the entire reserved version. The next attempt uses a higher one.
Only acknowledgements for every node followed by a durable confirmation make
the round available for checkpoints. A checkpoint independently reserves and
persists its higher checkpoint version before returning the exact signed bytes.
Both counters survive all approval changes, including new incarnations.

Records expire 60 seconds after the round begins. Publication starts on a
20-second schedule with skipped missed ticks; work never queues catch-up bursts.
Publication failure cannot refresh an earlier confirmation. A same-inventory
checkpoint may carry a fresh request nonce and higher checkpoint version, but
its expiry remains exactly the previously confirmed record expiry. Responses
stop when fewer than seven seconds remain (two seconds for the request and five
for clock skew), checked against both UTC and the original monotonic deadline.
New inventory never uses an old inventory's confirmation. Discipline the
authority, Redis and relay clocks; the existing cluster clock-skew bound is five
seconds. Arbitrary clock steps and rate error are outside the deployment proof.

**One unusable node stops the whole next publication round.** Before allocating,
every node needs a non-revoked active peer key under the relay's shared activation
rule; key expiry remains strict. All-future keys beyond the allowed activation
skew, expired keys or invalid entries refuse the round. No entry is silently
deleted and no window is extended. Previously confirmed trust can only run to
its original expiry, while each relay still enforces each key's own expiry.
Approve rotations/removals before any required key window lapses. This publisher
policy does not change M7-C187's relay behavior: a lapsed named record is absent
only for that node.

**Do not roll back the authority volume or reset either counter.** A valid
whole-volume rollback cannot be detected using that same volume alone. Backups
are evidence for independent recovery, not safe copies to restore over current
state. Missing/corrupt state requires operator reconciliation; this slice does
not introduce an automatic repair or external rollback anchor.

## Change approval while stopped

Stop the service, review a complete replacement inventory with revision exactly
one higher, and run:

```sh
tunnel-authority approve-membership \
  --config /var/lib/agentuplink-authority/secrets/authority.toml \
  --inventory /var/lib/agentuplink-authority/secrets/inventory-next.json \
  --expected-revision "$PREVIOUS_REVISION" \
  --expected-redis-run-id "$REVIEWED_REDIS_RUN_ID"
```

The command refuses a running writer, stale revision, deployment/namespace
change, mismatched signing key or invalid inventory. To change the expected
Redis run, an independently recovered different incarnation is required. This
command does not establish catalog reconciliation, quiescence or activation;
perform the existing recovery contract independently. It preserves both version
counters, clears confirmation and does not perform Redis I/O. Restart and wait
for a confirmed new round. A removed client pin is refused immediately after
restart, even if publication is unavailable. Newly approved clients receive 503
until the new inventory has a confirmed round. There is no live reload.

For publisher-key rotation, add the new public key alongside the current key
and roll each relay process so it loads that trust before signing with the new
key. Copying the trust file alone does not reload it; SIGHUP stages a peer
identity, not publisher trust. Verify all relays with both trusted publisher keys
before changing the authority inventory and signing-key path. A stop/update/restart interrupts checkpoint
availability, so keep it well within the existing trust lifetime. A prolonged
outage fails closed. Approve both peer keys during a controlled rotation, follow
the relay's convergence hold, then withdraw the old key with a later inventory
revision. Separately rotate checkpoint client pins; permit at most two per node.

The Redis directory retains removed node IDs and has a 32-entry bound. The
authority therefore permits at most **32 distinct node IDs over the namespace's
lifetime**, across incarnations. Reuse stable logical node IDs for process and
SPKI replacement. There is no safe online deletion command; directory cleanup
and deployments exceeding that historical bound remain M6-C236. Creating a new
incarnation does not free slots or justify resetting version counters.

## Service and network limits

The responder admits at most 64 TLS/HTTP connections, one authenticated request
per node, a 32-slot state-admission queue and one actual blocking state operation.
TLS handshake and HTTP exchange each have a two-second budget; request bodies
are at most 4 KiB, headers at most 16 and the HTTP buffer 8 KiB. Connections close
after one response. A disconnected caller cannot release the durable serializer
early or cancel its timeout watchdog. The publisher joins the same fair
serializer without requiring an HTTP admission slot. HTTP waits at most one
second for that serializer; the publisher waits at most three seconds, covering
older HTTP waiters' one-second queue budget, the last healthy one-second write
and a one-second scheduling margin. It therefore retains its fair position under
admitted HTTP load. The actual blocking operation watchdog stays at one second.

Authorized clients can use `GET /livez` for process liveness and `GET /readyz`
for current confirmed publication freshness. Readiness consumes no signed
checkpoint version. `POST /v1/checkpoint` requires JSON content type, exact scope
and a 16–128-character alphanumeric/underscore/hyphen nonce. Refused client
identities get 403, concurrent work for a node gets 429, and unavailable authority
state gets 503. Do not make readiness public or add a certificate bypass for a
load balancer. Logs contain fixed stage/status messages, no private material,
Redis URL, signed documents or request bodies.

The [systemd example](../examples/service/tunnel-authority.service) runs an
independent account with an owned persistent directory. The [container](../deploy/authority/Dockerfile)
contains only the authority executable; mount private configuration/credentials
read-only and state read-write with the fixed UID. Neither starts an initializer.
Mount the whole state directory so its stable sibling lock and atomic replacement
remain on the same durable filesystem. The image's UID is 10002; provision
owner-only directories and files for that identity before sealing the secrets
mount. One-time key generation needs a writable secrets child at the normal
container path, separately from read-only service use. The
[default-user mounted-layout proof](m6-authority-default-user-2026-10-31.md)
records actual provisioning, refusal checks and the retained inaccessible-parent
fixture failure; it does not establish production storage or readiness.
The CI deployment job builds this Dockerfile after the Fly proof, checks the
effective non-root UID and requires an unconfigured default startup to fail.
That image smoke does not replace the three-relay process acceptance below.
Restrict ingress to relay networks and egress to the independently approved Redis
primary. The actual hostnames, firewall rules, issued PKI, UID ownership,
durable-volume guarantees and Redis persistence/ACL configuration remain
deployment inputs. This is not an unattended production rollout manifest.

## Acceptance

Run the locked workspace checks and the registered actual-process gate:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build --workspace --bins --locked
TEST_REDIS_URL=redis://127.0.0.1:16379/ cargo test -p tunnel-test-harness \
  --test m6_online_authority --locked \
  online_authority_publishes_for_three_relays_and_fails_closed_across_lifecycle \
  -- --ignored --exact --test-threads=1
bash scripts/m6-authority-faults-verify.sh
```

The process gate uses generated PKI, an isolated publisher ACL and namespace,
the real authority binary, Redis TLS and three configured relay processes. It
checks exact binary canaries through a non-owner ingress while the same device
owner/session/carrier survives two confirmed refreshes and an authority restart,
then separately exercises outage expiry, pending client revocation and run
mismatch. The fault script owns a pinned disposable Redis container: one test
severs a successful publication reply after commit and requires a higher reserved
round before any successful checkpoint; the other restarts that actual Redis
process, preserves its ACL/AOF, and proves the running authority refuses the new
run without changing approval or publishing new records. The restart checks the
container ownership label, immutable ID and exact loopback port before acting; it
never restarts the shared test Redis. Both tests must run for the script to pass.
Storage tests separately exercise actual crash/rename boundaries, stable locks, permanent
failure and cancellation. Local tests do not attest deployment DNS, real volume
crash durability, hosted archives or independent recovery execution. Keep those
remaining M6-C22 obligations visible in the production deployment goal.

Local acceptance recorded on 2026-10-31 for the M6-C234 service slice:

| Check | Observed result |
|---|---|
| Formatting, strict workspace/all-target Clippy, locked workspace tests | Pass; 2,868 passed, zero failed, 106 ignored across 174 suite results. |
| Durable state, crash boundaries, cancellation and publisher fairness | Twenty state/store tests pass. The independent one-second publisher queue control fails; the bounded three-second publisher queue passes without changing the one-second I/O watchdog. |
| Actual daemon with committed publication reply loss and real isolated Redis restart | Both tests pass in 67.14 s; spent versions are not reused and a changed Redis run is not adopted. |
| Three-relay process traffic and lifecycle | Pass in 119.01 s; unchanged device session/carrier and exact non-owner canaries across two refreshes, authority restart and persisted checkpoint/all-node-floor adoption by all three relays. |
| Actual authority image | Build passes in 188.02 s. Default UID10002, help and unconfigured startup refusal pass. The same unchanged lifecycle gate using the actual image passes in 127.44 s, with original-expiry outage refusal after 53,052 ms and zero residual owned containers. |

M6-C247 subsequently corrected the publisher fairness test after hosted Ubuntu
job `124443738026` rejected the third HTTP request as busy. The old fixture left
only about 200 ms beyond two injected 400 ms sleeps for real signing, fsync and
scheduling; healthy individual writes do not guarantee that total queue wait.
The hosted log has no per-operation timings; a controlled setup delay reproduces
the invalid assumption without identifying that runner's exact delay source.
The replacement uses a paused Tokio test clock with bounded real-time barriers
around actual signing/fsync. It asserts exact HTTP queue residence of
0/400/800 ms and publisher residence of 1,200 ms. The old one-second publisher
budget is red, the unchanged three-second production budget is green, and the
restored authority unit suite passes all twenty tests. This proves timer-budget
and FIFO behavior, not real-time I/O margins. The separate real-stall watchdog
and cancellation tests remain unchanged; hosted re-verification is pending.

The image lifecycle uses a synthetic private fixture directory, host networking
and fixture UID/GID1000 to preserve its file ownership. Its root filesystem is
read-only, with all capabilities dropped, no-new-privileges, 256 MiB memory,
one CPU and 32 PIDs. The fixed production image UID10002 is checked separately.
The runtime source is `cd509527`; the equivalent optimized Dockerfile is
`9513540d`. The image ID is
`sha256:b4ebccb54ba01ce71158cdcb28aee7fb8bef4b73407a606ec9ba45eef606a3df`.
These component results leave hosted authority/platform verification, final
combined acceptance and the deployment/operator/recovery obligations above open.
