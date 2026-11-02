# Fly cluster image boundary

These are separate images for the three-relay profile. The historical single
relay/Redis recipes and shipped generic authority recipe are unchanged. The
Python tests validate configuration, filesystem and command boundaries only;
they do not establish image startup, Redis ACL/AOF behavior or Fly readiness.

Build each image from the repository root, on a separately authorized runner:

```sh
docker build --build-arg VCS_REF="$SOURCE_SHA" -f deploy/fly/cluster/images/relay/Dockerfile -t "$RELAY_TAG" .
docker build --build-arg VCS_REF="$SOURCE_SHA" -f deploy/fly/cluster/images/authority/Dockerfile -t "$AUTHORITY_TAG" .
docker build --build-arg VCS_REF="$SOURCE_SHA" -f deploy/fly/cluster/images/redis/Dockerfile -t "$REDIS_TAG" .
docker build --build-arg VCS_REF="$SOURCE_SHA" -f deploy/fly/cluster/images/rehearsal-client/Dockerfile -t "$CLIENT_TAG" .
```

`SOURCE_SHA` is the exact checked-out 40-character lowercase commit. Every
image records it as `org.opencontainers.image.revision`; independently bind
the checkout/tree, resulting immutable image IDs/digests, binary and notice
hashes. The label is a supplied provenance assertion, not proof of source
identity. Each Dockerfile has a repository-root context allowlist. Rust builds
use the pinned toolchain, locked dependencies, read-only source, a locked Cargo
cache and optional BuildKit `--secret id=cargo_ca,src=...`; credentials are not
build arguments. Production relay builds do not include the rehearsal client.

Relay/authority runtime images install Debian `python3`, including its full
stdlib; `python3-minimal` alone lacks required modules. Redis installs Alpine
`python3`. Each build probes every entrypoint stdlib import. Python runs with
`-I` and does not consume `PYTHONPATH`. The runtime package inventory and notice
limitations are in [PROVENANCE.md](PROVENANCE.md). Preserve upstream OS notices;
the Python addition and externally built Redis module provenance still require
distribution review and actual image inspection.

| Role | Default user | Preprovisioned writable state | Ephemeral private files |
| --- | --- | --- | --- |
| Relay | UID10001, named group `relay` | `/var/lib/agent-tunnel/state` | `/var/lib/agent-tunnel/secrets` |
| Authority | UID10002, named group `authority` | `/var/lib/agentuplink-authority/state` | `/var/lib/agentuplink-authority/secrets` |
| Redis | Pinned image's named user/group `redis` | Whole `/data` volume, owned child `/data/redis` | `/var/lib/agentuplink-redis/secrets` |
| Rehearsal client | UID10003, named group `client` | Explicit disposable fixture mount only | `/var/lib/agentuplink-client` |

Before starting a service, explicitly provision its new volume while stopped.
Discover the Redis UID/GID from the exact built image; do not infer its GID from
another image. The state directory must already exist, be owned by the runtime
UID and have mode0700. Its ancestors must be real directories. Startup never
creates, chmods, chowns, removes, resets or repairs state. Preserve the whole
authority directory for its stable lock and atomic replacements, and all
relay membership files, locks and the recovery fence. Never run two writers or replace a volume with an older
copy during an image rollback. Preparation must not recursively alter existing
state; inspect and resolve an unsafe existing volume through a separate operator
procedure. A read-only root requires an explicit writable ephemeral secrets
mount with the same ownership; secrets must never be placed on the state volume.

The relay membership path is fixed by the validated incarnation:
`/var/lib/agent-tunnel/state/membership-version-<digest>.json`, with the full
lowercase SHA256 of the incarnation's UTF-8 bytes. The entrypoint independently
checks the exact derived path. It has no arbitrary-path override and creates no
membership file itself. An approved new incarnation needs an explicit stopped
`initialize` command for its absent file, preserving all earlier files. A normal
restart of the same incarnation continues to use the same file and counters.
The recovery fence is always `state/recovery-approval-fence.json`; the authority
file is always `state/authority.json`. Neither changes with incarnation.

If an older profile already used `state/membership-version-state.json`, do not
initialize empty state under the new filename for that same incarnation. The
new image refuses the legacy path. Stop/fence the relay and use an independently
reviewed offline migration that preserves the old file/lock, verifies its exact
identity/high-waters, and creates a private, durably synced, byte-identical new
file without overwriting an existing destination. Verify that copy before
startup; keep the recovery fence and authority counters intact. There is no
automatic migration or claim that such a migration has been exercised. See
[the cluster upgrade/recovery contract](../../../../docs/deploy-fly-cluster.md#upgrade-rollback-and-redis-recovery).

The relay metrics listener is exactly `[::1]:9100`; alternative or wildcard
addresses are refused by the entrypoint. No public service/host publication is
added. Failure diagnostics execute an identity-checked, bounded local helper as
the relay user and retain only fixed readiness fields; raw metrics/logs remain
private. This does not configure a production scraper or prove readiness.

All required base64 values are strict, nonempty and at most128KiB decoded;
configuration is at most32KiB and the membership private key at most4096 bytes.
Existing files must be owned mode0600 regular files with exactly one link.
Writes use exclusive temporary creation, file fsync, atomic replacement and
directory fsync inside the private directory. Symlink/hardlink/FIFO/unsafe-mode
targets are refused, including dangling symlinks. A failure stops startup;
partial materialization is not a successful initialization. Failures use closed
diagnostic labels without values. All `AT_*`, `REDIS_*` and `PYTHON*` variables
are removed from the service's environment before fixed-path `execve`.
Unknown files or abandoned `.materialize-*` entries are retained and refused;
inspect an interrupted startup before retrying. The directory has a fixed role
file set, rather than accumulating temporary or unrelated secret files.

`AT_CLUSTER_CONFIG_B64` contains exactly the renderer's base TOML. Relay TOML
omits `redis_url`; the entrypoint prepends it from `AT_REDIS_URL`. Authority
TOML references the private `redis-url` file. Both roles use nonsecret
`AT_CLUSTER_REDIS_HOST=<redis-app>.internal` and `AT_CLUSTER_PUBLISHER_USER`.
The accepted Redis URL uses scheme `rediss`, user `default` for relays or the
named publisher for authority, the provisioned password, the exact private
Redis hostname, port `6379` and database path `/0`. Passwords are 32–128
ASCII letters/digits, which avoids quoting, URL and ACL injection. Certificate
and hostname verification remain enabled; Redis client certificates are not
required by this password-authenticated TLS profile.

Relay inputs (base64) map to fixed names in its secrets directory:

| Variable | File |
| --- | --- |
| `AT_DEVICE_TLS_CERT_CHAIN_B64` | `device-server-chain.pem` |
| `AT_DEVICE_TLS_KEY_B64` | `device-server-key.pem` |
| `AT_DEVICE_CLIENT_CA_B64` | `device-client-ca.pem` |
| `AT_CONSUMER_TLS_CERT_CHAIN_B64` | `consumer-server-chain.pem` |
| `AT_CONSUMER_TLS_KEY_B64` | `consumer-server-key.pem` |
| `AT_REDIS_CA_B64` | `redis-ca.pem` |
| `AT_OIDC_JWKS_B64` | `oidc-jwks.json` |
| `AT_PEER_TLS_CERT_CHAIN_B64` | `peer-chain.pem` |
| `AT_PEER_TLS_KEY_B64` | `peer-key.pem` |
| `AT_PEER_CLIENT_CA_B64` | `peer-ca.pem` |
| `AT_MEMBERSHIP_SIGNER_TRUST_B64` | `membership-signers.json` (public verification only) |
| `AT_CHECKPOINT_CA_B64` | `checkpoint-ca.pem` |
| `AT_CHECKPOINT_CLIENT_CERT_CHAIN_B64` | `checkpoint-client-chain.pem` |
| `AT_CHECKPOINT_CLIENT_KEY_B64` | `checkpoint-client-key.pem` |
| `AT_RECOVERY_TRUST_B64` | `recovery-approval-keys.json` (public verification only) |

Authority inputs (base64): `AT_MEMBERSHIP_SIGNING_KEY_B64`→`membership.der`,
`AT_REDIS_CA_B64`→`redis-ca.pem`, `AT_AUTHORITY_TLS_CERT_CHAIN_B64`→`https-chain.pem`,
`AT_AUTHORITY_TLS_KEY_B64`→`https-key.pem`, and
`AT_CHECKPOINT_CLIENT_CA_B64`→`checkpoint-client-ca.pem`. Only explicit
`initialize-membership`/`approve-membership` commands materialize
`AT_CLUSTER_INVENTORY_B64` as `inventory.json`. Startup does not consume it as
approval. Recovery signing and CA private keys stay outside every serving app;
unknown role `AT_*` variables are refused, not silently passed through.

Redis inputs: `REDIS_TLS_CERT_CHAIN_B64`, `REDIS_TLS_KEY_B64`, `REDIS_PASSWORD`,
distinct `REDIS_PUBLISHER_PASSWORD`, and nonsecret `AT_CLUSTER_REDIS_NAMESPACE`
and `AT_CLUSTER_PUBLISHER_USER`. The generated ACL retains password-protected
`default on` with the relay's broad privileges because Redis8.4 AOF transaction
replay with `default off` previously failed. This is not a least-privilege relay
ACL. The named publisher gets only `PING INFO EVAL HGET HLEN HSET EXPIRE` on
`tunnel-catalog:<namespace>:membership:operator:*`. Only password hashes are
written to the private ACL file; it is deterministically rematerialized from
the same independently provisioned credentials on restart. Preserve/reinstall
those credentials after replacement; this is not a credential backup mechanism.
Actual denied-write and AOF-restart verification remains required.

Redis listens on IPv6 `::`, TLS6379 only; no public service is configured. Its
profile retains AOF `appendfsync always`, `no-appendfsync-on-rewrite no`,
`aof-load-truncated no`, `maxmemory96mb`, and `noeviction`. The96MiB ceiling is
not a new capacity guarantee. Peer UDP7443 and authority TCP8444 require explicit
IPv6 binds. Runtime/PKI/allowlist semantics remain validated by the real binaries.
The initial renderer provides one peer key per node, and this wrapper refuses
unmanaged `peer_tls_next_*` paths. Live SIGHUP peer-key rotation is not supported
by this profile. A separately approved stopped identity replacement procedure
still needs its own verification; an image update is not permission to replace
an identity or weaken membership trust.

Default command is `serve`. Explicit relay commands are:

- `check-serve-config`, `initialize`, `recovery-initialize`, `recovery-observe`,
  `activate-first-incarnation`, each without caller options;
- `provision-catalog`, `add-user`, `add-device`, `add-service`, `set-grant`, each
  with `--records PATH` and optional `--dry-run`;
- `revoke-grant --tenant UUID --user UUID --device UUID --service UUID`,
  `revoke-device --tenant UUID --device UUID`, and
  `revoke-credential --tenant UUID --device UUID --credential UUID`, each with
  optional `--dry-run`;
- `recover --approval PATH --expected-nonce NONCE --acknowledgement-id ID
  --old-primary-fenced --old-relays-fenced`.

`PATH` for records/approval must name an owned mode0600 regular file directly
inside the role's separately mounted owner0700 `operator` directory. The caller
must supply and independently review those inputs. Values remain separate argv
entries, never shell syntax. Missing/duplicate/unknown flags and caller
`--config`/`--inventory` overrides are refused. The historical `rebind-redis-run`
command is intentionally unavailable for a cluster.

Authority permits `serve`, `check-config`,
`initialize-membership --expected-redis-run-id RUN`, and
`approve-membership --expected-redis-run-id RUN --expected-revision N`.
RUN must be an independently observed40-character lowercase Redis run ID;
the wrapper never obtains or approves it. Configuration/inventory paths are
fixed by the image. `--help` for relay/authority requires no secrets. Redis
permits only `serve` and accepts no extra server flags.

`generate-key` and `sign-recovery-approval` are deliberately absent from the
serving authority wrapper. An explicitly approved offline operation can invoke
the actual authority binary with a separate `--entrypoint`, network disabled,
and a distinct owner-private fixture/offline mount; never mount its recovery
or CA private key into a serving app. Those actions are not startup hooks.

Run the static and temporary-file tests without Cargo, Docker or services:

```sh
python3 -B scripts/test_fly_cluster_images.py -v
```
