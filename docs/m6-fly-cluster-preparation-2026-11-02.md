# Fly cluster preparation — M6-C258

Fly is the owner's selected initial host. Source merge is authorized; live
deployment and license-policy exceptions are not. This continuation prepares
a distinct five-app profile and a hosted actual-image rehearsal. It does not
promote the old single-relay Docker smoke test into cluster acceptance.

## Source and verification boundaries

The profile starts at consolidation head
`46a19cce1ce457943f80a2d134145ae386f2a0c5`, tree
`1e985753f9faa86fbd766b131240b5ca7099719c`. Its changes are separate from
the frozen #284 candidate. The Fly source freeze is
`4f8349d63b76f7fe5dffad6e1e69738d712cbcef`, tree
`0c3a996052b1b4fdfcfde741763debbca57edcfb`; it was integrated into a separate
publication checkout with C253 and current main. Hosted runner identities will
be recorded after publication; no Fly runtime result is claimed here.

The [operator guide](deploy-fly-cluster.md) specifies three stable relay apps,
one TLS Redis primary and one independently persisted online authority. Each
app has one intended machine and one durable volume. Peer H3 uses private IPv6
and exact per-app names; consumer/device TLS passes through Fly to the relay.
Public readiness checks verify the selected hostname against public trust.
Synthetic CA acceptance in Docker cannot establish Fly's trust-store behavior.

The deterministic renderer requires an explicit inventory. Production inputs
require immutable registry manifest digests; example-only Docker config IDs
are labeled separately and are not deployable image references. No default
account or actual region, domain, sizing, OIDC or PKI selection is inferred.
The guide binds subsequent operations to actual machine and volume IDs, since
Fly's configured volume name alone is not an exact custody guarantee.

The new nonroot relay, authority and Redis entrypoints materialize bounded
configuration and secrets into private directories, validate ownership and
refuse unknown inputs or implicit state initialization. Redis retains TLS,
AOF always-fsync, no eviction, the 96 MiB dataset ceiling and a password on the
default user. The publisher has a separate named, namespace-bound credential.
Recovery and CA signing keys stay offline. Relay least-privilege Redis commands
are not yet derived. The new OS package inventory is provenance, not a complete
distribution-license finding; existing C241 gaps remain open.

The hosted rehearsal builds four source-labeled images, including a separate
device-client fixture image. It binds extracted executables to staged notices,
renders the actual profile, uses dedicated IPv6 Docker networking and volumes,
and exercises three device clients with nine routes, six across relay hops.
Its planned assertions include TLS name/CA refusal, unknown device refusal,
anonymous and revoked-grant refusal, the publisher's catalog-write denial,
actual 300-second device rotation, relay restart with a fresh fenced owner,
persisted membership floors and authority restart with fresh publication.
Echo coverage does not replace MCP/filesystem/ACP gates. Ordinary relay and
authority restart does not establish Redis restart, coordinated restoration,
off-host backup, crash-fsync durability, capacity or soak.

The controller records exact source/tree/image identities and sanitized
success/failure events. Generated PKI, credentials and raw command output are
private temporary data, never uploaded. Execution and cleanup have separate
1500/180-second bounds. Serving containers have 512 MiB limits, helpers/clients
256 MiB, equal memory/swap limits and 256 PIDs. Startup/active memory floors
remain 4/3 GiB with 1.5 GiB filesystem reserves and no OOM/swap delta.
Cleanup acts only on identity-verified resources owned by the run; failure
records remain failed even if cleanup succeeds. The workflow never deploys,
publishes images or cancels an active rehearsal for a later push.

## Static evidence and review corrections

Renderer controls: 20 passed, receipt SHA256
`114a1522ee6736943d6816de88f404ef2c36fdb421256a49ae0510b2dc1bffa4`.
The integration review preserves eight executable/fixture inputs and has
SHA256 `66e12cfe76f15b5091eafff236503a531dd2855002d91f978b6eaeeaa88df82a`.
Image/entrypoint temporary-file controls: 20 passed, handoff SHA256
`c1df395c8d931247739d2ae2c39b23c823c50b1dbcf72e06ec527182ee825ed9`.
These are local Python/static results, not image-build or runtime passes.

The first image-control run retained two fixture failures: an expected
environment omitted preserved `RUST_LOG=info`, and its requested directory
mode was changed by the inherited umask. Explicit mode setup and the correct
sanitized environment expectation corrected those fixtures. Review also
aligned the 63-character app-name boundary and required Python's full standard
library before any image build. Historical image recipes remain unchanged.

Review rejected a proposed prebootstrap-authority refusal assertion: the
publisher has no catalog-activation gate and can populate an empty namespace.
The controller instead enforces activation, provisioning and explicit authority
initialization in order. It does not claim a nonexistent product refusal.
Other pre-runtime corrections cover actual client readiness envelopes,
required IPC rotation fields, ambiguous create identities and cleanup after
OOM/log/stop failures. The final controller uses latch-only INT/TERM handling, tests interruption at
the body/cleanup transition, joins fragmented RESP replies, and sends complete
TLS Redis commands under the unchanged absolute deadline. Its 33 pure/mock/temp
controls pass; receipt SHA256
`f7e8d36f909ac4a98fe8ca04ea74c3a896a3af8d8dda3bb57fb868c37090ef33`.
Final controller SHA256 is
`48d508f4a92480fbde7a6eac50c704d7e20a385cd9612b695747a59a82945864`;
independent read-only review receipt is
`787f6c057a3a0f88a31aa81092c346212f27ae37e57cb482468df5901040bca2`.

The first root precommit scan failed on three template-only credential-shaped
strings, with no actual secret value. Its receipt remains failed, SHA256
`ca6bb34c728627800d2074e284014b2268736157d1d2afc43455647a14e33dd9`.
Prose grammar and a default-user variable preserve exact URL semantics without
any scanner exemption. The corrected 24-file scan has zero findings in the
scanner's declared formats; Python AST and all three workflow shell blocks
pass syntax review. Receipt SHA256 is
`5b033b84f83a1f63d8e4728e9325d36b264cff96e0160bbd5be7834ba6611d14`.
This is not a universal secrets or runtime claim.

## Separate client license evidence — C253

The [artifact-aware client checker](m6-client-license-gate.md) is prepared at
`e2dc2a21ec0b461b6273e2f9d152b85a0fe26b0e`, tree
`b440900cb8a4a582a941178231a5d3824ad27ddb`. Its 55 seeded controls pass.
The actual graph result is **failure**, not an approval: all 324 lock entries,
320 distinct verified archives and seven aliases are accounted for, leaving
five policy refusals and two missing archived notices. The report SHA256 is
`e08d94430e03a343852bb45bdf1e852e4c6b2fed0a1370b77a9ed3503ade7882`.
The source/static receipt is
`9cddbf7b67826abdcada6e7629f02003926e8bddc74310e328678a3906234d6b`.
Earlier collector/control failures are preserved in its guide.

BlueOak-1.0.0 and optional node-liblzma's LGPL-3.0 remain outside the unchanged
allowlist. @nodable/entities 3.0.0 and files-sdk 2.4.0 lack collected archived
license text. Exact upstream notice candidates remain inactive pending their
separate applicability review. No dev, optional or nonhost platform node is
omitted. The existing Python-checker CI environment now runs the 55 seeded client
controls. It does not run the real graph gate or change its failure. Seeded CI
controls cannot substitute for real policy enforcement.

## Authorized consolidation merge

[#284](https://github.com/andymac4182/agentuplink/pull/284) merged at
2026-11-02T15:40:54+10:00 as
`626ba9365b5d3e1faf8265f0b6ff50cc9111b749`. Its verified parents are
`c749a78432c2d863572a601a7935abf73fa193a2` and
`46a19cce1ce457943f80a2d134145ae386f2a0c5`; its tree is exactly
`1e985753f9faa86fbd766b131240b5ca7099719c`, matching the actual hosted PR
checkout `5f2053f07da1a1b264bbde11f1830a09b42c50c5`.

[CI 41391363189](https://github.com/andymac4182/agentuplink/actions/runs/41391363189)
completed successfully at 2026-11-02T15:36:50+10:00: all 14 jobs, including
required Rust checks on three platforms, TypeScript 610/40 and audit zero,
M0/M1/M2/M3, full M4 and full M7. M4 retains the actual 300-second framework
gate with eight exchanges / 20,480 bytes, 1467 ms resumption, 326 ms revocation,
zero replay/recovery/forced retirement and joined cleanup. C244 reaches three
exchanges / zero streams / zero replay with all original controls. M2 proves
three actual 300-second rotations in 903.308505 seconds with 18,005 records and
zero replay. M7's original log SHA256 is
`76aefa60cbaf4fbcf81cb2c6144c719a1200caf537e1f4f354764ff948e6f0d4`.

[Packaging 41391363143](https://github.com/andymac4182/agentuplink/actions/runs/41391363143)
passes on all three OSes. [Release 41391363158](https://github.com/andymac4182/agentuplink/actions/runs/41391363158)
passes all five optimized builds and all five native archive verifiers;
attestation/publication are correctly skipped for this PR. C257's 18 static
trigger witnesses plus this matrix close its notice-trigger scope. The earlier
push CI cancellation by branch concurrency is retained; no manual cancellation
or rerun was used. Final premerge review receipt SHA256 is
`768d8e38ef752d4df5f2fae605372fdfac2c4d80130d163c99b6472f0b988562`.

The predecessor #283 also finished all 14 CI jobs successfully; its M7 actual
checkout remains `b3e011e0f465c581d191e7e2e88e775a1719cee1`, log SHA256
`8150a4f9ac9e6438228b23e1fd702bde614e9dc7682bcee4625a4223dc369b1a`.
Neither result changes any earlier failed attempt or establishes its cause.

Post-merge CI and main's normal development-prerelease workflow require their
own evidence. They are not declared successful from PR runs. This merge does
not deploy the Fly service or approve production readiness or licenses.

## Remaining production gates

No local native, Cargo, Docker, Redis or Fly execution is performed here.
C256's failed memory guard and three unreaped zombie children remain failed;
the local native/cache lease stays quarantined. Historical #278/#282 failures
and their unknown exact causes are retained. M4-47's recorded security rejection
must not be retried or bypassed. Public-close joining, broader adapters, license
policy and notice/provenance obligations remain open in their existing tasks.

The profile currently represents one peer key per node. Its device socket
rotation does not establish live peer-key rotation; the documented stopped
replacement procedure still needs execution. Actual Fly account access,
organization, names, region, public domains/certificates, OIDC/JWKS, exact
machine/volume custody, independent recovery history, backup destination,
monitoring, alert delivery, on-call ownership and capacity/soak evidence remain
required before readiness. All eight production completion criteria stay open.
