# Fly peer-address correction and authorization verification

Status: production goal active. Main remains `626ba936`; draft #289 has retained
Rust-formatting and Fly-readiness failures. Its other successful checks do not
waive either failure. This follow-up uses a separate source checkout; no active
run, frozen candidate or quarantined local runtime is modified.

## Exact #289 evidence

Head `f12de07646ded6438a6411c7ae2b49e0cc4764a3` and actual hosted checkout
`de3cbe30a812e9f292c2a595a287c801135d7994` share tree
`2ee8cbfee2425a58834a5e90a19594f7a5dc58b2`. Checkout parents are main
`626ba9365b5d3e1faf8265f0b6ff50cc9111b749` and the candidate head.

[Fly run41414103374, attempt1](https://github.com/andymac4182/agentuplink/actions/runs/41414103374),
job125173659850, passes191 static controls and builds all four source-bound
images. The baseline still fails `cluster_readiness_deadline` during bootstrap,
`https_readiness/readyz`. Relay-a receives113 verified-context HTTP503 replies
with the exact unready body; relay-b/c are not polled by the unchanged
short-circuit behavior. No clients, nine-route checks, rotation, revocation or
restart acceptance is reached. The new C264 recovery step is skipped after
baseline failure and remains unrun. Total141.294seconds includes cleanup.

The corrected named-account metrics helpers succeed on all three relays. Each
reports membership state ready, clock ready, zero offset,13 measurements and
zero clock failures, while overall readiness is false. The absent single-relay
`authority_ready` value is expected for this clustered profile. These are
post-failure observations; they narrow the source investigation but do not by
themselves identify a failed peer prerequisite or retrospectively measure the
old #287/#288 state. The historical numeric GID remains unknown.

Cleanup verifies40 removed/individually absent containers,40 successful private
log captures,12 removed volumes with an empty final owned inventory, one absent
network and541 absent process groups. All recorded commands exit0, source and
images are unchanged, and there are no cleanup errors, interruptions or OOM
observations. Earlier failures and C256 quarantine remain unchanged.

Artifact13127531017 is30,304bytes, ZIP SHA256
`228d43e436a6c1557341d143ca1b3f950cdb73d908405285beb721fd60b3cadc`.
Result SHA256 `4625dfcafa0ddcd391e5effbe7ea193700b93c6991b699c6d3b330ff0506d8f0`.
Independent failure receipt SHA256
`07186ed6fb1f615eaf2224cecb0ff141c77db23dd5343f3aab0a18a82e79c5a1`.
A monitor-only lookup used the wrong recovery-controller filename; that failed
preparation and corrected lookup are retained without changing source or results.

All four image identities below are Linuxamd64 Docker configuration IDs, with
revision label `de3cbe30a812e9f292c2a595a287c801135d7994`:

| Role | Docker configuration ID |
| --- | --- |
| authority | `sha256:969b780d7e61440db2a7683b80bda2f0f8a1161be4671aed658f666360efc635` |
| client | `sha256:b4afbc7fae1129b612306af36dd7c6a92288e4edf43c3ee1b9995463426e7e50` |
| redis | `sha256:3e8aa4827e8a0dca50260adc8c6b475a838286735c5ac969ffbb85db0d367cc7` |
| relay | `sha256:4e16f632716c81b9961f276c34ac08eef0eac4d415af69ed5d78652a3ae49387` |

The new client executable SHA256 is
`472239c2f8052628e32b9d7e19d71ebcf36f94ba1ded65619f4c5d6bc0fa652f`, with
notice manifest `6e55c4b72d97e677abc4200ff2f6dadbf35225dcd4974df170024f21ce025a6c`.
The relay, authority, Redis and deadman executable/notice hashes match the
previous explicitly listed entries in [the prior report](m6-fly-readiness-2026-11-02.md).
These identities do not imply successful cluster admission or recovery.

## Separate ordinary checks and formatting failure

All three Rust OS jobs stop at `Check formatting`, before their Clippy or test
steps. They report the same12 hunks in `fs_authority.rs`, `m2_runtime.rs` and
`m4c76_authorization_deadlines.rs`. First failure receipt SHA256
`eac840e747e5ea51c2791d0e7138eaa8e26ea4a925938cf05b47e5780d8989ee`
binds all three actual logs and checkout identity. The successor applies exactly
those hosted edits:11 whitespace-only hunks and one optional trailing comma in
an ordinary `drop(expression,)` call. There are no assertion, literal or runtime
decision changes; complete token equality is not claimed for that comma.

Patch SHA256 `6aceae86379e3d873b931098fe49044d8ebb11864442269aa49ffed95f01cc63`;
independent review SHA256
`d441b2a22606bedbe8449d09b223290c3fcda263799af0d8ca2a73a64accb00d`.
The first source-preparation attempt fails Windows ANSI decoding; a second
inefficient read-only comparison is stopped before source edits. Both remain
retained. The bounded exact-hunk comparison and whitespace check pass. No local
formatter/compiler execution occurs; fresh hosted formatting remains required.

At this continuation checkpoint, three-OS packaging, all five optimized builds
and five native archive verifiers, full M3, full M4 including C244, M0's21 real
gates/21 negative witnesses, Linux M1 and M2 all pass. M2 performs three actual
300-second rotations in903.311346648seconds. The separate regular-CI container
smoke/AOF/authority checks also pass; they do not replace the failed Fly topology.
Ordinary CI has10 successful jobs, three formatting failures and M7 still active.
Attestation/publication are skipped. No archive is downloaded or executed locally.

M2 and M4 logs contain zero records for any of the20 new M4-76 unit tests; those
harnesses build binaries and invoke their acceptance commands, not the new unit
suite. Their successful acceptance is useful regression evidence, but all20 new
unit cases and strict Clippy remain unverified. Exact scope receipt SHA256
`901d6b75bdb31c5ed3789fd58566c2e82abc92d06052c60ad7c0fb3707b6e59c`.
Other retained receipt hashes: packaging `7c952858e9f643ff579e8b6b532848ea7b4975624d0bd31596740b4cf46e5ee4`,
optimized `0095a39a6b4b42734eb5bccb5bd156675ab94bb9578680d2f32c8674ffc21c27`,
M3 `63a08f4748ac25ab586c4740de1bfa0937d1d852627cdfd47c9814e16ae9e28e`,
M4/container `399196fffbb7288dabf54d165a6941a8e2998b54419561c5663cc8a77d593170`,
M0 `41f4d2d5a1109019bf333d0f2ec15a61bde8d1c9c005374b191b53b7e2e87088`.

## M6-C265: signed peer addresses

Source review finds that the Fly renderer signs `<app>.internal:7443` as the
peer endpoint. Production `PeerRuntime::probe_route_until` and normal owner
`peer_destination` parse that field as `SocketAddr`; they do not resolve DNS.
Those hostnames therefore cannot reach a dial through these paths. The design
separates the approved private peer address from its TLS `server_name`, and
production client binding already follows the configured IPv6 peer listener.
This is a profile/runtime contract mismatch, not evidence of an IPv4-only
production client socket. Native fixtures commonly use numeric loopback peers.

The reviewed correction now requires explicit per-relay private
IPv6 addresses in the reviewed inventory, signs numeric `[address]:7443`
endpoints and retains the existing DNS TLS names and peer identity/SPKI checks.
The synthetic owned Docker network must assign and verify those same addresses.
Actual Fly6PN addresses are operator inventory, not invented defaults. Replacing
a Machine with a different address requires fencing the old role and approving
a new inventory revision; it cannot reset membership or recovery counters.
Authority/Redis DNS and all readiness/route/deadline assertions remain separate.
General DNS peer dialing is not implemented or claimed by this correction.

The owned IPv6-only /64 assigns three distinct high-suffix addresses through
Docker `--ip6`. Creation checks requested IPAM identity; a running container
must report the exact network, address and /64 prefix. Recovery removes and
independently observes absence of the old relay before reusing its address.
A separate C264 composition defect is corrected: its unique suffix belongs to
the container name, while the semantic relay role and ownership label must stay
exact for metrics and address assignment. Earlier C264 review missed that issue;
its source receipts remain retained. Recovery has not run, so this is a source
finding rather than an observed recovery failure.

The actual original renderer fails the new numeric-endpoint assertion. The first
broad run has three setup errors: two missing sparse design files and one mock
missing the required address. These are retained; materializing unchanged base
sources and supplying the mock field leaves its assertions intact. Final isolated
controls pass206 cases. Independent review verifies94 base and48 recovery methods
unchanged, with five base methods/one helper and two recovery methods modified.
No readiness, routing, identity, revocation, rotation, recovery-fence, resource or
cleanup assertion is weakened. Source receipt SHA256
`b07eecedbc620fe2b42281b817ac1d3eef47c221cb597edfa9d0f568b62a54e4`,
patch `ad834bdb7c20d73b7d98c390db38258fedcde44ee49edcc2c15293a06069e287`,
independent review `bf881c32621150a6affde40c69e9769bb115856f8d411ac93ddc91a2b50a700b`.
All ten reviewed files integrate with exact hashes. These are pure/temp controls,
not Docker IPAM or image acceptance.

The source mismatch is established by inspection. A corrected actual-image
baseline and recovery run are still required; the retained metrics do not
independently name an `InvalidEndpoint` failure or prove it was the only blocker.

## Explicit M4-76 hosted witnesses

The dedicated Linux workflow requires all20 new unit cases to be listed and pass
before nine isolated API-preserving behavioral mutations execute ten exact
assertion failures. Each mutation must match once, compile successfully and run
exactly one named test whose source location and failure message match the
planned witness. Compiler failure is never RED. Original source bytes are
restored and verified between cases; final all20 GREEN recompiles explicitly.
The original filesystem gate4 guard-deletion acceptance remains separate.

Each successful compile identifies a regular test executable under the private
target. Hashing is bounded to512MiB,1MiB chunks and30seconds within the shared
main deadline. Exactly one Cargo `Running unittests` record must name that
executable, whose hash must remain unchanged before and after each inventory or
test command. Public receipts contain fixed relative identities, sizes and hashes;
raw command logs, source backups and binaries are not uploaded. A complete run
records11 compile artifacts and13 bound inventory/test executions.

The controller owns a dedicated Cargo home/target and clean source checkout,
with45minutes main work, bounded group termination/reaping and60seconds source
restoration allowance. The workflow has a48minute execution step and60minute
job budget; cancellation on a newer candidate is disabled. A direct child is
reaped and its owned POSIX group checked absent; escaped descendants are not
observed or claimed joined. No shared quarantined native/cache resource is used.

V1 review rejects late-interrupt success and first-failure masking during receipt
persistence. V2 corrects both and passes30 mocked controls; four original-source
assertion failures and an initial fake-dispatch setup failure remain retained.
V3 adds binary identity binding:42 mocked/synthetic controls pass, and three
artifact controls fail against exact V2. All30 previous test methods are unchanged.
Independent final controller/workflow review SHA256
`7eb5d38bfca2069f05de2eea6e05b7550735d123b22a8665e91b701531b8dc46`;
controller patch `e6a7e2d4fdde379e85090acd3f4668f393a52ccae2d8bdc9dd1de3cd0add842e`;
workflow `aa8ca9d36c902e01d31937be79016fc8a6b2f0631dd3f71b1d3058bfaadf9c57`.
Real Rust execution, artifact binding, process supervision and the20/9/20 sequence
remain unrun. Required cross-platform Rust and full acceptance gates remain.

## Integrated local verification

The separate successor integrates all15 reviewed changed source files and the
reviewed workflow with exact hashes. Combined206 Fly controls and42 synthetic
witness controls pass, as do Python AST checks, declared-format secret scanning,
`git diff --check` and the evidence guard (606 verified rows,1898 table rows,
zero findings). The scan classifies two unchanged Redis URL f-string placeholders
by exact hashes, base bytes and AST formatted values; no credential value is
present and no blanket scanner exception is introduced. Its declared formats
are not universal secret proof. Existing five workflow receipt-dispatch controls
remain bound to byte-identical Fly workflow source. The integrated source is
unchanged during these checks.

Receipt SHA256 `8e062e44f4bd118dd2b85b0ade241e6c1e1073132b9f70416d8027e99381bf3b`.
All executed controls are local pure/mock/temp/static checks. No Rust formatter,
compiler, native workload, Docker, Redis, Node or Fly runtime is executed here.
Exact final-candidate hosted verification remains required before any eligible
merge; live deployment remains separately unauthorized.

## Predecessor disposition

#288 completes its ordinary CI with all14 jobs passing, including M7 at
2026-11-02T18:47:17+10:00, plus three-OS packaging and all five archive verifier
pairs. Final receipt SHA256
`af9cf29edbf8349e8d8b4f1f757c64deedb5a30437c49de591ecc44858f0b666`.
It is closed unmerged as superseded by #289 only after all six head-associated
runs are terminal. Its failed Fly run and automatically cancelled push CI remain
recorded; no run is manually cancelled and its branch/source remain preserved.
Main and the production completion criteria are unchanged; hourly continuation
remains enabled. License policy, actual Fly access/inventory/PKI/operations and
live deployment authorization remain outstanding.
