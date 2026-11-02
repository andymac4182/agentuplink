# Fly rehearsal failure and follow-up

Production readiness remains open. The owner-authorized consolidation #284 is
merged; the new Fly profile in #285 is not. Its first four image builds pass,
but its actual cluster rehearsal fails before bootstrap. The failed attempt,
cleanup errors and exact artifacts remain retained. A separate correction must
pass its own hosted run before any merge or deployment claim.

Main `626ba9365b5d3e1faf8265f0b6ff50cc9111b749` subsequently passes its
own [14-job CI run 41395438209](https://github.com/andymac4182/agentuplink/actions/runs/41395438209)
at 2026-11-02T16:17:31+10:00 and three-OS packaging run 41395438262.
The actual main M7 job `125115637719` passes; its decoded log SHA256 is
`cc821003e842d3b54b2e0720f1724c602ef84be66dfd53eaa5daa2ca3d599d54`.
Automatic [development release run 41398988746](https://github.com/andymac4182/agentuplink/actions/runs/41398988746)
subsequently passes all five builds, five native archive verifiers, attestation
and publication. Tag `v0.1.0-main.41395438209.626ba9365b5d` binds that exact
main commit/tree and publishes at 2026-11-02T16:30:47+10:00. Ten hosted
attestation subjects and exactly eight published assets are recorded. The
release is a prerelease, not a draft or latest, and the API reports
`immutable=false`. All four tiny checksum sidecars were independently downloaded
and exactly match the published archives' GitHub SHA256 digests. Large archives
were not downloaded or executed locally. Terminal receipt SHA256 is
`785671c3930e837e59c77e6ccd7d24001b54ced631e788ecaec1fae1d556b32a`.
This existing release pipeline does not deploy to Fly or close the production
criteria.

## Exact first attempt — C258 / C260

[Fly run 41396035468](https://github.com/andymac4182/agentuplink/actions/runs/41396035468),
job `125117444634`, attempt 1, finishes failed at
2026-11-02T15:56:45+10:00. PR #285 head is
`d343d21c1b1e6f753a60c2a862de89e8762698de`; the actual runner checkout is
`fe6fc25ad2171d1357c5a443345e43f32f03c3a6`, with identical tree
`08f73eb78d406d6b5e40612ffa7411620cfb972a`. Source is clean and unchanged
before and after execution. The actual images are Linux amd64 Docker config
identities, not published registry manifest digests:

| Role | Image config SHA256 |
| --- | --- |
| Relay | bc9e910d0596a37b20330818b8a6f8a76512393fd10fe40bf4532637118e9bf5 |
| Authority | 95fd784c92dca6d5805ace004e810dad770826c03acd8ad95d95687ae33aec56 |
| Redis | 61662b0b36fec1a7895548790885a903fcdd8cce6215a88fa448c8041475b4a1 |
| Rehearsal client | 4b23102330a3a0f982c07a3554b45942b43106a355d7b7b486fafd04c9d80176 |

All four source-labeled builds pass. The controller extracts each shipped
executable and verifies its notice inventory before attempting runtime startup.
The exact image/binary/notice receipt has SHA256
`b41a3741c20283280e5a6db73b747f3fb37b350c23a6138496f513484c426ddb`.
The complete nine-file sanitized artifact is `13119861808`, ZIP SHA256
`2ed29a12d948acbe608c55b2d7d69275e3e60229ef8a8e2c8252703f000ff9ec`;
decoded job log SHA256 is
`e9bdb08fa46056eea5bf3a3e13f6f63a427398a0673c37e05fa60dcd3cae635b`.

The first runtime failure is command 85: `prepare` / `docker_container_start`
/ `python-helper`, the first volume initializer. The command exits 1 after
0.150 seconds; Docker later reports container exit 128 without OOM. Its stderr
is 157 bytes, SHA256
`80a868096821299612792f8e0917bc2abf47d10457d368b829edc8e23bdf720e`.
The whole controller lasts 19.294 seconds. Catalog bootstrap, authority/relay
service startup, clients, cross-relay routes, rotation, revocation and restart
acceptance are all **unreached**.

Five cleanup log captures also fail; each stderr is 83 bytes, SHA256
`73cd41bda8d98d78c6c4122d7b314135fc53d000c8fd060b86ccb721efb31ec6`.
Removal and absence checks nevertheless succeed for all five owned containers,
two volumes and the network. All 126 recorded process groups are absent;
source/images remain unchanged, with no resource-floor, OOM or swap failure.
Successful removal does not change the five log-capture errors or aggregate
failure into passes. Result SHA256 is
`db31fa7dbbc7142d515b3b551633925b0d587b4c00c0f1875aac48c8d4821635`.
The initial failure review, SHA256
`0376240f1f4e8ecaef5c81c786d2d9257a7d890243cea2287b32f00de506a949`,
correctly left the cause unclassified at that observation.

Regular PR CI run 41396035417 later completes all 14 jobs successfully at
2026-11-02T16:29:12+10:00 on this same candidate; packaging also passes.
Those results do not override the distinct failed cluster workflow or establish
any of its unreached runtime assertions. The candidate remains unsuitable for
merge on ordinary CI alone.

## Subsequent diagnostic attribution and correction

The controller requests Docker's `local` log driver, `max-size=2m` and
`max-file=1`, while leaving compression at its default. Public Moby source at
`9aa9edfa787e08bb2da31694cd8a402876f32232` rejects compression with a single
file. The fixed error and standard wrappers reproduce both retained stderr
lengths and SHA256 values exactly:

- [Local logger validation](https://github.com/moby/moby/blob/9aa9edfa787e08bb2da31694cd8a402876f32232/daemon/logger/local/config.go#L61)
  supplies `compression cannot be enabled when max file count is 1`.
- [Logger initialization wrapper](https://github.com/moby/moby/blob/9aa9edfa787e08bb2da31694cd8a402876f32232/daemon/container/container.go#L712)
  and [task creation wrapper](https://github.com/moby/moby/blob/9aa9edfa787e08bb2da31694cd8a402876f32232/daemon/internal/libcontainerd/remote/client.go#L231)
  supply the first-start context.

This is independently checked fixed-public-diagnostic equality, not a runtime
reproduction or a claim that the hosted daemon's entire source revision is
known. It attributes the observed logger configuration failure without
recovering credentials or uploading private raw command logs. Earlier unknown
observations are preserved; this later evidence supplies their missing cause.
The independent diagnostic review receipt has SHA256
`8855ba12647ce8a9214e97b54ba0d46aef9024b0a0f86e2a98c1501b9e4e7040`;
its retained public source bundle has SHA256
`76dbc39cb0838ffa165290835fddba6da13a5acf12ea390030224f8219f76bd3`.

The narrow correction explicitly sets `compress=false`, retaining the same
driver, one-file count and `2m` size. It does not increase log or resource
budgets, skip log capture, weaken cleanup, or change application behavior.
Exact logging-config checks and closed Docker failure diagnostics are now
implemented in a separate checkout. The original logger configuration fails
seven new controls; the isolated logging correction passes 43 controls.
No never-started-container exemption or skipped log capture was added.
Local native/Docker/Cargo execution remains
quarantined; hosted verification of the corrected candidate is still required.

## Separate pre-runtime authority observer correction

Review also finds a distinct C258 rehearsal defect, never reached by the failed
first attempt. Its observer uses relay a's checkpoint-client identity and asks
for checkpoints during authority restart while all three relays are serving.
The authority permits one concurrent request per node, so the observer can
compete with relay a and receive or induce a 429. This repeats the mechanism
already corrected in the native C248 acceptance fixture; it is not evidence
that the first Fly failure reached this path.

The reference contract is
`crates/tunnel-test-harness/tests/common/authority_publication_observer.rs`.
The follow-up permits direct observer HTTP only before any relay serves,
with a guard before request construction. During restart it will read the
authority baseline after the old process has stopped, then requires a newly
confirmed membership version above that stopped high-water mark. Observations
must bind the exact inventory, expected Redis run, three known nodes, strict
schema, bounded confirmation window and monotonic u64 counters. An old persisted
`confirmed` value alone is insufficient: `Engine::open` preserves that value
while resetting its process-local freshness deadline.

Once a new confirmed publication is observed, freeze the checkpoint allocator's
H+1 and membership target once. Every real relay's correctly scoped durable
envelope must reach that checkpoint and all three node-version floors before
acceptance. The actual relays continue to perform signature/nonce verification;
the passive observer is not a new trust source. Authority observations are
capped at 256 KiB and relay observations at 16 KiB; duplicate/unknown schema,
wrong identity, rollback, expired windows and moving-target shortcuts fail.

The 30-second publication bound now includes passive durable adoption and all
reader commands; the subsequent existing 60-second readiness wait remains.
This is stricter than the original publication-only observation. The authority
publisher's first tick occurs immediately after restart, and each relay's
default five-second reconcile obtains a new checkpoint and persists its floors.
Docker reader overhead is still unmeasured. The command runner reserves its
last nine seconds for group termination/reaping, so no fresh command is admitted
after 21 seconds in this phase. No 429 tolerance, skipped relay or relaxed floor
is added to compensate for that cost; any hosted deadline failure must remain
visible.

The combined logger/passive-observer source passes 57 pure/mock/temp controls
and AST checks. The original checkpoint method fails the new pre-network
serving-relay guard assertion. An initial observer test-double clock failure
is also preserved separately. These controls do not establish Docker, image,
native acceptance or successful recovery; a new hosted run remains required.

The reviewed controller SHA256 is
`098d28fe54254a789caa8eaa60d48162922de7c719aebb4af838b04b7b138011`;
its test file is
`d4a67fb40c04ffbb217d9b0eec7811cdb327a52e9246dd0b0d717bcbfb338471`.
The combined source receipt has SHA256
`810e2bbcb6ecb76d566c9f9ae5382c856c08965aa14fb2f62c11919fc5e2ad0b`.
Independent review finds no blocking source issue and verifies the retained
failure/control receipts; review SHA256 is
`916bdfe4498058784a399a99b617b0d71d91dee89dc063deb507fa1acd1ec49e`.
The frozen report's six-call reader estimate is corrected by an appended
receipt: a volume snapshot uses five Docker CLI calls. No measured runtime
cost or deadline success is inferred from either estimate.

## Separate advisory review — C259

After merge, GitHub's push banner reports 19 default-branch alerts, six high
and thirteen moderate. Reading the Dependabot endpoint returns HTTP 403,
`Resource not accessible by integration`. Its applicability cannot be checked
from that banner. The permission receipt SHA256 is
`c30d62f15f5102720c882e16b403119dd2ec9517deee6abae8d30129eba833bc`.

Independent public npm bulk queries at exact main `626ba936` return HTTP 200
with empty advisory objects for all 324 client and 147 MCP lock nodes, including
aliases, dev, optional and platform entries. This fresh feed result does not
reconcile GitHub's inaccessible alerts or approve licenses. The source-bound
triage summary SHA256 is
`847c23d4447d73cb390bfe8930e53cff9f3d0c11fa5e767e4058b011901233c9`.
Standalone vendored Cargo locks are not the root release resolver; no build or
CI invocation consuming them was found.

The independent Python query covers 373 CUA guest/build records plus one
separate checker-tool record. It returns 97 version/advisory records, 96 IDs
and 71 alias groups across ten dependency names; exact locked versions occur
in matching PyPI affected-version metadata and none of those findings is
withdrawn. CUA remains disabled. These dedicated guest/build findings do not
establish exposure in the deployed Rust services. Source/advisory bindings,
platform lock hashes and permitted distribution hashes are retained with
SHA256 `fae75b76bfa77b1956a4663bc66632dba6a84dba4ea96331d338ff486b416432`;
no Python package artifact was downloaded or executed.

Remediation has a concrete upstream constraint: `cua-computer-server` 0.3.46
requires FastMCP `>=3.2.0,<3.3.0`, while applicable
[GHSA-7xgj-8392-5q4r](https://github.com/advisories/GHSA-7xgj-8392-5q4r)
fixes the 3.x line at 3.4.10. The observed PyPI release index has no newer stable
server release. An incompatible override is not a supported fix. The plan
retains both Linux/Python 3.12 and macOS/Python 3.13 resolutions, the explicit
Darwin-24 framework input, Linux build dependency and artifact-hash parity.
Its old macOS release cutoff must be advanced explicitly when compatible
security updates are resolved. No pins, hashes, license policy or supported
platforms have changed; resolver and dedicated-VM acceptance remain pending.
Plan SHA256 is
`aa4cd35eb540c35bfb1704952845b0d48dfeaeffd6be3ff40adb19ef8b1dfc21`.

The [new source-bound checker](m6-cua-dependency-audit.md) initially has 59 passing
offline controls at source SHA256
`ac06332a29e736e8ec4b23c7d547870f49ac2d1e4c6de7ddf3830669789a261f`. Its real second attempt at
2026-11-02T16:19:48+10:00 covers
all 373 CUA lock records and 270 distinct pairs, binds all 97 active records,
96 IDs and 71 alias groups, and correctly exits nonzero. There are zero withdrawn
or unknown bindings; the only 97 refusal reasons are active findings. Exact
report SHA256 is
`aebb7b6e8fd5a66998ec7296490dc4139ec9d32339fa5fec0999781a5b311539`.
The first incorrect count expectation and first real timestamp-precision
binding failure remain retained. OSV's batch/detail microsecond-versus-nanosecond
encoding is handled narrowly with both raw values retained; revisions inside
one batch-reported microsecond cannot be distinguished. CI adds only offline
checker controls, with no waiver or claim that the live dependency gate passes.

Independent review then finds additional checker defects: nanosecond chronology
could accept an invalid withdrawal, invalid timezone offsets could normalize,
unlimited cgroups could skip OOM counters, and exponent overflow could enter
strict JSON as infinity. The request deadline also needed interruption during
blocking socket operations, and report serialization needed a separate bound.
Targeted failures on the old source are retained. The correction compares exact
nanoseconds, treats lossy withdrawal evidence conservatively as active, validates
offsets and finite numbers, samples available OOM counters regardless of the
memory limit, and uses a main-thread alarm with handler/timer restoration.
This does not claim hard interruption of every native DNS/NSS implementation.
Streaming reports have an 8 MiB cap and resource checks; failure preserves the
previous snapshot and emits an explicit incomplete envelope capped at 16 KiB.

The corrected checker SHA256 is
`01a49eeb7cbbaf4fb75df1fbb211ea4632cd4817ad189646f27ea4fa0bc596eb`;
its 76 offline controls pass. Exact replay of the 99 retained responses has
**zero network requests** and still refuses 97 active records with complete
373-record/270-query coverage. Replay receipt SHA256 is
`3b0e56ee665a7dde7ff8f1d3a5976e588c6afc55afa613386ed2a930c07cb739`.
The old live report remains bound to its original source; the replay is not a
fresh vulnerability-feed observation. No package or guest code was executed.

Independent delta review verifies all 234 correction-artifact hashes, all eight
input hashes and the unchanged ASTs of all 59 prior controls plus 17 additions;
no remaining concrete source blocker is found. Review receipt SHA256 is
`118add29eb89f1f71804cf91c5552c1cdb769531f9a94dc05bf1d8805002abc7`.
The integrated checkout then independently passes 57 Fly and 76 CUA controls,
changed-Python AST checks, the 35-file declared-format secret scan and evidence
guard (606 verified rows, zero findings). Integration receipt SHA256 is
`6b5e39a055669a4b79a4e8ae4ba00f0b4b061800b99a03c50a7ba37e638d2b24`.
These remain local pure/static checks; corrected hosted acceptance is pending.

## Current open-PR review

A read-only review at main `626ba936` finds the target dependency records from
#279, #280 and #281 already incorporated, as is #259's OTel update. #259 also
deletes platform/Windows/Python 3.10 records; those deletions are not incorporated
and must not be imported as a routine update. #251's handler-lifecycle fix and
#253's failed-witness diagnostics are absent and need separate current-main
integration and verification. #247 is partial, with existing M4-53 remaining
open and M4-70 retaining its later narrow implementation scope; a wholesale old
branch merge would disregard newer queue work. #249's authority runtime purpose
is superseded, but residual tests/docs are not all incorporated. #175's trust
retention work remains deliberately held/reverted under the existing M7-C86/C131
scope. No old PR is declared fully incorporated solely from ancestry.
Exact heads, blob comparisons and tracker row hashes are retained in receipt
`81c3f7990ef7f5d3530ff1a62d9b0eb4e4aa5624ca885fae4df11cf3f573f3a0`.
This review does not reproduce a new runtime defect or authorize the held work.

The goal and continuation remain active. Actual Fly access, inventory, public
PKI/OIDC, off-host recovery/capacity/soak and operations are still unverified;
the existing M4-47 security rejection and all owner license decisions remain
explicit. No live deployment follows from either source merge authorization
or these local/static and hosted fixture results.
