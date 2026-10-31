# Integrated candidate evidence, 2026-10-31

The integrated runtime candidate passes the local and hosted checks below.
Production readiness remains open: these results do not supply the actual
deployment inventory, owner license decisions, off-host capacity/soak or
operational ownership. Nothing has been merged, published or deployed.
Earlier failed attempts in the [acceptance history](production-acceptance-2026-10-31.md)
remain failed; this is a separate successful candidate.

## Exact candidate and scope

| Identity | Value |
| --- | --- |
| Draft | [#273](https://github.com/andymac4182/agentuplink/pull/273), based on #272 |
| Local/head source | `8c8c14fc9f6bb164daad224ad7300c04389a296f` |
| Hosted checkout and release source | `f2945e8196187bc7aec1d4415a58d3dde19b4e8b` |
| Identical source tree | `d6969b5a8e13cf09ade1cf6b410848f7ced2851f` |
| Cargo.lock SHA-256 | `e255f401d45e150b41b86cb69094366fcc9b0ffc4f420caabc52fb02630e0399` |
| Release version | `v0.1.0-main.41178887933.f2945e819618` (development) |

Later test/documentation commits are distinct candidates. Their focused
checks cannot inherit an assertion that the complete suite ran at their head.
The local frozen source checkout and executable copies remain unchanged.

## Complete local checks

Rust 1.95.0, locked dependencies, two build jobs, debug information and
incremental compilation disabled. Process tests use a child subreaper because
this environment's PID 1 does not reap. No acceptance assertion changed.

| Check | Result |
| --- | --- |
| `cargo fmt --all -- --check` | Pass, 4.777 s |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Pass, 75.823 s |
| `cargo test --workspace --locked` | Pass, 335.537 s; 2,922 passed, zero failed, 108 ignored across 174 suite results |
| Real locked compiler-JSON preparation | Pass; 34 test executables and five runtime binaries independently copied outside Cargo, 1,036,148,520 bytes |
| Provenance, packaging declarations, live repository visibility and accessible-history secrets checks | Pass; 2,068 commits, 6,891 blobs, zero findings in declared scanner formats, no oversized blobs |
| M1 | Pass, 17.269 s |
| Accelerated M2 | Pass, 14.068 s |
| M2 real-socket faults | Pass, 20.519 s |
| Three actual 300-second M2 rotations | Pass, 907.339 s; one retained connection-reset warning |
| Complete M7, all 86 stages in original order | Pass; 1,988.122 s stage interval |

The 90-stage combined run completes once, with no skipped stage, scenario
retry, relaxed timeout or synthetic build receipt. Its stage interval is
2,947.391 s. All source/script/argv and 39 executable hashes remain unchanged;
all recorded root/stage process groups are observed absent. Nested children
use the explicit frozen binary paths, including the adjacent client/deadman
pair. The prior mixed-artifact OG-02 result remains inconclusive.

Selected M7 results are authority lifecycle 115.543 s, authority lost-reply
and real Redis restart 65.831 s, older-backup/operator recovery 114.343 s,
forwarded quiet/blackhole liveness 105.688 s, actual CLI reconnect 104.838 s,
three synthetic CLI rotations 14.820 s, signed trust expiry 13.620 s, exact
stale-authorization timing 53.126 s, GOAWAY 14.220 s, C11 145.348 s and OG-02
235.485 s with all ten correlation rows. CLI reconnect preserves one PID,
survives 70 seconds of healthy idle, releases the old owner in 30,020 ms and
reaches second readiness in 30,608 ms, within unchanged 35/40-second bounds;
38 OWNER_BUSY refusals, three exact canaries and clean stop are retained.
The timing gate preserves dispatch count 1 to 1 and distinguishes the exact
stale cause from actual grant/credential invalidation.

Local Node evidence is explicitly carried forward: 601 offline and 33
installed-framework tests at `41746cf5`, with all 58 recorded source,
configuration and lock hashes identical to this candidate. Full M4 was not
rerun locally at this head; the fresh hosted full M4 result below is separate.

## Fresh hosted checks

[CI 41178887953](https://github.com/andymac4182/agentuplink/actions/runs/41178887953)
passes all 14 jobs. [Release 41178887933](https://github.com/andymac4182/agentuplink/actions/runs/41178887933)
passes all five optimized builds and all five native archive verifiers.
[Packaging 41178887926](https://github.com/andymac4182/agentuplink/actions/runs/41178887926)
passes. Attestation and publication jobs are skipped for this draft PR.

- Rust passes on Linux, macOS and Windows. M0 payload witnesses, M1, M2,
  M3, dependency/secret checks and complete M7 pass. M7 job 124472251759
  includes all ten OG-02 rows. No attribution to the exact historical
  offending HTTP/3 stream is inferred from the new pass.
- TypeScript job 124472251634 passes 601 offline and 33 installed-peer tests
  on Node 24.22.1/npm 11.19.1. The workflow requests Node 24.
- Full M4 job 124472251584 uses Node 24.21.0 and passes the filesystem demo
  and all registered gates. Its installed-framework gate observes host
  effects at 295,031 ms before the 300,395 ms freeze, generation 1 to 2 with
  the same session/epoch, 1,430 ms resumption, eight completed exchanges and
  20,480 bytes, zero replay/recovery/forced retirement, and sockets 3 to 2.
  Host tampering is red. Native unknown revocation completes in 330 ms;
  exact 404 EXPORT_NOT_FOUND and independent stream IDs 13 then 14 prove no
  refused allocation. Cleanup is joined.
- Image job 124472251601 passes actual relay/Redis TLS, enrollment, all seven
  catalog commands, revocation, exact traffic, reconnect, fail-closed Redis
  outage and AOF recovery. Relay PID 1 runs as UID 10001 and SIGTERM takes
  154 ms. Its actual authority image has startup-boundary checks only;
  the separate local image lifecycle is described below.
- The 96 MiB Redis/256 MiB no-swap profile passes the AOF headroom gate in
  21.304 s: 4,672 keys, two paused passes, 53,984 acknowledged updates,
  76,189,696-byte CoW, zero OOM/refusals/evictions/swap and intact count/canary.
  Peak memory including file cache is 269,066,240 bytes. This is not an
  off-host capacity or 24-hour soak guarantee; the owned container is gone.
- Python MCP advisory and seeded checker controls pass. They do **not**
  pass the unresolved universal license policy (MIT-0, PSF-2.0 and bundled
  Windows LGPL obligations). No exception or supported-platform cut exists.

## Original release artifacts

Every downloaded GitHub artifact ZIP matches its API digest; each original
archive's sidecar names and hashes that exact archive. All five native
verifiers pass seven checks each, totaling 74 CLI probes and 55 applicable
planted negatives. Five platform-inapplicable negatives remain explicitly
skipped. Existing archive contents are unchanged: Linux x86-64 and both macOS
targets carry four binaries; Linux ARM64 and Windows carry the two device
binaries. This is the existing advertised packaging boundary.

| Target | GitHub artifact ID | Original archive SHA-256 |
| --- | --- | --- |
| Linux x86-64 | 13034281888 | `5a140cc3a71502f7f4a6b4aa78d55cd1caab30741a445448612f62c9cc2e18ca` |
| Linux ARM64 | 13034186940 | `d92931a24dc7e9623c36544047d47936f717a914a647c37f676a799e4b7092ec` |
| macOS x86-64 | 13034322658 | `10a49787dcbbc51c6cfb9900c0508f579a3b1d10dae8fdf4e01d760d9e3c8bb2` |
| macOS ARM64 | 13033992796 | `ee368bb638e339a75b4e96ec8a7ad59f323698aaa053a0724f1189106be97e1e` |
| Windows x86-64 | 13034157206 | `09636347f3d22a1ce6384b3f8a72aaca4ba1e4f647dda3c507b263ab2feb3374` |

The original optimized Linux binaries were copied unchanged outside Cargo.
After the complete core run ended, four separate drills passed:

| Drill | Result and exercised runtime |
| --- | --- |
| Three-relay authority lifecycle | 116.631 s; packaged authority and relay, frozen source-matched test/library device connector |
| Older-backup/operator recovery | 116.079 s; same packaged authority/relay, actual recovery CLI, all preapproval refusals, both revocations preserved, two owned Redis containers gone |
| Actual CLI reconnect | 102.530 s; packaged client/adjacent deadman, exact-source in-process relays |
| Three synthetic CLI rotations | 15.357 s; same packaged client/deadman and in-process relays, success/cleanup markers checked |

Every selected executable, source input, archive and baseline receipt remains
unchanged; selected processes and owned groups are absent. These four drills
are not another full-suite pass or execution on every supported platform.
The local host uses glibc 2.41; the existing archive README specifies an
Ubuntu 24.04-compatible glibc environment.

## Current actual authority image

The actual local image is
`sha256:c9058e7d9a35727b242618d6b88b116996b0d8af9beabbbf3031903b91b98fac`,
built from the exact head/tree above. Its executable SHA-256 is
`f3c1e48bf2adb3b7e8ad3ed450d6c134b1479114375a0db75e9289eff7370c04`.
Notice verification, default UID 10002, help and missing-config refusal pass.
The unchanged source-matched three-relay lifecycle passes in 126.267 s using
this immutable image ID and the original packaged relay. All 14 owned
inspection/lifecycle containers are absent and input hashes remain unchanged.

The lifecycle fixture explicitly uses UID 1000; default UID 10002 startup is
checked separately. This does not verify mounted-secret provisioning for the
default UID, older-backup recovery with this image, legal policy or a live
deployment. The container uses a read-only root filesystem, no capabilities,
no new privileges, 256 MiB memory, one CPU and a 32-PID limit.

Failures are retained. The first launcher invocation hit EACCES before the
driver or Docker because the immutable Python file was invoked as an
executable. Explicit Python corrected only that launch. Actual build attempt 1
then failed the unchanged 2 GiB free-disk guard after 47.989 s (exit 130).
Although Docker had exported the image, the canceled build was not accepted.
After separately recorded removal of inactive, unreferenced root-owned Cargo
cache files, attempt 2 passed in 1.001 s using cache with minimum free disk
3,177,230,336 bytes. It produced the same image ID. The controller requires
that separate successful receipt and rejects the retained canceled one.
No image, proof artifact, other agent's input, Node dependency tree or Redis
fixture was removed; the referenced C94 executable remains unchanged.

## Retained evidence identities

Detailed receipts and raw logs are private local artifacts, not published
downloads. Paths below are relative to
`/workspace/agentuplink-review-artifacts/`. They contain full argv,
environment, timestamps and executable/log identities; public CI links above
provide independently accessible hosted evidence.

| Receipt | SHA-256 |
| --- | --- |
| `combined-final-preparation-20261031/preparation-receipt.json` | `b2529413f873925590d776b8272d55bb449f8f5916eebeb4a918ca0694866e29` |
| `combined-final-core-8c8c14fc/results.json` | `7ebe788c78cc8f61dbe4a9552969af7dfaa6a94b20ea99a4999657440e1aa20e` |
| `combined-final-core-8c8c14fc/core-completion.json` | `ea9bd338e8e006ca3d96550a3aa4436d7cd1f9a3c38da7506e9a693eb16a49fc` |
| `packaged-runtime-f2945e81/attempt-1/attempt.json` | `e95c2b3807d67be15b034f63a34a81e7a519aa41c45772037bbc5357fce0ae52` |
| `final-authority-image-8c8c14fc/lifecycle-attempt-1/result.json` | `e5526a067c77e68cbed415d2a2aa661d6e991146a954b27b4e86302df8a14121` |
| `hosted-followup-20261031/job-124472251759.log` | `91109ee50ffcc4cc046da9dcd9ece993fefd61b077ddf3320091aa0bcc9d1551` |
| `hosted-followup-20261031/job-124472251584.log` | `e676080fca4cbc4f4edc7a558ad5e1dc4f51285c47b213727804c0ff42a8921c` |
| `hosted-followup-20261031/job-124472251634.log` | `9604b087f0eea723a1a3a4d214aaa1f4298807b886bccbbec249122e3e4adaae` |

The [production goal](production-readiness.md) remains active. Final-candidate
checks, real deployment topology, recovery/credential inventory, operational
ownership, capacity and legal policy are distinct completion requirements.

## Integrated test follow-up

The subsequent test/documentation source
`86fb4d70bd0fd44596b2189c8b4a2f23c044c780`, tree
`7173d51c34481565898e33178460e642bfd07252`, adds the C240 valid-state queue
controls and C244 real-endpoint fid confirmation gate. Production runtime
behavior is unchanged: the only connector addition is inside `cfg(test)`;
other code additions are harness/TypeScript test drivers and registrations.
Its required local checks pass: formatting5.004s, strict workspace/all-target
Clippy91.590s and locked workspace tests344.785s, with2,931passed, zero failed,
108ignored and174suite results. Source hashes and the protected C94 executable
remain unchanged, and each check's process group is absent. Native builds ran
under an exclusive lease; the read-only history scan overlapped part of the
checks, so this is not described as a quiet timing experiment.

The full accessible-history scan at this source passes2,081commits/6,923blobs
with zero findings in declared formats and zero oversized blobs. The later
documentation-only status update receives a separate changed-blob scan; it is
not described as another full-history run. New-head hosted acceptance is
pending. The complete local90-stage and hosted results above remain bound to
8c and its identical hosted tree, not relabelled as a full run on this follow-up.

Private follow-up receipts are under
`production-evidence-followup/required-checks-86fb4d70/`. The receipt SHA-256 is
`d64204a04a7d596e2f95d43ef9b052b791af7bc37bf776b02f826cbb76088918`;
the workspace log SHA-256 is
`31cbc5ba846851c349e4cce38e1c412d07181fab26fe70dfcae32d848a61ff88`.
C244's original8804 and final9596 sources were archived with hashes after the
worker explicitly released the completed source/execution lease, before that
checkout was reused. Frozen executables, driver copies, dependencies and all
prior receipts remain untouched.
