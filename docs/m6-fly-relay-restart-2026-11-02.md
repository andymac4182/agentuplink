# Fly relay restart failure and successor evidence, 2026-11-02

PR #292 proves the separate client disconnect helper works in its hosted
fixture, then fails when the same relay-a container exits during restart. The
startup cause remains unknown. Same-AOF and physical older-backup recovery are
skipped; the candidate is not ready to merge or deploy. This report preserves
the earlier [#291 disconnect failure](m6-fly-disconnect-2026-11-02.md) without
attributing its exit 137 to the mechanism modeled by the helper tests.

## Exact candidate and regular checks

| Identity | Value |
| --- | --- |
| PR head | `9b0820974038685e7a4c6a9195c3a75a018dfcec` |
| Actual hosted merge checkout | `990d5627da890715fcfce453632fa75016673d57` |
| Shared tree | `a154b7e6b76e783aa9cd297964c327a3b597469e` |
| Base/main | `626ba9365b5d3e1faf8265f0b6ff50cc9111b749` |

At the retained 2026-11-02T12:52:38Z snapshot,
[CI 41443943028](https://github.com/andymac4182/agentuplink/actions/runs/41443943028)
has 13 of 14 jobs passing; M7 job 125272854226 remains active. All three Rust jobs
pass formatting, strict Clippy, workspace tests and examples. M4-76 has 20 named
cases passing on Linux/macOS and 19 applicable cases on Windows, preserving the
existing Unix-only case. All four M3-53 cases pass on each platform. M0 records
21 gates and 21 declared RED witnesses; M1 on both OSes, full M3/M4,
TypeScript, ordinary container smoke and M6/dependency jobs pass. M2 completes
three default 300-second rotations in 903.311 seconds. These jobs do not clear
the separate license-policy refusals.

[Packaging 41443943027](https://github.com/andymac4182/agentuplink/actions/runs/41443943027)
passes on three OSes. [Optimized validation 41443943055](https://github.com/andymac4182/agentuplink/actions/runs/41443943055)
passes five builds and five native archive verifiers; attestation/publication
are skipped. ZIP digests and inner archive checksums are distinct identities;
no full operation/rotation from every archive or local archive execution is
claimed. The private summary receipt is
`7dcde314d9373a973e60121c2b2e03cb99632a1f4c8ce5a11473b41cc1bbe2b2`.

## Actual image progress, failure and cleanup

[Fly run 41443943040](https://github.com/andymac4182/agentuplink/actions/runs/41443943040),
job 125272302303, passes 298 offline controls and builds all four images. It
reaches three ready relays, nine exact routes and one genuine missing-scope
`403/FORBIDDEN/not_dispatched`, with the grant still active, target visible and
positive echoes before/after. Three clients rotate at the configured 300-second
interval (300.704 seconds observed, 66 route rounds). Revocation changes grant
revision 1→2 and active→false; all three ingresses return exact
`404/DEVICE_NOT_FOUND/not_dispatched`. Six unaffected positive routes complete
through the immutable control flow; they are not individually logged.

The same-image default-user disconnect helper uses network none and only the
exact profile volume read-only. Its stopped acknowledgement reports supervisor
PID 1 and waited 101 ms. The original client then has exit 0, PID 0, no OOM and
empty Docker Error. No success-path Docker stop or retry is used.

The first failure is `service_not_running` in `restart_revocation`, operation
`docker_container_inspect`, after restarting the same relay-a container. The
stop/inspect/start/inspect commands all exit 0; the running-state assertion fails.
Cleanup observes relay exit 1, PID 0, no OOM and empty Docker Error. Its combined
pre-stop/restart stderr is 3,597 bytes, SHA256
`7b178c418381460f0ac7991efcd9a51c18354b1d9f88b4f41181e7e26e8c0ac8`;
closed codes/errno are empty and classification is unknown. Raw log bytes are
withheld. Post-restart readiness, fresh owner/session/epoch and persisted
membership comparisons, authority restart and both recovery scenarios are
unreached. Physical older-backup job 125278936122 is skipped.

These are Linux/amd64 Docker configuration IDs, **not registry manifest digests**;
each image records the actual `990d5627` revision. Hashes below are SHA256.

| Role | Docker configuration ID | Binary | Notices manifest |
| --- | --- | --- | --- |
| relay | `fd09a3aa7d1eb66a958fd8bddb6ae5281bfc9675d9ddfd30d3f28088612292bc` | `6dd97259169a37bdea722a53e3b91379ea48711f0a97ae7fafeca91ff37c9e8c` | `ea6da5fd8febbb71ca628a1bf20527c02f659c796351577f73d4e8bdbe5a87fe` |
| authority | `ec80196cd22c6a234463ed5bdab2b12b90dfc27499fd08bfd8c9159398cf4989` | `75a244f6896da55b1944aa539ecac1c15b54a219bc2f828aacfc896674ac7fc7` | `4250fff00009a1f4bd69106420e5765221b3d5be69f1b8d124cc70bd2bdc6179` |
| Redis | `ffae245b817001307ab390840220dab0b88b7043a61912983aecc9e67bb97125` | `a775ade32bc71fc06684b1cfae8ef4a68c7aa57fb402c836cf5d0063333719ab` | `a77b6beef70547c4caf8ecc362dcdb5f8fa536c6ca0cd914485066e36c98b3db` |
| client | `a0eb0e8581ce0cd70b46510b095c1b2890551b8e96bd70b0758da9a224aff58f` | `3b49a9ad41195ef31953ad11275ddfd7983685b501b7cafef5a4db1c44c778db` | `d9c2ec1251ae47b15492052529ba6c3b16f6ab8989fb4574d9e6d6deebae43df` |
| deadman in client image | same client configuration | `a14944fd2fa8e262faeaee911ac6a0b5f3289cf2c98ecdb72d7297eb31ded3b7` | `8551e47327bf9454b12e354730e018721415f472f53f39b5a70876692baba136` |

Cleanup confirms 47 exact container IDs absent, 12 volume removals with the final
owned-volume inventory empty, one exact network ID absent and 1,431 normal
command process-group absence observations. There are no recorded cleanup errors,
interruptions or OOM kills; source/images remain unchanged. Cleanup does not
erase the failed acceptance. Artifact 13142910604 is 61,115 bytes, ZIP SHA256
`a2c7814f5447ea318c9a3f54026282e5d26e4e4d1059af764a46719f8173ba70`;
result SHA256 `25b00e79f8885990505f97e70d11e314a38d6af0d6ef71afcdea1efd71705681`;
failure review SHA256 `4bfe4dcf4f05608e6909e3d000f6334e1c9f0ba72e5e06db3a7c8d93cbf92048`.
This is owned synthetic Docker/IPv6/fixture-CA evidence, not a live Fly deployment,
public PKI, backup durability, capacity or soak result.

## Fresh authorization mutation receipts

| Workflow | Actual acceptance | Artifact and receipt SHA256 |
| --- | --- | --- |
| [41443943044](https://github.com/andymac4182/agentuplink/actions/runs/41443943044), job 125272302881 | 20 initial GREEN; nine compiled mutants/ten intended assertion RED; 20 restored GREEN; 11 compile hashes, 13 unchanged pre/post run bindings, 85 normal child/group cleanup observations | 13141510993; `0687537eb4d3b92c320bd784ec0f496884cd1e2e48864553aeddca75f1436215` |
| [41443943152](https://github.com/andymac4182/agentuplink/actions/runs/41443943152), job 125272302239 | Exact original gate4 declaration/WITNESSES and whole-guard deletion: one GREEN, one compiled intended helper-line-219 RED, exact restoration/fresh compile one GREEN; three compile/run bindings, 25 normal cleanup observations | 13141925109; `d15360cfba41c29c8f6477ad492032d95e607c765812ddf52b8b6db0896a943d` |

Independent review `bac3498722fa37c98776d7083791e80c73652eaa37cf5a0725fa51402361ed9f`
binds the current merge/tree and exact mutation/assertion/source/restoration
identities. Original/final binary hashes agree within each workflow. Raw compiler
logs and executable bytes were not uploaded. Forced timeout/TERM/KILL/unknown
cleanup paths remain mock-only; escaped descendants are not claimed joined.
The original focused property does not execute the literal broad four-crate CLI.

## Reviewed successor preparation

The diagnostic correction adds only a passive, bounded `relay_terminal` projection
to existing log receipts: 39 exact source literals and 120 valid bootstrap tuples,
complete-line matching, fixed codes/counts, whole-input bytes/hash and an explicit
absence of lifecycle attribution. Unknown, dynamic and partial lines do not become
causes; raw text is never emitted. Two baseline observation-loss assertions fail;
314 offline controls pass. A missing sparse source input in the first combined
attempt is retained separately. Source receipt
`0f458f40b01899f465b71dbdfbfa51f6f1d7cd59eef0835ee460502e792f0400`
and independent review
`46006b2bab8e6d08f2d54943df4ed2c6c513f8a355f3df930c0dc402b6ed80c9`
do not diagnose or fix #292's historical startup failure. No product decision,
acceptance assertion, request, deadline or cleanup behavior changes.

The separate [operator output verifier](deploy-fly-cluster.md) checks regenerated
authoritative bytes for the exact 11 files/five roles, bounded directory/file
traversal and final identity rechecks, without writes or repair. Its **new
`--verify-output` mode requires POSIX no-follow descriptor support** and refuses
unsupported systems; existing rendering/platform support is unchanged. It is not
an atomic snapshot/writer lock, ownership/permission attestation, trusted approval,
certificate validation or runtime proof. Inputs/output must be exclusively
controlled and rechecked before use. Its 52 pure/temp controls (28 existing plus
24 new), two intended comparator/final-binding REDs and independent review
`3ac3ebf39d647ec8fac344cf4435436a1a038aa4af221d5e315d393b8a612a82`
support source integration only. Source receipt is
`ebb0703c7868b615352ca57c1803468eac37106070888754585424c42cfe7501`.

The exact reviewed patches apply together without manual composition changes:
338 combined pure/temp controls pass in 1.193 seconds, all 510 materialized source
files unchanged and both resource reserves maintained. Receipt
`83c185912c686b11d235075e76c9691b35a016d522d4718b025a0c58f9d92bc3`
does not replace new candidate hosted/native/image checks.

## License finding and remaining deployment work

Investigation receipt
`c64ffb84218872b49b47248fea524204fc49962ce383d69bf9a3abe438cf55ac`
finds no safe compatible automatic dependency replacement. All five C253 and
three M3-50 policy refusals remain. cffi 2.0.0's PyPI metadata says MIT, but its
verified source LICENSE is byte-identical to 2.1.1's: 1,123 bytes headed MIT No
Attribution, SHA256 `5ba24ddc57067f9249add644c3afc41a5d6dc37e23433ef759d95df370b0af63`.
A downgrade cannot turn that metadata difference into an allowed license.
It would also lose actual crash/compiler/Python 3.15 ABI fixes and newer platform
coverage (83 versus 99 observed wheels, including new cp315/iOS coverage).
The initial duplicate flattened PKG-INFO inspection refusal is preserved; the
corrected bounded inspection uses distinct paths. No source/lock/policy change,
dependency installation, optional-branch/platform removal or exception occurred.

Full baseline/restart/same-AOF/physical-backup acceptance, production reconciliation
and independently trusted revocation/counter/backup custody remain required.
Actual Fly inventory/access, PKI/OIDC, operations ownership, capacity/24-hour soak
and live deployment authorization remain open. C259 advisories, C256's local
native/cache quarantine and the M4-47 security block remain unchanged. The
continuous production goal is active; hourly automation is disabled. No task or
production completion criterion closes from this report.
