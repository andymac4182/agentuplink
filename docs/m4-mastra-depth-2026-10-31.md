# Mastra traversal bounds and real framework integration

M4-75 corrects a descriptor-limit bypass and a false-complete default listing.
The adapter previously used a caller's `maxDepth` in place of the descriptor's
ceiling, and silently stopped default recursion at that ceiling. The correction
rejects invalid depth with typed `EINVAL` and above-ceiling depth with `ELOOP`
before I/O. Default recursion fails with `ELOOP` if it would descend beyond
the ceiling. Explicit integer depths from zero through equality retain Mastra's
intentional bounded-view semantics. Entry quotas, descendant prefixes, extension
filtering, grants and deadline policy are unchanged.

Source correction is `b117a6e835cdfc15c334bba3e18b0065d31bbef0`; the later clean
documentation head used for actual integration is
`4df856ec900d375cf0897727ec42fbc489fc4b98`, based on PR #274 head `107d94a2`.
Broader M4-21 remains open. Hosted verification of the narrow Mastra scope is
recorded below; the full candidate and M4 job remain separate gates.

## Boundary proof and package checks

The corrected tests-only baseline reproduces three failures: descriptor override,
false-complete default traversal and invalid-depth acceptance. Six controls pass.
An installed Mastra Workspace test independently fails on the missing typed
refusal. An earlier helper inspected the wrong wire field; that fixture failure
is retained and excluded from product evidence.

After correction, nine focused tests and the installed Workspace case pass.
The full pinned Node 24.21.0 `npm run check` passes in 21.729 s: 610 offline
tests, 34 installed-peer tests, lint, type checking, build and distribution lint.
The actual check ran on `107d94a2` plus the recorded source/test patch, not on
a pre-existing clean `b117a6e8` checkout. All 69 checked package/configuration
input hashes remained unchanged and exactly match the committed correction.
The checked patch SHA-256 is
`b4f7ae13d14c3a2dcd6761fce4aef8b98bd658a8721d21096b07fcc8b58a2b5b`;
full package result SHA-256 is
`11c7d7b84acd2607ebc0dc78459e717312e9409bd2893ea62413e21bdac8c5fb`.

These tests use real installed frameworks and a loopback protocol peer. The
following separate run supplies actual Rust relay/device integration; its
read/write workloads do not themselves exercise the traversal-depth boundary.

## Actual 300-second integration at clean 4df856ec

The unchanged `verify-m4-fs-adapters-rotation` gate passes on its first actual
attempt in 311.020 s. It uses four installed frameworks, real relay/device
sockets, the pinned Node binary, verified TLS and a unique namespace in the
existing Redis fixture. All 1,082 tracked source files remain unchanged.

| Observation | Result |
| --- | --- |
| Independent host write check | 295,033 ms, before scheduled rotation lower bound 300,402 ms |
| Rotation | Generation 1 to 2, same session epoch; resumed in 1,393 ms |
| Replay/recovery/forced retirement | Zero replay; no recovery or forced retirement |
| Sockets | Peak three, final two |
| Completed framework exchanges | Eight, with 20,480 bytes written |
| Independent host negative | Fails as required |
| Live revocation | Native framework outcomes pass in 411 ms |
| Revoked admission | Exact refusal and no stream allocation; control IDs 13 to 14 |
| Isolation controls | Non-owner refusal and independent grant survival pass |
| Cleanup | Gate joined; owned process group 597741 absent; both completed namespace scans report zero |

All 69 package/configuration inputs and all 16,798 dependency entries retain
their hashes. Node, harness, controller, subreaper and the protected prior C94
executable are unchanged. No timeout, assertion, quota or policy was relaxed.

The shared filesystem lacked comfortable build headroom. A minimal locked,
offline Rust 1.95.0 harness build instead used a fresh target on the separate
temporary filesystem, passing in 183.147 s. Real compiler JSON identified the
executable; an independent mode-0555 copy was selected for the gate. The build
and frozen executable are retained under `/tmp`, which is temporary environment
storage, not a durable artifact store. No old cache, proof, image or dependency
tree was deleted. Minimum workspace free space during the actual gate was
1,804,087,296 bytes, above the unchanged 1.5 GiB reserve.

The first launcher stopped before any harness/Node child or Redis write because
`redis-cli` was absent. Its failure and original controller remain preserved.
A separate controller used the existing bounded standard-library RESP scanner;
completed scans are required, and a diagnostic failure cannot count as zero.
That corrected launcher ran the first actual gate above. No live failure was
hidden or retried.

| Retained input/result | SHA-256 |
| --- | --- |
| Actual frozen harness | `2ac37f3d638429cd75dc61a821fe1c2cbd086df9dd70e54390b517cc8568b001` |
| Node 24.21.0 | `7fde7b8afa198da66257f42ee2001d874c7355631e6d1579a5fb5ef1f246df4c` |
| Dependency manifest | `d6ce3dcf3876f8f86e52f24b8531dae0f8c6457ab87e7bc3243b81a26f4bce61` |
| Corrected launch controller | `656ed8d4b5ffd09a0312719c44d0f0ca26d76a02007e4cdff44ad2593d5638cb` |
| Corrected freeze receipt | `f112c49a28f01b160e04e62c6d22a606860f61cef706e7a9ace41bfde2c88cad` |
| Actual gate result | `17ddb0504cbb55dd55801783dd883b9086d24fc333766da548d3d9851c8897e4` |
| Actual gate log | `d4f3391e36cde8e8daf9b85b42faee1f99f998fa0c65e70b403b5a39a4cf3888` |
| Final integrity receipt | `ad7bac70ca7bfdeaa4a7acadb081ae57f7fc429b5a90287f97e778c759e9da7e` |

Detailed private evidence is under `agentuplink-review-artifacts/mastra-depth/`,
with actual integration in `integration/`. Rust source, manifests and toolchain
at `4df856ec` are identical to the earlier `86fb4d70` required-check inputs;
that 2,931-test Rust result is carried forward by input equality, not reported
as a fresh workspace run. This gate is not the complete M4 suite, a hosted run,
a production deployment, or closure of the broader filesystem requirements.

## Hosted Mastra scope on PR275

The narrow M4-75 scope is verified local and hosted at
2026-10-31T20:49:49+10:00. PR275 head `b13f43cd` and actual hosted merge
`5909dc38ec843275e81dd2c73116b91ded575934` have the identical tree
`2bf1832d3554b1c9aba2f9478d2f980fc10b2ed8`.

TypeScript job124515625904 passes all nine depth controls and the installed
Workspace case within 610 offline and 34 peer tests on Node24.22.1. This is
separate from the earlier pinned Node24.21.0 full package proof.

M4 job124515625939 passes the standalone installed-framework rotation gate
on Node24.21.0 (311.346 s between the command-start and success log records).
Host writes are checked at295030ms before the scheduled lower bound300398ms;
resumption takes1354ms. Eight exchanges/20480B, zero replay/recovery/forced
retirement, sockets3→2, native revocation422ms, exact refusal/no stream
allocation13→14, independent grant/non-owner controls and joined cleanup pass.

The shell then proceeds to C200 and the separate C244 fid-confirmation command,
which fails its final independent witness. The **whole M4 job and candidate
remain failed**. The successful earlier command supplies only M4-75's stated
integration acceptance; depth boundaries are proven by its focused tests.
Broader M4-21 remains open. The two moderate npm audit entries are separately
tracked as M6-C252, with no exception or dependency compatibility claim.

Retained hosted log SHA-256 values: TypeScript
`c5bf2c593fa585b6ffda94432a34fede4de267c859d6e9eb65d017f4da8b28fa`;
M4 `9187f86018b42c111b24bbec73453e15a042c942f76a9cbcb7876a2b71ab97c5`.
