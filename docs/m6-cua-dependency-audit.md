# CUA dependency advisory evidence (M6-C259)

`scripts/cua-dependency-audit.py` checks the complete, hash-locked CUA
fixture graphs against the public OSV API. It does not install packages, resolve
new versions, execute guest code, approve licenses, or enable CUA. A passing
seeded test suite proves checker behavior; it does not mean the real graph passes.
Any active returned advisory, at any severity, causes a nonzero result. Missing,
ambiguous, changed, unsupported, or incomplete evidence also causes a nonzero
result.

The current graph has known advisories and the real gate is expected to fail.
There is no exception mechanism or severity cutoff in this checker. CI runs
the offline refusal controls using the existing hash-pinned parser environment.
The real advisory gate and remediation remain separate follow-up work; these
seeded checks do not establish continuous enforcement of the actual graph.

## Exact scope

| Input | Records | Role and resolver target |
| --- | ---: | --- |
| `tests/cua-fixture/requirements-linux-aarch64.lock` | 109 | Linux aarch64 guest runtime; Python 3.12, `aarch64-manylinux_2_39` |
| `tests/cua-fixture/requirements-macos-arm64.lock` | 263 | macOS arm64 Darwin 24 guest runtime; Python 3.13, `aarch64-apple-darwin` |
| `tests/cua-fixture/requirements-build-linux-aarch64.lock` | 1 | Linux aarch64 `evdev` build tooling |
| **Total** | **373** | **270 distinct canonical PyPI name/version pairs** |

Every locked record participates, including markers, optional dependencies and
platform-specific dependencies. Markers are parsed and retained but never
host-filtered. Canonical PyPI names determine query identity; each returned
advisory remains joined to every matching lock occurrence and its allowed
SHA-256 distribution hashes. Those hashes identify the lock's permitted artifact
set. This gate does not download or verify wheel/sdist bytes and does not claim
an installed artifact or executable call path.

The checker also hashes the three `.in` files, the Rust CUA server pin, and the
pinned `packaging==26.3` parser-tool requirements file. It verifies the server
root extras/version and exact wheel/sdist hash parity in both runtime locks,
the 158 explicit Darwin PyObjC input pins, the Linux build input/lock binding,
and the parser pin. The parser-tool record is **not** a fourth CUA graph. Earlier
public-feed triage queried 374 records including this separate tool record;
`packaging==26.3` already occurs in both CUA runtime locks, so the combined query
also had 270 distinct pairs.

Counts are deliberate completeness guards. A legitimate lock/input/platform
change requires review of the guard and its tests; deleting records to satisfy
the gate or replacing the two platform locks with the host graph is not valid.
The CUA fixture is disabled in the production profile. These guest/build
findings do not establish a vulnerability in the shipped Rust server graph.

## Running and reading evidence

Use the existing Python environment with the repository's hash-pinned parser
version; a different version is refused. The checker does not install it.
Run from the repository root on Linux, where the resource guard can observe
`/proc/meminfo` and, when present, cgroup memory counters:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s scripts -p test_cua_dependency_audit.py -v

PYTHONDONTWRITEBYTECODE=1 python3 scripts/cua-dependency-audit.py \
  --output /tmp/cua-advisory-evidence-unique
```

The evidence directory must not exist. Each request is recorded before network
access; response bytes, SHA-256 identities and terminal request status are
retained. `report.json` contains exact source hashes, all lock records, query
coverage, advisory bindings, raw published/modified/withdrawn timestamps,
aliases, affected ranges, occurrence joins, resource observations and errors.
An interrupted or failed query is not retried. Exit status is zero only when
all coverage/integrity checks succeed and no active advisory is returned.
An output-path creation failure occurs before the report exists and before any
network request.

Only `https://api.osv.dev/v1/querybatch` and validated advisory IDs under
`https://api.osv.dev/v1/vulns/` are used. Redirects are refused. Inherited proxy
and CA settings remain effective; no credentials are supplied by the checker.
Responses use strict duplicate-field and nonfinite-number rejection. Batch
result count/order must cover every submitted query; pagination or unknown
batch fields are refused. Details must match the exact ID and modified instant.
OSV's observed batch encoding truncates detail nanoseconds to six fractional
digits: the checker permits that narrow representation difference, retains
both raw timestamps, and rejects a changed microsecond, second or date. It
cannot distinguish revisions within the same batch-reported microsecond, so a
lossy-bound record cannot use a withdrawal to suppress an active finding.
Published/modified/withdrawn/observation chronology uses exact nanoseconds, with
strict timezone offsets; unknown `-00:00` offsets are refused.

Affected versions use the pinned PEP 440 parser. Only explicit matching versions
or understood PyPI `ECOSYSTEM` interval events establish applicability; unknown
range types and malformed intervals fail even when an explicit version matches.
Withdrawn records remain in evidence and are not active findings only when their
identity, version scope and withdrawal timestamps validate **and** the modified
instants match exactly. A lossy modified binding retains the record as active
with `unverified-lossy-modified-binding`. Alias groups are
informational: they never delete records, suppress active advisories, or turn
severity into an exception. One withdrawn alias cannot hide an active record.

The maximum is 128 queries per batch, 512 distinct advisories, 8,192 returned
advisory records, 4 MiB per batch response, 1 MiB per detail response and 32 MiB
total response bytes. Reports use streaming encoding with an 8 MiB cap; the
observed real report was 1,960,863 bytes. Every normal persist checks resources
and reserves report-sized disk headroom before writing, checks while encoding,
and checks after writing. Failure preserves the prior full snapshot separately
and emits a capped 16 KiB report marked failed with incomplete evidence. It
does not continue acceptance or reuse a prior pass. Raw responses remain intact.

Requests are sequential, with a 15-second socket timeout and a 180-second
Linux main-thread `SIGALRM` observation guard around the whole query sequence,
including open/header/body calls. An occupied timer is refused before network
access; the checker restores the previous handler and cancels only its own
timer. The alarm closes the demonstrated slow-body wait gap; Python can only
run signal handlers when the interpreter regains control, so a blocking native
DNS/NSS resolver is not proven to stop by that alarm. This is not an independent
hard process-wall-time supervisor; a stricter runner must provide one. Source
files and logical lines are bounded. The disk floor is 1.5 GiB on evidence, `/tmp` and `/workspace`
filesystems. Available-memory estimates require 4 GiB at startup and 3 GiB
thereafter; available cgroup OOM counters are checked even with an unlimited
memory limit, and missing counters for an observed cgroup fail. Increases fail.
Guards use sampled observations,
not a claim that every transient resource state was observed. All source input
bytes and checker bytes are compared again before final acceptance.

## Observed findings and remediation constraints

Public OSV triage at main `626ba9365b5d3e1faf8265f0b6ff50cc9111b749`
on 2026-11-02 returned 97 exact package/version/advisory records, 96 IDs and
71 alias-connected groups. All matched the locked PyPI versions; none was
withdrawn. Grouping is not proof of 71 independent exploitable production
vulnerabilities. Severity labels came from that feed: 7 critical, 34 high,
27 moderate and 3 low groups. Preserve the exact feed receipts rather than
replacing them with a GitHub banner count.

| Locked package/version | Candidate fix from public metadata | Scope / constraint |
| --- | --- | --- |
| `aiohttp==3.14.3` | `3.14.4` | Both guest locks |
| `authlib==1.8.0` | `1.9.1` | Both; observed fix boundaries include 1.9.0 and 1.9.1 |
| `certifi==2026.7.22` | `2026.10.18` | Both |
| `dnspython==2.8.0` | `2.9.0` | Both |
| `fastmcp==3.2.4` | `3.4.10` | Both; conflicts with current server's `<3.3.0` constraint |
| `joserfc==1.7.5` | `1.7.6` | Both |
| `opentelemetry-api==1.44.0` / `1.45.0` | `1.45.1` | Linux / macOS respectively |
| `pillow==12.3.0` | `13.0.0` | Both; major-version API compatibility still owed |
| `setuptools==84.0.0` | `84.1.0` | Linux build lock; advisory describes Windows legacy-wheel path escape, not a demonstrated Linux build exploit |
| `twisted==26.4.0` | stable `26.10.0` | Both; feed fix boundary is `26.10.0rc1`, but stable metadata exists |

These are available candidate releases, not a resolved/tested replacement graph.
The exact `cua-computer-server==0.3.46` metadata requires Python
`>=3.12,<3.14`, `fastmcp>=3.2.0,<3.3.0`, and, for the driver extra,
`cua-driver>=0.22.2,<0.23.0`. The observed driver `0.22.2` accepts Python
`>=3.10`. The public server release index retrieved at
2026-11-02T06:00:40.797299Z reported latest `0.3.46`, with no newer non-yanked
stable version. Thus no observed supported forward server release admits the
FastMCP `3.4.10` fix. Do not force an incompatible transitive override or present
this upstream constraint as an approval to ignore the advisory.

A supported remediation must regenerate, not hand-edit, both runtime locks and
the build lock using reviewed inputs and hash coverage. Existing commands use
`uv pip compile --generate-hashes`, Python 3.12 plus
`aarch64-manylinux_2_39` for Linux, and Python 3.13 plus
`aarch64-apple-darwin --only-binary :all:` with the explicit Darwin framework
input for macOS. The recorded macOS cutoff
`--exclude-newer 2026-09-26T00:00:00Z` must be advanced explicitly to admit
October fixes. Preserve all 158 PyObjC framework pins; the explicit input exists
because resolver platform information otherwise omits Darwin 24 dependencies.
A server pin change additionally needs the Rust pin/artifact contracts and
operator fixtures updated, followed by dedicated-VM validation. None of that
resolution, installation or VM validation is performed by this checker.

## Separate feeds and preserved failures

The same main-source triage queried the public npm advisory bulk endpoint for
the complete client graph (324 nodes, including seven aliases) and MCP graph
(147 nodes), with canonical name/version requests and no platform/dev filtering.
Both HTTP 200 responses were `{}` on 2026-11-02. This is source-bound public
npm-feed zero, not a fresh `npm audit`, license clearance, or all-database claim.

GitHub's push banner reported 19 vulnerabilities (6 high, 13 moderate), but the
read-only Dependabot alerts endpoint returned HTTP 403, “Resource not accessible
by integration.” No alert IDs or manifest bindings were available. The public
feed results do not reconcile or close those unknown GitHub alerts. The endpoint
was not retried or bypassed. The root Cargo lock remains the release resolver;
standalone vendor lock versions are not automatically release dependencies.

Implementation evidence is kept outside the checkout under
`c259-checker-implementation-20261102`. The first offline run retained one failed
expectation (269 instead of 270 distinct CUA pairs). The first real run queried
all 270 pairs and fetched 96 detail records but refused all 97 bindings because
it compared the microsecond/nanosecond modified fields as literal strings.
That failed result remains distinct from the corrected precision comparison;
it is not evidence that zero active findings existed. The corrected real result
at 2026-11-02T06:19:48.256128+00:00 was **failed** with complete 373-record /
270-query coverage, 97 active records, 96 advisory IDs, 71 alias groups and zero
withdrawn or unknown bindings. Its only 97 refusal reasons were active findings;
the report SHA-256 is
`aebb7b6e8fd5a66998ec7296490dc4139ec9d32339fa5fec0999781a5b311539`.
The 59 offline tests passed on that `ac06332a` checker. Review then found and
corrected nanosecond chronology/withdrawal ambiguity, invalid timezone offsets,
numeric JSON overflow, an unlimited-cgroup OOM observation gap, the observation
deadline and report-output limits. Targeted failures against each earlier source
are retained. The revised checker passes 76 offline tests, including actual
short timer interruption of mocked open/read waits, and a hash-verified offline
replay of all 99 saved request/response bindings still refuses the 97 active
records. That replay is explicitly **not** a fresh feed run of the revised
source. These results prove refusal of the known graph, not completed dependency
remediation.
