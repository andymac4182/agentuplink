# MCP test dependency policy review (M3-50)

The prepared gate **fails on three unresolved license entries**. M3-50 remains
open. The checker and its deterministic failure controls are implemented; the
live gate is not yet enforced by the release checker or CI. The current
`deny.toml` allowlist, dependency locks and existing advisory CI commands are
unchanged. A passing seeded-control job is not a license approval.

## Measured result

At **2026-10-31T14:46:00+10:00**, the strict live run exited **1**:

```text
M3-50 FAIL: 3 blocker(s)
python:cffi==2.1.1;platform_python_implementation != "PyPy": disallowed-license: MIT-0
python:pywin32==312;sys_platform == "win32": unknown-legacy-license
python:typing-extensions==4.16.0;: disallowed-license: PSF-2.0
```

It covered **147 npm lock entries** (including nonhost optional packages) and
**32 Python pins / 31 names**. Both `rpds-py` versions and their distinct Python
version markers were preserved. The Windows-only `pywin32` and Emscripten-only
`httpx2-jsfetch` were included. All npm archive declarations satisfy the current
allowlist. The Python entries other than the three above satisfy it.

[The review evidence](../tests/mcp-sdk-conformance/dependency-license-review.json)
records the exact policy, lock and manifest SHA256 values, selected blocker
archive and metadata SHA256 values, declared license-file hashes, and the live
advisory source hashes. This is a dated review snapshot, not an offline approval
or a reusable clean bill of health.

The npm audit returned zero known findings for all 147 entries. The **32 exact
PyPI release JSON responses** each had an empty `vulnerabilities` field. These
are npm's configured public registry advisory feed and PyPI's release-level
vulnerability data, respectively; this does not claim that every advisory
database was searched. The snapshot preserves each Python response's URL,
package/version/marker, response SHA256 and findings separately from the npm
report. It is not evidence from the existing `pip-audit` command. The checker
rejects **any** returned advisory, including npm info, low and moderate findings;
the existing high-threshold npm CI command is unchanged pending rollout.

## What the evidence establishes

`scripts/m3-test-dependency-gate.py` reads accepted SPDX expressions from
`deny.toml`. Pinned `packaging==26.3` provides the SPDX identifier catalogue and
PEP 508 parser. The checker evaluates `WITH`, `AND` and `OR` with their proper
precedence. Unknown identifiers, unreviewed license references, missing
declarations and conflicting declarations fail closed, even if another OR
branch would be allowed. Exact legacy MIT/Apache/BSD declarations and identifying
MIT/Apache/ISC classifiers are handled explicitly; arbitrary prose and `PSF` are
not guessed.

Every npm `package.json` comes from the lock's exact tarball after its SHA512
integrity is checked; artifact name/version and license must match the lock.
For Python, the checker selects **one wheel per exact marked pin**, preferring a
platform-independent wheel and otherwise sorting by filename, independently of
the host platform. Its SHA256 must occur in the hash-locked requirements, and
its filename, release identity and internal `METADATA` identity must match.
Declared `License-File` paths must exist, remain inside the wheel and have
recorded hashes. Cached archives are rehashed; advisory answers are fetched on
every run. Missing feed responses, incomplete audit coverage and source-input
changes during the run fail. The reviewed graph counts are explicit floors
that require review when locks change.

This checks **package-version license declarations**, not every platform
wheel's contents or every bundled source file's legal terms. Hashes tie the
inspection to actual downloaded artifacts; they do not turn a publisher's
declaration into a legal opinion. The manual component inspection below is why
the unresolved `pywin32` declaration must not be normalized away. The separate
client npm graph, CUA tooling, Rust graph and OS/container image packages are
outside this check. The parser tool's own hash-locked dependency is also
separate from the 32-pin MCP fixture graph.

## Policy decisions needed

### Two narrowly scoped permissive-license proposals

`cffi==2.1.1` declares **MIT-0**, and its selected wheel's `LICENSE` says
"MIT No Attribution". `typing-extensions==4.16.0` declares **PSF-2.0**; its
license file contains the PSF version 2 terms and historical notices. Neither
identifier is currently accepted by `deny.toml`.

If the owner approves these test-only dependencies, the minimal proposed policy
addition is a **new scoped exception file**, not a change to the global Cargo
allowlist. The following is a proposal only: this file and exception handling
are not installed or active. Each entry would require an explicit reason,
exact package/version/marker and the reviewed artifact and metadata hashes;
changed versions or evidence would fail until reviewed again. The checker
would also need controls proving that these entries do not authorize another
package or an altered artifact.

```toml
# Proposed tests/mcp-sdk-conformance/license-policy.toml; NOT APPROVED/ACTIVE.
[[exceptions]]
ecosystem = "pypi"
name = "cffi"
version = "2.1.1"
marker = 'platform_python_implementation != "PyPy"'
license = "MIT-0"
artifact_sha256 = "baed1e86cc735622097354b9d1281406caf42ff42a886d29faa8e8d1630333be"
metadata_sha256 = "558bafb9093a8e790175d9ecff9688382981d744877dad86fd6770db0f4dc918"
reason = "OWNER REVIEW REQUIRED: exact MCP test-only cffi pin"

[[exceptions]]
ecosystem = "pypi"
name = "typing-extensions"
version = "4.16.0"
marker = ""
license = "PSF-2.0"
artifact_sha256 = "481caa481374e813c1b176ada14e97f1f67a4539ce9cfeb3f350d78d6370c2e8"
metadata_sha256 = "b05084ca1d50879865178d9fff9fabeab61bdfb1f361bfbde95421ffc8f9be46"
reason = "OWNER REVIEW REQUIRED: exact MCP test-only typing-extensions pin"
```

No safe compatible dependency substitution that removes these licenses has
been established. Downgrading security-sensitive packages solely to change
their license label is not an approved solution.

### `pywin32` needs a separate component decision

The exact path is `requirements.in` → `mcp==2.2.0` →
`pywin32>=311; sys_platform == 'win32'` → locked `pywin32==312`. It is an
upstream direct dependency, not an optional extra. In the verified MCP wheel,
`mcp/os/win32/utilities.py` imports `win32api`, `win32con` and `win32job` on
Windows for stdio handle rebinding and Job Objects that terminate subprocess
trees. This code is shared by MCP's stdio client/server support.

The selected archive is `pywin32-312-cp310-cp310-win32.whl`, SHA256
`772235332b5d1024c696f11cea1ae4be7930f0a8b894bb43db14e3f435f1ff7e`.
Its metadata says `License: PSF`, but it bundles multiple component notices.
In particular:

- `pywin32-312.dist-info/licenses/adodbapi/license.txt` is the LGPL version
  2.1 text, SHA256
  `5ea2f23c7f00c3006bacf267183e816d8d4b6dc95ea57a4ddb0ff81de6d8719e`.
- `adodbapi/adodbapi.py` lines 8–11 permit version 2.1 **or any later
  version**, establishing an `LGPL-2.1-or-later` component. The exact source
  hash is recorded in the review evidence.
- Other declared files contain the Windows/com BSD-style notices, Microsoft's
  MIT notice, and Pythonwin/Python notices. The aggregate package terms have
  not been reduced to a reviewed SPDX expression.

Normalizing `PSF` to `PSF-2.0` would conceal those component terms. There is no
global LGPL allowance, no package-install bypass and no Windows marker filter.

The project's **hosted Python MCP conformance job runs on Ubuntu only**:
`.github/workflows/ci.yml` calls `m3-sdk-conformance.sh` in `m3-acceptance`,
whose runner is `ubuntu-latest`. The script also needs Unix shell/process
fixtures. This supplies no Python MCP conformance certification on Windows;
it does not change the universal requirements lock or the separate supported
Windows Rust client. Neither this review nor its gate ran Windows conformance.

The realistic choices are:

1. **Preserve the universal graph.** Review the complete `pywin32` component
   terms, then decide whether an exact test-only package/version/artifact
   clarification and exception is acceptable, including the bundled LGPL
   component. Such an exception must be separately scoped and tested. The
   current evidence does not authorize it or establish redistribution duties.
2. **Explicitly narrow supported Python conformance platforms.** If the owner
   chooses POSIX-only Python conformance, regenerate a genuinely platform-scoped
   lock and document that scope, then make the gate match that declared lock.
   Preserve other supported marker branches and prove that no host-only
   filtering is silently substituted for the current universal graph. This
   changes the M3-50 acceptance scope and needs an explicit owner decision;
   deleting the Windows line or using `pip --no-deps` is not a solution.
3. **Adopt a supported upstream packaging alternative.** Seek an MCP extra or
   compatible release that does not require the unwanted Windows distribution,
   or a reviewed upstream component split. No such compatible alternative is
   established here; an untested version downgrade or locally stripped wheel
   would add work and new supply-chain responsibility.

The first two are the immediate scope choices. Neither is applied by this
preparation patch. A global `LGPL-2.1-or-later` allowlist entry is not proposed.

## Running the prepared checker

Use Python 3.11 or newer and Node/npm (the project's CI uses Node 24). Create a
virtual environment and install
`scripts/m3-test-dependency-gate-requirements.txt` with pip's `--require-hashes`
and `--only-binary=:all:` options. Then invoke
`python scripts/m3-test-dependency-gate.py --cache /tmp/mcp-license-cache --report /tmp/mcp-license-report.json`
from the repository root. The known current result is exit 1 with the three
blockers above. Network/metadata failures also exit nonzero; a previously
generated report cannot be supplied as an offline acceptance input.

The deterministic controls run with
`python -m unittest discover -s scripts -p test_m3_test_dependency_gate.py -v`.
CI runs these controls in a separate hash-pinned tool environment while keeping
the existing live `pip-audit` and npm audit steps. Enabling the strict live
checker in M6-04/CI, testing any approved exceptions, and obtaining a full real
graph pass remain unfinished M3-50 acceptance work.
