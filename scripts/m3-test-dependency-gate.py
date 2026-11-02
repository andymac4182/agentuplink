#!/usr/bin/env python3
"""M3-50: universal MCP test dependency declarations and live advisories.

This preparation gate intentionally has no licence exceptions. It reads the
accepted SPDX expressions from deny.toml. It does not provide legal advice or
attest every platform wheel's contents: Python evidence is one lock-hash-bound
wheel per exact marked pin; npm evidence is every locked tarball. No package is
installed or executed. See docs/mcp-test-dependency-gate.md for scope/blockers.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import email.parser
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tempfile
import time
import tomllib
import urllib.parse
import urllib.request
import zipfile

import packaging
from packaging.licenses import canonicalize_license_expression
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name, parse_wheel_filename
from packaging.version import Version


TOOL_VERSION = "26.3"
EXPECTED_COUNTS = {"npm": 147, "python": 32}
INPUTS = (
    "deny.toml",
    "tests/mcp-sdk-conformance/package.json",
    "tests/mcp-sdk-conformance/package-lock.json",
    "tests/mcp-sdk-conformance/python/requirements.txt",
    "LICENSE",
)
MAX_DOWNLOAD = 64 * 1024 * 1024
MAX_METADATA = 2 * 1024 * 1024


class GateError(ValueError):
    """A nonzero gate result with a stable reason witness."""


def require(condition, reason):
    if not condition:
        raise GateError(reason)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def json_document(data):
    def unique_fields(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate-json-key")
            result[key] = value
        return result

    return json.loads(data, object_pairs_hook=unique_fields)


def expression(value):
    require(isinstance(value, str) and value.strip(), "missing-license")
    try:
        result = str(canonicalize_license_expression(value))
    except ValueError as error:
        raise GateError("unknown-license") from error
    # SPDX permits user-defined identifiers; this gate cannot identify their
    # texts, even when an allowed OR branch would otherwise satisfy policy.
    require("LicenseRef-" not in result, "unknown-license-reference")
    return result


def allowed_expression(value, allow):
    """Evaluate canonical SPDX with WITH > AND > OR precedence, no eval()."""
    tokens = re.findall(r"\(|\)|[^\s()]+", expression(value))
    position = 0

    def atom():
        nonlocal position
        token = tokens[position]
        position += 1
        if token == "(":
            result = disjunction()
            require(tokens[position] == ")", "invalid-license-expression")
            position += 1
            return result
        if position < len(tokens) and tokens[position] == "WITH":
            token += " WITH " + tokens[position + 1]
            position += 2
        return token in allow

    def conjunction():
        nonlocal position
        result = atom()
        while position < len(tokens) and tokens[position] == "AND":
            position += 1
            right = atom()
            result = result and right
        return result

    def disjunction():
        nonlocal position
        result = conjunction()
        while position < len(tokens) and tokens[position] == "OR":
            position += 1
            right = conjunction()
            result = result or right
        return result

    result = disjunction()
    require(position == len(tokens), "invalid-license-expression")
    require(result, "disallowed-license: " + expression(value))


def python_pins(data):
    """Parse every hashed PEP 508 requirement; never evaluate away markers."""
    logical = re.sub(r"\\\r?\n", " ", data.decode())
    pins = []
    for line in logical.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(" --hash=")
        require(len(parts) > 1, "python-missing-hashes")
        requirement = Requirement(parts[0].strip())
        specs = list(requirement.specifier)
        require(
            not requirement.url and not requirement.extras
            and len(specs) == 1 and specs[0].operator == "=="
            and "*" not in specs[0].version,
            "python-nonexact-pin",
        )
        hashes = [part.strip() for part in parts[1:]]
        require(all(re.fullmatch(r"sha256:[0-9a-f]{64}", h) for h in hashes),
                "python-invalid-hash")
        pin = {
            "name": str(canonicalize_name(requirement.name)),
            "version": str(Version(specs[0].version)),
            "marker": str(requirement.marker) if requirement.marker else "",
            "hashes": sorted(set(h.removeprefix("sha256:") for h in hashes)),
        }
        identity = (pin["name"], pin["version"], pin["marker"])
        require(not any((p["name"], p["version"], p["marker"]) == identity for p in pins),
                "python-duplicate-pin")
        pins.append(pin)
    require(pins, "python-empty-graph")
    return pins


def fetch(url):
    parsed = urllib.parse.urlparse(url)
    require(parsed.scheme == "https" and parsed.hostname in {
        "pypi.org", "files.pythonhosted.org", "registry.npmjs.org"
    } and not parsed.username and not parsed.password, "unapproved-artifact-origin")
    request = urllib.request.Request(url, headers={"User-Agent": "agentuplink-m3-50/1"})
    with urllib.request.urlopen(request, timeout=30) as response:
        final = urllib.parse.urlparse(response.url)
        require(final.scheme == "https" and final.hostname == parsed.hostname,
                "unexpected-artifact-redirect")
        data = response.read(MAX_DOWNLOAD + 1)
    require(len(data) <= MAX_DOWNLOAD, "artifact-too-large")
    return data


def artifact(url, algorithm, expected, cache):
    require(algorithm in {"sha256", "sha512"}, "unsupported-integrity")
    path = cache / (algorithm + "-" + expected)
    data = path.read_bytes() if path.exists() else fetch(url)
    require(hashlib.new(algorithm, data).hexdigest() == expected, "artifact-hash-mismatch")
    if not path.exists():
        # Multiple lock entries may share an archive. Never expose a partial
        # cache entry to another worker or a later invocation.
        with tempfile.NamedTemporaryFile(dir=cache, delete=False) as temporary:
            temporary.write(data)
        try:
            os.replace(temporary.name, path)
        finally:
            Path(temporary.name).unlink(missing_ok=True)
    return data


def npm_record(item, cache):
    path, locked = item
    require(path.startswith("node_modules/") and not locked.get("link"), "npm-unresolved-entry")
    name = path.rsplit("node_modules/", 1)[1]
    version = locked.get("version")
    require(isinstance(version, str) and version, "npm-missing-version")
    integrity = locked.get("integrity", "")
    require(integrity.startswith("sha512-") and " " not in integrity, "npm-missing-integrity")
    try:
        digest = base64.b64decode(integrity[7:], validate=True)
    except ValueError as error:
        raise GateError("npm-invalid-integrity") from error
    require(len(digest) == 64, "npm-invalid-integrity")
    archive = artifact(locked.get("resolved", ""), "sha512", digest.hex(), cache)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        entries = []
        total_size = 0
        for count, member in enumerate(tar, 1):
            total_size += member.size
            require(count <= 100000 and total_size <= MAX_DOWNLOAD * 10, "npm-expanded-archive-too-large")
            if member.name == "package/package.json":
                entries.append(member)
        require(len(entries) == 1 and entries[0].isfile()
                and entries[0].size <= MAX_METADATA, "npm-missing-or-duplicate-metadata")
        metadata = tar.extractfile(entries[0]).read(MAX_METADATA + 1)
    package = json_document(metadata)
    require(package.get("name") == name and package.get("version") == version,
            "npm-artifact-identity-mismatch")
    return {
        "ecosystem": "npm", "path": path, "name": name, "version": version,
        "artifact_url": locked["resolved"], "artifact_sha256": sha256(archive),
        "lock_integrity": integrity, "metadata_sha256": sha256(metadata),
        "license_sources": {"lock": locked.get("license"), "artifact": package.get("license")},
    }


def pypi_advisories(release):
    require("vulnerabilities" in release and isinstance(release["vulnerabilities"], list),
            "python-missing-advisory-coverage")
    findings = release["vulnerabilities"]
    require(all(isinstance(v, dict) and isinstance(v.get("id"), str) and v["id"]
                for v in findings), "python-malformed-advisory")
    return [v["id"] for v in findings]


def python_record(pin, cache):
    url = f"https://pypi.org/pypi/{pin['name']}/{pin['version']}/json"
    release_bytes = fetch(url)  # Never reuse cached vulnerability answers.
    release = json_document(release_bytes)
    info = release.get("info", {})
    require(canonicalize_name(info.get("name", "")) == pin["name"]
            and info.get("version") == pin["version"], "python-release-identity-mismatch")
    candidates = []
    for item in release.get("urls", []):
        if item.get("packagetype") != "bdist_wheel":
            continue
        digest = item.get("digests", {}).get("sha256")
        if digest not in pin["hashes"]:
            continue
        wheel_name, wheel_version, _, _ = parse_wheel_filename(item["filename"])
        require(wheel_name == pin["name"] and str(wheel_version) == pin["version"],
                "python-wheel-filename-identity-mismatch")
        candidates.append(item)
    require(candidates, "python-no-lock-matched-wheel")
    # Stable, host-independent choice. Prefer the platform-independent wheel,
    # otherwise the lexicographically first artifact. Markers remain in report.
    selected = min(candidates, key=lambda p: (not p["filename"].endswith("-any.whl"), p["filename"]))
    archive = artifact(selected["url"], "sha256", selected["digests"]["sha256"], cache)
    with zipfile.ZipFile(io.BytesIO(archive)) as wheel:
        names = wheel.namelist()
        require(len(names) == len(set(names)), "python-duplicate-archive-path")
        matches = [n for n in names if re.fullmatch(r"[^/]+\.dist-info/METADATA", n)]
        require(len(matches) == 1 and wheel.getinfo(matches[0]).file_size <= MAX_METADATA,
                "python-missing-or-duplicate-metadata")
        metadata = wheel.read(matches[0])
        fields = email.parser.BytesParser().parsebytes(metadata)
        for key in ("Name", "Version", "License", "License-Expression"):
            require(len(fields.get_all(key, [])) <= 1, "python-duplicate-metadata-field")
        require(canonicalize_name(fields.get("Name", "")) == pin["name"]
                and fields.get("Version") == pin["version"], "python-metadata-identity-mismatch")
        license_files = {}
        prefix = matches[0].rsplit("/", 1)[0]
        for declared in fields.get_all("License-File", []):
            relative = PurePosixPath(declared)
            require(not relative.is_absolute() and ".." not in relative.parts and "\\" not in declared,
                    "python-unsafe-license-path")
            # PEP 639 uses licenses/. Older wheels store the declared filename
            # directly in dist-info; exactly one form must exist.
            paths = [p for p in (f"{prefix}/licenses/{declared}", f"{prefix}/{declared}") if p in names]
            require(len(paths) == 1 and wheel.getinfo(paths[0]).file_size <= MAX_METADATA,
                    "python-missing-or-conflicting-license-file")
            license_files[paths[0]] = sha256(wheel.read(paths[0]))
    return {
        "ecosystem": "python", **pin, "artifact_url": selected["url"],
        "artifact_filename": selected["filename"], "artifact_sha256": sha256(archive),
        "metadata_sha256": sha256(metadata), "license_files": license_files,
        "release_metadata_url": url, "release_metadata_sha256": sha256(release_bytes),
        "advisories": pypi_advisories(release),
        "license_sources": {
            "expression": fields.get("License-Expression"),
            "legacy": fields.get("License"),
            "classifiers": [v for v in fields.get_all("Classifier", []) if v.startswith("License ::")],
        },
    }


# Only exact legacy declarations are interpreted. Full licence prose, `PSF`,
# a generic BSD classifier or a custom reference cannot silently become SPDX.
LEGACY_LICENSES = {"MIT": "MIT", "BSD-3-Clause": "BSD-3-Clause", "Apache-2.0": "Apache-2.0"}
CLASSIFIERS = {
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
}
GENERIC_CLASSIFIERS = {"License :: OSI Approved", "License :: OSI Approved :: BSD License"}


def record_license(record):
    sources = record["license_sources"]
    if record["ecosystem"] == "npm":
        declared = [expression(sources.get("lock")), expression(sources.get("artifact"))]
        require(declared[0] == declared[1], "conflicting-license-metadata")
        return declared[0]
    declarations = []
    if sources["expression"] is not None:
        declarations.append(expression(sources["expression"]))
    if sources["legacy"] is not None:
        require(sources["legacy"] in LEGACY_LICENSES, "unknown-legacy-license")
        declarations.append(LEGACY_LICENSES[sources["legacy"]])
    for classifier in sources["classifiers"]:
        if classifier in GENERIC_CLASSIFIERS:
            continue  # Non-identifying; never sufficient evidence alone.
        require(classifier in CLASSIFIERS, "unknown-license-classifier")
        declarations.append(CLASSIFIERS[classifier])
    require(declarations, "missing-license")
    require(len(set(declarations)) == 1, "conflicting-license-metadata")
    if "License :: OSI Approved :: BSD License" in sources["classifiers"]:
        require(any(token.startswith("BSD-") for token in declarations[0].split()),
                "conflicting-license-metadata")
    if not sources["expression"]:
        require(record["license_files"], "legacy-license-missing-file")
    return declarations[0]


def npm_audit(root):
    proc = subprocess.run(
        ["npm", "audit", "--package-lock-only", "--json", "--audit-level=low",
         "--include=dev", "--include=optional", "--include=peer",
         "--registry=https://registry.npmjs.org"],
        cwd=root / "tests/mcp-sdk-conformance", capture_output=True, timeout=120,
        check=False,
    )
    require(proc.returncode in (0, 1), "npm-audit-command-failed")
    report = json_document(proc.stdout)
    require(report.get("auditReportVersion") == 2 and "error" not in report,
            "npm-audit-missing-coverage")
    return report, sha256(proc.stdout), proc.returncode


def check_npm_audit(report, count, status):
    require(report.get("auditReportVersion") == 2 and "error" not in report,
            "npm-audit-missing-coverage")
    metadata = report.get("metadata", {})
    require(metadata.get("dependencies", {}).get("total") == count, "npm-audit-coverage-mismatch")
    counts = metadata.get("vulnerabilities", {})
    keys = {"info", "low", "moderate", "high", "critical", "total"}
    require(set(counts) == keys and all(type(v) is int and v >= 0 for v in counts.values()),
            "npm-audit-malformed-counts")
    findings = report.get("vulnerabilities")
    require(isinstance(findings, dict), "npm-audit-missing-findings")
    # Reject all severities, including info/unknown future finding shapes.
    require(not findings and all(v == 0 for v in counts.values()), "npm-known-advisory")
    require(status == 0, "npm-audit-inconsistent-exit-status")


def run(root, cache, expected_counts=EXPECTED_COUNTS):
    require(packaging.__version__ == TOOL_VERSION, "tool-version-mismatch")
    cache.mkdir(parents=True, exist_ok=True)
    inputs = {path: (root / path).read_bytes() for path in INPUTS}
    hashes = {path: sha256(data) for path, data in inputs.items()}
    allow = {expression(v) for v in tomllib.loads(inputs[INPUTS[0]].decode())["licenses"]["allow"]}
    require(allow, "empty-license-policy")
    manifest = json_document(inputs[INPUTS[1]])
    lock = json_document(inputs[INPUTS[2]])
    require(lock.get("lockfileVersion") == 3, "npm-unsupported-lock-format")
    packages = lock.get("packages", {})
    require("" in packages, "npm-missing-root")
    for key in ("name", "version", "license", "devDependencies", "dependencies", "optionalDependencies"):
        require(manifest.get(key) == packages[""].get(key), "npm-manifest-lock-mismatch")
    for key in ("devDependencies", "dependencies", "optionalDependencies"):
        for name, version in manifest.get(key, {}).items():
            require(packages.get("node_modules/" + name, {}).get("version") == version,
                    "npm-direct-pin-missing-or-nonexact")
    require(manifest.get("license") == "SEE LICENSE IN ../../LICENSE"
            and (root / "LICENSE").is_file(), "npm-root-license-missing")
    npm = [(path, value) for path, value in packages.items() if path]
    pins = python_pins(inputs[INPUTS[3]])
    require(len(npm) == expected_counts["npm"] and len(pins) == expected_counts["python"],
            "graph-count-changed-review-required")
    report = {
        "schema": 1, "started_at_unix": int(time.time()), "scope": "MCP test-only universal pins",
        "python_artifact_scope": "one lock-hash-bound wheel per exact marked pin",
        "input_sha256": hashes,
        "tool": {"packaging": TOOL_VERSION, "script_sha256": sha256(Path(__file__).read_bytes())},
        "counts": {"npm": len(npm), "python": len(pins)},
        "packages": [], "errors": [],
    }
    work = [("npm:" + path, npm_record, (path, value)) for path, value in npm]
    work += [("python:" + p["name"] + "==" + p["version"] + ";" + p["marker"], python_record, p) for p in pins]
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        pending = [(identity, pool.submit(fn, item, cache)) for identity, fn, item in work]
        for identity, future in pending:
            try:
                record = future.result()
                report["packages"].append(record)
                if record.get("advisories"):
                    report["errors"].append({"identity": identity, "reason": "python-known-advisory",
                                             "ids": record["advisories"]})
                record["license"] = record_license(record)
                allowed_expression(record["license"], allow)
            except Exception as error:
                report["errors"].append({"identity": identity, "reason": str(error) if isinstance(error, GateError)
                                         else "metadata-fetch-or-parse-failed: " + type(error).__name__})
    try:
        audit, digest, status = npm_audit(root)
        report["npm_advisories"] = {"report_sha256": digest, "report": audit, "exit_status": status}
        check_npm_audit(audit, len(npm), status)
    except Exception as error:
        report["errors"].append({"identity": "npm-audit", "reason": str(error) if isinstance(error, GateError)
                                 else "advisory-query-failed: " + type(error).__name__})
    require(all(sha256((root / path).read_bytes()) == digest for path, digest in hashes.items()),
            "inputs-changed-during-check")
    report["finished_at_unix"] = int(time.time())
    report["passed"] = not report["errors"]
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--cache", type=Path, required=True, help="Verified archive cache; advisory responses are always live")
    parser.add_argument("--report", type=Path, required=True, help="JSON evidence report (does not enable offline acceptance)")
    args = parser.parse_args()
    try:
        report = run(args.root.resolve(), args.cache.resolve())
    except Exception as error:
        report = {"schema": 1, "passed": False, "errors": [{"identity": "gate",
            "reason": str(error) if isinstance(error, GateError) else "gate-failed: " + type(error).__name__}]}
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"M3-50 {'PASS' if report['passed'] else 'FAIL'}: {len(report['errors'])} blocker(s); report={args.report}")
    for error in report["errors"]:
        print(f"  {error['identity']}: {error['reason']}")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
