#!/usr/bin/env python3
"""C253: full client lock/artifact license evidence; no exceptions or installs.

This is independent of the MCP gate's scope. Only its strict SPDX/JSON parsers
are reused. Package declarations and hashed notice files are not a legal or
bundled-component audit. See docs/m6-client-license-gate.md.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tarfile
import tempfile
import time
import tomllib
import urllib.parse
import urllib.request

import packaging

PARSER_PATH = Path(__file__).with_name("m3-test-dependency-gate.py")
SPEC = importlib.util.spec_from_file_location("client_license_spdx", PARSER_PATH)
parser = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(parser)
GateError, require = parser.GateError, parser.require
expression, allowed_expression = parser.expression, parser.allowed_expression
json_document, sha256 = parser.json_document, parser.sha256
EXPECTED_NODES, EXPECTED_ALIASES = 324, 7
ROOT_LICENSE_SHA256 = "e7a62762fe3dccd3c9e1a1fa3d2a0a2850b07a48ca48072542f3e5f2b66450ea"
INPUTS = ("deny.toml", "packages/client/package.json", "packages/client/package-lock.json", "LICENSE")
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_EXPANDED = 256 * 1024 * 1024
MAX_METADATA = 2 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
DISK_FLOOR = 1536 * 1024 * 1024
MEMORY_FLOOR = 3 * 1024 * 1024 * 1024
MEMORY_START = 4 * 1024 * 1024 * 1024
DEPENDENCIES = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
NAME = r"(?:@[a-z0-9_.~-]+/)?[a-z0-9_.~-]+"
VERSION = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?"
NOTICE = re.compile(r"^(?:licen[cs]e|copying|notice)(?:[._-].*)?$", re.I)
# Exact, reviewed full MIT notice inside this archive's README, not a policy
# exception and not a generic inference from a README's license label/link.
EMBEDDED_NOTICES = {
    ("@tokenizer/token", "0.3.0"): {
        "artifact_sha256": "911758ceca239c8e5372700eedfbbd514f16d3c117b5af0a648f6e720487c209",
        "path": "package/README.md",
        "sha256": "a88c936c259cc261d5b37a2433735e9819e01f824bdc26e644d46ccd3055c8d7",
    },
}


def package_name(value):
    require(isinstance(value, str) and re.fullmatch(NAME, value) and
            all(part not in {".", ".."} for part in value.split("/")), "invalid-package-name")
    return value


def lock_name(path):
    require(isinstance(path, str) and path.startswith("node_modules/"), "unsafe-lock-path")
    parts = path.split("node_modules/")
    require(parts[0] == "" and all(p.endswith("/") for p in parts[1:-1]), "unsafe-lock-path")
    for item in parts[1:-1]:
        package_name(item[:-1])
    return package_name(parts[-1])


def maps(package):
    for kind in DEPENDENCIES:
        value = package.get(kind, {})
        require(isinstance(value, dict), "invalid-dependency-map")
        for name, spec in value.items():
            package_name(name)
            require(isinstance(spec, str) and 0 < len(spec) <= 512, "invalid-dependency-spec")
        yield kind, value


def resolve(packages, owner, name):
    """Node's nearest enclosing node_modules lookup, retaining exact lock keys."""
    while True:
        key = (owner + "/" if owner else "") + "node_modules/" + name
        if key in packages:
            return key
        if not owner:
            return None
        owner = owner.rsplit("/node_modules/", 1)[0] if "/node_modules/" in owner else ""


def alias_spec(spec):
    match = re.fullmatch(r"npm:(" + NAME + r")@(~?)(" + VERSION + r")", spec)
    require(match is not None, "unsupported-alias-spec-review-required")
    return match.group(1), match.group(2), match.group(3)


def alias_version(spec, version):
    name, operator, requested = alias_spec(spec)
    if operator == "~":
        # This reviewed graph uses only stable ~major.minor.patch ranges.
        require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", requested) and
                re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version), "unsupported-alias-spec-review-required")
        have, minimum = tuple(map(int, version.split("."))), tuple(map(int, requested.split(".")))
        require(have[:2] == minimum[:2] and have[2] >= minimum[2], "alias-version-mismatch")
    else:
        require(requested == version, "alias-version-mismatch")
    return name


def integrity_digest(value):
    require(isinstance(value, str) and value.startswith("sha512-") and " " not in value,
            "missing-or-unsupported-integrity")
    try:
        raw = base64.b64decode(value[7:], validate=True)
    except ValueError as error:
        raise GateError("invalid-integrity") from error
    require(len(raw) == 64 and base64.b64encode(raw).decode() == value[7:], "invalid-integrity")
    return raw.hex()


def artifact_url(name, version):
    return f"https://registry.npmjs.org/{name}/-/{name.rsplit('/', 1)[-1]}-{version}.tgz"


def graph(manifest, lock, expected_nodes=EXPECTED_NODES, expected_aliases=EXPECTED_ALIASES):
    require(isinstance(manifest, dict), "invalid-root-manifest")
    require(isinstance(lock, dict) and lock.get("lockfileVersion") == 3, "unsupported-lock-format")
    packages = lock.get("packages")
    require(isinstance(packages, dict) and isinstance(packages.get(""), dict), "missing-lock-root")
    require(len(packages) - 1 == expected_nodes, "graph-count-changed-review-required")
    for key in ("name", "version", "license", "engines", "peerDependenciesMeta", *DEPENDENCIES):
        default = {} if key in DEPENDENCIES else None
        require(manifest.get(key, default) == packages[""].get(key, default), "manifest-lock-mismatch")
    require(lock.get("name") == manifest.get("name") and lock.get("version") == manifest.get("version"),
            "lock-root-identity-mismatch")
    require(manifest.get("license") == "SEE LICENSE IN ../../LICENSE", "root-license-reference-mismatch")
    aliases, nodes = [], {}
    for path, package in packages.items():
        require(isinstance(package, dict), "invalid-lock-entry")
        if not path:
            continue
        installed = lock_name(path)
        name = package_name(package.get("name", installed))
        version = package.get("version")
        require(isinstance(version, str) and re.fullmatch(VERSION, version), "missing-or-invalid-version")
        require(not package.get("link"), "unresolved-link-entry")
        for flag in ("dev", "optional", "devOptional"):
            require(flag not in package or type(package[flag]) is bool, "invalid-lock-flag")
        require(package.get("resolved") == artifact_url(name, version), "artifact-url-identity-mismatch")
        nodes[path] = {"path": path, "installed_name": installed, "name": name, "version": version,
                       "integrity": package.get("integrity"), "sha512": integrity_digest(package.get("integrity")),
                       "url": package["resolved"], "license": package.get("license"),
                       "flags": {k: package[k] for k in ("dev", "optional", "devOptional", "os", "cpu") if k in package}}
    for owner, package in packages.items():
        for kind, dependencies in maps(package):
            for name, spec in dependencies.items():
                target = resolve(packages, owner, name)
                if spec.startswith("npm:"):
                    require(target in nodes, "alias-target-missing")
                    canonical = alias_version(spec, nodes[target]["version"])
                    require(nodes[target]["name"] == canonical and nodes[target]["installed_name"] == name
                            and canonical != name, "alias-canonical-identity-mismatch")
                    aliases.append({"owner": owner, "kind": kind, "name": name, "spec": spec,
                                    "target": target, "canonical_name": canonical, "version": nodes[target]["version"]})
                elif target in nodes:
                    require(nodes[target]["name"] == name, "alias-target-without-alias-edge")
    targets = {edge["target"] for edge in aliases}
    require(targets == {key for key, node in nodes.items() if node["installed_name"] != node["name"]},
            "alias-entry-without-resolved-edge")
    require(len(aliases) == len(targets) == expected_aliases, "alias-count-changed-review-required")
    for kind, dependencies in maps(manifest):
        for name, spec in dependencies.items():
            target = resolve(packages, "", name)
            require(target in nodes and nodes[target]["version"] == spec, "direct-pin-missing-or-nonexact")
    return nodes, aliases


class Budget:
    """Sequential, bounded I/O; checks never install or execute package code."""
    def __init__(self, directory, seconds=900):
        self.directory = directory
        self.deadline = time.monotonic() + seconds
        self.total = 0
        self.last_resource_check = 0
        self.minimum_free = None
        self.minimum_memory = None
        self.oom_before = None
        self.oom_last = None

    def check(self):
        require(time.monotonic() < self.deadline, "evidence-deadline-exceeded")
        if time.monotonic() - self.last_resource_check < 0.25:
            return
        free = min(shutil.disk_usage(path).free for path in {self.directory, Path('/workspace'), Path('/tmp')} if path.exists())
        self.minimum_free = min(self.minimum_free or free, free)
        require(free >= DISK_FLOOR, "evidence-disk-reserve")
        # Linux-specific measurement is explicit; elsewhere no memory proof is claimed.
        if Path("/proc/meminfo").is_file():
            fields = dict(re.findall(r"^(\w+):\s+(\d+)", Path("/proc/meminfo").read_text(), re.M))
            memory = int(fields["MemAvailable"]) * 1024
            group = Path("/sys/fs/cgroup")
            maximum = group / "memory.max"
            if maximum.is_file() and maximum.read_text().strip() != "max":
                stats = dict(line.split() for line in (group / "memory.stat").read_text().splitlines())
                # Same conservative reclaimable-file estimate used by the local
                # acceptance guards; an estimate, not a promised allocatable peak.
                estimate = int(maximum.read_text()) - sum(int(stats[key]) for key in ("anon", "shmem", "kernel")) + int(stats["slab_reclaimable"])
                memory = min(memory, estimate)
                events = dict(line.split() for line in (group / "memory.events").read_text().splitlines())
                self.oom_last = {key: int(events[key]) for key in ("oom", "oom_kill", "oom_group_kill")}
                self.oom_before = self.oom_before or self.oom_last.copy()
                require(self.oom_last == self.oom_before, "evidence-oom-increase")
            require(memory >= (MEMORY_START if self.minimum_memory is None else MEMORY_FLOOR), "evidence-memory-reserve")
            self.minimum_memory = min(self.minimum_memory or memory, memory)
        self.last_resource_check = time.monotonic()

    def account(self, size):
        self.total += size
        require(self.total <= MAX_TOTAL, "evidence-total-byte-cap")
        self.check()

    def reserve_write(self, size):
        self.check()
        require(shutil.disk_usage(self.directory).free >= DISK_FLOOR + size, "evidence-disk-reserve")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise GateError("artifact-redirect-refused")


def fetch(url, budget):
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == "https" and parsed.netloc == "registry.npmjs.org"
            and not parsed.query and not parsed.fragment, "unapproved-artifact-origin")
    # Default proxy and CA handling is retained. No redirect reaches another host.
    opener = urllib.request.build_opener(NoRedirect())
    request = urllib.request.Request(url, headers={"User-Agent": "agentuplink-client-license/1"})
    data = bytearray()
    budget.check()
    with opener.open(request, timeout=30) as response:
        require(response.status == 200 and response.url == url, "unexpected-artifact-response")
        while chunk := response.read(64 * 1024):
            require(len(data) + len(chunk) <= MAX_ARCHIVE, "archive-too-large")
            budget.account(len(chunk))
            data.extend(chunk)
    return bytes(data)


def archive_bytes(node, cache, budget, offline):
    path = cache / (node["sha512"] + ".tgz")
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        metadata = None
    if metadata is not None:
        require(stat.S_ISREG(metadata.st_mode) and not path.is_symlink() and metadata.st_size <= MAX_ARCHIVE,
                "unsafe-or-oversized-cache-entry")
        data = path.read_bytes()
        budget.account(len(data))
    else:
        require(not offline, "offline-artifact-missing")
        data = fetch(node["url"], budget)
    require(hashlib.sha512(data).hexdigest() == node["sha512"], "artifact-integrity-mismatch")
    if metadata is None:
        # Only verified compressed bytes are retained; no extracted package tree.
        budget.reserve_write(len(data))
        with path.open("xb") as output:
            output.write(data)
    return data


def archive_record(node, data, directory, budget):
    """Never extract paths; bounded decompression, unique safe names, no links."""
    notices, metadata, members, total, archive_root = {}, None, set(), 0, None
    embedded = EMBEDDED_NOTICES.get((node["name"], node["version"]))
    embedded_bytes = None
    with tempfile.SpooledTemporaryFile(max_size=2 * 1024 * 1024, dir=directory) as expanded:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
            while chunk := compressed.read(64 * 1024):
                total += len(chunk)
                require(total <= MAX_EXPANDED, "expanded-archive-too-large")
                budget.check()
                # A spool rollover also writes its existing <=2 MiB RAM buffer.
                budget.reserve_write(len(chunk) + 2 * 1024 * 1024)
                expanded.write(chunk)
        expanded.seek(0)
        with tarfile.open(fileobj=expanded, mode="r:") as archive:
            for member in archive:
                budget.check()
                name = member.name.rstrip("/") if member.isdir() else member.name
                relative = PurePosixPath(name)
                require(name == str(relative) and not relative.is_absolute() and ".." not in relative.parts
                        and "\\" not in name and relative.parts, "unsafe-archive-path")
                allowed_roots = {"package"}
                if node["name"].startswith("@types/"):
                    allowed_roots.add(node["name"].split("/", 1)[1])
                archive_root = archive_root or relative.parts[0]
                require(relative.parts[0] == archive_root and archive_root in allowed_roots,
                        "unsafe-archive-path")
                require(name not in members, "duplicate-archive-path")
                members.add(name)
                require(len(members) <= 100000, "archive-member-cap")
                require(member.isfile() or member.isdir(), "archive-link-or-special-file")
                notice = member.isfile() and (NOTICE.fullmatch(relative.name) or "licenses" in [p.lower() for p in relative.parts[1:-1]])
                if name == archive_root + "/package.json" or notice or (embedded and name == embedded["path"]):
                    require(member.isfile() and 0 < member.size <= MAX_METADATA, "missing-or-oversized-metadata")
                    content = archive.extractfile(member).read(MAX_METADATA + 1)
                    require(len(content) == member.size, "truncated-archive-member")
                    if name == archive_root + "/package.json":
                        metadata = content
                    elif embedded and name == embedded["path"]:
                        embedded_bytes = content
                    else:
                        notices[name] = {"sha256": sha256(content), "bytes": len(content)}
    require(metadata is not None, "missing-package-metadata")
    package = json_document(metadata)
    require(isinstance(package, dict) and package.get("name") == node["name"]
            and package.get("version") == node["version"], "artifact-identity-mismatch")
    if embedded:
        require(sha256(data) == embedded["artifact_sha256"], "embedded-notice-artifact-mismatch")
        require(embedded_bytes is not None and sha256(embedded_bytes) == embedded["sha256"], "embedded-notice-text-mismatch")
        notices[embedded["path"]] = {"sha256": embedded["sha256"], "bytes": len(embedded_bytes),
                                     "provenance": "exact reviewed archive/README full MIT notice",
                                     "content_utf8": embedded_bytes.decode("utf-8")}
    artifact_aliases, publisher_development_aliases = [], []
    for kind, dependencies in maps(package):
        for name, spec in dependencies.items():
            if spec.startswith("npm:"):
                edge = {"kind": kind, "name": name, "spec": spec}
                if kind == "devDependencies":
                    # npm does not install a dependency package's own developer
                    # graph. This does not filter any client lock node or root dev edge.
                    publisher_development_aliases.append(edge)
                else:
                    artifact_aliases.append(edge)
    record = {**node, "artifact_sha256": sha256(data), "artifact_bytes": len(data),
              "metadata_sha256": sha256(metadata), "artifact_license": package.get("license"),
              "archive_root": archive_root, "notice_files": notices,
              "artifact_aliases": artifact_aliases, "publisher_development_aliases": publisher_development_aliases}
    return record


def decide(record, allow):
    declared = [expression(record["license"]), expression(record["artifact_license"])]
    require(declared[0] == declared[1], "conflicting-license-metadata")
    require(record["notice_files"], "missing-artifact-license-notice")
    allowed_expression(declared[0], allow)
    return declared[0]


def alias_evidence(aliases, records):
    """A lock alias alone is insufficient: parent and target must both verify."""
    result = []
    for edge in aliases:
        owner, target = records.get(edge["owner"]), records.get(edge["target"])
        require(owner is not None and target is not None, "alias-artifact-evidence-incomplete")
        expected = {key: edge[key] for key in ("kind", "name", "spec")}
        require(expected in owner["artifact_aliases"], "alias-parent-artifact-edge-mismatch")
        result.append({**edge, "parent_artifact_sha256": owner["artifact_sha256"],
                       "parent_metadata_sha256": owner["metadata_sha256"],
                       "target_artifact_sha256": target["artifact_sha256"],
                       "target_metadata_sha256": target["metadata_sha256"],
                       "target_integrity": target["integrity"]})
    for path, record in records.items():
        expected = [{key: edge[key] for key in ("kind", "name", "spec")} for edge in aliases if edge["owner"] == path]
        require(sorted(record["artifact_aliases"], key=lambda v: (v["kind"], v["name"])) ==
                sorted(expected, key=lambda v: (v["kind"], v["name"])), "alias-parent-artifact-edge-mismatch")
    return result


def run(root, cache, offline=False, *, expected_nodes=EXPECTED_NODES,
        expected_aliases=EXPECTED_ALIASES, root_license_sha256=ROOT_LICENSE_SHA256):
    report = {"schema": 1, "scope": "all client lock nodes; dev, optional and all platforms",
              "started_unix": int(time.time()), "status": "failed", "errors": [], "packages": [], "aliases": [],
              "advisories_checked": False, "bundled_component_audit": False,
              "policy_exceptions": [], "offline": offline}
    inputs, tool_inputs, budget = {}, {}, None
    try:
        require(packaging.__version__ == parser.TOOL_VERSION, "tool-version-mismatch")
        require(cache.is_dir() and not cache.is_symlink(), "cache-directory-required")
        budget = Budget(cache)
        budget.check()
        inputs = {path: (root / path).read_bytes() for path in INPUTS}
        tool_inputs = {str(path): path.read_bytes() for path in (Path(__file__), PARSER_PATH)}
        report["input_sha256"] = {path: sha256(data) for path, data in inputs.items()}
        report["tool"] = {"packaging": packaging.__version__, "source_sha256": {path: sha256(data) for path, data in tool_inputs.items()}}
        policy = tomllib.loads(inputs["deny.toml"].decode())["licenses"]
        require(not policy.get("exceptions"), "policy-exceptions-require-separate-review")
        allow = {expression(item) for item in policy["allow"]}
        require(allow, "empty-license-policy")
        report["allowed_expressions"] = sorted(allow)
        require(sha256(inputs["LICENSE"]) == root_license_sha256, "root-license-changed-review-required")
        report["root_license"] = {"reference": "../../LICENSE", "sha256": root_license_sha256, "reviewed_expression": "MIT"}
        allowed_expression("MIT", allow)
        nodes, aliases = graph(json_document(inputs["packages/client/package.json"]),
                               json_document(inputs["packages/client/package-lock.json"]), expected_nodes, expected_aliases)
        report["counts"] = {"lock_nodes": len(nodes), "alias_nodes": len(aliases), "artifact_verified": 0, "policy_pass": 0}
        records = {}
        for path, node in sorted(nodes.items()):
            try:
                data = archive_bytes(node, cache, budget, offline)
                record = archive_record(node, data, cache, budget)
                records[path] = record
                report["counts"]["artifact_verified"] += 1
                report["packages"].append(record)
                try:
                    record["accepted_expression"] = decide(record, allow)
                    record["policy_status"] = "passed"
                    report["counts"]["policy_pass"] += 1
                except (GateError, ValueError, TypeError) as error:
                    record["policy_status"] = "failed"
                    report["errors"].append({"path": path, "stage": "policy", "reason": str(error)})
            except (OSError, ValueError, tarfile.TarError, EOFError, TypeError) as error:
                report["errors"].append({"path": path, "stage": "artifact", "reason": str(error)})
                # Resource/deadline guards are fatal; policy/metadata errors retain other evidence.
                if isinstance(error, GateError) and str(error).startswith("evidence-"):
                    break
        try:
            report["aliases"] = alias_evidence(aliases, records)
        except GateError as error:
            report["errors"].append({"stage": "aliases", "reason": str(error)})
        require(len(records) == len(nodes), "artifact-coverage-incomplete")
    except (OSError, ValueError, KeyError, TypeError) as error:
        report["errors"].append({"stage": "gate", "reason": str(error)})
    finally:
        for path, data in inputs.items():
            try:
                require((root / path).read_bytes() == data, "source-input-changed")
            except (OSError, GateError) as error:
                report["errors"].append({"stage": "final-inputs", "path": path, "reason": str(error)})
        for path, data in tool_inputs.items():
            try:
                require(Path(path).read_bytes() == data, "tool-input-changed")
            except (OSError, GateError) as error:
                report["errors"].append({"stage": "final-inputs", "path": path, "reason": str(error)})
        if budget:
            try:
                budget.last_resource_check = 0
                budget.check()
            except (OSError, GateError) as error:
                report["errors"].append({"stage": "final-resources", "reason": str(error)})
            report["resources"] = {"compressed_bytes_read": budget.total, "minimum_free_bytes": budget.minimum_free,
                                   "minimum_memory_available_estimate_bytes": budget.minimum_memory,
                                   "oom_before": budget.oom_before, "oom_last": budget.oom_last}
        report["status"] = "failed" if report["errors"] else "passed"
        report["finished_unix"] = int(time.time())
    return report


def main():
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args.add_argument("--cache", type=Path, required=True, help="owned artifact directory; existing bytes are always rehashed")
    args.add_argument("--report", type=Path, required=True, help="new report pathname; never overwrite earlier evidence")
    args.add_argument("--offline", action="store_true", help="require every compressed archive already cached")
    options = args.parse_args()
    # Reserve the output before any network I/O, so every invocation keeps its own outcome.
    with options.report.open("x") as output:
        report = run(options.root.resolve(), options.cache, options.offline)
        json.dump(report, output, indent=2, sort_keys=True)
        output.write("\n")
    print(f"C253 {report['status'].upper()}: {len(report['errors'])} blocker(s); {report.get('counts', {})}")
    for error in report["errors"]:
        print(json.dumps(error, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
