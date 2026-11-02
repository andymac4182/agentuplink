#!/usr/bin/env python3
"""C259: source-bound public OSV evidence for all three CUA fixture hash locks.

No installation, dependency resolution, package execution, policy exception or
platform filtering. A real graph refusal is independent of seeded test success.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
from pathlib import Path
import re
import shutil
import signal
import sys
import threading
import time
import urllib.error
import urllib.request

import packaging
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

TOOL_VERSION = "26.3"
BASE = "tests/cua-fixture/"
SCOPES = {
    BASE + "requirements-linux-aarch64.lock": {"count": 109, "role": "Linux aarch64 guest runtime", "python": "3.12", "platform": "aarch64-manylinux_2_39"},
    BASE + "requirements-macos-arm64.lock": {"count": 263, "role": "macOS arm64 Darwin24 guest runtime", "python": "3.13", "platform": "aarch64-apple-darwin"},
    BASE + "requirements-build-linux-aarch64.lock": {"count": 1, "role": "Linux aarch64 evdev build tool", "python": "3.12", "platform": "aarch64-manylinux_2_39"},
}
ROOT_IN = BASE + "requirements.in"
BUILD_IN = BASE + "requirements-build.in"
MAC_IN = BASE + "requirements-macos-pyobjc-darwin24.in"
PIN = "crates/tunnel-http-forward/src/cua_pin.rs"
TOOL_LOCK = "scripts/m3-test-dependency-gate-requirements.txt"
AUX_INPUTS = (ROOT_IN, BUILD_IN, MAC_IN, PIN, TOOL_LOCK)
EXPECTED_FRAMEWORK_INPUTS = 158
BATCH_URL = "https://api.osv.dev/v1/querybatch"
DETAIL_URL = "https://api.osv.dev/v1/vulns/"
BATCH_SIZE = 128
MAX_RESPONSE = 4 * 1024 * 1024
MAX_DETAIL = 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
MAX_SOURCE = 2 * 1024 * 1024
MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_FAILURE_REPORT_BYTES = 16 * 1024
MAX_ADVISORIES = 512
DISK_FLOOR = 1536 * 1024 * 1024
MEMORY_START = 4 * 1024 * 1024 * 1024
MEMORY_ACTIVE = 3 * 1024 * 1024 * 1024
OBSERVATION_SECONDS = 180
ID_PATTERN = r"[A-Za-z0-9][A-Za-z0-9-]{0,127}"


class AuditError(ValueError):
    pass


class ObservationTimeout(TimeoutError):
    pass


class ObservationDeadline:
    """Own a Linux main-thread real-time alarm, including DNS/header/body waits."""
    def __enter__(self):
        require(sys.platform == "linux", "observation-deadline-requires-linux")
        require(threading.current_thread() is threading.main_thread(), "observation-deadline-requires-main-thread")
        require(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), "occupied-observation-timer")
        require(0 < OBSERVATION_SECONDS <= 180, "invalid-observation-budget")
        self.previous_handler = signal.getsignal(signal.SIGALRM)
        signal.signal(signal.SIGALRM, self.expired)
        try:
            signal.setitimer(signal.ITIMER_REAL, OBSERVATION_SECONDS)
        except BaseException:
            signal.signal(signal.SIGALRM, self.previous_handler)
            raise
        return self

    @staticmethod
    def expired(_signum, _frame):
        # Do not inherit ValueError: binding-validation catches must not swallow
        # the one-shot deadline and continue with its alarm already consumed.
        raise ObservationTimeout("observation-deadline")

    def __exit__(self, _kind, _value, _traceback):
        try:
            signal.setitimer(signal.ITIMER_REAL, 0)
        finally:
            signal.signal(signal.SIGALRM, self.previous_handler)


def require(condition, reason):
    if not condition:
        raise AuditError(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def json_data(data):
    def unique(pairs):
        result = {}
        for name, value in pairs:
            require(name not in result, "duplicate-json-field")
            result[name] = value
        return result
    def invalid_constant(_value):
        raise AuditError("nonfinite-json-number")
    def finite_float(value):
        parsed = float(value)
        require(math.isfinite(parsed), "nonfinite-json-number")
        return parsed
    return json.loads(data, object_pairs_hook=unique, parse_constant=invalid_constant, parse_float=finite_float)


def timestamp(value):
    """Return exact UTC epoch nanoseconds; never truncate feed chronology."""
    require(isinstance(value, str), "invalid-feed-timestamp")
    match = re.fullmatch(r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]{1,9}))?(Z|[+-][0-9]{2}:[0-9]{2})", value)
    require(match is not None, "invalid-feed-timestamp")
    whole, fraction, offset = match.groups()
    require(offset != "-00:00", "unknown-feed-timestamp-offset")
    require(offset == "Z" or (int(offset[1:3]) <= 23 and int(offset[4:6]) <= 59), "invalid-feed-timestamp-offset")
    try:
        parsed = dt.datetime.fromisoformat(whole + offset.replace("Z", "+00:00")).astimezone(dt.timezone.utc)
        delta = parsed - dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
    except (ValueError, OverflowError) as error:
        raise AuditError("invalid-feed-timestamp") from error
    return (delta.days * 86400 + delta.seconds) * 1_000_000_000 + int((fraction or "").ljust(9, "0"))


def modified_binding(batch, detail):
    """OSV querybatch truncates detail nanoseconds to six fractional digits.

    Preserve both raw values; allow only that observed precision representation,
    or exact instants. A changed batch microsecond or whole second still fails.
    """
    def parts(value):
        parsed = timestamp(value)
        fraction = re.search(r"\.(\d+)", value)
        digits = fraction[1] if fraction else ""
        return parsed, len(digits)
    bn, bp = parts(batch)
    dn, dp = parts(detail)
    if bn == dn:
        return "exact"
    if bp == 6 and 7 <= dp <= 9 and bn <= dn < bn + 1000:
        return "batch-microsecond-truncation"
    return None


def same_modified(batch, detail):
    return modified_binding(batch, detail) is not None


def identity(value):
    require(isinstance(value, str) and re.fullmatch(ID_PATTERN, value), "invalid-advisory-id")
    return value


def logical_lines(data):
    require(len(data) <= MAX_SOURCE, "oversized-source-input")
    for line in re.sub(r"\\\r?\n", " ", data.decode("utf-8")).splitlines():
        line = line.split(" #", 1)[0].strip()
        if line and not line.startswith("#"):
            require(len(line) <= 256 * 1024, "oversized-requirement-line")
            yield line


def requirement(value):
    item = Requirement(value)
    require(not item.url, "url-requirement-not-supported")
    return item


def locked_records(path, data, scope):
    records, seen = [], set()
    for line in logical_lines(data):
        parts = line.split(" --hash=")
        item = requirement(parts[0])
        specs = list(item.specifier)
        require(len(specs) == 1 and specs[0].operator == "==" and "*" not in specs[0].version,
                "nonexact-lock-pin")
        version = str(Version(specs[0].version))
        require(version == specs[0].version, "noncanonical-lock-version")
        hashes = [part.strip() for part in parts[1:]]
        require(hashes and all(re.fullmatch(r"sha256:[0-9a-f]{64}", value) for value in hashes), "missing-or-invalid-lock-hash")
        require(len(hashes) == len(set(hashes)), "duplicate-lock-hash")
        name, marker = str(canonicalize_name(item.name)), str(item.marker) if item.marker else ""
        key = (name, version, marker)
        require(key not in seen, "duplicate-lock-record")
        seen.add(key)
        records.append({"manifest": path, "manifest_sha256": digest(data), "name": name,
                        "version": version, "marker": marker, "extras": sorted(item.extras),
                        "distribution_hashes": sorted(hashes), "scope": scope["role"]})
    require(len(records) == scope["count"], "scope-count-changed-review-required: " + path)
    return records


def source_bytes(root, relative):
    path = root / relative
    require(path.resolve().is_relative_to(root.resolve()) and path.is_file() and not path.is_symlink(), "unsafe-source-input: " + relative)
    with path.open("rb") as stream:
        data = stream.read(MAX_SOURCE + 1)
    require(len(data) <= MAX_SOURCE, "oversized-source-input")
    return data


def source_scope(inputs, scopes=SCOPES, framework_count=EXPECTED_FRAMEWORK_INPUTS):
    require(set(scopes) == set(SCOPES), "complete-three-lock-scope-required")
    records = [record for path, scope in scopes.items() for record in locked_records(path, inputs[path], scope)]
    constants = {}
    for name in ("DISTRIBUTION", "VERSION", "WHEEL_SHA256", "SDIST_SHA256"):
        matches = re.findall(r'^pub const ' + name + r': &str = "([^"\n]+)";', inputs[PIN].decode(), re.M)
        require(len(matches) == 1, "server-pin-constant-missing-or-duplicate")
        constants[name] = matches[0]
    require(constants["DISTRIBUTION"] == "cua-computer-server", "unexpected-server-distribution")
    for name in ("WHEEL_SHA256", "SDIST_SHA256"):
        require(re.fullmatch(r"[0-9a-f]{64}", constants[name]), "invalid-server-artifact-hash")
    require(constants["WHEEL_SHA256"] != constants["SDIST_SHA256"], "collapsed-server-artifact-hashes")
    roots = [requirement(line) for line in logical_lines(inputs[ROOT_IN])]
    require(len(roots) == 1 and canonicalize_name(roots[0].name) == constants["DISTRIBUTION"]
            and str(roots[0].specifier) == "==" + constants["VERSION"]
            and roots[0].extras == {"driver", "vnc"} and roots[0].marker is None, "server-root-input-drift")
    for path in (BASE + "requirements-linux-aarch64.lock", BASE + "requirements-macos-arm64.lock"):
        server = [record for record in records if record["manifest"] == path and record["name"] == constants["DISTRIBUTION"]]
        require(len(server) == 1 and server[0]["version"] == constants["VERSION"]
                and set(server[0]["distribution_hashes"]) == {"sha256:" + constants[name] for name in ("WHEEL_SHA256", "SDIST_SHA256")},
                "server-lock-artifact-binding-mismatch")
    framework_inputs = [requirement(line) for line in logical_lines(inputs[MAC_IN])]
    require(len(framework_inputs) == framework_count and framework_count > 0, "darwin-framework-input-count-changed")
    names = set()
    for item in framework_inputs:
        name = str(canonicalize_name(item.name))
        specs = list(item.specifier)
        require(name.startswith("pyobjc-") and name not in names and not item.marker and not item.extras
                and len(specs) == 1 and specs[0].operator == "==" and "*" not in specs[0].version, "invalid-darwin-framework-input")
        names.add(name)
        require(any(r["manifest"] == BASE + "requirements-macos-arm64.lock" and r["name"] == name
                    and r["version"] == specs[0].version for r in records), "darwin-framework-lock-entry-missing")
    build = [requirement(line) for line in logical_lines(inputs[BUILD_IN])]
    require(len(build) == 1 and canonicalize_name(build[0].name) == "setuptools" and not build[0].marker
            and not build[0].extras, "unknown-build-input-scope")
    build_records = [r for r in records if r["manifest"] == BASE + "requirements-build-linux-aarch64.lock"]
    require(len(build_records) == 1 and build_records[0]["name"] == "setuptools"
            and build[0].specifier.contains(build_records[0]["version"]), "build-lock-input-mismatch")
    parser_records = locked_records(TOOL_LOCK, inputs[TOOL_LOCK], {"count": 1, "role": "audit parser only"})
    require(parser_records[0]["name"] == "packaging" and parser_records[0]["version"] == TOOL_VERSION
            and not parser_records[0]["marker"] and not parser_records[0]["extras"], "parser-lock-mismatch")
    return records, constants


def range_match(version, value):
    """OSV PyPI ECOSYSTEM intervals in PEP 440 order, without guessing syntax."""
    require(isinstance(value, dict) and value.get("type") == "ECOSYSTEM", "unknown-affected-range-type")
    events = value.get("events")
    require(isinstance(events, list) and 0 < len(events) <= 256, "invalid-affected-events")
    current, lower, previous, matched = Version(version), None, None, False
    opened = False
    for event in events:
        require(isinstance(event, dict) and len(event) == 1, "invalid-affected-event")
        kind, text = next(iter(event.items()))
        require(kind in {"introduced", "fixed", "last_affected", "limit"} and isinstance(text, str), "unknown-affected-event")
        boundary = None if kind == "introduced" and text == "0" else Version(text)
        require(boundary is not None or previous is None, "unordered-affected-events")
        require(boundary is None or previous is None or boundary >= previous, "unordered-affected-events")
        if kind == "introduced":
            require(not opened, "unclosed-affected-interval")
            lower, opened = boundary, True
        else:
            require(opened and boundary is not None, "affected-interval-without-introduction")
            matched |= (lower is None or current >= lower) and (current <= boundary if kind == "last_affected" else current < boundary)
            opened = False
        if boundary is not None:
            previous = boundary
    return matched or (opened and (lower is None or current >= lower))


def bind_advisory(doc, advisory_id, expected_modified, query, now):
    require(isinstance(doc, dict) and doc.get("id") == advisory_id, "advisory-identity-mismatch")
    binding = modified_binding(expected_modified, doc.get("modified"))
    require(binding is not None, "advisory-modified-during-query")
    published, modified = timestamp(doc.get("published")), timestamp(doc.get("modified"))
    require(published <= modified <= timestamp(now.isoformat()), "feed-timestamp-outside-observation")
    aliases = doc.get("aliases", [])
    require(isinstance(aliases, list) and len(aliases) <= 256 and len(set(map(identity, aliases))) == len(aliases), "invalid-advisory-aliases")
    withdrawn = doc.get("withdrawn")
    withdrawal_binding = "not-withdrawn"
    if withdrawn is not None:
        require(published <= timestamp(withdrawn) <= modified, "invalid-withdrawal-timestamp")
        withdrawal_binding = "verified-exact-modified-binding" if binding == "exact" else "unverified-lossy-modified-binding"
    affected = doc.get("affected")
    require(isinstance(affected, list) and 0 < len(affected) <= 256, "missing-affected-scope")
    matches = []
    for entry in affected:
        require(isinstance(entry, dict) and isinstance(entry.get("package"), dict), "malformed-affected-package")
        package = entry["package"]
        if package.get("ecosystem") != "PyPI" or not isinstance(package.get("name"), str) or canonicalize_name(package["name"]) != query["name"]:
            continue
        versions = entry.get("versions", [])
        ranges = entry.get("ranges", [])
        require(isinstance(versions, list) and len(versions) <= 50000 and all(isinstance(v, str) and len(v) <= 100 for v in versions), "invalid-affected-versions")
        parsed_versions = [Version(v) for v in versions]
        require(isinstance(ranges, list) and len(ranges) <= 256 and (versions or ranges), "missing-affected-version-scope")
        # Validate all matching-package intervals even if explicit versions suffice.
        intervals = [range_match(query["version"], value) for value in ranges]
        explicit = Version(query["version"]) in parsed_versions
        if explicit or any(intervals):
            matches.append({"package": package, "explicit_version_listed": explicit, "ranges": ranges})
    require(matches, "advisory-does-not-bind-query")
    return {"id": advisory_id, "name": query["name"], "version": query["version"],
            "aliases": aliases, "published": doc["published"], "modified": doc["modified"],
            "batch_modified": expected_modified,
            "modified_precision_binding": binding, "withdrawal_binding": withdrawal_binding,
            "withdrawn": withdrawn, "status": "withdrawn" if withdrawal_binding == "verified-exact-modified-binding" else "active",
            "summary": doc.get("summary"), "severity": doc.get("severity", []),
            "database_specific": doc.get("database_specific", {}), "matching_affected": matches}


def batch_results(document, queries):
    require(isinstance(document, dict) and set(document) == {"results"} and isinstance(document["results"], list)
            and len(document["results"]) == len(queries), "batch-query-coverage-mismatch")
    found = []
    for query, result in zip(queries, document["results"]):
        require(isinstance(result, dict) and set(result) <= {"vulns"}, "unknown-or-paginated-batch-scope")
        values = result.get("vulns", [])
        require(isinstance(values, list) and len(values) <= MAX_ADVISORIES, "invalid-batch-vulnerabilities")
        seen = set()
        for value in values:
            require(isinstance(value, dict) and set(value) == {"id", "modified"}, "invalid-batch-vulnerability")
            item = identity(value["id"])
            timestamp(value["modified"])
            require(item not in seen, "duplicate-batch-advisory")
            seen.add(item)
            found.append({**query, "id": item, "modified": value["modified"]})
    return found


class Budget:
    def __init__(self, directory):
        self.directory, self.deadline = directory, time.monotonic() + OBSERVATION_SECONDS
        self.bytes, self.last_check = 0, 0
        self.minimum_free = self.minimum_memory = self.oom_before = self.oom_last = None

    def check(self, force=False):
        require(time.monotonic() < self.deadline, "operation-deadline")
        if not force and time.monotonic() - self.last_check < 0.25:
            return
        free = min(shutil.disk_usage(path).free for path in {self.directory, Path('/tmp'), Path('/workspace')} if path.exists())
        self.minimum_free = min(self.minimum_free or free, free)
        require(free >= DISK_FLOOR, "disk-reserve")
        require(Path('/proc/meminfo').is_file(), 'resource-observation-unavailable')
        if Path('/proc/meminfo').is_file():
            fields = dict(re.findall(r'^(\w+):\s+(\d+)', Path('/proc/meminfo').read_text(), re.M))
            memory = int(fields['MemAvailable']) * 1024
            group = Path('/sys/fs/cgroup')
            if (group/'memory.max').is_file() and (group/'memory.max').read_text().strip() != 'max':
                stats = dict(line.split() for line in (group/'memory.stat').read_text().splitlines())
                memory = min(memory, int((group/'memory.max').read_text()) - sum(int(stats[k]) for k in ('anon', 'shmem', 'kernel')) + int(stats['slab_reclaimable']))
            if (group/'memory.events').is_file():
                events = dict(line.split() for line in (group/'memory.events').read_text().splitlines())
                self.oom_last = {k: int(events[k]) for k in ('oom', 'oom_kill', 'oom_group_kill')}
                self.oom_before = self.oom_before or self.oom_last.copy()
                require(self.oom_before == self.oom_last, 'oom-counter-increase')
            else:
                require(not (group/'memory.max').is_file(), 'oom-counters-unavailable')
            limit = MEMORY_START if self.minimum_memory is None else MEMORY_ACTIVE
            self.minimum_memory = min(self.minimum_memory or memory, memory)
            require(memory >= limit, 'memory-reserve')
        self.last_check = time.monotonic()

    def account(self, size):
        self.bytes += size
        require(self.bytes <= MAX_TOTAL, 'total-response-byte-cap')
        self.check()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AuditError('feed-redirect-refused')


def fetch(url, payload, budget):
    require(url == BATCH_URL or (url.startswith(DETAIL_URL) and re.fullmatch(ID_PATTERN, url[len(DETAIL_URL):])), 'unapproved-feed-endpoint')
    data = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode() if payload is not None else None
    require(data is None or len(data) <= 64 * 1024, 'request-byte-cap')
    maximum = MAX_RESPONSE if payload is not None else MAX_DETAIL
    request = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json', 'Accept': 'application/json', 'User-Agent': 'agentuplink-c259-audit/1'}, method='POST' if data is not None else 'GET')
    budget.check()
    body = bytearray()
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=15) as response:
        require(response.status == 200 and response.url == url, 'unexpected-feed-response')
        while chunk := response.read(64 * 1024):
            require(len(body) + len(chunk) <= maximum, 'response-byte-cap')
            budget.account(len(chunk))
            body.extend(chunk)
    return bytes(body)


def groups(records):
    parents = {}
    def find(key):
        parents.setdefault(key, key)
        if parents[key] != key:
            parents[key] = find(parents[key])
        return parents[key]
    for record in records:
        for alias in record['aliases']:
            parents[find(record['id'])] = find(alias)
        find(record['id'])
    collected = {}
    for record in records:
        collected.setdefault(find(record['id']), []).append(record)
    return [{'ids': sorted({r['id'] for r in rows}), 'aliases': sorted({a for r in rows for a in r['aliases']}),
             'package_versions': sorted({r['name'] + '==' + r['version'] for r in rows}),
             'active': any(r['status'] == 'active' for r in rows)} for rows in collected.values()]


def write_json(path, value, budget=None, maximum=None):
    maximum = MAX_REPORT_BYTES if maximum is None else maximum
    temporary = path.with_suffix(path.suffix + '.tmp')
    total = 0
    created = False
    if budget is not None:
        budget.check(force=True)
        require(shutil.disk_usage(path.parent).free >= DISK_FLOOR + maximum + MAX_FAILURE_REPORT_BYTES,
                'report-write-reserve')
    try:
        with temporary.open('xb') as output:
            created = True
            for piece in json.JSONEncoder(indent=2, sort_keys=True, allow_nan=False).iterencode(value):
                data = piece.encode()
                require(total + len(data) + 1 <= maximum, 'report-output-byte-cap')
                if budget is not None:
                    budget.check()
                output.write(data)
                total += len(data)
            output.write(b'\n')
        temporary.replace(path)
        if budget is not None:
            budget.check(force=True)
    finally:
        if created:
            temporary.unlink(missing_ok=True)


def run(root, output, *, scopes=SCOPES, framework_count=EXPECTED_FRAMEWORK_INPUTS):
    output.mkdir(mode=0o700)  # Refuse reuse before any network or source mutation.
    report = {'schema': 1, 'status': 'running', 'phase': 'source', 'scope': 'CUA guest/build hash locks only',
              'started_at': dt.datetime.now(dt.timezone.utc).isoformat(), 'errors': [], 'requests': [],
              'records': [], 'advisories': [], 'groups': [], 'github_alert_reconciliation': False,
              'package_execution': False, 'license_policy_evaluation': False, 'input_sha256': {}}
    inputs, budget, self_bytes = {}, Budget(output), Path(__file__).read_bytes()
    report['tool'] = {'packaging': packaging.__version__, 'script_sha256': digest(self_bytes)}
    write_failed = False
    def persist():
        nonlocal write_failed
        if write_failed:
            write_json(output / 'report.json', report, maximum=MAX_FAILURE_REPORT_BYTES)
            return
        try:
            write_json(output / 'report.json', report, budget)
        except BaseException as error:
            # Stop the run; preserve the prior complete snapshot and raw feed
            # files. A small explicit failure envelope can never reuse a pass.
            write_failed = True
            prior = output / 'report.json'
            if prior.is_file():
                prior.rename(output / 'report-before-write-failure.json')
            failure = {'stage': 'evidence-write', 'reason': type(error).__name__ + ': ' + str(error)[:512]}
            envelope = {key: report[key] for key in ('schema', 'phase', 'started_at', 'scope', 'tool', 'input_sha256')}
            envelope.update(status='failed', evidence_complete=False,
                            counts=report.get('counts', {}),
                            prior_snapshot='report-before-write-failure.json' if (output / 'report-before-write-failure.json').is_file() else None,
                            error_count_before_write_failure=len(report['errors']),
                            errors=[{key: value[:512] if isinstance(value, str) else value for key, value in item.items()}
                                    for item in report['errors'][:1]] + [failure])
            report.clear()
            report.update(envelope)
            # Completion diagnostics are capped separately; no resource failure
            # is suppressed just because recording it also consumes some space.
            write_json(output / 'report.json', report, maximum=MAX_FAILURE_REPORT_BYTES)
            raise
    def request(url, payload):
        index = len(report['requests'])
        require(index < MAX_ADVISORIES + 8, 'request-count-cap')
        body = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode() if payload is not None else b''
        require(len(body) <= 64 * 1024, 'request-byte-cap')
        receipt = {'url': url, 'method': 'POST' if payload is not None else 'GET', 'request_sha256': digest(body),
                   'started_at': dt.datetime.now(dt.timezone.utc).isoformat(), 'status': 'started'}
        (output / f'request-{index:03}.json').write_bytes(body)
        report['requests'].append(receipt)
        persist()
        try:
            data = fetch(url, payload, budget)
            (output / f'response-{index:03}.json').write_bytes(data)
            receipt.update(status='received',response_sha256=digest(data),response_bytes=len(data))
            return json_data(data), digest(data)
        except Exception as error:
            receipt.update(status='failed',error=type(error).__name__ + ': ' + str(error)[:512])
            raise
        finally:
            receipt['finished_at'] = dt.datetime.now(dt.timezone.utc).isoformat()
            persist()
    try:
        with ObservationDeadline():
            persist()
            require(packaging.__version__ == TOOL_VERSION, 'parser-version-mismatch')
            budget.check(force=True)
            for path in (*scopes, *AUX_INPUTS):
                inputs[path] = source_bytes(root, path)
                report['input_sha256'][path] = digest(inputs[path])
            records, server = source_scope(inputs, scopes, framework_count)
            report.update(records=records, server_artifact_binding=server, scopes=scopes)
            keys = sorted({(r['name'], r['version']) for r in records})
            queries = [{'name': name, 'version': version} for name, version in keys]
            report['counts'] = {'lock_records': len(records), 'unique_package_versions': len(keys), 'queries_covered': 0,
                                'returned_advisory_records': 0, 'active_advisory_records': 0, 'withdrawn_advisory_records': 0}
            report['phase'] = 'batches'
            found = []
            for start in range(0, len(queries), BATCH_SIZE):
                batch = queries[start:start+BATCH_SIZE]
                document, response_sha = request(BATCH_URL, {'queries': [{'package': {'ecosystem': 'PyPI', 'name': q['name']}, 'version': q['version']} for q in batch]})
                selected = batch_results(document, batch)
                for entry in selected:
                    entry['batch_response_sha256'] = response_sha
                found.extend(selected)
                report['counts']['queries_covered'] += len(batch)
                report['counts']['returned_advisory_records'] = len(found)
                require(len({f['id'] for f in found}) <= MAX_ADVISORIES, 'advisory-count-cap')
                require(len(found) <= 8192, 'advisory-record-count-cap')
                persist()
            report['phase'] = 'details'
            documents = {}
            for entry in found:
                if entry['id'] not in documents:
                    documents[entry['id']] = request(DETAIL_URL + entry['id'], None)
                document, source_sha = documents[entry['id']]
                try:
                    record = bind_advisory(document, entry['id'], entry['modified'], entry, dt.datetime.now(dt.timezone.utc))
                    record.update(advisory_sha256=source_sha, batch_response_sha256=entry['batch_response_sha256'],
                                  occurrences=[r for r in records if (r['name'], r['version']) == (entry['name'], entry['version'])])
                    report['advisories'].append(record)
                    report['counts'][record['status'] + '_advisory_records'] += 1
                    if record['status'] == 'active':
                        report['errors'].append({'stage': 'advisory', 'id': entry['id'], 'name': entry['name'], 'version': entry['version'], 'reason': 'active-known-advisory'})
                except (ValueError, KeyError, TypeError) as error:
                    report['errors'].append({'stage': 'binding', 'id': entry['id'], 'name': entry['name'], 'version': entry['version'], 'reason': str(error)[:512]})
                persist()
            report['groups'] = groups(report['advisories'])
            require(report['counts']['queries_covered'] == len(keys), 'incomplete-query-coverage')
            require(len(report['advisories']) == len(found), 'incomplete-advisory-binding')
            report['phase'] = 'complete'
    except BaseException as error:
        report['errors'].append({'stage': report['phase'], 'reason': type(error).__name__ + ': ' + str(error)[:512]})
    finally:
        for path, original in inputs.items():
            try:
                require(source_bytes(root, path) == original, 'source-input-changed')
            except Exception as error:
                report['errors'].append({'stage': 'final-source', 'path': path, 'reason': str(error)})
        try:
            require(Path(__file__).read_bytes() == self_bytes, 'checker-source-changed')
            budget.check(force=True)
        except Exception as error:
            report['errors'].append({'stage': 'final-guards', 'reason': str(error)})
        report['resources'] = {'response_bytes': budget.bytes, 'minimum_free_bytes': budget.minimum_free,
                               'minimum_memory_available_estimate': budget.minimum_memory,
                               'oom_before': budget.oom_before, 'oom_last': budget.oom_last}
        report['status'] = 'failed' if report['errors'] else 'passed'
        report['finished_at'] = dt.datetime.now(dt.timezone.utc).isoformat()
        persist()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--output', type=Path, required=True, help='new private evidence directory; must not exist')
    options = parser.parse_args()
    def interrupted(signum, _frame):
        raise InterruptedError('signal ' + str(signum))
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, interrupted)
    report = run(options.root.resolve(), options.output)
    print('C259 ' + report['status'].upper() + ': ' + json.dumps(report.get('counts', {}), sort_keys=True))
    print('errors=' + str(len(report['errors'])) + ' report=' + str(options.output / 'report.json'))
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
