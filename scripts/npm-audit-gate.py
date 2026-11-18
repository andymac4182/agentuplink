#!/usr/bin/env python3
"""npm audit gate with documented, per-advisory exceptions.

`npm audit --audit-level=high` has no way to accept one advisory, so a single
advisory with no fixed release turns the whole gate red and hides every later
one behind it.  This script runs `npm audit --json` in a package directory and
fails on every advisory of severity high or critical that is not listed, by
GHSA id and with a reason, in that directory's `audit-exceptions.json`.

It is not a weaker threshold:

* an exception names one advisory id; any other high or critical advisory, on
  the same package or another, still fails;
* an exception that no longer matches an advisory in the report fails too
  (`unused exception`), so an entry cannot outlive its cause -- the same rule
  `unused-ignored-advisory = "deny"` enforces in deny.toml;
* an exception without a non-empty reason fails;
* a report that is not a version 2 audit report, or carries an error, fails.

`--self-test` runs the classifier over fixed synthetic reports and proves each
of those failures is still reachable.  CI runs it before the real gate.
"""

import json
import subprocess
import sys
from pathlib import Path

GATED = {"high", "critical"}


def advisory_id(via):
    return via["url"].rstrip("/").rsplit("/", 1)[-1]


def classify(report, exceptions):
    """Return a list of failure strings; empty means the gate passes."""
    failures = []
    if report.get("auditReportVersion") != 2 or "error" in report:
        return ["audit report is missing, not version 2, or carries an error"]
    allowed = {}
    for entry in exceptions:
        if not str(entry.get("id", "")).startswith("GHSA-") or not str(entry.get("reason", "")).strip():
            failures.append(f"exception without a GHSA id and a reason: {entry!r}")
            continue
        allowed[entry["id"]] = False
    for package, vulnerability in sorted(report.get("vulnerabilities", {}).items()):
        for via in vulnerability.get("via", []):
            # A string names another vulnerable package, whose own entry
            # carries the advisory; only advisory objects are classified.
            if not isinstance(via, dict):
                continue
            identifier = advisory_id(via)
            if identifier in allowed:
                allowed[identifier] = True
            elif via.get("severity") in GATED:
                failures.append(f"{via.get('severity')} advisory {identifier} on {package}")
    failures.extend(
        f"unused exception {identifier}: no such advisory in the report"
        for identifier, used in sorted(allowed.items())
        if not used
    )
    return failures


def self_test():
    def report(*advisories):
        return {
            "auditReportVersion": 2,
            "vulnerabilities": {
                name: {"via": [{"url": f"https://github.com/advisories/{ghsa}", "severity": severity}]}
                for name, ghsa, severity in advisories
            }
            | {"dependent": {"via": ["a"]}},
        }

    accepted = [{"id": "GHSA-aaaa-aaaa-aaaa", "reason": "control"}]
    a = ("a", "GHSA-aaaa-aaaa-aaaa", "high")
    cases = [
        ("clean report passes", report(), [], 0),
        ("high advisory fails", report(a), [], 1),
        ("critical advisory fails", report(("a", "GHSA-aaaa-aaaa-aaaa", "critical")), [], 1),
        ("moderate advisory passes", report(("a", "GHSA-aaaa-aaaa-aaaa", "moderate")), [], 0),
        ("excepted advisory passes", report(a), accepted, 0),
        ("second advisory still fails", report(a, ("b", "GHSA-bbbb-bbbb-bbbb", "high")), accepted, 1),
        ("unused exception fails", report(), accepted, 1),
        ("exception without reason fails", report(a), [{"id": "GHSA-aaaa-aaaa-aaaa", "reason": " "}], 2),
        ("errored report fails", {"auditReportVersion": 2, "error": {}}, [], 1),
        ("wrong report version fails", {"auditReportVersion": 1}, [], 1),
    ]
    bad = [name for name, rep, exc, want in cases if len(classify(rep, exc)) != want]
    for name in bad:
        print(f"npm-audit-gate self-test FAILED: {name}", file=sys.stderr)
    if not bad:
        print(f"npm-audit-gate self-test: {len(cases)} controls behave as expected")
    return 1 if bad else 0


def main(argv):
    if argv == ["--self-test"]:
        return self_test()
    if len(argv) != 1:
        print("usage: npm-audit-gate.py <package-dir> | --self-test", file=sys.stderr)
        return 2
    directory = Path(argv[0])
    exceptions_path = directory / "audit-exceptions.json"
    exceptions = json.loads(exceptions_path.read_text()) if exceptions_path.exists() else []
    proc = subprocess.run(["npm", "audit", "--json"], cwd=directory, capture_output=True, text=True)
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print("npm-audit-gate: npm audit did not produce JSON", file=sys.stderr)
        return 1
    failures = classify(report, exceptions)
    counts = report.get("metadata", {}).get("vulnerabilities", {})
    print(f"npm-audit-gate: {directory}: reported {counts}; {len(exceptions)} documented exception(s)")
    for failure in failures:
        print(f"npm-audit-gate: FAIL: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
