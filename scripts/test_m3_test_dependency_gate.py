"""Seeded M3-50 controls use real synthetic archives and the complete checker.

Registry transport and npm's subprocess are mocked; parsing, identity/hash,
marker coverage, metadata reconciliation and policy/advisory decisions are not.
No network, package installation, Redis or Cargo is used by this test suite.
"""

import base64
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile


SPEC = importlib.util.spec_from_file_location(
    "mcp_dependency_gate", Path(__file__).with_name("m3-test-dependency-gate.py")
)
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


def tar_package(metadata):
    output = io.BytesIO()
    data = json.dumps(metadata).encode()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        info = tarfile.TarInfo("package/package.json")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    return output.getvalue()


def wheel_package(metadata, with_license=True, with_metadata=True):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        if with_metadata:
            archive.writestr("example-1.0.dist-info/METADATA", metadata)
        if with_license:
            archive.writestr("example-1.0.dist-info/licenses/LICENSE", "Synthetic MIT fixture notice")
    return output.getvalue()


class Fixture:
    def __init__(self, root):
        self.root = root
        self.cache = root / "cache"
        self.files = {}
        self.npm_package = {"name": "example", "version": "1.0.0", "license": "MIT"}
        self.manifest = {"name": "fixture", "version": "0.0.0", "license": "SEE LICENSE IN ../../LICENSE",
                         "devDependencies": {"example": "1.0.0"}}
        self.lock = {"lockfileVersion": 3, "packages": {"": copy.deepcopy(self.manifest)}}
        self.metadata = {}
        self.wheel_options = {}
        self.releases = {}
        self.audit = {
            "auditReportVersion": 2, "vulnerabilities": {},
            "metadata": {"dependencies": {"total": 1}, "vulnerabilities": {
                "info": 0, "low": 0, "moderate": 0, "high": 0, "critical": 0, "total": 0}},
        }
        self.audit_status = 0
        for version in ("1.0", "2.0"):
            self.metadata[version] = (f"Metadata-Version: 2.4\nName: example\nVersion: {version}\n"
                                      "License-Expression: MIT\nLicense-File: LICENSE\n\n")
            self.wheel_options[version] = {}

    def prepare(self):
        self.files = {}
        npm_url = "https://registry.npmjs.org/example/-/example-1.0.0.tgz"
        data = tar_package(self.npm_package)
        self.files[npm_url] = data
        entry = self.lock["packages"].setdefault("node_modules/example", {})
        entry.update({"version": "1.0.0", "resolved": npm_url,
                      "integrity": "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()})
        entry.setdefault("license", "MIT")
        lines = []
        for version, marker in (("1.0", 'python_full_version < "3.11"'),
                                ("2.0", 'python_full_version >= "3.11"')):
            filename = f"example-{version}-py3-none-any.whl"
            url = "https://files.pythonhosted.org/" + filename
            data = wheel_package(self.metadata[version], **self.wheel_options[version])
            digest = gate.sha256(data)
            self.files[url] = data
            release = {"info": {"name": "example", "version": version}, "vulnerabilities": [],
                       "urls": [{"filename": filename, "packagetype": "bdist_wheel", "url": url,
                                 "digests": {"sha256": digest}}]}
            release.update(self.releases.get(version, {}))
            self.files[f"https://pypi.org/pypi/example/{version}/json"] = json.dumps(release).encode()
            lines.append(f"example=={version} ; {marker} \\\n    --hash=sha256:{digest}\n")
        content = [
            '[licenses]\nallow = ["MIT", "Apache-2.0", "BSD-3-Clause", "Apache-2.0 WITH LLVM-exception"]\n',
            json.dumps(self.manifest), json.dumps(self.lock), "".join(lines),
        ]
        for path, text in zip(gate.INPUTS, content):
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
        (self.root / "LICENSE").write_text("Synthetic root licence")

    def run(self):
        with patch.object(gate, "fetch", side_effect=lambda url: self.files[url]), patch.object(
            gate, "npm_audit", return_value=(self.audit, gate.sha256(json.dumps(self.audit).encode()), self.audit_status)
        ):
            return gate.run(self.root, self.cache, {"npm": 1, "python": 2})


class CompleteGateControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.fixture = Fixture(Path(self.temp.name))

    def result(self):
        self.fixture.prepare()
        return self.fixture.run()

    def rejects(self, reason):
        result = self.result()
        self.assertFalse(result["passed"])
        self.assertTrue(any(reason in error["reason"] for error in result["errors"]), result["errors"])

    def test_allowed_full_graph_binds_both_marker_alternatives_and_artifacts(self):
        report = self.result()
        self.assertTrue(report["passed"], report["errors"])
        self.assertEqual(len(report["packages"]), 3)
        python = [p for p in report["packages"] if p["ecosystem"] == "python"]
        self.assertEqual({p["version"] for p in python}, {"1.0", "2.0"})
        self.assertEqual(len({p["marker"] for p in python}), 2)
        for record in report["packages"]:
            self.assertRegex(record["artifact_sha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(record["metadata_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(report["input_sha256"], {
            p: gate.sha256((self.fixture.root / p).read_bytes()) for p in gate.INPUTS})

    def test_disallowed_license_rejects(self):
        self.fixture.npm_package["license"] = "GPL-3.0-only"
        self.fixture.lock["packages"]["node_modules/example"] = {"license": "GPL-3.0-only"}
        self.rejects("disallowed-license")

    def test_unknown_branch_rejects_even_with_allowed_or_branch(self):
        self.fixture.npm_package["license"] = "MIT OR MadeUp-1.0"
        self.rejects("unknown-license")

    def test_missing_npm_license_rejects(self):
        del self.fixture.npm_package["license"]
        self.rejects("missing-license")

    def test_conflicting_npm_lock_and_artifact_license_rejects(self):
        self.fixture.npm_package["license"] = "Apache-2.0"
        self.rejects("conflicting-license-metadata")

    def test_npm_identity_mismatch_rejects_even_when_hash_matches(self):
        self.fixture.npm_package["name"] = "impostor"
        self.rejects("npm-artifact-identity-mismatch")

    def test_npm_hash_mutation_rejects(self):
        self.fixture.prepare()
        url = self.fixture.lock["packages"]["node_modules/example"]["resolved"]
        self.fixture.files[url] += b"tampered"
        report = self.fixture.run()
        self.assertIn("artifact-hash-mismatch", [e["reason"] for e in report["errors"]])

    def test_python_disallowed_marker_alternative_is_not_skipped(self):
        self.fixture.metadata["1.0"] = self.fixture.metadata["1.0"].replace("MIT", "GPL-3.0-only")
        self.rejects("disallowed-license")

    def test_python_missing_license_rejects(self):
        self.fixture.metadata["1.0"] = self.fixture.metadata["1.0"].replace("License-Expression: MIT\n", "")
        self.rejects("missing-license")

    def test_python_conflicting_license_sources_reject(self):
        self.fixture.metadata["1.0"] = self.fixture.metadata["1.0"].replace("\n\n", "\nLicense: Apache-2.0\n\n")
        self.rejects("conflicting-license-metadata")

    def test_python_generic_bsd_conflicting_with_mit_rejects(self):
        self.fixture.metadata["1.0"] = self.fixture.metadata["1.0"].replace(
            "\n\n", "\nClassifier: License :: OSI Approved :: BSD License\n\n")
        self.rejects("conflicting-license-metadata")

    def test_python_legacy_psf_is_not_silently_guessed(self):
        self.fixture.metadata["1.0"] = self.fixture.metadata["1.0"].replace("License-Expression: MIT", "License: PSF")
        self.rejects("unknown-legacy-license")

    def test_python_missing_metadata_rejects(self):
        self.fixture.wheel_options["1.0"]["with_metadata"] = False
        self.rejects("python-missing-or-duplicate-metadata")

    def test_python_missing_declared_license_file_rejects(self):
        self.fixture.wheel_options["1.0"]["with_license"] = False
        self.rejects("python-missing-or-conflicting-license-file")

    def test_python_duplicate_license_field_rejects(self):
        self.fixture.metadata["1.0"] = self.fixture.metadata["1.0"].replace(
            "\n\n", "\nLicense-Expression: Apache-2.0\n\n")
        self.rejects("python-duplicate-metadata-field")

    def test_python_metadata_identity_rejects_even_when_hash_matches(self):
        self.fixture.metadata["1.0"] = self.fixture.metadata["1.0"].replace("Name: example", "Name: impostor")
        self.rejects("python-metadata-identity-mismatch")

    def test_python_release_identity_mismatch_rejects(self):
        self.fixture.releases["1.0"] = {"info": {"name": "impostor", "version": "1.0"}}
        self.rejects("python-release-identity-mismatch")

    def test_python_no_lock_matched_artifact_rejects(self):
        self.fixture.releases["1.0"] = {"urls": []}
        self.rejects("python-no-lock-matched-wheel")

    def test_python_known_advisory_rejects(self):
        self.fixture.releases["1.0"] = {"vulnerabilities": [{"id": "PYSEC-SYNTHETIC-1"}]}
        self.rejects("python-known-advisory")

    def test_python_missing_advisory_response_rejects(self):
        self.fixture.releases["1.0"] = {"vulnerabilities": None}
        self.rejects("python-missing-advisory-coverage")

    def test_npm_all_severities_reject_including_low_and_moderate(self):
        for severity in ("info", "low", "moderate", "high", "critical"):
            with self.subTest(severity=severity):
                self.fixture.audit["vulnerabilities"] = {"example": {"severity": severity}}
                counts = dict.fromkeys(("info", "low", "moderate", "high", "critical", "total"), 0)
                counts[severity] = counts["total"] = 1
                self.fixture.audit["metadata"]["vulnerabilities"] = counts
                self.fixture.audit_status = 1
                self.rejects("npm-known-advisory")

    def test_npm_unknown_severity_finding_is_not_ignored(self):
        self.fixture.audit["vulnerabilities"] = {"example": {"severity": "future"}}
        self.rejects("npm-known-advisory")

    def test_npm_incomplete_audit_coverage_rejects(self):
        self.fixture.audit["metadata"]["dependencies"]["total"] = 0
        self.rejects("npm-audit-coverage-mismatch")

    def test_npm_empty_report_is_not_clean(self):
        self.fixture.audit = {}
        self.rejects("npm-audit-missing-coverage")

    def test_corrupt_cached_archive_is_not_trusted(self):
        self.assertTrue(self.result()["passed"])
        cached = next(self.fixture.cache.glob("sha256-*"))
        cached.write_bytes(b"tampered")
        report = self.fixture.run()
        self.assertIn("artifact-hash-mismatch", [e["reason"] for e in report["errors"]])

    def test_input_mutation_during_run_rejects(self):
        self.fixture.prepare()
        path = self.fixture.root / gate.INPUTS[3]
        original = self.fixture.files.copy()

        def fetch_and_mutate(url):
            path.write_text("# changed while checking\n")
            return original[url]

        with patch.object(gate, "fetch", side_effect=fetch_and_mutate), patch.object(
            gate, "npm_audit", return_value=(self.fixture.audit, "0" * 64, 0)
        ), self.assertRaisesRegex(gate.GateError, "inputs-changed-during-check"):
            gate.run(self.fixture.root, self.fixture.cache, {"npm": 1, "python": 2})

    def test_a_second_run_refreshes_advisories_despite_cached_archives(self):
        self.assertTrue(self.result()["passed"])
        url = "https://pypi.org/pypi/example/1.0/json"
        release = json.loads(self.fixture.files[url])
        release["vulnerabilities"] = [{"id": "PYSEC-SYNTHETIC-NEW"}]
        self.fixture.files[url] = json.dumps(release).encode()
        report = self.fixture.run()
        self.assertIn("python-known-advisory", [e["reason"] for e in report["errors"]])


class ParserControls(unittest.TestCase):
    def test_ambiguous_json_metadata_is_not_last_field_wins(self):
        with self.assertRaisesRegex(gate.GateError, "duplicate-json-key"):
            gate.json_document('{"license":"GPL-3.0-only","license":"MIT"}')

    def test_spdx_precedence_and_parentheses(self):
        allow = {"MIT", "Apache-2.0", "Apache-2.0 WITH LLVM-exception"}
        for value in ("MIT OR GPL-3.0-only", "MIT OR Apache-2.0 AND GPL-3.0-only",
                      "(MIT OR GPL-3.0-only) AND Apache-2.0", "Apache-2.0 WITH LLVM-exception"):
            gate.allowed_expression(value, allow)
        for value in ("MIT AND GPL-3.0-only", "(MIT OR Apache-2.0) AND GPL-3.0-only"):
            with self.assertRaisesRegex(gate.GateError, "disallowed-license"):
                gate.allowed_expression(value, allow)

    def test_unknown_reference_rejects_despite_allowed_or_branch(self):
        with self.assertRaisesRegex(gate.GateError, "unknown-license-reference"):
            gate.allowed_expression("MIT OR LicenseRef-unreviewed", {"MIT"})

    def test_unhashed_unpinned_and_duplicate_pins_reject(self):
        digest = "a" * 64
        for text, witness in (
            ("example==1.0", "python-missing-hashes"),
            (f"example>=1.0 --hash=sha256:{digest}", "python-nonexact-pin"),
            ((f"example==1.0 --hash=sha256:{digest}\n") * 2, "python-duplicate-pin"),
        ):
            with self.subTest(text=text), self.assertRaisesRegex(gate.GateError, witness):
                gate.python_pins(text.encode())

    def test_audit_command_overrides_omit_env_and_checks_any_advisory(self):
        audit = {"auditReportVersion": 2}
        with patch.object(gate.subprocess, "run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = json.dumps(audit).encode()
            gate.npm_audit(Path("/synthetic"))
        args = run.call_args.args[0]
        for flag in ("--package-lock-only", "--audit-level=low", "--include=dev",
                     "--include=optional", "--include=peer", "--registry=https://registry.npmjs.org"):
            self.assertIn(flag, args)


if __name__ == "__main__":
    unittest.main()
