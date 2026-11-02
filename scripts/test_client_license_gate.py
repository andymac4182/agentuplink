"""Offline C253 controls: real synthetic tarballs, no npm or package execution."""
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

SPEC = importlib.util.spec_from_file_location("client_license_gate", Path(__file__).with_name("client-license-gate.py"))
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)
REPOSITORY = Path(__file__).resolve().parents[1]


def tarball(metadata, notice=True, extra=(), root="package"):
    entries = [(root + "/package.json", json.dumps(metadata).encode(), None)]
    if notice:
        entries.append((root + "/LICENSE", b"Synthetic notice; not an approval of real package terms.\n", None))
    entries.extend(extra)
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, data, kind in entries:
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            if kind is not None:
                entry.type = kind
                entry.linkname = "package/LICENSE"
            archive.addfile(entry, io.BytesIO(data))
    return output.getvalue()


class Fixture:
    def __init__(self, root):
        self.root = root
        self.cache = root / "artifacts"
        self.cache.mkdir()
        self.manifest = {"name": "fixture", "version": "0.0.0", "license": "SEE LICENSE IN ../../LICENSE",
                         "devDependencies": {"parent": "1.0.0", "native": "1.0.0"}}
        self.metadata = {
            "parent": {"name": "parent", "version": "1.0.0", "license": "MIT",
                       "dependencies": {"compat": "npm:canonical@~1.0.0"}},
            "compat": {"name": "canonical", "version": "1.0.1", "license": "Apache-2.0"},
            "native": {"name": "native", "version": "1.0.0", "license": "MIT"},
        }
        self.notices, self.extra, self.files = {}, {}, {}

    def prepare(self):
        self.lock = {"name": "fixture", "version": "0.0.0", "lockfileVersion": 3,
                     "packages": {"": copy.deepcopy(self.manifest)}}
        for name, metadata in self.metadata.items():
            data = tarball(metadata, self.notices.get(name, True), self.extra.get(name, ()))
            url = gate.artifact_url(metadata["name"], metadata["version"])
            self.files[url] = data
            entry = {"version": metadata["version"], "license": metadata.get("license"), "resolved": url,
                     "integrity": "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode(), "dev": True}
            if name != metadata["name"]:
                entry["name"] = metadata["name"]
            if "dependencies" in metadata:
                entry["dependencies"] = metadata["dependencies"].copy()
            if name == "native":
                entry.update(optional=True, os=["win32"], cpu=["arm64"])
            self.lock["packages"]["node_modules/" + name] = entry
        self.save()

    def save(self):
        (self.root / "packages/client").mkdir(parents=True, exist_ok=True)
        (self.root / "packages/client/package.json").write_text(json.dumps(self.manifest))
        (self.root / "packages/client/package-lock.json").write_text(json.dumps(self.lock))
        (self.root / "deny.toml").write_text('[licenses]\nallow = ["MIT", "Apache-2.0", "BSD-3-Clause"]\nexceptions = []\n')
        (self.root / "LICENSE").write_bytes((REPOSITORY / "LICENSE").read_bytes())

    def run(self, fetch=None, **kwargs):
        # Resource safety has separate tests; fixture parsing and decisions are real.
        with patch.object(gate, "fetch", side_effect=fetch or (lambda url, budget: self.files[url])), \
                patch.object(gate.Budget, "check"), patch.object(gate.Budget, "reserve_write"):
            return gate.run(self.root, self.cache, expected_nodes=3, expected_aliases=1, **kwargs)


class ClientLicenseControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="client-license-control-")
        self.addCleanup(self.temporary.cleanup)
        self.fixture = Fixture(Path(self.temporary.name))
        self.fixture.prepare()

    def refused(self, report, reason):
        self.assertEqual(report["status"], "failed", report)
        self.assertTrue(any(reason in error["reason"] for error in report["errors"]), report["errors"])

    def test_complete_alias_and_nonhost_optional_positive(self):
        report = self.fixture.run()
        self.assertEqual(report["status"], "passed", report["errors"])
        self.assertEqual(report["counts"], {"lock_nodes": 3, "alias_nodes": 1, "artifact_verified": 3, "policy_pass": 3})
        self.assertEqual(len(report["aliases"]), 1)
        alias = report["aliases"][0]
        self.assertEqual(alias["canonical_name"], "canonical")
        self.assertEqual(alias["version"], "1.0.1")
        for key in ("parent_artifact_sha256", "target_artifact_sha256", "parent_metadata_sha256", "target_metadata_sha256"):
            self.assertEqual(len(alias[key]), 64)
        native = next(p for p in report["packages"] if p["name"] == "native")
        self.assertEqual(native["flags"]["os"], ["win32"])
        self.assertTrue(native["flags"]["dev"] and native["flags"]["optional"])
        self.assertFalse(report["advisories_checked"] or report["bundled_component_audit"])
        self.assertEqual(report["root_license"]["sha256"], gate.ROOT_LICENSE_SHA256)

    def test_exact_alias_range_positive(self):
        self.fixture.metadata["parent"]["dependencies"]["compat"] = "npm:canonical@1.0.1"
        self.fixture.prepare()
        self.assertEqual(self.fixture.run()["status"], "passed")

    def test_nearest_alias_resolution_positive_and_shadow_negative(self):
        packages = {"": {}, "node_modules/c": {}, "node_modules/p/node_modules/c": {}}
        self.assertEqual(gate.resolve(packages, "node_modules/p/node_modules/q", "c"), "node_modules/p/node_modules/c")
        self.assertEqual(gate.resolve(packages, "node_modules/x", "c"), "node_modules/c")
        self.fixture.lock["packages"]["node_modules/parent/node_modules/compat"] = copy.deepcopy(self.fixture.lock["packages"]["node_modules/compat"])
        self.fixture.lock["packages"].pop("node_modules/native")
        self.fixture.save()
        self.refused(self.fixture.run(), "alias-entry-without-resolved-edge")

    def test_missing_alias_edge(self):
        self.fixture.lock["packages"]["node_modules/parent"].pop("dependencies")
        self.fixture.save()
        self.refused(self.fixture.run(), "alias-entry-without-resolved-edge")

    def test_wrong_canonical_alias_edge(self):
        self.fixture.lock["packages"]["node_modules/parent"]["dependencies"]["compat"] = "npm:impostor@1.0.1"
        self.fixture.save()
        self.refused(self.fixture.run(), "alias-canonical-identity-mismatch")

    def test_missing_alias_target(self):
        entry = self.fixture.lock["packages"].pop("node_modules/compat")
        self.fixture.lock["packages"]["node_modules/other"] = entry
        self.fixture.save()
        self.refused(self.fixture.run(), "alias-target-missing")

    def test_wrong_alias_version(self):
        self.fixture.lock["packages"]["node_modules/parent"]["dependencies"]["compat"] = "npm:canonical@~1.1.0"
        self.fixture.save()
        self.refused(self.fixture.run(), "alias-version-mismatch")

    def test_unsupported_alias_range(self):
        self.fixture.lock["packages"]["node_modules/parent"]["dependencies"]["compat"] = "npm:canonical@*"
        self.fixture.save()
        self.refused(self.fixture.run(), "unsupported-alias-spec-review-required")

    def test_alias_lock_edge_without_parent_artifact_edge(self):
        self.fixture.metadata["parent"]["dependencies"]["compat"] = "npm:canonical@1.0.1"
        self.fixture.prepare()
        self.fixture.lock["packages"]["node_modules/parent"]["dependencies"]["compat"] = "npm:canonical@~1.0.0"
        self.fixture.save()
        self.refused(self.fixture.run(), "alias-parent-artifact-edge-mismatch")

    def test_alias_artifact_extra_edge_not_hidden(self):
        self.fixture.metadata["native"]["dependencies"] = {"shadow": "npm:canonical@1.0.1"}
        self.fixture.prepare()
        self.fixture.lock["packages"]["node_modules/native"].pop("dependencies")
        self.fixture.save()
        self.refused(self.fixture.run(), "alias-parent-artifact-edge-mismatch")

    def test_alias_target_cannot_be_used_as_ordinary_dependency(self):
        self.fixture.lock["packages"]["node_modules/native"]["dependencies"] = {"compat": "1.0.1"}
        self.fixture.save()
        self.refused(self.fixture.run(), "alias-target-without-alias-edge")

    def test_artifact_canonical_name_not_installed_alias(self):
        def changed(url, budget):
            if "canonical/-" in url:
                data = tarball({"name": "compat", "version": "1.0.1", "license": "Apache-2.0"})
                return data
            return self.fixture.files[url]
        data = changed(gate.artifact_url("canonical", "1.0.1"), None)
        self.fixture.lock["packages"]["node_modules/compat"]["integrity"] = "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()
        self.fixture.save()
        self.refused(self.fixture.run(changed), "artifact-identity-mismatch")

    def test_artifact_version_mismatch(self):
        node = self.fixture.lock["packages"]["node_modules/native"]
        data = tarball({"name": "native", "version": "9.0.0", "license": "MIT"})
        self.fixture.files[node["resolved"]] = data
        node["integrity"] = "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()
        self.fixture.save()
        self.refused(self.fixture.run(), "artifact-identity-mismatch")

    def test_integrity_mismatch(self):
        self.fixture.files[gate.artifact_url("native", "1.0.0")] += b"changed"
        self.refused(self.fixture.run(), "artifact-integrity-mismatch")

    def test_cached_archive_rehashed_offline(self):
        self.assertEqual(self.fixture.run()["status"], "passed")
        path = next(self.fixture.cache.iterdir())
        path.write_bytes(path.read_bytes() + b"changed")
        self.refused(self.fixture.run(offline=True), "artifact-integrity-mismatch")

    def test_offline_requires_every_artifact(self):
        self.refused(self.fixture.run(offline=True), "offline-artifact-missing")

    def test_cache_symlink_refused(self):
        node = self.fixture.lock["packages"]["node_modules/native"]
        (self.fixture.cache / (gate.integrity_digest(node["integrity"]) + ".tgz")).symlink_to(self.fixture.root / "LICENSE")
        self.refused(self.fixture.run(), "unsafe-or-oversized-cache-entry")

    def test_disallowed_blueoak_is_policy_failure_with_artifact_evidence(self):
        self.fixture.metadata["native"]["license"] = "BlueOak-1.0.0"
        self.fixture.prepare()
        report = self.fixture.run()
        self.refused(report, "disallowed-license: BlueOak-1.0.0")
        self.assertEqual(report["counts"]["artifact_verified"], 3)
        self.assertEqual(report["counts"]["policy_pass"], 2)

    def test_optional_lgpl_not_filtered(self):
        self.fixture.metadata["native"]["license"] = "LGPL-3.0"
        self.fixture.prepare()
        self.refused(self.fixture.run(), "disallowed-license")

    def test_missing_declaration(self):
        self.fixture.metadata["native"].pop("license")
        self.fixture.prepare()
        self.refused(self.fixture.run(), "missing-license")

    def test_unknown_declaration(self):
        self.fixture.metadata["native"]["license"] = "MIT OR MadeUp-1.0"
        self.fixture.prepare()
        self.refused(self.fixture.run(), "unknown-license")

    def test_unknown_license_reference(self):
        self.fixture.metadata["native"]["license"] = "MIT OR LicenseRef-unreviewed"
        self.fixture.prepare()
        self.refused(self.fixture.run(), "unknown-license-reference")

    def test_conflicting_lock_artifact_license(self):
        self.fixture.lock["packages"]["node_modules/native"]["license"] = "Apache-2.0"
        self.fixture.save()
        self.refused(self.fixture.run(), "conflicting-license-metadata")

    def test_missing_notice_keeps_metadata_but_refuses_policy(self):
        self.fixture.notices["native"] = False
        self.fixture.prepare()
        self.refused(self.fixture.run(), "missing-artifact-license-notice")

    def test_spdx_and_or_with_precedence(self):
        gate.allowed_expression("MIT OR (Apache-2.0 AND LGPL-3.0)", {"MIT"})
        with self.assertRaisesRegex(gate.GateError, "disallowed-license"):
            gate.allowed_expression("MIT AND LGPL-3.0", {"MIT"})
        with self.assertRaisesRegex(gate.GateError, "disallowed-license"):
            gate.allowed_expression("Apache-2.0 WITH LLVM-exception", {"Apache-2.0"})

    def test_duplicate_tar_path(self):
        self.fixture.extra["native"] = [("package/LICENSE", b"duplicate", None)]
        self.fixture.prepare()
        self.refused(self.fixture.run(), "duplicate-archive-path")

    def test_archive_traversal(self):
        self.fixture.extra["native"] = [("package/../../escape", b"bad", None)]
        self.fixture.prepare()
        self.refused(self.fixture.run(), "unsafe-archive-path")
        self.assertFalse((self.fixture.root / "escape").exists())

    def test_archive_symlink(self):
        self.fixture.extra["native"] = [("package/alias", b"", tarfile.SYMTYPE)]
        self.fixture.prepare()
        self.refused(self.fixture.run(), "archive-link-or-special-file")

    def test_types_unscoped_archive_root_with_exact_identity(self):
        node = {"name": "@types/native", "version": "1.0.0"}
        data = tarball({**node, "license": "MIT"}, root="native")
        budget = gate.Budget(self.fixture.cache)
        with patch.object(budget, "check"), patch.object(budget, "reserve_write"):
            record = gate.archive_record(node, data, self.fixture.cache, budget)
        self.assertEqual(record["archive_root"], "native")
        self.assertIn("native/LICENSE", record["notice_files"])

    def test_second_archive_root_refused(self):
        self.fixture.extra["native"] = [("other/LICENSE", b"bad", None)]
        self.fixture.prepare()
        self.refused(self.fixture.run(), "unsafe-archive-path")

    def test_publisher_dev_alias_not_a_consumer_lock_edge(self):
        self.fixture.metadata["parent"]["devDependencies"] = {"publisher-test": "npm:uninstalled@^1.0.0"}
        self.fixture.prepare()
        report = self.fixture.run()
        self.assertEqual(report["status"], "passed", report["errors"])
        self.assertEqual(report["counts"]["lock_nodes"], 3)
        self.assertEqual(report["counts"]["alias_nodes"], 1)
        parent = next(record for record in report["packages"] if record["name"] == "parent")
        self.assertEqual(parent["publisher_development_aliases"], [{"kind": "devDependencies", "name": "publisher-test", "spec": "npm:uninstalled@^1.0.0"}])

    def embedded_fixture(self):
        text = (REPOSITORY / "LICENSE").read_bytes()
        self.fixture.notices["native"] = False
        self.fixture.extra["native"] = [("package/README.md", text, None)]
        self.fixture.prepare()
        data = self.fixture.files[gate.artifact_url("native", "1.0.0")]
        return {("native", "1.0.0"): {"artifact_sha256": gate.sha256(data),
                                         "path": "package/README.md", "sha256": gate.sha256(text)}}

    def test_exact_embedded_notice_keeps_entire_text(self):
        mapping = self.embedded_fixture()
        with patch.object(gate, "EMBEDDED_NOTICES", mapping):
            report = self.fixture.run()
        self.assertEqual(report["status"], "passed", report["errors"])
        record = next(r for r in report["packages"] if r["name"] == "native")
        self.assertEqual(record["notice_files"]["package/README.md"]["content_utf8"], (REPOSITORY / "LICENSE").read_text())

    def test_embedded_changed_artifact_refused(self):
        mapping = self.embedded_fixture()
        self.fixture.extra["native"].append(("package/changed", b"changed", None))
        self.fixture.prepare()
        with patch.object(gate, "EMBEDDED_NOTICES", mapping):
            self.refused(self.fixture.run(), "embedded-notice-artifact-mismatch")

    def test_embedded_changed_text_hash_refused_even_with_new_artifact_pin(self):
        mapping = self.embedded_fixture()
        self.fixture.extra["native"] = [("package/README.md", b"altered complete grant", None)]
        self.fixture.prepare()
        mapping[("native", "1.0.0")]["artifact_sha256"] = gate.sha256(self.fixture.files[gate.artifact_url("native", "1.0.0")])
        with patch.object(gate, "EMBEDDED_NOTICES", mapping):
            self.refused(self.fixture.run(), "embedded-notice-text-mismatch")

    def test_embedded_label_only_refused(self):
        mapping = self.embedded_fixture()
        self.fixture.extra["native"] = [("package/README.md", b"## License\nMIT\n", None)]
        self.fixture.prepare()
        mapping[("native", "1.0.0")]["artifact_sha256"] = gate.sha256(self.fixture.files[gate.artifact_url("native", "1.0.0")])
        with patch.object(gate, "EMBEDDED_NOTICES", mapping):
            self.refused(self.fixture.run(), "embedded-notice-text-mismatch")

    def test_embedded_mapping_cannot_authorize_another_package(self):
        mapping = self.embedded_fixture()
        mapping[("another", "1.0.0")] = mapping.pop(("native", "1.0.0"))
        with patch.object(gate, "EMBEDDED_NOTICES", mapping):
            self.refused(self.fixture.run(), "missing-artifact-license-notice")

    def test_embedded_mapping_cannot_authorize_another_version(self):
        mapping = self.embedded_fixture()
        mapping[("native", "1.0.1")] = mapping.pop(("native", "1.0.0"))
        with patch.object(gate, "EMBEDDED_NOTICES", mapping):
            self.refused(self.fixture.run(), "missing-artifact-license-notice")

    def test_metadata_size_bound(self):
        with patch.object(gate, "MAX_METADATA", 10):
            self.refused(self.fixture.run(), "missing-or-oversized-metadata")

    def test_expanded_size_bound(self):
        with patch.object(gate, "MAX_EXPANDED", 100):
            self.refused(self.fixture.run(), "expanded-archive-too-large")

    def test_duplicate_json_field(self):
        with self.assertRaisesRegex(gate.GateError, "duplicate-json-key"):
            gate.json_document(b'{"license":"MIT","license":"LGPL-3.0"}')

    def test_missing_graph_node(self):
        self.fixture.lock["packages"].pop("node_modules/native")
        self.fixture.save()
        self.refused(self.fixture.run(), "graph-count-changed-review-required")

    def test_manifest_lock_mismatch(self):
        self.fixture.manifest["devDependencies"]["native"] = "2.0.0"
        self.fixture.save()
        self.refused(self.fixture.run(), "manifest-lock-mismatch")

    def test_empty_manifest_dependency_map_matches_absent_lock_map(self):
        self.fixture.manifest["dependencies"] = {}
        self.fixture.save()
        self.assertEqual(self.fixture.run()["status"], "passed")

    def test_nonexact_root_pin(self):
        self.fixture.manifest["devDependencies"]["native"] = "^1.0.0"
        self.fixture.prepare()
        self.refused(self.fixture.run(), "direct-pin-missing-or-nonexact")

    def test_wrong_resolved_url(self):
        self.fixture.lock["packages"]["node_modules/native"]["resolved"] = "https://registry.npmjs.org/another/-/another-1.0.0.tgz"
        self.fixture.save()
        self.refused(self.fixture.run(), "artifact-url-identity-mismatch")

    def test_bad_integrity_format(self):
        self.fixture.lock["packages"]["node_modules/native"]["integrity"] = "sha512-invalid"
        self.fixture.save()
        self.refused(self.fixture.run(), "invalid-integrity")

    def test_root_license_bytes_changed(self):
        (self.fixture.root / "LICENSE").write_text("MIT label alone is not the reviewed license file")
        self.refused(self.fixture.run(), "root-license-changed-review-required")

    def test_policy_exception_not_silently_applied(self):
        (self.fixture.root / "deny.toml").write_text('[licenses]\nallow=["MIT"]\nexceptions=[{name="native",allow=["LGPL-3.0"]}]\n')
        self.refused(self.fixture.run(), "policy-exceptions-require-separate-review")

    def test_input_mutation_during_fetch(self):
        def mutate(url, budget):
            (self.fixture.root / "LICENSE").write_text("changed during evidence collection")
            return self.fixture.files[url]
        self.refused(self.fixture.run(mutate), "source-input-changed")

    def test_unreachable_origin_refused_without_network(self):
        with self.assertRaisesRegex(gate.GateError, "unapproved-artifact-origin"):
            gate.fetch("http://registry.npmjs.org/a", None)
        with self.assertRaisesRegex(gate.GateError, "unapproved-artifact-origin"):
            gate.fetch("https://example.invalid/a", None)

    def test_redirect_refused_before_following(self):
        with self.assertRaisesRegex(gate.GateError, "artifact-redirect-refused"):
            gate.NoRedirect().redirect_request(None, None, 302, None, {}, "https://example.invalid/a")

    def test_deadline_refusal(self):
        budget = gate.Budget(self.fixture.cache, seconds=-1)
        with self.assertRaisesRegex(gate.GateError, "evidence-deadline-exceeded"):
            budget.check()

    def test_disk_reserve_refusal(self):
        budget = gate.Budget(self.fixture.cache)
        with patch.object(gate.shutil, "disk_usage", return_value=type("Usage", (), {"free": gate.DISK_FLOOR - 1})()):
            with self.assertRaisesRegex(gate.GateError, "evidence-disk-reserve"):
                budget.check()

    def test_cumulative_byte_bound(self):
        budget = gate.Budget(self.fixture.cache)
        with self.assertRaisesRegex(gate.GateError, "evidence-total-byte-cap"):
            budget.account(gate.MAX_TOTAL + 1)

    def test_runtime_lock_graph_full_scope_static(self):
        manifest = gate.json_document((REPOSITORY / "packages/client/package.json").read_bytes())
        lock = gate.json_document((REPOSITORY / "packages/client/package-lock.json").read_bytes())
        nodes, aliases = gate.graph(manifest, lock)
        self.assertEqual((len(nodes), len(aliases)), (324, 7))
        self.assertIn("node_modules/node-liblzma", nodes)
        self.assertTrue(nodes["node_modules/node-liblzma"]["flags"]["optional"])
        self.assertEqual({e["owner"] for e in aliases}, {"node_modules/@mastra/core"})


if __name__ == "__main__":
    unittest.main()
