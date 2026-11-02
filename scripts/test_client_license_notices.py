"""Pure/temp-file C253 supplement controls; no registry/npm/native execution."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location("client_gate_notice_controls", Path(__file__).with_name("client-license-gate.py"))
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)
notices = gate.notices
REPOSITORY = Path(__file__).resolve().parents[1]


class SupplementControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="client-notice-controls-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.directory = self.root / notices.DIRECTORY
        shutil.copytree(REPOSITORY / notices.DIRECTORY, self.directory)
        self.lock = (REPOSITORY / "packages/client/package-lock.json").read_bytes()
        self.output = self.root / "companion"
        self.catalog = notices.Catalog(self.root)
        self.records = {path: {**{k: entry[k] for k in notices.IDENTITY_KEYS}, "artifact_license": "MIT", "notice_files": {}}
                        for path, entry in self.catalog.entries.items()}

    def manifest(self):
        return notices.document((self.directory / "supplements.json").read_bytes())

    def alter_manifest(self, change):
        value = self.manifest()
        change(value)
        raw = notices.canonical(value)
        (self.directory / "supplements.json").write_bytes(raw)
        return notices.sha256(raw)

    def semantic_refusal(self, change, code):
        # The master hash is deliberately replaced only in planted tests to
        # exercise the inner checks. Production has no input/CLI hash override.
        pinned = self.alter_manifest(change)
        with patch.object(notices, "MANIFEST_SHA256", pinned), self.assertRaisesRegex(ValueError, code):
            notices.Catalog(self.root)

    def stage(self):
        return self.catalog.stage_bundle(self.records, self.lock, self.output, Mock())

    def test_exact_two_notice_bundle_is_written_and_independently_verified(self):
        result = self.stage()
        self.assertEqual(result, notices.Catalog(self.root).verify_bundle(self.output, self.lock))
        self.assertEqual(result["notice_count"], 2)
        self.assertFalse(result["sdk_distribution_verified"])
        self.assertFalse(result["full_dependency_distribution_verified"])
        self.assertEqual(set(path.name for path in self.output.iterdir()), set(self.catalog.texts) | {"manifest.json"})
        for name, data in self.catalog.texts.items():
            self.assertEqual((self.output / name).read_bytes(), data)
            self.assertIn(b"Permission is hereby granted", data)
            self.assertIn(b"THE SOFTWARE IS PROVIDED", data)
        self.catalog.final_inputs()

    def test_actual_applicability_keeps_version_and_root_license_scope_discrepancies(self):
        nodable, sdk = self.manifest()["packages"]
        a = notices.document((self.directory / nodable["applicability"]["file"]).read_bytes())
        b = notices.document((self.directory / sdk["applicability"]["file"]).read_bytes())
        self.assertEqual((a["version"], a["evidence"]["metadata_comparison"]["source_version"]), ("3.0.0", "2.2.0"))
        self.assertTrue(a["evidence"]["metadata_comparison"]["exact_text_after_single_version_replacement"])
        self.assertEqual(b["evidence"]["root_package"]["license"], "ISC")
        self.assertTrue(b["evidence"]["root_package"]["private"])
        self.assertEqual(sdk["license"], "MIT")
        self.assertIn("ISC", b["reason"])
        self.assertIn("generated JS", " ".join(b["limitations"]))

    def test_missing_or_changed_reviewed_manifest_never_authorizes_new_data(self):
        self.alter_manifest(lambda value: value["packages"][0].update(version="3.0.1"))
        with self.assertRaisesRegex(ValueError, "manifest-changed-review-required"):
            notices.Catalog(self.root)
        (self.directory / "supplements.json").unlink()
        with self.assertRaises(FileNotFoundError):
            notices.Catalog(self.root)

    def test_unknown_schema_fields_and_duplicate_json_are_refused(self):
        self.semantic_refusal(lambda value: value.update(extra=True), "supplement-schema")
        with self.assertRaisesRegex(ValueError, "duplicate-json-key"):
            notices.document(b'{"schema":1,"schema":1}')
        with self.assertRaisesRegex(ValueError, "nonfinite-json"):
            notices.document(b'{"schema":NaN}')

    def test_duplicate_entry_cannot_claim_one_notice_twice(self):
        self.semantic_refusal(lambda value: value["packages"].__setitem__(1, copy.deepcopy(value["packages"][0])), "duplicate-notice|duplicate-entry")

    def test_different_license_is_not_a_supplement_exception(self):
        self.semantic_refusal(lambda value: value["packages"][0].update(license="BlueOak-1.0.0"), "not-an-MIT-obligation")

    def test_changed_exact_registry_githead_is_refused(self):
        self.semantic_refusal(lambda value: value["packages"][0]["registry"].update(git_head="0" * 40), "registry-binding")

    def test_changed_registry_response_hash_is_refused(self):
        self.semantic_refusal(lambda value: value["packages"][0]["registry"].update(sha256="0" * 64), "source-hash")

    def test_changed_repository_binding_is_refused(self):
        self.semantic_refusal(lambda value: value["packages"][0]["source"].update(repository="other/repository"), "source-binding")

    def test_changed_commit_is_refused(self):
        self.semantic_refusal(lambda value: value["packages"][0]["source"].update(commit="0" * 40), "source-binding")

    def test_changed_package_directory_is_not_silently_inferred(self):
        self.semantic_refusal(lambda value: value["packages"][0]["source"].update(package_directory="different"), "applicability-binding")

    def test_changed_notice_blob_is_refused(self):
        self.semantic_refusal(lambda value: value["packages"][0]["source"].update(notice_blob_sha1="0" * 40), "notice-git-blob")

    def test_notice_label_or_changed_complete_text_does_not_match_review(self):
        first = self.manifest()["packages"][0]["notice"]["file"]
        (self.directory / first).write_bytes(b"MIT\n")
        with self.assertRaisesRegex(ValueError, "source-hash"):
            notices.Catalog(self.root)

    def test_missing_applicability_and_changed_reason_are_refused(self):
        entry = self.manifest()["packages"][0]
        path = self.directory / entry["applicability"]["file"]
        value = notices.document(path.read_bytes())
        value["reason"] = "unreviewed substitution"
        path.write_bytes(notices.canonical(value))
        with self.assertRaisesRegex(ValueError, "source-hash"):
            notices.Catalog(self.root)
        path.unlink()
        with self.assertRaises(FileNotFoundError):
            notices.Catalog(self.root)

    def test_symlink_or_oversized_source_notice_is_refused(self):
        name = self.manifest()["packages"][0]["notice"]["file"]
        path = self.directory / name
        original = path.read_bytes()
        other = self.root / "same-bytes"
        other.write_bytes(original)
        path.unlink()
        path.symlink_to(other)
        with self.assertRaisesRegex(ValueError, "supplement-symlink"):
            notices.Catalog(self.root)
        path.unlink()
        path.write_bytes(b"x" * (notices.MAX_FILE + 1))
        with self.assertRaisesRegex(ValueError, "supplement-file-bound"):
            notices.Catalog(self.root)

    def test_unsafe_notice_filename_is_refused(self):
        self.semantic_refusal(lambda value: value["packages"][0]["notice"].update(file="../outside"), "supplement-filename")

    def test_unexpected_source_file_is_refused(self):
        (self.directory / "unreviewed").write_bytes(b"another notice")
        with self.assertRaisesRegex(ValueError, "source-file-set"):
            notices.Catalog(self.root)

    def test_every_exact_artifact_identity_field_is_bound(self):
        for field in (*notices.IDENTITY_KEYS, "artifact_license"):
            records = copy.deepcopy(self.records)
            first = next(iter(records))
            records[first][field] = "changed"
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "artifact-binding"):
                self.catalog.bind_records(records)
        records = copy.deepcopy(self.records)
        records.pop(next(iter(records)))
        with self.assertRaisesRegex(ValueError, "artifact-binding"):
            self.catalog.bind_records(records)

    def test_new_archive_notice_requires_review_and_is_not_hidden_by_old_supplement(self):
        first = next(iter(self.records))
        self.records[first]["notice_files"] = {"package/LICENSE": {"sha256": "0" * 64}}
        with self.assertRaisesRegex(ValueError, "no-longer-needed-review-required"):
            self.catalog.bind_records(self.records)

    def test_lock_path_name_version_license_integrity_and_url_are_bound(self):
        for field in ("name", "version", "license", "integrity", "resolved"):
            lock = notices.document(self.lock)
            lock["packages"][next(iter(self.records))][field] = "changed"
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "lock-binding"):
                self.catalog.bundle_manifest(notices.canonical(lock))
        lock = notices.document(self.lock)
        lock["packages"].pop(next(iter(self.records)))
        with self.assertRaisesRegex(ValueError, "lock-binding"):
            self.catalog.bundle_manifest(notices.canonical(lock))

    def test_bundle_does_not_overwrite_existing_directory_or_symlink(self):
        self.output.mkdir()
        sentinel = self.output / "keep"
        sentinel.write_bytes(b"unchanged")
        with self.assertRaises(FileExistsError):
            self.stage()
        self.assertEqual(sentinel.read_bytes(), b"unchanged")
        sentinel.unlink()
        self.output.rmdir()
        self.output.symlink_to(self.directory, target_is_directory=True)
        with self.assertRaises(FileExistsError):
            self.stage()

    def test_bundle_rejects_missing_changed_extra_notice_and_manifest(self):
        self.stage()
        name = next(iter(self.catalog.texts))
        path = self.output / name
        original = path.read_bytes()
        path.unlink()
        with self.assertRaisesRegex(ValueError, "bundle-file-set"):
            self.catalog.verify_bundle(self.output, self.lock)
        path.write_bytes(original + b"changed")
        with self.assertRaisesRegex(ValueError, "bundle-text"):
            self.catalog.verify_bundle(self.output, self.lock)
        path.write_bytes(original)
        extra = self.output / "extra"
        extra.write_bytes(b"x")
        with self.assertRaisesRegex(ValueError, "bundle-file-set"):
            self.catalog.verify_bundle(self.output, self.lock)
        extra.unlink()
        manifest = notices.document((self.output / "manifest.json").read_bytes())
        manifest["lock_sha256"] = "0" * 64
        (self.output / "manifest.json").write_bytes(notices.canonical(manifest))
        with self.assertRaisesRegex(ValueError, "bundle-manifest"):
            self.catalog.verify_bundle(self.output, self.lock)

    def test_bundle_symlink_even_to_same_notice_is_refused(self):
        self.stage()
        name = next(iter(self.catalog.texts))
        path = self.output / name
        path.unlink()
        path.symlink_to(self.directory / name)
        with self.assertRaisesRegex(ValueError, "supplement-symlink"):
            self.catalog.verify_bundle(self.output, self.lock)

    def test_bundle_manifest_canonical_types_refuse_bool_and_float_schema(self):
        self.stage()
        original = notices.document((self.output / "manifest.json").read_bytes())
        for schema in (True, 1.0):
            changed = copy.deepcopy(original)
            changed["schema"] = schema
            (self.output / "manifest.json").write_bytes(notices.canonical(changed))
            with self.subTest(schema=schema), self.assertRaisesRegex(ValueError, "bundle-manifest"):
                self.catalog.verify_bundle(self.output, self.lock)

    def test_final_source_drift_refuses_previously_verified_bundle(self):
        self.stage()
        name = next(iter(self.catalog.texts))
        (self.directory / name).write_bytes(b"changed after staging")
        with self.assertRaisesRegex(ValueError, "source-input-changed"):
            self.catalog.final_inputs()

    def test_final_source_inventory_is_checked_again(self):
        self.stage()
        (self.directory / "new-unreviewed-file").write_bytes(b"unexpected")
        with self.assertRaisesRegex(ValueError, "source-file-set-changed"):
            self.catalog.final_inputs()

    def test_companion_does_not_waive_policy_or_create_archive_notices(self):
        self.stage()
        self.assertTrue(all(record["notice_files"] == {} for record in self.records.values()))
        record = copy.deepcopy(next(iter(self.records.values())))
        self.assertEqual(gate.decide(record, {"MIT"}, supplement_verified=True), "MIT")
        with self.assertRaisesRegex(ValueError, "missing-artifact-license-notice"):
            gate.decide(record, {"MIT"})
        for license in ("BlueOak-1.0.0", "LGPL-3.0"):
            record.update(license=license, artifact_license=license)
            with self.subTest(license=license), self.assertRaisesRegex(ValueError, "disallowed-license"):
                gate.decide(record, {"MIT"}, supplement_verified=True)

    def test_budget_refusal_precedes_output_creation(self):
        budget = Mock()
        budget.reserve_write.side_effect = ValueError("evidence-disk-reserve")
        with self.assertRaisesRegex(ValueError, "evidence-disk-reserve"):
            self.catalog.stage_bundle(self.records, self.lock, self.output, budget)
        self.assertFalse(self.output.exists())

    def gate_fixture(self):
        from test_client_license_gate import Fixture
        root = self.root / "synthetic-gate"
        root.mkdir()
        fixture = Fixture(root)
        fixture.notices["native"] = False
        fixture.prepare()
        locked = fixture.lock["packages"]["node_modules/native"]
        archive = fixture.files[locked["resolved"]]
        text = (REPOSITORY / "LICENSE").read_bytes()
        entry = copy.deepcopy(next(iter(self.catalog.entries.values())))
        entry.update(path="node_modules/native", name="native", version="1.0.0", url=locked["resolved"],
                     integrity=locked["integrity"], artifact_sha256=notices.sha256(archive),
                     metadata_sha256=notices.sha256(json.dumps(fixture.metadata["native"]).encode()))
        entry["source"].update(repository="synthetic/native", commit="1" * 40, package_directory="src",
                                notice_blob_sha1=notices.hashlib.sha1(b"blob " + str(len(text)).encode() + b"\0" + text).hexdigest())
        entry["notice"] = {"file": "native-MIT.txt", "sha256": notices.sha256(text), "bytes": len(text)}
        registry = {"name": "native", "version": "1.0.0", "license": "MIT", "gitHead": "1" * 40,
                    "repository": {"type": "git", "url": "git+https://github.com/synthetic/native.git"},
                    "dist": {"integrity": locked["integrity"], "tarball": locked["resolved"]}}
        raw = notices.canonical(registry)
        entry["registry"] = {"file": "native-registry.json", "sha256": notices.sha256(raw),
                             "url": "https://registry.npmjs.org/native/1.0.0", "git_head": "1" * 40,
                             "repository": registry["repository"]}
        review = {"schema": 1, "name": "native", "version": "1.0.0", "notice_sha256": notices.sha256(text),
                  "review_scope": "synthetic control only", "reason": "Test fixture, not approval of real package terms.",
                  "limitations": ["Synthetic fixture only."], "evidence": {"fixture": True},
                  **{k: entry["source"][k] for k in ("repository", "commit", "package_directory", "notice_path")}}
        review_bytes = notices.canonical(review)
        entry["applicability"] = {"file": "native-review.json", "sha256": notices.sha256(review_bytes)}
        directory = root / notices.DIRECTORY
        for name, content in (("native-MIT.txt", text), ("native-registry.json", raw), ("native-review.json", review_bytes)):
            (directory / name).write_bytes(content)
        manifest = notices.canonical({"schema": 1, "scope": self.manifest()["scope"], "packages": [entry]})
        (directory / "supplements.json").write_bytes(manifest)
        return fixture, notices.sha256(manifest)

    def run_fixture(self, fixture, manifest_hash, bundle, corrupt=False):
        original_stage = notices.Catalog.stage_bundle
        def stage(catalog, *args):
            result = original_stage(catalog, *args)
            if corrupt:
                (bundle / next(iter(catalog.texts))).write_bytes(b"changed after initial verification")
            return result
        with patch.object(gate, "fetch", side_effect=lambda url, budget: fixture.files[url]), \
                patch.object(gate.Budget, "check"), patch.object(gate.Budget, "reserve_write"), \
                patch.object(notices, "MANIFEST_SHA256", manifest_hash), patch.object(notices.Catalog, "stage_bundle", stage):
            return gate.run(fixture.root, fixture.cache, expected_nodes=3, expected_aliases=1, notice_bundle=bundle)

    def test_gate_requires_actual_bundle_before_counting_a_valid_supplement(self):
        fixture, manifest = self.gate_fixture()
        missing = self.run_fixture(fixture, manifest, None)
        self.assertEqual(missing["status"], "failed")
        self.assertEqual(missing["counts"]["artifact_verified"], 3)
        self.assertTrue(any(error["reason"] == "supplement-bundle-required" for error in missing["errors"]))
        self.assertTrue(any(error["reason"] == "missing-artifact-license-notice" for error in missing["errors"]))
        good = self.run_fixture(fixture, manifest, self.output)
        self.assertEqual(good["status"], "passed", good["errors"])
        self.assertEqual(good["policy_exceptions"], [])
        self.assertEqual(good["counts"], {"lock_nodes": 3, "alias_nodes": 1, "artifact_verified": 3, "policy_pass": 3})
        native = next(record for record in good["packages"] if record["name"] == "native")
        self.assertEqual(native["notice_files"], {})
        self.assertEqual(native["supplemental_notice"]["origin"], "reviewed-upstream-notice-companion")
        self.assertFalse(good["supplement_bundle"]["sdk_distribution_verified"])

    def test_gate_preserves_failure_if_bundle_changes_after_initial_verification(self):
        fixture, manifest = self.gate_fixture()
        result = self.run_fixture(fixture, manifest, self.output, corrupt=True)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any(error["stage"] == "final-supplements" and error["reason"] == "supplement-bundle-text"
                            for error in result["errors"]))


if __name__ == "__main__":
    unittest.main()
