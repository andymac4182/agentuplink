"""M6-C241: notice loss and source substitution must stop distribution."""
import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest

import container_notices as notices


class ContainerNoticesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.binary = self.root / "fixture-binary"
        self.binary.write_bytes(b"synthetic executable")
        (self.root / "LICENSE").write_text("Project MIT notice\n")
        (self.root / "Cargo.lock").write_text(
            'version = 4\n[[package]]\nname="app"\nversion="1.0.0"\n'
            '[[package]]\nname="dep"\nversion="2.0.0"\nsource="registry+fixture"\nchecksum="abc"\n'
            '[[package]]\nname="test-only"\nversion="3.0.0"\nsource="registry+fixture"\nchecksum="def"\n')
        self.packages = []
        for name, version, source in [("app", "1.0.0", None), ("dep", "2.0.0", "registry+fixture"), ("test-only", "3.0.0", "registry+fixture")]:
            directory = self.root / "sources" / name
            directory.mkdir(parents=True)
            (directory / "Cargo.toml").write_text(f'[package]\nname="{name}"\nversion="{version}"\n')
            self.packages.append({"id": name, "name": name, "version": version, "source": source,
                                  "license": "MIT", "license_file": None,
                                  "manifest_path": str(directory / "Cargo.toml")})
        self.dep = self.root / "sources/dep"
        (self.dep / "LICENSE").write_bytes(b"Dependency exact notice\r\n")
        nested = self.dep / "bundled/library"
        nested.mkdir(parents=True)
        (nested / "COPYING").write_text("Bundled native library notice\n")
        self.metadata = {"packages": self.packages, "workspace_members": ["app"], "resolve": {"nodes": [
            {"id": "app", "deps": [
                {"pkg": "dep", "dep_kinds": [{"kind": None}]},
                {"pkg": "test-only", "dep_kinds": [{"kind": "dev"}]},
            ]}, {"id": "dep", "deps": []}, {"id": "test-only", "deps": []},
        ]}}
        self.output = self.root / "bundle"

    def stage(self):
        return notices.stage(self.root, self.metadata, "app", self.binary, self.output, "fixture-target")

    def supplements(self):
        directory = self.root / "deploy/notices/rust"
        directory.mkdir(parents=True)
        data = b"Pinned upstream MIT notice\n"
        (directory / "dep-LICENSE").write_bytes(data)
        (self.dep / ".cargo_vcs_info.json").write_text(json.dumps({"git": {"sha1": "1" * 40}}))
        (directory / "supplements.json").write_text(json.dumps({"schema": 1, "packages": [{
            "name": "dep", "version": "2.0.0", "source": "registry+fixture", "license": "MIT",
            "crate_checksum": "abc", "vcs_commit": "1" * 40,
            "notices": [{"file": "dep-LICENSE", "sha256": notices.digest(data), "url": "https://example.invalid/pinned/LICENSE"}],
        }]}))
        (self.dep / "LICENSE").unlink()
        (self.dep / "bundled/library/COPYING").unlink()
        return directory

    def test_complete_normal_and_build_closure_preserves_exact_nested_bytes(self):
        self.metadata["resolve"]["nodes"][0]["deps"][0]["dep_kinds"] = [{"kind": "build"}]
        manifest = self.stage()
        self.assertEqual([p["name"] for p in manifest["packages"]], ["app", "dep"])
        self.assertEqual(manifest["packages"][0]["notices"], ["LICENSE"])
        self.assertEqual((self.output / "crates/dep-2.0.0/LICENSE").read_bytes(), b"Dependency exact notice\r\n")
        self.assertIn("crates/dep-2.0.0/bundled/library/COPYING", manifest["files"])
        notices.verify(self.output, self.binary)

    def test_missing_notice_refused_without_partial_output(self):
        (self.dep / "LICENSE").unlink()
        (self.dep / "bundled/library/COPYING").unlink()
        with self.assertRaises((ValueError, FileNotFoundError)):
            self.stage()
        self.assertFalse(self.output.exists())
        self.assertFalse(list(self.root.glob(".notices-*")))

    def test_removed_notice_extra_file_wrong_binary_and_changed_bytes_fail(self):
        self.stage()
        path = self.output / "crates/dep-2.0.0/LICENSE"
        original = path.read_bytes()
        path.unlink()
        with self.assertRaises(ValueError): notices.verify(self.output)
        path.write_bytes(original + b"changed")
        with self.assertRaises(ValueError): notices.verify(self.output)
        path.write_bytes(original)
        extra = self.output / "undeclared"
        extra.write_bytes(b"extra")
        with self.assertRaises(ValueError): notices.verify(self.output)
        extra.unlink()
        self.binary.write_bytes(b"different executable")
        with self.assertRaises(ValueError): notices.verify(self.output, self.binary)

    def test_metadata_must_match_lockfile_and_resolve_every_node(self):
        self.packages[1]["version"] = "2.1.0"
        with self.assertRaises(ValueError): self.stage()
        self.packages[1]["version"] = "2.0.0"
        self.metadata["resolve"]["nodes"].pop(1)
        with self.assertRaises(ValueError): self.stage()

    def test_declared_missing_and_traversal_license_paths_fail(self):
        for filename in ("MISSING", "../app/Cargo.toml", str(self.root / "LICENSE")):
            with self.subTest(filename=filename):
                self.packages[1]["license_file"] = filename
                with self.assertRaises((ValueError, FileNotFoundError)): self.stage()

    @unittest.skipUnless(hasattr(Path, "symlink_to"), "requires symlink support")
    def test_notice_and_directory_symlinks_are_refused(self):
        path = self.dep / "LICENSE"
        path.unlink()
        try:
            path.symlink_to(self.root / "LICENSE")
        except OSError:
            self.skipTest("host cannot create symlinks")
        with self.assertRaises(ValueError): self.stage()
        path.unlink()
        path.write_text("Dependency notice")
        link = self.dep / "linked"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError): self.stage()

    def test_empty_and_oversized_notice_refused(self):
        path = self.dep / "LICENSE"
        for payload in (b"", b"x" * (notices.MAX_NOTICE_BYTES + 1)):
            path.write_bytes(payload)
            with self.assertRaises(ValueError): self.stage()

    def test_exact_pinned_source_supplement_is_accepted(self):
        self.supplements()
        manifest = self.stage()
        self.assertEqual(manifest["packages"][1]["notices"], ["crates/dep-2.0.0/dep-LICENSE"])
        self.assertEqual((self.output / "crates/dep-2.0.0/dep-LICENSE").read_bytes(), b"Pinned upstream MIT notice\n")

    def test_supplement_commit_checksum_and_content_substitutions_are_refused(self):
        directory = self.supplements()
        original = json.loads((directory / "supplements.json").read_text())
        for field, value in (("vcs_commit", "2" * 40), ("crate_checksum", "different"), ("license", "Apache-2.0")):
            data = copy.deepcopy(original)
            data["packages"][0][field] = value
            (directory / "supplements.json").write_text(json.dumps(data))
            with self.subTest(field=field), self.assertRaises(ValueError): self.stage()
        (directory / "supplements.json").write_text(json.dumps(original))
        (directory / "dep-LICENSE").write_text("unreviewed text")
        with self.assertRaises(ValueError): self.stage()

    def test_output_is_create_only_and_empty_binary_is_refused(self):
        self.binary.write_bytes(b"")
        with self.assertRaises(ValueError): self.stage()
        self.binary.write_bytes(b"binary")
        self.stage()
        with self.assertRaises(ValueError): self.stage()


class RedisNoticeTests(unittest.TestCase):
    def setUp(self):
        self.repository = Path(__file__).resolve().parents[1]
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bundle = self.root / "notices"
        shutil.copytree(self.repository / "deploy/fly/redis/notices", self.bundle)
        self.project_license = self.repository / "LICENSE"
        self.dockerfile = self.repository / "deploy/fly/redis/Dockerfile"

    def check(self):
        return notices.verify_redis(self.bundle, self.project_license, self.dockerfile)

    def test_real_source_bundle_matches_exact_inventory_and_image_pin(self):
        result = self.check()
        self.assertEqual(len(result["files"]), 10)
        self.assertEqual(result["source_sha256"], "b947d9015622669b5bee8ec954f658b3278d42dbefae23a92d9b7704bfe143f9")

    def test_deleted_and_changed_notices_fail(self):
        target = self.bundle / "redis-8.4.0/LICENSE.txt"
        original = target.read_bytes()
        target.unlink()
        with self.assertRaises(ValueError): self.check()
        target.write_bytes(original + b"altered")
        with self.assertRaises(ValueError): self.check()

    def test_stale_project_copy_and_changed_base_refuse(self):
        project = self.root / "LICENSE"
        project.write_text("new project notice")
        with self.assertRaises(ValueError): notices.verify_redis(self.bundle, project, self.dockerfile)
        dockerfile = self.root / "Dockerfile"
        dockerfile.write_text(self.dockerfile.read_text().replace("redis:8.4.0-alpine@", "redis:other@"))
        with self.assertRaises(ValueError): notices.verify_redis(self.bundle, self.project_license, dockerfile)


if __name__ == "__main__":
    unittest.main()
