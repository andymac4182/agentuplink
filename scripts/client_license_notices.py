#!/usr/bin/env python3
"""Exact C253 MIT supplements and their two-notice companion bundle.

This verifies notice bytes and their reviewed source/artifact bindings, not a
license exception, the entire dependency distribution, or an SDK release.
No registry request, installation or package code execution occurs here.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import urllib.parse

DIRECTORY = Path("deploy/notices/npm")
MANIFEST_SHA256 = "54e8a05ec22f58ca2a029c489b10d2d8cc1a2a1946c2fdd93898c8863612258e"
MAX_FILE = 2 * 1024 * 1024
SCOPE = "companion bundle: two reviewed MIT notice supplements only; not full dependency or SDK distribution acceptance"
ENTRY_KEYS = {"path", "name", "version", "license", "integrity", "url", "artifact_sha256", "metadata_sha256",
              "registry", "source", "notice", "applicability"}
IDENTITY_KEYS = ("path", "name", "version", "license", "integrity", "url", "artifact_sha256", "metadata_sha256")


class NoticeError(ValueError):
    pass


def require(value, code):
    if not value:
        raise NoticeError(code)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def document(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "supplement-duplicate-json-key")
            result[key] = value
        return result
    def constant(_value):
        raise NoticeError("supplement-nonfinite-json")
    return json.loads(data, object_pairs_hook=pairs, parse_constant=constant)


def shape(value, keys):
    require(isinstance(value, dict) and set(value) == set(keys), "supplement-schema")


def filename(value):
    require(isinstance(value, str) and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,159}", value), "supplement-filename")
    return value


def regular(path, boundary):
    path, boundary = Path(path), Path(boundary)
    relative = path.relative_to(boundary)
    require(relative.parts and all(part not in {".", ".."} for part in relative.parts), "supplement-path")
    cursor = boundary
    require(not cursor.is_symlink(), "supplement-symlink")
    for part in relative.parts:
        cursor /= part
        require(not cursor.is_symlink(), "supplement-symlink")
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= MAX_FILE, "supplement-file-bound")
    with path.open("rb") as source:
        opened = os.fstat(source.fileno())
        require((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino), "supplement-file-changed")
        data = source.read(MAX_FILE + 1)
    after = path.lstat()
    require(len(data) == before.st_size and len(data) <= MAX_FILE
            and (after.st_dev, after.st_ino, after.st_size) == (before.st_dev, before.st_ino, before.st_size), "supplement-file-changed")
    return data


class Catalog:
    def __init__(self, root):
        self.root, self.inputs, self.texts, self.entries = Path(root), {}, {}, {}
        raw = self.read("supplements.json")
        manifest = document(raw)
        shape(manifest, {"schema", "scope", "packages"})
        require(type(manifest["schema"]) is int and manifest["schema"] == 1
                and manifest["scope"] == "Two exact MIT notice supplements; no license-policy exceptions."
                and isinstance(manifest["packages"], list) and len(manifest["packages"]) <= 2, "supplement-schema")
        require(sha256(raw) == MANIFEST_SHA256, "supplement-manifest-changed-review-required")
        self.manifest_sha256 = sha256(raw)
        for entry in manifest["packages"]:
            self.validate_entry(entry)
            require(entry["path"] not in self.entries, "supplement-duplicate-entry")
            self.entries[entry["path"]] = entry
        expected = {Path(name).name for name in self.inputs}
        actual = {path.name for path in (self.root / DIRECTORY).iterdir()}
        require(expected == actual, "supplement-source-file-set")

    def read(self, name):
        relative = DIRECTORY / filename(name)
        data = regular(self.root / relative, self.root)
        self.inputs[relative.as_posix()] = data
        return data

    def pinned_file(self, record):
        shape(record, {"file", "sha256"})
        data = self.read(record["file"])
        require(sha256(data) == record["sha256"], "supplement-source-hash")
        return data

    def validate_entry(self, entry):
        shape(entry, ENTRY_KEYS)
        require(entry["license"] == "MIT", "supplement-not-an-MIT-obligation")
        for key in ("artifact_sha256", "metadata_sha256"):
            require(isinstance(entry[key], str) and re.fullmatch(r"[0-9a-f]{64}", entry[key]), "supplement-source-hash")
        registry = entry["registry"]
        shape(registry, {"file", "sha256", "url", "git_head", "repository"})
        registry_bytes = self.pinned_file({k: registry[k] for k in ("file", "sha256")})
        published = document(registry_bytes)
        require(published.get("name") == entry["name"] and published.get("version") == entry["version"]
                and published.get("license") == "MIT" and published.get("gitHead") == registry["git_head"]
                and published.get("repository") == registry["repository"], "supplement-registry-binding")
        dist = published.get("dist", {})
        require(dist.get("integrity") == entry["integrity"] and dist.get("tarball") == entry["url"]
                and registry["url"] == f"https://registry.npmjs.org/{urllib.parse.quote(entry['name'], safe='')}/{entry['version']}", "supplement-registry-binding")
        source = entry["source"]
        shape(source, {"repository", "commit", "package_directory", "notice_path", "notice_blob_sha1"})
        require(isinstance(source["commit"], str) and re.fullmatch(r"[0-9a-f]{40}", source["commit"])
                and source["commit"] == registry["git_head"]
                and registry["repository"].get("url") == "git+https://github.com/" + source["repository"] + ".git"
                and source["notice_path"] == "LICENSE", "supplement-source-binding")
        # Directory omissions/version discrepancies are reviewed facts in the
        # pinned applicability file, not generic relaxed matching rules.
        notice = entry["notice"]
        shape(notice, {"file", "sha256", "bytes"})
        text = self.pinned_file({k: notice[k] for k in ("file", "sha256")})
        require(type(notice["bytes"]) is int and len(text) == notice["bytes"], "supplement-notice-length")
        git_blob = hashlib.sha1(b"blob " + str(len(text)).encode() + b"\0" + text).hexdigest()
        require(git_blob == source["notice_blob_sha1"], "supplement-notice-git-blob")
        text.decode("utf-8")
        review = document(self.pinned_file(entry["applicability"]))
        shape(review, {"schema", "name", "version", "repository", "commit", "package_directory", "notice_path",
                       "notice_sha256", "review_scope", "reason", "limitations", "evidence"})
        require(type(review["schema"]) is int and review["schema"] == 1
                and all(review[k] == entry[k] for k in ("name", "version"))
                and all(review[k] == source[k] for k in ("repository", "commit", "package_directory", "notice_path"))
                and review["notice_sha256"] == notice["sha256"] and isinstance(review["reason"], str) and review["reason"]
                and isinstance(review["limitations"], list) and review["limitations"]
                and isinstance(review["evidence"], dict) and review["evidence"], "supplement-applicability-binding")
        require(notice["file"] not in self.texts, "supplement-duplicate-notice")
        self.texts[notice["file"]] = text

    def bind_records(self, records):
        for path, entry in self.entries.items():
            record = records.get(path)
            require(record is not None and all(record.get(k) == entry[k] for k in IDENTITY_KEYS)
                    and record.get("artifact_license") == "MIT", "supplement-artifact-binding")
            require(record.get("notice_files") == {}, "supplement-no-longer-needed-review-required")
        return set(self.entries)

    def bundle_manifest(self, lock_bytes):
        lock = document(lock_bytes)
        for path, entry in self.entries.items():
            locked = lock.get("packages", {}).get(path, {})
            require(locked.get("name", path.removeprefix("node_modules/")) == entry["name"]
                    and all(locked.get(k) == entry[k] for k in ("version", "license", "integrity"))
                    and locked.get("resolved") == entry["url"], "supplement-lock-binding")
        return {"schema": 1, "scope": SCOPE, "supplements_sha256": self.manifest_sha256,
                "lock_sha256": sha256(lock_bytes), "packages": list(self.entries.values()),
                "files": {name: {"sha256": sha256(data), "bytes": len(data)} for name, data in self.texts.items()}}

    def verify_bundle(self, bundle, lock_bytes):
        bundle = Path(bundle)
        require(bundle.is_dir() and not bundle.is_symlink(), "supplement-bundle-directory")
        expected = self.bundle_manifest(lock_bytes)
        require({p.name for p in bundle.iterdir()} == set(self.texts) | {"manifest.json"}, "supplement-bundle-file-set")
        manifest_bytes = regular(bundle / "manifest.json", bundle)
        require(document(manifest_bytes) == expected and manifest_bytes == canonical(expected),
                "supplement-bundle-manifest")
        for name, text in self.texts.items():
            require(regular(bundle / name, bundle) == text, "supplement-bundle-text")
        return {"scope": SCOPE, "manifest_sha256": sha256(manifest_bytes), "notice_count": len(self.texts),
                "files": expected["files"], "sdk_distribution_verified": False, "full_dependency_distribution_verified": False}

    def stage_bundle(self, records, lock_bytes, output, budget):
        self.bind_records(records)
        output = Path(output)
        manifest = canonical(self.bundle_manifest(lock_bytes))
        budget.reserve_write(len(manifest) + sum(map(len, self.texts.values())), directory=output.parent)
        # Create-only, manifest last. Any partial failed output is retained;
        # absence/drift never qualifies as a verified shipping bundle.
        output.mkdir(mode=0o755)
        for name, data in {**self.texts, "manifest.json": manifest}.items():
            with (output / name).open("xb") as target:
                target.write(data)
        return self.verify_bundle(output, lock_bytes)

    def final_inputs(self):
        require({path.name for path in (self.root / DIRECTORY).iterdir()}
                == {Path(name).name for name in self.inputs}, "supplement-source-file-set-changed")
        for name, data in self.inputs.items():
            require(regular(self.root / name, self.root) == data, "supplement-source-input-changed")


def main():
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument("bundle", type=Path, help="verify an already-created two-notice companion directory")
    args.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    options = args.parse_args()
    root = options.root.resolve()
    catalog = Catalog(root)
    result = catalog.verify_bundle(options.bundle, regular(root / "packages/client/package-lock.json", root))
    catalog.final_inputs()
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
