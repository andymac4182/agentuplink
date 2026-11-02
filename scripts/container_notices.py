#!/usr/bin/env python3
"""Stage and verify notice bytes for a native Cargo binary, without choosing licenses.

The resolved normal/build dependency closure can over-include optional features
unified elsewhere in the workspace; it is not a linked-object bill of materials.
Source-omitted notice supplements are pinned to the exact locked crate checksum
and the crate's packaged VCS commit. Missing notices fail the image build.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import tomllib

PREFIXES = ("LICENSE", "LICENCE", "UNLICENSE", "COPYING", "NOTICE", "COPYRIGHT")
MAX_NOTICE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
SAFE_COMPONENT = re.compile(r"[A-Za-z0-9_.+-]+\Z")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def regular(path, boundary):
    """A notice must be a bounded regular file wholly inside its source package."""
    path, boundary = Path(path), Path(boundary)
    relative = path.relative_to(boundary)
    if not relative.parts or any(part in (".", "..") for part in relative.parts):
        raise ValueError(f"invalid notice path: {relative}")
    cursor = boundary
    if cursor.is_symlink():
        raise ValueError("source directory is a symlink")
    for part in relative.parts:
        cursor /= part
        if cursor.is_symlink():
            raise ValueError(f"notice symlink: {relative}")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_NOTICE_BYTES:
        raise ValueError(f"empty, oversized or nonregular notice: {relative}")
    data = path.read_bytes()
    if len(data) != info.st_size:
        raise ValueError("notice changed while reading")
    return data


def notice_paths(directory):
    """Keep nested bundled-library notices, not just a crate's top-level license."""
    result = set()
    for current, directories, files in os.walk(directory, followlinks=False):
        directories[:] = sorted(d for d in directories if d not in (".git", "target"))
        for name in directories:
            if (Path(current) / name).is_symlink():
                raise ValueError("symlink directory inside source package")
        for name in files:
            if name.upper().startswith(PREFIXES) or name == "UPSTREAM_PATCH.md":
                result.add(Path(current) / name)
    return result


def dependency_closure(metadata, package):
    packages = {p["id"]: p for p in metadata["packages"]}
    nodes = {p["id"]: p for p in metadata["resolve"]["nodes"]}
    if len(packages) != len(metadata["packages"]) or len(nodes) != len(metadata["resolve"]["nodes"]):
        raise ValueError("duplicate Cargo package or resolve node")
    roots = [p for p in packages.values() if p["name"] == package and p["id"] in metadata["workspace_members"]]
    if len(roots) != 1:
        raise ValueError("expected exactly one workspace binary package")
    pending, seen = [roots[0]["id"]], set()
    while pending:
        identity = pending.pop()
        if identity in seen:
            continue
        if identity not in packages or identity not in nodes:
            raise ValueError("incomplete Cargo dependency resolution")
        seen.add(identity)
        for dependency in nodes[identity]["deps"]:
            kinds = dependency["dep_kinds"]
            if not kinds or any(k["kind"] not in (None, "build", "dev") for k in kinds):
                raise ValueError("unknown Cargo dependency kind")
            if any(k["kind"] in (None, "build") for k in kinds):
                pending.append(dependency["pkg"])
    return sorted((packages[identity] for identity in seen), key=lambda p: (p["name"], p["version"], p["id"]))


def source_supplements(root, package, checksum):
    directory = root / "deploy/notices/rust"
    manifest = json.loads(regular(directory / "supplements.json", root))
    entries = [p for p in manifest["packages"] if p["name"] == package["name"] and p["version"] == package["version"]]
    if manifest["schema"] != 1 or len(entries) > 1:
        raise ValueError("invalid supplement registry")
    if not entries:
        return []
    entry = entries[0]
    vcs_path = Path(package["manifest_path"]).parent / ".cargo_vcs_info.json"
    vcs = json.loads(regular(vcs_path, vcs_path.parent))
    if (entry["source"] != package["source"] or entry["crate_checksum"] != checksum
            or entry["license"] != package["license"] or entry["vcs_commit"] != vcs["git"]["sha1"]):
        raise ValueError("notice supplement does not match locked source identity")
    result = []
    for notice in entry["notices"]:
        if not SAFE_COMPONENT.fullmatch(notice["file"]):
            raise ValueError("invalid supplement filename")
        data = regular(directory / notice["file"], directory)
        if digest(data) != notice["sha256"]:
            raise ValueError("notice supplement checksum mismatch")
        result.append((notice["file"], data, notice["url"]))
    return result


def stage(root, metadata, package, binary, output, target):
    root, binary, output = Path(root).absolute(), Path(binary), Path(output).absolute()
    if binary.is_symlink() or not binary.is_file() or binary.stat().st_size == 0:
        raise ValueError("binary must be a nonempty regular file")
    if output.exists() or output.is_symlink():
        raise ValueError("notice output already exists")
    selected = dependency_closure(metadata, package)
    lock_bytes = regular(root / "Cargo.lock", root)
    locked = tomllib.loads(lock_bytes.decode())["package"]
    manifest = {"schema": 1, "package": package, "target": target,
                "binary_sha256": digest(binary.read_bytes()), "cargo_lock_sha256": digest(lock_bytes),
                "coverage": "resolved normal/build Cargo closure; may include unlinked optional features; excludes OS packages",
                "packages": [], "files": {}}
    output.parent.mkdir(parents=True, exist_ok=True)
    total = 0
    with tempfile.TemporaryDirectory(prefix=".notices-", dir=output.parent) as scratch:
        staged = Path(scratch) / "notices"
        staged.mkdir(mode=0o755)

        def emit(name, data):
            nonlocal total
            path = Path(name)
            if path.is_absolute() or not path.parts or any(part in (".", "..") for part in path.parts):
                raise ValueError("invalid destination path")
            if name in manifest["files"]:
                raise ValueError("duplicate notice destination")
            total += len(data)
            if total > MAX_TOTAL_BYTES:
                raise ValueError("notice collection exceeds byte bound")
            destination = staged / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            destination.chmod(0o644)
            manifest["files"][name] = {"sha256": digest(data), "bytes": len(data)}

        project_license = regular(root / "LICENSE", root)
        emit("LICENSE", project_license)
        emit("Cargo.lock", lock_bytes)
        destinations = set()
        for item in selected:
            if not all(SAFE_COMPONENT.fullmatch(item[key]) for key in ("name", "version")):
                raise ValueError("invalid Cargo package name/version")
            destination = f"crates/{item['name']}-{item['version']}"
            if destination in destinations:
                raise ValueError("ambiguous package name/version from multiple sources")
            destinations.add(destination)
            matches = [p for p in locked if p["name"] == item["name"] and p["version"] == item["version"] and p.get("source") == item["source"]]
            if len(matches) != 1:
                raise ValueError("Cargo metadata package does not uniquely match lockfile")
            if not item.get("license") and not item.get("license_file"):
                raise ValueError("missing package license metadata")
            directory = Path(item["manifest_path"]).parent
            paths = notice_paths(directory)
            if item.get("license_file"):
                declared = Path(item["license_file"])
                if declared.is_absolute() or ".." in declared.parts:
                    raise ValueError("license_file escapes source package")
                paths.add(directory / declared)
            record = {key: item.get(key) for key in ("name", "version", "license", "source")}
            record.update({"crate_checksum": matches[0].get("checksum"),
                           "manifest_sha256": digest(regular(Path(item["manifest_path"]), directory)),
                           "notices": []})
            for source in sorted(paths):
                name = f"{destination}/{source.relative_to(directory).as_posix()}"
                emit(name, regular(source, directory))
                record["notices"].append(name)
            if not record["notices"]:
                if item["id"] in metadata["workspace_members"] and item["source"] is None and item["license"] == "MIT":
                    # Only this repository's actual workspace members inherit
                    # its project license; arbitrary path crates do not.
                    directory.relative_to(root)
                    record["notices"] = ["LICENSE"]
                else:
                    for name, data, url in source_supplements(root, item, matches[0].get("checksum")):
                        path = f"{destination}/{name}"
                        emit(path, data)
                        record["notices"].append(path)
                        record.setdefault("supplement_sources", []).append(url)
            if not record["notices"]:
                raise ValueError(f"no notice bytes for {item['name']} {item['version']}")
            manifest["packages"].append(record)
        (staged / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        verify(staged, binary)
        staged.rename(output)
    return manifest


def verify(directory, binary=None):
    directory = Path(directory)
    manifest = json.loads(regular(directory / "manifest.json", directory))
    if manifest["schema"] != 1 or not manifest["packages"]:
        raise ValueError("invalid or empty notice manifest")
    actual = set()
    for current, directories, files in os.walk(directory, followlinks=False):
        for name in directories:
            if (Path(current) / name).is_symlink():
                raise ValueError("symlink in notice bundle")
        for name in files:
            relative = (Path(current) / name).relative_to(directory).as_posix()
            if relative != "manifest.json":
                actual.add(relative)
    if actual != set(manifest["files"]) or not {"LICENSE", "Cargo.lock"} <= actual:
        raise ValueError("notice manifest coverage mismatch")
    for name, expected in manifest["files"].items():
        data = regular(directory / name, directory)
        if {"sha256": digest(data), "bytes": len(data)} != expected:
            raise ValueError("notice bytes differ from manifest")
    if digest(regular(directory / "Cargo.lock", directory)) != manifest["cargo_lock_sha256"]:
        raise ValueError("lockfile identity mismatch")
    for package in manifest["packages"]:
        if not package["notices"] or any(name not in actual for name in package["notices"]):
            raise ValueError("package has missing notice coverage")
    if binary is not None and digest(Path(binary).read_bytes()) != manifest["binary_sha256"]:
        raise ValueError("binary identity mismatch")
    return manifest


def verify_redis(directory, project_license=None, dockerfile=None):
    """Verify the retained core-source notice bundle, not all Redis obligations."""
    directory = Path(directory)
    manifest = json.loads(regular(directory / "manifest.json", directory))
    if manifest["schema"] != 1 or not manifest["files"]:
        raise ValueError("invalid Redis notice manifest")
    expected = set(manifest["files"]) | {"manifest.json"}
    recorded = {}
    for line in regular(directory / "SHA256SUMS", directory).decode().splitlines():
        checksum, name = line.split("  ", 1)
        if name in recorded or not re.fullmatch(r"[0-9a-f]{64}", checksum):
            raise ValueError("invalid Redis checksum inventory")
        recorded[name] = checksum
    actual = set()
    for current, directories, files in os.walk(directory, followlinks=False):
        if any((Path(current) / name).is_symlink() for name in directories):
            raise ValueError("symlink in Redis notices")
        actual.update((Path(current) / name).relative_to(directory).as_posix() for name in files)
    if set(recorded) != expected or actual != expected | {"SHA256SUMS"}:
        raise ValueError("Redis notice coverage mismatch")
    for name, checksum in recorded.items():
        data = regular(directory / name, directory)
        if digest(data) != checksum:
            raise ValueError("Redis notice checksum mismatch")
        if name in manifest["files"] and manifest["files"][name] != {"sha256": checksum, "bytes": len(data)}:
            raise ValueError("Redis notice manifest mismatch")
    if not {"agentuplink-LICENSE", "redis-8.4.0/LICENSE.txt", "redis-8.4.0/REDISCONTRIBUTIONS.txt"} <= set(manifest["files"]):
        raise ValueError("Redis core or project license missing")
    if project_license is not None and Path(project_license).read_bytes() != (directory / "agentuplink-LICENSE").read_bytes():
        raise ValueError("Redis wrapper project license is stale")
    if dockerfile is not None:
        source = Path(dockerfile).read_text()
        if f"FROM {manifest['base_image']}\n" not in source or f'"$REDIS_DOWNLOAD_SHA" = {manifest["source_sha256"]}' not in source:
            raise ValueError("Redis notices do not match pinned image/source")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("stage")
    create.add_argument("--root", required=True, type=Path)
    create.add_argument("--package", required=True)
    create.add_argument("--binary", required=True, type=Path)
    create.add_argument("--output", required=True, type=Path)
    create.add_argument("--offline", action="store_true", help="require the locked metadata source graph already cached")
    check = commands.add_parser("verify")
    check.add_argument("directory", type=Path)
    check.add_argument("--binary", type=Path)
    redis = commands.add_parser("verify-redis")
    redis.add_argument("directory", type=Path)
    redis.add_argument("--project-license", type=Path)
    redis.add_argument("--dockerfile", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "stage":
            version = subprocess.check_output(["rustc", "-vV"], text=True)
            target = next(line.removeprefix("host: ") for line in version.splitlines() if line.startswith("host: "))
            metadata = json.loads(subprocess.check_output([
                "cargo", "metadata", "--manifest-path", str(args.root / "Cargo.toml"),
                "--locked", "--format-version", "1", "--filter-platform", target,
            ] + (["--offline"] if args.offline else [])))
            result = stage(args.root, metadata, args.package, args.binary, args.output, target)
        elif args.command == "verify":
            result = verify(args.directory, args.binary)
        else:
            result = verify_redis(args.directory, args.project_license, args.dockerfile)
        print(f"container-notices: {args.command} ok packages={len(result.get('packages', []))} files={len(result['files'])}")
        return 0
    except (OSError, ValueError, KeyError, TypeError, StopIteration, subprocess.CalledProcessError) as error:
        parser.exit(1, f"container-notices: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
