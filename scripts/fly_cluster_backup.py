#!/usr/bin/env python3
"""Private synthetic backup mechanics, NOT production reconciliation tooling.

No Redis/server/package code is executed by importing this module. The image
helper entrypoint has fixed mount paths and emits only bounded hash summaries.
DUMP bytes and physical files remain private; errors use closed codes only.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import stat
import sys
import time

MAX_TREE = 8 * 1024**2
MAX_ENTRIES = 64
MAX_DEPTH = 4
MAX_MANIFEST = 128 * 1024
MAX_KEYS = 256
MAX_KEY = 512
MAX_RECORD = 64 * 1024
MAX_SNAPSHOT = 4 * 1024**2
MAX_REQUEST = MAX_SNAPSHOT + MAX_KEYS * MAX_KEY + 128 * 1024
MAX_PRIVATE_SNAPSHOT = 8 * 1024**2
DISK_FLOOR = 1536 * 1024**2
EXTRA_RESERVE = 40 * 1024**2


class BackupRefused(Exception):
    """Closed, payload-free fixture refusal."""


def require(value, code):
    if not value:
        raise BackupRefused(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def json_value(data, maximum):
    require(isinstance(data, bytes) and len(data) <= maximum, "backup_json_bound")
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "backup_json_duplicate")
            value[key] = item
        return value
    def nonfinite(_):
        raise BackupRefused("backup_json_number")
    try:
        return json.loads(data, object_pairs_hook=pairs, parse_constant=nonfinite, parse_float=nonfinite)
    except (ValueError, UnicodeError, RecursionError):
        raise BackupRefused("backup_json_shape") from None


def u64(value):
    return type(value) is int and 0 <= value < 2**64


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def private_file(path, data, maximum):
    require(len(data) <= maximum, "backup_private_file_bound")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as target:
        target.write(data)
        target.flush()
        os.fsync(target.fileno())
    sync_directory(Path(path).parent)


def read_regular(path, maximum, guard):
    guard()
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= maximum,
            "backup_file_shape")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as source:
        opened = os.fstat(source.fileno())
        require((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino), "backup_file_changed")
        data = source.read(maximum + 1)
        after = os.fstat(source.fileno())
    require(len(data) <= maximum and (before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
            (after.st_size, after.st_mtime_ns, after.st_ctime_ns), "backup_file_changed")
    require(path.lstat() == after, "backup_file_changed")
    guard()
    return data


def physical_guard(root, *, deadline=None, reserve=0):
    require(deadline is None or time.monotonic() < deadline, "backup_copy_deadline")
    require(shutil.disk_usage(root).free >= DISK_FLOOR + reserve, "backup_copy_disk_floor")


def bounded_children(directory, maximum, guard, code, allowed=None):
    # Path.iterdir uses eager os.listdir on Python3.12. scandir is incremental;
    # consume no more than the bounded result plus its first refusing entry.
    require(type(maximum) is int and 0 <= maximum <= MAX_ENTRIES, "backup_enumeration_bound")
    children = []
    with os.scandir(directory) as scan:
        while True:
            guard()
            try:
                entry = next(scan)
            except StopIteration:
                break
            require(len(children) < maximum and (allowed is None or entry.name in allowed), code)
            children.append(directory / entry.name)
    return sorted(children)


def tree_manifest(root, uid, gid, guard):
    require(type(uid) is int and uid >= 0 and type(gid) is int and gid >= 0, "backup_owner_shape")
    root_stat = root.lstat()
    require(stat.S_ISDIR(root_stat.st_mode) and not stat.S_ISLNK(root_stat.st_mode)
            and root_stat.st_uid == uid and root_stat.st_gid == gid
            and not stat.S_IMODE(root_stat.st_mode) & 0o7022, "backup_root_shape")
    entries, identities, size = {}, {}, 0
    def walk(directory, depth):
        nonlocal size
        guard()
        require(depth <= MAX_DEPTH, "backup_tree_depth")
        for item in bounded_children(directory, MAX_ENTRIES - len(entries), guard, "backup_tree_count"):
            guard()
            relative = item.relative_to(root).as_posix()
            require(len(relative.encode()) <= MAX_KEY and all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", p)
                    for p in Path(relative).parts), "backup_tree_path")
            require(len(entries) < MAX_ENTRIES, "backup_tree_count")
            info = item.lstat()
            require(info.st_dev == root_stat.st_dev, "backup_tree_mount_escape")
            require(info.st_uid == uid and info.st_gid == gid and not stat.S_IMODE(info.st_mode) & 0o7022,
                    "backup_tree_owner_mode")
            record = {"uid": info.st_uid, "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode)}
            identities[relative] = [info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns]
            if stat.S_ISDIR(info.st_mode):
                record["type"] = "directory"
                entries[relative] = record
                walk(item, depth + 1)
            else:
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "backup_tree_not_regular")
                require(info.st_size <= MAX_TREE and size + info.st_size <= MAX_TREE, "backup_tree_bytes")
                data = read_regular(item, MAX_TREE - size, guard)
                size += len(data)
                record.update(type="file", size=len(data), sha256=sha(data), mtime_ns=info.st_mtime_ns)
                entries[relative] = record
    walk(root, 0)
    require(entries and size > 0, "backup_tree_empty")
    return {"schema_version": 1, "uid": uid, "gid": gid, "entries": entries, "bytes": size}, identities


def validate_aof(root, manifest, guard):
    entries = manifest["entries"]
    # This fixture binds Redis8.4's observed defaults, never an arbitrary path.
    name = "appendonlydir/appendonly.aof.manifest"
    require(name in entries and entries[name]["type"] == "file", "backup_aof_manifest_missing")
    raw = read_regular(root / name, MAX_MANIFEST, guard)
    require(raw and raw.endswith(b"\n"), "backup_aof_manifest_shape")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError:
        raise BackupRefused("backup_aof_manifest_encoding") from None
    require(1 <= len(lines) <= MAX_ENTRIES - 2, "backup_aof_manifest_count")
    referenced, sequences, base_count, incrementals = set(), set(), 0, []
    for line in lines:
        match = re.fullmatch(r"file (appendonly\.aof\.([1-9][0-9]{0,19})\.(base\.(?:rdb|aof)|incr\.aof)) seq ([1-9][0-9]{0,19}) type ([bi])", line)
        require(match is not None, "backup_aof_manifest_row")
        filename, file_seq, suffix, sequence, kind = match.groups()
        require(file_seq == sequence and int(sequence) < 2**64, "backup_aof_manifest_sequence")
        require((kind == "b") == suffix.startswith("base."), "backup_aof_manifest_type")
        key = "appendonlydir/" + filename
        require(key not in referenced and (kind, sequence) not in sequences, "backup_aof_manifest_duplicate")
        require(key in entries and entries[key]["type"] == "file", "backup_aof_member_missing")
        referenced.add(key)
        sequences.add((kind, sequence))
        require(kind != "b" or not incrementals, "backup_aof_manifest_order")
        base_count += kind == "b"
        if kind == "i":
            incrementals.append(int(sequence))
    require(base_count <= 1 and incrementals and incrementals == sorted(set(incrementals)), "backup_aof_manifest_order")
    expected = referenced | {"appendonlydir", name}
    # A complete incidental RDB is retained but never substituted for AOF.
    if "dump.rdb" in entries:
        require(entries["dump.rdb"]["type"] == "file", "backup_rdb_shape")
        expected.add("dump.rdb")
    require(set(entries) == expected and entries["appendonlydir"]["type"] == "directory", "backup_aof_unexplained_member")


def copy_tree(source, destination, manifest, guard):
    # Publication is create-only. A partial copy is failed, never automatically
    # deleted/retried or presented as a usable backup.
    require(not os.path.lexists(destination), "backup_destination_exists")
    guard()
    destination.mkdir(mode=0o700)
    os.chown(destination, manifest["uid"], manifest["gid"])
    for relative, record in sorted(manifest["entries"].items(), key=lambda pair: (len(Path(pair[0]).parts), pair[0])):
        guard()
        src, dst = source / relative, destination / relative
        if record["type"] == "directory":
            dst.mkdir(mode=0o700)
            os.chown(dst, record["uid"], record["gid"])
            os.chmod(dst, record["mode"])
            continue
        data = read_regular(src, MAX_TREE, guard)
        require(len(data) == record["size"] and sha(data) == record["sha256"], "backup_source_copy_changed")
        private_file(dst, data, MAX_TREE)
        os.chown(dst, record["uid"], record["gid"])
        os.chmod(dst, record["mode"])
        os.utime(dst, ns=(record["mtime_ns"], record["mtime_ns"]), follow_symlinks=False)
        fd = os.open(dst, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        require((src.stat().st_dev, src.stat().st_ino) != (dst.stat().st_dev, dst.stat().st_ino), "backup_copy_alias")
    for path in sorted([destination, *[destination / p for p, value in manifest["entries"].items() if value["type"] == "directory"]],
                       key=lambda p: len(p.parts), reverse=True):
        sync_directory(path)
    sync_directory(destination.parent)
    copied, _ = tree_manifest(destination, manifest["uid"], manifest["gid"], guard)
    require(copied == manifest, "backup_copy_manifest_differs")


def summary(manifest, manifest_bytes):
    return {"schema_version": 1, "tree_sha256": sha(canonical(manifest)), "manifest_sha256": sha(manifest_bytes),
            "files": sum(row["type"] == "file" for row in manifest["entries"].values()),
            "entries": len(manifest["entries"]), "bytes": manifest["bytes"], "uid": manifest["uid"], "gid": manifest["gid"]}


def capture_tree(source, backup, uid, gid, guard):
    bounded_children(backup, 0, guard, "backup_custody_not_empty")
    before, identities = tree_manifest(source, uid, gid, guard)
    validate_aof(source, before, guard)
    copy_tree(source, backup / "tree", before, guard)
    after, after_identities = tree_manifest(source, uid, gid, guard)
    require(before == after and identities == after_identities, "backup_source_changed_during_copy")
    data = canonical(before)
    private_file(backup / "manifest.json", data, MAX_MANIFEST)
    os.chmod(backup / "manifest.json", 0o400)
    sync_directory(backup)
    return verify_tree(backup, sha(data), guard)


def verify_tree(backup, expected_hash, guard):
    require(isinstance(expected_hash, str) and re.fullmatch(r"[0-9a-f]{64}", expected_hash), "backup_custody_hash_shape")
    require([p.name for p in bounded_children(backup, 2, guard, "backup_custody_entries", {"manifest.json", "tree"})]
            == ["manifest.json", "tree"], "backup_custody_entries")
    data = read_regular(backup / "manifest.json", MAX_MANIFEST, guard)
    require(sha(data) == expected_hash, "backup_custody_hash")
    manifest = json_value(data, MAX_MANIFEST)
    require(isinstance(manifest, dict) and set(manifest) == {"schema_version", "uid", "gid", "entries", "bytes"}
            and type(manifest["schema_version"]) is int and manifest["schema_version"] == 1, "backup_manifest_schema")
    actual, _ = tree_manifest(backup / "tree", manifest["uid"], manifest["gid"], guard)
    require(canonical(actual) == data, "backup_custody_content")
    validate_aof(backup / "tree", actual, guard)
    return summary(actual, data)


def restore_tree(backup, destination, expected_hash, guard):
    result = verify_tree(backup, expected_hash, guard)
    manifest = json_value(read_regular(backup / "manifest.json", MAX_MANIFEST, guard), MAX_MANIFEST)
    copy_tree(backup / "tree", destination, manifest, guard)
    require(verify_tree(backup, expected_hash, guard) == result, "backup_custody_changed_during_restore")
    return result


def helper_main():
    request = json_value(sys.stdin.buffer.read(16 * 1024 + 1), 16 * 1024)
    require(isinstance(request, dict) and request.get("operation") in {"capture", "verify", "restore"}, "backup_helper_operation")
    operation = request["operation"]
    required = {"operation", "uid", "gid"} if operation == "capture" else {"operation", "manifest_sha256"}
    require(set(request) == required, "backup_helper_fields")
    deadline = time.monotonic() + 25
    disk = Path("/backup") if operation == "capture" else Path("/target") if operation == "restore" else Path("/backup")
    guard = lambda: physical_guard(disk, deadline=deadline)
    if operation == "capture":
        require(type(request["uid"]) is int and request["uid"] > 0 and type(request["gid"]) is int and request["gid"] >= 0,
                "backup_redis_identity")
        physical_guard(disk, deadline=deadline, reserve=MAX_TREE + MAX_MANIFEST)
        result = capture_tree(Path("/source/redis"), Path("/backup"), request["uid"], request["gid"], guard)
    elif operation == "restore":
        physical_guard(disk, deadline=deadline, reserve=MAX_TREE + MAX_MANIFEST)
        result = restore_tree(Path("/backup"), Path("/target/redis"), request["manifest_sha256"], guard)
    else:
        result = verify_tree(Path("/backup"), request["manifest_sha256"], guard)
    sys.stdout.buffer.write(canonical(result))


class ReplyBudget:
    def __init__(self):
        self.bytes, self.values = 256 * 1024, 1024

    def take(self, count):
        require(type(count) is int and 0 <= count <= self.bytes, "snapshot_reply_bytes")
        self.bytes -= count


def exact_read(stream, size):
    parts = []
    while size:
        part = stream.read(size)
        require(part and len(part) <= size, "snapshot_reply_truncated")
        parts.append(part)
        size -= len(part)
    return b"".join(parts)


def read_binary_resp(stream, budget=None, depth=0):
    budget = ReplyBudget() if budget is None else budget
    require(depth <= 4 and budget.values > 0, "snapshot_reply_structure")
    budget.values -= 1
    line = bytearray()
    for _ in range(512):
        budget.take(1)
        line.extend(exact_read(stream, 1))
        if line.endswith(b"\r\n"):
            break
    else:
        raise BackupRefused("snapshot_reply_line")
    kind, raw = bytes(line[:1]), bytes(line[1:-2])
    if kind == b"+":
        return raw
    if kind == b"-":
        raise BackupRefused("snapshot_redis_refused")
    require(kind in {b":", b"$", b"*"} and re.fullmatch(rb"0|-?[1-9][0-9]{0,19}", raw), "snapshot_reply_integer")
    value = int(raw)
    require(-(2**63) <= value < 2**63, "snapshot_reply_integer")
    if kind == b":":
        return value
    if kind == b"$":
        if value == -1:
            return None
        require(0 <= value <= MAX_RECORD, "snapshot_reply_bulk")
        budget.take(value + 2)
        data = exact_read(stream, value + 2)
        require(data[-2:] == b"\r\n", "snapshot_reply_terminator")
        return data[:-2]
    require(0 <= value <= 512 and value <= budget.values, "snapshot_reply_array")
    return [read_binary_resp(stream, budget, depth + 1) for _ in range(value)]


def encode_command(parts):
    require(isinstance(parts, (list, tuple)) and parts and all(type(p) is bytes for p in parts), "snapshot_command_bytes")
    length = len(str(len(parts))) + 3 + sum(len(p) + len(str(len(p))) + 5 for p in parts)
    require(length <= MAX_REQUEST, "snapshot_request_bound")
    return b"*" + str(len(parts)).encode() + b"\r\n" + b"".join(b"$" + str(len(p)).encode() + b"\r\n" + p + b"\r\n" for p in parts)


@contextmanager
def command_timer(deadline):
    require(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), "snapshot_existing_timer")
    seconds = min(2.0, deadline - time.monotonic())
    require(seconds > 0, "snapshot_operation_deadline")
    old = signal.getsignal(signal.SIGALRM)
    def expired(_signal, _frame):
        raise BackupRefused("snapshot_command_deadline")
    signal.signal(signal.SIGALRM, expired)
    try:
        signal.setitimer(signal.ITIMER_REAL, seconds)
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


class BinaryConnection:
    def __init__(self, sock, stream, deadline, guard, timer=command_timer):
        self.sock, self.stream, self.deadline, self.guard, self.timer = sock, stream, deadline, guard, timer

    def command(self, *parts):
        request = encode_command(parts)
        self.guard()
        with self.timer(self.deadline):
            self.sock.sendall(request)
            result = read_binary_resp(self.stream)
        self.guard()
        return result

    def transaction(self, commands):
        encoded = [encode_command([b"MULTI"])]
        total = len(encoded[0])
        for command in commands:
            part = encode_command(command)
            total += len(part)
            require(total <= MAX_REQUEST - 32, "snapshot_request_bound")
            encoded.append(part)
        encoded.append(encode_command([b"EXEC"]))
        self.guard()
        with self.timer(self.deadline):
            self.sock.sendall(b"".join(encoded))
            require(read_binary_resp(self.stream) == b"OK", "snapshot_multi_response")
            for _ in commands:
                require(read_binary_resp(self.stream) == b"QUEUED", "snapshot_queued_response")
            replies = read_binary_resp(self.stream)
            require(isinstance(replies, list) and len(replies) == len(commands), "snapshot_exec_count")
            for command, reply in zip(commands, replies):
                require((command[0] == b"DEL" and type(reply) is int and reply in (0, 1))
                        or (command[0] == b"RESTORE" and reply == b"OK"), "snapshot_exec_response")
        self.guard()


def validate_prefix(prefix):
    require(type(prefix) is bytes and re.fullmatch(rb"tunnel-catalog:aur-[0-9a-f]{12}:", prefix), "snapshot_owned_prefix")


def durable(prefix, key):
    require(type(key) is bytes and key.startswith(prefix) and len(prefix) < len(key) <= MAX_KEY, "snapshot_key_scope")
    suffix = key[len(prefix):]
    return not (suffix.startswith((b"coord:owner:", b"coord:ticket:", b"coord:tickets:", b"membership:operator:"))
                or suffix in (b"meta:active_incarnation", b"meta:redis_run_id"))


def scan(connection, prefix, guard):
    validate_prefix(prefix)
    cursor, seen, keys = b"0", set(), set()
    for _ in range(128):
        guard()
        reply = connection.command(b"SCAN", cursor, b"MATCH", prefix + b"*", b"COUNT", b"256")
        require(isinstance(reply, list) and len(reply) == 2 and type(reply[0]) is bytes
                and re.fullmatch(rb"0|[1-9][0-9]{0,19}", reply[0]) and int(reply[0]) < 2**64
                and isinstance(reply[1], list), "snapshot_scan_shape")
        for key in reply[1]:
            durable(prefix, key)  # reject escaped/oversized keys even when excluded
            keys.add(key)
            require(len(keys) <= MAX_KEYS, "snapshot_key_count")
        cursor = reply[0]
        if cursor == b"0":
            return keys
        require(cursor not in seen, "snapshot_scan_cycle")
        seen.add(cursor)
    raise BackupRefused("snapshot_scan_bound")


class Snapshot:
    def __init__(self, prefix, records):
        validate_prefix(prefix)
        require(isinstance(records, dict) and 0 < len(records) <= MAX_KEYS, "snapshot_record_count")
        total = 0
        for key, payload in records.items():
            require(durable(prefix, key) and type(payload) is bytes and payload, "snapshot_record_shape")
            size = len(key) + len(payload) + 8
            require(size <= MAX_RECORD, "snapshot_record_bound")
            total += size
            require(total <= MAX_SNAPSHOT, "snapshot_total_bound")
        self.prefix, self.records, self.bytes = prefix, dict(records), total

    def summary(self):
        digest = hashlib.sha256(b"agentuplink-synthetic-snapshot-v1\0")
        for key, payload in sorted(self.records.items()):
            digest.update(len(key).to_bytes(8, "big")); digest.update(key)
            digest.update((-1).to_bytes(8, "big", signed=True))
            digest.update(len(payload).to_bytes(8, "big")); digest.update(payload)
        return {"records": len(self.records), "bytes": self.bytes, "sha256": digest.hexdigest()}

    def retain(self, path):
        data = canonical({"schema_version": 1, "prefix": self.prefix.decode("ascii"),
                          "records": [[base64.b64encode(k).decode(), base64.b64encode(v).decode()] for k, v in sorted(self.records.items())]})
        private_file(path, data, MAX_PRIVATE_SNAPSHOT)
        return sha(data)

    @classmethod
    def load(cls, path, expected_hash, prefix, guard):
        raw = read_regular(path, MAX_PRIVATE_SNAPSHOT, guard)
        require(sha(raw) == expected_hash, "snapshot_custody_hash")
        value = json_value(raw, MAX_PRIVATE_SNAPSHOT)
        require(isinstance(value, dict) and set(value) == {"schema_version", "prefix", "records"}
                and type(value["schema_version"]) is int and value["schema_version"] == 1
                and value["prefix"] == prefix.decode("ascii") and isinstance(value["records"], list)
                and 0 < len(value["records"]) <= MAX_KEYS, "snapshot_custody_schema")
        records = {}
        for pair in value["records"]:
            require(isinstance(pair, list) and len(pair) == 2 and all(type(x) is str for x in pair), "snapshot_custody_record")
            try:
                key, payload = (base64.b64decode(x, validate=True) for x in pair)
            except ValueError:
                raise BackupRefused("snapshot_custody_encoding") from None
            require(key not in records, "snapshot_custody_duplicate")
            records[key] = payload
        return cls(prefix, records)

    def restore(self, connection, guard):
        current = scan(connection, self.prefix, guard)
        commands = [[b"DEL", key] for key in sorted(current) if durable(self.prefix, key) and key not in self.records]
        commands += [[b"RESTORE", key, b"0", payload, b"REPLACE"] for key, payload in sorted(self.records.items())]
        connection.transaction(commands)  # unknown/partial outcome is terminal; no retry
        after = scan(connection, self.prefix, guard)
        require({k for k in after if durable(self.prefix, k)} == set(self.records), "snapshot_restored_key_set")
        for key in sorted(self.records):
            ttl = connection.command(b"PTTL", key)
            require(type(ttl) is int and ttl == -1, "snapshot_restored_ttl")


def capture_snapshot(connection, prefix, guard):
    keys = scan(connection, prefix, guard)
    records = {}
    for key in sorted(keys):
        if not durable(prefix, key):
            continue
        guard()
        payload = connection.command(b"DUMP", key)
        require(type(payload) is bytes and payload, "snapshot_dump_shape")
        ttl = connection.command(b"PTTL", key)
        require(type(ttl) is int and ttl == -1, "snapshot_persistent_keys_only")
        records[key] = payload
        Snapshot(prefix, records)  # enforce aggregate before retaining further records
    require({k for k in scan(connection, prefix, guard) if durable(prefix, k)} == set(records), "snapshot_capture_key_set_changed")
    return Snapshot(prefix, records)


if __name__ == "__main__":
    try:
        helper_main()
    except BackupRefused as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
    except Exception:
        print("backup_helper_failed", file=sys.stderr)
        raise SystemExit(1)
