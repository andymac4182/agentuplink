#!/usr/bin/env python3
"""Bounded offline filesystem/RESP/mocked orchestration controls; no services."""
import ast
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import pwd
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value
b = load("backup_controls", ROOT / "scripts/fly_cluster_backup.py")
r = load("physical_recovery_controls", ROOT / "scripts/fly_cluster_recovery_rehearsal.py")
PREFIX = b"tunnel-catalog:aur-123456789abc:"
KEY = PREFIX + b"credential:synthetic"
GUARD = lambda: None


class PhysicalTreeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="aof-pure-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source, self.custody = self.root / "source", self.root / "custody"
        self.source.mkdir(mode=0o700); self.custody.mkdir(mode=0o700)
        self.aof = self.source / "appendonlydir"; self.aof.mkdir(mode=0o700)
        self.write(self.aof / "appendonly.aof.1.base.rdb", b"synthetic-physical-base\xff\0")
        self.write(self.aof / "appendonly.aof.1.incr.aof", b"synthetic-physical-incremental\0")
        self.manifest = self.aof / "appendonly.aof.manifest"
        self.lines = b"file appendonly.aof.1.base.rdb seq 1 type b\nfile appendonly.aof.1.incr.aof seq 1 type i\n"
        self.write(self.manifest, self.lines)
        self.uid, self.gid = os.geteuid(), os.getegid()

    def write(self, path, data):
        path.write_bytes(data); path.chmod(0o600)

    def capture(self):
        return b.capture_tree(self.source, self.custody, self.uid, self.gid, GUARD)

    def test_complete_capture_and_restore_independent_bytes(self):
        receipt = self.capture()
        target = self.root / "restored"
        self.assertEqual(b.restore_tree(self.custody, target, receipt["manifest_sha256"], GUARD), receipt)
        for path in self.source.rglob("*"):
            if path.is_file():
                relative = path.relative_to(self.source)
                self.assertEqual(path.read_bytes(), (target / relative).read_bytes())
                self.assertNotEqual(path.stat().st_ino, (target / relative).stat().st_ino)
                self.assertNotEqual(path.stat().st_ino, (self.custody / "tree" / relative).stat().st_ino)
        self.assertEqual(receipt["files"], 3)
        self.assertEqual(receipt["entries"], 4)
        self.assertNotIn(b"synthetic-physical-base", b.canonical(receipt))

    def test_missing_manifest(self):
        self.manifest.unlink()
        with self.assertRaisesRegex(b.BackupRefused, "manifest_missing"): self.capture()

    def test_missing_referenced_member(self):
        (self.aof / "appendonly.aof.1.base.rdb").unlink()
        with self.assertRaisesRegex(b.BackupRefused, "member_missing"): self.capture()

    def test_unreferenced_or_temporary_member(self):
        self.write(self.aof / "temp-rewrite.aof", b"unexplained")
        with self.assertRaisesRegex(b.BackupRefused, "unexplained_member"): self.capture()

    def test_manifest_paths_history_duplicates_and_sequence_refuse(self):
        cases = [b"file ../escape seq 1 type i\n", self.lines + self.lines.splitlines(keepends=True)[0],
                 self.lines.replace(b"type b", b"type h"), self.lines.replace(b"seq 1", b"seq 2", 1),
                 self.lines.replace(b"type b", b"type i"), self.lines[:-1],
                 b"".join(reversed(self.lines.splitlines(keepends=True))) ]
        for data in cases:
            with self.subTest(data=data):
                self.write(self.manifest, data)
                with self.assertRaises(b.BackupRefused): self.capture()
        self.assertEqual(list(self.custody.iterdir()), [])

    def test_symlink_and_hardlink_never_followed(self):
        path = self.aof / "appendonly.aof.1.base.rdb"
        path.unlink(); path.symlink_to(self.manifest)
        with self.assertRaises(b.BackupRefused): self.capture()
        path.unlink(); os.link(self.manifest, path)
        with self.assertRaises(b.BackupRefused): self.capture()

    def test_wrong_uid_and_world_writable_refused(self):
        with self.assertRaises(b.BackupRefused): b.capture_tree(self.source, self.custody, self.uid + 1, self.gid, GUARD)
        self.manifest.chmod(0o666)
        with self.assertRaises(b.BackupRefused): self.capture()

    def test_tree_count_depth_and_byte_budget(self):
        for name, limit in (("MAX_ENTRIES", 2), ("MAX_TREE", 16), ("MAX_DEPTH", 0)):
            with self.subTest(name=name), mock.patch.object(b, name, limit), self.assertRaises(b.BackupRefused): self.capture()

    def test_restore_collision_including_dangling_link(self):
        result = self.capture()
        target = self.root / "restored"; target.symlink_to(self.root / "absent")
        with self.assertRaisesRegex(b.BackupRefused, "destination_exists"):
            b.restore_tree(self.custody, target, result["manifest_sha256"], GUARD)

    def test_custody_corruption_never_restored(self):
        result = self.capture()
        self.write(self.custody / "tree/appendonlydir/appendonly.aof.1.incr.aof", b"tampered")
        target = self.root / "restored"
        with self.assertRaises(b.BackupRefused): b.restore_tree(self.custody, target, result["manifest_sha256"], GUARD)
        self.assertFalse(target.exists())

    def test_manifest_digest_pinned_before_copy(self):
        self.capture()
        with self.assertRaisesRegex(b.BackupRefused, "custody_hash"):
            b.restore_tree(self.custody, self.root / "restored", "0" * 64, GUARD)

    def test_source_change_during_copy_fails_without_publishing_manifest(self):
        original = b.copy_tree
        def changed(source, dest, manifest, guard):
            original(source, dest, manifest, guard)
            self.write(self.aof / "appendonly.aof.1.incr.aof", b"changed")
        with mock.patch.object(b, "copy_tree", side_effect=changed), self.assertRaisesRegex(b.BackupRefused, "source_changed"):
            self.capture()
        self.assertFalse((self.custody / "manifest.json").exists())

    def test_partial_copy_not_overwritten_or_retried(self):
        with mock.patch.object(b, "copy_tree", side_effect=OSError("synthetic")) as copy_call:
            with self.assertRaises(OSError): self.capture()
            copy_call.assert_called_once()
        self.assertFalse((self.custody / "manifest.json").exists())

    def test_reserve_and_deadline_guards(self):
        sample = mock.Mock(free=b.DISK_FLOOR + 10)
        with mock.patch.object(b.shutil, "disk_usage", return_value=sample):
            b.physical_guard(self.root, reserve=10)
            with self.assertRaises(b.BackupRefused): b.physical_guard(self.root, reserve=11)
            with mock.patch.object(b.time, "monotonic", return_value=5), self.assertRaises(b.BackupRefused):
                b.physical_guard(self.root, deadline=5)


class EnumerationAndIdentityReviewTests(unittest.TestCase):
    def test_directory_enumeration_stops_at_declared_bound(self):
        with tempfile.TemporaryDirectory(prefix="aof-enumeration-pure-") as tmp:
            root = Path(tmp); root.chmod(0o700)
            sample = root / "sample"; sample.write_bytes(b"x"); sample.chmod(0o600)
            directory_stat, file_stat = root.stat(), sample.stat()
            for kind, maximum in (("capture", 1), ("verify", 3), ("tree", b.MAX_ENTRIES + 1)):
                seen = []
                def paths(_):
                    for index in range(1000):
                        seen.append(index)
                        name = ["manifest.json", "tree"][index] if kind == "verify" and index < 2 else "entry-" + str(index)
                        yield root / name
                @contextlib.contextmanager
                def scan(path):
                    yield (SimpleNamespace(name=p.name) for p in paths(path))
                def lstat(path):
                    return directory_stat if path == root else file_stat
                with self.subTest(kind=kind), mock.patch.object(Path, "iterdir", paths), \
                     mock.patch.object(b.os, "scandir", scan), mock.patch.object(Path, "lstat", lstat), \
                     mock.patch.object(b, "read_regular", return_value=b"x"):
                    with self.assertRaises(b.BackupRefused):
                        if kind == "capture": b.capture_tree(root, root, directory_stat.st_uid, directory_stat.st_gid, GUARD)
                        elif kind == "verify": b.verify_tree(root, "0" * 64, GUARD)
                        else: b.tree_manifest(root, directory_stat.st_uid, directory_stat.st_gid, GUARD)
                    self.assertEqual(len(seen), maximum)

    def test_custody_first_unexpected_name_refused_before_next_entry(self):
        calls = []
        def entries():
            calls.append(1); yield SimpleNamespace(name="unexpected")
            raise AssertionError("read beyond first unexpected custody member")
        with mock.patch.object(b.os, "scandir", return_value=contextlib.nullcontext(entries())):
            with self.assertRaisesRegex(b.BackupRefused, "custody_entries"):
                b.verify_tree(Path("/synthetic"), "0" * 64, GUARD)
        self.assertEqual(calls, [1])

    def identity_program(self):
        tree = ast.parse((ROOT / "scripts/fly_cluster_recovery_rehearsal.py").read_bytes())
        matches = [node.value for node in ast.walk(tree) if isinstance(node, ast.Constant)
                   and isinstance(node.value, str) and node.value.startswith("import json,os,pwd; p=pwd.getpwnam('redis')")]
        self.assertEqual(len(matches), 1)
        return matches[0]

    def test_redis_identity_requires_actual_effective_gid(self):
        with mock.patch.object(pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=999, pw_gid=999)), \
             mock.patch.object(os, "geteuid", return_value=999), mock.patch.object(os, "getegid", return_value=888), \
             contextlib.redirect_stdout(io.StringIO()), self.assertRaises(AssertionError):
            exec(self.identity_program(), {})

    def test_redis_identity_emits_both_observed_ids(self):
        with mock.patch.object(pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=999, pw_gid=999)), \
             mock.patch.object(os, "geteuid", return_value=999), mock.patch.object(os, "getegid", return_value=999) as gid, \
             contextlib.redirect_stdout(io.StringIO()) as output:
            exec(self.identity_program(), {})
        self.assertGreater(gid.call_count, 0)
        self.assertEqual(json.loads(output.getvalue()), [999, 999])


class BinaryRespTests(unittest.TestCase):
    def test_binary_bulk_roundtrip_not_text_conversion(self):
        payload = b"\xff\x00\r\n\xfe"
        encoded = b"$5\r\n" + payload + b"\r\n"
        self.assertEqual(b.read_binary_resp(io.BytesIO(encoded)), payload)
        self.assertIn(payload, b.encode_command([b"RESTORE", KEY, b"0", payload, b"REPLACE"]))
        self.assertNotIn(b"b'", b.encode_command([payload]))

    def test_partial_legal_reads_are_joined(self):
        class Short(io.BytesIO):
            def read(self, count=-1): return super().read(min(count, 1))
        self.assertEqual(b.read_binary_resp(Short(b"$3\r\nabc\r\n")), b"abc")

    def test_bad_resp_bounds_and_closed_errors(self):
        for data in (b"$65537\r\n", b"$-2\r\n", b"*513\r\n", b"*-1\r\n", b"$1\r\nxXX", b":-0\r\n",
                     b"*1\r\n" * 6 + b"+OK\r\n", b"+" + b"x" * 512, b"-ERR secret-value\r\n", b"$2\r\nx"):
            with self.subTest(data=data[:20]), self.assertRaises(b.BackupRefused) as raised:
                b.read_binary_resp(io.BytesIO(data))
            self.assertNotIn("secret-value", str(raised.exception))

    def test_command_requires_bytes_and_bounds_before_join(self):
        with self.assertRaises(b.BackupRefused): b.encode_command(["DUMP", KEY])
        with mock.patch.object(b, "MAX_REQUEST", 5), self.assertRaises(b.BackupRefused): b.encode_command([b"DUMP", KEY])

    def connection(self, response, timer=lambda _: contextlib.nullcontext()):
        sock = mock.Mock()
        return b.BinaryConnection(sock, io.BytesIO(response), 99, GUARD, timer), sock

    def test_transaction_checks_every_reply(self):
        conn, sock = self.connection(b"+OK\r\n+QUEUED\r\n*1\r\n+OK\r\n")
        conn.transaction([[b"RESTORE", KEY, b"0", b"bytes", b"REPLACE"]])
        sock.sendall.assert_called_once()
        self.assertEqual(sock.sendall.call_args.args[0].count(b"*1\r\n$4\r\nEXEC"), 1)

    def test_partial_error_and_lost_exec_never_redispatched(self):
        for response in (b"+OK\r\n+QUEUED\r\n", b"+OK\r\n+QUEUED\r\n*1\r\n-ERR private\r\n",
                         b"+OK\r\n+QUEUED\r\n*0\r\n", b"+OK\r\n+QUEUED\r\n*1\r\n+NO\r\n"):
            conn, sock = self.connection(response)
            with self.subTest(response=response), self.assertRaises(b.BackupRefused):
                conn.transaction([[b"RESTORE", KEY, b"0", b"bytes", b"REPLACE"]])
            sock.sendall.assert_called_once()

    def test_expired_absolute_command_budget_sends_nothing(self):
        @contextlib.contextmanager
        def expired(_):
            raise b.BackupRefused("snapshot_command_deadline")
            yield
        conn, sock = self.connection(b"+OK\r\n", expired)
        with self.assertRaises(b.BackupRefused): conn.command(b"PING")
        sock.sendall.assert_not_called()

    def test_occupied_timer_refused_without_cancellation(self):
        with mock.patch.object(b.signal, "getitimer", return_value=(2, 0)), mock.patch.object(b.signal, "setitimer") as timer:
            with self.assertRaises(b.BackupRefused), b.command_timer(100): pass
            timer.assert_not_called()

    def test_timer_is_absolute_and_restored_on_failure(self):
        with mock.patch.object(b.signal, "getitimer", return_value=(0, 0)), \
             mock.patch.object(b.signal, "getsignal", return_value="previous"), \
             mock.patch.object(b.signal, "signal") as handler, mock.patch.object(b.signal, "setitimer") as timer, \
             mock.patch.object(b.time, "monotonic", return_value=10):
            with self.assertRaises(RuntimeError), b.command_timer(11): raise RuntimeError("synthetic")
            self.assertEqual(timer.call_args_list, [mock.call(b.signal.ITIMER_REAL, 1), mock.call(b.signal.ITIMER_REAL, 0)])
            handler.assert_called_with(b.signal.SIGALRM, "previous")


class SnapshotTests(unittest.TestCase):
    def test_durable_predicate_retains_epochs_generation_and_auth_membership(self):
        for suffix in (b"credential:x", b"grant:x", b"coord:epoch:x", b"meta:catalog_generation", b"membership:tenant:user"):
            self.assertTrue(b.durable(PREFIX, PREFIX + suffix))
        for suffix in (b"coord:owner:x", b"coord:ticket:x", b"coord:tickets:x", b"membership:operator:x", b"meta:active_incarnation", b"meta:redis_run_id"):
            self.assertFalse(b.durable(PREFIX, PREFIX + suffix))
        with self.assertRaises(b.BackupRefused): b.durable(PREFIX, b"foreign:credential")

    def test_snapshot_custody_private_hash_and_binary_bytes(self):
        snapshot = b.Snapshot(PREFIX, {KEY: b"\xff\0private"})
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "latest.json"; digest = snapshot.retain(path)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(b.Snapshot.load(path, digest, PREFIX, GUARD).records, snapshot.records)
            with self.assertRaises(b.BackupRefused): b.Snapshot.load(path, "0" * 64, PREFIX, GUARD)
            with self.assertRaises(FileExistsError): snapshot.retain(path)
        self.assertNotIn("private", str(snapshot.summary()))

    def test_capture_requires_persistent_ttl_and_same_keyset(self):
        for ttl in (0, 12, -2, True, -1.0):
            connection = mock.Mock(); connection.command.side_effect = [[b"0", [KEY]], b"bytes", ttl]
            with self.subTest(ttl=ttl), self.assertRaises(b.BackupRefused): b.capture_snapshot(connection, PREFIX, GUARD)
        connection = mock.Mock(); connection.command.side_effect = [[b"0", [KEY]], b"bytes", -1, [b"0", []]]
        with self.assertRaisesRegex(b.BackupRefused, "key_set_changed"): b.capture_snapshot(connection, PREFIX, GUARD)

    def test_capture_binary_payload_and_exact_summary(self):
        connection = mock.Mock(); connection.command.side_effect = [[b"0", [KEY]], b"\xff\0", -1, [b"0", [KEY]]]
        value = b.capture_snapshot(connection, PREFIX, GUARD)
        self.assertEqual(value.records, {KEY: b"\xff\0"})
        self.assertEqual(value.summary()["bytes"], len(KEY) + 2 + 8)

    def test_scan_repeat_wrong_scope_and_key_bound(self):
        for replies in ([[b"1", []], [b"1", []]], [[b"0", [b"foreign"]]], [[b"0", [PREFIX + b"x" * 512]]]):
            connection = mock.Mock(); connection.command.side_effect = replies
            with self.assertRaises(b.BackupRefused): b.scan(connection, PREFIX, GUARD)

    def test_restore_excludes_runtime_authority_and_never_retries(self):
        excluded = [PREFIX + x for x in (b"coord:owner:old", b"membership:operator:old", b"meta:active_incarnation", b"meta:redis_run_id")]
        extra = PREFIX + b"grant:obsolete"
        connection = mock.Mock(); connection.command.side_effect = [[b"0", [KEY, extra, *excluded]], [b"0", [KEY, *excluded]], -1]
        value = b.Snapshot(PREFIX, {KEY: b"\0binary"}); value.restore(connection, GUARD)
        commands = connection.transaction.call_args.args[0]
        self.assertEqual(commands, [[b"DEL", extra], [b"RESTORE", KEY, b"0", b"\0binary", b"REPLACE"]])
        self.assertTrue(all(key not in command for key in excluded for command in commands))
        connection = mock.Mock(); connection.command.return_value = [b"0", [KEY]]; connection.transaction.side_effect = TimeoutError()
        with self.assertRaises(TimeoutError): value.restore(connection, GUARD)
        connection.transaction.assert_called_once(); self.assertEqual(connection.command.call_count, 1)


class OrchestrationTests(unittest.TestCase):
    def test_physical_scenario_keeps_original_stage_order(self):
        obj = object.__new__(r.PhysicalBackupRehearsal); obj.run = mock.Mock()
        calls = []
        for name in ("prepare", "bootstrap", "all_routes", "setup_revocations", "stop_and_restart", "explicit_recovery", "restart_serving"):
            setattr(obj, name, lambda name=name: calls.append((name, obj.run.stage)))
        obj.start_client = lambda index: calls.append(("client-" + str(index), obj.run.stage))
        obj.execute()
        self.assertEqual(calls, [("prepare", "prepare"), ("bootstrap", "bootstrap_physical_capture"),
            ("client-0", "baseline_routes"), ("client-1", "baseline_routes"), ("client-2", "baseline_routes"),
            ("all_routes", "baseline_routes"), ("setup_revocations", "baseline_revocations"),
            ("stop_and_restart", "physical_older_backup_restore"), ("explicit_recovery", "explicit_recovery"),
            ("restart_serving", "recovered_adoption")])

    def test_helper_exact_mounts_no_network_and_fixed_user(self):
        obj = object.__new__(r.PhysicalBackupRehearsal)
        obj.backup_helper_sha256 = r.digest(Path(r.backup.__file__).read_bytes())
        obj.backup_volume = "owned-backup"; obj.states = {"redis": "owned-current"}
        obj.redis_uid, obj.redis_gid = 999, 999
        receipt = {"schema_version": 1, "tree_sha256": "a" * 64, "manifest_sha256": "b" * 64,
                   "files": 3, "entries": 4, "bytes": 20, "uid": 999, "gid": 999}
        obj.physical_snapshot = receipt
        obj.docker = mock.Mock(); obj.docker.images = {"authority": "sha256:" + "c" * 64}
        obj.docker.one_shot.return_value = r.canonical(receipt); obj.event = mock.Mock()
        for operation, mounts in (("capture", [("owned-backup", "/backup", True), ("owned-current", "/source", False)]),
                                  ("verify", [("owned-backup", "/backup", False)]),
                                  ("restore", [("owned-backup", "/backup", False), ("owned-current", "/target", True)])):
            with self.subTest(operation=operation):
                self.assertEqual(obj.physical_helper(operation), receipt)
                kwargs = obj.docker.one_shot.call_args.kwargs
                self.assertEqual(kwargs["mounts"], mounts)
                self.assertIs(kwargs["network"], False)
                self.assertEqual(kwargs["user"], "0:0")
                self.assertEqual(kwargs["entrypoint"], "/usr/bin/python3")

    def test_missing_or_changed_aof_config_refused(self):
        obj = object.__new__(r.PhysicalBackupRehearsal); obj.redis = mock.Mock()
        profile = {"dir": "/data/redis", "appendfilename": "appendonly.aof", "appenddirname": "appendonlydir",
                   "appendonly": "yes", "appendfsync": "always", "no-appendfsync-on-rewrite": "no",
                   "aof-load-truncated": "no", "auto-aof-rewrite-min-size": "67108864"}
        obj.redis.command.return_value = [x for pair in profile.items() for x in pair]
        self.assertEqual(obj.aof_profile(), profile)
        for field, value in (("appenddirname", "elsewhere"), ("appendfilename", "other"), ("auto-aof-rewrite-min-size", "1024")):
            changed = {**profile, field: value}; obj.redis.command.return_value = [x for pair in changed.items() for x in pair]
            with self.subTest(field=field), self.assertRaises(r.Refused): obj.aof_profile()
        obj.redis.command.return_value = obj.redis.command.return_value[:-2]
        with self.assertRaises(r.Refused): obj.aof_profile()

    def test_resume_ambiguity_preserves_intent_and_cannot_continue(self):
        run = mock.Mock(cleanup=False); docker = r.PhysicalBackupDocker(run, "owner", {})
        item = {"id": "a" * 64, "role": "redis"}; docker.containers = [item]; docker.pause_intents[item["id"]] = item
        docker.inspect = mock.Mock(side_effect=[{"State": {"Running": True, "Paused": True}}, RuntimeError("inspection")])
        with self.assertRaises(RuntimeError): docker.set_paused(item, False)
        self.assertEqual(docker.pause_intents, {item["id"]: item})
        run.assert_called_once()

    def test_noop_hook_exists_before_authority_start(self):
        tree = ast.parse((ROOT / "scripts/fly_cluster_rehearsal.py").read_bytes())
        cls = next(x for x in tree.body if isinstance(x, ast.ClassDef) and x.name == "Rehearsal")
        method = next(x for x in cls.body if isinstance(x, ast.FunctionDef) and x.name == "bootstrap")
        statements = [ast.unparse(x) for x in method.body]
        hook = statements.index("self.after_catalog_provisioned()")
        self.assertIn("self.authority_command(['initialize-membership'", statements[hook + 1])
        self.assertIsNone(r.base.Rehearsal.after_catalog_provisioned(object()))

    def test_missing_serving_writer_fence_refuses_capture(self):
        obj = object.__new__(r.PhysicalBackupRehearsal); obj.relays = ["running"]; obj.clients = []
        with self.assertRaisesRegex(r.Refused, "serving_writers"): obj.after_catalog_provisioned()

    def test_pause_intent_survives_unknown_dispatch(self):
        run = mock.Mock(cleanup=False); docker = r.PhysicalBackupDocker(run, "owner", {})
        item = {"id": "a" * 64, "role": "redis"}; docker.containers = [item]
        docker.inspect = mock.Mock(return_value={"State": {"Running": True, "Paused": False}})
        run.side_effect = TimeoutError()
        with self.assertRaises(TimeoutError): docker.set_paused(item, True)
        self.assertEqual(docker.pause_intents, {item["id"]: item})
        self.assertEqual(run.call_count, 1)

    def test_pause_refuses_foreign_role_before_dispatch(self):
        run = mock.Mock(cleanup=False); docker = r.PhysicalBackupDocker(run, "owner", {})
        item = {"id": "a" * 64, "role": "authority"}; docker.containers = [item]
        with self.assertRaises(r.Refused): docker.set_paused(item, True)
        run.assert_not_called()

    def test_cleanup_unpause_uses_same_budget_then_stop(self):
        run = mock.Mock(cleanup=True); run.deadline = 321
        docker = r.PhysicalBackupDocker(run, "owner", {}); item = {"id": "a" * 64, "role": "redis"}
        docker.pause_intents[item["id"]] = item
        docker.inspect = mock.Mock(side_effect=[{"State": {"Paused": True}}, {"State": {"Paused": False}}])
        with mock.patch.object(r.base.Docker, "call", return_value=b"stopped") as parent:
            self.assertEqual(docker.call(["container", "stop", "--time=5", item["id"]]), b"stopped")
            parent.assert_called_once()
        run.assert_called_once_with(r.base.DOCKER + ["container", "unpause", item["id"]], timeout=10)
        self.assertEqual(run.deadline, 321)
        self.assertEqual(docker.pause_intents, {})

    def test_latest_capture_brackets_run_generation_digest_and_revocations(self):
        for changed in ("run", "generation", "digest", "flags"):
            obj = object.__new__(r.PhysicalBackupRehearsal)
            obj.inventory = {"redis_namespace": "aur-123456789abc"}
            obj.run_identity = mock.Mock(side_effect=["a", "b" if changed == "run" else "a"])
            obj.bindings = mock.Mock(side_effect=[["old", "a", "2"], ["old", "a", "3" if changed == "generation" else "2"]])
            obj.observe = mock.Mock(side_effect=[{"catalog_digest": "x"}, {"catalog_digest": "y" if changed == "digest" else "x"}])
            obj.flag_record_hashes = mock.Mock(side_effect=[["one", "two"], ["changed", "two"] if changed == "flags" else ["one", "two"]])
            obj.binary_session = lambda: contextlib.nullcontext((mock.Mock(), GUARD))
            with mock.patch.object(r.backup, "capture_snapshot", return_value=mock.Mock()) as capture:
                with self.subTest(changed=changed), self.assertRaisesRegex(r.Refused, "latest_capture_changed"): obj.capture_latest()
                capture.return_value.retain.assert_not_called()

    def test_failed_reconciliation_cannot_observe_sign_or_continue(self):
        obj = object.__new__(r.PhysicalBackupRehearsal)
        obj.inventory = {"redis_namespace": "aur-123456789abc"}; obj.latest_path = Path("unused")
        obj.latest_file_sha, obj.latest_summary = "a" * 64, {"records": 1}
        obj.run = mock.Mock(); obj.bindings = mock.Mock(return_value=["old", "run", "1"])
        obj.binary_session = lambda: contextlib.nullcontext((mock.Mock(), GUARD))
        obj.observe, obj.sign = mock.Mock(), mock.Mock()
        snapshot = mock.Mock(); snapshot.summary.return_value = obj.latest_summary; snapshot.restore.side_effect = TimeoutError()
        with mock.patch.object(r.backup.Snapshot, "load", return_value=snapshot):
            with self.assertRaises(TimeoutError): obj.reconcile_latest()
        snapshot.restore.assert_called_once(); obj.observe.assert_not_called(); obj.sign.assert_not_called()


if __name__ == "__main__":
    unittest.main()
