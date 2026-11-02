"""Pure/mock controls: never execute an archive binary, Cargo, Redis or a child."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import release_catalog_offline as c
import verify_release_archive as verifier


class Clock:
    def __init__(self):
        self.now = 0.0
    def __call__(self):
        return self.now
    def sleep(self, seconds):
        self.now += seconds


class Process:
    def __init__(self, clock, *, code=0, stdout=b"ok", stderr=b"", hang=False,
                 residual=False, unknown=False, prepare_error=False, close_error=False,
                 ignore_term=False, read_interrupt=False):
        self.clock, self.code = clock, code
        self.chunks = [("stdout", stdout), ("stderr", stderr)]
        self.hang, self.residual, self.unknown = hang, residual, unknown
        self.prepare_error, self.close_error = prepare_error, close_error
        self.ignore_term, self.read_interrupt = ignore_term, read_interrupt
        self.sent, self.closed, self.prepared = [], False, False
    def prepare(self):
        self.prepared = True
        if self.prepare_error:
            raise OSError("private text must not escape")
    def read(self, wait, remaining):
        self.clock.sleep(wait)
        if self.read_interrupt:
            raise KeyboardInterrupt()
        chunks, self.chunks = self.chunks, []
        return chunks
    def eof(self):
        return not self.chunks
    def poll(self):
        return None if self.hang else self.code
    def group(self):
        return "unknown" if self.unknown else "present" if self.hang or self.residual else "absent"
    def send(self, sig):
        self.sent.append(sig)
        if sig == signal.SIGKILL or not self.ignore_term:
            self.hang = self.residual = False
    def close(self):
        self.closed = True
        if self.close_error:
            raise OSError("private close failure")


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        # SIGKILL exists on the Unix execution targets, not every mock-test host.
        patch = mock.patch.object(signal, "SIGKILL", 9, create=True)
        patch.start(); self.addCleanup(patch.stop)

    def run_fake(self, **options):
        clock = Clock(); process = Process(clock, **options)
        supervisor = c.Supervisor(clock, clock.sleep, lambda *_: process)
        result = supervisor.run("fixed-phase", ["owned-binary"], Path("."), {})
        self.assertTrue(process.closed)
        return result, process, clock

    def test_actual_result_shape_with_normal_child_and_group(self):
        (record, out, err), process, _ = self.run_fake(stdout=b"answer", stderr=b"")
        self.assertEqual((record["status"], record["returncode"], out, err), ("completed", 0, b"answer", b""))
        self.assertEqual(record["stdout"], {"bytes": 6, "sha256": c.digest(b"answer")})
        self.assertEqual(record["cleanup"], {"direct_child_reaped": True, "owned_group_absent": True, "errors": []})
        self.assertEqual(process.sent, [])

    def test_nonzero_is_observed_not_automatically_accepted(self):
        (record, _, _), _, _ = self.run_fake(code=2)
        self.assertEqual(record["returncode"], 2)
        self.assertEqual(record["status"], "completed")

    def test_timeout_is_retained_after_successful_kill_and_reap(self):
        (record, _, _), process, clock = self.run_fake(hang=True, ignore_term=True)
        self.assertEqual(record["failure"], "command-timeout")
        self.assertEqual(process.sent, [signal.SIGTERM, signal.SIGKILL])
        self.assertLess(clock(), c.COMMAND_SECONDS + c.CLEANUP_SECONDS + 0.1)
        self.assertTrue(record["cleanup"]["owned_group_absent"])

    def test_normal_exit_with_residual_group_still_fails(self):
        (record, _, _), process, _ = self.run_fake(residual=True)
        self.assertEqual(record["failure"], "command-residual-group")
        self.assertTrue(record["cleanup"]["owned_group_absent"])
        self.assertEqual(process.sent, [signal.SIGTERM])

    def test_unknown_group_is_not_clean(self):
        (record, _, _), _, _ = self.run_fake(unknown=True)
        self.assertEqual(record["status"], "failed")
        self.assertFalse(record["cleanup"]["owned_group_absent"])
        self.assertIn("group-unknown", record["cleanup"]["errors"])

    def test_combined_output_bound_and_no_raw_error_text(self):
        (record, _, _), _, _ = self.run_fake(stdout=b"x" * c.OUTPUT_LIMIT, stderr=b"y")
        self.assertEqual(record["failure"], "command-output-bound")
        self.assertNotIn("xxxxx", json.dumps(record))

    def test_prepare_failure_is_cleaned_after_spawn(self):
        (record, _, _), process, _ = self.run_fake(prepare_error=True, hang=True)
        self.assertEqual(record["failure"], "command-supervision-error")
        self.assertTrue(record["cleanup"]["owned_group_absent"])
        self.assertTrue(process.sent)

    def test_interrupt_stays_failed_and_closes(self):
        (record, _, _), process, _ = self.run_fake(read_interrupt=True, hang=True)
        self.assertEqual(record["failure"], "interrupted")
        self.assertTrue(process.sent)

    def test_close_failure_cannot_replace_prior_timeout(self):
        (record, _, _), _, _ = self.run_fake(hang=True, close_error=True)
        self.assertEqual(record["failure"], "command-timeout")

    def test_stage_deadline_prevents_spawn(self):
        clock = Clock(); factory = mock.Mock()
        supervisor = c.Supervisor(clock, clock.sleep, factory)
        clock.now = c.STAGE_SECONDS
        record, _, _ = supervisor.run("fixed", [], Path("."), {})
        factory.assert_not_called()
        self.assertEqual(record["failure"], "stage-timeout")

    def test_unexpected_cleanup_exception_preserves_timeout(self):
        clock = Clock(); process = Process(clock, hang=True)
        sup = c.Supervisor(clock, clock.sleep, lambda *_: process)
        with mock.patch.object(sup, "cleanup", side_effect=OSError("private")):
            record, _, _ = sup.run("fixed", [], Path("."), {})
        self.assertEqual(record["failure"], "command-timeout")
        self.assertEqual(record["cleanup"]["errors"], ["cleanup-exception"])
        self.assertTrue(process.closed)

    def test_inspection_failure_cannot_suppress_kill_escalation(self):
        for broken in ["poll", "group"]:
            with self.subTest(broken=broken):
                clock = Clock(); process = Process(clock, hang=True, ignore_term=True)
                original = getattr(process, broken)
                def inspect():
                    if process.sent: raise OSError("synthetic inspection refusal")
                    return original()
                setattr(process, broken, inspect)
                sup = c.Supervisor(clock, clock.sleep, lambda *_: process)
                record, _, _ = sup.run("fixed", [], Path("."), {})
                self.assertEqual(record["failure"], "command-timeout")
                self.assertEqual(process.sent, [signal.SIGTERM, signal.SIGKILL])
                self.assertIn("cleanup-inspection-failed", record["cleanup"]["errors"])
                self.assertFalse(record["cleanup"]["owned_group_absent"])
                self.assertTrue(process.closed)

    def test_signal_handlers_restore_after_error(self):
        sup = c.Supervisor(); saved = {signal.SIGINT: object(), signal.SIGTERM: object()}
        with mock.patch.object(c.signal, "getsignal", side_effect=saved.get), mock.patch.object(c.signal, "signal") as install:
            with self.assertRaises(ValueError), sup.signals():
                install.call_args_list[0].args[1](signal.SIGINT, None)
                self.assertTrue(sup.interrupted)
                raise ValueError("fixture")
        self.assertEqual(install.call_args_list[-2].args, (signal.SIGINT, saved[signal.SIGINT]))
        self.assertEqual(install.call_args_list[-1].args, (signal.SIGTERM, saved[signal.SIGTERM]))


class ParsingTests(unittest.TestCase):
    def test_strict_json_refuses_duplicates_trailing_and_nonfinite(self):
        for data in [b'{"x":1,"x":2}', b'{}{}', b'{"x":NaN}', b'\xff']:
            with self.subTest(data=data), self.assertRaises(c.Refusal):
                c.strict_json(data)

    def test_exact_types_reject_boolean_and_float_schema(self):
        self.assertTrue(c.same_json({"schema": 1, "allowed": False}, {"schema": 1, "allowed": False}))
        for value in [True, 1.0, "1"]:
            self.assertFalse(c.same_json({"schema": value}, {"schema": 1}))
        self.assertFalse(c.same_json({"schema": 1, "extra": 2}, {"schema": 1}))

    def test_file_mode_type_hardlink_and_owner_controls(self):
        def info(mode=stat.S_IFREG | 0o600, links=1, uid=42):
            return SimpleNamespace(st_mode=mode, st_nlink=links, st_uid=uid)
        with mock.patch.object(c.os, "geteuid", return_value=42, create=True):
            c.validate_metadata(info(), True)
            for candidate in [info(stat.S_IFLNK | 0o600), info(links=2), info(uid=43), info(stat.S_IFREG | 0o644)]:
                with self.subTest(candidate=candidate), self.assertRaises(c.Refusal):
                    c.validate_metadata(candidate, True)

    def test_directory_enumeration_refuses_first_extra(self):
        consumed = []
        def entries():
            for i in range(1000):
                consumed.append(i)
                yield SimpleNamespace(name=str(i))
        with mock.patch.object(c.os, "scandir", return_value=contextlib.nullcontext(entries())):
            with self.assertRaises(c.Refusal):
                c.bounded_names(Path("unused"))
        self.assertEqual(len(consumed), 5)


class FileReadTests(unittest.TestCase):
    def info(self, **changes):
        values = dict(st_dev=1, st_ino=2, st_mode=stat.S_IFREG | 0o600, st_uid=42,
                      st_nlink=1, st_size=3, st_mtime_ns=4, st_ctime_ns=5)
        return SimpleNamespace(**(values | changes))

    def read(self, path_info=None, descriptor_info=None, chunks=None):
        info = self.info(); path = mock.Mock()
        path.lstat.side_effect = path_info or [info, info]
        with mock.patch.object(c.os, "open", return_value=17) as opened, mock.patch.object(c.os, "close") as closed, mock.patch.object(c.os, "fstat", side_effect=descriptor_info or [info, info]), mock.patch.object(c.os, "read", side_effect=chunks or [b"abc", b""]), mock.patch.object(c.os, "geteuid", return_value=42, create=True), mock.patch.object(c.os, "O_NOFOLLOW", 0x100000, create=True), mock.patch.object(c.os, "O_NONBLOCK", 0x200000, create=True):
            try:
                result = c.read_bound(path, 3, lambda: None, private=True)
                self.assertTrue(opened.call_args.args[1] & c.os.O_NOFOLLOW)
                self.assertTrue(opened.call_args.args[1] & c.os.O_NONBLOCK)
                return result
            finally:
                if opened.called: closed.assert_called_once_with(17)

    def test_bounded_read_binds_path_descriptor_and_bytes(self):
        record, data = self.read()
        self.assertEqual((record["sha256"], record["bytes"], data), (c.digest(b"abc"), 3, b"abc"))

    def test_replaced_path_or_descriptor_refused(self):
        info = self.info(); replaced = self.info(st_ino=99)
        for path_info, descriptor_info in [([info, replaced], None), (None, [replaced]), (None, [info, self.info(st_mtime_ns=99)])]:
            with self.subTest(path_info=path_info, descriptor_info=descriptor_info), self.assertRaises(c.Refusal):
                self.read(path_info, descriptor_info)

    def test_growth_and_short_read_refused(self):
        for chunks in [[b"abcd"], [b"ab", b""]]:
            with self.subTest(chunks=chunks), self.assertRaises(c.Refusal):
                self.read(chunks=chunks)

    def test_nonregular_file_refused_before_open(self):
        with self.assertRaises(c.Refusal):
            self.read(path_info=[self.info(st_mode=stat.S_IFIFO | 0o600)])


class FixtureSupervisor(c.Supervisor):
    def __init__(self, transform=None):
        self.clock_value = Clock()
        super().__init__(self.clock_value, self.clock_value.sleep)
        self.transform = transform or (lambda phase, code, out, err, argv: (code, out, err))
        self.calls = []
    def signals(self):
        return contextlib.nullcontext()
    def run(self, phase, argv, cwd, env):
        self.calls.append((phase, argv, cwd, env))
        # Independent golden response/draft construction in the test, not expected_plan().
        flags = dict(zip(argv[2::2], argv[3::2]))
        unproven = {"historical_completeness": "unproven", "custody": "unproven", "quiescence": "unproven", "apply_authorized": False}
        code, err = 0, b""
        if phase == "bundle-valid":
            out = json.dumps({"schema_version": 1, "status": "schema_valid_only", "file_sha256": c.FIXTURES["offline_catalog_bundle.json"], "catalog_digest": c.BUNDLE_DIGEST, "key_count": 11, "canonical_byte_count": 1796, **unproven}).encode()
        elif phase == "plan-valid":
            bundle = json.loads(Path(flags["--baseline"]).read_bytes())
            plan = {"schema_version": 1, "status": "offline_draft", "deployment_id": "deployment-a", "redis_namespace": "test-schema", "baseline_sha256": c.FIXTURES["offline_catalog_bundle.json"], "target_sha256": c.FIXTURES["offline_catalog_bundle.json"], "baseline_catalog_digest": c.BUNDLE_DIGEST, "target_catalog_digest": c.BUNDLE_DIGEST, "baseline_source": bundle["source"], "target_source": bundle["source"], **{k: v for k, v in unproven.items() if k != "apply_authorized"}, "external_anchors_verified": False, "apply_authorized": False, "differences": []}
            data = json.dumps(plan, separators=(",", ":")).encode()
            with Path(flags["--output"]).open("xb") as f:
                f.write(data)
            out = json.dumps({"schema_version": 1, "status": "offline_draft", "plan_sha256": c.digest(data), "difference_count": 0, "external_anchors_verified": False, **unproven}).encode()
        elif phase == "bundle-wrong-hash":
            code, out, err = 1, b"", b"tunnel-relay: catalog bundle expected hash does not match\n"
        else:
            code, out, err = 1, b"", b"tunnel-relay: output already exists or cannot be created\n"
        code, out, err = self.transform(phase, code, out, err, argv)
        record = {"phase": phase, "status": "completed", "returncode": code, "failure": None,
                  "cleanup": {"direct_child_reaped": True, "owned_group_absent": True, "errors": []},
                  "stdout": {"bytes": len(out), "sha256": c.digest(out)}, "stderr": {"bytes": len(err), "sha256": c.digest(err)}}
        return record, out, err


class WitnessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name).resolve()
        self.binary = self.work / "archive-relay"; self.binary.write_bytes(b"synthetic never-executed executable")
        self.fixtures = self.work / "fixtures"; self.fixtures.mkdir()
        source = Path(__file__).resolve().parents[1] / "crates/tunnel-relay/tests/fixtures"
        for name in c.FIXTURES:
            (self.fixtures / name).write_bytes((source / name).read_bytes())

    @staticmethod
    def portable_read(path, limit, guard, private=False, keep=True):
        # Portable file model: POSIX metadata rules have independent pure controls.
        guard(); before = path.lstat(); data = path.read_bytes(); guard()
        c.require(len(data) <= limit, "file-size-bound")
        record = {"sha256": c.digest(data), "bytes": len(data), "identity": c.metadata_key(before)}
        return record, data if keep else b""

    def witness(self, transform=None, supervisor=None):
        sup = supervisor or FixtureSupervisor(transform)
        with mock.patch.object(c, "supported_host", return_value=True), mock.patch.object(c, "private_parent", return_value=True), mock.patch.object(c, "read_bound", side_effect=self.portable_read), mock.patch.object(c, "create_private", side_effect=lambda p, b: p.write_bytes(b)):
            result = c.check(self.binary, self.fixtures, self.work, {"PATH": "system-only"}, sup)
        return result, sup

    def test_honest_four_commands_exact_binding_and_cleanup(self):
        result, sup = self.witness()
        self.assertEqual(result["status"], "passed", result)
        self.assertEqual([x[0] for x in sup.calls], ["bundle-valid", "plan-valid", "bundle-wrong-hash", "plan-create-only"])
        self.assertTrue(result["temporary_tree_removed"] and result["binary_unchanged"] and result["inputs_unchanged"])
        self.assertTrue(all(call[1][0] == str(self.binary) for call in sup.calls))
        self.assertNotIn(str(self.work), json.dumps(result))
        self.assertFalse(result["apply_authorized"])

    def test_wrong_summary_fields_are_not_success(self):
        for phase, field, value in [("bundle-valid", "schema_version", True), ("bundle-valid", "key_count", 0), ("bundle-valid", "file_sha256", "0" * 64), ("bundle-valid", "apply_authorized", True), ("plan-valid", "plan_sha256", "0" * 64), ("plan-valid", "external_anchors_verified", True), ("plan-valid", "difference_count", 1)]:
            def alter(p, code, out, err, argv):
                if p == phase:
                    obj = json.loads(out); obj[field] = value; out = json.dumps(obj).encode()
                return code, out, err
            with self.subTest(phase=phase, field=field):
                result, _ = self.witness(alter)
                self.assertEqual(result["first_failure"], "command-summary")

    def test_wrong_negative_exit_and_wrong_refusal_are_not_red(self):
        for phase in ["bundle-wrong-hash", "plan-create-only"]:
            for code, err in [(0, b""), (2, b"usage"), (1, b"tunnel-relay: unknown\n")]:
                def alter(p, rc, out, stderr, argv):
                    return (code, b"", err) if p == phase else (rc, out, stderr)
                with self.subTest(phase=phase, code=code, err=err):
                    result, _ = self.witness(alter)
                    self.assertEqual(result["status"], "failed")
                    self.assertIn(result["first_failure"], ["command-exit", "command-refusal"])

    def test_expected_refusal_text_with_wrong_exit_still_fails(self):
        def alter(phase, code, out, err, argv):
            return (2, out, err) if phase == "bundle-wrong-hash" else (code, out, err)
        result, _ = self.witness(alter)
        self.assertEqual(result["first_failure"], "command-exit")

    def test_modified_plan_bytes_refused_independently_of_summary(self):
        def alter(phase, code, out, err, argv):
            if phase == "plan-valid":
                Path(argv[-1]).write_bytes(b'{}')
            return code, out, err
        result, _ = self.witness(alter)
        self.assertEqual(result["first_failure"], "plan-bytes")

    def test_collision_cannot_modify_existing_output(self):
        def alter(phase, code, out, err, argv):
            if phase == "plan-create-only":
                Path(argv[-1]).write_bytes(b'changed')
            return code, out, err
        result, _ = self.witness(alter)
        self.assertEqual(result["first_failure"], "plan-changed")

    def test_changed_binary_and_inputs_fail_final_integrity(self):
        for path, expected in [(self.binary, "binary-changed"), (self.fixtures / "offline_catalog_config.toml", "fixture-changed")]:
            before = path.read_bytes()
            def alter(phase, code, out, err, argv):
                if phase == "plan-create-only": path.write_bytes(b'changed')
                return code, out, err
            with self.subTest(path=path.name):
                result, _ = self.witness(alter)
                self.assertEqual(result["first_failure"], expected)
            path.write_bytes(before)

    def test_wrong_fixture_refused_before_any_child(self):
        (self.fixtures / "offline_catalog_config.toml").write_bytes(b'altered')
        result, sup = self.witness()
        self.assertEqual(result["first_failure"], "fixture-hash")
        self.assertFalse(sup.calls)

    def test_unexpected_output_retained_as_cleanup_failure(self):
        def alter(phase, code, out, err, argv):
            if phase == "plan-create-only": Path(argv[-1]).with_name('unexpected').write_bytes(b'x')
            return code, out, err
        result, _ = self.witness(alter)
        self.assertEqual(result["first_failure"], "fixture-extra-output")
        self.assertFalse(result["temporary_tree_removed"])
        self.assertIn("temporary-cleanup", result["cleanup_failures"])

    def test_cleanup_failure_preserves_first_refusal_failure(self):
        def alter(phase, code, out, err, argv):
            if phase == "bundle-valid":
                Path(argv[3]).with_name('unexpected').write_bytes(b'x')
                return 0, b'{}', b''
            return code, out, err
        result, _ = self.witness(alter)
        self.assertEqual(result["first_failure"], "command-summary")
        self.assertTrue(result["cleanup_failures"])

    def test_late_interrupt_cannot_pass(self):
        sup = FixtureSupervisor()
        original = sup.run
        def late(*args):
            result = original(*args)
            if args[0] == "plan-create-only": sup.interrupted = True
            return result
        sup.run = late
        result, _ = self.witness(supervisor=sup)
        self.assertEqual(result["first_failure"], "interrupted")

    def test_signal_finalizer_interrupt_cannot_pass_or_replace_first_failure(self):
        for earlier_failure in [False, True]:
            with self.subTest(earlier_failure=earlier_failure):
                def alter(phase, code, out, err, argv):
                    return (code, b"{}", err) if earlier_failure else (code, out, err)
                sup = FixtureSupervisor(alter)
                @contextlib.contextmanager
                def late():
                    yield
                    sup.interrupted = True
                sup.signals = late
                result, _ = self.witness(supervisor=sup)
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["first_failure"], "command-summary" if earlier_failure else "interrupted")

    def test_new_witness_does_not_run_after_old_check_failure(self):
        checks = ["check_checksums", "check_layout", "check_targets", "check_notices",
                  "check_assets", "check_cli", "check_portability"]
        for failed in [None, *checks]:
            with self.subTest(failed=failed), contextlib.ExitStack() as stack:
                for name in checks:
                    stack.enter_context(mock.patch.object(verifier, name, return_value=verifier.Result(name, name != failed)))
                added = stack.enter_context(mock.patch.object(verifier, "check_catalog_offline", return_value=verifier.Result("catalog-offline", True)))
                results = verifier.run_checks(self.work, self.work / "archive", self.work / "checksum",
                                              "x86_64-unknown-linux-gnu", None, None)
                self.assertEqual(added.call_count, int(failed is None))
                if failed: self.assertTrue(any(not result.ok for result in results))

    def test_two_device_targets_never_launch_relay(self):
        with mock.patch.object(c, "check") as run:
            for target in ["x86_64-pc-windows-msvc", "aarch64-unknown-linux-gnu"]:
                result = verifier.check_catalog_offline(self.work, target, self.work)
                self.assertTrue(result.ok); self.assertIn("not applicable", result.summary)
            run.assert_not_called()

    def test_all_three_relay_targets_select_archive_path(self):
        with mock.patch.object(c, "check", return_value={"status": "passed"}) as run, mock.patch.object(verifier.shutil, "which", return_value=None):
            for target in ["x86_64-unknown-linux-gnu", "aarch64-apple-darwin", "x86_64-apple-darwin"]:
                self.assertTrue(verifier.check_catalog_offline(self.work, target, self.work).ok)
                self.assertEqual(run.call_args.args[0], self.work / "bin/tunnel-relay")
        self.assertEqual(run.call_count, 3)


if __name__ == "__main__":
    unittest.main()
