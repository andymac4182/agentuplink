#!/usr/bin/env python3
"""Synthetic files and fake process operations only; never starts a process."""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import m4_authorization_witnesses as w


def test_log(names, red=False, site=None):
    status = "FAILED" if red else "ok"
    text = f"running {len(names)} test" + ("s" if len(names) != 1 else "") + "\n"
    text += "".join(f"test {name} ... {status}\n" for name in names)
    if red:
        path, line, message = site
        text += (f"\nfailures:\n\n---- {names[0]} stdout ----\n\n"
                 f"thread '{names[0]}' (123) panicked at {path}:{line}:9:\n"
                 f"{message} synthetic assertion\n\nfailures:\n    {names[0]}\n\n")
    text += (f"test result: {status}. {0 if red else len(names)} passed; "
             f"{len(names) if red else 0} failed; 0 ignored; 0 measured; 100 filtered out; "
             "finished in 0.01s\n")
    return text


ARTIFACT_ID = "debug/deps/tunnel_client-0123456789abcdef"


def compile_log(target, content=b"synthetic compiled bytes; never executed"):
    path = target / ARTIFACT_ID
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return "\n".join(json.dumps(item) for item in (
        {"reason": "compiler-artifact", "target": {"name": "tunnel_client"},
         "profile": {"test": True}, "executable": str(path)},
        {"reason": "build-finished", "success": True},
    ))


def synthetic_repo(root):
    """Mutation matchers and assertion anchors, not runnable Rust source."""
    for path in {case["path"] for case in w.PLAN["cases"]}:
        anchors = {case["before"] for case in w.PLAN["cases"] if case["path"] == path}
        anchors = {anchor for anchor in anchors if not any(anchor != other and anchor in other for other in anchors)}
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("\n// synthetic separator\n".join(sorted(anchors)) + "\n")
    for path, prefix in ((w.ACTOR_TEST, w.ACTOR), (w.PROVIDER_SOURCE, w.PROVIDER)):
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        tests = w.TEST_MARKER + "\n" if path == w.PROVIDER_SOURCE else "// synthetic tests\n"
        for name in w.INVENTORY:
            if name.startswith(prefix):
                short = name.split("::")[-1]
                anchor = w.ASSERTIONS.get(short, w.Assertion("assert!(true);"))
                tests += f"fn {short}() {{\n{anchor.anchor}\n}}\n"
        target.write_text((target.read_text() if target.exists() else "") + tests)


class NoProcesses(unittest.TestCase):
    def setUp(self):
        # Any accidental production start fails before executing a command.
        self.block = patch("subprocess.Popen", side_effect=AssertionError("real process forbidden"))
        self.block.start()
        self.addCleanup(self.block.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)


class ParserTests(NoProcesses):
    def test_plan_and_inventory_are_fixed(self):
        self.assertEqual(hashlib.sha256(w.REFERENCE_PLAN.encode()).hexdigest(), w.PLAN_SHA256)
        self.assertEqual(len(w.INVENTORY), 20)
        self.assertEqual(len(set(w.INVENTORY)), 20)
        self.assertEqual(len(w.PLAN["cases"]), 9)
        self.assertEqual(sum(len(case["witnesses"]) for case in w.PLAN["cases"]), 10)

    def test_inventory_requires_all_twenty_names_once(self):
        output = "\n".join(name + ": test" for name in w.INVENTORY) + "\n20 tests, 0 benchmarks\n"
        w.check_inventory(output)
        for bad in (output.replace(w.INVENTORY[0], "unknown"), output + output,
                    output.replace("20 tests", "19 tests"), "0 tests, 0 benchmarks\n"):
            with self.subTest(bad=bad[:20]), self.assertRaises(w.Refusal):
                w.check_inventory(bad)

    def test_green_requires_actual_all_twenty_results(self):
        output = test_log(w.INVENTORY)
        w.check_tests(output, 0, w.INVENTORY, False)
        for text, code in ((output, 1), (output.replace("20 passed", "19 passed"), 0),
                           (output.replace("... ok", "... ignored", 1), 0),
                           (output.replace("running 20 tests", "running 0 tests"), 0),
                           (output + output, 0), (output + "panicked at something", 0)):
            with self.subTest(code=code), self.assertRaises(w.Refusal):
                w.check_tests(text, code, w.INVENTORY, False)

    def test_red_requires_one_specific_assertion_not_nonzero(self):
        name = w.INVENTORY[0]
        site = (w.PROVIDER_SOURCE, 42, "assertion failed:")
        text = test_log((name,), True, site)
        w.check_tests(text, 101, (name,), True, site)
        bad = [
            (text, 1), (text, 0), (text.replace(":42:9:", ":43:9:"), 101),
            (text.replace("assertion failed:", "unwrap panicked"), 101),
            (text.replace("running 1 test", "running 0 tests"), 101),
            (text.replace(name, "other_test"), 101),
            (text + "\nthread 'other' panicked at x.rs:1:1:\nassertion failed:\n", 101),
            ("error[E1234]: compiler failure", 101),
            (test_log((name, name), True, site), 101),
            (text.replace("0 ignored", "1 ignored"), 101),
        ]
        for output, code in bad:
            with self.subTest(output=output[:40]), self.assertRaises(w.Refusal):
                w.check_tests(output, code, (name,), True, site)

    def test_compilation_needs_success_and_owned_test_artifact(self):
        target = self.root / "target"
        output = compile_log(target)
        w.check_compilation(output, 0, target)
        for text, code in ((output, 101), ("", 0), (output.replace('true', 'false'), 0),
                           (output.replace(str(target), str(self.root / "foreign")), 0),
                           (output + "\n" + output, 0), ("{broken", 0)):
            with self.subTest(code=code), self.assertRaises(w.Refusal):
                w.check_compilation(text, code, target)


class SourceTests(NoProcesses):
    def setUp(self):
        super().setUp()
        self.repo, self.backup = self.root / "repo", self.root / "backup"
        self.backup.mkdir()
        synthetic_repo(self.repo)
        self.sources = w.Sources(self.repo, self.backup)

    def test_each_unique_mutation_preserves_tests_and_restores_exact_bytes(self):
        for case in w.PLAN["cases"]:
            with self.subTest(case=case["id"]):
                self.sources.apply(case)
                self.sources.verify()
                for name in case["witnesses"]:
                    path, line, _ = w.assertion_site(self.repo, name)
                    self.assertIn("assert", (self.repo / path).read_text().splitlines()[line - 1])
                self.sources.restore()
                self.assertEqual(w.test_hashes(self.repo), self.sources.tests)
                self.assertIsNone(self.sources.active)

    def test_no_match_duplicate_and_noop_are_setup_failures(self):
        original = w.PLAN["cases"][1]
        for case in ({**original, "before": "absent"},
                     {**original, "after": original["before"]},
                     {**original, "before": " "}):
            with self.subTest(case=case), self.assertRaisesRegex(w.Refusal, "mutation_not_unique"):
                self.sources.apply(case)
            self.assertIsNone(self.sources.active)

    def test_changed_test_is_never_restored_over(self):
        self.sources.apply(w.PLAN["cases"][1])
        test = self.repo / w.ACTOR_TEST
        test.write_text(test.read_text() + "// foreign test change\n")
        with self.assertRaisesRegex(w.Refusal, "source_bytes_changed"):
            self.sources.restore()
        self.assertIsNone(self.sources.active)
        self.assertTrue(test.read_text().endswith("// foreign test change\n"))

    def test_foreign_target_edit_refuses_overwrite_and_keeps_backup(self):
        case = w.PLAN["cases"][1]
        self.sources.apply(case)
        (self.repo / case["path"]).write_text("foreign content")
        with self.assertRaisesRegex(w.Refusal, "restore_foreign_edit"):
            self.sources.restore()
        self.assertIsNotNone(self.sources.active)
        self.assertEqual((self.repo / case["path"]).read_text(), "foreign content")
        self.assertEqual(len(list(self.backup.iterdir())), len(self.sources.paths))

    def test_interrupted_atomic_replacement_leaves_restorable_original(self):
        with patch.object(Path, "replace", side_effect=OSError("synthetic write failure")):
            with self.assertRaises(OSError):
                self.sources.apply(w.PLAN["cases"][1])
        self.sources.restore()
        self.assertFalse(list(self.repo.rglob("*.m4-witness-tmp")))


class FakeProcess:
    pid = 123

    def __init__(self):
        self.returncode = None
        self.stdout = io.BytesIO()

    def poll(self):
        return self.returncode

    def wait(self, timeout):
        if self.returncode is None:
            raise subprocess.TimeoutExpired("synthetic", timeout)
        return self.returncode


class FakeOps:
    def __init__(self, mode="success"):
        self.mode, self.now = mode, 0.0
        self.process = FakeProcess()
        self.chunks = [b"synthetic output\n", b""]
        self.signals = []
        self.started = False

    def monotonic(self):
        return self.now

    def sleep(self, delay):
        self.now += delay

    def start(self, _argv, _cwd, _env):
        self.started = True
        if self.mode == "spawn_error":
            raise OSError("PRIVATE spawn payload")
        return self.process

    def read(self, _process, delay):
        self.now += delay
        if self.mode == "io_error":
            raise OSError("PRIVATE output payload")
        if self.mode == "keyboard_interrupt":
            raise KeyboardInterrupt()
        if self.mode == "output_limit":
            return b"x" * 32
        if self.mode in ("timeout", "unkillable", "kill_only"):
            return None
        if self.mode == "pipe_held":
            self.process.returncode = 0
            return None
        chunk = self.chunks.pop(0)
        if not chunk:
            self.process.returncode = 0
        return chunk

    def group_exists(self, _pid):
        return self.mode in ("unkillable", "stray_group", "pipe_held") or self.process.returncode is None

    def signal_group(self, _pid, number):
        self.signals.append(number)
        if self.mode != "unkillable" and (self.mode != "kill_only" or number == signal.SIGKILL):
            self.process.returncode = -number
            self.mode = "stopped"


class SupervisorTests(NoProcesses):
    def run_fake(self, mode, seconds=2, interrupt=False):
        ops = FakeOps(mode)
        supervisor = w.Supervisor(ops)
        supervisor.interrupted = interrupt
        result = supervisor.run(("fake",), self.root, {}, self.root / "command.log", seconds)
        return result, ops

    def test_success_reaps_direct_child_and_observes_absent_group(self):
        result, ops = self.run_fake("success")
        self.assertEqual(result["status"], "completed")
        self.assertTrue(result["direct_child_reaped"])
        self.assertTrue(result["owned_group_absent"])
        self.assertFalse(ops.signals)

    def test_timeout_term_kill_and_join_have_bounded_waits(self):
        result, ops = self.run_fake("kill_only")
        self.assertEqual(result["status"], "command_timeout")
        self.assertEqual(ops.signals, [signal.SIGTERM, signal.SIGKILL])
        self.assertTrue(result["direct_child_reaped"] and result["owned_group_absent"])
        self.assertLessEqual(ops.now, 7.1)

    def test_unknown_cleanup_never_becomes_joined(self):
        result, ops = self.run_fake("unkillable")
        self.assertEqual(result["status"], "command_timeout")
        self.assertFalse(result["direct_child_reaped"])
        self.assertFalse(result["owned_group_absent"])
        self.assertLessEqual(ops.now, 7.1)

    def test_leftover_owned_group_is_failure_even_if_cleanup_succeeds(self):
        result, _ = self.run_fake("stray_group")
        self.assertEqual(result["status"], "owned_group_survived")
        self.assertTrue(result["owned_group_absent"])

    def test_interruption_before_start_claims_no_child_join(self):
        result, ops = self.run_fake("success", interrupt=True)
        self.assertEqual(result["status"], "interrupted")
        self.assertFalse(ops.started)
        self.assertFalse(result["process_started"])
        self.assertFalse(result["direct_child_reaped"])

    def test_raw_log_is_capped(self):
        with patch.object(w, "MAX_LOG_BYTES", 40):
            result, _ = self.run_fake("output_limit")
        self.assertEqual(result["status"], "output_limit")
        self.assertEqual(result["log_bytes"], 40)

    def test_pipe_or_io_failure_is_not_red(self):
        for mode, status in (("pipe_held", "output_pipe_unclosed"),
                             ("io_error", "process_io_failed"),
                             ("spawn_error", "process_io_failed"),
                             ("keyboard_interrupt", "interrupted")):
            with self.subTest(mode=mode):
                (self.root / "command.log").unlink(missing_ok=True)
                result, _ = self.run_fake(mode)
                self.assertEqual(result["status"], status)
                self.assertNotIn("PRIVATE", json.dumps(result))

    def test_overall_budget_prevents_start_and_cleanup_has_separate_allowance(self):
        ops = FakeOps()
        supervisor = w.Supervisor(ops)
        supervisor.deadline = -1
        result = supervisor.run(("fake",), self.root, {}, self.root / "expired.log", 20)
        self.assertEqual(result["status"], "overall_timeout")
        self.assertFalse(ops.started)
        result = supervisor.run(("fake",), self.root, {}, self.root / "cleanup.log", 15,
                                cleanup_deadline=60)
        self.assertEqual(result["status"], "completed")


class FakeSupervisor:
    def __init__(self, bad_phase=None, mode="compile"):
        self.ops, self.bad_phase, self.mode = FakeOps(), bad_phase, mode
        self.controller = None
        self.interrupted = False
        self.deadline = w.MAIN_SECONDS

    def run(self, argv, _cwd, _env, log, _seconds, **_kwargs):
        c = self.controller
        rc = 0
        if argv[0] == "git":
            if argv[1:] == ("rev-parse", "HEAD"):
                output = c.expected + "\n"
            elif argv[1:] == ("rev-parse", "HEAD^{tree}"):
                output = "b" * 40 + "\n"
            else:
                output = f" M {c.sources.active[0]}\n" if c.sources and c.sources.active else ""
        elif "--no-run" in argv:
            output = compile_log(c.output / "private" / "target", ("synthetic " + c.phase).encode())
            if c.phase == self.bad_phase and self.mode == "compile":
                output, rc = "PRIVATE synthetic compiler error", 101
        elif "--list" in argv:
            output = "\n".join(name + ": test" for name in w.INVENTORY) + "\n20 tests, 0 benchmarks\n"
        elif "--exact" in argv:
            name = argv[len(w.CARGO)]
            output, rc = test_log((name,), True, w.assertion_site(c.repo, name)), 101
            if c.phase == self.bad_phase:
                if self.mode == "panic":
                    output = output.replace("panicked at", "PRIVATE wrong panic at")
                elif self.mode == "interrupt":
                    raise KeyboardInterrupt()
                elif self.mode == "foreign":
                    (c.repo / c.sources.active[0]).write_text("PRIVATE foreign content")
                elif self.mode == "final_green":
                    pass
        else:
            output = test_log(w.INVENTORY)
            if c.phase == self.bad_phase and self.mode != "late_interrupt":
                output, rc = "PRIVATE failed green", 101
        if argv[0] == "cargo" and "--no-run" not in argv:
            artifact = c.output / "private" / "target" / ARTIFACT_ID
            running_path = artifact
            if c.phase == self.bad_phase and self.mode == "artifact_changed":
                artifact.write_bytes(b"synthetic replacement")
            if c.phase == self.bad_phase and self.mode == "wrong_artifact":
                running_path = artifact.with_name("tunnel_client-fedcba9876543210")
            if not (c.phase == self.bad_phase and self.mode == "missing_artifact_record"):
                output = f"     Running unittests src/lib.rs ({running_path})\n" + output
        log.write_text(output)
        result = {"status": "completed", "returncode": rc, "process_started": True,
                  "direct_child_reaped": True, "owned_group_absent": True,
                  "log_bytes": len(output), "log_sha256": w.digest(output.encode())}
        if c.phase == self.bad_phase and self.mode == "cleanup" and "--no-run" in argv:
            result.update(status="command_timeout", direct_child_reaped=False, owned_group_absent=False)
        if c.phase == self.bad_phase and self.mode == "late_interrupt" and argv[:2] == ("git", "status"):
            self.interrupted = True
        return result


class ControllerTests(NoProcesses):
    def execute_fake(self, bad_phase=None, mode="compile", save_fault=None):
        repo, output = self.root / "repo", self.root / "evidence"
        synthetic_repo(repo)
        supervisor = FakeSupervisor(bad_phase, mode)
        controller = w.Controller(repo, "a" * 40, output, supervisor)
        supervisor.controller = controller
        original_save = controller.save
        fired = False

        def save():
            nonlocal fired
            if not fired and save_fault == "after_timeout" and controller.receipt["commands"] and controller.receipt["commands"][-1]["status"] == "command_timeout":
                fired = True
                raise OSError("PRIVATE receipt write failure")
            original_save()
            if not fired and save_fault == "artifact_before" and controller.receipt.get("compile_artifacts"):
                fired = True
                (controller.output / "private" / "target" / ARTIFACT_ID).write_bytes(b"synthetic replacement")
            if not fired and save_fault == "terminal_interrupt" and controller.receipt["status"] == "passed":
                fired = True
                supervisor.interrupted = True

        controller.save = save
        with patch.dict("os.environ", {"GITHUB_ACTIONS": "true"}), patch.object(w.sys, "platform", "linux"):
            rc = controller.execute()
        receipt = json.loads((output / "public/receipt.json").read_text())
        self.assertNotIn("PRIVATE", json.dumps(receipt))
        self.assertEqual(list((output / "public").iterdir()), [output / "public/receipt.json"])
        return rc, receipt, controller

    def test_all_nine_mutants_require_initial_and_final_twenty_green(self):
        rc, receipt, _ = self.execute_fake()
        self.assertEqual(rc, 0)
        self.assertEqual(receipt["status"], "passed")
        self.assertEqual(len(receipt["mutants"]), 9)
        self.assertTrue(receipt["baseline_green"] and receipt["final_green"] and receipt["source_restored"])
        self.assertIsNone(receipt["first_failure"])

    def test_baseline_failure_never_applies_a_mutant(self):
        rc, receipt, controller = self.execute_fake("baseline_green")
        self.assertEqual(rc, 1)
        self.assertEqual(receipt["mutants"], [])
        self.assertFalse(receipt["baseline_green"])
        self.assertTrue(receipt["source_restored"])
        controller.sources.verify()

    def test_compile_error_is_not_red_and_source_restores(self):
        rc, receipt, controller = self.execute_fake("A3-provider-accepted-bound")
        self.assertEqual(rc, 1)
        self.assertEqual(len(receipt["mutants"]), 2)
        self.assertEqual(receipt["first_failure"]["code"], "compile_failed")
        self.assertTrue(receipt["source_restored"])
        controller.sources.verify()

    def test_wrong_panic_cannot_serve_as_red(self):
        rc, receipt, _ = self.execute_fake("A1-last-accepted-bound", "panic")
        self.assertEqual(rc, 1)
        self.assertEqual(receipt["mutants"], [])
        self.assertTrue(receipt["source_restored"])

    def test_interrupt_during_mutant_restores_and_is_failure(self):
        rc, receipt, _ = self.execute_fake("A1-last-accepted-bound", "interrupt")
        self.assertEqual(rc, 1)
        self.assertEqual(receipt["first_failure"]["code"], "interrupted")
        self.assertTrue(receipt["source_restored"])

    def test_unconfirmed_process_cleanup_preserves_original_timeout(self):
        rc, receipt, _ = self.execute_fake("A1-last-accepted-bound", "cleanup")
        self.assertEqual(rc, 1)
        self.assertEqual(receipt["first_failure"]["code"], "command_timeout")
        self.assertEqual(receipt["cleanup_failures"][0]["code"], "process_cleanup_unconfirmed")
        self.assertTrue(receipt["source_restored"])
        self.assertFalse(receipt["final_green"])

    def test_restore_failure_does_not_replace_original_failure(self):
        rc, receipt, _ = self.execute_fake("A1-last-accepted-bound", "foreign")
        self.assertEqual(rc, 1)
        self.assertEqual(receipt["first_failure"]["code"], "source_bytes_changed")
        self.assertIn("restore_foreign_edit", [item["code"] for item in receipt["cleanup_failures"]])
        self.assertFalse(receipt["source_restored"])

    def test_failed_final_green_keeps_status_failed_after_all_mutants(self):
        rc, receipt, _ = self.execute_fake("final_green", "final_green")
        self.assertEqual(rc, 1)
        self.assertEqual(len(receipt["mutants"]), 9)
        self.assertFalse(receipt["final_green"])
        self.assertTrue(receipt["source_restored"])

    def test_late_interrupt_after_final_green_identity_is_failed(self):
        rc, receipt, _ = self.execute_fake("final_green", "late_interrupt")
        self.assertEqual(rc, 1)
        self.assertTrue(receipt["final_green"] and receipt["source_restored"])
        self.assertEqual(receipt["first_failure"]["code"], "interrupted")

    def test_interrupt_during_cleanup_is_failed(self):
        rc, receipt, _ = self.execute_fake("cleanup", "late_interrupt")
        self.assertEqual(rc, 1)
        self.assertTrue(receipt["final_green"] and receipt["source_restored"])
        self.assertEqual(receipt["first_failure"]["code"], "interrupted")

    def test_interrupt_during_terminal_save_replaces_passed_receipt(self):
        rc, receipt, _ = self.execute_fake(save_fault="terminal_interrupt")
        self.assertEqual(rc, 1)
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["first_failure"]["code"], "interrupted")

    def test_save_failure_cannot_mask_observed_timeout(self):
        rc, receipt, _ = self.execute_fake("A1-last-accepted-bound", "cleanup", "after_timeout")
        self.assertEqual(rc, 1)
        self.assertEqual(receipt["first_failure"]["code"], "command_timeout")
        self.assertEqual(receipt["cleanup_failures"][0]["code"], "process_cleanup_unconfirmed")
        self.assertTrue(receipt["source_restored"])

    def test_inventory_rejects_changed_compiled_artifact(self):
        rc, receipt, _ = self.execute_fake("inventory", "artifact_changed")
        self.assertEqual(rc, 1)
        self.assertEqual(receipt["first_failure"]["code"], "artifact_changed_after_run")
        self.assertFalse(receipt["baseline_green"])
        self.assertEqual(receipt["mutants"], [])

    def test_artifact_changed_before_launch_stops_without_test_run(self):
        rc, receipt, _ = self.execute_fake(save_fault="artifact_before")
        self.assertEqual(rc, 1)
        self.assertEqual(receipt["first_failure"]["code"], "artifact_changed_before_run")
        self.assertEqual(receipt["artifact_runs"], [])

    def test_wrong_red_executable_cannot_count_as_assertion_red(self):
        rc, receipt, _ = self.execute_fake("A1-last-accepted-bound", "wrong_artifact")
        self.assertEqual(rc, 1)
        self.assertEqual(receipt["first_failure"]["code"], "running_artifact_mismatch")
        self.assertEqual(receipt["mutants"], [])
        self.assertTrue(receipt["source_restored"])

    def test_missing_inventory_running_record_is_not_evidence(self):
        rc, receipt, _ = self.execute_fake("inventory", "missing_artifact_record")
        self.assertEqual(rc, 1)
        self.assertEqual(receipt["first_failure"]["code"], "running_artifact_mismatch")
        self.assertFalse(receipt["baseline_green"])

    def test_every_run_binds_a_phase_compile_hash_including_final_green(self):
        rc, receipt, controller = self.execute_fake()
        self.assertEqual(rc, 0)
        self.assertEqual(len(receipt["compile_artifacts"]), 11)
        self.assertEqual(len(receipt["artifact_runs"]), 13)
        self.assertEqual(receipt["compile_artifacts"][-1]["phase"], "final_compile")
        for run in receipt["artifact_runs"]:
            artifact = receipt["compile_artifacts"][run["compile_index"]]
            self.assertEqual(run["identifier"], ARTIFACT_ID)
            self.assertEqual(run["before_sha256"], artifact["sha256"])
            self.assertEqual(run["after_sha256"], artifact["sha256"])
            self.assertTrue(run["running_record_verified"])
        self.assertEqual(receipt["artifact_runs"][-1]["compile_index"], 10)
        self.assertNotIn(str(controller.output), json.dumps(receipt))


class ArtifactTests(NoProcesses):
    def setUp(self):
        super().setUp()
        self.target = self.root / "private" / "target"
        compile_log(self.target)
        self.path = self.target / ARTIFACT_ID

    def fingerprint(self, clock=lambda: 0, deadline=30, interrupted=lambda: False):
        return w.fingerprint_artifact(self.path, self.target, clock, deadline, interrupted)

    def test_regular_artifact_has_only_relative_identifier_size_and_hash(self):
        artifact = self.fingerprint()
        self.assertEqual(artifact.public(), {"identifier": ARTIFACT_ID,
                                             "size_bytes": self.path.stat().st_size,
                                             "sha256": hashlib.sha256(self.path.read_bytes()).hexdigest()})
        self.assertNotIn(str(self.root), json.dumps(artifact.public()))

    def test_missing_directory_empty_and_oversized_artifacts_are_refused(self):
        self.path.unlink()
        with self.assertRaisesRegex(w.Refusal, "artifact_unreadable"):
            self.fingerprint()
        self.path.mkdir()
        with self.assertRaisesRegex(w.Refusal, "artifact_not_regular"):
            self.fingerprint()
        self.path.rmdir()
        self.path.write_bytes(b"")
        with self.assertRaisesRegex(w.Refusal, "artifact_size_invalid"):
            self.fingerprint()
        self.path.write_bytes(b"too big")
        with patch.object(w, "MAX_ARTIFACT_BYTES", 4), self.assertRaisesRegex(w.Refusal, "artifact_size_invalid"):
            self.fingerprint()

    def test_symlink_and_foreign_paths_are_refused_before_hashing(self):
        foreign = self.root / "foreign"
        foreign.write_bytes(b"foreign")
        self.path.unlink()
        self.path.symlink_to(foreign)
        with self.assertRaisesRegex(w.Refusal, "artifact_path_invalid"):
            self.fingerprint()
        self.path = foreign
        with self.assertRaisesRegex(w.Refusal, "artifact_path_invalid"):
            self.fingerprint()

    def test_unknown_identifier_is_refused(self):
        self.path = self.path.rename(self.path.with_name("payload-name"))
        with self.assertRaisesRegex(w.Refusal, "artifact_identifier_invalid"):
            self.fingerprint()

    def test_hash_deadline_and_interrupt_are_fail_closed(self):
        with self.assertRaisesRegex(w.Refusal, "artifact_hash_timeout"):
            self.fingerprint(deadline=0)
        with self.assertRaisesRegex(w.Refusal, "interrupted"):
            self.fingerprint(interrupted=lambda: True)
        ticks = iter(range(20))
        with patch.object(w, "HASH_CHUNK_BYTES", 4), self.assertRaisesRegex(w.Refusal, "artifact_hash_timeout"):
            self.fingerprint(clock=lambda: next(ticks), deadline=5)

    def test_replacement_during_chunked_hash_is_refused(self):
        calls = 0

        def clock():
            nonlocal calls
            calls += 1
            if calls == 4:
                self.path.write_bytes(b"changed within hash")
            return 0

        with patch.object(w, "HASH_CHUNK_BYTES", 4), self.assertRaisesRegex(w.Refusal, "artifact_changed_during_hash"):
            self.fingerprint(clock=clock)

    def test_running_record_requires_exact_compiled_path_once(self):
        artifact = self.fingerprint()
        record = f"     Running unittests src/lib.rs ({self.path})\n"
        w.check_running_artifact(record, artifact, self.root)
        relative = record.replace(str(self.path), os.path.relpath(self.path, self.root))
        w.check_running_artifact(relative, artifact, self.root)
        for output in ("", record + record, record.replace("0123456789abcdef", "fedcba9876543210"),
                       record + " Running tests/foreign.rs (unknown)\n"):
            with self.subTest(output=output), self.assertRaisesRegex(w.Refusal, "running_artifact_mismatch"):
                w.check_running_artifact(output, artifact, self.root)


if __name__ == "__main__":
    unittest.main()
