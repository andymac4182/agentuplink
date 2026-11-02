#!/usr/bin/env python3
"""Fake process tools and temporary synthetic source/binary files only."""

from __future__ import annotations

import json
from pathlib import Path
import unittest
from unittest.mock import patch

import m4_original_gate4_witness as gate
import test_m4_authorization_witnesses as controls


def synthetic_repo(root):
    for path in gate.PATHS:
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("synthetic source\n")
    case = f"({gate.CASE!r}, [(PROVIDER_SRC, {gate.GUARD!r}, '')])"
    driver = (f"GATE4_CASES = [{case}]\n"
              f"WITNESSES = {{('gate4', {gate.CASE!r}): frozenset({{{gate.WITNESS!r}}})}}\n")
    (root / gate.DRIVER).write_text(driver)
    (root / gate.PROVIDER).write_text("synthetic prefix\n" + gate.GUARD + "synthetic suffix\n")
    (root / gate.DISPATCHER).write_text(f"fn {gate.WITNESS}() {{ one_close(provider.step()); }}\n")
    (root / gate.SUPPORT).write_text("fn one_close() {\n" + gate.PANIC_ANCHOR + "\n}\n")
    return {path: gate.shared.digest((root / path).read_bytes()) for path in gate.ORIGINAL_SHA256}


def compile_output(repo, target, content=b"synthetic dispatcher bytes"):
    path = target / "debug/deps/dispatcher-0123456789abcdef"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return "\n".join(json.dumps(item) for item in (
        {"reason": "compiler-artifact", "target": {"name": "dispatcher", "kind": ["test"],
                                                    "src_path": str(repo / gate.DISPATCHER)},
         "profile": {"test": True}, "executable": str(path)},
        {"reason": "build-finished", "success": True},
    )), path


class ContractTests(controls.NoProcesses):
    def setUp(self):
        super().setUp()
        self.repo = self.root / "repo"
        self.hashes = synthetic_repo(self.repo)

    def contract(self, *, repin=False):
        hashes = {path: gate.shared.digest((self.repo / path).read_bytes()) for path in self.hashes}
        with patch.object(gate, "ORIGINAL_SHA256", hashes if repin else self.hashes):
            return gate.original_contract(self.repo, hashes)

    def test_exact_original_declaration_and_witness_produce_full_guard_delete(self):
        case, site = self.contract()
        self.assertEqual(case["before"], gate.GUARD)
        self.assertEqual(case["after"], "")
        self.assertEqual(case["path"], gate.PROVIDER)
        self.assertEqual(site, (gate.SUPPORT, 2, gate.PANIC_PREFIX))

    def test_changed_original_driver_or_test_hash_refuses_before_mutation(self):
        for path in (gate.DRIVER, gate.DISPATCHER, gate.SUPPORT):
            original = (self.repo / path).read_bytes()
            (self.repo / path).write_bytes(original + b"foreign change")
            with self.subTest(path=path), self.assertRaisesRegex(gate.shared.Refusal, "original_source_hash_mismatch"):
                self.contract()
            (self.repo / path).write_bytes(original)

    def test_wrong_declared_witness_is_not_the_original_case(self):
        path = self.repo / gate.DRIVER
        path.write_text(path.read_text().replace(gate.WITNESS, "unrelated_test"))
        with self.assertRaisesRegex(gate.shared.Refusal, "original_witness_mismatch"):
            self.contract(repin=True)

    def test_missing_duplicate_case_or_partial_guard_are_not_accepted(self):
        path = self.repo / gate.DRIVER
        original = path.read_text()
        variants = [original.replace(gate.CASE, "absent case"),
                    original.replace("GATE4_CASES = [", "GATE4_CASES = [" +
                                     f"({gate.CASE!r}, [(PROVIDER_SRC, {gate.GUARD!r}, '')]), "),
                    original.replace("self.close();", "// missing close")]
        for variant in variants:
            path.write_text(variant)
            with self.subTest(variant=variant[:60]), self.assertRaises(gate.shared.Refusal):
                self.contract(repin=True)
        path.write_text(original)

    def test_duplicate_production_guard_is_refused(self):
        path = self.repo / gate.PROVIDER
        path.write_text(path.read_text() + gate.GUARD)
        with self.assertRaisesRegex(gate.shared.Refusal, "mutation_not_unique"):
            self.contract(repin=True)

    def test_dispatcher_artifact_kind_is_explicit_and_default_stays_client_only(self):
        target = self.root / "target"
        output, path = compile_output(self.repo, target)
        self.assertEqual(gate.compiled_dispatcher(output, 0, self.repo, target), path)
        with self.assertRaisesRegex(gate.shared.Refusal, "artifact_identifier_invalid"):
            gate.shared.fingerprint_artifact(path, target, lambda: 0, 30, lambda: False)
        artifact = gate.shared.fingerprint_artifact(path, target, lambda: 0, 30, lambda: False,
                                                    executable_kind="provider_dispatcher")
        self.assertEqual(artifact.identifier, "debug/deps/dispatcher-0123456789abcdef")
        with self.assertRaisesRegex(gate.shared.Refusal, "artifact_kind_invalid"):
            gate.shared.fingerprint_artifact(path, target, lambda: 0, 30, lambda: False,
                                             executable_kind="arbitrary")

    def test_compile_requires_original_integration_target_and_source(self):
        target = self.root / "target"
        output, _ = compile_output(self.repo, target)
        for text, code in ((output, 101), ("", 0), (output + "\n" + output, 0),
                           (output.replace('"dispatcher"', '"tunnel_client"'), 0),
                           (output.replace('["test"]', '["lib"]'), 0),
                           (output.replace(gate.DISPATCHER, "tests/other.rs"), 0)):
            with self.subTest(text=text[:40]), self.assertRaises(gate.shared.Refusal):
                gate.compiled_dispatcher(text, code, self.repo, target)

    def test_only_original_integration_running_record_binds_the_binary(self):
        target = self.root / "target"
        _, path = compile_output(self.repo, target)
        artifact = gate.shared.fingerprint_artifact(path, target, lambda: 0, 30, lambda: False,
                                                    executable_kind="provider_dispatcher")
        record = f"     Running tests/dispatcher.rs ({path})\n"
        gate.running_dispatcher(record, artifact, self.repo)
        for text in ("", record + record, record.replace("0123456789abcdef", "fedcba9876543210"),
                     record.replace("tests/dispatcher.rs", "unittests src/lib.rs")):
            with self.subTest(text=text), self.assertRaises(gate.shared.Refusal):
                gate.running_dispatcher(text, artifact, self.repo)


class FakeSupervisor:
    def __init__(self, bad_phase=None, mode=None):
        self.ops, self.deadline = controls.FakeOps(), gate.shared.MAIN_SECONDS
        self.interrupted = False
        self.controller = None
        self.bad_phase, self.mode = bad_phase, mode

    def run(self, argv, _cwd, _env, log, _seconds, **_kwargs):
        controller = self.controller
        output, code = "", 0
        selected = controller.phase == self.bad_phase
        if argv[0] == "git":
            if argv[1:] == ("rev-parse", "HEAD"):
                output = controller.expected + "\n"
            elif argv[1:] == ("rev-parse", "HEAD^{tree}"):
                output = "b" * 40 + "\n"
            elif argv[1] == "status":
                output = f" M {gate.PROVIDER}\n" if controller.sources and controller.sources.active else ""
            elif argv[1] == "ls-files":
                output = "\n".join(gate.PATHS) + "\n"
                if selected and self.mode == "lost_index":
                    output = ""
                if selected and self.mode == "late_interrupt":
                    self.interrupted = True
            else:
                raise AssertionError("unexpected synthetic Git invocation")
        else:
            assert tuple(argv[:len(gate.BASE)]) == gate.BASE
            target = controller.output / "private" / "target"
            path = target / "debug/deps/dispatcher-0123456789abcdef"
            if "--no-run" in argv:
                output, path = compile_output(controller.repo, target, ("synthetic " + controller.phase).encode())
                if selected and self.mode == "compile_failure":
                    output, code = "PRIVATE compiler error", 101
            else:
                assert tuple(argv[len(gate.BASE):]) == (gate.WITNESS, "--", "--exact", "--test-threads=1")
                red = controller.phase == "original_red"
                _, site = gate.original_contract(controller.repo, controller.sources.hashes) if not red else (
                    None, (gate.SUPPORT, 2, gate.PANIC_PREFIX))
                output = controls.test_log((gate.WITNESS,), red, site)
                code = 101 if red else 0
                if selected and self.mode == "wrong_panic":
                    output = output.replace(gate.PANIC_PREFIX, "unrelated unwrap panic:")
                if selected and self.mode == "zero_tests":
                    output, code = "running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.01s\n", 0
                if selected and self.mode == "changed_artifact":
                    path.write_bytes(b"PRIVATE replacement")
                if selected and self.mode == "foreign":
                    (controller.repo / gate.PROVIDER).write_text("PRIVATE foreign source")
                if selected and self.mode == "green_failure":
                    code = 101
                running = path if not (selected and self.mode == "wrong_binary") else path.with_name("dispatcher-fedcba9876543210")
                output = f"     Running tests/dispatcher.rs ({running})\n" + output
        log.write_text(output)
        result = {"status": "completed", "returncode": code, "process_started": True,
                  "direct_child_reaped": True, "owned_group_absent": True,
                  "log_bytes": len(output), "log_sha256": gate.shared.digest(output.encode())}
        if selected and self.mode == "timeout":
            result.update(status="command_timeout", direct_child_reaped=False, owned_group_absent=False)
        return result


class ControllerTests(controls.NoProcesses):
    def execute_fake(self, phase=None, mode=None, save_fault=None, journal=False):
        repo, output = self.root / "repo", self.root / "evidence"
        pins = synthetic_repo(repo)
        if journal:
            (repo / ".guard-mutation-journal.json").write_text("synthetic resident mutation")
        supervisor = FakeSupervisor(phase, mode)
        controller = gate.Controller(repo, "a" * 40, output, supervisor)
        supervisor.controller = controller
        original_save, fired = controller.save, False

        def save():
            nonlocal fired
            if not fired and save_fault == "timeout" and controller.receipt["commands"] and controller.receipt["commands"][-1]["status"] == "command_timeout":
                fired = True
                raise OSError("PRIVATE save failure")
            original_save()
            if not fired and save_fault == "terminal_interrupt" and controller.receipt["status"] == "passed":
                fired = True
                supervisor.interrupted = True

        controller.save = save
        with patch.object(gate, "ORIGINAL_SHA256", pins), patch.dict("os.environ", {"GITHUB_ACTIONS": "true"}), patch.object(gate.sys, "platform", "linux"):
            code = controller.execute()
        receipt = json.loads((output / "public/receipt.json").read_text())
        self.assertNotIn("PRIVATE", json.dumps(receipt))
        self.assertNotIn(str(output), json.dumps(receipt))
        self.assertEqual(list((output / "public").iterdir()), [output / "public/receipt.json"])
        return code, receipt, controller

    def test_exact_three_artifacts_and_three_runs_prove_focused_original_case(self):
        code, receipt, controller = self.execute_fake()
        self.assertEqual(code, 0)
        self.assertTrue(receipt["baseline_green"] and receipt["original_named_red"] and receipt["final_green"])
        self.assertTrue(receipt["source_restored"])
        self.assertFalse(receipt["literal_four_crate_cli_executed"])
        self.assertFalse(receipt["client_twenty_suite_repeated"])
        self.assertEqual(len(receipt["mutants"]), 1)
        self.assertEqual([entry["phase"] for entry in receipt["compile_artifacts"]],
                         ["baseline_compile", "mutant_compile", "final_compile"])
        self.assertEqual(len(receipt["artifact_runs"]), 3)
        self.assertEqual([entry["failed"] for entry in receipt["artifact_runs"]], [0, 1, 0])
        for i, run in enumerate(receipt["artifact_runs"]):
            compiled = receipt["compile_artifacts"][i]
            self.assertEqual(run["compile_index"], i)
            self.assertEqual(run["before_sha256"], compiled["sha256"])
            self.assertEqual(run["after_sha256"], compiled["sha256"])
            self.assertTrue(run["running_record_verified"])
        controller.sources.verify()

    def test_compile_failure_is_not_the_original_red_and_restores(self):
        code, receipt, _ = self.execute_fake("mutant_compile", "compile_failure")
        self.assertEqual(code, 1)
        self.assertEqual(receipt["first_failure"]["code"], "compile_failed")
        self.assertFalse(receipt["original_named_red"])
        self.assertTrue(receipt["source_restored"])

    def test_wrong_helper_panic_does_not_credit_original_case(self):
        code, receipt, _ = self.execute_fake("original_red", "wrong_panic")
        self.assertEqual(code, 1)
        self.assertEqual(receipt["first_failure"]["code"], "wrong_assertion")
        self.assertFalse(receipt["original_named_red"])
        self.assertTrue(receipt["source_restored"])

    def test_zero_test_mutant_is_not_red(self):
        code, receipt, _ = self.execute_fake("original_red", "zero_tests")
        self.assertEqual(code, 1)
        self.assertFalse(receipt["original_named_red"])
        self.assertTrue(receipt["source_restored"])

    def test_zero_test_baseline_never_applies_original_guard(self):
        code, receipt, _ = self.execute_fake("baseline_green", "zero_tests")
        self.assertEqual(code, 1)
        self.assertFalse(receipt["baseline_green"])
        self.assertEqual(receipt["mutants"], [])
        self.assertIsNone(receipt["active_mutation"])

    def test_changed_mutant_binary_is_not_red(self):
        code, receipt, _ = self.execute_fake("original_red", "changed_artifact")
        self.assertEqual(code, 1)
        self.assertEqual(receipt["first_failure"]["code"], "artifact_changed_after_run")
        self.assertFalse(receipt["original_named_red"])

    def test_wrong_launched_binary_is_not_red(self):
        code, receipt, _ = self.execute_fake("original_red", "wrong_binary")
        self.assertEqual(code, 1)
        self.assertEqual(receipt["first_failure"]["code"], "running_artifact_mismatch")
        self.assertFalse(receipt["original_named_red"])

    def test_timeout_and_save_failure_preserve_first_cause_and_unknown_cleanup(self):
        code, receipt, _ = self.execute_fake("original_red", "timeout", "timeout")
        self.assertEqual(code, 1)
        self.assertEqual(receipt["first_failure"]["code"], "command_timeout")
        self.assertEqual(receipt["cleanup_failures"][0]["code"], "process_cleanup_unconfirmed")
        self.assertTrue(receipt["source_restored"])

    def test_foreign_source_edit_is_not_erased_or_reported_restored(self):
        code, receipt, controller = self.execute_fake("original_red", "foreign")
        self.assertEqual(code, 1)
        self.assertEqual(receipt["first_failure"]["code"], "source_bytes_changed")
        self.assertFalse(receipt["source_restored"])
        self.assertEqual((controller.repo / gate.PROVIDER).read_text(), "PRIVATE foreign source")

    def test_final_recompile_failure_keeps_whole_gate_failed(self):
        code, receipt, _ = self.execute_fake("final_compile", "compile_failure")
        self.assertEqual(code, 1)
        self.assertTrue(receipt["original_named_red"])
        self.assertFalse(receipt["final_green"])
        self.assertTrue(receipt["source_restored"])

    def test_final_green_failure_keeps_whole_gate_failed(self):
        code, receipt, _ = self.execute_fake("final_green", "green_failure")
        self.assertEqual(code, 1)
        self.assertFalse(receipt["final_green"])
        self.assertTrue(receipt["source_restored"])

    def test_late_interrupt_cannot_leave_a_passed_receipt(self):
        code, receipt, _ = self.execute_fake(save_fault="terminal_interrupt")
        self.assertEqual(code, 1)
        self.assertEqual(receipt["first_failure"]["code"], "interrupted")

    def test_resident_original_journal_refuses_start(self):
        code, receipt, _ = self.execute_fake(journal=True)
        self.assertEqual(code, 1)
        self.assertEqual(receipt["first_failure"]["code"], "original_mutation_journal_present")
        self.assertEqual(receipt["compile_artifacts"], [])

    def test_lost_index_refuses_start(self):
        code, receipt, _ = self.execute_fake("setup", "lost_index")
        self.assertEqual(code, 1)
        self.assertEqual(receipt["first_failure"]["code"], "tracked_source_identity_mismatch")
        self.assertEqual(receipt["compile_artifacts"], [])


if __name__ == "__main__":
    unittest.main()
