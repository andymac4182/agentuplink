#!/usr/bin/env python3
"""Pure witness-diagnostic checks; no harness, child process, or Redis."""

import importlib.util
import contextlib
import io
from pathlib import Path
import sys
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "m0_witness_diagnostics_under_test",
    Path(__file__).with_name("m0-payload-scan.py"),
)
SCAN = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SCAN
SPEC.loader.exec_module(SCAN)


class WitnessDiagnosticsTests(unittest.TestCase):
    def run_record(self, *, exit_code=1, error="", sentinels=None, stderr=None):
        if sentinels is None:
            sentinels = {
                "credential": [b"synthetic-credential-capture-0123"],
                "application_payload": [b"synthetic-payload-capture-0123"],
                "filesystem_path": [b"/synthetic/private/capture-0123"],
                "private_endpoint": [b"synthetic-endpoint.invalid:1234"],
            }
        if stderr is None:
            stderr = b"ACP cluster gate failed: synthetic completion rule\n"
            stderr += b"\n".join(value for values in sentinels.values() for value in values)
        return SCAN.GateRun(
            gate=SCAN.Gate("M8", "verify-m8-acp-cluster", SCAN.KIND_ORDER),
            planted=True,
            exit_code=exit_code,
            seconds=1,
            sentinels=sentinels,
            retired=0,
            streams={"harness_stderr": stderr},
            error=error,
        )

    def test_failed_child_keeps_error_rule_and_redacts_every_recorded_domain(self):
        run = self.run_record()
        output = "\n".join(SCAN.witness_failure_diagnostics(run))
        self.assertIn("ACP cluster gate failed: synthetic completion rule", output)
        for kind, values in run.sentinels.items():
            self.assertIn(f"[{kind}]", output)
            for value in values:
                self.assertNotIn(value.decode(), output)

    def test_unreadable_capture_withholds_stderr_and_its_error(self):
        run = self.run_record(error="synthetic-unrecorded-sensitive-error")
        with mock.patch.object(SCAN, "redacted_tail", side_effect=AssertionError("must not read")):
            output = "\n".join(SCAN.witness_failure_diagnostics(run))
        self.assertIn("withheld", output)
        self.assertNotIn(run.error, output)
        self.assertNotIn("synthetic completion rule", output)

    def test_missing_required_domain_withholds_stderr(self):
        run = self.run_record()
        run.sentinels["credential"] = []
        with mock.patch.object(SCAN, "redacted_tail", side_effect=AssertionError("must not read")):
            self.assertIn("withheld", "\n".join(SCAN.witness_failure_diagnostics(run)))

    def test_successful_child_adds_no_failure_diagnostic(self):
        self.assertEqual(SCAN.witness_failure_diagnostics(self.run_record(exit_code=0)), [])

    def test_failed_child_stays_wrong_witness_even_when_planted_hit_exists(self):
        run = self.run_record()
        run.hits = [SCAN.Hit("application_payload", "harness_stderr", 0, True)]
        before = SCAN.classify_witness(run)
        self.assertEqual(before, "WRONG WITNESS (the planted child exited 1)")
        SCAN.witness_failure_diagnostics(run)
        self.assertEqual(SCAN.classify_witness(run), before)

    def test_failed_child_main_prints_safe_diagnostic_and_stays_red(self):
        run = self.run_record()
        output = io.StringIO()
        argv = ["m0-payload-scan.py", "--witness-only", "--gate", run.gate.command,
                "--harness", sys.executable]
        # Isolate only orchestration dependencies: no child, filesystem setup,
        # network, or actual Redis is involved in this diagnostic rule.
        with (mock.patch.object(sys, "argv", argv),
              mock.patch.dict(SCAN.os.environ, {"TEST_REDIS_URL": "redis://127.0.0.1:1"}),
              mock.patch.object(SCAN, "unit_probes", return_value=[]),
              mock.patch.object(SCAN, "run_gate", return_value=run) as run_gate,
              mock.patch.object(SCAN.tempfile, "TemporaryDirectory") as temporary,
              mock.patch.object(SCAN.os, "chmod"),
              contextlib.redirect_stdout(output)):
            temporary.return_value.name = "/synthetic-m0-diagnostics-test"
            status = SCAN.main()
            temporary.return_value.cleanup.assert_called_once_with()
        run_gate.assert_called_once()
        self.assertTrue(run_gate.call_args.kwargs["plant"])
        self.assertEqual(status, 1)
        text = output.getvalue()
        self.assertIn("WRONG WITNESS (the planted child exited 1)", text)
        self.assertIn("failed witness child: redacted stderr tail", text)
        self.assertIn("ACP cluster gate failed: synthetic completion rule", text)
        for values in run.sentinels.values():
            for value in values:
                self.assertNotIn(value.decode(), text)

    def test_tail_preserves_existing_line_and_column_bounds(self):
        run = self.run_record(stderr=(b"x" * 1000 + b"\n") * 40)
        output = SCAN.witness_failure_diagnostics(run)[0]
        lines = output.splitlines()
        self.assertEqual(len(lines), 21)
        self.assertTrue(all(len(line) <= 404 for line in lines[1:]))


if __name__ == "__main__":
    unittest.main()
