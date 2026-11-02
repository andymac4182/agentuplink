#!/usr/bin/env python3
"""Pure witness diagnostics; no harness, child process, Redis or network."""

import contextlib
import hashlib
import importlib.util
import io
import json
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
    def run_record(self, *, exit_code=1, error="", stderr=None):
        sentinels = {
            kind: [("synthetic-recorded-" + kind).encode()]
            for kind in SCAN.KIND_ORDER
        }
        if stderr is None:
            stderr = b"assertion failed: synthetic-unrecorded-payload\n"
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

    def diagnostic(self, run):
        lines = SCAN.witness_failure_diagnostics(run)
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith("failed witness child: "))
        return json.loads(lines[0].removeprefix("failed witness child: "))

    def test_unrecorded_key_body_and_payload_are_withheld_with_recorded_values(self):
        run = self.run_record()
        key_body = b"synthetic-unrecorded-key-body-ONLY-A-TEST"
        payload = b"synthetic-unrecorded-payload-ONLY-A-TEST"
        data = (b"-----BEGIN " + b"PRIVATE KEY-----\n" + key_body
                + b"\n-----END " + b"PRIVATE KEY-----\n" + payload + b"\n"
                + b"\n".join(value for values in run.sentinels.values() for value in values)
                + b"\nassertion failed: private detail\n")
        run.streams["harness_stderr"] = data
        output = "\n".join(SCAN.witness_failure_diagnostics(run))
        for value in [key_body, payload, b"private detail", *[v for vs in run.sentinels.values() for v in vs]]:
            self.assertNotIn(value.decode(), output)
        result = self.diagnostic(run)
        self.assertTrue(result["raw_stderr_withheld"])
        self.assertEqual(result["codes"], ["assertion_failure"])
        self.assertEqual(result["stderr_bytes"], len(data))
        self.assertEqual(result["stderr_sha256"], hashlib.sha256(data).hexdigest())

    def test_unreadable_capture_never_prints_its_error_or_child_text(self):
        run = self.run_record(error="synthetic-unrecorded-sensitive-error")
        result = self.diagnostic(run)
        self.assertEqual(result["classification"], "capture_incomplete")
        self.assertEqual(result["codes"], [])
        output = json.dumps(result)
        self.assertNotIn(run.error, output)
        self.assertNotIn("synthetic-unrecorded-payload", output)

    def test_missing_required_domain_retains_the_incomplete_capture_guard(self):
        run = self.run_record()
        run.sentinels["credential"] = []
        result = self.diagnostic(run)
        self.assertEqual(result["classification"], "capture_incomplete")
        self.assertEqual(result["codes"], [])

    def test_successful_child_adds_no_failure_diagnostic(self):
        self.assertEqual(SCAN.witness_failure_diagnostics(self.run_record(exit_code=0)), [])

    def test_failed_child_remains_wrong_witness_even_with_the_declared_hit(self):
        run = self.run_record()
        run.hits = [SCAN.Hit("application_payload", "harness_stderr", 0, True)]
        before = SCAN.classify_witness(run)
        self.assertEqual(before, "WRONG WITNESS (the planted child exited 1)")
        self.diagnostic(run)
        self.assertEqual(SCAN.classify_witness(run), before)

    def test_failed_child_main_prints_closed_diagnostic_and_stays_failed(self):
        run = self.run_record()
        output = io.StringIO()
        argv = ["m0-payload-scan.py", "--witness-only", "--gate", run.gate.command,
                "--harness", sys.executable]
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
        self.assertIn("failed witness child: ", text)
        self.assertIn('"raw_stderr_withheld": true', text)
        self.assertIn('"codes": ["assertion_failure"]', text)
        self.assertIn("witnesses=0/1 RED", text)
        self.assertNotIn("synthetic-unrecorded-payload", text)

    def test_classification_is_tail_bounded_but_digest_covers_all_stderr(self):
        data = b"connection refused\n" + b"x" * 16_384 + b"\nassertion failed\n"
        result = self.diagnostic(self.run_record(stderr=data))
        self.assertEqual(result["codes"], ["assertion_failure"])
        self.assertEqual(result["classified_bytes"], 16_384)
        self.assertEqual(result["classification_scope"], "tail")
        self.assertEqual(result["stderr_bytes"], len(data))
        self.assertEqual(result["stderr_sha256"], hashlib.sha256(data).hexdigest())

    def test_unknown_binary_or_arbitrary_text_is_unclassified_and_withheld(self):
        for data in (b"\xff\x00synthetic-unrecorded-payload", b"synthetic-arbitrary-error"):
            with self.subTest(size=len(data)):
                result = self.diagnostic(self.run_record(stderr=data))
                self.assertEqual(result["classification"], "unclassified")
                self.assertTrue(result["raw_stderr_withheld"])
                self.assertEqual(result["codes"], [])
                self.assertEqual(result["stderr_sha256"], hashlib.sha256(data).hexdigest())

    def test_missing_stderr_is_distinct_from_an_empty_captured_stream(self):
        empty = self.diagnostic(self.run_record(stderr=b""))
        self.assertEqual(empty["stderr_bytes"], 0)
        self.assertEqual(empty["stderr_sha256"], hashlib.sha256(b"").hexdigest())
        self.assertEqual(empty["classification"], "unclassified")
        run = self.run_record()
        run.streams.clear()
        missing = self.diagnostic(run)
        self.assertIsNone(missing["stderr_bytes"])
        self.assertIsNone(missing["stderr_sha256"])
        self.assertEqual(missing["classification"], "stderr_unavailable")

    def test_capture_bound_is_not_silently_replaced_with_a_prefix_digest(self):
        with mock.patch.object(SCAN, "MAX_STREAM_BYTES", 4):
            result = self.diagnostic(self.run_record(stderr=b"12345"))
        self.assertEqual(result["stderr_bytes"], 5)
        self.assertIsNone(result["stderr_sha256"])
        self.assertEqual(result["classification"], "stderr_over_bound")
        self.assertEqual(result["classified_bytes"], 0)
        self.assertEqual(result["codes"], [])

    def test_fixed_vocabulary_never_emits_the_matching_line_or_a_claimed_cause(self):
        cases = {
            b"assertion failed: private": "assertion_failure",
            b"thread 'private' panicked at private": "rust_panic",
            b"private deadline exceeded private": "deadline_exceeded",
            b"private timed out private": "timeout",
            b"private connection refused private": "connection_refused",
            b"private permission denied private": "permission_denied",
        }
        for data, code in cases.items():
            with self.subTest(code=code):
                result = self.diagnostic(self.run_record(stderr=data))
                self.assertEqual(result["codes"], [code])
                self.assertEqual(result["classification"], "matched_vocabulary")
                self.assertNotIn("private", json.dumps(result))
                self.assertLess(len(json.dumps(result)), 700)


if __name__ == "__main__":
    unittest.main()
