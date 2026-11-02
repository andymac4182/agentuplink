"""Pure C239 boundary regressions; no Docker, subprocess or network calls."""

import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import Mock


SPEC = importlib.util.spec_from_file_location(
    "redis_aof_headroom", Path(__file__).with_name("m6-redis-aof-headroom.py")
)
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class RespBoundaryTests(unittest.TestCase):
    def read(self, wire):
        return gate.RespReader(io.BytesIO(wire)).read()

    def test_real_nested_reply_and_redacted_error(self):
        self.assertEqual(self.read(b"*3\r\n+OK\r\n:16384\r\n$3\r\nxyz\r\n"), [b"OK", 16384, b"xyz"])
        error = self.read(b"-OOM synthetic-secret-must-not-be-retained\r\n")
        self.assertEqual(vars(error), {"code": "OOM"})

    def test_truncation_invalid_lengths_and_resource_bounds(self):
        cases = [
            b"+not-terminated", b"$3\r\nxy", b"$3\r\nxyz!!", b"*-2\r\n",
            b"*4097\r\n", b"$2097153\r\n", b"*1\r\n" * 10 + b"+OK\r\n",
            b"+" + b"x" * 4096 + b"\r\n", b":99999999999999999999999\r\n",
        ]
        for wire in cases:
            with self.subTest(prefix=wire[:16]):
                with self.assertRaises(gate.GateError):
                    self.read(wire)

    def test_batch_ceiling_precedes_any_write_and_oom_is_fatal(self):
        client = Mock()
        workload = gate.Workload(client, lambda: None)
        workload.wire_bytes = gate.MAX_INPUT_BYTES
        self.assertFalse(workload.write(["fixture-key"], b"data", False))
        client.batch.assert_not_called()
        workload.wire_bytes = 0
        client.batch.return_value = [b"OK", gate.RedisRefusal(b"OOM withheld-detail")]
        with self.assertRaises(gate.GateError):
            workload.write(["key-a", "key-b"], b"data", False)
        self.assertEqual((workload.acknowledged, workload.refused, workload.oom_refused), (1, 1, 1))


class ProvenanceAndLimitTests(unittest.TestCase):
    def image(self):
        return {"layers": ["base-a", "base-b", "copy-entrypoint"], "os": "linux",
                "architecture": "amd64", "entrypoint": ["/usr/local/bin/agentuplink-redis-entrypoint"]}

    def test_entire_pinned_base_prefix_is_required(self):
        base = {"layers": ["base-a", "base-b"], "architecture": "amd64"}
        gate.verify_layers(self.image(), base)
        for layers in (["base-a", "different", "copy-entrypoint"], ["base-a", "base-b"], []):
            image = self.image()
            image["layers"] = layers
            with self.assertRaises(gate.GateError):
                gate.verify_layers(image, base)
        for dockerfile in ("FROM redis:8.4.0-alpine\n", "FROM redis:latest\n"):
            with self.assertRaises(gate.GateError):
                gate.pinned_base(dockerfile)

    def info(self):
        return {"image": "expected-image", "running": True, "oom_killed": False,
                "memory": gate.MEMORY_LIMIT, "memory_swap": gate.MEMORY_LIMIT,
                "nano_cpus": 1_000_000_000, "pids_limit": 64,
                "ports": {"6379/tcp": [{"HostIp": "127.0.0.1", "HostPort": "32001"}]}}

    def test_different_limits_and_shared_or_public_port_refuse(self):
        self.assertEqual(gate.verify_container_limits(self.info(), "expected-image"), 32001)
        for field, value in (("memory_swap", -1), ("nano_cpus", 0), ("pids_limit", 0),
                             ("memory", 512 * gate.MIB), ("image", "other-image")):
            info = self.info()
            info[field] = value
            with self.assertRaises(gate.GateError):
                gate.verify_container_limits(info, "expected-image")
        for host, port in (("0.0.0.0", "32001"), ("127.0.0.1", "16379")):
            info = self.info()
            info["ports"]["6379/tcp"][0].update(HostIp=host, HostPort=port)
            with self.assertRaises(gate.GateError):
                gate.verify_container_limits(info, "expected-image")


class EvidenceTests(unittest.TestCase):
    def sample(self):
        return {"swap_current": 0, "events": {"oom": 0, "oom_kill": 0, "oom_group_kill": 0, "max": 100},
                "pids_events": {"max": 0}}

    def final(self):
        return {"aof_last_cow_size": 750, "aof_rewrite_in_progress": 0, "aof_rewrites": 1,
                "evicted_keys": 0, "rejected_connections": 0, "total_error_replies": 0}

    def test_cow_floor_rejects_prechurn_or_no_overlap_false_green(self):
        # A cache-reclaim max event alone is not an OOM: the passing baseline
        # intentionally includes one while preserving the true CoW evidence.
        gate.validate_success(self.final(), self.sample(), [self.sample()], 1000, 100, 100, 0)
        for cow in (0, 749):
            final = self.final()
            final["aof_last_cow_size"] = cow
            with self.assertRaises(gate.GateError):
                gate.validate_success(final, self.sample(), [], 1000, 100, 100, 0)
        with self.assertRaises(gate.GateError):
            gate.validate_success(self.final(), self.sample(), [], 1000, 99, 100, 0)

    def test_any_oom_or_refusal_fails_even_with_enough_cow(self):
        for field in ("oom", "oom_kill", "oom_group_kill"):
            failed = self.sample()
            failed["events"][field] = 1
            with self.assertRaises(gate.GateError):
                gate.validate_success(self.final(), self.sample(), [failed], 1000, 100, 100, 0)
        with self.assertRaises(gate.GateError):
            gate.validate_success(self.final(), self.sample(), [], 1000, 100, 100, 1)

    def test_failed_finally_resume_preserves_the_original_failure(self):
        container = Mock()
        container.token = "a" * 32
        controller = gate.RewriteChild(container)
        controller.process = Mock()
        original = gate.GateError("original observer failure")
        controller.resume = Mock(side_effect=original)
        container.exec.side_effect = gate.GateError("fallback refused identity")
        with self.assertRaises(gate.GateError) as caught:
            controller.cleanup()
        self.assertIs(caught.exception.__cause__, original)
        self.assertIn("also failed", str(caught.exception))

    def test_late_cleanup_cannot_pass_or_replace_an_original_failure(self):
        at_bound = {"errors": [], "cleaned_owned_container": True}
        gate.finalize_result(at_bound, True, 180.0)
        self.assertTrue(at_bound["passed"])
        late = {"errors": [], "cleaned_owned_container": True}
        gate.finalize_result(late, True, 180.001)
        self.assertFalse(late["passed"])
        self.assertEqual(late["errors"][0]["stage"], "whole_trial_deadline")
        original = {"stage": "paused_churn", "error": "original failure"}
        failed = {"errors": [original], "cleaned_owned_container": True}
        gate.finalize_result(failed, False, 181)
        self.assertIs(failed["errors"][0], original)
        self.assertEqual(len(failed["errors"]), 2)
        self.assertFalse(failed["passed"])


if __name__ == "__main__":
    unittest.main()
