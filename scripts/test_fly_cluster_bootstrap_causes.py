#!/usr/bin/env python3
"""Pure closed bootstrap-cause controls, with source vocabulary binding."""

import importlib.util
import json
from pathlib import Path
import re
import unittest

SPEC = importlib.util.spec_from_file_location("cause_rehearsal", Path(__file__).with_name("fly_cluster_rehearsal.py"))
r = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(r)
ROOT = Path(__file__).resolve().parents[1]
BASE = b"tunnel-relay: cluster membership bootstrap did not reach ready: readiness=unready reason=membership_rejected category=membership"


class BootstrapCauses(unittest.TestCase):
    def observe(self, suffix=b"", newline=True):
        return r.relay_terminal_observation(BASE + suffix + (b"\n" if newline else b""))

    def test_all_new_codes_and_cleanup_are_exact_closed_observations(self):
        self.assertEqual(len(set(r.RELAY_BOOTSTRAP_CAUSES)), len(r.RELAY_BOOTSTRAP_CAUSES))
        for cause in r.RELAY_BOOTSTRAP_CAUSES:
            for cleanup in (None, *r.RELAY_SHUTDOWN_REASONS):
                suffix = " bootstrap_cause=" + cause
                if cleanup:
                    suffix += "; cleanup=membership_shutdown_failed reason=" + cleanup
                with self.subTest(cause=cause, cleanup=cleanup):
                    value = self.observe(suffix.encode())
                    self.assertEqual(value["recognized_lines"], 1)
                    self.assertEqual(value["unrecognized_terminal_lines"], 0)
                    self.assertEqual(value["observations"][0]["bootstrap_cause"], cause)
                    self.assertEqual(value["observations"][0].get("cleanup_reason"), cleanup)
                    self.assertEqual(value["lifecycle_attribution"], "none")

    def test_old_output_does_not_fabricate_initial_cause(self):
        value = self.observe()
        self.assertEqual(value["recognized_lines"], 1)
        self.assertNotIn("bootstrap_cause", value["observations"][0])
        self.assertEqual(value["lifecycle_attribution"], "none")

    def test_equal_record_checkpoint_and_signature_causes_are_distinct(self):
        codes = ["membership_equal_version_conflict", "membership_checkpoint_equal_version_conflict", "membership_signature_invalid"]
        lines = b"".join(BASE + b" bootstrap_cause=" + code.encode() + b"\n" for code in codes)
        value = r.relay_terminal_observation(lines)
        self.assertEqual({x["bootstrap_cause"] for x in value["observations"]}, set(codes))
        self.assertEqual(value["lifecycle_attribution"], "none")

    def test_unknown_partial_dynamic_and_extra_fields_remain_unclassified(self):
        suffixes = [b" bootstrap_cause=PRIVATE_TOKEN", b" bootstrap_cause=membership_equal_version_conflict version=4",
                    b" bootstrap_cause=membership_equal_version_conflict; PRIVATE_TOKEN",
                    b" bootstrap_cause=runtime_join bootstrap_cause=runtime_join", b" bootstrap_cause=runtime_join ",
                    b" bootstrap_cause=initial_ok; cleanup=membership_shutdown_failed reason=PRIVATE_TOKEN",
                    b" bootstrap_cause=runtime_join\xff"]
        for suffix in suffixes:
            with self.subTest(suffix=suffix):
                value = self.observe(suffix)
                self.assertEqual(value["observations"], [])
                self.assertEqual(value["unrecognized_terminal_lines"], 1)
                self.assertNotIn("PRIVATE_TOKEN", json.dumps(value))
        value = self.observe(b" bootstrap_cause=runtime_join", newline=False)
        self.assertEqual(value["observations"], [])
        self.assertEqual(value["incomplete_terminal_lines"], 1)

    def test_vocabulary_is_exact_exhaustive_rust_mapping_plus_initial_ok(self):
        runtime = (ROOT / "crates/tunnel-relay/src/membership_runtime.rs").read_text()
        mapping = runtime.split("impl From<&MembershipRuntimeError> for MembershipBootstrapFailure {", 1)[1].split("/// A cancellable, joined", 1)[0]
        codes = re.findall(r'"([a-z_]+)"', mapping)
        self.assertEqual(len(codes), len(set(codes)))
        self.assertEqual(set(r.RELAY_BOOTSTRAP_CAUSES), {"initial_ok", *codes})
        self.assertNotRegex(mapping, r"format!|to_string|error\.fmt|error\.code|_\s*=>")
        enum = (ROOT / "crates/tunnel-cluster/src/membership.rs").read_text().split("pub enum MembershipError {", 1)[1].split("impl fmt::Display for MembershipError", 1)[0]
        variants = set(re.findall(r"^    ([A-Z][A-Za-z]+)(?:[,(]| \{)", enum, re.MULTILINE))
        arms = set(re.findall(r"MembershipError::([A-Za-z]+)", mapping))
        self.assertEqual(variants, arms)
        main = (ROOT / "crates/tunnel-relay/src/main.rs").read_text()
        self.assertIn('message.push_str(" bootstrap_cause=");', main)
        self.assertIn('bootstrap_failure.map_or("initial_ok", MembershipBootstrapFailure::code)', main)


if __name__ == "__main__":
    unittest.main()
