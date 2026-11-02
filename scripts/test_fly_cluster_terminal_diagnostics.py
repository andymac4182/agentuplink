#!/usr/bin/env python3
"""Closed relay diagnostics: synthetic bytes and source reads only."""

import importlib.util
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("rehearsal", Path(__file__).with_name("fly_cluster_rehearsal.py"))
rehearsal = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rehearsal)
ROOT = Path(__file__).resolve().parents[1]
PREFIX = b"tunnel-relay: "
BOOTSTRAP = "cluster membership bootstrap did not reach ready: readiness={} reason={} category={}"


class TerminalDiagnostics(unittest.TestCase):
    def receipt(self, data, **kwargs):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "output"
            path.write_bytes(data)
            return rehearsal.safe_log_receipt(path, **kwargs)

    def observation(self, data):
        return self.receipt(data)["relay_terminal"]

    def test_actual_bootstrap_terminal_is_retained_as_closed_observation(self):
        raw = PREFIX + BOOTSTRAP.format("unready", "unknown_authority", "authority").encode() + b"\n"
        expected = {"code": "membership_bootstrap_not_ready", "readiness": "unready",
                    "reason": "unknown_authority", "category": "authority"}
        self.assertEqual(self.receipt(raw).get("relay_terminal", {}).get("observations"), [expected])

    def test_actual_state_open_terminal_is_retained_as_closed_observation(self):
        raw = PREFIX + b"membership state is already open\n"
        self.assertEqual(self.receipt(raw).get("relay_terminal", {}).get("observations"),
                         [{"code": "membership_state_busy"}])

    def test_all_static_messages_are_exact_and_finite(self):
        for message, code in rehearsal.RELAY_TERMINAL_LITERALS.items():
            with self.subTest(code=code):
                value = self.observation(PREFIX + message.encode() + b"\n")
                self.assertEqual(value["observations"], [{"code": code}])
                self.assertEqual(value["recognized_lines"], 1)
                self.assertEqual(value["unrecognized_terminal_lines"], 0)
                self.assertEqual(value["lifecycle_attribution"], "none")

    def test_all_bootstrap_tuples_and_cleanup_reasons(self):
        for state, reason, category in rehearsal.RELAY_BOOTSTRAP_TUPLES:
            for cleanup in (None, *rehearsal.RELAY_SHUTDOWN_REASONS):
                with self.subTest(state=state, reason=reason, cleanup=cleanup):
                    body = BOOTSTRAP.format(state, reason, category)
                    expected = {"code": "membership_bootstrap_not_ready", "readiness": state,
                                "reason": reason, "category": category}
                    if cleanup is not None:
                        body += "; cleanup=membership_shutdown_failed reason=" + cleanup
                        expected["cleanup_reason"] = cleanup
                    self.assertEqual(self.observation(PREFIX + body.encode() + b"\n")["observations"], [expected])

    def test_observation_cardinality_is_the_finite_source_vocabulary(self):
        lines = [PREFIX + text.encode() + b"\n" for text in rehearsal.RELAY_TERMINAL_LITERALS]
        for state, reason, category in rehearsal.RELAY_BOOTSTRAP_TUPLES:
            base = BOOTSTRAP.format(state, reason, category)
            lines.append(PREFIX + base.encode() + b"\n")
            for cleanup in rehearsal.RELAY_SHUTDOWN_REASONS:
                lines.append(PREFIX + (base + "; cleanup=membership_shutdown_failed reason=" + cleanup).encode() + b"\n")
        value = self.observation(b"".join(lines + lines))
        self.assertEqual(len(lines), 159)
        self.assertEqual(len(value["observations"]), 159)
        self.assertEqual(value["recognized_lines"], 318)
        self.assertEqual(value["unrecognized_terminal_lines"], 0)

    def test_invalid_bootstrap_combinations_remain_unknown(self):
        for triple in [("ready", "unknown_authority", "authority"), ("unready", "starting", "bootstrap"),
                       ("unready", "persistence_unavailable", "authority"), ("unready", "unknown", "authority")]:
            raw = PREFIX + BOOTSTRAP.format(*triple).encode() + b"\n"
            value = self.observation(raw)
            self.assertEqual(value["observations"], [])
            self.assertEqual(value["unrecognized_terminal_lines"], 1)
        body = BOOTSTRAP.format("unready", "unknown_authority", "authority")
        for suffix in ["; cleanup=membership_shutdown_failed reason=PRIVATE_TOKEN", "; cleanup=other reason=join",
                       "; cleanup=membership_shutdown_failed reason=join trailing"]:
            self.assertEqual(self.observation(PREFIX + (body + suffix).encode() + b"\n")["observations"], [])

    def test_full_lines_reject_substrings_whitespace_ansi_and_unicode(self):
        line = PREFIX + b"membership state is already open"
        for data in [b"prefix " + line + b"\n", line + b" PRIVATE_TOKEN\n", b" " + line + b"\n",
                     line + b" \n", b"\x1b[31m" + line + b"\n", line + b"\x1b[0m\n",
                     line + b"\r\r\n", line.replace(b"state", b"sta\rte") + b"\n",
                     b"PRIVATE_TOKEN\xe2\x80\xa8" + line + b"\n", line + b"\xe2\x80\xa8\n",
                     b'{"message":"' + line + b'"}\n', line + b"\xff\n"]:
            with self.subTest(data=data):
                self.assertEqual(self.observation(data)["observations"], [])

    def test_partial_line_is_not_a_terminal_observation(self):
        raw = PREFIX + b"membership state is already open"
        value = self.observation(raw)
        self.assertEqual(value["observations"], [])
        self.assertEqual(value["incomplete_terminal_lines"], 1)
        self.assertEqual(value["recognized_lines"], 0)

    def test_lf_and_single_crlf_match(self):
        for ending in [b"\n", b"\r\n"]:
            self.assertEqual(self.observation(PREFIX + b"membership state is already open" + ending)["observations"],
                             [{"code": "membership_state_busy"}])

    def test_dynamic_details_remain_unknown(self):
        for body in [b"unsupported membership state schema 2", b"membership state exceeds 12 bytes (received 14)",
                     b"checkpoint authority returned HTTP 503", b"Permission denied (os error 13)",
                     b"Redis catalog connection failed; stage=ping class=io", b"unknown PRIVATE_TOKEN"]:
            value = self.observation(PREFIX + body + b"\n")
            self.assertEqual(value["observations"], [])
            self.assertEqual(value["unrecognized_terminal_lines"], 1)
            self.assertNotIn("PRIVATE_TOKEN", json.dumps(value))

    def test_mixed_historical_lines_are_deduplicated_without_attribution(self):
        a = PREFIX + b"membership state is already open\n"
        b = PREFIX + b"membership state is missing\n"
        raw = a + b"old log PRIVATE_TOKEN\n" + b + a + PREFIX + b"unknown PRIVATE_TOKEN\n" + a[:-1]
        value = self.observation(raw)
        self.assertEqual(value["recognized_lines"], 3)
        self.assertEqual(value["unrecognized_terminal_lines"], 1)
        self.assertEqual(value["incomplete_terminal_lines"], 1)
        self.assertEqual(value["observations"], [{"code": "membership_state_busy"}, {"code": "membership_state_missing"}])
        self.assertEqual(value["lifecycle_attribution"], "none")
        self.assertNotIn("PRIVATE_TOKEN", json.dumps(value))

    def test_whole_input_hash_and_old_client_docker_fields_preserved(self):
        raw = b'{"error":{"code":"CREDENTIAL_ERROR","message":"PRIVATE_TOKEN"}}\n'
        raw += PREFIX + b"membership state is already open\n"
        value = self.receipt(raw, docker=True)
        self.assertEqual(value["bytes"], len(raw))
        self.assertEqual(value["sha256"], rehearsal.digest(raw))
        self.assertEqual(value["closed_codes"], ["CREDENTIAL_ERROR"])
        self.assertEqual(value["cause_classification"], "closed_code")
        self.assertEqual(value["docker_error"], rehearsal.closed_docker_error(raw))
        self.assertFalse(value["raw_uploaded"])
        self.assertNotIn("PRIVATE_TOKEN", json.dumps(value))

    def test_input_bound_refuses_parsing_and_claiming_line_counts(self):
        with mock.patch.object(rehearsal, "MAX_OUTPUT", 32):
            value = self.receipt(PREFIX + b"membership state is already open\n")
        self.assertTrue(value["output_bound_exceeded"])
        self.assertIsNone(value["sha256"])
        self.assertFalse(value["relay_terminal"]["scanned"])
        self.assertIsNone(value["relay_terminal"]["recognized_lines"])
        self.assertIsNone(value["relay_terminal"]["unrecognized_terminal_lines"])
        self.assertIsNone(value["relay_terminal"]["incomplete_terminal_lines"])
        self.assertEqual(value["relay_terminal"]["observations"], [])

    def test_empty_and_unrelated_logs_have_no_terminal_observation(self):
        for raw in [b"", b"ordinary log\n", b"unrelated partial"]:
            value = self.observation(raw)
            self.assertTrue(value["scanned"])
            self.assertEqual(value["recognized_lines"], 0)
            self.assertEqual(value["unrecognized_terminal_lines"], 0)
            self.assertEqual(value["incomplete_terminal_lines"], 0)
            self.assertEqual(value["observations"], [])

    def test_literal_vocabulary_is_bound_to_exact_static_display_source(self):
        families = [("membership_version_state.rs", "MembershipVersionStateStoreError", "membership_state"),
                    ("membership_runtime.rs", "MembershipRuntimeError", "membership_runtime"),
                    ("membership_runtime.rs", "CheckpointAuthorityError", "checkpoint_authority"),
                    ("membership_runtime.rs", "MembershipSourceError", "membership_source")]
        found = {}
        for file, name, prefix in families:
            text = (ROOT / "crates/tunnel-relay/src" / file).read_text()
            body = text.split("impl fmt::Display for " + name + " {", 1)[1].split("impl Error for " + name, 1)[0]
            entries = re.findall(r'Self::(\w+)\s*=>\s*(?:\{\s*)?formatter\.write_str\(\s*"([^"]+)"\s*\)', body)
            self.assertTrue(entries, name)
            for variant, literal in entries:
                code = prefix + "_" + re.sub(r"(?<!^)(?=[A-Z])", "_", variant).lower()
                self.assertNotIn(literal, found)
                found[literal] = code
        main = (ROOT / "crates/tunnel-relay/src/main.rs").read_text()
        for literal, code in [("membership state load task failed", "membership_state_load_task_failed"),
                              ("cluster membership contains no approved peer keys", "membership_no_approved_peer_keys")]:
            self.assertEqual(main.count('"' + literal + '"'), 1)
            found[literal] = code
        self.assertEqual(rehearsal.RELAY_TERMINAL_LITERALS, found)
        self.assertIn('eprintln!("tunnel-relay: {error}");', main)

    def test_bootstrap_template_tuples_and_cleanup_bound_to_source(self):
        main = (ROOT / "crates/tunnel-relay/src/main.rs").read_text()
        runtime = (ROOT / "crates/tunnel-relay/src/membership_runtime.rs").read_text()
        self.assertIn('"cluster membership bootstrap did not reach ready: readiness={readiness_state} reason={reason} category={category}"', main)
        self.assertIn('"; cleanup=membership_shutdown_failed reason={}"', main)
        body = main.split("fn membership_readiness_code(", 1)[1].split("fn membership_shutdown_code(", 1)[0]
        reasons = runtime.split("impl MembershipUnreadyReason {", 1)[1].split("    /// Whether", 1)[0]
        reason_codes = dict(re.findall(r'Self::(\w+) => "([a-z_]+)"', reasons))
        categories = re.findall(r'((?:MembershipUnreadyReason::\w+\s*\|?\s*)+) => "([a-z_]+)"', body)
        expected = {("starting", "starting", "bootstrap"), ("ready", "ready", "bootstrap")}
        self.assertIn('MembershipReadiness::Starting => ("starting", readiness.code(), "bootstrap")', body)
        self.assertIn('MembershipReadiness::Ready => ("ready", readiness.code(), "bootstrap")', body)
        for variants, category in categories:
            for variant in re.findall(r'MembershipUnreadyReason::(\w+)', variants):
                expected.add(("unready", reason_codes[variant], category))
        self.assertEqual(len(reason_codes), 8)
        self.assertEqual({variant for variants, _ in categories
                          for variant in re.findall(r'MembershipUnreadyReason::(\w+)', variants)}, set(reason_codes))
        readiness = runtime.split("impl MembershipReadiness {", 1)[1].split("impl MembershipUnreadyReason {", 1)[0]
        self.assertIn('Self::Starting => "starting"', readiness)
        self.assertIn('Self::Ready => "ready"', readiness)
        self.assertEqual(len(expected), 10)
        self.assertEqual(set(rehearsal.RELAY_BOOTSTRAP_TUPLES), expected)
        shutdown = main.split("fn membership_shutdown_code(", 1)[1].split("/// Reconcile", 1)[0]
        self.assertEqual(set(rehearsal.RELAY_SHUTDOWN_REASONS), set(re.findall(r'=> "([a-z_]+)"', shutdown)))


if __name__ == "__main__":
    unittest.main()
