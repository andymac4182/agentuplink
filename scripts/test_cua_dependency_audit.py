#!/usr/bin/env python3
"""Offline C259 refusal controls: synthetic locks/feed, no network or package code."""
import copy
import datetime as dt
import importlib.util
import json
from pathlib import Path
import signal
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("cua_audit", Path(__file__).with_name("cua-dependency-audit.py"))
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)
NOW = dt.datetime(2026, 11, 2, tzinfo=dt.timezone.utc)
MODIFIED = "2026-10-30T00:00:00Z"
H1, H2 = "1" * 64, "2" * 64
LINUX, MAC, BUILD = audit.SCOPES


def locked(value, hashes=(H1,)):
    return value + "".join(" --hash=sha256:" + item for item in hashes) + "\n"


def fixture():
    inputs = {
        LINUX: locked("cua-computer-server==1.0.0", (H1, H2)) + locked('Demo_Package==1.0.0; sys_platform == "impossible"'),
        MAC: locked("cua-computer-server==1.0.0", (H1, H2)) + locked("demo-package==1.0.0") + locked("pyobjc-core==1.0.0"),
        BUILD: locked("setuptools==1.0.0"),
        audit.ROOT_IN: "cua-computer-server[driver,vnc]==1.0.0\n",
        audit.BUILD_IN: "setuptools>=1.0.0\n",
        audit.MAC_IN: "pyobjc-core==1.0.0\n",
        audit.PIN: "\n".join('pub const ' + key + ': &str = "' + value + '";' for key, value in {
            "DISTRIBUTION": "cua-computer-server", "VERSION": "1.0.0", "WHEEL_SHA256": H1, "SDIST_SHA256": H2}.items()),
        audit.TOOL_LOCK: locked("packaging==26.3"),
    }
    scopes = copy.deepcopy(audit.SCOPES)
    for path, count in ((LINUX, 2), (MAC, 3), (BUILD, 1)):
        scopes[path]["count"] = count
    return {path: data.encode() for path, data in inputs.items()}, scopes


def advisory(**updates):
    result = {"id": "GHSA-aaaa-bbbb-cccc", "modified": MODIFIED, "published": "2026-10-01T00:00:00Z",
              "aliases": ["CVE-2026-12345"], "database_specific": {"severity": "LOW"},
              "affected": [{"package": {"ecosystem": "PyPI", "name": "Demo_Package"},
                            "versions": ["1.0.0"], "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.1.0"}]}]}]}
    result.update(updates)
    return result


class FakeBudget:
    def __init__(self, _directory):
        self.bytes = 0
        self.minimum_free = self.minimum_memory = 8 * 1024**3
        self.oom_before = self.oom_last = {"oom": 0, "oom_kill": 0, "oom_group_kill": 0}
    def check(self, force=False):
        pass
    def account(self, size):
        self.bytes += size


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.inputs, self.scopes = fixture()
    def parse(self):
        return audit.source_scope(self.inputs, self.scopes, 1)
    def rejects(self, reason):
        with self.assertRaisesRegex(audit.AuditError, reason):
            self.parse()
    def test_all_three_complete_scopes_and_false_host_marker_preserved(self):
        records, _ = self.parse()
        self.assertEqual(len(records), 6)
        self.assertEqual(len({(r["name"], r["version"]) for r in records}), 4)
        self.assertIn('sys_platform == "impossible"', [r["marker"] for r in records])
    def test_scope_order_does_not_choose_runtime_locks(self):
        self.scopes = dict(reversed(list(self.scopes.items())))
        self.assertEqual(len(self.parse()[0]), 6)
    def test_missing_lock_scope(self):
        del self.scopes[BUILD]
        self.rejects("complete-three-lock")
    def test_unexpected_lock_scope(self):
        self.scopes["extra.lock"] = self.scopes[BUILD]
        self.rejects("complete-three-lock")
    def test_omitted_locked_record(self):
        self.inputs[LINUX] = locked("cua-computer-server==1.0.0", (H1, H2)).encode()
        self.rejects("scope-count-changed")
    def test_no_hash(self):
        self.inputs[BUILD] = b"setuptools==1.0.0\n"
        self.rejects("missing-or-invalid-lock-hash")
    def test_bad_hash(self):
        self.inputs[BUILD] = locked("setuptools==1.0.0", ("not-a-digest",)).encode()
        self.rejects("missing-or-invalid-lock-hash")
    def test_duplicate_hash(self):
        self.inputs[BUILD] = locked("setuptools==1.0.0", (H1, H1)).encode()
        self.rejects("duplicate-lock-hash")
    def test_unpinned_requirement(self):
        self.inputs[BUILD] = locked("setuptools>=1.0.0").encode()
        self.rejects("nonexact-lock-pin")
    def test_direct_url_requirement(self):
        self.inputs[BUILD] = locked("setuptools @ https://example.invalid/x.whl").encode()
        self.rejects("url-requirement-not-supported")
    def test_duplicate_package_marker_record(self):
        self.inputs[LINUX] += locked('demo-package==1.0.0; sys_platform == "impossible"').encode()
        self.rejects("duplicate-lock-record")
    def test_root_version_drift(self):
        self.inputs[audit.ROOT_IN] = b"cua-computer-server[driver,vnc]==1.0.1"
        self.rejects("server-root-input-drift")
    def test_server_lock_artifact_drift(self):
        self.inputs[MAC] = self.inputs[MAC].replace(H2.encode(), b"3" * 64)
        self.rejects("server-lock-artifact-binding-mismatch")
    def test_framework_omitted_from_lock(self):
        self.inputs[MAC] = self.inputs[MAC].replace(b"pyobjc-core", b"different-package")
        self.rejects("darwin-framework-lock-entry-missing")
    def test_unknown_build_scope(self):
        self.inputs[audit.BUILD_IN] = b"other>=1.0.0"
        self.rejects("unknown-build-input-scope")
    def test_build_input_drift(self):
        self.inputs[audit.BUILD_IN] = b"setuptools>=2.0.0"
        self.rejects("build-lock-input-mismatch")
    def test_parser_lock_drift(self):
        self.inputs[audit.TOOL_LOCK] = locked("packaging==26.2").encode()
        self.rejects("parser-lock-mismatch")
    def test_current_full_source_scope_is_373_not_tool_inclusive_374(self):
        root = Path(__file__).resolve().parents[1]
        inputs = {p: audit.source_bytes(root, p) for p in (*audit.SCOPES, *audit.AUX_INPUTS)}
        records, server = audit.source_scope(inputs)
        self.assertEqual(len(records), 373)
        self.assertEqual(len({(r["name"], r["version"]) for r in records}), 270)
        self.assertEqual(server["VERSION"], "0.3.46")


class FeedTests(unittest.TestCase):
    def bind(self, doc):
        return audit.bind_advisory(doc, "GHSA-aaaa-bbbb-cccc", MODIFIED, {"name": "demo-package", "version": "1.0.0"}, NOW)
    def test_canonical_package_name_and_exact_version(self):
        self.assertEqual(self.bind(advisory())["status"], "active")
    def test_wrong_advisory_id(self):
        with self.assertRaisesRegex(audit.AuditError, "identity-mismatch"):
            self.bind(advisory(id="GHSA-other-id-xxxx"))
    def test_modified_drift(self):
        with self.assertRaisesRegex(audit.AuditError, "modified-during-query"):
            self.bind(advisory(modified="2026-10-31T00:00:00Z"))
    def test_actual_osv_batch_microsecond_detail_nanosecond_shape(self):
        self.assertTrue(audit.same_modified("2026-10-19T17:15:04.113194Z", "2026-10-19T17:15:04.113194208Z"))
    def test_changed_microsecond_or_date_not_precision_normalization(self):
        for value in ("2026-10-19T17:15:04.113195208Z", "2026-10-20T17:15:04.113194208Z", "2026-10-19T17:15:04.113193999Z"):
            with self.subTest(value=value):
                self.assertFalse(audit.same_modified("2026-10-19T17:15:04.113194Z", value))
    def test_other_precision_loss_not_silently_accepted(self):
        self.assertFalse(audit.same_modified("2026-10-19T17:15:04.113Z", "2026-10-19T17:15:04.113194208Z"))
        self.assertFalse(audit.same_modified("2026-10-19T17:15:04.113194208Z", "2026-10-19T17:15:04.113194Z"))
    def test_unzoned_or_reversed_timestamp_refused(self):
        for value in ("2026-10-01T00:00:00", "2026-10-31T00:00:00Z"):
            with self.subTest(value=value), self.assertRaises(audit.AuditError):
                self.bind(advisory(published=value))
    def test_wrong_package(self):
        doc = advisory()
        doc["affected"][0]["package"]["name"] = "other"
        with self.assertRaisesRegex(audit.AuditError, "does-not-bind"):
            self.bind(doc)
    def test_wrong_ecosystem(self):
        doc = advisory()
        doc["affected"][0]["package"]["ecosystem"] = "npm"
        with self.assertRaisesRegex(audit.AuditError, "does-not-bind"):
            self.bind(doc)
    def test_unaffected_version(self):
        doc = advisory()
        doc["affected"][0].update(versions=["2.0.0"], ranges=[])
        with self.assertRaisesRegex(audit.AuditError, "does-not-bind"):
            self.bind(doc)
    def test_unknown_range_even_when_explicit_version_matches(self):
        doc = advisory()
        doc["affected"][0]["ranges"][0]["type"] = "GIT"
        with self.assertRaisesRegex(audit.AuditError, "unknown-affected-range-type"):
            self.bind(doc)
    def test_invalid_explicit_version(self):
        doc = advisory()
        doc["affected"][0]["versions"].append("not-a-version")
        with self.assertRaises(ValueError):
            self.bind(doc)
    def test_valid_withdrawn_preserved(self):
        self.assertEqual(self.bind(advisory(withdrawn="2026-10-29T00:00:00Z"))["status"], "withdrawn")
    def test_nanosecond_withdrawal_after_modified_refused(self):
        modified = "2026-10-30T00:00:00.123456100Z"
        doc = advisory(modified=modified, withdrawn="2026-10-30T00:00:00.123456200Z")
        with self.assertRaisesRegex(audit.AuditError, "withdrawal"):
            audit.bind_advisory(doc, doc["id"], modified, {"name": "demo-package", "version": "1.0.0"}, NOW)
    def test_nanosecond_publication_after_modified_refused(self):
        modified = "2026-10-30T00:00:00.123456100Z"
        doc = advisory(modified=modified, published="2026-10-30T00:00:00.123456200Z")
        with self.assertRaisesRegex(audit.AuditError, "timestamp"):
            audit.bind_advisory(doc, doc["id"], modified, {"name": "demo-package", "version": "1.0.0"}, NOW)
    def test_nanosecond_modified_after_now_refused(self):
        modified = "2026-11-02T00:00:00.000000001Z"
        doc = advisory(modified=modified)
        with self.assertRaisesRegex(audit.AuditError, "timestamp"):
            audit.bind_advisory(doc, doc["id"], modified, {"name": "demo-package", "version": "1.0.0"}, NOW)
    def test_lossy_modified_binding_cannot_suppress_withdrawn(self):
        doc = advisory(modified="2026-10-30T00:00:00.123456200Z", withdrawn="2026-10-29T00:00:00Z")
        bound = audit.bind_advisory(doc, doc["id"], "2026-10-30T00:00:00.123456Z", {"name": "demo-package", "version": "1.0.0"}, NOW)
        self.assertEqual(bound["status"], "active")
        self.assertEqual(bound["withdrawal_binding"], "unverified-lossy-modified-binding")
    def test_malformed_and_unknown_offset_refused(self):
        for offset in ("+00:60", "+24:00", "-00:00"):
            with self.subTest(offset=offset), self.assertRaisesRegex(audit.AuditError, "timestamp"):
                audit.timestamp("2026-10-01T00:00:00" + offset)
    def test_invalid_withdrawal_refused(self):
        for value in ("bad", "2026-10-31T00:00:00Z", "2026-09-01T00:00:00Z"):
            with self.subTest(value=value), self.assertRaises(audit.AuditError):
                self.bind(advisory(withdrawn=value))
    def test_alias_duplicate_or_invalid(self):
        for aliases in (["CVE-2026-1"] * 2, ["../escape"], "CVE-2026-1"):
            with self.subTest(aliases=aliases), self.assertRaises(audit.AuditError):
                self.bind(advisory(aliases=aliases))
    def test_active_alias_not_hidden_by_withdrawn_record(self):
        a = self.bind(advisory())
        b = copy.deepcopy(a)
        b.update(id="PYSEC-2026-1", status="withdrawn")
        groups = audit.groups([a, b])
        self.assertEqual(len(groups), 1)
        self.assertTrue(groups[0]["active"])
        self.assertEqual(len(groups[0]["ids"]), 2)
    def test_range_endpoints(self):
        for kind, version, expected in (("fixed", "1.1", False), ("last_affected", "1.1", True), ("limit", "1.1", False)):
            with self.subTest(kind=kind):
                self.assertEqual(audit.range_match(version, {"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {kind: "1.1"}]}), expected)
    def test_unordered_reintroduced_zero_refused(self):
        with self.assertRaisesRegex(audit.AuditError, "unordered"):
            audit.range_match("1.0", {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.1"}, {"introduced": "0"}]})
    def test_unknown_or_unclosed_event_refused(self):
        for events in ([{"fixed": "1.1"}], [{"introduced": "0"}, {"introduced": "1"}], [{"introduced": "0"}, {"unknown": "1"}]):
            with self.subTest(events=events), self.assertRaises(audit.AuditError):
                audit.range_match("1.0", {"type": "ECOSYSTEM", "events": events})
    def test_batch_coverage_mismatch(self):
        with self.assertRaisesRegex(audit.AuditError, "coverage"):
            audit.batch_results({"results": []}, [{"name": "demo", "version": "1"}])
    def test_batch_pagination_unknown_scope(self):
        with self.assertRaisesRegex(audit.AuditError, "paginated"):
            audit.batch_results({"results": [{"next_page_token": "remaining"}]}, [{}])
    def test_batch_duplicate_advisory(self):
        item = {"id": "GHSA-aaaa-bbbb-cccc", "modified": MODIFIED}
        with self.assertRaisesRegex(audit.AuditError, "duplicate-batch"):
            audit.batch_results({"results": [{"vulns": [item, item]}]}, [{}])
    def test_duplicate_json_field(self):
        with self.assertRaisesRegex(audit.AuditError, "duplicate-json"):
            audit.json_data(b'{"results":[],"results":[]}')
    def test_nonfinite_json_number(self):
        with self.assertRaisesRegex(audit.AuditError, "nonfinite-json"):
            audit.json_data(b'{"results":NaN}')
    def test_overflow_json_number_refused(self):
        for value in (b'{"metadata":[{"value":1e999}]}', b'{"metadata":{"value":-1e999}}'):
            with self.subTest(value=value), self.assertRaisesRegex(audit.AuditError, "nonfinite-json"):
                audit.json_data(value)
    def test_finite_json_numbers_preserved(self):
        self.assertEqual(audit.json_data(b'{"metadata":[1.25,-2.5e2,3]}'), {"metadata": [1.25, -250.0, 3]})


class RunTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="c259-pure-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "source"
        self.root.mkdir()
        self.inputs, self.scopes = fixture()
        for path, data in self.inputs.items():
            destination = self.root / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        self.output = Path(self.temp.name) / "result"
        self.docs = []
        self.seen = []
    def feed(self, url, payload, budget):
        self.seen.append((url, payload))
        if url == audit.BATCH_URL:
            results = []
            for query in payload["queries"]:
                values = [{"id": d["id"], "modified": d["modified"]} for d in self.docs] if query["package"]["name"] == "demo-package" else []
                results.append({"vulns": values} if values else {})
            data = {"results": results}
        else:
            data = next(d for d in self.docs if url == audit.DETAIL_URL + d["id"])
        raw = json.dumps(data).encode()
        budget.account(len(raw))
        return raw
    def run_gate(self, feed=None):
        with patch.object(audit, "Budget", FakeBudget), patch.object(audit, "fetch", feed or self.feed):
            report = audit.run(self.root, self.output, scopes=self.scopes, framework_count=1)
        self.assertEqual(report, json.loads((self.output / "report.json").read_text()))
        return report
    def test_complete_zero_feed_pass_retains_request_response_hashes(self):
        report = self.run_gate()
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["counts"]["queries_covered"], 4)
        self.assertEqual(report["counts"]["lock_records"], 6)
        receipt = report["requests"][0]
        self.assertEqual(receipt["response_sha256"], audit.digest((self.output / "response-000.json").read_bytes()))
    def test_every_severity_including_low_and_unknown_fails(self):
        for severity in ("LOW", "MODERATE", "HIGH", "CRITICAL", "UNKNOWN"):
            with self.subTest(severity=severity):
                self.output = Path(self.temp.name) / severity
                self.docs = [advisory(database_specific={"severity": severity})]
                report = self.run_gate()
                self.assertEqual(report["status"], "failed")
                self.assertEqual(report["counts"]["active_advisory_records"], 1)
                self.assertEqual(report["errors"][0]["reason"], "active-known-advisory")
                self.assertEqual(len(report["advisories"][0]["occurrences"]), 2)
    def test_withdrawn_only_retained_not_active(self):
        self.docs = [advisory(withdrawn="2026-10-29T00:00:00Z")]
        report = self.run_gate()
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["counts"]["withdrawn_advisory_records"], 1)
    def test_binding_failure_retained_and_fails_complete_coverage(self):
        self.docs = [advisory(affected=[])]
        report = self.run_gate()
        self.assertEqual(report["status"], "failed")
        self.assertIn("incomplete-advisory-binding", str(report["errors"]))
        self.assertTrue((self.output / "response-001.json").is_file())
    def test_source_change_during_response_refused(self):
        def drift(*args):
            raw = self.feed(*args)
            (self.root / audit.ROOT_IN).write_text("changed\n")
            return raw
        report = self.run_gate(drift)
        self.assertEqual(report["status"], "failed")
        self.assertIn("source-input-changed", str(report["errors"]))
    def test_network_failure_preserved_no_retry(self):
        calls = []
        def failure(*args):
            calls.append(args)
            raise TimeoutError("synthetic socket deadline")
        report = self.run_gate(failure)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(len(calls), 1)
        self.assertEqual(report["requests"][0]["status"], "failed")
    def test_output_reuse_refused_before_network(self):
        self.output.mkdir()
        with self.assertRaises(FileExistsError):
            self.run_gate()
        self.assertEqual(self.seen, [])
    def test_source_symlink_refused_before_network(self):
        (self.root / audit.ROOT_IN).unlink()
        (self.root / audit.ROOT_IN).symlink_to(self.root / audit.BUILD_IN)
        report = self.run_gate()
        self.assertEqual(report["status"], "failed")
        self.assertIn("unsafe-source-input", str(report["errors"]))
        self.assertEqual(self.seen, [])
    def test_parser_version_mismatch_refused(self):
        with patch.object(audit.packaging, "__version__", "other"):
            report = self.run_gate()
        self.assertIn("parser-version-mismatch", str(report["errors"]))
        self.assertEqual(self.seen, [])
    def test_unapproved_endpoint_refused_before_open(self):
        with patch.object(audit.urllib.request, "build_opener") as opener:
            with self.assertRaisesRegex(audit.AuditError, "unapproved-feed-endpoint"):
                audit.fetch("https://example.invalid/", None, FakeBudget(None))
            opener.assert_not_called()
    def test_redirect_refused(self):
        with self.assertRaisesRegex(audit.AuditError, "redirect-refused"):
            audit.NoRedirect().redirect_request(None, None, 302, "", {}, "https://example.invalid/")
    def test_total_bytes_cap(self):
        budget = audit.Budget(Path(self.temp.name))
        with patch.object(budget, "check"), self.assertRaisesRegex(audit.AuditError, "total-response-byte-cap"):
            budget.account(audit.MAX_TOTAL + 1)
    def test_deadline_refused(self):
        budget = audit.Budget(Path(self.temp.name))
        budget.deadline = 0
        with self.assertRaisesRegex(audit.AuditError, "operation-deadline"):
            budget.check()
    def test_disk_floor_refused(self):
        budget = audit.Budget(Path(self.temp.name))
        with patch.object(audit.shutil, "disk_usage", return_value=type("Usage", (), {"free": audit.DISK_FLOOR - 1})()):
            with self.assertRaisesRegex(audit.AuditError, "disk-reserve"):
                budget.check(force=True)
    def test_response_cap_refused_with_bounded_reader(self):
        class Response:
            status = 200
            url = audit.DETAIL_URL + "GHSA-aaaa-bbbb-cccc"
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def read(self, size):
                self.test_size = size
                return b"x" * size
        response = Response()
        with patch.object(audit.urllib.request, "build_opener") as opener:
            opener.return_value.open.return_value = response
            with self.assertRaisesRegex(audit.AuditError, "response-byte-cap"):
                audit.fetch(response.url, None, FakeBudget(None))
        self.assertEqual(response.test_size, 64 * 1024)
    def test_memory_floor_refused(self):
        budget = audit.Budget(Path(self.temp.name))
        read = Path.read_text
        def contents(path, *args, **kwargs):
            if str(path) == "/proc/meminfo":
                return "MemAvailable: 1 kB\n"
            return read(path, *args, **kwargs)
        with patch.object(audit.shutil, "disk_usage", return_value=type("Usage", (), {"free": 8 * 1024**3})()), patch.object(Path, "read_text", contents):
            with self.assertRaisesRegex(audit.AuditError, "memory-reserve"):
                budget.check(force=True)
    def test_incomplete_batch_run_cannot_pass_zero_findings(self):
        report = self.run_gate(lambda *args: b'{"results":[]}')
        self.assertEqual(report["status"], "failed")
        self.assertIn("batch-query-coverage-mismatch", str(report["errors"]))
        self.assertEqual(report["counts"]["queries_covered"], 0)
    def simulated_blocked_http(self, block_at):
        data = json.dumps({"results": [{}] * 4}).encode()
        class Response:
            status = 200
            url = audit.BATCH_URL
            done = False
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def read(self, _size):
                if self.done:
                    return b""
                self.done = True
                if block_at == "read":
                    time.sleep(0.10)
                return data
        def blocked_open(*args, **kwargs):
            if block_at == "open":
                time.sleep(0.10)
            return Response()
        before = signal.getsignal(signal.SIGALRM)
        with patch.object(audit, "OBSERVATION_SECONDS", 0.02, create=True), patch.object(audit.urllib.request, "build_opener") as opener:
            opener.return_value.open.side_effect = blocked_open
            report = self.run_gate(audit.fetch)
        self.assertEqual(signal.getsignal(signal.SIGALRM), before)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        self.assertEqual(report["status"], "failed")
        self.assertIn("observation-deadline", str(report["errors"]))
        self.assertEqual(report["requests"][0]["status"], "failed")
        self.assertEqual(opener.return_value.open.call_count, 1)
    def test_deadline_interrupts_simulated_dns_open_headers(self):
        self.simulated_blocked_http("open")
    def test_deadline_interrupts_simulated_body_read(self):
        self.simulated_blocked_http("read")
    def test_occupied_timer_refused_before_network_without_cancelling_it(self):
        with patch.object(signal, "getitimer", return_value=(0.25, 0.0)), patch.object(signal, "setitimer") as setter:
            report = self.run_gate()
        self.assertEqual(report["status"], "failed")
        self.assertIn("occupied-observation-timer", str(report["errors"]))
        self.assertEqual(self.seen, [])
        setter.assert_not_called()
    def test_non_main_thread_refused_before_network(self):
        results = []
        def worker():
            results.append(self.run_gate())
        thread = threading.Thread(target=worker)
        thread.start()
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["status"], "failed")
        self.assertIn("main-thread", str(results[0]["errors"]))
        self.assertEqual(self.seen, [])
    def test_unlimited_cgroup_oom_delta_refused(self):
        budget = audit.Budget(Path(self.temp.name))
        state = {"oom": 0}
        contents = {
            "/proc/meminfo": "MemAvailable: 8388608 kB\n",
            "/sys/fs/cgroup/memory.max": "max\n",
        }
        def read(path, *args, **kwargs):
            if str(path) == "/sys/fs/cgroup/memory.events":
                return f"oom {state['oom']}\noom_kill {state['oom']}\noom_group_kill 0\n"
            return contents[str(path)]
        def is_file(path):
            return str(path) in (*contents, "/sys/fs/cgroup/memory.events")
        with patch.object(audit.shutil, "disk_usage", return_value=type("Usage", (), {"free": 8 * 1024**3})()), patch.object(Path, "read_text", read), patch.object(Path, "is_file", is_file):
            budget.check(force=True)
            state["oom"] = 1
            with self.assertRaisesRegex(audit.AuditError, "oom-counter-increase"):
                budget.check(force=True)
    def test_existing_cgroup_without_oom_counters_refused(self):
        budget = audit.Budget(Path(self.temp.name))
        values = {"/proc/meminfo": "MemAvailable: 8388608 kB\n", "/sys/fs/cgroup/memory.max": "max\n"}
        with patch.object(audit.shutil, "disk_usage", return_value=type("Usage", (), {"free": 8 * 1024**3})()), patch.object(Path, "read_text", lambda p, **kw: values[str(p)]), patch.object(Path, "is_file", lambda p: str(p) in values):
            with self.assertRaisesRegex(audit.AuditError, "oom-counters-unavailable"):
                budget.check(force=True)
    def test_previous_alarm_handler_restored_on_success(self):
        previous = signal.getsignal(signal.SIGALRM)
        def owned_handler(_signum, _frame):
            raise AssertionError("previous handler must not run")
        signal.signal(signal.SIGALRM, owned_handler)
        try:
            report = self.run_gate()
            self.assertEqual(report["status"], "passed")
            self.assertIs(signal.getsignal(signal.SIGALRM), owned_handler)
            self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        finally:
            signal.signal(signal.SIGALRM, previous)
    def test_failed_timer_install_restores_handler_without_cancellation(self):
        previous = signal.getsignal(signal.SIGALRM)
        with patch.object(signal, "setitimer", side_effect=OSError("synthetic timer installation failure")) as setter:
            report = self.run_gate()
        self.assertEqual(report["status"], "failed")
        self.assertEqual(setter.call_count, 1)
        self.assertEqual(signal.getsignal(signal.SIGALRM), previous)
        self.assertEqual(self.seen, [])
    def test_report_cap_refuses_withdrawn_only_and_preserves_previous_snapshot(self):
        self.docs = [advisory(withdrawn="2026-10-29T00:00:00Z", summary="x" * 100_000)]
        with patch.object(audit, "MAX_REPORT_BYTES", 32 * 1024, create=True):
            report = self.run_gate()
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["evidence_complete"])
        self.assertIn("report-output-byte-cap", str(report["errors"]))
        self.assertLessEqual((self.output / "report.json").stat().st_size, 16 * 1024)
        self.assertTrue((self.output / "report-before-write-failure.json").is_file())
        self.assertTrue((self.output / "response-001.json").is_file())
        self.assertFalse((self.output / "report.json.tmp").exists())
    def test_report_write_headroom_refused_before_network(self):
        with patch.object(audit.shutil, "disk_usage", return_value=type("Usage", (), {"free": audit.DISK_FLOOR + 1024})()):
            report = self.run_gate()
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["evidence_complete"])
        self.assertIn("report-write-reserve", str(report["errors"]))
        self.assertEqual(self.seen, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
