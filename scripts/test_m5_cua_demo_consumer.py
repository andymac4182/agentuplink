"""Offline controls for the integration consumer; no sockets or input."""
import importlib.util
import json
from pathlib import Path
import tempfile
import os
import signal
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("demo", Path(__file__).with_name("m5-cua-demo.py"))
demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(demo)


class FakeConsumer:
    def __init__(self, overrides=None):
        self.overrides = overrides or {}
        self.log = []
        self.clicks = 0
        self.captures = 0
        self.header_file = "/nonexistent/task11-test-header"

    def call(self, operation, params=None):
        self.log.append({"operation": operation, "params": params})
        if operation in self.overrides:
            return self.overrides[operation]
        if operation == "capture":
            self.captures += 1
            return {"outcome": "ok", "result": {"capture": str(self.captures)}, "_png": b"fake"}
        if operation == "click":
            self.clicks += 1
            if self.clicks in (1, 4, 5):
                return {"outcome": "not_dispatched", "error": {"code": "lease_not_held" if self.clicks in (1, 5) else "capture_superseded"}}
        if operation in ("acquire_input_lease", "release_input_lease"):
            return {"outcome": "answered_locally"}
        return {"outcome": "ok", "result": {}}


class ConsumerControls(unittest.TestCase):
    def run_flow(self, consumer, marker_ok=True):
        with tempfile.TemporaryDirectory() as root:
            state = Path(root) / "state.json"
            state.write_text(json.dumps({"entry": {"x": 100, "y": 100, "width": 400, "height": 32}, "button": {"x": 100, "y": 160, "width": 160, "height": 40}}))
            args = SimpleNamespace(state=str(state), out=root, text="synthetic", reset_entry=True)
            with patch.object(demo, "markers", return_value={}), patch.object(demo, "markers_match", return_value=marker_ok):
                return demo.consumer_flow(args, consumer)

    def test_repeat_flow_clears_entry_after_lease_and_focus(self):
        consumer = FakeConsumer()
        self.assertEqual(self.run_flow(consumer), 0)
        operations = [call["operation"] for call in consumer.log]
        self.assertLess(operations.index("acquire_input_lease"), operations.index("hotkey"))
        self.assertLess(operations.index("hotkey"), len(operations) - 1 - operations[::-1].index("press_key"))
        self.assertLess(operations.index("press_key"), operations.index("type_text"))
        self.assertEqual(operations[-2], "release_input_lease")

    def test_wrong_markers_send_no_input(self):
        consumer = FakeConsumer()
        self.assertEqual(self.run_flow(consumer, marker_ok=False), 3)
        self.assertNotIn("click", [call["operation"] for call in consumer.log])

    def test_failed_lease_does_not_clear_or_type(self):
        consumer = FakeConsumer({"acquire_input_lease": {"outcome": "not_dispatched"}})
        self.assertEqual(self.run_flow(consumer), 4)
        self.assertNotIn("type_text", [call["operation"] for call in consumer.log])

    def test_release_failure_is_not_success(self):
        consumer = FakeConsumer({"release_input_lease": {"outcome": "not_dispatched"}})
        self.assertEqual(self.run_flow(consumer), 4)

    def test_unknown_typing_is_not_success(self):
        consumer = FakeConsumer({"type_text": {"outcome": "unknown"}})
        self.assertEqual(self.run_flow(consumer), 4)
        self.assertEqual(consumer.clicks, 2)

    def test_failed_clear_does_not_type(self):
        consumer = FakeConsumer({"hotkey": {"outcome": "unknown"}})
        self.assertEqual(self.run_flow(consumer), 4)
        self.assertNotIn("type_text", [call["operation"] for call in consumer.log])

    def test_exception_releases_lease_and_deletes_header(self):
        with tempfile.TemporaryDirectory() as root:
            token = Path(root) / "token"
            token.write_text("synthetic-token")
            header = Path(root) / "header"
            header.write_text("synthetic-header")
            consumer = FakeConsumer()
            consumer.header_file = str(header)
            consumer.lease_held = True
            args = SimpleNamespace(token_file=str(token))
            with patch.object(demo, "Consumer", return_value=consumer), patch.object(demo, "consumer_flow", side_effect=RuntimeError("synthetic failure")):
                with self.assertRaises(RuntimeError):
                    demo.cmd_consumer(args)
            self.assertFalse(header.exists())
            self.assertEqual(consumer.log[-1]["operation"], "release_input_lease")

    def test_header_stays_inside_the_token_directory(self):
        with tempfile.TemporaryDirectory() as root:
            args = SimpleNamespace(consumer_port=18443, device="synthetic", service="synthetic",
                                   token="synthetic", token_file=str(Path(root) / "token"))
            consumer = demo.Consumer(args)
            try:
                self.assertEqual(Path(consumer.header_file).parent, Path(root))
                self.assertEqual(os.stat(consumer.header_file).st_mode & 0o777, 0o600)
            finally:
                Path(consumer.header_file).unlink()

    @unittest.skipIf(os.name == "nt", "POSIX signal control")
    def test_sigterm_releases_lease_and_removes_header(self):
        with tempfile.TemporaryDirectory() as root:
            token = Path(root) / "token"
            token.write_text("synthetic")
            marker = Path(root) / "released"
            code = '''import importlib.util,json,time,sys
from pathlib import Path
from types import SimpleNamespace
spec=importlib.util.spec_from_file_location("demo",sys.argv[1])
demo=importlib.util.module_from_spec(spec);spec.loader.exec_module(demo)
def flow(args,consumer):
    consumer.lease_held=True
    def call(operation,params=None):
        if operation=="release_input_lease":
            Path(sys.argv[3]).write_text("released")
            consumer.lease_held=False
        return {"outcome":"answered_locally"}
    consumer.call=call
    print(json.dumps({"header":consumer.header_file}),flush=True)
    time.sleep(30)
demo.consumer_flow=flow
demo.cmd_consumer(SimpleNamespace(consumer_port=18443,device="synthetic",service="synthetic",token_file=sys.argv[2]))
'''
            child = subprocess.Popen([sys.executable, "-c", code, str(Path(demo.__file__)),
                                      str(token), str(marker)], stdout=subprocess.PIPE, text=True)
            try:
                header = Path(json.loads(child.stdout.readline())["header"])
                child.send_signal(signal.SIGTERM)
                self.assertEqual(child.wait(timeout=5), 143)
                self.assertFalse(header.exists())
                self.assertEqual(marker.read_text(), "released")
                self.assertTrue(token.exists())
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()
                child.stdout.close()


if __name__ == "__main__":
    unittest.main()
