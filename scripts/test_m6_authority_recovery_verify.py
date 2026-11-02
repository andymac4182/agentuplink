"""Pure ownership and artifact-mode guards; no Docker/network/process calls."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("recovery_gate", Path(__file__).with_name("m6-authority-recovery-verify.py"))
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class OwnershipTests(unittest.TestCase):
    def setUp(self):
        self.owner = "a" * 32
        self.image = "sha256:" + "b" * 64
        self.container = {"id": "c" * 64, "role": "candidate"}
        self.port = 32123
        self.fields = [self.container["id"], f"/agentuplink-authority-recovery-{self.owner}-candidate",
                       {GATE.LABEL: self.owner}, self.image,
                       {"6379/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(self.port)}]},
                       GATE.MEMORY, GATE.MEMORY, 1_000_000_000, 64, False, 0]

    def validate(self):
        raw = "\n".join(json.dumps(value) for value in self.fields).encode()
        return GATE.validate_inspection(raw, self.container, self.owner, self.image, self.port)

    def test_created_or_stopped_candidate_retains_checked_endpoint(self):
        self.assertEqual(self.validate(), {"id": self.container["id"], "running": False, "pid": 0})

    def test_same_name_replacement_owner_or_image_is_refused(self):
        for index, wrong in [(0, "d" * 64), (1, "/another-container"), (2, {GATE.LABEL: "e" * 32}), (3, "sha256:" + "f" * 64)]:
            with self.subTest(index=index):
                previous = self.fields[index]
                self.fields[index] = wrong
                with self.assertRaises(GATE.GateError):
                    self.validate()
                self.fields[index] = previous

    def test_nonloopback_extra_binding_and_shared_port_are_refused(self):
        for wrong in [{"6379/tcp": [{"HostIp": "0.0.0.0", "HostPort": str(self.port)}]},
                      {"6379/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(self.port)}], "6380/tcp": []}]:
            self.fields[4] = wrong
            with self.assertRaises(GATE.GateError):
                self.validate()
        self.port = 16379
        with self.assertRaises(GATE.GateError):
            self.validate()

    def test_resource_boundary_changes_are_refused(self):
        for index in (5, 6, 7, 8):
            with self.subTest(index=index):
                previous = self.fields[index]
                self.fields[index] = previous + 1
                with self.assertRaises(GATE.GateError):
                    self.validate()
                self.fields[index] = previous

    def test_partial_binary_overrides_never_fall_back_to_build(self):
        self.assertIsNone(GATE.overridden_binaries({}))
        for key in ("TUNNEL_C22_RECOVERY_HARNESS_BIN", "TUNNEL_AUTHORITY_BIN", "TUNNEL_RELAY_BIN"):
            with self.subTest(key=key), self.assertRaises(GATE.GateError):
                GATE.overridden_binaries({key: "/some/artifact"})

    @unittest.skipUnless(os.name == "posix", "POSIX executable permission boundary")
    def test_complete_overrides_require_executable_files(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "fixture"
            artifact.write_bytes(b"synthetic artifact: never executed")
            values = {key: str(artifact) for key in ("TUNNEL_C22_RECOVERY_HARNESS_BIN", "TUNNEL_AUTHORITY_BIN", "TUNNEL_RELAY_BIN")}
            artifact.chmod(0o600)
            with self.assertRaises(GATE.GateError):
                GATE.overridden_binaries(values)
            artifact.chmod(0o700)
            self.assertEqual(set(GATE.overridden_binaries(values)), {"harness", "authority", "relay"})


if __name__ == "__main__":
    unittest.main()
