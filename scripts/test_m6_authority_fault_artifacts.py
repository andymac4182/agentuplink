#!/usr/bin/env python3
"""Artifact selection controls: no Cargo, Redis, or actual Docker execution."""

import importlib.util
import io
import itertools
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "authority_fault_artifacts",
    Path(__file__).with_name("m6-authority-fault-artifacts.py"),
)
assert SPEC is not None and SPEC.loader is not None
SELECTOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SELECTOR)


class ArtifactSelectionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.environment = {}
        for index, key in enumerate(SELECTOR.ARTIFACT_KEYS):
            path = self.root / f"artifact {index}"
            path.write_text("fixture executable; never launched\n", encoding="utf-8")
            path.chmod(0o500)
            self.environment[key] = str(path)

    def test_no_overrides_preserve_exact_real_cargo_command(self):
        self.assertIsNone(SELECTOR.artifact_paths({"UNRELATED": "present"}))
        self.assertEqual(SELECTOR.test_command({}), [
            "cargo", "test", "--locked", "-p", "tunnel-test-harness",
            "--test", "m6_online_authority", "online_authority_fault_", "--",
            "--ignored", "--test-threads=1", "--nocapture",
        ])

    def test_all_artifacts_preserve_exact_test_filter_and_flags(self):
        self.assertEqual(SELECTOR.artifact_paths(self.environment), self.environment)
        self.assertEqual(SELECTOR.test_command(self.environment), [
            self.environment[SELECTOR.ARTIFACT_KEYS[0]], "online_authority_fault_",
            "--ignored", "--test-threads=1", "--nocapture",
        ])

    def test_every_partial_selection_is_fatal(self):
        for count in (1, 2):
            for keys in itertools.combinations(SELECTOR.ARTIFACT_KEYS, count):
                with self.subTest(keys=keys), self.assertRaisesRegex(ValueError, "requires nonempty"):
                    SELECTOR.test_command({key: self.environment[key] for key in keys})

    def test_empty_explicit_values_are_fatal_even_without_other_overrides(self):
        for key in SELECTOR.ARTIFACT_KEYS:
            for environment in ({key: ""}, {**self.environment, key: ""}):
                with self.subTest(key=key, complete=len(environment) == 3):
                    with self.assertRaisesRegex(ValueError, "requires nonempty"):
                        SELECTOR.test_command(environment)

    def test_missing_directory_nonexecutable_and_symlink_are_fatal_for_each_role(self):
        nonexecutable = self.root / "not executable"
        nonexecutable.write_text("fixture", encoding="utf-8")
        nonexecutable.chmod(0o400)
        symlink = self.root / "symbolic link"
        symlink.symlink_to(self.environment[SELECTOR.ARTIFACT_KEYS[0]])
        for key in SELECTOR.ARTIFACT_KEYS:
            for path in (self.root / "missing", self.root, nonexecutable, symlink):
                with self.subTest(key=key, kind=path.name):
                    with self.assertRaisesRegex(ValueError, f"{key} must identify an executable regular file"):
                        SELECTOR.test_command({**self.environment, key: str(path)})

    def test_mode_reports_artifact_without_launching(self):
        output = io.StringIO()
        with patch.dict(os.environ, self.environment, clear=True), \
             patch("sys.argv", ["selector", "--mode"]), \
             patch("sys.stdout", output), patch.object(SELECTOR.os, "execvpe") as launch:
            self.assertEqual(SELECTOR.main(), 0)
            launch.assert_not_called()
        self.assertEqual(output.getvalue(), "artifact\n")

    def test_invalid_override_never_launches_or_leaks_value(self):
        output = io.StringIO()
        environment = {**self.environment, SELECTOR.ARTIFACT_KEYS[0]: "/private-missing-path"}
        with patch.dict(os.environ, environment, clear=True), \
             patch("sys.argv", ["selector", "--run-tests"]), \
             patch("sys.stderr", output), patch.object(SELECTOR.os, "execvpe") as launch:
            self.assertEqual(SELECTOR.main(), 1)
            launch.assert_not_called()
        self.assertNotIn("/private-missing-path", output.getvalue())
        self.assertIn("executable regular file", output.getvalue())

    def test_artifact_launch_uses_argv_without_shell_splitting(self):
        with patch.dict(os.environ, self.environment, clear=True), \
             patch("sys.argv", ["selector", "--run-tests"]), \
             patch.object(SELECTOR.os, "execvpe") as launch:
            self.assertEqual(SELECTOR.main(), 0)
            command = SELECTOR.test_command(self.environment)
            launch.assert_called_once_with(command[0], command, os.environ)

    def test_relative_artifacts_are_absolute_for_every_child_lookup(self):
        environment = {key: os.path.relpath(value) for key, value in self.environment.items()}
        with patch.dict(os.environ, environment, clear=True), \
             patch("sys.argv", ["selector", "--run-tests"]), \
             patch.object(SELECTOR.os, "execvpe") as launch:
            self.assertEqual(SELECTOR.main(), 0)
            command = SELECTOR.test_command(environment)
            launch.assert_called_once_with(command[0], command, self.environment)

    def test_wrapper_preflights_before_any_docker_command(self):
        wrapper = Path(__file__).with_name("m6-authority-faults-verify.sh").read_text(encoding="utf-8")
        preflight = 'ARTIFACT_MODE="$(python3 "${ARTIFACT_SELECTOR}" --mode)"'
        self.assertIn("set -euo pipefail", wrapper)
        self.assertLess(wrapper.index(preflight), wrapper.index("command -v docker"))
        # A readonly assignment would hide a failed command substitution's status.
        self.assertNotIn("readonly " + preflight, wrapper)
        self.assertIn('if [[ "${ARTIFACT_MODE}" == source ]]; then\n'
                      '    cargo build --locked -p tunnel-authority -p tunnel-relay --bins\nfi', wrapper)
        self.assertIn('python3 "${ARTIFACT_SELECTOR}" --run-tests >"${GATE_LOG}" 2>&1 &', wrapper)

    @unittest.skipUnless(shutil.which("bash"), "wrapper requires Bash")
    def test_bad_wrapper_inputs_never_reach_docker_sentinel(self):
        marker = self.root / "docker-was-called"
        sentinel = self.root / "docker"
        sentinel.write_text(
            f"#!/bin/sh\nprintf 'unexpected Docker call' > {shlex.quote(str(marker))}\nexit 97\n",
            encoding="utf-8",
        )
        sentinel.chmod(0o500)
        cases = []
        for count in (1, 2):
            cases.extend({key: self.environment[key] for key in keys}
                         for keys in itertools.combinations(SELECTOR.ARTIFACT_KEYS, count))
        for key in SELECTOR.ARTIFACT_KEYS:
            cases.extend(({**self.environment, key: ""},
                          {**self.environment, key: str(self.root / "missing")},
                          {**self.environment, key: str(self.root)}))
        wrapper = Path(__file__).with_name("m6-authority-faults-verify.sh")
        for index, inputs in enumerate(cases):
            with self.subTest(case=index):
                result = subprocess.run(
                    [shutil.which("bash"), str(wrapper)],
                    env={"PATH": str(self.root) + os.pathsep + os.environ["PATH"], **inputs},
                    capture_output=True, text=True, timeout=5, check=False,
                )
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("authority-fault artifacts:", result.stderr)
                self.assertFalse(marker.exists(), "invalid input reached Docker")


if __name__ == "__main__":
    unittest.main()
