#!/usr/bin/env python3
"""Select source or complete frozen-artifact inputs before creating any fixtures."""

import argparse
import os
from pathlib import Path
import stat
import sys
from collections.abc import Mapping


ARTIFACT_KEYS = (
    "TUNNEL_AUTHORITY_FAULT_HARNESS_BIN",
    "TUNNEL_AUTHORITY_BIN",
    "TUNNEL_RELAY_BIN",
)
TEST_ARGS = (
    "online_authority_fault_",
    "--ignored",
    "--test-threads=1",
    "--nocapture",
)


def artifact_paths(environment: Mapping[str, str]) -> dict[str, str] | None:
    """Explicit inputs are all-or-nothing; an invalid override never uses Cargo."""
    if not any(key in environment for key in ARTIFACT_KEYS):
        return None
    paths = {}
    for key in ARTIFACT_KEYS:
        value = environment.get(key)
        if not value:
            raise ValueError(f"artifact mode requires nonempty {key}")
        path = Path(os.path.abspath(value))
        try:
            metadata = path.lstat()
        except OSError:
            raise ValueError(f"{key} must identify an executable regular file") from None
        if not stat.S_ISREG(metadata.st_mode) or not os.access(path, os.X_OK):
            raise ValueError(f"{key} must identify an executable regular file")
        paths[key] = str(path)
    return paths


def test_command(environment: Mapping[str, str]) -> list[str]:
    paths = artifact_paths(environment)
    if paths is None:
        return [
            "cargo", "test", "--locked", "-p", "tunnel-test-harness",
            "--test", "m6_online_authority", TEST_ARGS[0], "--", *TEST_ARGS[1:],
        ]
    return [paths[ARTIFACT_KEYS[0]], *TEST_ARGS]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--mode", action="store_true")
    mode.add_argument("--run-tests", action="store_true")
    args = parser.parse_args()
    try:
        paths = artifact_paths(os.environ)
        if args.mode:
            print("source" if paths is None else "artifact")
        else:
            command = test_command(os.environ)
            environment = dict(os.environ)
            if paths is not None:
                # Preserve the files preflight checked even for relative input:
                # subprocess launch must not reinterpret a bare name via PATH.
                environment.update(paths)
            # exec preserves the wrapper's child PID and the real test exit code.
            os.execvpe(command[0], command, environment)
    except (ValueError, OSError) as error:
        # Do not print paths, process environment, or fixture configuration.
        message = str(error) if isinstance(error, ValueError) else "test executable could not start"
        print(f"authority-fault artifacts: {message}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
