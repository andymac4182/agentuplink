#!/usr/bin/env python3
"""Hosted focused execution of the original expired-authorization gate4 case.

The original script's exact declaration and WITNESSES entry supply the mutation
and test. This is not execution of its broad four-crate CLI. The existing client
20-test/nine-mutant gate is separate and is not repeated here. Original Rust
assertions and helper panics remain unchanged. Only public/receipt.json may be
uploaded; compiler/test logs, source backups and binaries stay private.

Uses the reviewed supervisor and artifact hashing: 45-minute main budget,
up to five seconds of command teardown, then 60 seconds of source cleanup.
Imports launch no processes. Local controls use fake processes/synthetic files.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
from pathlib import Path
import re
import signal
import sys

import m4_authorization_witnesses as shared

DRIVER = "scripts/fs-guard-deletion.py"
OUTCOMES = "scripts/guard_outcomes.py"
DEBT = "scripts/guard_witness_debt.json"
PROVIDER = "crates/tunnel-fs-provider/src/provider.rs"
DISPATCHER = "crates/tunnel-fs-provider/tests/dispatcher.rs"
SUPPORT = "crates/tunnel-fs-provider/tests/support/mod.rs"
SELF = "scripts/m4_original_gate4_witness.py"
SHARED = "scripts/m4_authorization_witnesses.py"
CASE = "close on an expired authorization snapshot"
WITNESS = "an_expired_authorization_snapshot_closes_the_session_before_the_host_is_touched"
GUARD = """        if !live.fresh {
            self.stats.freshness_closures += 1;
            self.close();
            return vec![Outbound::Close(live.freshness_failure.close_code())];
        }
"""
PANIC_ANCHOR = '        Outbound::Frame(frame) => panic!("expected a close, got a frame: {frame:?}"),'
PANIC_PREFIX = "expected a close, got a frame:"
ORIGINAL_SHA256 = {
    DRIVER: "5e6f2468492bcadae8d48e4fafdcb72c1e3f19e80c5827bb93b741ff52a0e648",
    OUTCOMES: "47f6bcbae8a6a685d9d169fa41bb3500b457b9b4bab372844a6571a37857bb29",
    DEBT: "a14cb68611222fb77f0fda5822d58e7e7e119d39f44f4b97b498e9b44b6e0c3d",
    PROVIDER: "ca207797c1aa186235c5e54294159f262b2b1dfdf7b0f523ce0c4ef75c8512a7",
    DISPATCHER: "f0b7c9b15b4778ddd4fc81e152d2d097e889a80e43e278cddb814aad60fc52a2",
    SUPPORT: "04123a4732952ad04d74c9edeb389cc9ac2e12efa3c20ebaccf2d7fbc81b0806",
}
PATHS = tuple(sorted((*ORIGINAL_SHA256, SELF, SHARED, "Cargo.lock", "rust-toolchain.toml")))
BASE = ("cargo", "test", "--locked", "-p", "tunnel-fs-provider", "--test", "dispatcher")
MAX_SOURCE_BYTES = 2 * 1024 * 1024
CONTRACT = {"scope": "focused_original_gate4_case", "case": CASE, "witness": WITNESS,
            "guard": GUARD, "path": PROVIDER, "panic_anchor": PANIC_ANCHOR,
            "original_sha256": ORIGINAL_SHA256, "cargo": BASE}
CONTRACT_SHA256 = shared.digest(json.dumps(CONTRACT, sort_keys=True).encode())


def assignment(module, name):
    found = []
    for node in module.body:
        targets = node.targets if isinstance(node, ast.Assign) else (
            [node.target] if isinstance(node, ast.AnnAssign) else [])
        if any(isinstance(target, ast.Name) and target.id == name for target in targets):
            found.append(node.value)
    shared.require(len(found) == 1, "original_assignment_not_unique")
    return found[0]


def original_contract(repo: Path, hashes):
    shared.require(all(hashes.get(path) == expected for path, expected in ORIGINAL_SHA256.items()),
                   "original_source_hash_mismatch")
    module = ast.parse((repo / DRIVER).read_text())
    declaration = assignment(module, "GATE4_CASES")
    shared.require(isinstance(declaration, ast.List), "original_cases_invalid")
    matches = [node for node in declaration.elts if isinstance(node, ast.Tuple)
               and ast.literal_eval(node.elts[0]) == CASE]
    shared.require(len(matches) == 1, "original_case_not_unique")
    edits = matches[0].elts[1]
    shared.require(isinstance(edits, ast.List) and len(edits.elts) == 1, "original_edit_not_unique")
    edit = edits.elts[0]
    shared.require(isinstance(edit, ast.Tuple) and len(edit.elts) == 3
                   and isinstance(edit.elts[0], ast.Name) and edit.elts[0].id == "PROVIDER_SRC",
                   "original_edit_target_mismatch")
    shared.require(ast.literal_eval(edit.elts[1]) == GUARD and ast.literal_eval(edit.elts[2]) == "",
                   "original_guard_mismatch")
    witnesses = assignment(module, "WITNESSES")
    shared.require(isinstance(witnesses, ast.Dict), "original_witness_map_invalid")
    rows = [value for key, value in zip(witnesses.keys, witnesses.values)
            if ast.literal_eval(key) == ("gate4", CASE)]
    shared.require(len(rows) == 1, "original_witness_not_unique")
    row = rows[0]
    shared.require(isinstance(row, ast.Call) and isinstance(row.func, ast.Name)
                   and row.func.id == "frozenset" and len(row.args) == 1 and not row.keywords
                   and ast.literal_eval(row.args[0]) == {WITNESS}, "original_witness_mismatch")
    shared.require((repo / PROVIDER).read_text().count(GUARD) == 1, "mutation_not_unique")
    support = (repo / SUPPORT).read_text()
    shared.require(support.count(PANIC_ANCHOR) == 1, "original_panic_not_unique")
    line = support.count("\n", 0, support.index(PANIC_ANCHOR)) + 1
    return {"id": "original-gate4-expired-authorization", "path": PROVIDER,
            "before": GUARD, "after": ""}, (SUPPORT, line, PANIC_PREFIX)


class Sources(shared.Sources):
    """Reuse exact atomic mutation/restoration; pin the original driver/tests."""

    def __init__(self, repo, backup):
        self.repo, self.paths, self.active = repo, PATHS, None
        for path in self.paths:
            shared.require((repo / path).stat().st_size <= MAX_SOURCE_BYTES, "source_size_invalid")
        self.original = {path: (repo / path).read_bytes() for path in self.paths}
        self.hashes = {path: shared.digest(data) for path, data in self.original.items()}
        self.tests = {path: self.hashes[path] for path in (DISPATCHER, SUPPORT)}
        for i, path in enumerate(self.paths):
            (backup / f"source-{i}.bin").write_bytes(self.original[path])

    def verify(self):
        for path, original in self.original.items():
            expected = self.active[1] if self.active and path == self.active[0] else original
            shared.require((self.repo / path).read_bytes() == expected, "source_bytes_changed")


def compiled_dispatcher(output, code, repo, target):
    shared.require(code == 0, "compile_failed")
    messages = []
    for line in output.splitlines():
        if line.startswith("{"):
            try:
                messages.append(json.loads(line))
            except (ValueError, TypeError):
                raise shared.Refusal("compile_json_invalid") from None
    shared.require([m.get("success") for m in messages if m.get("reason") == "build-finished"]
                   == [True], "compile_completion_missing")
    artifacts = [m for m in messages if m.get("reason") == "compiler-artifact"
                 and m.get("target", {}).get("name") == "dispatcher"
                 and m.get("target", {}).get("kind") == ["test"]
                 and m.get("profile", {}).get("test") is True and m.get("executable")]
    shared.require(len(artifacts) == 1, "compile_test_artifact_missing")
    item = artifacts[0]
    shared.require(Path(item["target"].get("src_path", "")).resolve() == (repo / DISPATCHER).resolve(),
                   "compile_test_source_mismatch")
    path = Path(item["executable"])
    shared.require(path.is_absolute() and path.resolve().is_relative_to(target.resolve()),
                   "compile_artifact_outside_target")
    return path


def running_dispatcher(output, artifact, repo):
    records = re.findall(
        r"^\s*Running (?:tests/dispatcher\.rs|crates/tunnel-fs-provider/tests/dispatcher\.rs) \(([^\n]+)\)$",
        output, re.M)
    expected = {str(artifact.path), os.path.relpath(artifact.path, repo)}
    shared.require(len(records) == 1 and records[0] in expected
                   and len(re.findall(r"^\s*Running\b", output, re.M)) == 1,
                   "running_artifact_mismatch")


class Controller(shared.Controller):
    def __init__(self, repo, expected, output, supervisor=None):
        super().__init__(repo, expected, output, supervisor)
        self.receipt.update({"plan_sha256": CONTRACT_SHA256, "scope": "focused_original_gate4_case",
                             "case": CASE, "witness": WITNESS, "literal_four_crate_cli_executed": False,
                             "client_twenty_suite_repeated": False, "original_named_red": False,
                             "separate_required_checks": ["full_rust_milestones_platforms", "authorization_nine_mutant_gate"]})

    def identity(self, *, cleanup_deadline=None):
        super().identity(cleanup_deadline=cleanup_deadline)
        tracked = self.git(("ls-files", "--error-unmatch", "--", *PATHS), cleanup_deadline=cleanup_deadline)
        shared.require(tuple(sorted(tracked.splitlines())) == PATHS, "tracked_source_identity_mismatch")
        shared.require(not any((self.repo / name).exists() for name in
                               (".guard-mutation-journal.json", ".guard-mutation-journal.json.tmp")),
                       "original_mutation_journal_present")

    def hash_artifact(self, path):
        return shared.fingerprint_artifact(
            path, self.output / "private" / "target", self.supervisor.ops.monotonic,
            min(self.supervisor.deadline, self.supervisor.ops.monotonic() + shared.HASH_SECONDS),
            lambda: self.supervisor.interrupted, executable_kind="provider_dispatcher")

    def compile(self):
        self.artifact = None
        output, code = self.command((*BASE, "--no-run", "--message-format=json"), 900)
        path = compiled_dispatcher(output, code, self.repo, self.output / "private" / "target")
        artifact = self.hash_artifact(path)
        self.sources.verify()
        self.artifact = artifact
        self.receipt["compile_artifacts"].append({"phase": self.phase,
                                                  "command_sequence": self.sequence, **artifact.public()})
        self.save()

    def witness(self, red, site):
        shared.require(self.artifact is not None, "compiled_artifact_missing")
        before = self.hash_artifact(self.artifact.path)
        shared.require(before == self.artifact, "artifact_changed_before_run")
        run = {"phase": self.phase, "compile_index": len(self.receipt["compile_artifacts"]) - 1,
               "command_sequence": self.sequence + 1, "selector": WITNESS,
               "identifier": before.identifier, "before_sha256": before.sha256,
               "after_sha256": None, "running_record_verified": False}
        self.receipt["artifact_runs"].append(run)
        self.save()
        output, code = self.command((*BASE, WITNESS, "--", "--exact", "--test-threads=1"), 120)
        after = self.hash_artifact(self.artifact.path)
        run["after_sha256"] = after.sha256
        shared.require(after == self.artifact, "artifact_changed_after_run")
        running_dispatcher(output, self.artifact, self.repo)
        run["running_record_verified"] = True
        self.sources.verify()
        shared.check_tests(output, code, (WITNESS,), red, site if red else None)
        run.update({"executed": 1, "passed": 0 if red else 1, "failed": 1 if red else 0})
        self.save()

    def execute(self):
        shared.require(re.fullmatch(r"[0-9a-f]{40}", self.expected) is not None, "invalid_expected_commit")
        shared.require(not self.output.is_relative_to(self.repo), "output_inside_checkout")
        self.output.mkdir(mode=0o700)
        (self.output / "private").mkdir(mode=0o700)
        (self.output / "public").mkdir(mode=0o700)
        try:
            shared.require(sys.platform == "linux" and os.environ.get("GITHUB_ACTIONS") == "true",
                           "hosted_linux_required")
            self.identity()
            tree = self.git(("rev-parse", "HEAD^{tree}")).strip()
            shared.require(re.fullmatch(r"[0-9a-f]{40}", tree) is not None, "invalid_tree")
            self.receipt.update({"commit": self.expected, "tree": tree})
            self.sources = Sources(self.repo, self.output / "private")
            case, site = original_contract(self.repo, self.sources.hashes)
            self.receipt.update({"source_sha256": self.sources.hashes, "test_sha256": self.sources.tests,
                                 "original_declaration_sha256": shared.digest(GUARD.encode()),
                                 "original_panic_site": {"path": site[0], "line": site[1]}})
            self.phase = "baseline_compile"
            self.compile()
            self.phase = "baseline_green"
            self.witness(False, site)
            self.identity()
            self.receipt["baseline_green"] = True
            self.phase = "original_mutation"
            self.sources.apply(case)
            self.receipt["active_mutation"] = {
                "id": case["id"], "path": PROVIDER, "match_count": 1,
                "before_sha256": self.sources.hashes[PROVIDER],
                "after_sha256": shared.digest(self.sources.active[1]), "test_sha256": self.sources.tests}
            self.save()
            self.identity()
            self.phase = "mutant_compile"
            self.compile()
            self.phase = "original_red"
            self.witness(True, site)
            self.receipt["original_named_red"] = True
            self.receipt["mutants"].append({**self.receipt["active_mutation"], "compile_verified": True,
                                             "status": "assertion_red", "test": WITNESS,
                                             "panic_path": site[0], "panic_line": site[1]})
            self.phase = "restore"
            self.sources.restore()
            self.receipt["active_mutation"] = None
            self.identity()
            self.phase = "final_compile"
            self.compile()
            self.phase = "final_green"
            self.witness(False, site)
            self.identity()
            self.receipt["final_green"] = True
        except shared.Refusal as error:
            self.note_failure(str(error))
        except BaseException as error:
            self.note_failure("interrupted" if isinstance(error, KeyboardInterrupt) else "unexpected_failure")
        finally:
            self.phase = "cleanup"
            until = self.supervisor.ops.monotonic() + shared.CLEANUP_SECONDS
            try:
                if self.sources:
                    self.sources.restore()
                    self.receipt["active_mutation"] = None
                    self.identity(cleanup_deadline=until)
                    self.receipt["source_restored"] = True
            except shared.Refusal as error:
                self.note_failure(str(error), cleanup=True)
            except BaseException:
                self.note_failure("restore_failed", cleanup=True)
            if self.supervisor.interrupted:
                self.note_failure("interrupted")
            self.receipt["status"] = "passed" if self.receipt["first_failure"] is None else "failed"
            self.save()
            if self.supervisor.interrupted and self.receipt["status"] == "passed":
                self.note_failure("interrupted")
                self.receipt["status"] = "failed"
                self.save()
        return 0 if self.receipt["status"] == "passed" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    controller = Controller(args.repository, args.expected_commit, args.output)
    signal.signal(signal.SIGTERM, controller.supervisor.on_signal)
    signal.signal(signal.SIGINT, controller.supervisor.on_signal)
    try:
        result = controller.execute()
    except (shared.Refusal, OSError):
        print("Original gate4 witness: setup refused; no RED claimed.")
        return 1
    print("Original gate4 witness: " + controller.receipt["status"] + ".")
    return result


if __name__ == "__main__":
    raise SystemExit(main())
