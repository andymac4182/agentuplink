#!/usr/bin/env python3
"""Hosted-only M4-76 behavioral witnesses; raw logs stay in private/.

The embedded, immutable plan is a reference, not a claim of executed evidence.
Only public/receipt.json may be uploaded. A RED requires a compiled mutant,
one exact test, and its intended assertion location. No runtime is started on
import. Unit tests inject process operations and use synthetic source files.
This controller covers nine mutants/ten assertion runs. The existing gate4
guard-deletion command and the full milestone/platform checks in the reference
plan remain separate required gates; this controller does not run them.

The main budget is 45 minutes, followed by at most 60 seconds for cleanup.
We reap our direct child and observe its POSIX group, not arbitrary escaped
descendants. A missing cleanup observation is never reported as joined.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass


PLAN_SHA256 = "d84b2fbea691bff6f2f43b7a633f53a0c2f1cf7251ec51568ea2f7636ae30d1c"
REFERENCE_PLAN = r'''{
  "schema_version": 1,
  "status": "PLAN ONLY; no mutation, compiler, test or formatter executed locally",
  "reviewed_source_tree": "670e5dc549531e5d7e0fd2cc85eff4b83cab1313",
  "reviewed_patch_sha256": "3efbb61ec81b950b20d88aba40421dbf2e90428144a4dcb6a4a81fa38e8886f3",
  "scope": "Isolated authorized Linux hosted job on the successor's immutable commit/tree. Keep all new APIs/types and all assertions. Mutate one production behavior at a time. No M4-47, relay response-budget, account-security/FIDO2 or platform/license changes.",
  "baseline_green_argv": [
    "cargo",
    "test",
    "--locked",
    "-p",
    "tunnel-client",
    "--lib",
    "m4c76_"
  ],
  "required_baseline_result": "Exactly20 m4c76 test functions executed, zero failed/ignored; source tree and artifact hashes captured. A compile failure or different inventory stops the job before RED controls.",
  "mutation_protocol": [
    "Record successor commit/tree and SHA256 of every target source file; verify no existing source changes. Rust1.95.0 and Cargo.lock remain pinned.",
    "For each case separately, require exact before-string count ==1 and after-string differs. If zero or multiple matches, stop as setup failure; never classify absent match as RED.",
    "Apply only that replacement in the ephemeral hosted checkout. Confirm expected diff path/content; preserve every new API, test and assertion.",
    "Run cargo test --locked -p tunnel-client --lib <fully qualified witness> -- --exact for each named witness. Require successful compilation and exactly1 test executed, then nonzero exit caused by the identified assertion. Zero tests, compile/link failure, timeout, process failure and unrelated panic are not accepted RED evidence.",
    "Archive bounded command/results and the actual named assertion failure. Do not count raw exit status alone. Mutant Clippy/format warnings are not substitute evidence; formatting/Clippy requirements apply to the unmutated candidate.",
    "Restore the exact original file bytes in a finally path and verify every original source hash/tree before the next case. Never chain mutations or reuse an unrestored source.",
    "After all cases, rerun the20-test focused baseline green and verify source identity. Only the original candidate may proceed to full required checks/publication."
  ],
  "cases": [
    {
      "id": "A1-last-accepted-bound",
      "path": "crates/tunnel-client/src/m2_runtime.rs",
      "before": "            || self\n                .last_confirmed_deadline\n                .is_some_and(|deadline| deadline.expired_at(now, wall_now))",
      "after": "",
      "witnesses": [
        "m2_runtime::tests::m4c76_authorization_deadlines::m4c76_buffered_http_stops_at_prior_confirmation_for_both_queue_paths",
        "m2_runtime::tests::m4c76_authorization_deadlines::m4c76_a_late_matching_confirmation_cannot_bridge_a_lapse"
      ],
      "expected_assertion": "Buffered read returns Data instead of Closed; late matching answer is accepted instead of invalidating. No post-bound expiry tick is required."
    },
    {
      "id": "A2-unconfirmed-http-bypass",
      "path": "crates/tunnel-client/src/m2_http.rs",
      "before": "        let expired = stream.authorization_expired_at(Instant::now(), SystemTime::now());",
      "after": "        let expired = stream.auth.confirmed\n            && stream.authorization_expired_at(Instant::now(), SystemTime::now());",
      "witnesses": [
        "m2_runtime::tests::m4c76_authorization_deadlines::m4c76_buffered_http_stops_at_prior_confirmation_for_both_queue_paths"
      ],
      "expected_assertion": "Reader gets Data while refresh is in flight although accepted bound elapsed; Closed assertion fails."
    },
    {
      "id": "A3-provider-accepted-bound",
      "path": "crates/tunnel-client/src/fs_authority.rs",
      "before": "                        confirmation.expired(now, wall)\n                            || challenge.expired(now, wall)",
      "after": "                        (confirmation.expired(now, wall) && false)\n                            || challenge.expired(now, wall)",
      "witnesses": [
        "fs_export::fs_authority::tests::m4c76_provider_checks_the_newer_in_flight_challenge_anchor"
      ],
      "expected_assertion": "The last assertion at original.monotonic/original.wall sees fresh=true, because newer challenge and operation remain live. First newer-anchor refusal still passes. Expression retains field use so there is no unused-variable compilation failure."
    },
    {
      "id": "A4-provider-refresh-publication",
      "path": "crates/tunnel-client/src/m2_runtime.rs",
      "before": "                .is_some_and(|authority| !authority.begin_refresh(deadline))",
      "after": "                .is_some_and(|_| false)",
      "witnesses": [
        "m2_runtime::tests::m4c76_authorization_deadlines::m4c76_both_queued_filesystem_refresh_paths_publish_the_challenge_bound"
      ],
      "expected_assertion": "Actor refuses injected reversal between captured starts but provider reports fresh; assertion 'provider checks the admitted challenge without actor tick' fails. Runtime configuration remains fixed."
    },
    {
      "id": "A5-provider-close-cause",
      "path": "crates/tunnel-fs-provider/src/provider.rs",
      "before": "            return vec![Outbound::Close(live.freshness_failure.close_code())];",
      "after": "            return vec![Outbound::Close(SessionErrorCode::AuthExpired)];",
      "witnesses": [
        "fs_export::fs_authority::tests::m4c76_queued_provider_read_uses_the_exact_observed_failure_cause"
      ],
      "expected_assertion": "The first clock-lapse case returns AuthExpired/1008 instead of SessionLost/1011. Pre-deadline host read passes before that distinguishing assertion."
    },
    {
      "id": "A6-shortened-expired-confirmation",
      "path": "crates/tunnel-client/src/m2_runtime.rs",
      "before": "                    Some(deadline)\n                        if !deadline.expired_at(now, wall_now)\n                            && stream.fs_authority.as_ref().is_none_or(|authority| {",
      "after": "                    Some(deadline)\n                        if stream.fs_authority.as_ref().is_none_or(|authority| {",
      "witnesses": [
        "m2_runtime::tests::m4c76_authorization_deadlines::m4c76_a_matching_shortened_expired_confirmation_cannot_publish_authority"
      ],
      "expected_assertion": "With zero stream.pending and a matching answer whose one-millisecond derived bound elapsed, auth.invalidated remains false/auth.confirmed becomes true; invalidated assertion fails."
    },
    {
      "id": "A7-unavailable-terminal-cause",
      "path": "crates/tunnel-client/src/fs_authority.rs",
      "before": "        let freshness_failure = match self.status.load(Ordering::SeqCst) {\n            INVALIDATED => FreshnessFailure::Invalidated,\n            LAPSED => FreshnessFailure::DeadlineElapsed,\n            _ => FreshnessFailure::SnapshotUnavailable,\n        };",
      "after": "        let freshness_failure = FreshnessFailure::SnapshotUnavailable;",
      "witnesses": [
        "fs_export::fs_authority::tests::m4c76_terminal_cause_survives_odd_or_unavailable_publication"
      ],
      "expected_assertion": "A known Invalidated observation becomes SnapshotUnavailable under held odd generation; exact cause assertion fails (1008 would become1011)."
    },
    {
      "id": "A8-torn-snapshot-rejection",
      "path": "crates/tunnel-client/src/fs_authority.rs",
      "before": "            if before & 1 != 0 {\n                continue;\n            }\n",
      "after": "",
      "witnesses": [
        "fs_export::fs_authority::tests::m4c76_partial_deadline_publication_never_exposes_a_torn_bound"
      ],
      "expected_assertion": "Held odd partial publication is returned as DeadlineElapsed instead of SnapshotUnavailable; exact cause assertion fails before the coherent-publication positive."
    },
    {
      "id": "A9-independent-reversal-anchor",
      "path": "crates/tunnel-client/src/m2_runtime.rs",
      "before": "                .last_confirmed_deadline\n                .is_some_and(|deadline| deadline.expired_at(now, wall_now))",
      "after": "                .last_confirmed_deadline\n                .is_some_and(|deadline| now >= deadline.monotonic || wall_now >= deadline.wall)",
      "witnesses": [
        "m2_runtime::tests::m4c76_authorization_deadlines::m4c76_every_deadline_keeps_its_own_wall_reversal_anchor"
      ],
      "expected_assertion": "After swapping the later start into the last confirmation, the second reversal assertion fails. Both expiry ends remain live; only the independent start-anchor check distinguishes it."
    }
  ],
  "existing_guard_deletion": {
    "argv": [
      "python3",
      "scripts/fs-guard-deletion.py",
      "--suite",
      "gate4",
      "--case",
      "close on an expired authorization snapshot"
    ],
    "mutation": "Delete the same entire if !live.fresh block; current script matcher contains live.freshness_failure.close_code().",
    "required_witness": "an_expired_authorization_snapshot_closes_the_session_before_the_host_is_touched",
    "requirement": "Preserve script's clean-source precondition, exact replacement, existing witness and nonzero assertion requirement; no absent-match/compile-error acceptance. Run after restoring all custom mutants."
  },
  "future_full_checks": "Fresh unmutated pinned rustfmt check, strict locked workspace/all-target Clippy, workspace tests, full hosted M1/M2/M3/M4/M7 plus all five archive/platform acceptance remain required. Focused mutation evidence does not replace them.",
  "old_source_limit": "Do not apply new tests alone to unmodified old source and claim failure: they use new fields/APIs. These reversible mutants preserve those APIs and demonstrate behavioral assertion sensitivity on the compiled new candidate.",
  "resource_limit": "Hosted only, coordinator-owned runner/resource guard and joined cleanup; local C256 native/cache quarantine remains unchanged."
}
'''
PLAN = json.loads(REFERENCE_PLAN)
assert hashlib.sha256(REFERENCE_PLAN.encode()).hexdigest() == PLAN_SHA256

ACTOR = "m2_runtime::tests::m4c76_authorization_deadlines::"
PROVIDER = "fs_export::fs_authority::tests::"
ACTOR_TEST = "crates/tunnel-client/src/m2_runtime/tests/m4c76_authorization_deadlines.rs"
PROVIDER_SOURCE = "crates/tunnel-client/src/fs_authority.rs"
TEST_MARKER = "#[cfg(test)]\nmod tests {"
INVENTORY = tuple(sorted(
    [ACTOR + "m4c76_" + name for name in (
        "buffered_http_stops_at_prior_confirmation_for_both_queue_paths",
        "a_late_matching_confirmation_cannot_bridge_a_lapse",
        "timely_confirmation_renews_from_the_original_challenge_start",
        "a_matching_shortened_expired_confirmation_cannot_publish_authority",
        "both_queued_filesystem_refresh_paths_publish_the_challenge_bound",
        "unanswered_refresh_preserves_frozen_stale_terminal_ordering",
        "a_refresh_still_waiting_for_queue_space_expires_without_nonce_replacement",
        "every_deadline_keeps_its_own_wall_reversal_anchor",
        "queued_challenge_expiry_keeps_transport_failure_and_releases_budget",
    )] + [PROVIDER + "m4c76_" + name for name in (
        "provider_checks_both_clocks_and_operation_without_actor_tick",
        "timely_provider_renewal_survives_old_deadline",
        "provider_renewal_cannot_extend_admission_operation_bound",
        "provider_checks_the_newer_in_flight_challenge_anchor",
        "snapshot_retries_never_return_a_torn_publication",
        "snapshot_contention_is_bounded_and_distinct_from_expiry",
        "writer_conflict_and_version_exhaustion_retire_authority",
        "terminal_cause_survives_odd_or_unavailable_publication",
        "partial_deadline_publication_never_exposes_a_torn_bound",
        "frozen_grant_and_terminal_reason_cannot_be_replaced",
        "queued_provider_read_uses_the_exact_observed_failure_cause",
    )]
))
CARGO = ("cargo", "test", "--locked", "-p", "tunnel-client", "--lib")
MAIN_SECONDS = 45 * 60
CLEANUP_SECONDS = 60
MAX_LOG_BYTES = 8 * 1024 * 1024
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
HASH_CHUNK_BYTES = 1024 * 1024
HASH_SECONDS = 30
ARTIFACT_IDENTIFIER = re.compile(r"debug/deps/tunnel_client-[0-9a-f]{16}")
SUMMARY = re.compile(
    r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; "
    r"(\d+) measured; (\d+) filtered out; finished in [^\n]+$", re.M
)


class Refusal(Exception):
    """Only fixed codes reach the public receipt; never exception text."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise Refusal(code)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class Assertion:
    anchor: str
    message: str = "assertion failed:"


ASSERTIONS = {
    "m4c76_buffered_http_stops_at_prior_confirmation_for_both_queue_paths": Assertion(
        "assert!(matches!(fixture.read().await, DeviceRead::Closed));"),
    "m4c76_a_late_matching_confirmation_cannot_bridge_a_lapse": Assertion(
        "assert!(fixture.actor.streams[&STREAM].auth.invalidated);"),
    "m4c76_provider_checks_the_newer_in_flight_challenge_anchor": Assertion(
        "assert!(\n            !authority\n                .current_with_clock(|| (original.monotonic, original.wall))\n                .fresh\n        );"),
    "m4c76_both_queued_filesystem_refresh_paths_publish_the_challenge_bound": Assertion(
        'assert!(\n            !observed.fresh,\n            "provider checks the admitted challenge without actor tick"\n        );',
        "provider checks the admitted challenge without actor tick"),
    "m4c76_queued_provider_read_uses_the_exact_observed_failure_cause": Assertion(
        "assert!(\n                    matches!(&result[..], [Outbound::Close(code)] if *code == cause.close_code())\n                );"),
    "m4c76_a_matching_shortened_expired_confirmation_cannot_publish_authority": Assertion(
        "assert!(fixture.actor.streams[&STREAM].auth.invalidated);"),
    "m4c76_terminal_cause_survives_odd_or_unavailable_publication": Assertion(
        "assert_eq!(observed.freshness_failure, cause);", "assertion `left == right` failed"),
    "m4c76_partial_deadline_publication_never_exposes_a_torn_bound": Assertion(
        "assert_eq!(\n            while_torn.freshness_failure,\n            FreshnessFailure::SnapshotUnavailable\n        );", "assertion `left == right` failed"),
    "m4c76_every_deadline_keeps_its_own_wall_reversal_anchor": Assertion(
        "stream.last_confirmed_deadline.as_mut().unwrap(),\n    );\n    assert!(stream.authorization_expired_at(\n        start + Duration::from_secs(3),\n        wall + Duration::from_millis(1_500),\n    ));"),
}


def assertion_site(repo: Path, name: str) -> tuple[str, int, str]:
    short = name.split("::")[-1]
    path = ACTOR_TEST if name.startswith(ACTOR) else PROVIDER_SOURCE
    source = (repo / path).read_text()
    functions = list(re.finditer(r"(?m)^\s*(?:async )?fn (m4c76_\w+)\(\) \{", source))
    chosen = [i for i, match in enumerate(functions) if match[1] == short]
    require(len(chosen) == 1, "assertion_function_not_unique")
    i = chosen[0]
    start = functions[i].start()
    end = functions[i + 1].start() if i + 1 < len(functions) else len(source)
    anchor = ASSERTIONS[short]
    body = source[start:end]
    require(body.count(anchor.anchor) == 1, "assertion_anchor_not_unique")
    offset = start + body.index(anchor.anchor) + anchor.anchor.rindex("assert")
    return path, source.count("\n", 0, offset) + 1, anchor.message


def test_hashes(repo: Path) -> dict[str, str]:
    provider = (repo / PROVIDER_SOURCE).read_bytes()
    marker = TEST_MARKER.encode()
    require(provider.count(marker) == 1, "test_region_not_unique")
    return {
        ACTOR_TEST: digest((repo / ACTOR_TEST).read_bytes()),
        PROVIDER_SOURCE + "#tests": digest(provider[provider.index(marker):]),
    }


def check_inventory(output: str) -> None:
    names = re.findall(r"^([\w:]+): test$", output, re.M)
    require(tuple(sorted(names)) == INVENTORY, "inventory_mismatch")
    require(re.findall(r"^\d+ tests?, \d+ benchmarks?$", output, re.M)
            == ["20 tests, 0 benchmarks"], "inventory_count_mismatch")


def check_tests(output: str, returncode: int, names: tuple[str, ...], red: bool,
                site: tuple[str, int, str] | None = None) -> None:
    expected = "FAILED" if red else "ok"
    require(returncode == (101 if red else 0), "test_exit_mismatch")
    require(re.findall(r"^running (\d+) tests?$", output, re.M)
            == [str(len(names))], "executed_test_count_mismatch")
    records = re.findall(r"^test ([\w:]+) \.\.\. (ok|FAILED|ignored)$", output, re.M)
    require(sorted(records) == sorted((name, expected) for name in names), "test_records_mismatch")
    summaries = SUMMARY.findall(output)
    require(len(summaries) == 1, "test_summary_not_unique")
    status, passed, failed, ignored, measured, _ = summaries[0]
    require((status, int(passed), int(failed), int(ignored), int(measured))
            == (expected, 0 if red else len(names), len(names) if red else 0, 0, 0),
            "test_summary_mismatch")
    panics = re.findall(
        r"^thread '([^']+)'(?: \(\d+\))? panicked at ([^\n]+):(\d+):(\d+):\n([^\n]+)",
        output, re.M)
    if not red:
        require(not panics and "panicked at" not in output, "green_contains_panic")
        return
    require(len(names) == 1 and site is not None, "red_contract_invalid")
    require(len(panics) == 1 and output.count("panicked at") == 1, "panic_count_mismatch")
    name, path, line, _, message = panics[0]
    require(name == names[0] and path == site[0] and int(line) == site[1]
            and message.startswith(site[2]), "wrong_assertion")
    require(re.findall(r"^    ([\w:]+)$", output, re.M) == list(names), "failure_list_mismatch")


def check_compilation(output: str, returncode: int, target: Path) -> Path:
    require(returncode == 0, "compile_failed")
    messages = []
    for line in output.splitlines():
        if line.startswith("{"):
            try:
                messages.append(json.loads(line))
            except (ValueError, TypeError):
                raise Refusal("compile_json_invalid") from None
    require([m.get("success") for m in messages if m.get("reason") == "build-finished"]
            == [True], "compile_completion_missing")
    artifacts = [m for m in messages if m.get("reason") == "compiler-artifact"
                 and m.get("target", {}).get("name") == "tunnel_client"
                 and m.get("profile", {}).get("test") is True and m.get("executable")]
    require(len(artifacts) == 1, "compile_test_artifact_missing")
    executable = Path(artifacts[0]["executable"])
    require(executable.is_absolute() and executable.resolve().is_relative_to(target.resolve()),
            "compile_artifact_outside_target")
    return executable


@dataclass(frozen=True)
class Artifact:
    path: Path
    identifier: str
    size_bytes: int
    sha256: str

    def public(self):
        # The absolute compiler path is never copied into the public receipt.
        return {"identifier": self.identifier, "size_bytes": self.size_bytes,
                "sha256": self.sha256}


def fingerprint_artifact(path: Path, target: Path, clock, deadline, interrupted,
                         *, executable_kind="client_library") -> Artifact:
    """Bounded regular-file read; no symlinks, binary copies, or full-file buffer."""
    def budget():
        require(not interrupted(), "interrupted")
        require(clock() < deadline, "artifact_hash_timeout")

    def identity(info):
        return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns

    budget()
    require(executable_kind in ("client_library", "provider_dispatcher"), "artifact_kind_invalid")
    try:
        canonical = path.resolve(strict=True)
        require(target.is_absolute() and target.resolve() == target
                and path.is_absolute() and canonical == path
                and path.is_relative_to(target), "artifact_path_invalid")
        identifier = path.relative_to(target).as_posix()
        pattern = ARTIFACT_IDENTIFIER if executable_kind == "client_library" else re.compile(
            r"debug/deps/dispatcher-[0-9a-f]{16}")
        require(pattern.fullmatch(identifier) is not None, "artifact_identifier_invalid")
        before = path.lstat()
        require(stat.S_ISREG(before.st_mode), "artifact_not_regular")
        require(0 < before.st_size <= MAX_ARTIFACT_BYTES, "artifact_size_invalid")
        budget()
        # O_NONBLOCK also prevents a substituted FIFO from blocking open().
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            stream = os.fdopen(descriptor, "rb", buffering=0)
        except BaseException:
            os.close(descriptor)
            raise
        with stream:
            opened = os.fstat(stream.fileno())
            require(stat.S_ISREG(opened.st_mode) and identity(opened) == identity(before),
                    "artifact_changed_during_hash")
            count, checksum = 0, hashlib.sha256()
            while True:
                budget()
                chunk = stream.read(HASH_CHUNK_BYTES)
                if not chunk:
                    break
                count += len(chunk)
                require(count <= before.st_size and count <= MAX_ARTIFACT_BYTES,
                        "artifact_changed_during_hash")
                checksum.update(chunk)
            budget()
            require(count == before.st_size and identity(os.fstat(stream.fileno())) == identity(before)
                    and identity(path.lstat()) == identity(before), "artifact_changed_during_hash")
    except OSError:
        raise Refusal("artifact_unreadable") from None
    budget()
    return Artifact(path, identifier, count, checksum.hexdigest())


def check_running_artifact(output: str, artifact: Artifact, repo: Path) -> None:
    records = re.findall(
        r"^\s*Running unittests (?:src/lib\.rs|crates/tunnel-client/src/lib\.rs) \(([^\n]+)\)$",
        output, re.M)
    # Exactly one known Cargo launch record; absent/extra records are not proof.
    expected = {str(artifact.path), os.path.relpath(artifact.path, repo)}
    require(len(records) == 1 and records[0] in expected
            and len(re.findall(r"^\s*Running\b", output, re.M)) == 1,
            "running_artifact_mismatch")


class ProcessOps:
    """Linux implementation; tests replace this entire process boundary."""

    monotonic = staticmethod(time.monotonic)
    sleep = staticmethod(time.sleep)

    @staticmethod
    def start(argv, cwd, env):
        return subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                start_new_session=True, bufsize=0)

    @staticmethod
    def read(process, timeout):
        ready, _, _ = select.select([process.stdout], [], [], timeout)
        return os.read(process.stdout.fileno(), 65536) if ready else None

    @staticmethod
    def group_exists(pid):
        try:
            os.killpg(pid, 0)
            return True
        except ProcessLookupError:
            return False

    @staticmethod
    def signal_group(pid, number):
        try:
            os.killpg(pid, number)
        except ProcessLookupError:
            pass


class Supervisor:
    def __init__(self, ops=None):
        self.ops = ops or ProcessOps()
        self.interrupted = False
        self.deadline = self.ops.monotonic() + MAIN_SECONDS

    def on_signal(self, _number, _frame):
        # No asynchronous exception can interrupt source restoration.
        self.interrupted = True

    def cleanup(self, process):
        reaped, absent = False, False
        try:
            for number, budget in ((signal.SIGTERM, 2), (signal.SIGKILL, 3)):
                if process.poll() is not None and not self.ops.group_exists(process.pid):
                    break
                self.ops.signal_group(process.pid, number)
                until = self.ops.monotonic() + budget
                while self.ops.monotonic() < until:
                    if process.poll() is not None and not self.ops.group_exists(process.pid):
                        break
                    self.ops.sleep(min(0.05, max(0, until - self.ops.monotonic())))
            process.wait(timeout=0)
            reaped = True
        except BaseException:
            pass
        try:
            absent = not self.ops.group_exists(process.pid)
        except BaseException:
            pass
        return reaped, absent

    def run(self, argv, cwd, env, log: Path, seconds, *, cleanup_deadline=None):
        limit = min(self.ops.monotonic() + seconds,
                    self.deadline if cleanup_deadline is None else cleanup_deadline)
        status, process, returncode = "completed", None, None
        reaped, absent, count = False, False, 0
        with log.open("xb") as stream:
            try:
                require(self.ops.monotonic() < limit, "overall_timeout")
                require(not self.interrupted or cleanup_deadline is not None, "interrupted")
                process = self.ops.start(argv, cwd, env)
                eof, exited = False, None
                while True:
                    now = self.ops.monotonic()
                    require(not self.interrupted or cleanup_deadline is not None, "interrupted")
                    require(now < limit, "command_timeout")
                    chunk = self.ops.read(process, min(0.1, limit - now)) if not eof else None
                    if chunk == b"":
                        eof = True
                    elif chunk:
                        stream.write(chunk[:max(0, MAX_LOG_BYTES - count)])
                        count += len(chunk)
                        require(count <= MAX_LOG_BYTES, "output_limit")
                    returncode = process.poll()
                    if returncode is not None:
                        if eof:
                            break
                        exited = now if exited is None else exited
                        require(now - exited < 1, "output_pipe_unclosed")
                    if eof:
                        self.ops.sleep(min(0.05, max(0, limit - self.ops.monotonic())))
                require(not self.ops.group_exists(process.pid), "owned_group_survived")
            except Refusal as error:
                status = str(error)
            except BaseException as error:
                status = "interrupted" if isinstance(error, KeyboardInterrupt) else "process_io_failed"
            finally:
                if process is not None:
                    reaped, absent = self.cleanup(process)
                    try:
                        returncode = process.poll()
                        process.stdout.close()
                    except BaseException:
                        if status == "completed":
                            status = "process_close_failed"
        return {"status": status, "returncode": returncode, "direct_child_reaped": reaped,
                "owned_group_absent": absent, "process_started": process is not None,
                "log_bytes": log.stat().st_size, "log_sha256": digest(log.read_bytes())}


class Sources:
    def __init__(self, repo: Path, backup: Path):
        self.repo = repo
        self.paths = tuple(sorted({case["path"] for case in PLAN["cases"]} | {ACTOR_TEST}))
        self.original = {path: (repo / path).read_bytes() for path in self.paths}
        self.hashes = {path: digest(data) for path, data in self.original.items()}
        self.tests = test_hashes(repo)
        self.active = None
        for index, path in enumerate(self.paths):
            (backup / f"source-{index}.bin").write_bytes(self.original[path])

    def verify(self):
        for path, data in self.original.items():
            expected = self.active[1] if self.active and path == self.active[0] else data
            require((self.repo / path).read_bytes() == expected, "source_bytes_changed")
        require(test_hashes(self.repo) == self.tests, "test_hash_changed")

    def apply(self, case):
        require(self.active is None, "mutation_already_active")
        self.verify()
        path = case["path"]
        before, after = case["before"].encode(), case["after"].encode()
        source = self.original[path]
        require(before and source.count(before) == 1 and before != after, "mutation_not_unique")
        changed = source.replace(before, after)
        self.active = path, changed
        self.write(path, changed)
        self.verify()

    def write(self, path, content):
        target = self.repo / path
        temporary = target.with_name(target.name + ".m4-witness-tmp")
        require(not temporary.exists(), "source_temporary_exists")
        try:
            with temporary.open("xb") as stream:
                stream.write(content)
            temporary.replace(target)
        finally:
            temporary.unlink(missing_ok=True)

    def restore(self):
        if self.active:
            path, changed = self.active
            current = (self.repo / path).read_bytes()
            require(current in (changed, self.original[path]), "restore_foreign_edit")
            self.write(path, self.original[path])
            self.active = None
        self.verify()


class Controller:
    def __init__(self, repo: Path, expected: str, output: Path, supervisor=None):
        self.repo, self.expected, self.output = repo.resolve(), expected, output.resolve()
        self.supervisor = supervisor or Supervisor()
        self.sources = None
        self.artifact = None
        self.sequence = 0
        self.phase = "setup"
        self.receipt = {
            "schema_version": 1, "plan_sha256": PLAN_SHA256, "status": "incomplete",
            "first_failure": None, "cleanup_failures": [], "commands": [], "mutants": [],
            "baseline_green": False, "final_green": False, "source_restored": False,
            "active_mutation": None,
            "compile_artifacts": [], "artifact_runs": [],
            "artifact_hash_max_bytes": MAX_ARTIFACT_BYTES,
            "artifact_hash_chunk_bytes": HASH_CHUNK_BYTES, "artifact_hash_seconds": HASH_SECONDS,
            "separate_required_checks": ["existing_gate4_guard_deletion", "full_rust_milestones_platforms"],
            "main_budget_seconds": MAIN_SECONDS, "cleanup_allowance_seconds": CLEANUP_SECONDS,
            "escaped_descendants": "not_observed_or_claimed_joined",
        }
        self.env = dict(os.environ)
        # No inherited compiler wrappers, flags, target, or shared Cargo cache.
        for key in tuple(self.env):
            if key.startswith(("CARGO_", "RUST", "SCCACHE")):
                del self.env[key]
        self.env.update({"CARGO_HOME": str(self.output / "private" / "cargo-home"),
                         "CARGO_TARGET_DIR": str(self.output / "private" / "target"),
                         "CARGO_INCREMENTAL": "0", "CARGO_TERM_COLOR": "never",
                         "CARGO_PROFILE_DEV_DEBUG": "0", "CARGO_PROFILE_TEST_DEBUG": "0",
                         "RUST_BACKTRACE": "0", "RUSTUP_TOOLCHAIN": "1.95.0",
                         "GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C"})

    def note_failure(self, code, *, cleanup=False):
        failure = {"phase": self.phase, "code": code}
        if self.receipt["first_failure"] is None:
            self.receipt["first_failure"] = failure
        if cleanup:
            self.receipt["cleanup_failures"].append(failure)

    def save(self):
        target = self.output / "public" / "receipt.json"
        temporary = target.with_suffix(".tmp")
        temporary.write_text(json.dumps(self.receipt, sort_keys=True, indent=2) + "\n")
        temporary.replace(target)

    def command(self, argv, seconds, *, cleanup_deadline=None):
        self.sequence += 1
        log = self.output / "private" / f"command-{self.sequence:03}.log"
        result = self.supervisor.run(argv, self.repo, self.env, log, seconds,
                                     cleanup_deadline=cleanup_deadline)
        self.receipt["commands"].append({"phase": self.phase, **result})
        if result["status"] != "completed":
            self.note_failure(result["status"])
        if result["process_started"] and not (result["direct_child_reaped"] and result["owned_group_absent"]):
            self.note_failure("process_cleanup_unconfirmed", cleanup=True)
        # Persistence cannot replace a process failure already observed.
        self.save()
        require(result["status"] == "completed", result["status"])
        require(result["direct_child_reaped"] and result["owned_group_absent"], "process_cleanup_unconfirmed")
        return log.read_text(errors="replace"), result["returncode"]

    def git(self, args, *, cleanup_deadline=None):
        output, code = self.command(("git", *args), 15, cleanup_deadline=cleanup_deadline)
        require(code == 0, "git_failed")
        return output

    def identity(self, *, cleanup_deadline=None):
        head = self.git(("rev-parse", "HEAD"), cleanup_deadline=cleanup_deadline).strip()
        require(head == self.expected, "head_changed")
        dirty = self.git(("status", "--porcelain", "--untracked-files=all"),
                         cleanup_deadline=cleanup_deadline)
        expected = f" M {self.sources.active[0]}\n" if self.sources and self.sources.active else ""
        require(dirty == expected, "checkout_diff_mismatch")
        if self.sources:
            self.sources.verify()

    def compile(self):
        self.artifact = None
        output, code = self.command((*CARGO, "--no-run", "--message-format=json"), 900)
        path = check_compilation(output, code, self.output / "private" / "target")
        artifact = self.hash_artifact(path)
        self.sources.verify()
        self.artifact = artifact
        self.receipt["compile_artifacts"].append({"phase": self.phase,
                                                  "command_sequence": self.sequence, **artifact.public()})
        self.save()
        return artifact

    def hash_artifact(self, path):
        return fingerprint_artifact(path, self.output / "private" / "target",
                                    self.supervisor.ops.monotonic,
                                    min(self.supervisor.deadline,
                                        self.supervisor.ops.monotonic() + HASH_SECONDS),
                                    lambda: self.supervisor.interrupted)

    def artifact_command(self, argv, seconds):
        require(self.artifact is not None, "compiled_artifact_missing")
        before = self.hash_artifact(self.artifact.path)
        require(before == self.artifact, "artifact_changed_before_run")
        run = {"phase": self.phase, "compile_index": len(self.receipt["compile_artifacts"]) - 1,
               "command_sequence": self.sequence + 1, "selector": argv[len(CARGO)],
               "identifier": before.identifier, "before_sha256": before.sha256,
               "after_sha256": None, "running_record_verified": False}
        self.receipt["artifact_runs"].append(run)
        self.save()
        output, code = self.command(argv, seconds)
        # A failed/unknown command retains its first failure and the incomplete
        # artifact record. No post-deadline hashing is started during cleanup.
        after = self.hash_artifact(self.artifact.path)
        run["after_sha256"] = after.sha256
        require(after == self.artifact, "artifact_changed_after_run")
        check_running_artifact(output, self.artifact, self.repo)
        run["running_record_verified"] = True
        self.sources.verify()
        self.save()
        return output, code

    def green(self):
        output, code = self.artifact_command((*CARGO, "m4c76_", "--", "--test-threads=1"), 180)
        check_tests(output, code, INVENTORY, False)
        self.sources.verify()

    def execute(self):
        require(re.fullmatch(r"[0-9a-f]{40}", self.expected) is not None, "invalid_expected_commit")
        require(not self.output.is_relative_to(self.repo), "output_inside_checkout")
        self.output.mkdir(mode=0o700)
        (self.output / "private").mkdir(mode=0o700)
        (self.output / "public").mkdir(mode=0o700)
        try:
            require(sys.platform == "linux" and os.environ.get("GITHUB_ACTIONS") == "true",
                    "hosted_linux_required")
            self.identity()
            tree = self.git(("rev-parse", "HEAD^{tree}")).strip()
            require(re.fullmatch(r"[0-9a-f]{40}", tree) is not None, "invalid_tree")
            self.receipt.update({"commit": self.expected, "tree": tree})
            self.sources = Sources(self.repo, self.output / "private")
            self.receipt.update({"source_sha256": self.sources.hashes, "test_sha256": self.sources.tests,
                                 "inventory_sha256": digest(("\n".join(INVENTORY) + "\n").encode())})
            self.phase = "baseline_compile"
            self.compile()
            self.phase = "inventory"
            output, code = self.artifact_command((*CARGO, "m4c76_", "--", "--list"), 180)
            require(code == 0, "inventory_command_failed")
            check_inventory(output)
            self.phase = "baseline_green"
            self.green()
            self.receipt["baseline_green"] = True
            for case in PLAN["cases"]:
                self.phase = case["id"]
                self.identity()
                try:
                    self.sources.apply(case)
                    self.receipt["active_mutation"] = {
                        "id": case["id"], "path": case["path"], "match_count": 1,
                        "before_sha256": self.sources.hashes[case["path"]],
                        "after_sha256": digest(self.sources.active[1]),
                        "test_sha256": self.sources.tests,
                    }
                    self.save()
                    self.identity()
                    self.compile()
                    assertions = []
                    for name in case["witnesses"]:
                        site = assertion_site(self.repo, name)
                        output, code = self.artifact_command((*CARGO, name, "--", "--exact", "--test-threads=1"), 120)
                        self.sources.verify()
                        check_tests(output, code, (name,), True, site)
                        assertions.append({"test": name, "path": site[0], "line": site[1],
                                           "executed": 1, "failed": 1})
                    self.receipt["mutants"].append({**self.receipt["active_mutation"],
                                                     "status": "assertion_red", "compile_verified": True,
                                                     "assertions": assertions})
                except Refusal as error:
                    self.note_failure(str(error))
                    raise
                except BaseException as error:
                    self.note_failure("interrupted" if isinstance(error, KeyboardInterrupt) else "unexpected_failure")
                    raise
                finally:
                    try:
                        self.sources.restore()
                        self.receipt["active_mutation"] = None
                    except Refusal as error:
                        self.note_failure(str(error), cleanup=True)
                    except BaseException:
                        self.note_failure("restore_failed", cleanup=True)
                require(self.receipt["first_failure"] is None, "mutation_or_restore_failed")
                self.identity()
                self.save()
            self.phase = "final_compile"
            self.compile()
            self.phase = "final_green"
            self.green()
            self.identity()
            self.receipt["final_green"] = True
        except Refusal as error:
            self.note_failure(str(error))
        except BaseException as error:
            self.note_failure("interrupted" if isinstance(error, KeyboardInterrupt) else "unexpected_failure")
        finally:
            self.phase = "cleanup"
            until = self.supervisor.ops.monotonic() + CLEANUP_SECONDS
            try:
                if self.sources:
                    self.sources.restore()
                    self.receipt["active_mutation"] = None
                    self.identity(cleanup_deadline=until)
                    self.receipt["source_restored"] = True
            except Refusal as error:
                self.note_failure(str(error), cleanup=True)
            except BaseException:
                self.note_failure("restore_failed", cleanup=True)
            if self.supervisor.interrupted:
                self.note_failure("interrupted")
            self.receipt["status"] = "passed" if self.receipt["first_failure"] is None else "failed"
            self.save()
            # A signal handler can run during the final atomic receipt write.
            # Once failed, later signals cannot change the retained cause.
            if self.supervisor.interrupted and self.receipt["status"] == "passed":
                self.note_failure("interrupted")
                self.receipt["status"] = "failed"
                self.save()
        return 0 if self.receipt["status"] == "passed" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--output", type=Path, required=True, help="new private directory outside checkout")
    args = parser.parse_args()
    os.umask(0o077)
    controller = Controller(args.repository, args.expected_commit, args.output)
    signal.signal(signal.SIGTERM, controller.supervisor.on_signal)
    signal.signal(signal.SIGINT, controller.supervisor.on_signal)
    try:
        result = controller.execute()
    except (Refusal, OSError):
        print("M4 authorization witnesses: setup refused; no RED claimed.")
        return 1
    print("M4 authorization witnesses: " + controller.receipt["status"] + ".")
    return result


if __name__ == "__main__":
    raise SystemExit(main())
