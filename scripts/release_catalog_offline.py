"""Bounded offline CLI delivery witness for an already verified archive relay.

Repository synthetic fixtures are separately source-bound; they are not archive
assets. No Redis, recovery, apply, custody, or syscall network-isolation claim.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import tempfile
import time

FIXTURES = {
    "offline_catalog_config.toml": "7b126e9f661b42d2e13e4a9bcfb126b5cc867fe8707a748f3bcf270baba97f9b",
    "offline_catalog_bundle.json": "c1d37050ba8aeb869ed97748a1b21f48bfd884c6cc9534917d6359343e4e0e8f",
}
SMALL_LIMIT = 16 * 1024
OUTPUT_LIMIT = 64 * 1024
BINARY_LIMIT = 512 * 1024 * 1024
CHUNK = 1024 * 1024
COMMAND_SECONDS = 30
STAGE_SECONDS = 120
CLEANUP_SECONDS = 5
BUNDLE_DIGEST = "6e34dcfa69fbc53bd7115f6ee2885d80e56c35c6c10faf4649f341a020fbab7b"


class Refusal(Exception):
    """Only closed codes reach the public result."""


def require(condition, code):
    if not condition:
        raise Refusal(code)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def metadata_key(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def validate_metadata(info, private=False):
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "file-not-regular-single-link")
    if private:
        require(stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.geteuid(),
                "file-not-private")


def read_bound(path, limit, guard, private=False, keep=True):
    """No-follow, bounded streaming hash with stable file and path identities."""
    guard()
    before = path.lstat()
    validate_metadata(before, private)
    require(before.st_size <= limit, "file-size-bound")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        require(metadata_key(opened) == metadata_key(before), "file-changed")
        data, hashed, size = [], hashlib.sha256(), 0
        while True:
            guard()
            chunk = os.read(fd, min(CHUNK, limit + 1 - size))
            if not chunk:
                break
            size += len(chunk)
            require(size <= limit, "file-size-bound")
            hashed.update(chunk)
            if keep:
                data.append(chunk)
        guard()
        require(metadata_key(os.fstat(fd)) == metadata_key(before)
                == metadata_key(path.lstat()), "file-changed")
        require(size == before.st_size, "file-changed")
        return {"sha256": hashed.hexdigest(), "bytes": size,
                "identity": metadata_key(before)}, b"".join(data)
    finally:
        os.close(fd)


class PosixProcess:
    def __init__(self, argv, cwd, env):
        self.selector = selectors.DefaultSelector()
        try:
            self.child = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                          start_new_session=True)
        except BaseException:
            self.selector.close()
            raise
        self.pid = self.child.pid

    def prepare(self):
        # The caller already owns the process before any pipe setup can fail.
        for name, stream in (("stdout", self.child.stdout), ("stderr", self.child.stderr)):
            os.set_blocking(stream.fileno(), False)
            self.selector.register(stream, selectors.EVENT_READ, name)

    def read(self, wait, remaining):
        chunks = []
        for key, _ in self.selector.select(wait):
            try:
                data = os.read(key.fileobj.fileno(), max(1, remaining))
            except BlockingIOError:
                continue
            if data:
                chunks.append((key.data, data))
                remaining -= len(data)
            else:
                self.selector.unregister(key.fileobj)
        return chunks

    def eof(self):
        return not self.selector.get_map()

    def poll(self):
        return self.child.poll()  # Popen.poll reaps the direct child.

    def group(self):
        try:
            os.killpg(self.pid, 0)
            return "present"
        except ProcessLookupError:
            return "absent"
        except PermissionError:
            return "unknown"

    def send(self, sig):
        try:
            os.killpg(self.pid, sig)
        except ProcessLookupError:
            pass

    def close(self):
        try:
            self.selector.close()
        finally:
            try:
                self.child.stdout.close()
            finally:
                self.child.stderr.close()


class Supervisor:
    def __init__(self, clock=time.monotonic, sleep=time.sleep, factory=PosixProcess):
        self.clock, self.sleep, self.factory = clock, sleep, factory
        self.interrupted = False
        self.stage_end = clock() + STAGE_SECONDS

    def guard(self):
        require(not self.interrupted, "interrupted")
        require(self.clock() < self.stage_end, "stage-timeout")

    @contextlib.contextmanager
    def signals(self):
        previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
        def mark(_sig, _frame):
            self.interrupted = True
        try:
            for sig in previous:
                signal.signal(sig, mark)
            yield
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)

    def cleanup(self, process):
        """Continue bounded owned cleanup after failures; never assert success early."""
        end, kill_at = self.clock() + CLEANUP_SECONDS, self.clock() + 2
        errors = []
        sent_kill = False
        try:
            process.send(signal.SIGTERM)
        except Exception:
            errors.append("term-failed")
        while self.clock() < end:
            try:
                reaped, group = process.poll() is not None, process.group()
                if reaped and group == "absent":
                    return {"direct_child_reaped": True, "owned_group_absent": True,
                            "errors": errors}
                if group == "unknown" and "group-unknown" not in errors:
                    errors.append("group-unknown")
            except Exception:
                if "cleanup-inspection-failed" not in errors:
                    errors.append("cleanup-inspection-failed")
            # Inspection failure must not suppress the scheduled owned-group escalation.
            if not sent_kill and self.clock() >= kill_at:
                sent_kill = True
                try:
                    process.send(signal.SIGKILL)
                except Exception:
                    errors.append("kill-failed")
            self.sleep(0.01)
        return {"direct_child_reaped": False, "owned_group_absent": False,
                "errors": errors + ["cleanup-unconfirmed"]}

    def run(self, phase, argv, cwd, env):
        output = {"stdout": bytearray(), "stderr": bytearray()}
        record = {"phase": phase, "status": "failed", "returncode": None,
                  "failure": None, "cleanup": None}
        process = None
        try:
            self.guard()
            process = self.factory(argv, cwd, env)
            process.prepare()
            end = min(self.stage_end, self.clock() + COMMAND_SECONDS)
            while True:
                self.guard()
                require(self.clock() < end, "command-timeout")
                used = sum(map(len, output.values()))
                for name, data in process.read(min(0.05, end - self.clock()), OUTPUT_LIMIT + 1 - used):
                    output[name].extend(data)
                    require(sum(map(len, output.values())) <= OUTPUT_LIMIT, "command-output-bound")
                code = process.poll()
                if code is not None:
                    require(process.group() == "absent", "command-residual-group")
                    if process.eof():
                        record.update(status="completed", returncode=code,
                                      cleanup={"direct_child_reaped": True,
                                               "owned_group_absent": True, "errors": []})
                        break
        except Refusal as error:
            record["failure"] = str(error)
        except KeyboardInterrupt:
            record["failure"] = "interrupted"
        except Exception:
            record["failure"] = "command-supervision-error"
        finally:
            if process is not None:
                if record["status"] != "completed":
                    try:
                        record["cleanup"] = self.cleanup(process)
                    except BaseException:
                        record["cleanup"] = {"direct_child_reaped": False, "owned_group_absent": False,
                                             "errors": ["cleanup-exception"]}
                try:
                    process.close()
                except Exception:
                    record["status"] = "failed"
                    record["failure"] = record["failure"] or "command-close-error"
            for name, data in output.items():
                record[name] = {"bytes": len(data), "sha256": digest(data)}
        return record, bytes(output["stdout"]), bytes(output["stderr"])


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "summary-json")
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Refusal("summary-json")))
    except (ValueError, UnicodeError):
        raise Refusal("summary-json") from None


def same_json(actual, expected):
    """Unlike ==, JSON booleans cannot impersonate integers."""
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return actual.keys() == expected.keys() and all(same_json(actual[k], v) for k, v in expected.items())
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(same_json(x, y) for x, y in zip(actual, expected))
    return actual == expected


def expected_plan(bundle, bundle_hash):
    return json.dumps({
        "schema_version": 1, "status": "offline_draft",
        "deployment_id": bundle["deployment_id"], "redis_namespace": bundle["redis_namespace"],
        "baseline_sha256": bundle_hash, "target_sha256": bundle_hash,
        "baseline_catalog_digest": BUNDLE_DIGEST, "target_catalog_digest": BUNDLE_DIGEST,
        "baseline_source": bundle["source"], "target_source": bundle["source"],
        "historical_completeness": "unproven", "custody": "unproven", "quiescence": "unproven",
        "external_anchors_verified": False, "apply_authorized": False, "differences": [],
    }, ensure_ascii=False, separators=(",", ":")).encode()


def create_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
    finally:
        os.close(fd)


def public_file(record):
    return {k: record[k] for k in ("sha256", "bytes")}


def supported_host():
    return os.name == "posix"


def private_parent(info):
    return (stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
            and info.st_uid == os.geteuid())


def _check(binary, fixture_root, work, env, sup):
    receipt = {"schema_version": 1, "status": "failed", "scope": "archive-relay-repository-synthetic-inputs",
               "first_failure": None, "cleanup_failures": [], "commands": [], "inputs": {},
               "binary": None, "plan": None, "inputs_unchanged": False, "binary_unchanged": False,
               "temporary_tree_removed": False,
               "bounds": {"stage_seconds": STAGE_SECONDS, "command_seconds": COMMAND_SECONDS,
                          "cleanup_seconds": CLEANUP_SECONDS, "output_bytes": OUTPUT_LIMIT},
               "network_isolation_claimed": False, "apply_authorized": False}
    snapshots = {}
    private_snapshots = {}
    temporary = None
    def latch(code):
        receipt["first_failure"] = receipt["first_failure"] or code
    try:
        require(supported_host(), "unsupported-offline-witness-host")
        before, _ = read_bound(binary, BINARY_LIMIT, sup.guard, keep=False)
        receipt["binary"] = public_file(before)
        inputs = {}
        for name, expected in FIXTURES.items():
            record, data = read_bound(fixture_root / name, SMALL_LIMIT, sup.guard)
            require(record["sha256"] == expected, "fixture-hash")
            snapshots[name] = record
            receipt["inputs"][name] = public_file(record)
            inputs[name] = data
        temporary = Path(tempfile.mkdtemp(prefix="catalog-offline-", dir=work.resolve()))
        private = temporary.resolve(strict=True)
        info = private.lstat()
        directory_identity = (info.st_dev, info.st_ino)
        require(private_parent(info), "fixture-parent-not-private")
        config, baseline, target, output = [private / name for name in ("config", "baseline", "target", "plan")]
        for path, data in [(config, inputs["offline_catalog_config.toml"]),
                           (baseline, inputs["offline_catalog_bundle.json"]),
                           (target, inputs["offline_catalog_bundle.json"])]:
            create_private(path, data)
            copied = read_bound(path, SMALL_LIMIT, sup.guard, private=True)[0]
            require(copied["sha256"] == digest(data) and copied["bytes"] == len(data), "private-input-copy")
            private_snapshots[path] = copied
        bundle_hash = FIXTURES["offline_catalog_bundle.json"]
        plan_bytes = expected_plan(strict_json(inputs["offline_catalog_bundle.json"]), bundle_hash)
        bundle_args = ["catalog-bundle-check", "--config", str(config), "--bundle", str(baseline),
                       "--expected-bundle-sha256", bundle_hash]
        plan_args = ["catalog-reconcile-plan", "--config", str(config), "--baseline", str(baseline),
                     "--expected-baseline-sha256", bundle_hash, "--target", str(target),
                     "--expected-target-sha256", bundle_hash, "--output", str(output)]
        def invoke(phase, args, code, expected=None, error=None):
            record, stdout, stderr = sup.run(phase, [str(binary), *args], private, env)
            receipt["commands"].append(record)
            require(record["status"] == "completed", record["failure"] or "command-incomplete")
            require(record["cleanup"] == {"direct_child_reaped": True, "owned_group_absent": True, "errors": []}, "command-cleanup")
            require(record["returncode"] == code, "command-exit")
            if expected is not None:
                require(not stderr and same_json(strict_json(stdout), expected), "command-summary")
            else:
                require(not stdout and stderr == ("tunnel-relay: " + error + "\n").encode(), "command-refusal")
        unproven = {"historical_completeness": "unproven", "custody": "unproven", "quiescence": "unproven", "apply_authorized": False}
        invoke("bundle-valid", bundle_args, 0, {"schema_version": 1, "status": "schema_valid_only",
               "file_sha256": bundle_hash, "catalog_digest": BUNDLE_DIGEST,
               "key_count": 11, "canonical_byte_count": 1796, **unproven})
        invoke("plan-valid", plan_args, 0, {"schema_version": 1, "status": "offline_draft",
               "plan_sha256": digest(plan_bytes), "difference_count": 0,
               "external_anchors_verified": False, **unproven})
        plan_record, actual = read_bound(output, SMALL_LIMIT, sup.guard, private=True)
        require(actual == plan_bytes, "plan-bytes")
        receipt["plan"] = public_file(plan_record)
        invoke("bundle-wrong-hash", [*bundle_args[:-1], "0" * 64], 1,
               error="catalog bundle expected hash does not match")
        invoke("plan-create-only", plan_args, 1, error="output already exists or cannot be created")
        require(read_bound(output, SMALL_LIMIT, sup.guard, private=True)[0] == plan_record, "plan-changed")
        require(bounded_names(private) == {"config", "baseline", "target", "plan"}, "fixture-extra-output")
        sup.guard()
    except Refusal as error:
        latch(str(error))
    except KeyboardInterrupt:
        latch("interrupted")
    except Exception:
        latch("offline-witness-error")
    finally:
        # Integrity checking cannot gain another full stage budget after failure.
        try:
            sup.guard()
            for name, old in snapshots.items():
                require(read_bound(fixture_root / name, SMALL_LIMIT, sup.guard)[0] == old, "fixture-changed")
            for path, old in private_snapshots.items():
                require(read_bound(path, SMALL_LIMIT, sup.guard, private=True)[0] == old, "private-input-changed")
            receipt["inputs_unchanged"] = len(snapshots) == len(FIXTURES)
            if receipt["binary"] is not None:
                require(read_bound(binary, BINARY_LIMIT, sup.guard, keep=False)[0] == before, "binary-changed")
                receipt["binary_unchanged"] = True
        except Refusal as error:
            latch(str(error)); receipt["cleanup_failures"].append(str(error))
        except Exception:
            latch("integrity-check-error"); receipt["cleanup_failures"].append("integrity-check-error")
        if temporary is not None:
            try:
                cleanup_end = sup.clock() + CLEANUP_SECONDS
                require(sup.clock() < cleanup_end, "temporary-cleanup-timeout")
                info = private.lstat()
                require(stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino) == directory_identity,
                        "temporary-directory-changed")
                names = bounded_names(private)
                require(names <= {"config", "baseline", "target", "plan"}, "temporary-extra-output")
                for name in names:
                    require(sup.clock() < cleanup_end, "temporary-cleanup-timeout")
                    # Unlink only known entries; never follow or recursively remove paths.
                    (private / name).unlink()
                require(sup.clock() < cleanup_end, "temporary-cleanup-timeout")
                private.rmdir()
                require(not os.path.lexists(private), "temporary-cleanup")
                receipt["temporary_tree_removed"] = True
            except Exception:
                latch("temporary-cleanup"); receipt["cleanup_failures"].append("temporary-cleanup")
        if sup.interrupted:
            latch("interrupted")
        if receipt["first_failure"] is None and not receipt["cleanup_failures"]:
            if (len(receipt["commands"]) == 4 and receipt["plan"] is not None
                    and receipt["inputs_unchanged"] and receipt["binary_unchanged"]
                    and receipt["temporary_tree_removed"]):
                receipt["status"] = "passed"
            else:
                latch("incomplete-witness")
    require(len(json.dumps(receipt).encode()) <= SMALL_LIMIT, "receipt-bound")
    return receipt


def bounded_names(directory):
    names = set()
    with os.scandir(directory) as entries:
        for entry in entries:
            require(len(names) < 4, "fixture-extra-output")
            names.add(entry.name)
    return names


def check(binary, fixture_root, work, env, supervisor=None):
    """Return a closed receipt. Only the caller decides applicability/prerequisites."""
    sup = supervisor or Supervisor()
    with sup.signals():
        receipt = _check(binary, fixture_root, work, env, sup)
    # A signal can be latched while the context restores its previous handlers.
    if sup.interrupted:
        receipt["status"] = "failed"
        receipt["first_failure"] = receipt["first_failure"] or "interrupted"
    return receipt
