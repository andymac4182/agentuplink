#!/usr/bin/env python3
"""Disposable, actual-image cluster acceptance; never deploys to Fly.

Only the four named JSON files in --output are uploadable. Private generated
credentials, environment files and raw command output live in a separate 0700
temporary directory. No retries of failed scenarios, image builds or pulls.
"""

from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import datetime as dt
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import tempfile
import time
import tomllib
import uuid

ROOT = Path(__file__).resolve().parents[1]
DOCKER = ["docker", "--host=unix:///var/run/docker.sock"]
OWNER_LABEL = "io.agentuplink.fly-rehearsal"
IMAGE_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
ID_RE = re.compile(r"[0-9a-f]{64}\Z")
MAIN_SECONDS = 1500
CLEANUP_SECONDS = 180
COMMAND_SECONDS = 30
MAX_OUTPUT = 8 * 1024 * 1024
MAX_PRIVATE = 256 * 1024 * 1024
NETWORK_DEADLINE = None  # one sequential controller; all requests share its original budget
ROLE_BASE = {"relay": "/var/lib/agent-tunnel", "authority": "/var/lib/agentuplink-authority"}
LIMITATIONS = [
    "synthetic local Docker IPv6 and fixture CAs, not actual Fly routing or public trust",
    "echo only; other adapter acceptance is provided by separate existing gates",
    "ordinary relay/authority restart, not Redis restart or coordinated recovery",
    "bounded smoke, not device capacity, availability, backup or crash-fsync acceptance",
    "bootstrap sequencing is enforced by this controller; publisher has no catalog-bootstrap refusal gate",
]


class Refused(Exception):
    """A static, non-secret failure code suitable for the public receipt."""


def require(value, code):
    if not value:
        raise Refused(code)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def private_write(path, data):
    with open(path, "xb") as output:
        os.chmod(path, 0o600)
        output.write(data)


def safe_environment():
    result = os.environ.copy()
    for key in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"):
        result.pop(key, None)
    return result


def resource_sample(path):
    values = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, _, value = line.partition(":")
        if key == "MemAvailable":
            values["memory_available"] = int(value.split()[0]) * 1024
    require("memory_available" in values, "memory_observation_unavailable")
    values["temporary_free"] = shutil.disk_usage(path).free
    values["workspace_free"] = shutil.disk_usage(ROOT).free
    counters = dict(line.split() for line in Path("/proc/vmstat").read_text().splitlines())
    for key in ("pswpin", "pswpout", "oom_kill"):
        require(key in counters, "kernel_resource_counter_unavailable")
        values[key] = int(counters[key])
    # A smaller cgroup allowance takes precedence over host MemAvailable.
    cgroup = Path("/sys/fs/cgroup")
    maximum, current = cgroup / "memory.max", cgroup / "memory.current"
    if maximum.is_file() and current.is_file():
        limit = maximum.read_text().strip()
        if limit != "max":
            values["memory_available"] = min(values["memory_available"], max(0, int(limit) - int(current.read_text())))
    swap = cgroup / "memory.swap.current"
    if swap.is_file():
        values["cgroup_swap"] = int(swap.read_text())
    return values


def check_resources(sample, initial, *, startup=False):
    require(sample["memory_available"] >= (4 if startup else 3) * 1024**3, "memory_guard")
    require(min(sample["temporary_free"], sample["workspace_free"]) >= 1536 * 1024**2, "disk_guard")
    require(sample.get("cgroup_swap", 0) == 0, "cgroup_swap_guard")
    require(all(sample[key] == initial[key] for key in ("pswpin", "pswpout", "oom_kill")), "swap_or_oom_delta")


def safe_log_receipt(path):
    size = path.stat().st_size
    if size > MAX_OUTPUT:
        return {"bytes": size, "sha256": None, "closed_codes": [], "raw_uploaded": False,
                "output_bound_exceeded": True, "cause_classification": "unclassified"}
    data = path.read_bytes()
    codes = []
    allowed = {"CREDENTIAL_ERROR", "SUPERVISOR_ABSENT", "CONFIG_ERROR", "INVALID_CONFIG", "INVALID_INVOCATION",
               "TRANSPORT_ERROR", "PROTOCOL_ERROR", "DEADLINE_EXCEEDED", "OWNER_BUSY", "RESOURCE_EXHAUSTED",
               "AUTHORIZATION_STALE", "SESSION_CLOSED", "SUPERVISOR_FAILED", "CANCELLED"}
    for line in data.splitlines():
        try:
            value = json.loads(line)
        except (ValueError, UnicodeError):
            continue
        if isinstance(value, dict) and isinstance(value.get("error"), dict):
            code = value["error"].get("code")
            if code in allowed and code not in codes:
                codes.append(code)
    return {"bytes": len(data), "sha256": digest(data), "closed_codes": codes, "raw_uploaded": False,
            "cause_classification": "closed_code" if codes else "unclassified"}


def group_present(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False


def source_receipt(run):
    run.operation, run.role, run.subcommand = "git_source_identity", "controller", "none"
    head = run(["git", "rev-parse", "HEAD"], cwd=ROOT).decode().strip()
    tree = run(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT).decode().strip()
    dirty = run(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=ROOT)
    require(re.fullmatch(r"[0-9a-f]{40}", head) and re.fullmatch(r"[0-9a-f]{40}", tree), "source_identity")
    # Paths are retained locally, but cannot disclose unexpected user filenames
    # into an uploaded receipt. A clean source is mandatory for this CI gate.
    require(not dirty, "source_not_clean")
    return {"commit": head, "tree": tree, "dirty_paths": []}


def check_image(value, expected_id, revision):
    require(value.get("Id") == expected_id, "image_id_changed")
    config = value.get("Config") or {}
    require((config.get("Labels") or {}).get("org.opencontainers.image.revision") == revision, "image_revision")
    require(config.get("User"), "image_default_user_missing")
    return {"id": expected_id, "revision": revision, "user": config["User"], "os": value.get("Os"), "architecture": value.get("Architecture")}


def check_container(value, expected, owner):
    require(value.get("Id") == expected["id"] and value.get("Name") == "/" + expected["name"], "container_identity")
    require(value.get("Image") == expected["image"], "container_image")
    config, host = value.get("Config", {}), value.get("HostConfig", {})
    require((config.get("Labels") or {}).get(OWNER_LABEL) == owner, "container_owner")
    require((config.get("Labels") or {}).get(OWNER_LABEL + ".role") == expected["role"], "container_role")
    actual = sorted((m.get("Name"), m.get("Destination"), m.get("RW")) for m in value.get("Mounts", []))
    require(actual == sorted(expected["mounts"]), "container_mounts")
    require(host.get("NetworkMode") == expected["network"], "container_network")
    require(host.get("Memory") == expected["memory"] and host.get("MemorySwap") == expected["memory"]
            and host.get("PidsLimit") == 256, "container_resource_limits")
    require((host.get("RestartPolicy") or {}).get("Name") == "no", "container_restart_policy")
    return value.get("State", {})


def checked_status(raw, device):
    body = json.loads(raw)
    require(body.get("ok") is True and body.get("command") == "status", "client_status_envelope")
    result = body.get("result", {})
    require(result.get("device_id") == device, "client_status_device")
    require(result.get("rotation_policy") == {"interval_seconds": 300, "handshake_timeout_seconds": 10, "overlap_seconds": 30}, "client_rotation_policy")
    session = result.get("session")
    if session is not None:
        require({"phase", "session_id", "epoch", "active_generation", "candidate_generation", "rotations_completed",
                 "recovery_attempt", "recovery_attempt_deadline_ms", "recovery_episode_deadline_ms"} <= set(session), "client_status_missing_fields")
    return result


def check_identity_refusal(raw):
    rows = [json.loads(line) for line in raw.splitlines() if line]
    errors = [row for row in rows if row.get("ok") is False and row.get("command") == "connect"]
    require(len(errors) == 1 and errors[0].get("error", {}).get("code") == "CREDENTIAL_ERROR"
            and errors[0]["error"].get("retryable") is False
            and errors[0]["error"].get("message", "").startswith("the relay refused this device's identity:"), "unknown_device_refusal")
    # Use the actual CLI Diagnostic<ConnectResult> envelope, not a nonexistent
    # `event` field. Even a ready-then-refused path must fail this control.
    require(not any(row.get("ok") is True and row.get("command") == "connect" for row in rows), "unknown_device_was_ready")


def ready_session(status):
    session = status.get("session") or {}
    return session.get("phase") == "active" and session.get("active_generation") is not None and session.get("session_id") is not None


def check_rotation(before, after):
    require(after.get("sessions") == before.get("sessions") == 1, "rotation_reconnected")
    a, b = before["session"], after["session"]
    require(b.get("session_id") == a["session_id"] and b.get("epoch") == a["epoch"], "rotation_session_changed")
    require(b["recovery_attempt"] is None and b["recovery_attempt_deadline_ms"] is None
            and b["recovery_episode_deadline_ms"] is None, "rotation_recovery")
    return (ready_session(after) and b["rotations_completed"] >= a["rotations_completed"] + 1
            and b["active_generation"] >= a["active_generation"] + 1
            and b.get("candidate_generation") is None)


def check_checkpoint(value, inventory, nonce):
    require(value.get("schema_version") == 1 and value.get("nonce") == nonce, "checkpoint_nonce_schema")
    require(value.get("deployment_id") == inventory["deployment_id"] and value.get("deployment_incarnation") == inventory["deployment_incarnation"], "checkpoint_deployment")
    floors = value.get("minimum_versions", {})
    require(set(floors) == {"relay-a", "relay-b", "relay-c"} and all(type(v) is int and v > 0 for v in floors.values()), "checkpoint_nodes")
    require(type(value.get("checkpoint_version")) is int and value["checkpoint_version"] > 0, "checkpoint_version")
    require(value.get("publisher_key_id") == inventory["membership"]["publisher_key_id"], "checkpoint_key")
    require(isinstance(value.get("signature"), str) and value["signature"], "checkpoint_signature_missing")
    # Cryptographic acceptance is performed by each real relay's configured
    # verifier. This HTTP observation is only an exact nonce/version join.
    return value


def check_persisted_version(before, after):
    required = {"schema_version", "deployment_id", "deployment_incarnation", "node_id", "state"}
    require(required <= set(before) and required <= set(after), "persisted_identity_missing")
    for key in ("schema_version", "deployment_id", "deployment_incarnation", "node_id"):
        require(before.get(key) == after.get(key), "persisted_identity_changed")
    a, b = before["state"], after["state"]
    require(type(a.get("checkpoint_version")) is int and type(b.get("checkpoint_version")) is int
            and b["checkpoint_version"] >= a["checkpoint_version"], "checkpoint_rollback")
    require(set(a["node_versions"]) <= set(b["node_versions"])
            and all(b["node_versions"][key] >= value for key, value in a["node_versions"].items()), "membership_rollback")


class Runner:
    def __init__(self, private, event):
        self.private, self.event = private, event
        self.deadline = time.monotonic() + MAIN_SECONDS
        self.index = 0
        self.processes = []
        self.samples = []
        self.cleanup = False
        self.initial = None
        self.stage = "preflight"
        self.operation = "none"
        self.role = "controller"
        self.subcommand = "none"
        self.stop_requested = False

    def guard(self):
        require(not self.stop_requested, "controller_interrupted")
        require(time.monotonic() < self.deadline, "controller_deadline")
        sample = resource_sample(self.private)
        check_resources(sample, self.initial)
        total = sum(p.stat().st_size for p in self.private.rglob("*") if p.is_file())
        require(total <= MAX_PRIVATE, "private_output_guard")
        if not self.samples or time.monotonic() - self.samples[-1]["monotonic"] > 5:
            self.samples.append({**sample, "monotonic": round(time.monotonic(), 3)})

    def __call__(self, args, *, timeout=COMMAND_SECONDS, data=None, cwd=None, allowed=(0,)):
        if not self.cleanup:
            self.guard()
        # Leave the original budget's final nine seconds for owned process
        # termination/reaping; cleanup never starts an unbounded late command.
        require(time.monotonic() + 9 < self.deadline, "cleanup_deadline" if self.cleanup else "controller_deadline")
        self.index += 1
        stem = self.private / f"command-{self.index:04d}"
        stdin_path = stem.with_suffix(".stdin")
        private_write(stdin_path, b"" if data is None else data)
        stdout_path, stderr_path = stem.with_suffix(".stdout"), stem.with_suffix(".stderr")
        proc = None
        error = None
        start = time.monotonic()
        try:
            with open(stdin_path, "rb") as inp, open(stdout_path, "xb") as out, open(stderr_path, "xb") as err:
                proc = subprocess.Popen(args, stdin=inp, stdout=out, stderr=err, cwd=cwd,
                                        env=safe_environment(), start_new_session=True)
                self.processes.append(proc.pid)
                deadline = min(self.deadline - 9, start + timeout)
                while proc.poll() is None:
                    require(time.monotonic() < deadline, "command_deadline")
                    require(stdout_path.stat().st_size + stderr_path.stat().st_size <= MAX_OUTPUT, "command_output_bound")
                    if not self.cleanup:
                        self.guard()
                    time.sleep(0.1)
                require(proc.returncode in allowed, "command_exit")
        except BaseException as exc:
            error = exc
        finally:
            cleanup_failures = []
            if proc is not None:
                # A CLI return does not establish the absence of its children.
                try:
                    for sig, seconds in ((signal.SIGTERM, 5), (signal.SIGKILL, 3)):
                        if not group_present(proc.pid):
                            break
                        try:
                            os.killpg(proc.pid, sig)
                        except ProcessLookupError:
                            break
                        until = time.monotonic() + seconds
                        while group_present(proc.pid) and time.monotonic() < until:
                            proc.poll()
                            time.sleep(0.05)
                    proc.wait(timeout=1)
                    require(not group_present(proc.pid), "process_group_remains")
                except BaseException as cleanup_error:
                    cleanup_failures.append(error_code(cleanup_error))
                    if error is None:
                        error = Refused("process_cleanup_failed")
            try:
                absent = proc is not None and not group_present(proc.pid)
            except BaseException as observation_error:
                absent = False
                cleanup_failures.append(error_code(observation_error))
                if error is None:
                    error = Refused("process_group_observation_failed")
            self.event("command", ordinal=self.index, exit_code=proc.returncode if proc else None,
                       elapsed_seconds=round(time.monotonic() - start, 3),
                       process_group_absent=absent, cleanup_failures=cleanup_failures,
                       stage=self.stage, operation=self.operation, role=self.role, subcommand=self.subcommand, passed=error is None,
                       stdout=safe_log_receipt(stdout_path), stderr=safe_log_receipt(stderr_path),
                       failure=error_code(error) if error else None)
        if error:
            raise error
        require(stdout_path.stat().st_size + stderr_path.stat().st_size <= MAX_OUTPUT, "command_output_bound")
        return stdout_path.read_bytes()


class Docker:
    def __init__(self, run, owner, images):
        self.run, self.owner, self.images = run, owner, images
        self.containers, self.volumes = [], []
        self.network = None
        self.inventory = []

    def call(self, args, **kw):
        allowed = {"container", "network", "image", "volume"}
        require(len(args) >= 2 and args[0] in allowed and args[1] in {
            "create", "inspect", "start", "stop", "exec", "logs", "rm", "ls", "cp"}, "docker_command_shape")
        self.run.operation = "docker_" + args[0] + "_" + args[1]
        return self.run(DOCKER + args, **kw)

    def inspect(self, item, *, identity_only=False):
        self.run.role = item["role"]
        self.run.subcommand = item.get("subcommand", "none")
        values = json.loads(self.call(["container", "inspect", item["id"]]))
        require(len(values) == 1, "container_inspection_cardinality")
        state = check_container(values[0], item, self.owner)
        if not identity_only:
            require(not state.get("OOMKilled"), "container_oom")
        return values[0]

    def volume(self, role):
        name = self.owner + "-" + role
        self.volumes.append(name)  # journal intent before a possibly ambiguous CLI return
        actual = self.call(["volume", "create", "--label", OWNER_LABEL + "=" + self.owner, name]).decode().strip()
        require(actual == name, "volume_create_identity")
        return name

    def create(self, role, image, *, mounts=(), env=None, aliases=(), ports=(), command=(), entrypoint=None,
               user=None, network=True, memory=256, interactive=False):
        name = f"{self.owner}-{len(self.containers):03d}-{role}"
        net = self.network["id"] if network else "none"
        item = {"id": None, "name": name, "role": role, "image": image, "mounts": list(mounts),
                "network": net, "memory": memory * 1024**2}
        known = {"generate-key", "initialize", "recovery-initialize", "activate-first-incarnation", "provision-catalog",
                 "add-device", "add-service", "set-grant", "revoke-grant", "initialize-membership", "check-config", "connect"}
        item["subcommand"] = command[0] if command and command[0] in known else ("python-helper" if entrypoint == "/usr/bin/python3" else "serve-or-inspect")
        self.run.role = role
        self.run.subcommand = item["subcommand"]
        self.containers.append(item)
        args = ["container", "create", "--pull=never", "--name", name, "--label", OWNER_LABEL + "=" + self.owner,
                "--label", OWNER_LABEL + ".role=" + role, "--network", net, "--memory", str(item["memory"]),
                "--memory-swap", str(item["memory"]), "--pids-limit", "256", "--restart=no", "--cap-drop=ALL",
                "--security-opt=no-new-privileges", "--log-driver=local", "--log-opt=max-size=2m", "--log-opt=max-file=1"]
        if user == "0:0":
            # These three capabilities are only used by the explicit owned-volume
            # initializer/reader, never by an ordinary serving entrypoint.
            args += ["--cap-add=CHOWN", "--cap-add=DAC_OVERRIDE", "--cap-add=FOWNER"]
        for volume, destination, write in mounts:
            args += ["--mount", f"type=volume,source={volume},target={destination},volume-nocopy" + ("" if write else ",readonly")]
        for alias in aliases:
            args += ["--network-alias", alias]
        for port in ports:
            args += ["--publish", f"127.0.0.1::{port}"]
        if env is not None:
            require(all(re.fullmatch(r"[A-Z_][A-Z_0-9]*", key) and isinstance(value, str) and not any(c in value for c in "\r\n\x00") for key, value in env.items()), "environment_shape")
            path = self.run.private / (name + ".env")
            private_write(path, "".join(f"{k}={v}\n" for k, v in sorted(env.items())).encode())
            args += ["--env-file", str(path)]
        if entrypoint:
            args += ["--entrypoint", entrypoint]
        if user:
            args += ["--user", user]
        if interactive:
            args += ["--interactive"]
        args += [image, *command]
        item["id"] = self.call(args).decode().strip()
        require(ID_RE.fullmatch(item["id"]), "container_create_id")
        self.inspect(item)
        return item

    def start(self, item, *, attached=False, data=None, expected_exit=0):
        self.inspect(item)
        output = self.call(["container", "start"] + (["--attach", "--interactive"] if attached else []) + [item["id"]],
                           data=data, allowed=(expected_exit,) if attached else (0,))
        state = self.inspect(item)["State"]
        if attached:
            require(state.get("Running") is False and state.get("ExitCode") == expected_exit, "operator_container_exit")
        else:
            require(state.get("Running") is True, "service_not_running")
        return output

    def one_shot(self, role, image, **kwargs):
        data = kwargs.pop("data", None)
        expected_exit = kwargs.pop("expected_exit", 0)
        item = self.create(role, image, interactive=True, **kwargs)
        return self.start(item, attached=True, data=data, expected_exit=expected_exit)

    def stop(self, item):
        self.inspect(item)
        self.call(["container", "stop", "--time=15", item["id"]], timeout=25)
        state = self.inspect(item)["State"]
        require(not state.get("Running") and state.get("ExitCode") == 0, "service_unclean_stop")

    def port(self, item, port):
        bindings = self.inspect(item)["NetworkSettings"]["Ports"].get(f"{port}/tcp")
        require(isinstance(bindings, list) and len(bindings) == 1 and bindings[0]["HostIp"] == "127.0.0.1", "published_port_scope")
        return int(bindings[0]["HostPort"])

    def setup_volume(self, name, uid, gid, files=None, directories=()):
        payload = {"uid": uid, "gid": gid, "directories": list(directories),
                   "files": {k: base64.b64encode(v).decode() for k, v in (files or {}).items()}}
        self.one_shot("volume-init", self.images["authority"], network=False, user="0:0",
                      mounts=[(name, "/volume", True)], entrypoint="/usr/bin/python3",
                      command=["-I", "-c", VOLUME_INITIALIZE], data=canonical(payload))

    def read_volume(self, name, relative):
        raw = self.one_shot("volume-read", self.images["authority"], network=False, user="0:0",
                            mounts=[(name, "/volume", False)], entrypoint="/usr/bin/python3",
                            command=["-I", "-c", VOLUME_READ], data=canonical({"paths": relative}))
        values = json.loads(raw)
        require(set(values) == set(relative), "volume_read_paths")
        return {key: base64.b64decode(value, validate=True) for key, value in values.items()}

    def artifact_receipt(self, role):
        """Verify shipped notices against the exact copied image executables."""
        mounts = []
        if role == "redis":
            # Redis's upstream VOLUME must not create an untracked anonymous
            # volume even for this stopped, never-executed image inspection.
            mounts = [(self.volume("redis-inspection"), "/data", True)]
        item = self.create("inspect-" + role, self.images[role], network=False,
                           mounts=mounts, entrypoint="/bin/true")
        directory = self.run.private / ("image-" + role)
        directory.mkdir(mode=0o700)
        packages = {"relay": ["tunnel-relay"], "authority": ["tunnel-authority"],
                    "client": ["tunnel-client", "tunnel-deadman"], "redis": ["redis-server"]}[role]
        verifier = load_python(ROOT / "scripts/container_notices.py", "container_notice_verifier")
        receipts = {}
        for package in packages:
            binary = directory / package
            notice = directory / (package + "-notices")
            base = "/usr/local/share/licenses/agentuplink"
            if role == "client":
                base += "-client" if package == "tunnel-client" else "-deadman"
            elif role == "redis":
                base += "-redis"
            self.call(["container", "cp", item["id"] + ":/usr/local/bin/" + package, str(binary)])
            self.call(["container", "cp", item["id"] + ":" + base, str(notice)])
            require(binary.is_file() and not binary.is_symlink(), "image_binary_shape")
            if role == "redis":
                verifier.verify_redis(notice, ROOT / "LICENSE", ROOT / "deploy/fly/cluster/images/redis/Dockerfile")
            else:
                manifest = verifier.verify(notice, binary)
                require(manifest["cargo_lock_sha256"] == digest((ROOT / "Cargo.lock").read_bytes())
                        and (notice / "LICENSE").read_bytes() == (ROOT / "LICENSE").read_bytes(), "image_notice_source_identity")
            receipts[package] = {"binary_sha256": digest(binary.read_bytes()),
                                 "notices_manifest_sha256": digest((notice / "manifest.json").read_bytes())}
        return receipts

    def cleanup(self):
        errors = []
        self.run.cleanup = True
        self.run.deadline = time.monotonic() + CLEANUP_SECONDS
        for item in reversed(self.containers):
            try:
                if not isinstance(item["id"], str) or not ID_RE.fullmatch(item["id"]):
                    # Resolve only an ambiguous create bearing our random name,
                    # then apply every ordinary identity/ownership check.
                    rows = json.loads(self.call(["container", "inspect", item["name"]]))
                    require(len(rows) == 1 and ID_RE.fullmatch(rows[0].get("Id", "")), "ambiguous_container")
                    item["id"] = rows[0]["Id"]
                value = self.inspect(item, identity_only=True)
                state = value["State"]
                if state.get("OOMKilled"):
                    errors.append({"resource": item["role"], "code": "container_oom"})
                self.inventory.append({"role": item["role"], "id": item["id"], "image": item["image"],
                                       "exit_code_before_cleanup": state.get("ExitCode"), "running_before_cleanup": state.get("Running"),
                                       "oom_killed": state.get("OOMKilled")})
                if state.get("Running"):
                    try:
                        self.call(["container", "stop", "--time=5", item["id"]], timeout=10)
                    except BaseException as exc:
                        errors.append({"resource": item["role"], "code": error_code(exc), "step": "stop"})
                # Capture private logs before removal; never put them in upload output.
                try:
                    self.call(["container", "logs", "--tail=300", item["id"]])
                except BaseException as exc:
                    errors.append({"resource": item["role"], "code": error_code(exc), "step": "logs"})
                # Failed observation/stop cannot skip the independently bounded
                # removal of an identity-verified container owned by this run.
                self.inspect(item, identity_only=True)
                self.call(["container", "rm", "--force", item["id"]])
                remaining = self.call(["container", "ls", "--all", "--quiet", "--no-trunc", "--filter", "id=" + item["id"]]).strip()
                require(not remaining, "container_remains")
            except BaseException as exc:
                errors.append({"resource": item["role"], "code": error_code(exc)})
        for name in reversed(self.volumes):
            try:
                values = json.loads(self.call(["volume", "inspect", name]))
                require(len(values) == 1 and values[0]["Name"] == name and (values[0].get("Labels") or {}).get(OWNER_LABEL) == self.owner, "volume_owner")
                self.call(["volume", "rm", name])
                require(name not in self.call(["volume", "ls", "--quiet", "--filter", "label=" + OWNER_LABEL + "=" + self.owner]).decode().splitlines(), "volume_remains")
            except BaseException as exc:
                errors.append({"resource": "volume", "code": error_code(exc)})
        if self.network:
            try:
                value = json.loads(self.call(["network", "inspect", self.network["id"]]))[0]
                if not ID_RE.fullmatch(self.network["id"]):
                    require(ID_RE.fullmatch(value.get("Id", "")), "ambiguous_network")
                    self.network["id"] = value["Id"]
                require(value["Id"] == self.network["id"] and value["Name"] == self.network["name"]
                        and (value.get("Labels") or {}).get(OWNER_LABEL) == self.owner and not value.get("Containers"), "network_owner_or_attached")
                self.call(["network", "rm", self.network["id"]])
                require(not self.call(["network", "ls", "--quiet", "--no-trunc", "--filter", "id=" + self.network["id"]]).strip(), "network_remains")
            except BaseException as exc:
                errors.append({"resource": "network", "code": error_code(exc)})
        return errors


VOLUME_INITIALIZE = r'''
import base64,json,os,pathlib,stat,sys
v=json.load(sys.stdin); root=pathlib.Path('/volume')
assert set(v)=={'uid','gid','files','directories'} and not any(root.iterdir())
os.chmod(root,0o700); os.chown(root,v['uid'],v['gid'])
for name in v['directories']:
 assert name and '/' not in name and name not in {'.','..'}
 child=root/name; child.mkdir(mode=0o700); os.chown(child,v['uid'],v['gid'])
for name,data in v['files'].items():
 p=pathlib.PurePosixPath(name); assert not p.is_absolute() and '..' not in p.parts and p.parts
 target=root.joinpath(*p.parts)
 for parent in reversed(target.parents):
  if parent==root or root in parent.parents:
   parent.mkdir(mode=0o700,exist_ok=True); os.chmod(parent,0o700); os.chown(parent,v['uid'],v['gid'])
 with target.open('xb') as f: f.write(base64.b64decode(data,validate=True))
 os.chmod(target,0o600); os.chown(target,v['uid'],v['gid'])
'''
VOLUME_READ = r'''
import base64,json,pathlib,stat,sys
v=json.load(sys.stdin); out={}; root=pathlib.Path('/volume')
for name in v['paths']:
 p=pathlib.PurePosixPath(name); assert not p.is_absolute() and '..' not in p.parts and p.parts
 target=root.joinpath(*p.parts); assert target.is_file() and not target.is_symlink() and target.stat().st_size<1048576
 out[name]=base64.b64encode(target.read_bytes()).decode()
print(json.dumps(out))
'''


def tls_context(ca, identity=None):
    context = ssl.create_default_context(cafile=str(ca))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if identity:
        context.load_cert_chain(str(identity[0]), str(identity[1]))
    return context


@contextmanager
def bounded_network():
    """An absolute bound, including peers that dribble header/body bytes."""
    require(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), "network_timer_already_active")
    remaining = 5 if NETWORK_DEADLINE is None else min(5, NETWORK_DEADLINE - time.monotonic())
    require(remaining > 0, "controller_deadline")
    previous = signal.getsignal(signal.SIGALRM)
    def expired(_signal, _frame):
        raise Refused("network_request_deadline")
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, remaining)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def http_request(port, host, context, path, *, method="GET", data=b"", headers=None):
    with bounded_network():
        return _http_request(port, host, context, path, method=method, data=data, headers=headers)


def _http_request(port, host, context, path, *, method="GET", data=b"", headers=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.sock = context.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=5), server_hostname=host)
        connection.request(method, path, body=data, headers={"Host": host, "Connection": "close", **(headers or {})})
        response = connection.getresponse()
        body = response.read(65537)
        require(len(body) <= 65536, "http_body_bound")
        return response.status, body
    finally:
        connection.close()


def read_resp(stream, depth=0):
    require(depth < 8, "redis_reply_depth")
    line = stream.readline(65537)
    require(line.endswith(b"\r\n") and len(line) <= 65536, "redis_reply_line")
    kind, value = line[:1], line[1:-2]
    if kind == b"+":
        return value.decode()
    if kind == b"-":
        # Never include Redis error text: it can contain an authenticated URL.
        raise Refused("redis_permission_denied" if value.startswith(b"NOPERM ") else "redis_command_refused")
    if kind == b":":
        return int(value)
    if kind == b"$":
        size = int(value)
        if size == -1:
            return None
        require(0 <= size <= 1024**2, "redis_bulk_bound")
        # SocketIO may return a legal short read. Retain the declared size
        # bound and the enclosing absolute request timer while joining bytes.
        parts, remaining = [], size + 2
        while remaining:
            part = stream.read(remaining)
            require(part and len(part) <= remaining, "redis_bulk_truncated")
            parts.append(part)
            remaining -= len(part)
        result = b"".join(parts)
        require(result[-2:] == b"\r\n", "redis_bulk_truncated")
        return result[:-2].decode()
    if kind == b"*":
        size = int(value)
        require(0 <= size <= 1024, "redis_array_bound")
        return [read_resp(stream, depth + 1) for _ in range(size)]
    raise Refused("redis_reply_type")


def resp_command(parts):
    encoded = [str(x).encode() for x in parts]
    return b"*" + str(len(encoded)).encode() + b"\r\n" + b"".join(b"$" + str(len(x)).encode() + b"\r\n" + x + b"\r\n" for x in encoded)


class Redis:
    def __init__(self, port, host, context, password):
        self.port, self.host, self.context, self.password = port, host, context, password

    def command(self, *parts, user="default", password=None):
        with bounded_network(), self.context.wrap_socket(socket.create_connection(("127.0.0.1", self.port), timeout=5), server_hostname=self.host) as sock:
            with sock.makefile("rb", buffering=0) as stream:
                # Raw SocketIO.write may short-write; SSL sendall completes the
                # frame or fails under the same absolute request timer.
                sock.sendall(resp_command(["AUTH", user, password or self.password]))
                require(read_resp(stream) == "OK", "redis_auth")
                sock.sendall(resp_command(parts))
                return read_resp(stream)


class PKI:
    def __init__(self, root, run):
        self.root, self.run = root, run
        self.cas = {}

    def openssl(self, args, data=None):
        require(args[0] in {"req", "x509", "pkey", "genpkey", "rsa", "dgst"}, "openssl_command_shape")
        self.run.operation, self.run.role = "openssl_" + args[0], "pki"
        return self.run(["openssl", *args], data=data)

    def ca(self, name):
        key, cert = self.root / (name + "-ca.key"), self.root / (name + "-ca.pem")
        self.openssl(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "2",
                      "-subj", "/CN=synthetic-" + name, "-keyout", str(key), "-out", str(cert), "-addext", "basicConstraints=critical,CA:TRUE",
                      "-addext", "keyUsage=critical,keyCertSign,cRLSign"])
        self.cas[name] = (cert, key)
        return cert

    def leaf(self, name, ca, sans, eku):
        key, cert = self.root / (name + ".key"), self.root / (name + ".pem")
        csr, ext = self.root / (name + ".csr"), self.root / (name + ".ext")
        private_write(ext, ("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=" + eku + "\nsubjectAltName=" + ",".join(sans) + "\n").encode())
        self.openssl(["req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-subj", "/CN=" + name,
                      "-keyout", str(key), "-out", str(csr)])
        ca_cert, ca_key = self.cas[ca]
        self.openssl(["x509", "-req", "-in", str(csr), "-CA", str(ca_cert), "-CAkey", str(ca_key), "-set_serial", "0x" + secrets.token_hex(16),
                      "-days", "1", "-sha256", "-extfile", str(ext), "-out", str(cert)])
        return cert, key

    def spki(self, cert):
        public = self.openssl(["x509", "-in", str(cert), "-pubkey", "-noout"])
        return digest(self.openssl(["pkey", "-pubin", "-outform", "DER"], public))

    def jwt(self, issuer, subject):
        key = self.root / "oidc.key"
        self.openssl(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(key)])
        modulus = self.openssl(["rsa", "-in", str(key), "-modulus", "-noout"]).decode().strip()
        require(re.fullmatch(r"Modulus=[0-9A-F]+", modulus), "oidc_modulus")
        n = bytes.fromhex(modulus.partition("=")[2])
        b64 = lambda value: base64.urlsafe_b64encode(value).rstrip(b"=")
        jwks = {"keys": [{"kty": "RSA", "kid": "synthetic", "alg": "RS256", "use": "sig", "n": b64(n).decode(), "e": "AQAB"}]}
        now = int(time.time())
        payload = {"iss": issuer, "sub": subject, "aud": "agent-tunnel", "iat": now - 5, "exp": now + 3600, "scope": "echo:invoke"}
        unsigned = b64(canonical({"alg": "RS256", "kid": "synthetic", "typ": "JWT"})) + b"." + b64(canonical(payload))
        signature = self.openssl(["dgst", "-sha256", "-sign", str(key)], unsigned)
        return canonical(jwks), (unsigned + b"." + b64(signature)).decode()


def load_python(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_renderer():
    return load_python(ROOT / "deploy/fly/cluster/render.py", "fly_cluster_renderer")


def b64(data):
    return base64.b64encode(data).decode()


def wait_until(run, predicate, seconds, code):
    deadline = time.monotonic() + seconds
    while True:
        run.guard()
        if predicate():
            return
        require(time.monotonic() < deadline, code)
        time.sleep(0.5)


def error_code(exc):
    return str(exc) if isinstance(exc, Refused) else "unexpected_" + type(exc).__name__


class Rehearsal:
    def __init__(self, run, docker, private, event):
        self.run, self.docker, self.private, self.event = run, docker, private, event
        self.prefix = docker.owner
        self.inventory = json.loads((ROOT / "deploy/fly/cluster/inventory.example.json").read_bytes())
        self.pki = PKI(private, run)
        self.relays, self.clients, self.states, self.env = [], [], {}, {}
        self.devices = [str(uuid.uuid4()) for _ in range(3)]
        self.services = [str(uuid.uuid4()) for _ in range(3)]
        self.tenant, self.user = str(uuid.uuid4()), str(uuid.uuid4())
        self.identities, self.public_hosts, self.canaries = [], [], []
        self.grant_revoked = False

    def prepare(self):
        d, inv = self.docker, self.inventory
        now = dt.datetime.now(dt.timezone.utc)
        stamp = lambda value: value.strftime("%Y-%m-%dT%H:%M:%SZ")
        inv.update(deployment_id=self.prefix, deployment_incarnation=self.prefix + "-1", redis_namespace=self.prefix,
                   evaluation_time=stamp(now), images={role: d.images[role] for role in ("relay", "authority", "redis")})
        for name in ("public", "device", "peer", "checkpoint-client", "authority", "redis", "untrusted"):
            self.pki.ca(name)
        self.password, self.publisher_password = secrets.token_hex(32), secrets.token_hex(32)
        self.jwks, self.token = self.pki.jwt(inv["oidc"]["issuer"], "synthetic-user")
        subnet = "fd" + secrets.token_hex(1) + ":" + secrets.token_hex(2) + ":" + secrets.token_hex(2) + "::/64"
        name = self.prefix + "-network"
        d.network = {"name": name, "id": name}  # resolve/verify name if create outcome is ambiguous
        nid = d.call(["network", "create", "--driver=bridge", "--ipv4=false", "--ipv6", "--subnet", subnet,
                      "--label", OWNER_LABEL + "=" + self.prefix, name]).decode().strip()
        require(ID_RE.fullmatch(nid), "network_id")
        d.network["id"] = nid
        network = json.loads(d.call(["network", "inspect", nid]))[0]
        require(network.get("EnableIPv6") is True and network.get("EnableIPv4") is False, "network_not_ipv6_only")
        self.event("network", ipv6_only=True, network_id=nid)
        for role in ("authority", "redis"):
            inv[role]["app"] = self.prefix + "-" + role
            inv[role]["volume"] = self.prefix.replace("-", "_") + "_" + role
        self.authority_host, self.redis_host = inv["authority"]["app"] + ".internal", inv["redis"]["app"] + ".internal"
        self.authority_identity = self.pki.leaf("authority", "authority", ["DNS:" + self.authority_host], "serverAuth")
        self.redis_identity = self.pki.leaf("redis", "redis", ["DNS:" + self.redis_host], "serverAuth")
        self.peer_ids, self.checkpoint_ids, self.server_ids = [], [], []
        for i, relay in enumerate(inv["relays"]):
            node = relay["node_id"]
            relay["app"], relay["volume"] = self.prefix + "-" + node, self.prefix.replace("-", "_") + "_" + node.replace("-", "_")
            host = node + "." + self.prefix + ".invalid"
            relay["public_hostname"] = host
            peer = self.pki.leaf(node + "-peer", "peer", ["DNS:" + relay["app"] + ".internal", "URI:urn:agent-tunnel:peer:" + node], "clientAuth,serverAuth")
            checkpoint = self.pki.leaf(node + "-checkpoint", "checkpoint-client", ["URI:urn:agent-tunnel:peer:" + node], "clientAuth")
            server = self.pki.leaf(node + "-server", "public", ["DNS:" + host], "serverAuth")
            device = self.pki.leaf(node + "-device", "device", ["URI:urn:agent-tunnel:device:" + self.devices[i]], "clientAuth")
            relay["peer_key"].update(spki_sha256=self.pki.spki(peer[0]), not_before=stamp(now - dt.timedelta(minutes=5)), expires_at=stamp(now + dt.timedelta(hours=1)))
            relay["checkpoint_client_spki"] = self.pki.spki(checkpoint[0])
            self.peer_ids.append(peer); self.checkpoint_ids.append(checkpoint); self.server_ids.append(server)
            self.identities.append(device); self.public_hosts.append(host); self.canaries.append("synthetic-" + str(i) + ":")
        self.unknown_device_id = str(uuid.uuid4())
        self.unknown_device = self.pki.leaf("unknown-device", "device", ["URI:urn:agent-tunnel:device:" + self.unknown_device_id], "clientAuth")
        offline = d.volume("offline")
        d.setup_volume(offline, 10002, 10002)
        for purpose in ("membership", "recovery"):
            d.one_shot("offline-" + purpose, d.images["authority"], network=False,
                       mounts=[(offline, "/offline", True)], entrypoint="/usr/local/bin/tunnel-authority",
                       command=["generate-key", "--key-id", "synthetic-" + purpose, "--private-key", "/offline/" + purpose + ".der",
                                "--public-keys", "/offline/" + purpose + ".json", "--purpose", purpose])
        keys = d.read_volume(offline, ["membership.der", "membership.json", "recovery.json"])
        trust = json.loads(keys["membership.json"])
        require(len(trust["keys"]) == 1, "membership_trust_count")
        inv["membership"].update(publisher_key_id=trust["keys"][0]["key_id"], publisher_public_key=trust["keys"][0]["public_key"])
        self.rendered = self.private / "rendered"
        manifest = load_renderer().render_to(inv, self.rendered, example=True)
        require(manifest["image_identity_kind"] == {role: "docker-config" for role in ("relay", "redis", "authority")}, "rendered_image_kind")
        for path, sha in manifest["files"].items():
            require(digest((self.rendered / path).read_bytes()) == sha, "rendered_file_hash")
        self.event("rendered", manifest_sha256=digest(canonical(manifest)), config_hashes=manifest["files"])
        read = lambda path: Path(path).read_bytes()
        default_user = "default"
        for i, relay in enumerate(inv["relays"]):
            node = relay["node_id"]
            env = tomllib.loads((self.rendered / node / "fly.toml").read_text())["env"]
            env["AT_REDIS_URL"] = f"rediss://{default_user}:{self.password}@{self.redis_host}:6379/0"
            inputs = {"AT_DEVICE_TLS_CERT_CHAIN_B64": read(self.server_ids[i][0]), "AT_DEVICE_TLS_KEY_B64": read(self.server_ids[i][1]),
                      "AT_DEVICE_CLIENT_CA_B64": read(self.pki.cas["device"][0]), "AT_CONSUMER_TLS_CERT_CHAIN_B64": read(self.server_ids[i][0]),
                      "AT_CONSUMER_TLS_KEY_B64": read(self.server_ids[i][1]), "AT_REDIS_CA_B64": read(self.pki.cas["redis"][0]),
                      "AT_OIDC_JWKS_B64": self.jwks, "AT_PEER_TLS_CERT_CHAIN_B64": read(self.peer_ids[i][0]),
                      "AT_PEER_TLS_KEY_B64": read(self.peer_ids[i][1]), "AT_PEER_CLIENT_CA_B64": read(self.pki.cas["peer"][0]),
                      "AT_MEMBERSHIP_SIGNER_TRUST_B64": keys["membership.json"], "AT_CHECKPOINT_CA_B64": read(self.pki.cas["authority"][0]),
                      "AT_CHECKPOINT_CLIENT_CERT_CHAIN_B64": read(self.checkpoint_ids[i][0]), "AT_CHECKPOINT_CLIENT_KEY_B64": read(self.checkpoint_ids[i][1]),
                      "AT_RECOVERY_TRUST_B64": keys["recovery.json"]}
            env.update({key: b64(value) for key, value in inputs.items()})
            self.env[node] = env
            self.states[node] = d.volume(node)
            d.setup_volume(self.states[node], 10001, 10001)
        env = tomllib.loads((self.rendered / "authority/fly.toml").read_text())["env"]
        env["AT_REDIS_URL"] = f"rediss://{inv['redis']['publisher_user']}:{self.publisher_password}@{self.redis_host}:6379/0"
        env.update({key: b64(value) for key, value in {"AT_MEMBERSHIP_SIGNING_KEY_B64": keys["membership.der"],
                    "AT_REDIS_CA_B64": read(self.pki.cas["redis"][0]), "AT_AUTHORITY_TLS_CERT_CHAIN_B64": read(self.authority_identity[0]),
                    "AT_AUTHORITY_TLS_KEY_B64": read(self.authority_identity[1]), "AT_CHECKPOINT_CLIENT_CA_B64": read(self.pki.cas["checkpoint-client"][0])}.items()})
        self.env["authority"] = env
        self.states["authority"] = d.volume("authority")
        d.setup_volume(self.states["authority"], 10002, 10002)
        self.states["redis"] = d.volume("redis")
        redis_user = json.loads(d.one_shot("redis-user", d.images["redis"], network=False,
                    mounts=[(self.states["redis"], "/data", True)], entrypoint="/usr/bin/python3",
                    command=["-I", "-c", "import json,os,pwd; p=pwd.getpwnam('redis'); assert os.geteuid()==p.pw_uid; print(json.dumps([p.pw_uid,p.pw_gid]))"]))
        require(len(redis_user) == 2 and all(type(x) is int and x > 0 for x in redis_user), "redis_uid")
        self.event("redis_default_identity", uid=redis_user[0], gid=redis_user[1], uid_matches_named_user=True)
        d.setup_volume(self.states["redis"], *redis_user, directories=["redis"])
        env = tomllib.loads((self.rendered / "redis/fly.toml").read_text())["env"]
        env.update(REDIS_PASSWORD=self.password, REDIS_PUBLISHER_PASSWORD=self.publisher_password,
                   REDIS_TLS_CERT_CHAIN_B64=b64(read(self.redis_identity[0])), REDIS_TLS_KEY_B64=b64(read(self.redis_identity[1])))
        self.env["redis"] = env
        self.public_context = tls_context(self.pki.cas["public"][0])
        self.checkpoint_context = tls_context(self.pki.cas["authority"][0], self.checkpoint_ids[0])
        self.fixture = d.volume("catalog-fixture")
        files = self.catalog_files()
        d.setup_volume(self.fixture, 10001, 10001, files)
        self.client_volumes = []
        for i in range(3):
            volume = d.volume("client-" + str(i))
            files = {"client.toml": self.client_config(i).encode(), "credentials/device-chain.pem": read(self.identities[i][0]),
                     "credentials/device-key.pem": read(self.identities[i][1]), "credentials/public-ca.pem": read(self.pki.cas["public"][0])}
            d.setup_volume(volume, 10003, 10003, files)
            self.client_volumes.append(volume)
        self.unknown_volume = d.volume("unknown-client")
        d.setup_volume(self.unknown_volume, 10003, 10003, {
            "client.toml": self.client_config(0).replace(self.devices[0], self.unknown_device_id).encode(),
            "credentials/device-chain.pem": read(self.unknown_device[0]), "credentials/device-key.pem": read(self.unknown_device[1]),
            "credentials/public-ca.pem": read(self.pki.cas["public"][0])})

    def catalog_files(self):
        files = {"device-" + str(i) + ".pem": self.identities[i][0].read_bytes() for i in range(3)}
        initial = f'''[tenant]
id = "{self.tenant}"
display_name = "Synthetic tenant"
[user]
id = "{self.user}"
display_name = "Synthetic user"
oidc_subject = "synthetic-user"
role = "member"
[device]
id = "{self.devices[0]}"
display_name = "Synthetic device"
certificate = "device-0.pem"
[service]
id = "{self.services[0]}"
type = "echo"
display_name = "Synthetic echo"
operations = ["echo:invoke"]
[grant]
operations = ["echo:invoke"]
'''
        files["initial.toml"] = initial.encode()
        for i in (1, 2):
            files[f"device-{i}.toml"] = f'''[device]
tenant = "{self.tenant}"
owner = "{self.user}"
id = "{self.devices[i]}"
display_name = "Synthetic device"
certificate = "device-{i}.pem"
'''.encode()
            files[f"service-{i}.toml"] = f'''[service]
tenant = "{self.tenant}"
device = "{self.devices[i]}"
id = "{self.services[i]}"
type = "echo"
display_name = "Synthetic echo"
operations = ["echo:invoke"]
'''.encode()
            files[f"grant-{i}.toml"] = f'''[grant]
tenant = "{self.tenant}"
user = "{self.user}"
device = "{self.devices[i]}"
service = "{self.services[i]}"
operations = ["echo:invoke"]
'''.encode()
        return files

    def client_config(self, i):
        return f'''device_id = "{self.devices[i]}"
relay_url = "wss://{self.public_hosts[i]}:9443/v1/tunnel/control"
[credentials]
client_certificate = "credentials/device-chain.pem"
client_key = "credentials/device-key.pem"
server_ca = "credentials/public-ca.pem"
[exports."{self.services[i]}"]
type = "echo"
device_canary = "{self.canaries[i]}"
[limits]
max_streams = 64
max_queue_frames = 128
max_queue_bytes = 8388608
grant_timeout_ms = 5000
operation_timeout_ms = 30000
[rotation]
interval_seconds = 300
handshake_timeout_seconds = 10
overlap_seconds = 30
'''

    def relay_command(self, node, command):
        self.run.operation = "relay_" + command[0].replace("-", "_")
        return self.docker.one_shot("relay-operator", self.docker.images["relay"], env=self.env[node],
                    mounts=[(self.states[node], ROLE_BASE["relay"] + "/state", True), (self.fixture, ROLE_BASE["relay"] + "/operator", False)], command=command)

    def authority_command(self, command):
        self.run.operation = "authority_" + command[0].replace("-", "_")
        return self.docker.one_shot("authority-operator", self.docker.images["authority"], env=self.env["authority"],
                                   mounts=[(self.states["authority"], ROLE_BASE["authority"] + "/state", True)], command=command)

    def start_authority(self):
        self.authority = self.docker.create("authority", self.docker.images["authority"], memory=512, env=self.env["authority"],
             mounts=[(self.states["authority"], ROLE_BASE["authority"] + "/state", True)], aliases=[self.authority_host], ports=[8444])
        self.docker.start(self.authority)
        self.authority_port = self.docker.port(self.authority, 8444)

    def checkpoint(self):
        self.run.guard()
        self.run.operation, self.run.role = "https_checkpoint", "authority"
        nonce = secrets.token_hex(16)
        request = {key: self.inventory[key] for key in ("deployment_id", "deployment_incarnation")}
        request["nonce"] = nonce
        try:
            status, body = http_request(self.authority_port, self.authority_host, self.checkpoint_context, "/v1/checkpoint",
                                        method="POST", data=canonical(request), headers={"Content-Type": "application/json"})
        except ConnectionRefusedError:
            return None
        if status == 503:
            require(json.loads(body) == {"status": "unavailable"}, "checkpoint_unavailable_shape")
            return None
        require(status == 200, "checkpoint_http")
        return check_checkpoint(json.loads(body), self.inventory, nonce)

    def bootstrap(self):
        d = self.docker
        self.redis_container = d.create("redis", d.images["redis"], memory=512, env=self.env["redis"],
                             mounts=[(self.states["redis"], "/data", True)], aliases=[self.redis_host], ports=[6379])
        d.start(self.redis_container)
        self.redis = Redis(d.port(self.redis_container, 6379), self.redis_host, tls_context(self.pki.cas["redis"][0]), self.password)
        def ping():
            try:
                return self.redis.command("PING") == "PONG"
            except (ConnectionError, OSError):
                return False
        wait_until(self.run, ping, 20, "redis_start_deadline")
        require(self.redis.command("DBSIZE") == 0, "redis_not_empty")
        config = self.redis.command("CONFIG", "GET", "port", "tls-port", "appendonly", "appendfsync", "no-appendfsync-on-rewrite", "aof-load-truncated", "maxmemory", "maxmemory-policy")
        require(dict(zip(config[::2], config[1::2])) == {"port": "0", "tls-port": "6379", "appendonly": "yes", "appendfsync": "always", "no-appendfsync-on-rewrite": "no", "aof-load-truncated": "no", "maxmemory": str(96 * 1024**2), "maxmemory-policy": "noeviction"}, "redis_profile")
        info = self.redis.command("INFO", "server")
        run_ids = re.findall(r"^run_id:([0-9a-f]{40})\r?$", info, re.MULTILINE)
        require(len(run_ids) == 1, "redis_run_id")
        self.run_id = run_ids[0]
        for node in ("relay-a", "relay-b", "relay-c"):
            self.relay_command(node, ["initialize"])
            self.relay_command(node, ["recovery-initialize"])
        # The publisher intentionally has no catalog-bootstrap read privileges.
        # Starting it before activation could populate the empty namespace and
        # prevent activation; order is enforced here, not claimed as a product
        # publication-before-bootstrap refusal that does not exist.
        self.relay_command("relay-a", ["activate-first-incarnation"])
        operator = ROLE_BASE["relay"] + "/operator"
        self.relay_command("relay-a", ["provision-catalog", "--records", operator + "/initial.toml"])
        for i in (1, 2):
            for kind, command in (("device", "add-device"), ("service", "add-service"), ("grant", "set-grant")):
                self.relay_command("relay-a", [command, "--records", f"{operator}/{kind}-{i}.toml"])
        self.authority_command(["initialize-membership", "--expected-redis-run-id", self.run_id])
        self.authority_command(["check-config"])
        self.start_authority()
        wait_until(self.run, lambda: self.checkpoint() is not None, 30, "authority_publication_deadline")
        for i, relay in enumerate(self.inventory["relays"]):
            node = relay["node_id"]
            item = d.create(node, d.images["relay"], memory=512, env=self.env[node],
                     mounts=[(self.states[node], ROLE_BASE["relay"] + "/state", True)],
                     aliases=[relay["app"] + ".internal", self.public_hosts[i]], ports=[8443, 9443])
            d.start(item)
            self.relays.append(item)
        self.consumer_ports = [d.port(item, 8443) for item in self.relays]
        self.device_ports = [d.port(item, 9443) for item in self.relays]
        self.wait_ready()
        self.event("bootstrap", relays_ready=3, authority_fresh_publication=True, redis_tls=True)

    def wait_ready(self):
        def ready():
            for i, port in enumerate(self.consumer_ports):
                try:
                    status, body = http_request(port, self.public_hosts[i], self.public_context, "/readyz")
                except (ConnectionError, OSError):
                    return False
                if status == 503:
                    return False
                require(status == 200 and json.loads(body) == {"status": "ready"}, "relay_ready_response")
            return True
        wait_until(self.run, ready, 60, "cluster_readiness_deadline")

    def start_client(self, i):
        item = self.docker.create("client-" + str(i), self.docker.images["client"], mounts=[(self.client_volumes[i], "/profile", True)],
                   command=["connect", "--no-reconnect", "--config", "/profile/client.toml", "--json"])
        self.docker.start(item)
        if len(self.clients) <= i:
            self.clients.append(item)
        else:
            self.clients[i] = item
        def active():
            self.docker.inspect(item)
            # IPC absence is expected only during this bounded startup poll.
            raw = self.docker.call(["container", "exec", item["id"], "/usr/local/bin/tunnel-client", "status", "--config", "/profile/client.toml", "--json"], allowed=(0, 8))
            value = json.loads(raw)
            if value.get("ok") is not True:
                require(value.get("command") == "status" and value.get("error", {}).get("code") == "SUPERVISOR_ABSENT", "client_start_status")
                return False
            return ready_session(checked_status(raw, self.devices[i]))
        wait_until(self.run, active, 30, "client_start_deadline")

    def status(self, i):
        self.docker.inspect(self.clients[i])
        raw = self.docker.call(["container", "exec", self.clients[i]["id"], "/usr/local/bin/tunnel-client", "status", "--config", "/profile/client.toml", "--json"])
        return checked_status(raw, self.devices[i])

    def owner(self, i):
        key = f"tunnel-catalog:{self.inventory['redis_namespace']}:coord:owner:{self.inventory['deployment_incarnation']}:{self.tenant}:{self.devices[i]}"
        values = self.redis.command("HGETALL", key)
        value = dict(zip(values[::2], values[1::2]))
        require(value.get("node_id") == f"relay-{chr(97+i)}" and value.get("deployment_incarnation") == self.inventory["deployment_incarnation"], "device_owner_node")
        require(self.redis.command("PTTL", key) > 0, "device_owner_expired")
        session = self.status(i)["session"]
        require(value.get("session_id") == session["session_id"] and int(value.get("owner_epoch", "0")) == session["epoch"], "owner_session_join")
        return value

    def echo(self, ingress, device, *, anonymous=False, denied=False):
        self.run.guard()
        self.run.operation, self.run.role = "https_echo", f"relay-{chr(97+ingress)}"
        path = f"/v1/devices/{self.devices[device]}/services/{self.services[device]}/echo"
        payload = secrets.token_hex(16).encode()
        status, body = http_request(self.consumer_ports[ingress], self.public_hosts[ingress], self.public_context,
                         path, method="POST", data=payload, headers={} if anonymous else {"Authorization": "Bearer " + self.token})
        if anonymous or denied:
            require(status == (401 if anonymous else 403), "authorization_negative_status")
            result = json.loads(body)
            require(result.get("code") == ("UNAUTHORIZED" if anonymous else "FORBIDDEN") and result.get("execution") == "not_dispatched", "authorization_negative_cause")
        else:
            require(status == 200 and body == self.canaries[device].encode() + payload, "echo_exact_body")

    def all_routes(self):
        for device in range(3):
            self.owner(device)
            for ingress in range(3):
                self.echo(ingress, device, denied=self.grant_revoked and device == 0)

    def negatives(self):
        for context, host, cause in ((self.public_context, "wrong.invalid", "wrong_name"),
                                     (tls_context(self.pki.cas["untrusted"][0]), self.public_hosts[0], "untrusted_ca")):
            try:
                http_request(self.consumer_ports[0], host, context, "/readyz")
            except ssl.SSLCertVerificationError:
                self.event("tls_refusal", cause=cause)
            else:
                raise Refused("tls_negative_accepted")
        self.echo(0, 0, anonymous=True)
        self.event("anonymous_refusal", status=401)
        for port, host, ca, role in ((self.authority_port, self.authority_host, self.pki.cas["authority"][0], "authority"),
                                    (self.device_ports[0], self.public_hosts[0], self.pki.cas["public"][0], "device")):
            context = tls_context(ca)
            context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
            try:
                http_request(port, host, context, "/readyz")
            except ssl.SSLError as exc:
                require(exc.reason == "TLSV13_ALERT_CERTIFICATE_REQUIRED", "mtls_negative_wrong_cause")
            else:
                raise Refused("mtls_anonymous_accepted")
            self.event("mtls_anonymous_refusal", role=role, cause="TLSV13_ALERT_CERTIFICATE_REQUIRED")
        # A CA-trusted, syntactically correct, unregistered device uses the
        # actual client HELLO. The typed control refusal is not an HTTP401.
        raw = self.docker.one_shot("unknown-client", self.docker.images["client"], expected_exit=3,
                   mounts=[(self.unknown_volume, "/profile", True)], command=["connect", "--no-reconnect", "--config", "/profile/client.toml", "--json"])
        check_identity_refusal(raw)
        self.event("device_identity_refusal", cli_exit=3, cause="CREDENTIAL_ERROR", retryable=False)
        # The named publisher must not be able to mutate durable catalog keys.
        require(self.redis.command("PING", user=self.inventory["redis"]["publisher_user"], password=self.publisher_password) == "PONG", "publisher_auth_positive")
        try:
            self.redis.command("SET", "tunnel-catalog:" + self.inventory["redis_namespace"] + ":forbidden-probe", "x",
                               user=self.inventory["redis"]["publisher_user"], password=self.publisher_password)
        except Refused as exc:
            require(str(exc) == "redis_permission_denied", "publisher_negative_transport")
        else:
            raise Refused("publisher_catalog_write_allowed")
        require(self.redis.command("EXISTS", "tunnel-catalog:" + self.inventory["redis_namespace"] + ":forbidden-probe") == 0, "publisher_negative_side_effect")
        self.event("publisher_catalog_write_refusal")

    def rotations(self):
        before = [self.status(i) for i in range(3)]
        require(all(x["session"]["rotations_completed"] == 0 for x in before), "rotation_initial_not_zero")
        started = time.monotonic()
        rounds = 0
        while True:
            self.run.guard()
            require(time.monotonic() - started < 350, "normal_rotation_deadline")
            self.all_routes()
            rounds += 1
            after = [self.status(i) for i in range(3)]
            complete = [check_rotation(a, b) for a, b in zip(before, after)]
            if all(complete):
                break
            time.sleep(2)
        self.event("normal_rotation", interval_seconds=300, clients=3, route_rounds=rounds,
                   observed_seconds=round(time.monotonic() - started, 3),
                   generations=[x["session"]["active_generation"] for x in after],
                   rotations=[x["session"]["rotations_completed"] for x in after])

    def restarts(self):
        self.relay_command("relay-a", ["revoke-grant", "--tenant", self.tenant, "--user", self.user, "--device", self.devices[0], "--service", self.services[0]])
        self.grant_revoked = True
        self.all_routes()
        old_owner = self.owner(0)
        # The normal CLI's bounded disconnect joins its connector; a successful
        # stop alone is not used as a new connection/rotation assertion.
        self.docker.call(["container", "exec", self.clients[0]["id"], "/usr/local/bin/tunnel-client", "disconnect", "--config", "/profile/client.toml", "--json"])
        self.docker.stop(self.clients[0])
        old_state = json.loads(self.docker.read_volume(self.states["relay-a"], ["membership-version-state.json"])["membership-version-state.json"])
        self.docker.stop(self.relays[0])
        self.docker.start(self.relays[0])
        self.consumer_ports[0], self.device_ports[0] = self.docker.port(self.relays[0], 8443), self.docker.port(self.relays[0], 9443)
        self.wait_ready()
        self.start_client(0)
        new_owner = self.owner(0)
        require(new_owner["boot_id"] != old_owner["boot_id"] and new_owner["session_id"] != old_owner["session_id"]
                and int(new_owner["owner_epoch"]) > int(old_owner["owner_epoch"]), "relay_restart_fresh_owner")
        new_state = json.loads(self.docker.read_volume(self.states["relay-a"], ["membership-version-state.json"])["membership-version-state.json"])
        check_persisted_version(old_state, new_state)
        self.all_routes()
        self.event("relay_restart", stable_node="relay-a", new_boot=True, new_session=True, persisted_version_monotonic=True, revoked_grant_refused=True)
        before = self.checkpoint()
        require(before is not None, "authority_before_restart_unready")
        self.docker.stop(self.authority)
        self.docker.start(self.authority)
        self.authority_port = self.docker.port(self.authority, 8444)
        def fresh():
            value = self.checkpoint()
            return value is not None and value["checkpoint_version"] > before["checkpoint_version"] and all(value["minimum_versions"][n] > v for n, v in before["minimum_versions"].items())
        wait_until(self.run, fresh, 30, "authority_restart_fresh_publication")
        self.wait_ready()
        self.all_routes()
        require(re.findall(r"^run_id:([0-9a-f]{40})\r?$", self.redis.command("INFO", "server"), re.MULTILINE) == [self.run_id], "redis_unexpected_restart")
        self.event("authority_restart", fresh_publication=True, revoked_grant_refused=True, redis_restart=False)

    def execute(self):
        self.run.stage = "prepare"
        self.prepare()
        self.run.stage = "bootstrap"
        self.bootstrap()
        self.run.stage = "clients"
        for i in range(3):
            self.start_client(i)
        self.all_routes()
        self.event("cross_relay_routes", owner_nodes=3, routes=9, remote_routes=6, exact_echo=True)
        self.run.stage = "negative_controls"
        self.negatives()
        self.run.stage = "normal_rotation"
        self.rotations()
        self.run.stage = "restart_revocation"
        self.restarts()


def main(argv=None):
    global NETWORK_DEADLINE
    parser = argparse.ArgumentParser(description=__doc__)
    for role in ("relay", "authority", "redis", "client"):
        parser.add_argument("--" + role + "-image", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    images = {role: getattr(args, role + "_image") for role in ("relay", "authority", "redis", "client")}
    for value in images.values():
        require(IMAGE_RE.fullmatch(value), "immutable_image_id_required")
    args.output.mkdir(mode=0o700)  # existing output is never replaced
    started = time.monotonic()
    result = {"schema_version": 1, "status": "failed", "scope": "synthetic-rendered-three-relay-images", "limitations": LIMITATIONS,
              "main_bound_seconds": MAIN_SECONDS, "cleanup_bound_seconds": CLEANUP_SECONDS}
    def event(kind, **fields):
        with (args.output / "events.jsonl").open("ab") as file:
            file.write(canonical({"event": kind, "elapsed_seconds": round(time.monotonic() - started, 3), **fields}))
    with tempfile.TemporaryDirectory(prefix="agentuplink-fly-private-") as tmp:
        private = Path(tmp)
        run = Runner(private, event)
        NETWORK_DEADLINE = run.deadline
        docker = Docker(run, "au-" + secrets.token_hex(6), images)
        first_error = None
        source, image_receipts = None, {}
        interruptions = []
        def interrupted(signum, _frame):
            # Only latch here: raising between the protected main body and
            # cleanup would skip cleanup. The guarded command loop observes
            # this flag; network operations have their own absolute5s bound.
            run.stop_requested = True
            interruptions.append({"signal": signum, "stage": run.stage, "operation": run.operation, "during_cleanup": run.cleanup})
            # Repeated INT/TERM cannot interrupt the existing bounded180s
            # cleanup. SIGKILL remains outside any program's cleanup guarantee.
        previous_signals = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)}
        try:
            initial = resource_sample(private)
            run.initial = initial
            check_resources(initial, run.initial, startup=True)
            source = source_receipt(run)
            private_write(args.output / "source.json", canonical(source))
            for role, identity in images.items():
                rows = json.loads(docker.call(["image", "inspect", identity]))
                require(len(rows) == 1, "image_inspection_cardinality")
                image_receipts[role] = check_image(rows[0], identity, source["commit"])
                image_receipts[role]["artifacts"] = docker.artifact_receipt(role)
            private_write(args.output / "images.json", canonical(image_receipts))
            Rehearsal(run, docker, private, event).execute()
            require(source_receipt(run) == source, "source_changed")
            for role, identity in images.items():
                check_image(json.loads(docker.call(["image", "inspect", identity]))[0], identity, source["commit"])
        except BaseException as exc:
            first_error = error_code(exc)
        if run.stop_requested and first_error is None:
            first_error = "controller_interrupted"
        result["failure_stage"] = run.stage if first_error else None
        result["failure_operation"] = run.operation if first_error else None
        result["failure_subcommand"] = run.subcommand if first_error else None
        cleanup_errors = docker.cleanup()
        # These observations are independent of the primary guard and do not
        # erase its first failure when cleanup happened to succeed.
        try:
            result["final_resources"] = resource_sample(private)
            check_resources(result["final_resources"], run.initial)
            require(all(not group_present(pid) for pid in run.processes), "owned_process_group_remains")
        except BaseException as exc:
            cleanup_errors.append({"resource": "final-observation", "code": error_code(exc)})
        try:
            if source is not None:
                require(source_receipt(run) == source, "final_source_changed")
                for role in image_receipts:
                    check_image(json.loads(docker.call(["image", "inspect", images[role]]))[0], images[role], source["commit"])
                result["final_source_images_unchanged"] = True
        except BaseException as exc:
            cleanup_errors.append({"resource": "final-inputs", "code": error_code(exc)})
        if interruptions and first_error is None:
            first_error = "controller_interrupted"
            result["failure_stage"] = interruptions[0]["stage"]
            result["failure_operation"] = interruptions[0]["operation"]
        result.update(first_failure=first_error, cleanup_errors=cleanup_errors, containers=docker.inventory,
                      process_groups=len(run.processes), resource_samples=run.samples,
                      interruptions=interruptions,
                      elapsed_seconds=round(time.monotonic() - started, 3))
        if first_error is None and not cleanup_errors and not interruptions:
            result["status"] = "passed"
        private_write(args.output / "result.json", canonical(result))
        for sig, previous in previous_signals.items():
            signal.signal(sig, previous)
        NETWORK_DEADLINE = None
    print("Fly cluster image rehearsal: " + result["status"] + "; sanitized receipt: " + str(args.output / "result.json"))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
