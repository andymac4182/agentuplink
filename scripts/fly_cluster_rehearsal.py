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
import inspect
import ipaddress
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
HOST_LOOPBACK = "::1"  # published ports must match the IPv6-only bridge
OWNER_LABEL = "io.agentuplink.fly-rehearsal"
IMAGE_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
ID_RE = re.compile(r"[0-9a-f]{64}\Z")
MAIN_SECONDS = 1500
CLEANUP_SECONDS = 180
COMMAND_SECONDS = 30
MAX_OUTPUT = 8 * 1024 * 1024
MAX_PRIVATE = 256 * 1024 * 1024
MAX_DOCKER_ERROR = 16 * 1024
MAX_AUTHORITY_OBSERVATION = 256 * 1024
MAX_RELAY_OBSERVATION = 16 * 1024
MAX_READINESS_METRICS = 64 * 1024
READINESS_METRICS_PORT = 9100
MEMBERSHIP_STATES = ("starting", "ready", "unknown_authority", "checkpoint_expired", "catalog_unavailable",
                     "membership_rejected", "missing_local_membership", "missing_local_key", "persistence_unavailable", "cancelled")
METRICS_FAILURE_CODES = {"metrics_body_bound", "metrics_encoding", "metrics_selected_shape", "metrics_duplicate",
                         "metrics_missing", "metrics_value", "metrics_membership_state", "metrics_one_hot",
                         "metrics_identity", "metrics_http_status", "metrics_timeout", "metrics_transport", "metrics_unclassified"}
NODES = ("relay-a", "relay-b", "relay-c")
LOG_CONFIG = {"Type": "local", "Config": {"max-size": "2m", "max-file": "1", "compress": "false"}}
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


def closed_docker_error(data):
    """Report only fixed engine vocabulary, never a matched substring/value.

    These are observations of an error, not inferred container outcomes. An
    unfamiliar error stays unclassified. Oversized inputs have an explicitly
    prefix-scoped hash/classification; they are never emitted as raw text.
    """
    bounded = data[:MAX_DOCKER_ERROR]
    lowered = bounded.lower()
    vocabulary = (
        ("local_compression_single_file", b"compression cannot be enabled when max file count is 1"),
        ("logging_driver_initialization", b"failed to initialize logging driver"),
        ("container_task_creation", b"failed to create task for container"),
        ("oci_runtime_creation", b"oci runtime create failed"),
        ("container_process_start", b"unable to start container process"),
        ("executable_not_found", b"executable file not found"),
        ("missing_file", b"no such file or directory"),
        ("permission_denied", b"permission denied"),
        ("operation_not_permitted", b"operation not permitted"),
        ("disk_full", b"no space left on device"),
        ("read_only_filesystem", b"read-only file system"),
        ("memory_allocation", b"cannot allocate memory"),
        ("daemon_unreachable", b"cannot connect to the docker daemon"),
        ("logging_read_unsupported", b"configured logging driver does not support reading"),
    )
    codes = [name for name, phrase in vocabulary if phrase in lowered]
    errno = [name for name in ("EACCES", "EPERM", "ENOENT", "ENOSPC", "EROFS", "ENOMEM")
             if re.search(rb"\b" + name.encode() + rb"\b", bounded)]
    return {"bytes": len(data), "sha256": digest(bounded), "hash_scope": "complete" if len(data) <= MAX_DOCKER_ERROR else "prefix",
            "classified_bytes": len(bounded), "classification_complete": len(data) <= MAX_DOCKER_ERROR,
            "codes": codes, "errno_terms": errno, "raw_uploaded": False,
            "classification": "matched_engine_vocabulary" if codes or errno else ("empty" if not data else "unclassified")}


def safe_container_state(state):
    """A small diagnostic projection; do not change lifecycle predicates."""
    result, invalid, missing = {}, [], []
    for field, output in (("Status", "status"), ("StartedAt", "started_at"), ("Pid", "pid"),
                          ("Running", "running"), ("ExitCode", "exit_code"), ("OOMKilled", "oom_killed")):
        if field not in state:
            result[output] = None
            missing.append(field)
            continue
        value = state[field]
        if field == "Status":
            valid = isinstance(value, str) and value in {"created", "running", "paused", "restarting", "removing", "exited", "dead"}
        elif field == "StartedAt":
            valid = isinstance(value, str) and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z", value) is not None
            if valid:
                try:
                    dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
                except ValueError:
                    valid = False
        elif field in {"Pid", "ExitCode"}:
            valid = type(value) is int and 0 <= value <= (2**31 - 1 if field == "Pid" else 255)
        else:
            valid = type(value) is bool
        result[output] = value if valid else None
        if not valid:
            invalid.append(field)
    error = state.get("Error")
    result["error"] = ({"present": True, "valid_type": True, **closed_docker_error(error.encode())}
                       if isinstance(error, str) else {"present": "Error" in state, "valid_type": False})
    result.update(missing_fields=missing, invalid_fields=invalid)
    return result


def safe_engine_projection(server, log_drivers):
    """Accept the fixed version/API projection, not arbitrary docker info."""
    require(isinstance(server, dict) and isinstance(log_drivers, list), "docker_engine_projection")
    fields = {}
    patterns = {"Version": r"[0-9]+\.[0-9]+(?:\.[0-9]+)?[0-9A-Za-z.+_~-]{0,48}",
                "ApiVersion": r"[0-9]+\.[0-9]+", "MinAPIVersion": r"[0-9]+\.[0-9]+",
                "Os": r"linux", "Arch": r"amd64|arm64"}
    for key, pattern in patterns.items():
        value = server.get(key)
        require(isinstance(value, str) and re.fullmatch(pattern, value) is not None, "docker_engine_projection")
        fields[key] = value
    require(len(log_drivers) <= 64 and all(isinstance(item, str) for item in log_drivers), "docker_log_plugin_projection")
    known = {"awslogs", "fluentd", "gcplogs", "gelf", "journald", "json-file", "local", "none", "splunk", "syslog", "etwlogs"}
    fields["known_log_drivers"] = sorted(set(log_drivers) & known)
    fields["unknown_log_driver_count"] = sum(item not in known for item in log_drivers)
    require("local" in fields["known_log_drivers"], "docker_local_logging_unavailable")
    return fields


def published_binding_shape(value, port):
    """Closed diagnostics for one requested mapping, never raw inspect values.

    Missing/null/multiple mappings remain distinct without disclosing any
    address or port string. Only one canonical IPv6 loopback binding passes.
    This describes the current inspect result, not a past failure's cause.
    """
    missing = object()

    def kind(item):
        if item is missing:
            return "missing"
        return {type(None): "null", dict: "object", list: "array", str: "string",
                bool: "boolean", int: "number", float: "number"}.get(type(item), "other")

    settings = value.get("NetworkSettings", missing) if isinstance(value, dict) else missing
    ports = settings.get("Ports", missing) if isinstance(settings, dict) else missing
    bindings = ports.get(f"{port}/tcp", missing) if isinstance(ports, dict) else missing
    count = len(bindings) if isinstance(bindings, list) else None
    binding = bindings[0] if count == 1 else missing
    address = binding.get("HostIp", missing) if isinstance(binding, dict) else missing
    host_port = binding.get("HostPort", missing) if isinstance(binding, dict) else missing
    if address is missing:
        address_class = "missing"
    elif not isinstance(address, str):
        address_class = "invalid_type"
    elif address == HOST_LOOPBACK:
        address_class = "ipv6_loopback"
    elif address == "127.0.0.1":
        address_class = "ipv4_loopback"
    elif address in {"0.0.0.0", "::"}:
        address_class = "wildcard"
    else:
        address_class = "other"
    valid_port = (isinstance(host_port, str) and re.fullmatch(r"[1-9][0-9]{0,4}", host_port) is not None
                  and int(host_port) <= 65535)
    return {"network_settings_type": kind(settings), "ports_type": kind(ports),
            "binding_present": bindings is not missing, "bindings_type": kind(bindings), "binding_count": count,
            "binding_type": kind(binding), "host_ip_type": kind(address), "host_ip_class": address_class,
            "host_port_type": kind(host_port), "host_port_valid": valid_port,
            "accepted": count == 1 and address_class == "ipv6_loopback" and valid_port}


def readiness_transport_observation(error):
    """Closed classes only; exception text may contain hostnames or secrets."""
    if isinstance(error, ssl.SSLCertVerificationError):
        code = getattr(error, "verify_code", None)
        return {"kind": "certificate_verification", "verify_code": code if type(code) is int and 0 <= code <= 65535 else None}
    for kind, exception in (("tls", ssl.SSLError), ("connection_refused", ConnectionRefusedError),
                            ("connection_reset", ConnectionResetError), ("connection_aborted", ConnectionAbortedError),
                            ("timeout", TimeoutError), ("dns", socket.gaierror),
                            ("connection", ConnectionError), ("os", OSError), ("http_protocol", http.client.HTTPException)):
        if isinstance(error, exception):
            return {"kind": kind}
    if isinstance(error, Refused) and str(error) in {"network_request_deadline", "controller_deadline", "http_body_bound"}:
        return {"kind": str(error)}
    return {"kind": "unclassified_exception"}


def readiness_http_observation(status, body):
    """Describe the bounded reply without retaining its body or raw fields."""
    try:
        value = json.loads(body)
    except (ValueError, UnicodeError, RecursionError):
        body_class = "invalid_json"
    else:
        body_class = "ready" if value == {"status": "ready"} else ("unready" if value == {"status": "unready"} else "other_json")
    return {"kind": "http", "status": status if type(status) is int and 100 <= status <= 599 else None,
            "body_class": body_class}


def readiness_metrics(data):
    """Select only fixed private readiness series; no raw labels escape."""
    require(isinstance(data, bytes) and 0 < len(data) <= MAX_READINESS_METRICS, "metrics_body_bound")
    try:
        text = data.decode("utf-8")
    except UnicodeError:
        raise Refused("metrics_encoding") from None
    names = {"tunnel_relay_ready": "ready", "tunnel_relay_authority_ready": "authority_ready",
             "tunnel_relay_clock_offset_ready": "clock_ready", "tunnel_relay_clock_offset_milliseconds": "clock_offset_ms",
             "tunnel_relay_clock_offset_measurements_total": "clock_measurements",
             "tunnel_relay_clock_offset_measurement_failures_total": "clock_failures"}
    values, states = {}, {}
    for line in text.splitlines():
        match = re.match(r"([a-zA-Z_:][a-zA-Z0-9_:]*)", line.lstrip())
        if match is None:
            continue
        name = match[1]
        if name == "tunnel_relay_membership_readiness":
            sample = re.fullmatch(r'tunnel_relay_membership_readiness\{state="([a-z_]+)"\} ([01])', line)
            require(sample is not None, "metrics_selected_shape")
            label, number = sample.groups()
            require(label in MEMBERSHIP_STATES, "metrics_membership_state")
            require(label not in states, "metrics_duplicate")
            states[label] = int(number)
        elif name in names:
            sample = re.fullmatch(re.escape(name) + r" (-?(?:0|[1-9][0-9]{0,19}))", line)
            require(sample is not None, "metrics_selected_shape")
            key, number = names[name], int(sample[1])
            require(key not in values, "metrics_duplicate")
            if key in {"ready", "authority_ready", "clock_ready"}:
                require(number in (0, 1), "metrics_value")
                values[key] = bool(number)
            else:
                lower, upper = (-(2**63), 2**63 - 1) if key == "clock_offset_ms" else (0, 2**64 - 1)
                require(lower <= number <= upper, "metrics_value")
                values[key] = number
    require(set(states) == set(MEMBERSHIP_STATES)
            and {"ready", "clock_ready", "clock_measurements", "clock_failures"} <= set(values), "metrics_missing")
    require(sum(states.values()) == 1, "metrics_one_hot")
    values["membership_state"] = next(state for state in MEMBERSHIP_STATES if states[state] == 1)
    values.setdefault("authority_ready", None)
    values.setdefault("clock_offset_ms", None)
    return values


def readiness_metrics_program():
    # The same pure parser is used by controls and the fixed, non-root exec
    # helper. No raw metric body or exception is printed by that helper.
    return ("import http.client,json,os,pwd,re,signal\n"
            "class Refused(Exception): pass\n"
            "def require(value, code):\n    if not value: raise Refused(code)\n"
            f"MAX_READINESS_METRICS={MAX_READINESS_METRICS}\nMEMBERSHIP_STATES={MEMBERSHIP_STATES!r}\n"
            + inspect.getsource(readiness_metrics) + f'''
def main():
    connection = None
    def expired(_signal, _frame):
        raise TimeoutError()
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, 5)
    try:
        try:
            account = pwd.getpwnam("relay")
        except KeyError:
            raise Refused("metrics_identity") from None
        require(os.geteuid() == account.pw_uid == 10001
                and os.getegid() == account.pw_gid and account.pw_gid > 0, "metrics_identity")
        connection = http.client.HTTPConnection("{HOST_LOOPBACK}", {READINESS_METRICS_PORT}, timeout=5)
        connection.request("GET", "/metrics", headers={{"Connection": "close"}})
        response = connection.getresponse()
        require(response.status == 200, "metrics_http_status")
        result = {{"status": "ok", "metrics": readiness_metrics(response.read(MAX_READINESS_METRICS + 1))}}
    except Refused as error:
        result = {{"status": "failed", "code": str(error)}}
    except TimeoutError:
        result = {{"status": "failed", "code": "metrics_timeout"}}
    except (OSError, http.client.HTTPException):
        result = {{"status": "failed", "code": "metrics_transport"}}
    except BaseException:
        result = {{"status": "failed", "code": "metrics_unclassified"}}
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        if connection is not None:
            try:
                connection.close()
            except BaseException:
                if result["status"] == "ok":
                    result = {{"status": "failed", "code": "metrics_unclassified"}}
    print(json.dumps(result, sort_keys=True))
if __name__ == "__main__":
    main()
''')


def readiness_metrics_envelope(data):
    value = observation_json(data, 4096)
    require(isinstance(value, dict), "metrics_envelope")
    if value.get("status") == "failed":
        require(set(value) == {"status", "code"} and isinstance(value["code"], str)
                and value["code"] in METRICS_FAILURE_CODES, "metrics_envelope")
        return value
    require(set(value) == {"status", "metrics"} and value["status"] == "ok", "metrics_envelope")
    metrics = value["metrics"]
    require(isinstance(metrics, dict) and set(metrics) == {"ready", "authority_ready", "clock_ready", "clock_offset_ms",
            "clock_measurements", "clock_failures", "membership_state"}, "metrics_envelope")
    require(type(metrics["ready"]) is bool and type(metrics["clock_ready"]) is bool
            and (metrics["authority_ready"] is None or type(metrics["authority_ready"]) is bool)
            and (metrics["clock_offset_ms"] is None or type(metrics["clock_offset_ms"]) is int
                 and -(2**63) <= metrics["clock_offset_ms"] < 2**63)
            and u64(metrics["clock_measurements"]) and u64(metrics["clock_failures"])
            and metrics["membership_state"] in MEMBERSHIP_STATES, "metrics_envelope")
    return value


def readiness_diagnostic_code(error):
    allowed = METRICS_FAILURE_CODES | {"metrics_envelope", "controller_deadline", "controller_interrupted",
                                      "command_deadline", "command_exit", "command_output_bound", "metrics_container"}
    return str(error) if isinstance(error, Refused) and str(error) in allowed else "diagnostic_unclassified"


# Closed source-derived observations only; never infer which lifecycle failed.
# Source equality controls bind these messages to the Rust Display implementations.
RELAY_TERMINAL_LITERALS = {
    "checkpoint authority deadline exceeded": "checkpoint_authority_deadline_exceeded",
    "checkpoint authority request was cancelled": "checkpoint_authority_cancelled",
    "checkpoint authority response exceeded the size bound": "checkpoint_authority_body_too_large",
    "checkpoint authority response was invalid": "checkpoint_authority_invalid_response",
    "checkpoint authority transport failed": "checkpoint_authority_transport",
    "cluster membership contains no approved peer keys": "membership_no_approved_peer_keys",
    "invalid checkpoint authority client identity": "checkpoint_authority_invalid_client_identity",
    "invalid checkpoint authority endpoint": "checkpoint_authority_invalid_endpoint",
    "invalid checkpoint authority request": "checkpoint_authority_invalid_request",
    "invalid checkpoint authority trust bundle": "checkpoint_authority_invalid_trust_bundle",
    "invalid membership runtime configuration": "membership_runtime_invalid_configuration",
    "invalid membership state identity": "membership_state_invalid_identity",
    "invalid membership state path": "membership_state_invalid_path",
    "membership catalog read was cancelled": "membership_source_cancelled",
    "membership catalog unavailable": "membership_source_catalog",
    "membership checkpoint expired": "membership_runtime_checkpoint_expired",
    "membership record count exceeded the bound": "membership_source_too_many_records",
    "membership record envelope was invalid": "membership_source_invalid_record_envelope",
    "membership runtime cancelled": "membership_runtime_cancelled",
    "membership runtime is not ready": "membership_runtime_not_ready",
    "membership state I/O failed": "membership_state_io",
    "membership state already exists": "membership_state_already_exists",
    "membership state durable sync failed": "membership_state_durable_sync",
    "membership state identity mismatch": "membership_state_identity_mismatch",
    "membership state is already open": "membership_state_busy",
    "membership state is corrupt": "membership_state_corrupt",
    "membership state is invalid": "membership_state_invalid_state",
    "membership state is missing": "membership_state_missing",
    "membership state is not a regular file": "membership_state_not_regular_file",
    "membership state load task failed": "membership_state_load_task_failed",
    "membership state parent directory is not private": "membership_state_parent_directory_not_private",
    "membership state path changed during access": "membership_state_path_changed",
    "membership state permissions are too broad": "membership_state_insecure_permissions",
    "membership state serialization failed": "membership_state_serialization",
    "membership state symlink is rejected": "membership_state_symlink_rejected",
    "membership state would roll back a fence": "membership_state_state_rollback",
    "membership task did not join cleanly": "membership_runtime_join",
    "membership version state persistence timed out": "membership_runtime_persistence_timeout",
    "peer membership is not currently trusted": "membership_runtime_peer_rejected",
}
RELAY_BOOTSTRAP_TUPLES = (
    ("starting", "starting", "bootstrap"),
    ("ready", "ready", "bootstrap"),
    ("unready", "unknown_authority", "authority"),
    ("unready", "checkpoint_expired", "checkpoint"),
    ("unready", "catalog_unavailable", "catalog"),
    ("unready", "membership_rejected", "membership"),
    ("unready", "missing_local_membership", "membership"),
    ("unready", "missing_local_key", "membership"),
    ("unready", "persistence_unavailable", "persistence"),
    ("unready", "cancelled", "lifecycle"),
)
RELAY_SHUTDOWN_REASONS = (
    "invalid_configuration", "authority", "source", "membership", "persistence",
    "persistence_timeout", "not_ready", "peer_rejected", "checkpoint_expired", "cancelled", "join",
)


def relay_terminal_observation(data):
    """Observe complete closed-vocabulary lines, without lifecycle/cause attribution.

    Docker logs can combine old and restarted processes. Counts describe only
    this bounded captured input; unknown and unterminated relay lines remain
    explicitly unclassified. No raw text, paths, numeric details or line order
    enter the projection. An oversized input is not scanned.
    """
    value = {"scanned": False, "recognized_lines": None, "unrecognized_terminal_lines": None,
             "incomplete_terminal_lines": None, "observations": [], "lifecycle_attribution": "none"}
    if data is None or len(data) > MAX_OUTPUT:
        return value
    value.update(scanned=True, recognized_lines=0, unrecognized_terminal_lines=0,
                 incomplete_terminal_lines=0)
    lines = data.split(b"\n")
    prefix = b"tunnel-relay: "
    if lines[-1].startswith(prefix):
        value["incomplete_terminal_lines"] = 1
    observations = set()
    for line in lines[:-1]:
        if line.endswith(b"\r"):
            line = line[:-1]
        if not line.startswith(prefix):
            continue
        observation = None
        try:
            body = line[len(prefix):].decode("ascii")
        except UnicodeError:
            body = ""
        code = RELAY_TERMINAL_LITERALS.get(body)
        if code is not None:
            observation = {"code": code}
        else:
            match = re.fullmatch(
                r"cluster membership bootstrap did not reach ready: readiness=([a-z_]+) "
                r"reason=([a-z_]+) category=([a-z_]+)"
                r"(?:; cleanup=membership_shutdown_failed reason=([a-z_]+))?", body)
            if match is not None:
                state, reason, category, cleanup = match.groups()
                if (state, reason, category) in RELAY_BOOTSTRAP_TUPLES and (
                        cleanup is None or cleanup in RELAY_SHUTDOWN_REASONS):
                    observation = {"code": "membership_bootstrap_not_ready", "readiness": state,
                                   "reason": reason, "category": category}
                    if cleanup is not None:
                        observation["cleanup_reason"] = cleanup
        if observation is None:
            value["unrecognized_terminal_lines"] += 1
        else:
            value["recognized_lines"] += 1
            observations.add(tuple(sorted(observation.items())))
    value["observations"] = [dict(item) for item in sorted(observations)]
    return value


def safe_log_receipt(path, *, docker=False):
    size = path.stat().st_size
    if size > MAX_OUTPUT:
        return {"bytes": size, "sha256": None, "closed_codes": [], "raw_uploaded": False,
                "output_bound_exceeded": True, "cause_classification": "unclassified",
                "relay_terminal": relay_terminal_observation(None)}
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
            if isinstance(code, str) and code in allowed and code not in codes:
                codes.append(code)
    receipt = {"bytes": len(data), "sha256": digest(data), "closed_codes": codes, "raw_uploaded": False,
               "cause_classification": "closed_code" if codes else "unclassified",
               "relay_terminal": relay_terminal_observation(data)}
    if docker:
        receipt["docker_error"] = closed_docker_error(data)
    return receipt


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
    if "required_user" in expected:
        require(config.get("User") == expected["required_user"], "container_default_user")
    actual = sorted((m.get("Name"), m.get("Destination"), m.get("RW")) for m in value.get("Mounts", []))
    require(actual == sorted(expected["mounts"]), "container_mounts")
    require(host.get("NetworkMode") == expected["network"], "container_network")
    require(host.get("Memory") == expected["memory"] and host.get("MemorySwap") == expected["memory"]
            and host.get("PidsLimit") == 256, "container_resource_limits")
    require((host.get("RestartPolicy") or {}).get("Name") == "no", "container_restart_policy")
    require(host.get("LogConfig") == LOG_CONFIG, "container_logging_configuration")
    if "peer_ipv6" in expected:
        networks = value.get("NetworkSettings", {}).get("Networks", {})
        require(isinstance(networks, dict) and len(networks) == 1, "container_peer_network")
        attached = next(iter(networks.values()))
        require(isinstance(attached, dict)
                and (attached.get("IPAMConfig") or {}).get("IPv6Address") == expected["peer_ipv6"],
                "container_requested_peer_ipv6")
        require(attached.get("NetworkID") in (None, "", expected["network"])
                and attached.get("GlobalIPv6Address") in (None, "", expected["peer_ipv6"]),
                "container_peer_attachment_identity")
        # Docker create records IPAM intent before network attachment. Actual
        # address/network identity is mandatory once the service is running.
        if value.get("State", {}).get("Running") is True:
            require(attached.get("NetworkID") == expected["network"]
                    and attached.get("GlobalIPv6Address") == expected["peer_ipv6"]
                    and attached.get("GlobalIPv6PrefixLen") == 64,
                    "container_actual_peer_ipv6")
    return value.get("State", {})


def peer_ipv6_addresses(subnet):
    require(type(subnet) is str, "peer_network_subnet")
    try:
        network = ipaddress.IPv6Network(subnet, strict=True)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
        raise Refused("peer_network_subnet") from None
    require(str(network) == subnet and network.prefixlen == 64
            and network.subnet_of(ipaddress.IPv6Network("fc00::/7")), "peer_network_subnet")
    # Keep explicit peer addresses far from Docker's low sequential helper
    # allocations and the subnet gateway. This is private fixture allocation,
    # never a guessed Fly machine address.
    return {node: str(network.network_address + (1 << 63) + index + 1)
            for index, node in enumerate(NODES)}


# Closed diagnostic vocabulary from the public relay HTTP response mapping.
# This projection never changes the route's acceptance predicates or exposes
# arbitrary response values, messages, headers, paths or request payloads.
ECHO_RESPONSE_CODES = frozenset({
    "UNAUTHORIZED", "FORBIDDEN", "NOT_FOUND", "DEVICE_NOT_FOUND", "SERVICE_NOT_FOUND",
    "SERVICE_AMBIGUOUS", "AUTHORIZATION_UNAVAILABLE", "CLUSTER_UNREADY", "PEER_UNTRUSTED",
    "PEER_UNAVAILABLE", "OWNER_NOT_READY", "OWNER_CHANGED", "ROTATION_FREEZE",
    "RESOURCE_EXHAUSTED", "DEVICE_OFFLINE", "DEADLINE_EXCEEDED", "BODY_LIMIT", "BODY_TIMEOUT",
    "REVERSE_CHANNEL_UNAVAILABLE",
})
ECHO_EXECUTIONS = frozenset({"not_dispatched", "unknown"})
MAX_ECHO_RESPONSE_OBSERVATION = 65536  # unchanged http_request response bound


def echo_response_observation(status, body, expected_body, expected_status, expected_code):
    def field(value, key, allowed):
        if key not in value:
            return {"classification": "missing", "value": None}
        selected = value[key]
        if type(selected) is not str:
            return {"classification": "invalid_type", "value": None}
        return {"classification": "known" if selected in allowed else "unknown",
                "value": selected if selected in allowed else None}

    observed = {"status": status if type(status) is int and 100 <= status <= 999 else None,
                "status_valid": type(status) is int and 100 <= status <= 999,
                "expected_status": expected_status, "body_bytes": len(body) if type(body) is bytes else None,
                "body_sha256": None, "hash_scope": "unavailable", "raw_uploaded": False,
                "body_format": "invalid_type", "code": {"classification": "unavailable", "value": None},
                "execution": {"classification": "unavailable", "value": None},
                "expected_echo_body_match": type(body) is bytes and body == expected_body,
                "expected_denial_fields_match": None if expected_code is None else False}
    if type(body) is not bytes:
        return observed
    if len(body) > MAX_ECHO_RESPONSE_OBSERVATION:
        observed.update(body_format="body_bound_exceeded", hash_scope="omitted_body_bound")
        return observed
    observed.update(body_sha256=digest(body), hash_scope="complete")
    if not body:
        observed["body_format"] = "empty"
        return observed
    duplicate = False
    def pairs(rows):
        nonlocal duplicate
        value = {}
        for key, item in rows:
            duplicate |= key in value
            value[key] = item
        return value
    def invalid_constant(_value):
        raise ValueError("nonfinite JSON constant")
    try:
        value = json.loads(body.decode("utf-8"), object_pairs_hook=pairs, parse_constant=invalid_constant)
    except (ValueError, UnicodeError, RecursionError):
        observed["body_format"] = "invalid_json"
        return observed
    if duplicate:
        observed["body_format"] = "duplicate_json_keys"
        return observed
    observed["body_format"] = "json_object" if type(value) is dict else "json_non_object"
    if type(value) is dict:
        observed["code"] = field(value, "code", ECHO_RESPONSE_CODES)
        observed["execution"] = field(value, "execution", ECHO_EXECUTIONS)
        if expected_code is not None:
            observed["expected_denial_fields_match"] = (observed["code"]["value"] == expected_code
                                                        and observed["execution"]["value"] == "not_dispatched")
    return observed


def checked_grant_state(values):
    require(type(values) is list and len(values) == 2
            and type(values[0]) is str and values[0] in {"0", "1"}
            and type(values[1]) is str and re.fullmatch(r"[1-9][0-9]{0,19}", values[1]) is not None
            and int(values[1]) <= 2**64 - 1, "grant_state_schema")
    return {"active": values[0] == "1", "revision": int(values[1])}


def check_grant_revocation(before, after):
    for state in (before, after):
        require(type(state) is dict and set(state) == {"active", "revision"}
                and type(state["active"]) is bool and u64(state["revision"]) and state["revision"] > 0,
                "grant_revocation_schema")
    require(before["active"] is True and after["active"] is False
            and after["revision"] > before["revision"], "grant_revocation_not_advanced")


def check_visible_echo_target(value, tenant, device, service):
    require(type(value) is list and 1 <= len(value) <= 3
            and all(type(row) is dict for row in value), "grant_discovery_shape")
    matches = [row for row in value if row.get("device_id") == device]
    require(len(matches) == 1, "grant_discovery_target")
    target = matches[0]
    require(target.get("tenant_id") == tenant and target.get("active") is True,
            "grant_discovery_target")
    services = target.get("services")
    require(type(services) is list and len(services) == 1 and type(services[0]) is dict,
            "grant_discovery_sole_service")
    selected = services[0]
    require(selected.get("tenant_id") == tenant and selected.get("device_id") == device
            and selected.get("service_id") == service and selected.get("service_type") == "echo"
            and selected.get("active") is True, "grant_discovery_sole_service")


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


def checked_disconnect(raw, supervisor_pid):
    value = observation_json(raw, 64 * 1024)
    require(isinstance(value, dict) and set(value) == {"schema_version", "command", "ok", "result", "error"}
            and type(value["schema_version"]) is int and value["schema_version"] == 1
            and value["command"] == "disconnect" and value["ok"] is True and value["error"] is None,
            "client_disconnect_envelope")
    result = value["result"]
    require(type(supervisor_pid) is int and 0 < supervisor_pid < 2**32
            and isinstance(result, dict) and set(result) == {"pid", "state", "state_at_request", "waited_ms"}
            and type(result["pid"]) is int and result["pid"] == supervisor_pid
            and result["state"] == "stopped" and result["state_at_request"] == "ready"
            and u64(result["waited_ms"]), "client_disconnect_result")
    return result


def client_exit_complete(state):
    require(isinstance(state, dict) and {"Running", "Status", "Pid", "ExitCode", "OOMKilled", "Error"} <= set(state)
            and type(state["Running"]) is bool and state["OOMKilled"] is False
            and type(state["ExitCode"]) is int and state["ExitCode"] == 0
            and type(state["Pid"]) is int and state["Pid"] >= 0 and state["Error"] == "",
            "client_disconnect_unclean_exit")
    if state["Running"]:
        require(state["Status"] == "running" and state["Pid"] > 0, "client_disconnect_process_state")
        return False
    require(state["Status"] == "exited" and state["Pid"] == 0, "client_disconnect_process_state")
    return True


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


def observation_json(raw, maximum):
    require(isinstance(raw, bytes) and len(raw) <= maximum, "observation_byte_bound")
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "observation_duplicate_field")
            result[key] = value
        return result
    def constant(_value):
        raise Refused("observation_json")
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError):
        raise Refused("observation_json") from None


def u64(value):
    return type(value) is int and 0 <= value <= 2**64 - 1


def timestamp_ns(value):
    # Preserve Rust DateTime's nanoseconds: truncation could hide an extension
    # of a fixed confirmation. No floating-point timestamps enter comparisons.
    require(isinstance(value, str), "observation_timestamp")
    match = re.fullmatch(r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]{1,9}))?(Z|[+-][0-9]{2}:[0-9]{2})", value)
    require(match is not None, "observation_timestamp")
    require(match[3] == "Z" or (int(match[3][1:3]) < 24 and int(match[3][4:]) < 60), "observation_timestamp")
    try:
        whole = dt.datetime.fromisoformat(match[1] + match[3].replace("Z", "+00:00"))
        delta = whole - dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
    except ValueError:
        raise Refused("observation_timestamp") from None
    return (delta.days * 86400 + delta.seconds) * 10**9 + int((match[2] or "0").ljust(9, "0"))


def utc_ns():
    return timestamp_ns(dt.datetime.now(dt.timezone.utc).isoformat())


def membership_state_file(config, incarnation):
    require(type(incarnation) is str and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}", incarnation) is not None,
            "membership_state_incarnation")
    name = "membership-version-" + digest(incarnation.encode("utf-8")) + ".json"
    require(isinstance(config, dict) and config.get("deployment_incarnation") == incarnation
            and isinstance(config.get("cluster"), dict)
            and config["cluster"].get("membership_version_state_path") == ROLE_BASE["relay"] + "/state/" + name,
            "membership_state_path")
    return name


def publication_observation(raw, inventory, run_id, now, previous=None):
    """Passive equivalent of the native authority_publication_observer.

    The unsigned local state is evidence only. Real relays must verify their
    own nonce-bound checkpoints and records before their durable fences count.
    """
    value = observation_json(raw, MAX_AUTHORITY_OBSERVATION)
    required = {"schema_version", "inventory", "expected_redis_run_id", "membership_high_water",
                "checkpoint_high_water", "known_node_ids", "confirmed"}
    require(isinstance(value, dict) and set(value) == required, "publication_schema")
    require(type(value["schema_version"]) is int and value["schema_version"] == 1
            and canonical(value["inventory"]) == canonical(inventory)
            and value["expected_redis_run_id"] == run_id, "publication_identity")
    nodes = value["known_node_ids"]
    require(isinstance(nodes, list) and len(nodes) == 3 and all(isinstance(n, str) for n in nodes)
            and set(nodes) == set(NODES)
            and {n["node_id"] for n in inventory["nodes"]} == set(NODES)
            and len(inventory["nodes"]) == 3, "publication_nodes")
    require(u64(value["membership_high_water"]) and u64(value["checkpoint_high_water"]), "publication_counter")
    confirmed = value["confirmed"]
    if confirmed is not None:
        require(isinstance(confirmed, dict) and set(confirmed) == {"inventory_revision", "membership_version", "expires_at"}, "confirmation_schema")
        require(u64(confirmed["inventory_revision"]) and confirmed["inventory_revision"] == inventory["revision"]
                and u64(confirmed["membership_version"]) and 0 < confirmed["membership_version"] <= value["membership_high_water"], "confirmation_version")
        expires = timestamp_ns(confirmed["expires_at"])
        require(now < expires <= now + 60 * 10**9, "confirmation_window")
    if previous is not None:
        require(value["membership_high_water"] >= previous["membership_high_water"]
                and value["checkpoint_high_water"] >= previous["checkpoint_high_water"], "publication_rollback")
        old = previous["confirmed"]
        if old is not None:
            require(confirmed is not None and confirmed["membership_version"] >= old["membership_version"]
                    and (confirmed["membership_version"] != old["membership_version"]
                         or timestamp_ns(confirmed["expires_at"]) == timestamp_ns(old["expires_at"])), "confirmation_rollback_or_extension")
    return value


def relay_observation(raw, inventory, node):
    value = observation_json(raw, MAX_RELAY_OBSERVATION)
    require(isinstance(value, dict) and set(value) == {"schema_version", "deployment_id", "deployment_incarnation", "node_id", "state"}, "relay_observation_schema")
    require(type(value["schema_version"]) is int and value["schema_version"] == 1
            and value["deployment_id"] == inventory["deployment_id"]
            and value["deployment_incarnation"] == inventory["deployment_incarnation"]
            and node in NODES and value["node_id"] == node, "relay_observation_identity")
    state = value["state"]
    require(isinstance(state, dict) and set(state) == {"checkpoint_version", "node_versions"}
            and (state["checkpoint_version"] is None or u64(state["checkpoint_version"]))
            and isinstance(state["node_versions"], dict) and set(state["node_versions"]) <= set(NODES)
            and all(u64(v) for v in state["node_versions"].values()), "relay_observation_state")
    return state


class PublicationWatch:
    def __init__(self, stopped):
        self.stopped, self.latest, self.target = stopped, stopped, None

    def observe(self, current):
        # Freeze H+1 once. A moving checkpoint allocator is not an adoption
        # target, and a spent but unconfirmed membership round cannot pass.
        self.latest = current
        confirmed = current["confirmed"]
        if self.target is None and confirmed is not None and confirmed["membership_version"] > self.stopped["membership_high_water"]:
            require(current["checkpoint_high_water"] < 2**64 - 1, "adoption_floor_overflow")
            self.target = {"checkpoint_version": current["checkpoint_high_water"] + 1,
                           "membership_version": confirmed["membership_version"],
                           "expires_ns": timestamp_ns(confirmed["expires_at"])}

    def adopted(self, states, now):
        require(self.target is not None and now < self.target["expires_ns"], "adoption_target_expired")
        return set(states) == set(NODES) and all(
            state["checkpoint_version"] is not None and state["checkpoint_version"] >= self.target["checkpoint_version"]
            and all(state["node_versions"].get(node, -1) >= self.target["membership_version"] for node in NODES)
            for state in states.values())


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
        self.readiness_diagnostic_failures = []
        self.echo_response_diagnostic_failure = None

    @contextmanager
    def budget(self, seconds):
        # All volume-read CLI calls and their owned-group cleanup consume the
        # same absolute budget. Never reset it for a poll or an individual node.
        original = self.deadline
        self.deadline = min(original, time.monotonic() + seconds)
        try:
            yield
            self.guard()
        finally:
            self.deadline = original

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
                       stdout=safe_log_receipt(stdout_path), stderr=safe_log_receipt(stderr_path, docker=self.operation.startswith("docker_")),
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
        self.peer_ipv6 = {}
        self.inventory = []

    def call(self, args, **kw):
        for command, operation in ((["version", "--format", "{{json .Server}}"], "docker_engine_version"),
                                   (["info", "--format", "{{json .Plugins.Log}}"], "docker_log_plugins")):
            if args == command:
                self.run.operation, self.run.role, self.run.subcommand = operation, "controller", "engine-metadata"
                return self.run(DOCKER + args, **kw)
        allowed = {"container", "network", "image", "volume"}
        require(len(args) >= 2 and args[0] in allowed and args[1] in {
            "create", "inspect", "start", "stop", "exec", "logs", "rm", "ls", "cp"}, "docker_command_shape")
        self.run.operation = "docker_" + args[0] + "_" + args[1]
        return self.run(DOCKER + args, **kw)

    def engine_preflight(self):
        server = json.loads(self.call(["version", "--format", "{{json .Server}}"]))
        drivers = json.loads(self.call(["info", "--format", "{{json .Plugins.Log}}"]))
        projection = safe_engine_projection(server, drivers)
        self.run.event("docker_engine", **projection)
        return projection

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
               user=None, network=True, memory=256, interactive=False, peer_ipv6=None, name_sequence=None,
               required_user=None):
        name = f"{self.owner}-{len(self.containers):03d}-{role}"
        if name_sequence is not None:
            require(u64(name_sequence), "container_name_sequence")
            name += "-r" + str(name_sequence)
        net = self.network["id"] if network else "none"
        item = {"id": None, "name": name, "role": role, "image": image, "mounts": list(mounts),
                "network": net, "memory": memory * 1024**2}
        if required_user is not None:
            require(required_user == "client:client" and user is None and image == self.images.get("client"),
                    "container_required_user")
            item["required_user"] = required_user
        if role in NODES or peer_ipv6 is not None:
            require(role in NODES and network and image == self.images.get("relay")
                    and self.network is not None and "subnet" in self.network,
                    "peer_container_assignment")
            approved = peer_ipv6_addresses(self.network["subnet"])
            require(self.peer_ipv6 == approved and type(peer_ipv6) is str
                    and peer_ipv6 == approved[role], "peer_container_assignment")
            require(not any(prior.get("peer_ipv6") == peer_ipv6 for prior in self.containers),
                    "peer_container_duplicate_address")
            item["peer_ipv6"] = peer_ipv6
        known = {"generate-key", "initialize", "recovery-initialize", "activate-first-incarnation", "provision-catalog",
                 "add-device", "add-service", "set-grant", "revoke-grant", "initialize-membership", "check-config", "connect", "disconnect"}
        item["subcommand"] = command[0] if command and command[0] in known else ("python-helper" if entrypoint == "/usr/bin/python3" else "serve-or-inspect")
        self.run.role = role
        self.run.subcommand = item["subcommand"]
        self.containers.append(item)
        args = ["container", "create", "--pull=never", "--name", name, "--label", OWNER_LABEL + "=" + self.owner,
                "--label", OWNER_LABEL + ".role=" + role, "--network", net, "--memory", str(item["memory"]),
                "--memory-swap", str(item["memory"]), "--pids-limit", "256", "--restart=no", "--cap-drop=ALL",
                "--security-opt=no-new-privileges", "--log-driver=local", "--log-opt=max-size=2m", "--log-opt=max-file=1",
                "--log-opt=compress=false"]
        if peer_ipv6 is not None:
            args += ["--ip6", peer_ipv6]
        if user == "0:0":
            # These three capabilities are only used by the explicit owned-volume
            # initializer/reader, never by an ordinary serving entrypoint.
            args += ["--cap-add=CHOWN", "--cap-add=DAC_OVERRIDE", "--cap-add=FOWNER"]
        for volume, destination, write in mounts:
            args += ["--mount", f"type=volume,source={volume},target={destination},volume-nocopy" + ("" if write else ",readonly")]
        for alias in aliases:
            args += ["--network-alias", alias]
        for port in ports:
            args += ["--publish", f"[{HOST_LOOPBACK}]::{port}"]
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
        observed = self.inspect(item)
        shape = published_binding_shape(observed, port)
        self.run.event("published_port_binding", role=item["role"], container_port=port, **shape)
        require(shape["accepted"], "published_port_scope")
        return int(observed["NetworkSettings"]["Ports"][f"{port}/tcp"][0]["HostPort"])

    def readiness_metrics(self, item):
        require(item["role"] in NODES and item["image"] == self.images["relay"], "metrics_container")
        before = self.inspect(item)
        require(before["State"].get("Running") is True, "metrics_container")
        self.run.subcommand = "readiness-metrics"
        data = self.call(["container", "exec", item["id"], "/usr/bin/python3", "-I", "-c", readiness_metrics_program()], timeout=10)
        after = self.inspect(item)
        require(after["State"].get("Running") is True, "metrics_container")
        return readiness_metrics_envelope(data)

    def setup_volume(self, name, uid, gid, files=None, directories=()):
        payload = {"uid": uid, "gid": gid, "directories": list(directories),
                   "files": {k: base64.b64encode(v).decode() for k, v in (files or {}).items()}}
        self.one_shot("volume-init", self.images["authority"], network=False, user="0:0",
                      mounts=[(name, "/volume", True)], entrypoint="/usr/bin/python3",
                      command=["-I", "-c", VOLUME_INITIALIZE], data=canonical(payload))

    def read_volume(self, name, relative, *, max_bytes=1024 * 1024 - 1):
        require(type(max_bytes) is int and 0 < max_bytes < 1024 * 1024, "volume_read_byte_limit")
        raw = self.one_shot("volume-read", self.images["authority"], network=False, user="0:0",
                            mounts=[(name, "/volume", False)], entrypoint="/usr/bin/python3",
                            command=["-I", "-c", VOLUME_READ], data=canonical({"paths": relative, "max_bytes": max_bytes}))
        values = json.loads(raw)
        require(set(values) == set(relative), "volume_read_paths")
        decoded = {key: base64.b64decode(value, validate=True) for key, value in values.items()}
        require(all(len(value) <= max_bytes for value in decoded.values()), "volume_read_byte_bound")
        return decoded

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
                                       "oom_killed": state.get("OOMKilled"), "state_before_cleanup": safe_container_state(state)})
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
import base64,json,os,pathlib,stat,sys
v=json.load(sys.stdin); out={}; root=pathlib.Path('/volume'); limit=v['max_bytes']
assert type(limit) is int and 0<limit<1048576
for name in v['paths']:
 p=pathlib.PurePosixPath(name); assert not p.is_absolute() and '..' not in p.parts and p.parts
 target=root.joinpath(*p.parts)
 with os.fdopen(os.open(target,os.O_RDONLY|os.O_NOFOLLOW),'rb') as f:
  info=os.fstat(f.fileno()); assert stat.S_ISREG(info.st_mode) and info.st_size<=limit
  data=f.read(limit+1); assert len(data)<=limit
 out[name]=base64.b64encode(data).decode()
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
    connection = http.client.HTTPConnection(HOST_LOOPBACK, port, timeout=5)
    try:
        connection.sock = context.wrap_socket(socket.create_connection((HOST_LOOPBACK, port), timeout=5), server_hostname=host)
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
        with bounded_network(), self.context.wrap_socket(socket.create_connection((HOST_LOOPBACK, self.port), timeout=5), server_hostname=self.host) as sock:
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
        self.primary_claims = dict(payload)
        return canonical(jwks), self.sign_claims(payload)

    def sign_claims(self, claims):
        # Signing only: every control uses the original trusted key/JWKS.
        b64 = lambda value: base64.urlsafe_b64encode(value).rstrip(b"=")
        unsigned = b64(canonical({"alg": "RS256", "kid": "synthetic", "typ": "JWT"})) + b"." + b64(canonical(claims))
        signature = self.openssl(["dgst", "-sha256", "-sign", str(self.root / "oidc.key")], unsigned)
        return (unsigned + b"." + b64(signature)).decode()

    def scope_refusal_token(self):
        claims = dict(self.primary_claims)
        require(claims.pop("scope") == "echo:invoke", "scope_control_original_claim")
        return self.sign_claims(claims)


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
        self.membership_files = {}
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
        self.scope_token = self.pki.scope_refusal_token()
        subnet = str(ipaddress.IPv6Network("fd" + secrets.token_hex(1) + ":" + secrets.token_hex(2)
                                          + ":" + secrets.token_hex(2) + "::/64"))
        name = self.prefix + "-network"
        d.network = {"name": name, "id": name, "subnet": subnet}  # resolve/verify name if create outcome is ambiguous
        nid = d.call(["network", "create", "--driver=bridge", "--ipv4=false", "--ipv6", "--subnet", subnet,
                      "--label", OWNER_LABEL + "=" + self.prefix, name]).decode().strip()
        require(ID_RE.fullmatch(nid), "network_id")
        d.network["id"] = nid
        network = json.loads(d.call(["network", "inspect", nid]))[0]
        require(network.get("EnableIPv6") is True and network.get("EnableIPv4") is False, "network_not_ipv6_only")
        require(network.get("Id") == nid and network.get("Name") == name
                and (network.get("Labels") or {}).get(OWNER_LABEL) == self.prefix
                and [row.get("Subnet") for row in network.get("IPAM", {}).get("Config", [])] == [subnet],
                "network_peer_subnet_identity")
        d.peer_ipv6 = peer_ipv6_addresses(subnet)
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
            relay["peer_ipv6"] = d.peer_ipv6[node]
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
        self.authority_inventory = observation_json((self.rendered / "authority/inventory.json").read_bytes(), MAX_AUTHORITY_OBSERVATION)
        self.event("rendered", manifest_sha256=digest(canonical(manifest)), config_hashes=manifest["files"])
        read = lambda path: Path(path).read_bytes()
        default_user = "default"
        for i, relay in enumerate(inv["relays"]):
            node = relay["node_id"]
            self.membership_files[node] = membership_state_file(
                tomllib.loads((self.rendered / node / "relay.toml").read_text()), inv["deployment_incarnation"])
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
        # The serving relay owns this identity's one authority permit. Apply
        # the guard before nonce/request construction or any network operation.
        require(not self.relays, "checkpoint_observer_with_serving_relays")
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

    def publication(self, previous=None):
        raw = self.docker.read_volume(self.states["authority"], ["authority.json"], max_bytes=MAX_AUTHORITY_OBSERVATION)["authority.json"]
        self.run.guard()
        return publication_observation(raw, self.authority_inventory, self.run_id, utc_ns(), previous)

    def restart_authority(self):
        self.docker.stop(self.authority)
        # Read only after the process is stopped. A pre-stop observation can
        # miss one last completed round and falsely attribute it to restart.
        stopped = self.publication()
        self.event("authority_stopped_publication", membership_high_water=stopped["membership_high_water"],
                   checkpoint_high_water=stopped["checkpoint_high_water"],
                   confirmed_version=None if stopped["confirmed"] is None else stopped["confirmed"]["membership_version"])
        self.docker.start(self.authority)
        self.authority_port = self.docker.port(self.authority, 8444)
        watch = PublicationWatch(stopped)
        def fresh():
            current = self.publication(watch.latest)
            watch.observe(current)
            if watch.target is None:
                return False
            require(utc_ns() < watch.target["expires_ns"], "adoption_target_expired")
            states = {}
            for node in NODES:
                name = self.membership_files[node]
                raw = self.docker.read_volume(self.states[node], [name], max_bytes=MAX_RELAY_OBSERVATION)[name]
                self.run.guard()
                states[node] = relay_observation(raw, self.authority_inventory, node)
            # Recheck both absolute budget and validity after the last read.
            self.run.guard()
            if not watch.adopted(states, utc_ns()):
                return False
            self.event("authority_passive_adoption", membership_version=watch.target["membership_version"],
                       fixed_checkpoint_floor=watch.target["checkpoint_version"], adopted_nodes=list(NODES),
                       observed_states=states, unsigned_observation=True)
            return True
        with self.run.budget(30):
            wait_until(self.run, fresh, 30, "authority_restart_fresh_publication")

    def after_catalog_provisioned(self):
        """Optional fixture-only checkpoint before any serving writer starts."""

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
        self.after_catalog_provisioned()
        self.authority_command(["initialize-membership", "--expected-redis-run-id", self.run_id])
        self.authority_command(["check-config"])
        self.start_authority()
        wait_until(self.run, lambda: self.checkpoint() is not None, 30, "authority_publication_deadline")
        for i, relay in enumerate(self.inventory["relays"]):
            node = relay["node_id"]
            item = d.create(node, d.images["relay"], memory=512, env=self.env[node],
                     mounts=[(self.states[node], ROLE_BASE["relay"] + "/state", True)],
                     aliases=[relay["app"] + ".internal", self.public_hosts[i]], ports=[8443, 9443],
                     peer_ipv6=relay["peer_ipv6"])
            d.start(item)
            self.relays.append(item)
        self.consumer_ports = [d.port(item, 8443) for item in self.relays]
        self.device_ports = [d.port(item, 9443) for item in self.relays]
        self.wait_ready()
        self.event("bootstrap", relays_ready=3, authority_fresh_publication=True, redis_tls=True)

    def wait_ready(self):
        observations = [{"node": node, "attempts": 0, "counts": {}, "first": None, "last": None} for node in NODES]
        def record(index, observation):
            row = observations[index]
            row["attempts"] += 1
            kind = observation["kind"]
            if kind == "http":
                kind = f"http_{observation['status']}_{observation['body_class']}" if observation["status"] in (200, 503) else "http_other_status"
            row["counts"][kind] = row["counts"].get(kind, 0) + 1
            if row["first"] is None:
                row["first"] = observation
            row["last"] = observation
        def ready():
            for i, port in enumerate(self.consumer_ports):
                self.run.operation, self.run.role, self.run.subcommand = "https_readiness", NODES[i], "readyz"
                try:
                    status, body = http_request(port, self.public_hosts[i], self.public_context, "/readyz")
                except (ConnectionError, OSError) as error:
                    record(i, readiness_transport_observation(error))
                    return False
                except BaseException as error:
                    record(i, readiness_transport_observation(error))
                    raise
                record(i, readiness_http_observation(status, body))
                if status == 503:
                    return False
                require(status == 200 and json.loads(body) == {"status": "ready"}, "relay_ready_response")
            return True
        try:
            wait_until(self.run, ready, 60, "cluster_readiness_deadline")
        except BaseException:
            # Inspect/exec diagnostics must not overwrite the original failed
            # stage/last-command context or replace its exception.
            context = (self.run.stage, self.run.operation, self.run.role, self.run.subcommand)
            try:
                self.event("readiness_observations", passed=False, nodes=observations)
                self.collect_readiness_metrics()
            except BaseException as error:
                self.run.readiness_diagnostic_failures.append({"code": readiness_diagnostic_code(error)})
            finally:
                self.run.stage, self.run.operation, self.run.role, self.run.subcommand = context
            raise
        self.event("readiness_observations", passed=True, nodes=observations)

    def collect_readiness_metrics(self):
        rows = []
        complete = False
        self.run.stage = "readiness_diagnostics"
        try:
            with self.run.budget(30):
                for node, item in zip(NODES, self.relays, strict=True):
                    try:
                        self.run.guard()
                        value = self.docker.readiness_metrics(item)
                        rows.append({"node": node, **value})
                        if value["status"] == "failed":
                            self.run.readiness_diagnostic_failures.append({"node": node, "code": value["code"]})
                    except BaseException as error:
                        code = readiness_diagnostic_code(error)
                        rows.append({"node": node, "status": "failed", "code": code})
                        self.run.readiness_diagnostic_failures.append({"node": node, "code": code})
                        return
            complete = True
        finally:
            self.event("readiness_metrics", nodes=rows, complete=complete)

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

    def disconnect_client(self, item, device):
        # The caller must outlive connect/PID1. An exec in that same container
        # may be terminated before it can report the socket's orderly close.
        require(any(owned is item for owned in self.docker.containers)
                and item["image"] == self.docker.images["client"]
                and item["role"] in {"client-0", "client-1", "client-2", "spare-client-positive"},
                "client_disconnect_target")
        mounts = item["mounts"]
        require(len(mounts) == 1 and len(mounts[0]) == 3 and mounts[0][1] == "/profile"
                and mounts[0][2] is True and mounts[0][0] in self.docker.volumes,
                "client_disconnect_profile")
        observed = self.docker.inspect(item)
        require(observed["Config"].get("User") == "client:client"
                and not client_exit_complete(observed["State"]), "client_disconnect_target_not_running")
        self.run.subcommand = "status"
        raw = self.docker.call(["container", "exec", item["id"], "/usr/local/bin/tunnel-client",
                                "status", "--config", "/profile/client.toml", "--json"])
        observation_json(raw, 64 * 1024)  # refuse duplicate/nonfinite fields before the shared status parser
        before = checked_status(raw, device)
        pid = before.get("pid")
        require(type(pid) is int and 0 < pid < 2**32 and before.get("state") == "ready"
                and ready_session(before), "client_disconnect_supervisor")
        self.event("client_disconnect_requested", client_id=item["id"], role=item["role"], supervisor_pid=pid)
        # Keep the original 30s command budget, including helper setup. The
        # Runner's existing nine seconds are reserved only for owned cleanup.
        with self.run.budget(COMMAND_SECONDS + 9):
            raw = self.docker.one_shot("client-disconnect", self.docker.images["client"], network=False,
                                      mounts=[(mounts[0][0], "/profile", False)], required_user="client:client",
                                      command=["disconnect", "--config", "/profile/client.toml", "--json"])
            result = checked_disconnect(raw, pid)
        # Observe process exit under the former Docker-stop 25s bound. Never
        # send a second stop request or use final cleanup to rescue acceptance.
        with self.run.budget(25 + 9):
            deadline = time.monotonic() + 25
            while True:
                self.run.guard()
                require(time.monotonic() < deadline, "client_disconnect_exit_deadline")
                observed = self.docker.inspect(item)
                require(time.monotonic() < deadline, "client_disconnect_exit_deadline")
                require(observed["Config"].get("User") == "client:client", "client_disconnect_target_user")
                if client_exit_complete(observed["State"]):
                    break
                time.sleep(min(0.5, max(0, deadline - time.monotonic())))
        self.event("client_disconnected", client_id=item["id"], role=item["role"], supervisor_pid=pid,
                   waited_ms=result["waited_ms"], state="stopped", original_exit_code=0,
                   original_pid=0, oom_killed=False, helper_network="none", profile_readonly=True)

    def owner(self, i):
        key = f"tunnel-catalog:{self.inventory['redis_namespace']}:coord:owner:{self.inventory['deployment_incarnation']}:{self.tenant}:{self.devices[i]}"
        values = self.redis.command("HGETALL", key)
        value = dict(zip(values[::2], values[1::2]))
        require(value.get("node_id") == f"relay-{chr(97+i)}" and value.get("deployment_incarnation") == self.inventory["deployment_incarnation"], "device_owner_node")
        require(self.redis.command("PTTL", key) > 0, "device_owner_expired")
        session = self.status(i)["session"]
        require(value.get("session_id") == session["session_id"] and int(value.get("owner_epoch", "0")) == session["epoch"], "owner_session_join")
        return value

    def grant_state(self, principal):
        self.run.guard()
        self.run.operation, self.run.role = "redis_grant_observation", "redis"
        key = f"tunnel-catalog:{self.inventory['redis_namespace']}:grant:{self.tenant}:{principal}:{self.devices[0]}:{self.services[0]}"
        return checked_grant_state(self.redis.command("HMGET", key, "active", "revision"))

    def visible_echo_target(self, token):
        self.run.guard()
        self.run.operation, self.run.role = "https_discovery", "relay-a"
        status, body = http_request(self.consumer_ports[0], self.public_hosts[0], self.public_context,
                                   "/v1/devices", headers={"Authorization": "Bearer " + token})
        diagnostic_failed = False
        try:
            observed = echo_response_observation(status, body, None, 200, None)
            self.event("grant_discovery_response", stage=self.run.stage, ingress="relay-a", **observed)
        except Exception:
            diagnostic_failed = True
            self.run.echo_response_diagnostic_failure = {"code": "echo_response_observation_failed"}
        require(status == 200, "grant_discovery_status")
        check_visible_echo_target(observation_json(body, 65536), self.tenant, self.devices[0], self.services[0])
        require(not diagnostic_failed, "echo_response_observation_failed")

    def scope_refusal(self):
        before = self.grant_state(self.user)
        require(before["active"] is True, "scope_control_grant_inactive")
        self.echo(0, 0)
        self.visible_echo_target(self.scope_token)
        saved = self.token
        try:
            self.token = self.scope_token
            self.echo(0, 0, denied=True)
        finally:
            self.token = saved
        self.echo(0, 0)
        require(self.grant_state(self.user) == before, "scope_control_grant_changed")
        self.event("consumer_scope_refusal", status=403, code="FORBIDDEN", execution="not_dispatched",
                   target_discovered=True, active_grant_unchanged=True, exact_echo_before_after=True)

    def revoke_target_grant(self, principal, token):
        self.visible_echo_target(token)
        before = self.grant_state(principal)
        require(before["active"] is True, "grant_revocation_already_inactive")
        self.relay_command("relay-a", ["revoke-grant", "--tenant", self.tenant, "--user", principal,
                                      "--device", self.devices[0], "--service", self.services[0]])
        after = self.grant_state(principal)
        check_grant_revocation(before, after)
        self.event("grant_revocation_observed", active=False, before_revision=before["revision"], revision=after["revision"])
        return {"before": before, "after": after}

    def assert_grant_revocation(self, principal, proof):
        require(type(proof) is dict and set(proof) == {"before", "after"}, "grant_revocation_proof")
        check_grant_revocation(proof["before"], proof["after"])
        require(self.grant_state(principal) == proof["after"], "grant_revocation_not_preserved")

    def echo(self, ingress, device, *, anonymous=False, denied=False, revoked=False):
        require(all(type(flag) is bool for flag in (anonymous, denied, revoked))
                and sum((anonymous, denied, revoked)) <= 1, "echo_expectation")
        self.run.guard()
        self.run.operation, self.run.role = "https_echo", f"relay-{chr(97+ingress)}"
        path = f"/v1/devices/{self.devices[device]}/services/{self.services[device]}/echo"
        payload = secrets.token_hex(16).encode()
        status, body = http_request(self.consumer_ports[ingress], self.public_hosts[ingress], self.public_context,
                         path, method="POST", data=payload, headers={} if anonymous else {"Authorization": "Bearer " + self.token})
        expected_body = self.canaries[device].encode() + payload
        expected_status = 401 if anonymous else 403 if denied else 404 if revoked else 200
        expected_code = "UNAUTHORIZED" if anonymous else "FORBIDDEN" if denied else "DEVICE_NOT_FOUND" if revoked else None
        diagnostic_failed = False
        # Record negative responses and unexpected positive responses only;
        # successful rotation traffic does not add per-payload observations.
        if anonymous or denied or revoked or status != 200 or body != expected_body:
            try:
                observed = echo_response_observation(status, body, expected_body, expected_status, expected_code)
                self.event("echo_response", stage=self.run.stage, ingress=NODES[ingress], device_index=device,
                           expectation="anonymous_refusal" if anonymous else "consumer_scope_refusal" if denied
                                       else "revoked_sole_grant" if revoked else "exact_echo",
                           **observed)
            except Exception:
                # Diagnostics must not replace the original status/body failure.
                # If those original assertions pass, fail on missing evidence.
                diagnostic_failed = True
                self.run.echo_response_diagnostic_failure = {"code": "echo_response_observation_failed"}
        if anonymous or denied or revoked:
            require(status == expected_status, "authorization_negative_status")
            result = json.loads(body)
            require(result.get("code") == expected_code and result.get("execution") == "not_dispatched", "authorization_negative_cause")
            require(body != expected_body, "authorization_negative_echo")
        else:
            require(status == 200 and body == self.canaries[device].encode() + payload, "echo_exact_body")
        require(not diagnostic_failed, "echo_response_observation_failed")

    def all_routes(self):
        if self.grant_revoked:
            self.assert_grant_revocation(self.user, self.grant_revocation)
        for device in range(3):
            self.owner(device)
            for ingress in range(3):
                self.echo(ingress, device, revoked=self.grant_revoked and device == 0)

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
        self.scope_refusal()
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
        self.grant_revocation = self.revoke_target_grant(self.user, self.token)
        self.grant_revoked = True
        self.all_routes()
        old_owner = self.owner(0)
        # The normal CLI's bounded disconnect joins its connector; a successful
        # stop alone is not used as a new connection/rotation assertion.
        self.disconnect_client(self.clients[0], self.devices[0])
        membership_file = self.membership_files["relay-a"]
        old_state = json.loads(self.docker.read_volume(self.states["relay-a"], [membership_file])[membership_file])
        self.docker.stop(self.relays[0])
        self.docker.start(self.relays[0])
        self.consumer_ports[0], self.device_ports[0] = self.docker.port(self.relays[0], 8443), self.docker.port(self.relays[0], 9443)
        self.wait_ready()
        self.start_client(0)
        new_owner = self.owner(0)
        require(new_owner["boot_id"] != old_owner["boot_id"] and new_owner["session_id"] != old_owner["session_id"]
                and int(new_owner["owner_epoch"]) > int(old_owner["owner_epoch"]), "relay_restart_fresh_owner")
        new_state = json.loads(self.docker.read_volume(self.states["relay-a"], [membership_file])[membership_file])
        check_persisted_version(old_state, new_state)
        self.all_routes()
        self.event("relay_restart", stable_node="relay-a", new_boot=True, new_session=True, persisted_version_monotonic=True, revoked_grant_refused=True)
        self.restart_authority()
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
            result["docker_engine"] = docker.engine_preflight()
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
                      readiness_diagnostic_failures=run.readiness_diagnostic_failures,
                      echo_response_diagnostic_failure=run.echo_response_diagnostic_failure,
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
