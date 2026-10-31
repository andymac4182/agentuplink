#!/usr/bin/env python3
"""Bounded M6-C239 acceptance of the shipped Redis image under AOF CoW.

Requires Linux, Docker cgroup v2, OpenSSL, and an already-built --image. Pull
the Dockerfile-pinned base image before this gate; the measured trial never
builds or pulls images. Only its uniquely labelled container is controlled.

The exploratory protocol allowed an eight-second stopped rewrite child. This
gate uses a six-second in-container watchdog and at most five seconds of
paused churn, then verifies the actual stop lasted at most eight seconds.
At least one complete paused pass and >=75% raw-payload AOF CoW are required.
Success is local workload evidence, not a production capacity guarantee.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import platform
import random
import re
import select
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path

MIB = 1024 * 1024
EXPECTED_MAXMEMORY = 96 * MIB
MEMORY_LIMIT = 256 * MIB
VALUE_BYTES = 16 * 1024
MAX_KEYS = 12000
MAX_INPUT_BYTES = 1024 * MIB
MAX_SAMPLES = 4096
TRIAL_SECONDS = 180
REWRITE_SECONDS = 45
SOURCE_ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = SOURCE_ROOT / "deploy/fly/redis/entrypoint.sh"
DOCKERFILE = SOURCE_ROOT / "deploy/fly/redis/Dockerfile"
LABEL = "agentuplink.c239-owner"
TITLES = ("redis-aof-rewrite *:6379", "redis-rdb-to-aof *:6379")
REQUIRED_CONFIG = {
    "appendonly": "yes",
    "appendfsync": "always",
    "no-appendfsync-on-rewrite": "no",
    "aof-load-truncated": "no",
    "maxmemory-policy": "noeviction",
    "maxmemory": str(EXPECTED_MAXMEMORY),
    "port": "0",
    "tls-port": "6379",
}


class GateError(Exception):
    """Fixed, payload-free failure description safe to retain in artifacts."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise GateError(message)


def run_command(args: list[str], seconds: float = 5) -> bytes:
    """Bound time and retained output; never include argv/stderr in errors."""
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
        try:
            status = process.wait(timeout=seconds)
        except BaseException:
            process.kill()
            process.wait(timeout=2)
            raise
        require(status == 0, "external command failed")
        stdout.seek(0)
        result = stdout.read(MIB + 1)
        require(len(result) <= MIB, "external command output exceeded its bound")
        return result


class RedisRefusal:
    def __init__(self, line: bytes):
        token = line.split(b" ", 1)[0]
        self.code = token.decode("ascii") if re.fullmatch(rb"[A-Z][A-Z0-9_]{0,31}", token) else "UNKNOWN"


class RespReader:
    """RESP2 replies: bounded depth, item count, line length and total bytes."""
    def __init__(self, stream):
        self.stream = stream

    def read(self):
        budget = [2 * MIB, 4096]
        return self._read(0, budget)

    def _exact(self, count: int, budget: list[int]) -> bytes:
        require(0 <= count <= budget[0], "RESP byte bound exceeded")
        budget[0] -= count
        data = self.stream.read(count)
        require(len(data) == count, "truncated RESP reply")
        return data

    def _read(self, depth: int, budget: list[int]):
        require(depth <= 8 and budget[1] > 0, "RESP depth or item bound exceeded")
        budget[1] -= 1
        line = self.stream.readline(min(4097, budget[0] + 1))
        require(len(line) <= 4096 and line.endswith(b"\r\n"), "invalid RESP line")
        budget[0] -= len(line)
        require(budget[0] >= 0 and len(line) >= 3, "invalid RESP byte budget")
        tag, body = line[:1], line[1:-2]
        if tag == b"+":
            return body
        if tag == b"-":
            return RedisRefusal(body)
        require(tag in (b":", b"$", b"*") and re.fullmatch(rb"-?[0-9]{1,12}", body) is not None,
                "invalid RESP type or integer")
        number = int(body)
        if tag == b":":
            return number
        if number == -1:
            return None
        require(number >= 0, "invalid RESP length")
        if tag == b"$":
            result = self._exact(number, budget)
            require(self._exact(2, budget) == b"\r\n", "invalid RESP bulk terminator")
            return result
        require(number <= budget[1], "RESP array bound exceeded")
        return [self._read(depth + 1, budget) for _ in range(number)]


def encode_commands(commands) -> bytes:
    require(1 <= len(commands) <= 32, "Redis batch count exceeded")
    output = bytearray()
    for command in commands:
        require(1 <= len(command) <= 8, "Redis command argument count exceeded")
        output.extend(f"*{len(command)}\r\n".encode())
        for argument in command:
            value = argument if isinstance(argument, bytes) else str(argument).encode()
            require(len(value) <= VALUE_BYTES, "Redis command argument exceeded its bound")
            output.extend(f"${len(value)}\r\n".encode())
            output.extend(value)
            output.extend(b"\r\n")
    require(len(output) <= MIB, "Redis encoded batch exceeded its bound")
    return bytes(output)


class RedisConnection:
    def __init__(self, port: int, certificate: Path, password: str):
        context = ssl.create_default_context(cafile=str(certificate))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        plain = socket.create_connection(("127.0.0.1", port), timeout=3)
        try:
            self.socket = context.wrap_socket(plain, server_hostname="localhost")
        except BaseException:
            plain.close()
            raise
        self.socket.settimeout(3)
        self.stream = self.socket.makefile("rb")
        self.reader = RespReader(self.stream)
        try:
            require(self.command("AUTH", password) == b"OK", "Redis authentication did not succeed")
        except BaseException:
            self.close()
            raise

    def batch(self, commands):
        self.socket.sendall(encode_commands(commands))
        return [self.reader.read() for _ in commands]

    def command(self, *arguments):
        reply = self.batch([arguments])[0]
        if isinstance(reply, RedisRefusal):
            raise GateError("Redis command refused: " + reply.code)
        return reply

    def info(self, section: str) -> dict[str, str]:
        raw = self.command("INFO", section)
        require(isinstance(raw, bytes), "invalid Redis INFO reply")
        try:
            lines = raw.decode("ascii").splitlines()
        except UnicodeError as error:
            raise GateError("invalid Redis INFO encoding") from error
        return dict(line.split(":", 1) for line in lines if ":" in line and not line.startswith("#"))

    def close(self):
        self.stream.close()
        self.socket.close()


def numeric_info(info: dict[str, str], names: tuple[str, ...]) -> dict[str, int]:
    result = {}
    for name in names:
        value = info.get(name, "")
        require(re.fullmatch(r"-?[0-9]{1,20}", value) is not None, "missing or invalid numeric Redis evidence")
        result[name] = int(value)
    return result


def pinned_base(dockerfile: str) -> str:
    matches = re.findall(r"^FROM (redis:8\.4\.0-alpine@sha256:[0-9a-f]{64})\s*$", dockerfile, re.MULTILINE)
    require(len(matches) == 1, "Dockerfile must have one pinned Redis8.4.0 base")
    return matches[0]


def verify_layers(image: dict, base: dict) -> None:
    prefix = base.get("layers", [])
    layers = image.get("layers", [])
    require(bool(prefix) and len(layers) > len(prefix) and layers[:len(prefix)] == prefix,
            "image does not extend the exact Dockerfile-pinned base layers")
    require(image.get("os") == "linux" and image.get("architecture") == base.get("architecture"),
            "image platform does not match the inspected pinned base")
    require(image.get("entrypoint") == ["/usr/local/bin/agentuplink-redis-entrypoint"],
            "image entrypoint differs from shipped profile")


class OwnedContainer:
    def __init__(self, token: str):
        self.token = token
        self.name = "agentuplink-c239-" + token
        self.identity = None
        self.created = False

    def inspect(self) -> dict:
        template = ('{"id":{{json .Id}},"name":{{json .Name}},"owner":{{json (index .Config.Labels "agentuplink.c239-owner")}},'
                    '"image":{{json .Image}},"memory":{{.HostConfig.Memory}},"memory_swap":{{.HostConfig.MemorySwap}},'
                    '"nano_cpus":{{.HostConfig.NanoCpus}},"pids_limit":{{.HostConfig.PidsLimit}},'
                    '"ports":{{json .NetworkSettings.Ports}},"running":{{.State.Running}},'
                    '"oom_killed":{{.State.OOMKilled}},"exit_code":{{.State.ExitCode}}}')
        info = json.loads(run_command(["docker", "inspect", "--format", template, self.identity or self.name]))
        require(info["name"] == "/" + self.name and info["owner"] == self.token
                and (self.identity is None or info["id"] == self.identity), "owned container identity changed")
        return info

    def exec(self, arguments: list[str], seconds: float = 3) -> bytes:
        require(self.identity is not None, "owned container has no immutable identity")
        return run_command(["docker", "exec", self.identity, *arguments], seconds)

    def remove(self) -> None:
        self.inspect()
        run_command(["docker", "rm", "--force", "--volumes", self.identity or self.name], 8)


def verify_container_limits(info: dict, image_id: str) -> int:
    require(info["image"] == image_id and info["running"] and not info["oom_killed"], "container image or running state mismatch")
    require(info["memory"] == MEMORY_LIMIT and info["memory_swap"] == MEMORY_LIMIT
            and info["nano_cpus"] == 1_000_000_000 and info["pids_limit"] == 64,
            "container does not enforce256MiB/no-swap/one-CPU/64-PIDs")
    bindings = info["ports"].get("6379/tcp", [])
    require(len(bindings) == 1 and bindings[0]["HostIp"] == "127.0.0.1", "Redis is not published only on loopback")
    port = int(bindings[0]["HostPort"])
    require(0 < port <= 65535 and port != 16379, "refusing shared or invalid Redis port")
    return port


CGROUP_FILES = {
    "current": "memory.current", "peak": "memory.peak", "maximum": "memory.max",
    "swap_max": "memory.swap.max", "swap_current": "memory.swap.current",
    "events": "memory.events", "stat": "memory.stat", "cpu_max": "cpu.max",
    "pids_max": "pids.max", "pids_current": "pids.current", "pids_events": "pids.events",
}


def parse_cgroup(raw: bytes) -> dict:
    fields = {}
    current = None
    for line in raw.decode("ascii").splitlines():
        if line.startswith("FILE "):
            current = line[5:]
            require(current in CGROUP_FILES and current not in fields, "invalid cgroup evidence marker")
            fields[current] = []
        else:
            require(current is not None, "cgroup evidence lacks marker")
            fields[current].append(line)
    require(fields.keys() == CGROUP_FILES.keys(), "incomplete cgroupv2 evidence")
    result = {}
    for key, lines in fields.items():
        if key in ("events", "stat", "pids_events"):
            result[key] = dict((name, int(value)) for name, value in (line.split() for line in lines))
        elif key == "cpu_max":
            require(len(lines) == 1, "invalid CPU cgroup evidence")
            result[key] = [int(value) for value in lines[0].split()]
        else:
            require(len(lines) == 1, "invalid scalar cgroup evidence")
            result[key] = int(lines[0])
    quota, period = result["cpu_max"]
    require(result["maximum"] == MEMORY_LIMIT and result["swap_max"] == 0 and result["swap_current"] == 0
            and result["pids_max"] == 64 and quota == period and period > 0,
            "effective cgroupv2 limits differ from the shipped profile")
    return result


class Sampler:
    def __init__(self, container: OwnedContainer, started: float):
        self.container = container
        self.started = started
        self.phase = "setup"
        self.samples = []
        self.errors = []
        self.stop_event = threading.Event()
        self.thread = None

    def sample(self) -> dict:
        script = "set -eu\n" + "\n".join(f"printf 'FILE {name}\\n'\ncat /sys/fs/cgroup/{filename}" for name, filename in CGROUP_FILES.items())
        sample = parse_cgroup(self.container.exec(["sh", "-c", script]))
        sample.update(seconds=round(time.monotonic() - self.started, 4), phase=self.phase)
        require(len(self.samples) < MAX_SAMPLES, "cgroup sample bound exceeded")
        self.samples.append(sample)
        return sample

    def start(self):
        def loop():
            while not self.stop_event.wait(0.05):
                try:
                    self.sample()
                except Exception:
                    self.errors.append("cgroup sampler failed")
                    return
        self.thread = threading.Thread(target=loop, name="c239-cgroup-sampler", daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=4)
            require(not self.thread.is_alive(), "cgroup sampler did not join")
        require(not self.errors, "cgroup sampler failed")


# This controller lives inside the owned container, independently of Python.
# PPid, exact title and /proc start time are checked before EVERY SIGCONT.
# Metadata is written before SIGSTOP so finally can recover a lost stdout.
CHILD_FUNCTIONS = r'''
set -eu
umask 077
meta=$1
title_of() { tr '\000' ' ' <"/proc/$1/cmdline" | sed 's/ *$//'; }
start_of() { sed 's/^.*) //' "/proc/$1/stat" | awk '{print $20}'; }
identity() {
    [ -r "/proc/$pid/status" ] || return 1
    [ "$(awk '/^PPid:/{print $2}' "/proc/$pid/status")" = 1 ] || return 1
    actual=$(title_of "$pid")
    case "$actual" in 'redis-aof-rewrite *:6379'|'redis-rdb-to-aof *:6379') ;; *) return 1;; esac
    [ "$actual" = "$title" ] && [ "$(start_of "$pid")" = "$born" ]
}
uptime_now() { cut -d ' ' -f 1 /proc/uptime; }
resume() {
    identity || return 1
    kill -CONT "$pid" || return 1
    printf 'RESUMED\t%s\t%s\n' "$reason" "$(uptime_now)"
}
'''

CAPTURE_CHILD = CHILD_FUNCTIONS + r'''
pid=; born=; title=
begin=$(uptime_now); begin=${begin%.*}
printf 'ARMED\n'
while :; do
    for status in /proc/[0-9]*/status; do
        [ -r "$status" ] || continue
        [ "$(awk '/^PPid:/{print $2}' "$status" 2>/dev/null)" = 1 ] || continue
        candidate=${status#/proc/}; candidate=${candidate%/status}
        candidate_title=$(title_of "$candidate" 2>/dev/null) || continue
        case "$candidate_title" in 'redis-aof-rewrite *:6379'|'redis-rdb-to-aof *:6379') ;; *) continue;; esac
        pid=$candidate; title=$candidate_title; born=$(start_of "$pid")
        identity || exit 4
        printf '%s\n%s\n%s\n' "$pid" "$born" "$title" >"$meta"
        trap 'reason=signal; resume || exit 5; exit 6' TERM INT HUP
        kill -STOP "$pid" || exit 4
        stopped=$(uptime_now)
        printf 'STOPPED\t%s\t%s\t%s\t%s\n' "$pid" "$born" "$stopped" "$title"
        reason=watchdog
        if read -r -t 6 request; then
            if [ "$request" = resume ]; then reason=manual; else reason=bad_request; fi
        fi
        resume || exit 5
        trap - TERM INT HUP
        exit 0
    done
    now=$(uptime_now); now=${now%.*}
    [ "$((now-begin))" -lt 6 ] || exit 3
    sleep 0.005
done
'''

CHECK_CHILD = CHILD_FUNCTIONS + r'''
[ -r "$meta" ] || exit 3
{ read -r pid; read -r born; read -r title; } <"$meta"
identity || exit 4
[ "$(awk '/^State:/{print $2}' "/proc/$pid/status")" = T ] || exit 5
printf 'STOPPED\n'
'''

RESUME_CHILD = CHILD_FUNCTIONS + r'''
[ -r "$meta" ] || exit 0
{ read -r pid; read -r born; read -r title; } <"$meta"
identity || exit 4
reason=finally
resume
'''


class RewriteChild:
    def __init__(self, container: OwnedContainer):
        self.container = container
        self.metadata = "/run/c239-child-" + container.token
        self.process = None
        self.stopped = None
        self.resumed = None

    def start(self):
        self.container.inspect()
        self.process = subprocess.Popen(["docker", "exec", "-i", self.container.identity,
                                         "sh", "-c", CAPTURE_CHILD, "c239-child", self.metadata],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                        bufsize=0)
        require(self._line(3) == b"ARMED\n", "rewrite child observer did not arm")

    def _line(self, seconds: float) -> bytes:
        require(self.process is not None, "rewrite observer was not started")
        deadline = time.monotonic() + seconds
        line = bytearray()
        while not line.endswith(b"\n"):
            left = deadline - time.monotonic()
            require(left > 0 and bool(select.select([self.process.stdout], [], [], left)[0]), "rewrite child capture deadline")
            byte = self.process.stdout.read(1)
            require(bool(byte) and len(line) < 256, "rewrite child capture was inconclusive")
            line.extend(byte)
        return bytes(line)

    def capture(self) -> dict:
        fields = self._line(7).decode("ascii").strip().split("\t")
        require(len(fields) == 5 and fields[0] == "STOPPED" and fields[4] in TITLES,
                "invalid rewrite child identity evidence")
        self.stopped = dict(pid=int(fields[1]), start_ticks=int(fields[2]), uptime=float(fields[3]), title=fields[4])
        require(self.stopped["pid"] > 1 and self.stopped["start_ticks"] > 0, "invalid rewrite child process identity")
        return self.stopped

    def verify_stopped(self):
        self.container.inspect()
        require(self.container.exec(["sh", "-c", CHECK_CHILD, "c239-child", self.metadata]) == b"STOPPED\n",
                "rewrite child did not remain stopped through paused churn")

    def resume(self):
        if self.process is None or self.resumed is not None:
            return
        self.container.inspect()
        try:
            output, _ = self.process.communicate(b"resume\n", timeout=8)
            require(self.process.returncode == 0, "rewrite child controller failed")
            fields = output.decode("ascii").strip().split("\t")
            require(len(fields) == 3 and fields[0] == "RESUMED", "rewrite child resume evidence missing")
            self.resumed = dict(reason=fields[1], uptime=float(fields[2]))
            require(self.stopped is not None, "rewrite child stopped without captured identity")
            self.resumed["stopped_seconds"] = self.resumed["uptime"] - self.stopped["uptime"]
            require(0 <= self.resumed["stopped_seconds"] <= 8, "rewrite child exceeded eight-second stop bound")
            require(self.resumed["reason"] == "manual", "rewrite safety watchdog fired before manual resume")
        except BaseException:
            # Closing the controller input wakes its independent EOF/watchdog
            # path. The exact-identity fallback handles lost controller output.
            if self.process.poll() is None:
                self.process.kill()
                self.process.wait(timeout=2)
            raise

    def cleanup(self):
        if self.process is None:
            return
        primary = None
        try:
            self.resume()
        except Exception as error:
            primary = error
        if self.resumed is None:
            try:
                self.container.inspect()
                self.container.exec(["sh", "-c", RESUME_CHILD, "c239-child", self.metadata])
            except Exception as error:
                if primary is not None:
                    raise GateError("rewrite controller failed and exact-identity finally resume also failed") from primary
                raise GateError("exact-identity finally resume failed") from error
        if primary is not None:
            raise primary


class Workload:
    def __init__(self, connection: RedisConnection, check):
        self.connection = connection
        self.check = check
        self.wire_bytes = 0
        self.payload_bytes = 0
        self.acknowledged = 0
        self.refused = 0
        self.oom_refused = 0

    def write(self, keys: list[str], value: bytes, overwrite: bool) -> bool:
        self.check()
        commands = [("SETRANGE", key, 0, value) if overwrite else ("SET", key, value) for key in keys]
        encoded = encode_commands(commands)
        if self.wire_bytes + len(encoded) > MAX_INPUT_BYTES:
            return False
        self.wire_bytes += len(encoded)
        self.payload_bytes += len(keys) * len(value)
        replies = self.connection.batch(commands)
        for reply in replies:
            if isinstance(reply, RedisRefusal):
                self.refused += 1
                self.oom_refused += int(reply.code == "OOM")
            else:
                require(reply == (len(value) if overwrite else b"OK"), "unexpected Redis write acknowledgement")
                self.acknowledged += 1
        require(self.refused == 0, "Redis refused a bounded workload write")
        return True

    def churn(self, keys: list[str], value: bytes, deadline: float, max_passes: int | None) -> int:
        accepted = 0
        passes = 0
        while max_passes is None or passes < max_passes:
            for offset in range(0, len(keys), 32):
                if time.monotonic() >= deadline:
                    return accepted
                batch = keys[offset:offset + 32]
                if not self.write(batch, value, True):
                    return accepted
                accepted += len(batch)
            passes += 1
        return accepted


def validate_success(final: dict, initial: dict, samples: list[dict], raw_payload: int,
                     paused_acks: int, key_count: int, refused: int) -> None:
    require(paused_acks >= key_count and key_count > 0, "paused churn did not cover one complete filled dataset")
    require(refused == 0, "Redis workload had refusals")
    require(final["aof_last_cow_size"] * 4 >= raw_payload * 3,
            "actual AOF CoW was below75% of filled raw payload; overlap was not demonstrated")
    require(final["aof_rewrite_in_progress"] == 0 and final["aof_rewrites"] == 1,
            "exactly one requested AOF rewrite did not complete")
    require(final["evicted_keys"] == 0 and final["rejected_connections"] == 0 and final["total_error_replies"] == 0,
            "Redis reported eviction, connection refusal or error replies")
    for sample in [initial, *samples]:
        require(sample["swap_current"] == 0, "container used swap")
        require(all(sample["events"].get(name, -1) == 0 for name in ("oom", "oom_kill", "oom_group_kill")),
                "cgroup reported OOM activity")
        require(sample["pids_events"].get("max", -1) == 0, "cgroup refused process admission")


def image_evidence(reference: str) -> dict:
    template = ('{"id":{{json .Id}},"layers":{{json .RootFS.Layers}},"os":{{json .Os}},'
                '"architecture":{{json .Architecture}},"entrypoint":{{json .Config.Entrypoint}}}')
    return json.loads(run_command(["docker", "image", "inspect", "--format", template, reference]))


def finalize_result(result: dict, validated: bool, total_seconds: float) -> None:
    result["total_seconds_including_cleanup"] = total_seconds
    if total_seconds > TRIAL_SECONDS:
        result["errors"].append({
            "stage": "whole_trial_deadline",
            "error": "trial including cleanup exceeded180s",
        })
    result["passed"] = validated and not result["errors"] and result.get("cleaned_owned_container", False)


def run_gate(image_reference: str, output: Path) -> int:
    token = uuid.uuid4().hex
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    artifacts = output.resolve() / token
    artifacts.mkdir(mode=0o700)
    result = {
        "schema_version": 1, "task": "M6-C239", "token": token,
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "passed": False, "errors": [], "phases": {},
        "protocol": {
            "maxmemory_bytes": EXPECTED_MAXMEMORY, "container_memory_bytes": MEMORY_LIMIT,
            "swap_bytes": 0, "cpu_count": 1, "pids_limit": 64,
            "value_bytes": VALUE_BYTES, "value_seeds": [239, 240], "fill_headroom_bytes": 4 * MIB,
            "max_keys": MAX_KEYS, "fill_seconds": 90, "max_write_wire_bytes": MAX_INPUT_BYTES,
            "paused_churn_max_passes": 2, "paused_churn_seconds": 5,
            "child_watchdog_seconds": 6, "child_stop_max_seconds": 8,
            "resumed_observation_seconds": 15, "rewrite_seconds": REWRITE_SECONDS,
            "trial_seconds": TRIAL_SECONDS, "minimum_aof_cow_percent_of_raw_payload": 75,
        },
        "interpretation": (
            "Bounded local workload evidence only. memory.peak includes reclaimable AOF file cache, "
            "kernel memory and observer processes; it is not Redis RSS or unallocated application headroom. "
            "Report anon/file/cache-reclaim counters alongside peak. Only automatic AOF rewrite scheduling "
            "is disabled; durability, noeviction and shipped96MiB maxmemory remain unchanged. "
            "Resumed writes stop at the1GiB wire-input ceiling; observation continues for15s."
        ),
    }
    started = time.monotonic()
    container = OwnedContainer(token)
    sampler = Sampler(container, started)
    connection = None
    child = RewriteChild(container)
    workload = None
    validated = False
    initial = None
    phase = "preflight"

    def failure(stage: str, error: BaseException):
        message = str(error) if isinstance(error, GateError) else type(error).__name__
        result["errors"].append({"stage": stage, "error": message[:300]})

    def check():
        require(time.monotonic() - started < TRIAL_SECONDS, "trial180s deadline")
        require(not sampler.errors, "cgroup sampler failed")

    def interrupted(signum, _frame):
        raise GateError("trial interrupted by signal" + str(signum))

    previous = {number: signal.signal(number, interrupted) for number in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM)}
    signal.setitimer(signal.ITIMER_REAL, TRIAL_SECONDS)
    try:
        require(platform.system() == "Linux", "gate requires Linux Docker cgroupv2")
        base_reference = pinned_base(DOCKERFILE.read_text())
        base = image_evidence(base_reference)
        image = image_evidence(image_reference)
        verify_layers(image, base)
        source_hash = hashlib.sha256(ENTRYPOINT.read_bytes()).hexdigest()
        result["provenance"] = {
            "image_id": image["id"], "base_reference": base_reference, "base_id": base["id"],
            "base_layers": base["layers"], "image_layers": image["layers"],
            "source_entrypoint_sha256": source_hash,
            "source_dockerfile_sha256": hashlib.sha256(DOCKERFILE.read_bytes()).hexdigest(),
        }
        with tempfile.TemporaryDirectory(prefix="agentuplink-c239-keys-") as keys_dir:
            keys_path = Path(keys_dir).resolve()
            require(not artifacts.is_relative_to(keys_path), "artifacts must be outside temporary key storage")
            certificate, private_key, environment = (keys_path / name for name in ("cert.pem", "key.pem", "redis.env"))
            run_command(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                         "-nodes", "-days", "1", "-subj", "/CN=localhost", "-addext",
                         "subjectAltName=DNS:localhost,IP:127.0.0.1", "-keyout", str(private_key), "-out", str(certificate)])
            private_key.chmod(0o600)
            password = uuid.uuid4().hex + uuid.uuid4().hex
            environment.write_text(
                "REDIS_TLS_CERT_CHAIN_B64=" + base64.b64encode(certificate.read_bytes()).decode() + "\n"
                "REDIS_TLS_KEY_B64=" + base64.b64encode(private_key.read_bytes()).decode() + "\n"
                "REDIS_PASSWORD=" + password + "\n")
            environment.chmod(0o600)
            phase = sampler.phase = "startup"
            # Mark before dispatch: an ambiguous docker-run result still
            # reaches cleanup, guarded by the unique name+owner label.
            container.created = True
            identity = run_command(["docker", "run", "--detach", "--name", container.name,
                                    "--label", LABEL + "=" + token, "--memory", "256m", "--memory-swap", "256m",
                                    "--cpus", "1", "--pids-limit", "64", "--ulimit", "nofile=1024:1024",
                                    "--publish", "127.0.0.1::6379/tcp", "--env-file", str(environment), image["id"]], 10).decode().strip()
            require(re.fullmatch(r"[0-9a-f]{64}", identity) is not None, "Docker did not return an immutable container ID")
            container.identity = identity
            info = container.inspect()
            result["container_initial"] = info
            port = verify_container_limits(info, image["id"])
            actual_hash = container.exec(["sha256sum", "/usr/local/bin/agentuplink-redis-entrypoint"]).decode().split()[0]
            require(actual_hash == source_hash, "image entrypoint bytes differ from shipped source")
            startup_deadline = time.monotonic() + 10
            while connection is None and time.monotonic() < startup_deadline:
                check()
                try:
                    connection = RedisConnection(port, certificate, password)
                except (ConnectionError, OSError):
                    time.sleep(0.05)
            require(connection is not None, "verified Redis TLS startup deadline")
            result["tls_version"] = connection.socket.version()
            require(connection.info("server").get("redis_version") == "8.4.0", "image Redis version differs from8.4.0")
            for setting, expected in REQUIRED_CONFIG.items():
                reply = connection.command("CONFIG", "GET", setting)
                require(reply == [setting.encode(), expected.encode()], "shipped Redis durability/listener/memory setting mismatch")
            require(connection.command("CONFIG", "SET", "auto-aof-rewrite-percentage", 0) == b"OK", "cannot disable automatic AOF rewrite schedule")
            require(connection.command("CONFIG", "GET", "auto-aof-rewrite-percentage") == [b"auto-aof-rewrite-percentage", b"0"], "automatic AOF rewrite schedule was not disabled")
            result["phases"]["configuration"] = dict(REQUIRED_CONFIG, **{"auto-aof-rewrite-percentage": "0"})
            initial = sampler.sample()
            result["cgroup_initial"] = initial
            sampler.start()
            workload = Workload(connection, check)
            require(connection.command("SET", "c239-canary", b"unchanged-authority-canary") == b"OK", "initial canary write failed")

            phase = sampler.phase = "fill"
            fill_started = time.monotonic()
            keys = []
            value = random.Random(239).randbytes(VALUE_BYTES)
            changed = random.Random(240).randbytes(VALUE_BYTES)
            require(value != changed, "workload seeds did not produce distinct values")
            while int(connection.info("memory")["used_memory"]) < EXPECTED_MAXMEMORY - 4 * MIB:
                check()
                require(time.monotonic() - fill_started < 90, "fill90s deadline")
                require(len(keys) + 32 <= MAX_KEYS, "fill key bound")
                batch = [f"c239:{index:05d}" for index in range(len(keys), len(keys) + 32)]
                require(workload.write(batch, value, False), "fill exhausted total input ceiling")
                keys.extend(batch)
            raw_payload = len(keys) * VALUE_BYTES
            persistence = numeric_info(connection.info("persistence"), ("aof_rewrites", "aof_rewrite_in_progress", "rdb_bgsave_in_progress"))
            require(all(value == 0 for value in persistence.values()), "another persistence child preceded explicit AOF rewrite")
            result["phases"]["filled"] = {
                "keys": len(keys), "raw_payload_bytes": raw_payload,
                "memory": numeric_info(connection.info("memory"), ("used_memory", "used_memory_rss", "maxmemory")),
                "cgroup": sampler.sample(), "seconds": time.monotonic() - fill_started,
            }

            phase = sampler.phase = "rewrite_child_capture"
            child.start()
            rewrite_started = time.monotonic()
            require(connection.command("BGREWRITEAOF") == b"Background append only file rewriting started", "explicit AOF rewrite was not started")
            result["phases"]["stopped_child"] = child.capture()
            child.verify_stopped()
            phase = sampler.phase = "paused_rewrite_churn"
            pause_started = time.monotonic()
            paused_acks = workload.churn(keys, changed, pause_started + 5, 2)
            require(paused_acks >= len(keys), "paused churn did not complete one full dataset pass")
            child.verify_stopped()
            child.resume()
            result["phases"]["paused_churn"] = {
                "acknowledged": paused_acks, "passes": paused_acks / len(keys),
                "seconds": time.monotonic() - pause_started, "resume": child.resumed,
            }

            phase = sampler.phase = "resumed_rewrite_churn"
            resumed_started = time.monotonic()
            resumed_end = resumed_started + 15
            resumed_acks = workload.churn(keys, value, resumed_end, None)
            write_seconds = time.monotonic() - resumed_started
            while time.monotonic() < resumed_end:
                check()
                time.sleep(min(0.05, resumed_end - time.monotonic()))
            result["phases"]["resumed_churn"] = {
                "acknowledged": resumed_acks, "write_seconds": write_seconds,
                "observation_seconds": time.monotonic() - resumed_started,
                "input_ceiling_reached": workload.wire_bytes + 32 * VALUE_BYTES >= MAX_INPUT_BYTES,
            }
            phase = sampler.phase = "rewrite_completion"
            while True:
                check()
                require(time.monotonic() - rewrite_started < REWRITE_SECONDS, "rewrite45s deadline")
                persistence_raw = connection.info("persistence")
                if persistence_raw.get("aof_rewrite_in_progress") == "0":
                    break
                time.sleep(0.1)
            require(persistence_raw.get("aof_last_bgrewrite_status") == "ok" and persistence_raw.get("aof_last_write_status") == "ok", "Redis AOF rewrite/write did not succeed")
            final = numeric_info(persistence_raw, ("aof_last_cow_size", "aof_rewrite_in_progress", "aof_rewrites", "aof_current_size"))
            final.update(numeric_info(connection.info("stats"), ("evicted_keys", "rejected_connections", "total_error_replies")))
            require(connection.command("DBSIZE") == len(keys) + 1, "workload key count changed")
            require(connection.command("GET", "c239-canary") == b"unchanged-authority-canary", "authority canary changed")
            # Re-check all invariant settings; maxmemory was never overridden.
            for setting, expected in REQUIRED_CONFIG.items():
                require(connection.command("CONFIG", "GET", setting) == [setting.encode(), expected.encode()], "Redis profile changed during the trial")
            result["phases"]["final"] = dict(final, memory=numeric_info(connection.info("memory"), ("used_memory", "used_memory_rss", "maxmemory")), cgroup=sampler.sample())
            validate_success(final, initial, sampler.samples, raw_payload, paused_acks, len(keys), workload.refused)
            validated = True
    except BaseException as error:
        failure(phase, error)
    finally:
        result["trial_seconds"] = time.monotonic() - started
        signal.setitimer(signal.ITIMER_REAL, 0)
        # Finish bounded cleanup even if an operator sends a second interrupt.
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        phase = sampler.phase = "cleanup"
        for label, action in (("rewrite_resume", child.cleanup), ("sampler_join", sampler.stop)):
            try:
                action()
            except BaseException as error:
                failure(label, error)
        if connection:
            try:
                connection.close()
            except BaseException as error:
                failure("Redis_connection_cleanup", error)
        if container.created:
            try:
                info = container.inspect()
                result["container_final"] = info
                require(not info["oom_killed"] and info["running"], "owned Redis exited or was OOM-killed")
                result["cgroup_final"] = sampler.sample()
            except BaseException as error:
                failure("final_container_evidence", error)
            try:
                container.inspect()
                logs = run_command(["docker", "logs", "--tail", "512", container.identity or container.name])
                (artifacts / "redis.log").write_bytes(logs)
            except BaseException as error:
                failure("Redis_log_capture", error)
            try:
                container.remove()
                result["cleaned_owned_container"] = True
            except BaseException as error:
                failure("owned_container_cleanup", error)
        if workload:
            result["writes"] = {
                "acknowledged": workload.acknowledged, "refused": workload.refused,
                "oom_refused": workload.oom_refused, "wire_input_bytes": workload.wire_bytes,
                "raw_payload_input_bytes": workload.payload_bytes,
            }
        if sampler.samples:
            result["memory_summary"] = {
                "cgroup_peak_bytes": max(sample["peak"] for sample in sampler.samples),
                "max_sampled_anon_bytes": max(sample["stat"].get("anon", 0) for sample in sampler.samples),
                "max_sampled_file_bytes": max(sample["stat"].get("file", 0) for sample in sampler.samples),
                "sample_count": len(sampler.samples),
                "note": "Separate maxima need not coincide; file-cache reclaim can produce a peak at the cgroup limit without OOM.",
            }
            for sample in sampler.samples:
                if any(sample["events"].get(name, -1) != 0 for name in ("oom", "oom_kill", "oom_group_kill")):
                    failure("cgroup_OOM_evidence", GateError("cgroup reported OOM activity"))
                    break
        try:
            (artifacts / "samples.json").write_text(json.dumps(sampler.samples, indent=2) + "\n")
        except OSError as error:
            failure("sample_evidence_write", error)
        # Include cleanup and the largest evidence write in the declared
        # whole-trial bound; a late cleanup can never turn green afterward.
        finalize_result(result, validated, time.monotonic() - started)
        try:
            (artifacts / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        except OSError:
            result["passed"] = False
            print("C239 failed: cannot retain result and sample evidence", flush=True)
        for number, handler in previous.items():
            signal.signal(number, handler)
    print(json.dumps({"passed": result["passed"], "result": str(artifacts / "result.json"),
                      "errors": result["errors"], "seconds": result["total_seconds_including_cleanup"]}), flush=True)
    return 0 if result["passed"] else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="already-built shipped Redis image; no build/pull occurs")
    parser.add_argument("--output", required=True, type=Path, help="retained evidence directory, outside ephemeral keys")
    arguments = parser.parse_args()
    return run_gate(arguments.image, arguments.output)


if __name__ == "__main__":
    raise SystemExit(main())
