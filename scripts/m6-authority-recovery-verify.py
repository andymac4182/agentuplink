#!/usr/bin/env python3
"""M6-C243: owned, bounded local three-relay operator recovery acceptance.

No shared Redis is accepted. The Rust drill performs actual RDB capture/restore
and all approval assertions; this wrapper owns both immutable container IDs and
always attempts guarded cleanup. Artifacts contain identifiers/hashes and bounded
diagnostics, never the private fixture, raw RDB, ACL or signed approval contents.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import subprocess
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parent.parent
REDIS_IMAGE = "redis:8.4.0-alpine@sha256:6cbef353e480a8a6e7f10ec545f13d7d3fa85a212cdcc5ffaf5a1c818b9d3798"
LABEL = "agentuplink.authority-recovery-owner"
TEST = "recovery::online_authority_three_relay_cli_recovery_preserves_reconciled_revocations"
MEMORY = 256 * 1024 * 1024
MAX_LOG = 32 * 1024 * 1024
INSPECT_FORMAT = (
    '{{json .Id}}\n{{json .Name}}\n{{json .Config.Labels}}\n'
    '{{json .Image}}\n{{json .HostConfig.PortBindings}}\n'
    '{{json .HostConfig.Memory}}\n{{json .HostConfig.MemorySwap}}\n'
    '{{json .HostConfig.NanoCpus}}\n{{json .HostConfig.PidsLimit}}\n'
    '{{json .State.Running}}\n{{json .State.Pid}}'
)


class GateError(RuntimeError):
    pass


def validate_inspection(raw: bytes, container: dict, owner: str, image: str, port: int) -> dict:
    """Fail closed before stop/copy/remove, including a same-name replacement."""
    if (not re.fullmatch(r"[0-9a-f]{32}", owner)
            or not re.fullmatch(r"[0-9a-f]{64}", container["id"])
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", image)
            or not 0 < port <= 65535 or port == 16379
            or container["role"] not in ("old", "candidate")):
        raise GateError("invalid owned container identity")
    fields = [json.loads(line) for line in raw.decode("utf-8").splitlines()]
    if len(fields) != 11:
        raise GateError("owned container inspection shape")
    cid, name, labels, actual_image, bindings, memory, swap, cpus, pids, running, pid = fields
    expected_name = f"agentuplink-authority-recovery-{owner}-{container['role']}"
    if (cid != container["id"] or name != f"/{expected_name}"
            or not isinstance(labels, dict) or labels.get(LABEL) != owner
            or actual_image != image
            or bindings != {"6379/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(port)}]}
            or (memory, swap, cpus, pids) != (MEMORY, MEMORY, 1_000_000_000, 64)
            or type(running) is not bool or type(pid) is not int):
        raise GateError("container owner/ID/image/endpoint/resource boundary changed")
    return {"id": cid, "running": running, "pid": pid}


def overridden_binaries(environment: dict) -> dict | None:
    names = {
        "harness": "TUNNEL_C22_RECOVERY_HARNESS_BIN",
        "authority": "TUNNEL_AUTHORITY_BIN",
        "relay": "TUNNEL_RELAY_BIN",
    }
    supplied = {key: environment.get(name) for key, name in names.items()}
    if not any(supplied.values()):
        return None
    if not all(supplied.values()):
        raise GateError("artifact mode requires all three explicit binary paths; no implicit build/fallback")
    result = {}
    for key, value in supplied.items():
        path = Path(value).resolve(strict=True)
        if not path.is_file() or not os.access(path, os.X_OK):
            raise GateError(f"{key} override is not an executable file")
        result[key] = path
    return result


class Runner:
    def __init__(self, output: Path):
        self.output = output
        self.sequence = 0

    def run(self, command: list[str], *, timeout: float = 20, env: dict | None = None,
            check: bool = True, label: str = "command") -> tuple[int, bytes]:
        self.sequence += 1
        logfile = self.output / f"{self.sequence:03d}-{label}.log"
        started = time.monotonic()
        captured = bytearray()
        child = subprocess.Popen(command, cwd=ROOT, env=env, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, start_new_session=True)
        try:
            with selectors.DefaultSelector() as selector, logfile.open("xb") as log:
                selector.register(child.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    if time.monotonic() - started > timeout:
                        raise GateError(f"{label} exceeded {timeout}s deadline; log retained")
                    for key, _ in selector.select(timeout=0.1):
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        if len(captured) + len(chunk) > MAX_LOG:
                            raise GateError(f"{label} exceeded retained output bound")
                        captured.extend(chunk)
                        log.write(chunk)
                code = child.wait(timeout=max(0.1, timeout - (time.monotonic() - started)))
        finally:
            # A dead harness can leave relay/authority descendants holding its
            # output pipe. Always signal this newly created group, including
            # when the direct child has already exited.
            previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT})
            try:
                try:
                    os.killpg(child.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                if child.poll() is None:
                    try:
                        child.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        os.killpg(child.pid, signal.SIGKILL)
                        child.wait(timeout=3)
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                if child.stdout:
                    child.stdout.close()
            finally:
                # Deliver any queued cancellation only after owned descendants
                # and pipes have received their bounded cleanup.
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        if check and code:
            raise GateError(f"{label} exited {code}; bounded output retained in {logfile.name}")
        return code, bytes(captured)

    def inspect(self, container: dict, owner: str, image: str, port: int) -> dict:
        _, raw = self.run(["docker", "inspect", "--type", "container", "--format",
                           INSPECT_FORMAT, container["id"]], label="owned-inspect")
        return validate_inspection(raw, container, owner, image, port)


def build(runner: Runner) -> dict:
    runner.run(["cargo", "build", "--locked", "-p", "tunnel-authority", "-p", "tunnel-relay", "--bins"],
               timeout=900, label="build-shipped-binaries")
    _, raw = runner.run(["cargo", "test", "--locked", "-p", "tunnel-test-harness", "--test",
                         "m6_online_authority", "--no-run", "--message-format=json"],
                        timeout=900, label="build-recovery-harness")
    executables = []
    for line in raw.splitlines():
        try:
            message = json.loads(line)
        except (ValueError, UnicodeDecodeError):
            continue
        if (message.get("reason") == "compiler-artifact"
                and message.get("target", {}).get("name") == "m6_online_authority"
                and message.get("profile", {}).get("test") and message.get("executable")):
            executables.append(Path(message["executable"]).resolve(strict=True))
    if len(executables) != 1:
        raise GateError("Cargo did not identify exactly one recovery test executable")
    harness = executables[0]
    directory = harness.parent.parent if harness.parent.name == "deps" else harness.parent
    return {"harness": harness, "authority": directory / "tunnel-authority", "relay": directory / "tunnel-relay"}


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    if port == 16379:
        raise GateError("reserved shared Redis port was selected")
    return port


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def create(runner: Runner, owner: str, role: str, image: str, port: int, registry: list) -> dict:
    name = f"agentuplink-authority-recovery-{owner}-{role}"
    # Register the unique intended name before an ambiguous Docker create.
    # Cleanup may pin a late-created ID only after all independent labels,
    # image, endpoint and resource settings validate; never remove by name.
    container = {"id": None, "role": role}
    registry.append(container)
    _, raw = runner.run([
        "docker", "create", "--name", name, "--label", f"{LABEL}={owner}",
        "--publish", f"127.0.0.1:{port}:6379/tcp", "--memory", str(MEMORY),
        "--memory-swap", str(MEMORY), "--cpus", "1", "--pids-limit", "64",
        "--ulimit", "nofile=1024:1024", image,
        "sh", "-c", 'if [ ! -e /data/users.acl ]; then printf "user default on nopass ~* &* +@all\\n" > /data/users.acl; fi; exec redis-server "$@"',
        "sh", "--aclfile", "/data/users.acl", "--appendonly", "yes" if role == "old" else "no",
        "--appendfsync", "always", "--aof-load-truncated", "no", "--save", "",
        "--maxmemory", "96mb", "--maxmemory-policy", "noeviction", "--protected-mode", "no",
        "--bind", "0.0.0.0",
    ], label=f"create-{role}")
    cid = raw.decode("ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{64}", cid):
        raise GateError("Docker create did not return an immutable container ID")
    container["id"] = cid
    return container


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="new private evidence directory (never overwritten)")
    args = parser.parse_args()
    if args.output:
        args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
        output = args.output.resolve(strict=True)
    else:
        output = Path(tempfile.mkdtemp(prefix="agentuplink-c243-")).resolve()
    os.chmod(output, 0o700)
    runner = Runner(output)
    owner = uuid.uuid4().hex
    containers = []
    image = ""
    port = 0
    result = {"owner": owner, "status": "failed", "scope": "local synthetic three-relay recovery; device uses production library", "cleanup": []}
    def interrupted(signum, _frame):
        raise GateError(f"interrupted by signal {signum}; owned cleanup required")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    started = time.monotonic()
    print(f"C243 evidence: {output}", flush=True)
    try:
        if os.name != "posix" or not hasattr(signal, "pthread_sigmask"):
            raise GateError("this Unix authority process drill requires POSIX signal cleanup")
        binaries = overridden_binaries(os.environ) or build(runner)
        result["binaries"] = {
            role: {"path": str(path), "sha256": file_hash(path)}
            for role, path in binaries.items()
        }
        _, revision = runner.run(["git", "rev-parse", "HEAD"], label="checkout-revision")
        result["checkout_head"] = revision.decode("ascii").strip()
        source_files = [
            "crates/tunnel-test-harness/tests/m6_online_authority.rs",
            "crates/tunnel-test-harness/tests/m6_online_authority/recovery.rs",
            "crates/tunnel-test-harness/tests/common/authority_publication_observer.rs",
            "crates/tunnel-test-harness/tests/common/authority_canary_diagnostics.rs",
            "crates/tunnel-test-harness/tests/common/recovery_fixture_snapshot.rs",
            "scripts/m6-authority-recovery-verify.py",
        ]
        result["source_inputs_sha256"] = {name: file_hash(ROOT / name) for name in source_files}
        code, _ = runner.run(["docker", "image", "inspect", "--format", "{{.Id}}", REDIS_IMAGE], check=False, label="pinned-image-present")
        if code:
            runner.run(["docker", "pull", REDIS_IMAGE], timeout=180, label="pull-pinned-redis")
        _, raw = runner.run(["docker", "image", "inspect", "--format", "{{.Id}}", REDIS_IMAGE], label="pinned-image-identity")
        image = raw.decode("ascii").strip()
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
            raise GateError("pinned image identity is malformed")
        result["redis_image"] = {"reference": REDIS_IMAGE, "id": image}
        # Port collisions are setup failures with retained evidence. There is
        # no scenario retry that could hide a failed recovery attempt.
        port = free_port()
        result["port"] = port
        for role in ("old", "candidate"):
            container = create(runner, owner, role, image, port, containers)
            runner.inspect(container, owner, image, port)
        result["containers"] = containers
        runner.inspect(containers[0], owner, image, port)
        runner.run(["docker", "start", containers[0]["id"]], label="start-old")
        deadline = time.monotonic() + 20
        while True:
            runner.inspect(containers[0], owner, image, port)
            code, reply = runner.run(["docker", "exec", containers[0]["id"], "redis-cli", "PING"], check=False, label="old-ready")
            if code == 0 and reply.strip() == b"PONG":
                break
            if time.monotonic() >= deadline:
                raise GateError("old Redis startup deadline")
            time.sleep(0.1)
        environment = dict(os.environ)
        process_logs = output / "private-process-captures"
        process_logs.mkdir(mode=0o700)
        environment.update({
            "TEST_REDIS_URL": f"redis://127.0.0.1:{port}/0",
            "TUNNEL_CATALOG_REDIS_URL": f"redis://127.0.0.1:{port}/0",
            "TUNNEL_C22_REDIS_OWNER": owner, "TUNNEL_C22_REDIS_IMAGE_ID": image,
            "TUNNEL_C22_REDIS_OLD_ID": containers[0]["id"],
            "TUNNEL_C22_REDIS_CANDIDATE_ID": containers[1]["id"],
            "TUNNEL_AUTHORITY_BIN": str(binaries["authority"]),
            "TUNNEL_RELAY_BIN": str(binaries["relay"]), "RUST_LOG": "info",
            "TUNNEL_HARNESS_PROCESS_LOG_DIR": str(process_logs),
        })
        code, log = runner.run([str(binaries["harness"]), TEST, "--ignored", "--exact", "--test-threads=1", "--nocapture"],
                               env=environment, timeout=420, check=False, label="actual-recovery-drill")
        if (code or b"test result: ok. 1 passed; 0 failed; 0 ignored;" not in log
                or b"c243 phase=PASS three_relays=3" not in log):
            raise GateError(f"actual recovery drill failed or did not execute exactly one required case (exit {code})")
        result["status"] = "passed"
    except (GateError, OSError, ValueError, subprocess.SubprocessError) as error:
        result["error"] = str(error)
    finally:
        # Complete bounded cleanup even if another cancellation signal arrives.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        for container in reversed(containers):
            try:
                if container["id"] is None:
                    name = f"agentuplink-authority-recovery-{owner}-{container['role']}"
                    code, raw = runner.run(["docker", "inspect", "--type", "container", "--format",
                                            INSPECT_FORMAT, name], check=False, label="resolve-ambiguous-create")
                    if code:
                        # Distinguish absent owned name from an unavailable
                        # daemon: the latter must remain a cleanup failure.
                        if f"No such container: {name}" not in raw.decode("utf-8", errors="replace"):
                            raise GateError("cannot resolve ambiguous owned container creation")
                        result["cleanup"].append({"role": container["role"], "never_created": True})
                        continue
                    container["id"] = json.loads(raw.decode("utf-8").splitlines()[0])
                    validate_inspection(raw, container, owner, image, port)
                runner.inspect(container, owner, image, port)
                runner.run(["docker", "logs", "--tail", "200", container["id"]], check=False, label=f"redis-{container['role']}-logs")
                # Recheck after log capture immediately before the only remove.
                runner.inspect(container, owner, image, port)
                runner.run(["docker", "rm", "--force", "--volumes", container["id"]], label="remove-owned")
                code, missing = runner.run(["docker", "inspect", "--type", "container", "--format", "{{.Id}}", container["id"]], check=False, label="confirm-removed")
                if code == 0 or f"No such container: {container['id']}" not in missing.decode("utf-8", errors="replace"):
                    raise GateError("owned container deletion was not proved by an exact absent-ID response")
                result["cleanup"].append({"id": container["id"], "removed": True})
            except (GateError, OSError, ValueError, subprocess.SubprocessError) as error:
                result["status"] = "failed"
                result["cleanup"].append({"id": container["id"], "removed": False, "error": str(error)})
        result["elapsed_seconds"] = round(time.monotonic() - started, 3)
        (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"C243 {result['status']}; retained evidence: {output}", flush=True)
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
