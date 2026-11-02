#!/usr/bin/env python3
"""Pure/mock and temporary-file controls; no Docker, service or native execution."""

import copy
from contextlib import nullcontext, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("rehearsal", Path(__file__).with_name("fly_cluster_rehearsal.py"))
rehearsal = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rehearsal)


def state():
    return {"device_id": "device", "sessions": 1,
            "rotation_policy": {"interval_seconds": 300, "handshake_timeout_seconds": 10, "overlap_seconds": 30},
            "session": {"phase": "active", "session_id": "session", "epoch": 7, "active_generation": 1,
                        "candidate_generation": None, "rotations_completed": 0, "recovery_attempt": None,
                        "recovery_attempt_deadline_ms": None, "recovery_episode_deadline_ms": None}}


def owned():
    expected = {"id": "a" * 64, "name": "owner-relay", "image": "sha256:" + "b" * 64, "role": "relay-a",
                "mounts": [("owned-volume", "/state", True)], "network": "network", "memory": 512 * 1024**2}
    observed = {"Id": expected["id"], "Name": "/" + expected["name"], "Image": expected["image"],
                "Config": {"Labels": {rehearsal.OWNER_LABEL: "owner", rehearsal.OWNER_LABEL + ".role": "relay-a"}},
                "Mounts": [{"Name": "owned-volume", "Destination": "/state", "RW": True}],
                "HostConfig": {"NetworkMode": "network", "Memory": 512 * 1024**2, "MemorySwap": 512 * 1024**2,
                               "PidsLimit": 256, "RestartPolicy": {"Name": "no"}},
                "State": {"Running": True, "ExitCode": 0, "OOMKilled": False}}
    return expected, observed


class Validation(unittest.TestCase):
    def refused(self, code, fn, *args):
        with self.assertRaisesRegex(rehearsal.Refused, "^" + code + "$"):
            fn(*args)

    def test_local_selector_preserves_proxy_config_ca(self):
        supplied = {"DOCKER_HOST": "remote", "DOCKER_CONTEXT": "remote", "DOCKER_TLS": "1", "DOCKER_TLS_VERIFY": "1",
                    "DOCKER_CERT_PATH": "/remote", "DOCKER_CONFIG": "/keep", "HTTPS_PROXY": "proxy", "CARGO_HTTP_CAINFO": "/ca"}
        with mock.patch.dict(os.environ, supplied, clear=True):
            self.assertEqual(rehearsal.safe_environment(), {"DOCKER_CONFIG": "/keep", "HTTPS_PROXY": "proxy", "CARGO_HTTP_CAINFO": "/ca"})

    def test_image_requires_exact_id_revision_and_default_user(self):
        identity = "sha256:" + "b" * 64
        observed = {"Id": identity, "Config": {"User": "authority:authority", "Labels": {"org.opencontainers.image.revision": "c" * 40}}}
        self.assertEqual(rehearsal.check_image(observed, identity, "c" * 40)["id"], identity)
        self.refused("image_id_changed", rehearsal.check_image, observed, "sha256:" + "d" * 64, "c" * 40)
        self.refused("image_revision", rehearsal.check_image, observed, identity, "d" * 40)
        observed["Config"]["User"] = ""
        self.refused("image_default_user_missing", rehearsal.check_image, observed, identity, "c" * 40)

    def test_container_exact_identity_accepts_owned_only(self):
        expected, observed = owned()
        self.assertEqual(rehearsal.check_container(observed, expected, "owner"), observed["State"])
        for key in ("Id", "Name", "Image"):
            changed = copy.deepcopy(observed)
            changed[key] = "foreign"
            with self.subTest(key=key), self.assertRaises(rehearsal.Refused):
                rehearsal.check_container(changed, expected, "owner")
        for key in (rehearsal.OWNER_LABEL, rehearsal.OWNER_LABEL + ".role"):
            changed = copy.deepcopy(observed)
            changed["Config"]["Labels"][key] = "foreign"
            with self.subTest(key=key), self.assertRaises(rehearsal.Refused):
                rehearsal.check_container(changed, expected, "owner")

    def test_container_extra_mount_or_changed_network_refused(self):
        expected, observed = owned()
        for change in (lambda x: x["Mounts"].append({"Name": "foreign", "Destination": "/foreign", "RW": True}),
                       lambda x: x["HostConfig"].update(NetworkMode="host")):
            changed = copy.deepcopy(observed)
            change(changed)
            with self.assertRaises(rehearsal.Refused):
                rehearsal.check_container(changed, expected, "owner")

    def test_container_unbounded_memory_swap_pids_restart_refused(self):
        expected, observed = owned()
        for key, value in (("Memory", 0), ("MemorySwap", -1), ("MemorySwap", 1024**3), ("PidsLimit", 0), ("RestartPolicy", {"Name": "always"})):
            changed = copy.deepcopy(observed)
            changed["HostConfig"][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(rehearsal.Refused):
                rehearsal.check_container(changed, expected, "owner")

    def test_resource_floors_and_all_swap_oom_deltas(self):
        initial = {"memory_available": 5 * 1024**3, "temporary_free": 2 * 1024**3, "workspace_free": 2 * 1024**3,
                   "pswpin": 8, "pswpout": 9, "oom_kill": 10, "cgroup_swap": 0}
        rehearsal.check_resources(initial, initial, startup=True)
        for key, value in (("memory_available", 3 * 1024**3 - 1), ("temporary_free", 1536 * 1024**2 - 1),
                           ("workspace_free", 1536 * 1024**2 - 1), ("pswpin", 9), ("pswpout", 10),
                           ("oom_kill", 11), ("cgroup_swap", 1)):
            changed = {**initial, key: value}
            with self.subTest(key=key), self.assertRaises(rehearsal.Refused):
                rehearsal.check_resources(changed, initial)
        with self.assertRaises(rehearsal.Refused):
            rehearsal.check_resources({**initial, "memory_available": 4 * 1024**3 - 1}, initial, startup=True)

    def test_actual_status_requires_device_default_policy_and_field_presence(self):
        value = state()
        envelope = lambda: rehearsal.canonical({"ok": True, "command": "status", "result": value})
        self.assertEqual(rehearsal.checked_status(envelope(), "device"), value)
        self.refused("client_status_device", rehearsal.checked_status, envelope(), "other")
        value["rotation_policy"]["interval_seconds"] = 3
        self.refused("client_rotation_policy", rehearsal.checked_status, envelope(), "device")
        value["rotation_policy"]["interval_seconds"] = 300
        del value["session"]["recovery_attempt"]
        self.refused("client_status_missing_fields", rehearsal.checked_status, envelope(), "device")

    def test_rotation_unchanged_generation_and_pending_candidate_not_pass(self):
        before, after = state(), state()
        self.assertFalse(rehearsal.check_rotation(before, after))
        after["session"].update(active_generation=2, rotations_completed=1, candidate_generation=3)
        self.assertFalse(rehearsal.check_rotation(before, after))
        after["session"]["candidate_generation"] = None
        self.assertTrue(rehearsal.check_rotation(before, after))

    def test_rotation_reconnect_is_not_a_rotation(self):
        for scope, key, value in (("outer", "sessions", 2), ("session", "session_id", "other"), ("session", "epoch", 8),
                                  ("session", "recovery_attempt", 1), ("session", "recovery_attempt_deadline_ms", 10),
                                  ("session", "recovery_episode_deadline_ms", 10)):
            before, after = state(), state()
            after["session"].update(active_generation=2, rotations_completed=1)
            (after if scope == "outer" else after["session"])[key] = value
            with self.subTest(key=key), self.assertRaises(rehearsal.Refused):
                rehearsal.check_rotation(before, after)

    def test_checkpoint_exact_nonce_deployment_all_nodes_positive_versions(self):
        inventory = {"deployment_id": "deployment", "deployment_incarnation": "incarnation", "membership": {"publisher_key_id": "key"}}
        value = {"schema_version": 1, "nonce": "nonce", "deployment_id": "deployment", "deployment_incarnation": "incarnation",
                 "checkpoint_version": 1, "minimum_versions": {"relay-a": 1, "relay-b": 1, "relay-c": 1}, "publisher_key_id": "key", "signature": "signed"}
        self.assertEqual(rehearsal.check_checkpoint(value, inventory, "nonce"), value)
        for key, replacement in (("nonce", "old"), ("deployment_incarnation", "old"), ("checkpoint_version", 0),
                                  ("minimum_versions", {"relay-a": 1}), ("publisher_key_id", "wrong"), ("signature", "")):
            with self.subTest(key=key), self.assertRaises(rehearsal.Refused):
                rehearsal.check_checkpoint({**value, key: replacement}, inventory, "nonce")
        value["minimum_versions"]["relay-a"] = True
        self.refused("checkpoint_nodes", rehearsal.check_checkpoint, value, inventory, "nonce")

    def test_state_restart_refuses_identity_or_floor_rollback(self):
        before = {"schema_version": 1, "deployment_id": "d", "deployment_incarnation": "i", "node_id": "relay-a",
                  "state": {"checkpoint_version": 4, "node_versions": {"relay-a": 3, "relay-b": 2}}}
        after = copy.deepcopy(before)
        after["state"]["checkpoint_version"] = 5
        after["state"]["node_versions"]["relay-a"] = 4
        rehearsal.check_persisted_version(before, after)
        after["state"]["node_versions"]["relay-b"] = 1
        self.refused("membership_rollback", rehearsal.check_persisted_version, before, after)
        after = copy.deepcopy(before)
        after["state"]["checkpoint_version"] = 3
        self.refused("checkpoint_rollback", rehearsal.check_persisted_version, before, after)
        after["node_id"] = "relay-b"
        self.refused("persisted_identity_changed", rehearsal.check_persisted_version, before, after)

    def test_resp_exact_decode_and_command_encoding(self):
        self.assertEqual(rehearsal.read_resp(io.BytesIO(b"*3\r\n+OK\r\n:7\r\n$3\r\nabc\r\n")), ["OK", 7, "abc"])
        self.assertEqual(rehearsal.resp_command(["AUTH", "default", "password"]), b"*3\r\n$4\r\nAUTH\r\n$7\r\ndefault\r\n$8\r\npassword\r\n")

    def test_redis_bulk_joins_legal_fragments_but_refuses_truncated_eof(self):
        class Fragmented(io.BytesIO):
            def read(self, size=-1):
                return super().read(min(size, 2))
        self.assertEqual(rehearsal.read_resp(Fragmented(b"$5\r\nhello\r\n")), "hello")
        self.assertEqual(rehearsal.read_resp(Fragmented(b"$0\r\n\r\n")), "")
        for value in (b"$5\r\nhell", b"$5\r\nhello\r", b"$5\r\nhelloXX"):
            with self.subTest(value=value):
                self.refused("redis_bulk_truncated", rehearsal.read_resp, Fragmented(value))

    def test_redis_auth_and_command_use_ssl_sendall_not_raw_file_write(self):
        class ReadOnly(io.BytesIO):
            def write(self, data):
                raise AssertionError("raw SocketIO write must not be used")
        sock = mock.MagicMock()
        sock.__enter__.return_value = sock
        sock.makefile.return_value = ReadOnly(b"+OK\r\n+PONG\r\n")
        context = mock.Mock()
        context.wrap_socket.return_value = sock
        with mock.patch.object(rehearsal.socket, "create_connection"), \
                mock.patch.object(rehearsal, "bounded_network", side_effect=nullcontext):
            client = rehearsal.Redis(1, "redis.synthetic.invalid", context, "synthetic-password")
            self.assertEqual(client.command("PING"), "PONG")
        self.assertEqual(sock.sendall.call_args_list, [
            mock.call(rehearsal.resp_command(["AUTH", "default", "synthetic-password"])),
            mock.call(rehearsal.resp_command(["PING"]))])
        sock.makefile.assert_called_once_with("rb", buffering=0)

    def test_redis_acl_error_cannot_be_auth_failure_or_transport(self):
        self.refused("redis_permission_denied", rehearsal.read_resp, io.BytesIO(b"-NOPERM command denied\r\n"))
        self.refused("redis_command_refused", rehearsal.read_resp, io.BytesIO(b"-WRONGPASS password\r\n"))
        self.refused("redis_reply_line", rehearsal.read_resp, io.BytesIO(b""))

    def test_redis_bounds_and_truncated_bulk(self):
        for raw in (b"*1025\r\n", b"$1048577\r\n", b"$5\r\nab\r\n", b"?bad\r\n", b"*1\r\n" * 9 + b"+x\r\n"):
            with self.subTest(raw=raw[:12]), self.assertRaises(rehearsal.Refused):
                rehearsal.read_resp(io.BytesIO(raw))

    def test_diagnostics_never_include_raw_output_or_unknown_error_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "output"
            secret = "PRIVATE-KEY-OR-TOKEN"
            raw = rehearsal.canonical({"ok": False, "error": {"code": "CREDENTIAL_ERROR", "message": secret}})
            raw += rehearsal.canonical({"error": {"code": secret}})
            path.write_bytes(raw)
            value = rehearsal.safe_log_receipt(path)
            self.assertEqual(value["closed_codes"], ["CREDENTIAL_ERROR"])
            self.assertEqual(value["sha256"], rehearsal.digest(raw))
            self.assertNotIn(secret, json.dumps(value))
            self.assertFalse(value["raw_uploaded"])

    def test_unknown_exception_message_is_redacted(self):
        self.assertEqual(rehearsal.error_code(ValueError("PRIVATE-TOKEN")), "unexpected_ValueError")

    def test_actual_connect_ready_envelope_invalidates_identity_refusal(self):
        refusal = {"ok": False, "command": "connect", "error": {"code": "CREDENTIAL_ERROR", "retryable": False,
                   "message": "the relay refused this device's identity: synthetic"}}
        rehearsal.check_identity_refusal(rehearsal.canonical(refusal))
        ready = {"ok": True, "command": "connect", "result": {"state": "ready", "session_id": "synthetic", "epoch": 1, "generation": 1}}
        self.refused("unknown_device_was_ready", rehearsal.check_identity_refusal,
                     rehearsal.canonical(ready) + rehearsal.canonical(refusal))
        refusal["error"]["message"] = "local certificate parse failed before reaching relay"
        self.refused("unknown_device_refusal", rehearsal.check_identity_refusal, rehearsal.canonical(refusal))

    def test_identity_negative_does_not_accept_other_failure_duplicate_or_retry(self):
        refusal = {"ok": False, "command": "connect", "error": {"code": "CREDENTIAL_ERROR", "retryable": False,
                   "message": "the relay refused this device's identity: synthetic"}}
        self.refused("unknown_device_refusal", rehearsal.check_identity_refusal,
                     rehearsal.canonical(refusal) + rehearsal.canonical(refusal))
        for key, value in (("code", "TRANSPORT_ERROR"), ("retryable", True)):
            changed = copy.deepcopy(refusal)
            changed["error"][key] = value
            self.refused("unknown_device_refusal", rehearsal.check_identity_refusal, rehearsal.canonical(changed))

    def test_private_receipts_are_create_only_and_owner_private(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "receipt"
            rehearsal.private_write(path, b"first")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                rehearsal.private_write(path, b"second")
            self.assertEqual(path.read_bytes(), b"first")


class Cleanup(unittest.TestCase):
    def fixture(self, *, oom=False, ambiguous=None, fail_logs=False, fail_stop=False, foreign=False):
        expected, observed = owned()
        observed["State"]["OOMKilled"] = oom
        if foreign:
            observed["Config"]["Labels"][rehearsal.OWNER_LABEL] = "foreign"
        if ambiguous is not None:
            expected["id"] = ambiguous
        run = mock.Mock()
        docker = rehearsal.Docker(run, "owner", {})
        docker.containers = [expected]
        calls = []
        def call(args, **kwargs):
            calls.append(args)
            if args[:2] == ["container", "inspect"]:
                return rehearsal.canonical([observed])
            if fail_logs and args[:2] == ["container", "logs"]:
                raise rehearsal.Refused("log_capture_failed")
            if fail_stop and args[:2] == ["container", "stop"]:
                raise rehearsal.Refused("stop_failed")
            return b""
        docker.call = call
        return docker, calls

    def test_oom_is_failed_evidence_but_owned_container_still_removed(self):
        docker, calls = self.fixture(oom=True)
        errors = docker.cleanup()
        self.assertIn({"resource": "relay-a", "code": "container_oom"}, errors)
        self.assertIn(["container", "rm", "--force", "a" * 64], calls)

    def test_invalid_create_id_is_resolved_by_exact_name_and_owner(self):
        for invalid in ("", "not-an-id"):
            docker, calls = self.fixture(ambiguous=invalid)
            self.assertEqual(docker.cleanup(), [])
            self.assertIn(["container", "inspect", "owner-relay"], calls)
            self.assertIn(["container", "rm", "--force", "a" * 64], calls)

    def test_foreign_container_never_removed(self):
        docker, calls = self.fixture(foreign=True)
        self.assertTrue(docker.cleanup())
        self.assertFalse(any(args[:2] == ["container", "rm"] for args in calls))

    def test_logs_failure_does_not_skip_removal_or_become_pass(self):
        docker, calls = self.fixture(fail_logs=True)
        errors = docker.cleanup()
        self.assertEqual(errors[0]["code"], "log_capture_failed")
        self.assertIn(["container", "rm", "--force", "a" * 64], calls)

    def test_stop_failure_does_not_skip_exact_owned_force_remove(self):
        docker, calls = self.fixture(fail_stop=True)
        self.assertEqual(docker.cleanup()[0]["code"], "stop_failed")
        self.assertIn(["container", "rm", "--force", "a" * 64], calls)

    def test_one_bad_container_does_not_skip_later_resources(self):
        docker, calls = self.fixture(foreign=True)
        docker.volumes = ["owned-volume"]
        original = docker.call
        def call(args, **kw):
            if args[:2] == ["volume", "inspect"]:
                return rehearsal.canonical([{"Name": "owned-volume", "Labels": {rehearsal.OWNER_LABEL: "owner"}}])
            return original(args, **kw)
        docker.call = call
        self.assertTrue(docker.cleanup())
        self.assertIn(["volume", "rm", "owned-volume"], calls)

    def test_termination_between_main_and_cleanup_is_latched_and_cleanup_runs(self):
        handlers, removed = {}, []
        source = {"commit": "c" * 40, "tree": "d" * 40, "dirty_paths": []}
        resources = {"memory_available": 5 * 1024**3, "temporary_free": 2 * 1024**3, "workspace_free": 2 * 1024**3,
                     "pswpin": 0, "pswpout": 0, "oom_kill": 0, "cgroup_swap": 0}
        class FakeDocker(rehearsal.Docker):
            def __init__(self, run, owner, images):
                super().__init__(run, owner, images)
                item, self.observed = owned()
                self.observed["Config"]["Labels"][rehearsal.OWNER_LABEL] = owner
                self.containers = [item]
            def artifact_receipt(self, _role):
                return {}
            def call(self, args, **kwargs):
                if args[:2] == ["image", "inspect"]:
                    return rehearsal.canonical([{"Id": args[2], "Config": {"User": "fixture", "Labels": {"org.opencontainers.image.revision": source["commit"]}}}])
                if args[:2] == ["container", "inspect"]:
                    return rehearsal.canonical([self.observed])
                if args[:2] == ["container", "rm"]:
                    removed.append(args[-1])
                return b""
            def cleanup(self):
                # The main protected try has returned, but cleanup has not yet
                # switched modes: this is the reported SIGTERM race boundary.
                handlers[rehearsal.signal.SIGTERM](rehearsal.signal.SIGTERM, None)
                return super().cleanup()
        def install(sig, handler):
            if callable(handler):
                handlers[sig] = handler
            return rehearsal.signal.SIG_DFL
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(rehearsal, "Docker", FakeDocker), \
                mock.patch.object(rehearsal, "source_receipt", return_value=source), \
                mock.patch.object(rehearsal, "resource_sample", return_value=resources), \
                mock.patch.object(rehearsal.Rehearsal, "execute"), mock.patch.object(rehearsal.signal, "signal", side_effect=install), redirect_stdout(io.StringIO()):
            output = Path(temporary) / "output"
            args = ["--output", str(output)]
            for role in ("relay", "authority", "redis", "client"):
                args += ["--" + role + "-image", "sha256:" + "b" * 64]
            self.assertEqual(rehearsal.main(args), 1)
            receipt = json.loads((output / "result.json").read_bytes())
            self.assertEqual(receipt["status"], "failed")
            self.assertEqual(receipt["first_failure"], "controller_interrupted")
            self.assertEqual(receipt["cleanup_errors"], [])
            self.assertEqual(removed, ["a" * 64])

    def test_command_failure_survives_group_disappearance_race(self):
        events = []
        process = mock.Mock(pid=314159, returncode=17)
        process.poll.return_value = 17
        process.wait.return_value = 17
        with tempfile.TemporaryDirectory() as temporary:
            run = rehearsal.Runner(Path(temporary), lambda kind, **fields: events.append((kind, fields)))
            with mock.patch.object(run, "guard"), mock.patch.object(rehearsal.subprocess, "Popen", return_value=process), \
                    mock.patch.object(rehearsal, "group_present", side_effect=[True, False, False]), \
                    mock.patch.object(rehearsal.os, "killpg", side_effect=ProcessLookupError):
                with self.assertRaisesRegex(rehearsal.Refused, "^command_exit$"):
                    run(["not-executed"])
        self.assertEqual(events[0][1]["failure"], "command_exit")
        self.assertEqual(events[0][1]["exit_code"], 17)
        self.assertTrue(events[0][1]["process_group_absent"])

    def test_command_failure_survives_secondary_reaping_error(self):
        events = []
        process = mock.Mock(pid=314159, returncode=17)
        process.poll.return_value = 17
        process.wait.side_effect = rehearsal.subprocess.TimeoutExpired("not-executed", 1)
        with tempfile.TemporaryDirectory() as temporary:
            run = rehearsal.Runner(Path(temporary), lambda kind, **fields: events.append((kind, fields)))
            with mock.patch.object(run, "guard"), mock.patch.object(rehearsal.subprocess, "Popen", return_value=process), \
                    mock.patch.object(rehearsal, "group_present", return_value=False):
                with self.assertRaisesRegex(rehearsal.Refused, "^command_exit$"):
                    run(["not-executed"])
        self.assertEqual(events[0][1]["failure"], "command_exit")
        self.assertEqual(events[0][1]["cleanup_failures"], ["unexpected_TimeoutExpired"])


class SourceContract(unittest.TestCase):
    def test_renderer_example_config_ids_and_exact_config_environment(self):
        renderer = rehearsal.load_renderer()
        inventory = json.loads((rehearsal.ROOT / "deploy/fly/cluster/inventory.example.json").read_bytes())
        inventory["images"] = {role: "sha256:" + str(i) * 64 for i, role in enumerate(("relay", "redis", "authority"), 1)}
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "rendered"
            manifest = renderer.render_to(inventory, output, example=True)
            self.assertEqual(manifest["image_identity_kind"], {role: "docker-config" for role in inventory["images"]})
            for path, sha in manifest["files"].items():
                self.assertEqual(rehearsal.digest((output / path).read_bytes()), sha)
            for role in ("relay-a", "relay-b", "relay-c", "authority"):
                env = rehearsal.tomllib.loads((output / role / "fly.toml").read_text())["env"]
                config = "relay.toml" if role.startswith("relay") else "authority.toml"
                self.assertEqual(rehearsal.base64.b64decode(env["AT_CLUSTER_CONFIG_B64"], validate=True), (output / role / config).read_bytes())

    def test_client_config_keeps_actual300_second_rotation(self):
        dummy = object.__new__(rehearsal.Rehearsal)
        dummy.devices, dummy.services = ["device"], ["service"]
        dummy.public_hosts, dummy.canaries = ["device.synthetic.invalid"], ["synthetic:"]
        config = rehearsal.tomllib.loads(dummy.client_config(0))
        self.assertEqual(config["rotation"], {"interval_seconds": 300, "handshake_timeout_seconds": 10, "overlap_seconds": 30})
        self.assertEqual(config["relay_url"], "wss://device.synthetic.invalid:9443/v1/tunnel/control")
        self.assertEqual(config["exports"]["service"]["type"], "echo")

    def test_bootstrap_commands_precede_authority_service_and_no_hidden_reset(self):
        # Execute the scenario method against in-memory fakes. This proves the
        # orchestration order, not actual service startup or Redis semantics.
        dummy = object.__new__(rehearsal.Rehearsal)
        calls = []
        dummy.inventory = {"relays": [{"node_id": "relay-" + x, "app": "app-" + x} for x in "abc"]}
        dummy.docker = mock.Mock()
        dummy.docker.images = {"redis": "redis", "relay": "relay"}
        dummy.docker.create.side_effect = lambda *args, **kw: calls.append(("create", args[0])) or {"id": args[0]}
        dummy.docker.start.side_effect = lambda item: calls.append(("start", item["id"]))
        dummy.docker.port.return_value = 1
        dummy.states = {"redis": "redis", **{"relay-" + x: x for x in "abc"}}
        dummy.env = {"redis": {}, **{"relay-" + x: {} for x in "abc"}}
        dummy.redis_host, dummy.password = "redis.internal", "secret"
        dummy.pki = mock.Mock(cas={"redis": ["ca"]})
        dummy.public_hosts, dummy.relays = ["a", "b", "c"], []
        dummy.run = mock.Mock()
        dummy.event = mock.Mock()
        dummy.relay_command = lambda node, args: calls.append((args[0], node))
        dummy.authority_command = lambda args: calls.append((args[0], "authority"))
        dummy.start_authority = lambda: calls.append(("serve-authority", "authority"))
        dummy.wait_ready = lambda: calls.append(("wait-ready", "all"))
        dummy.checkpoint = lambda: {"fresh": True}
        config = {"port": "0", "tls-port": "6379", "appendonly": "yes", "appendfsync": "always", "no-appendfsync-on-rewrite": "no",
                  "aof-load-truncated": "no", "maxmemory": str(96 * 1024**2), "maxmemory-policy": "noeviction"}
        redis = mock.Mock()
        def command(*args):
            return {"DBSIZE": 0, "PING": "PONG", "CONFIG": [item for pair in config.items() for item in pair], "INFO": "run_id:" + "a" * 40 + "\r\n"}[args[0]]
        redis.command.side_effect = command
        with mock.patch.object(rehearsal, "Redis", return_value=redis), mock.patch.object(rehearsal, "tls_context"), \
                mock.patch.object(rehearsal, "wait_until", side_effect=lambda run, predicate, *args: self.assertTrue(predicate())):
            dummy.bootstrap()
        names = [row[0] for row in calls]
        self.assertLess(names.index("activate-first-incarnation"), names.index("provision-catalog"))
        self.assertLess(names.index("provision-catalog"), names.index("initialize-membership"))
        self.assertLess(names.index("initialize-membership"), names.index("serve-authority"))
        self.assertEqual([x for x in calls if x[0] == "start"][-3:], [("start", "relay-a"), ("start", "relay-b"), ("start", "relay-c")])
        self.assertEqual(calls[-1], ("wait-ready", "all"))


if __name__ == "__main__":
    unittest.main()
