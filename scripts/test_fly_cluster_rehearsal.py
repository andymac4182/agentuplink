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
                               "PidsLimit": 256, "RestartPolicy": {"Name": "no"},
                               "LogConfig": {"Type": "local", "Config": {"max-size": "2m", "max-file": "1", "compress": "false"}}},
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

    def test_logging_configuration_requires_compression_off_and_original_budget(self):
        expected, observed = owned()
        rehearsal.check_container(observed, expected, "owner")
        for config in ({"max-size": "2m", "max-file": "1"},
                       {"max-size": "2m", "max-file": "1", "compress": "true"},
                       {"max-size": "4m", "max-file": "1", "compress": "false"},
                       {"max-size": "2m", "max-file": "2", "compress": "false"},
                       {"max-size": "2m", "max-file": "1", "compress": "false", "unknown": "value"}):
            changed = copy.deepcopy(observed)
            changed["HostConfig"]["LogConfig"]["Config"] = config
            with self.subTest(config=config), self.assertRaisesRegex(rehearsal.Refused, "container_logging_configuration"):
                rehearsal.check_container(changed, expected, "owner")
        changed = copy.deepcopy(observed)
        changed["HostConfig"]["LogConfig"]["Type"] = "json-file"
        with self.assertRaisesRegex(rehearsal.Refused, "container_logging_configuration"):
            rehearsal.check_container(changed, expected, "owner")

    def test_create_disables_compression_without_increasing_log_retention(self):
        run = mock.Mock()
        docker = rehearsal.Docker(run, "owner", {})
        commands = []
        docker.call = lambda args, **kw: commands.append(args) or ("a" * 64).encode()
        docker.inspect = mock.Mock()
        docker.create("inspect-relay", "sha256:" + "b" * 64, network=False, entrypoint="/bin/true")
        options = [value for value in commands[0] if value.startswith("--log-")]
        self.assertEqual(options, ["--log-driver=local", "--log-opt=max-size=2m", "--log-opt=max-file=1", "--log-opt=compress=false"])

    def test_retained_start_and_logs_hashes_match_fixed_engine_vocabulary(self):
        message = "compression cannot be enabled when max file count is 1"
        logs = ("Error response from daemon: " + message + "\n").encode()
        start = ("Error response from daemon: failed to create task for container: failed to initialize logging driver: " + message + "\n").encode()
        self.assertEqual(len(logs), 83)
        self.assertEqual(rehearsal.digest(logs), "73cd41bda8d98d78c6c4122d7b314135fc53d000c8fd060b86ccb721efb31ec6")
        self.assertEqual(len(start), 157)
        self.assertEqual(rehearsal.digest(start), "80a868096821299612792f8e0917bc2abf47d10457d368b829edc8e23bdf720e")
        self.assertEqual(rehearsal.closed_docker_error(logs)["codes"], ["local_compression_single_file"])
        result = rehearsal.closed_docker_error(start)
        self.assertEqual(set(result["codes"]), {"local_compression_single_file", "logging_driver_initialization", "container_task_creation"})
        self.assertEqual(result["hash_scope"], "complete")
        self.assertTrue(result["classification_complete"])

    def test_closed_docker_error_does_not_emit_arbitrary_values(self):
        secret = "private-token-certificate-command-path"
        raw = ("OCI runtime create failed: EACCES permission denied " + secret).encode()
        value = rehearsal.closed_docker_error(raw)
        self.assertEqual(value["errno_terms"], ["EACCES"])
        self.assertEqual(set(value["codes"]), {"oci_runtime_creation", "permission_denied"})
        self.assertNotIn(secret, json.dumps(value))
        unknown = rehearsal.closed_docker_error(secret.encode())
        self.assertEqual(unknown["classification"], "unclassified")
        self.assertEqual(unknown["codes"], [])
        self.assertNotIn(secret, json.dumps(unknown))

    def test_docker_error_scan_and_hash_are_explicitly_prefix_bounded(self):
        prefix = b"x" * rehearsal.MAX_DOCKER_ERROR
        raw = prefix + b" permission denied ENOSPC"
        value = rehearsal.closed_docker_error(raw)
        self.assertEqual(value["bytes"], len(raw))
        self.assertEqual(value["classified_bytes"], len(prefix))
        self.assertEqual(value["sha256"], rehearsal.digest(prefix))
        self.assertEqual(value["hash_scope"], "prefix")
        self.assertFalse(value["classification_complete"])
        self.assertEqual(value["codes"], [])
        self.assertEqual(value["errno_terms"], [])

    def test_container_state_projection_preserves_fields_and_error_hash_only(self):
        error = "failed to initialize logging driver: compression cannot be enabled when max file count is 1"
        state = {"Status": "exited", "StartedAt": "0001-01-01T00:00:00Z", "Pid": 0, "Running": False,
                 "ExitCode": 128, "OOMKilled": False, "Error": error, "unrelated": "private-value"}
        value = rehearsal.safe_container_state(state)
        self.assertEqual((value["status"], value["started_at"], value["pid"], value["exit_code"]),
                         ("exited", "0001-01-01T00:00:00Z", 0, 128))
        self.assertEqual(value["error"]["sha256"], rehearsal.digest(error.encode()))
        self.assertEqual(value["missing_fields"], [])
        self.assertEqual(value["invalid_fields"], [])
        self.assertNotIn(error, json.dumps(value))
        self.assertNotIn("private-value", json.dumps(value))

    def test_missing_invalid_state_does_not_invent_zero_or_echo_input(self):
        missing = rehearsal.safe_container_state({})
        self.assertIsNone(missing["pid"])
        self.assertIsNone(missing["running"])
        self.assertFalse(missing["error"]["present"])
        secret = "private-value"
        invalid = rehearsal.safe_container_state({"Status": secret, "StartedAt": secret, "Pid": True,
                   "Running": "false", "ExitCode": -1, "OOMKilled": None, "Error": [secret]})
        self.assertEqual(set(invalid["invalid_fields"]), {"Status", "StartedAt", "Pid", "Running", "ExitCode", "OOMKilled"})
        self.assertFalse(invalid["error"]["valid_type"])
        self.assertNotIn(secret, json.dumps(invalid))

    def test_engine_projection_retains_only_checked_version_and_known_plugins(self):
        server = {"Version": "28.5.1", "ApiVersion": "1.51", "MinAPIVersion": "1.24", "Os": "linux", "Arch": "amd64",
                  "RegistryConfig": "private-credentials"}
        value = rehearsal.safe_engine_projection(server, ["local", "json-file", "private-plugin"])
        self.assertEqual(value["known_log_drivers"], ["json-file", "local"])
        self.assertEqual(value["unknown_log_driver_count"], 1)
        self.assertNotIn("private", json.dumps(value))
        self.refused("docker_local_logging_unavailable", rehearsal.safe_engine_projection, server, ["json-file"])
        for key in ("Version", "ApiVersion", "MinAPIVersion", "Os", "Arch"):
            with self.subTest(key=key):
                self.refused("docker_engine_projection", rehearsal.safe_engine_projection, {**server, key: "private-value"}, ["local"])

    def test_preflight_rejects_full_docker_info_or_caller_format_override(self):
        run = mock.Mock()
        docker = rehearsal.Docker(run, "owner", {})
        for args in (["info"], ["info", "--format", "{{json .}}"], ["version", "--format", "{{json .Client}}"]):
            with self.subTest(args=args), self.assertRaisesRegex(rehearsal.Refused, "docker_command_shape"):
                docker.call(args)
        run.assert_not_called()
        docker.call(["info", "--format", "{{json .Plugins.Log}}"])
        run.assert_called_once_with(rehearsal.DOCKER + ["info", "--format", "{{json .Plugins.Log}}"])

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

    def test_created_inspection_container_still_records_real_logs_failure(self):
        docker, calls = self.fixture(fail_logs=True)
        # A created inspection intent is not grounds to erase a daemon failure:
        # the original83-byte error was invalid logging config, not absent logs.
        original = docker.call
        def call(args, **kwargs):
            output = original(args, **kwargs)
            if args[:2] == ["container", "inspect"]:
                value = json.loads(output)[0]
                value["State"].update(Status="created", StartedAt="0001-01-01T00:00:00Z", Pid=0, Running=False, Error="")
                return rehearsal.canonical([value])
            return output
        docker.call = call
        errors = docker.cleanup()
        self.assertEqual(errors[0]["code"], "log_capture_failed")
        self.assertTrue(any(args[:2] == ["container", "logs"] for args in calls))
        self.assertIn(["container", "rm", "--force", "a" * 64], calls)
        self.assertEqual(docker.inventory[0]["state_before_cleanup"]["status"], "created")

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
            def engine_preflight(self):
                return {"Version": "28.5.1", "ApiVersion": "1.51", "MinAPIVersion": "1.24", "Os": "linux", "Arch": "amd64", "known_log_drivers": ["local"]}
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


class PassivePublication(unittest.TestCase):
    def setUp(self):
        self.inventory = {"schema_version": 1, "deployment_id": "deployment", "deployment_incarnation": "incarnation",
                          "revision": 1, "nodes": [{"node_id": n} for n in rehearsal.NODES]}
        self.run_id = "a" * 40
        self.now = rehearsal.timestamp_ns("2026-11-02T00:00:00Z")
        self.stopped = {"schema_version": 1, "inventory": self.inventory, "expected_redis_run_id": self.run_id,
                        "membership_high_water": 7, "checkpoint_high_water": 10, "known_node_ids": list(rehearsal.NODES),
                        "confirmed": {"inventory_revision": 1, "membership_version": 6, "expires_at": "2026-11-02T00:00:40Z"}}

    def observe(self, value, previous=None):
        return rehearsal.publication_observation(rehearsal.canonical(value), self.inventory, self.run_id, self.now, previous)

    def fresh(self):
        value = copy.deepcopy(self.stopped)
        value.update(membership_high_water=8, checkpoint_high_water=12)
        value["confirmed"].update(membership_version=8)
        return value

    def relay(self, node, checkpoint=13, membership=8):
        return {"schema_version": 1, "deployment_id": "deployment", "deployment_incarnation": "incarnation", "node_id": node,
                "state": {"checkpoint_version": checkpoint, "node_versions": {n: membership for n in rehearsal.NODES}}}

    def test_bootstrap_http_refused_before_nonce_or_network_with_any_serving_relay(self):
        fixture = rehearsal.Rehearsal.__new__(rehearsal.Rehearsal)
        fixture.relays, fixture.run = [{}], mock.Mock()
        fixture.inventory, fixture.authority_port, fixture.authority_host, fixture.checkpoint_context = self.inventory, 1, "authority.invalid", object()
        with mock.patch.object(rehearsal.secrets, "token_hex", return_value="nonce") as nonce, \
                mock.patch.object(rehearsal, "http_request", return_value=(503, b'{"status":"unavailable"}')) as network:
            with self.assertRaisesRegex(rehearsal.Refused, "checkpoint_observer_with_serving_relays"):
                fixture.checkpoint()
            nonce.assert_not_called()
            network.assert_not_called()
            fixture.relays = []
            self.assertIsNone(fixture.checkpoint())
            network.assert_called_once()

    def test_publication_schema_identity_nodes_and_u64_fail_closed(self):
        self.assertEqual(self.observe(self.stopped), self.stopped)
        changes = [lambda x: x.pop("confirmed"), lambda x: x.update(unexpected=True),
                   lambda x: x.update(schema_version=True), lambda x: x.update(expected_redis_run_id="b" * 40),
                   lambda x: x["inventory"].update(revision=True), lambda x: x["inventory"].update(deployment_incarnation="other"),
                   lambda x: x.update(known_node_ids=["relay-a", "relay-a", "relay-c"]),
                   lambda x: x.update(known_node_ids=["relay-a", "relay-b"]), lambda x: x.update(known_node_ids=[{}, {}, {}])]
        for field in ("membership_high_water", "checkpoint_high_water"):
            for invalid in (True, -1, 2**64, 1.0, "1", None):
                changes.append(lambda x, k=field, v=invalid: x.update({k: v}))
        for index, change in enumerate(changes):
            changed = copy.deepcopy(self.stopped)
            change(changed)
            with self.subTest(index=index), self.assertRaises(rehearsal.Refused):
                self.observe(changed)

    def test_observation_rejects_duplicate_fields_oversize_nonfinite_and_bad_json(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'\xff', b'{', b' ' * (256 * 1024 + 1)):
            with self.subTest(size=len(raw)), self.assertRaises(rehearsal.Refused):
                rehearsal.publication_observation(raw, self.inventory, self.run_id, self.now)
        with self.assertRaisesRegex(rehearsal.Refused, "observation_byte_bound"):
            rehearsal.relay_observation(b' ' * (16 * 1024 + 1), self.inventory, "relay-a")

    def test_confirmation_requires_exact_revision_version_and_current_bounded_window(self):
        changes = [lambda c: c.pop("expires_at"), lambda c: c.update(extra=1), lambda c: c.update(inventory_revision=2),
                   lambda c: c.update(inventory_revision=True), lambda c: c.update(membership_version=True),
                   lambda c: c.update(membership_version=0), lambda c: c.update(membership_version=8),
                   lambda c: c.update(expires_at="2026-11-02T00:00:00Z"),
                   lambda c: c.update(expires_at="2026-11-02T00:01:00.000000001Z"),
                   lambda c: c.update(expires_at="2026-11-02T01:39:40+00:99"),
                   lambda c: c.update(expires_at="2026-11-02T00:00:40"), lambda c: c.update(expires_at=42)]
        for index, change in enumerate(changes):
            changed = copy.deepcopy(self.stopped)
            change(changed["confirmed"])
            with self.subTest(index=index), self.assertRaises(rehearsal.Refused):
                self.observe(changed)
        boundary = copy.deepcopy(self.stopped)
        boundary["confirmed"]["expires_at"] = "2026-11-02T00:01:00Z"
        self.observe(boundary)

    def test_highwaters_and_confirmation_never_roll_back_or_extend_same_version(self):
        previous = self.observe(self.stopped)
        for change in (lambda x: x.update(membership_high_water=6), lambda x: x.update(checkpoint_high_water=9),
                       lambda x: x.update(confirmed=None), lambda x: x["confirmed"].update(membership_version=5),
                       lambda x: x["confirmed"].update(expires_at="2026-11-02T00:00:40.000000001Z")):
            changed = copy.deepcopy(self.stopped)
            change(changed)
            with self.assertRaises(rehearsal.Refused):
                self.observe(changed, previous)
        same_instant = copy.deepcopy(self.stopped)
        same_instant["confirmed"]["expires_at"] = "2026-11-02T01:00:40+01:00"
        self.observe(same_instant, previous)

    def test_restart_old_confirmation_or_spent_round_cannot_supply_target(self):
        watch = rehearsal.PublicationWatch(self.observe(self.stopped))
        for high_water, confirmed in ((7, 6), (8, 6), (8, 7)):
            current = copy.deepcopy(self.stopped)
            current["membership_high_water"] = high_water
            current["confirmed"]["membership_version"] = confirmed
            watch.observe(self.observe(current, watch.latest))
            self.assertIsNone(watch.target)
        watch.observe(self.observe(self.fresh(), watch.latest))
        self.assertEqual(watch.target["membership_version"], 8)

    def test_fixed_checkpoint_floor_does_not_chase_live_allocator(self):
        watch = rehearsal.PublicationWatch(self.observe(self.stopped))
        watch.observe(self.observe(self.fresh(), watch.latest))
        fixed = copy.deepcopy(watch.target)
        moved = self.fresh()
        moved["checkpoint_high_water"] = 99
        moved["membership_high_water"] = 9
        moved["confirmed"]["membership_version"] = 9
        watch.observe(self.observe(moved, watch.latest))
        self.assertEqual(watch.target, fixed)
        states = {node: self.relay(node)["state"] for node in rehearsal.NODES}
        self.assertTrue(watch.adopted(states, self.now))
        overflow = self.fresh()
        overflow["checkpoint_high_water"] = 2**64 - 1
        with self.assertRaisesRegex(rehearsal.Refused, "adoption_floor_overflow"):
            rehearsal.PublicationWatch(self.observe(self.stopped)).observe(self.observe(overflow))

    def test_adoption_requires_all_three_checkpoint_and_all_three_node_fences(self):
        watch = rehearsal.PublicationWatch(self.observe(self.stopped))
        watch.observe(self.observe(self.fresh()))
        states = {node: self.relay(node)["state"] for node in rehearsal.NODES}
        self.assertTrue(watch.adopted(states, self.now))
        for relay in rehearsal.NODES:
            absent = copy.deepcopy(states)
            absent.pop(relay)
            self.assertFalse(watch.adopted(absent, self.now))
            for checkpoint in (None, 12):
                pending = copy.deepcopy(states)
                pending[relay]["checkpoint_version"] = checkpoint
                self.assertFalse(watch.adopted(pending, self.now))
            for node in rehearsal.NODES:
                for missing in (False, True):
                    pending = copy.deepcopy(states)
                    if missing:
                        pending[relay]["node_versions"].pop(node)
                    else:
                        pending[relay]["node_versions"][node] = 7
                    self.assertFalse(watch.adopted(pending, self.now))
        with self.assertRaisesRegex(rehearsal.Refused, "adoption_target_expired"):
            watch.adopted(states, self.now + 40 * 10**9)

    def test_relay_envelopes_bind_each_identity_and_exact_typed_schema(self):
        original = self.relay("relay-a")
        self.assertEqual(rehearsal.relay_observation(rehearsal.canonical(original), self.inventory, "relay-a"), original["state"])
        changes = [lambda x: x.update(node_id="relay-b"), lambda x: x.update(deployment_id="other"),
                   lambda x: x.update(deployment_incarnation="other"), lambda x: x.update(schema_version=True),
                   lambda x: x.update(extra=1), lambda x: x.pop("state"),
                   lambda x: x["state"].pop("checkpoint_version"), lambda x: x["state"].update(extra=1),
                   lambda x: x["state"].update(checkpoint_version=True), lambda x: x["state"].update(checkpoint_version=2**64),
                   lambda x: x["state"]["node_versions"].update({"relay-a": True}),
                   lambda x: x["state"]["node_versions"].update({"relay-a": -1}),
                   lambda x: x["state"]["node_versions"].update({"relay-d": 8})]
        for index, change in enumerate(changes):
            changed = copy.deepcopy(original)
            change(changed)
            with self.subTest(index=index), self.assertRaises(rehearsal.Refused):
                rehearsal.relay_observation(rehearsal.canonical(changed), self.inventory, "relay-a")

    def test_read_volume_enforces_requested_bound_at_both_helper_and_reader(self):
        docker = rehearsal.Docker(mock.Mock(), "owner", {"authority": "image"})
        docker.one_shot = mock.Mock(return_value=rehearsal.canonical({"authority.json": rehearsal.b64(b"{}\n")}))
        self.assertEqual(docker.read_volume("state", ["authority.json"], max_bytes=3), {"authority.json": b"{}\n"})
        command = docker.one_shot.call_args.kwargs
        self.assertFalse(command["network"])
        self.assertEqual(command["mounts"], [("state", "/volume", False)])
        self.assertEqual(json.loads(command["data"])["max_bytes"], 3)
        with self.assertRaisesRegex(rehearsal.Refused, "volume_read_byte_bound"):
            docker.read_volume("state", ["authority.json"], max_bytes=2)
        # Execute only the helper's file reader with an in-memory stdin and a
        # private temporary directory; no subprocess or container is involved.
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "authority.json"
            path.write_bytes(b"1234")
            helper = rehearsal.VOLUME_READ.replace("pathlib.Path('/volume')", "pathlib.Path(" + repr(root) + ")")
            with mock.patch("sys.stdin", io.StringIO('{"paths":["authority.json"],"max_bytes":3}')), self.assertRaises(AssertionError):
                exec(helper, {})
            # Even an observed small size cannot bypass the bounded read if
            # a file grows between metadata sampling and the actual read.
            observed = path.stat()
            smaller = mock.Mock(st_mode=observed.st_mode, st_size=3)
            with mock.patch("sys.stdin", io.StringIO('{"paths":["authority.json"],"max_bytes":3}')), \
                    mock.patch.object(os, "fstat", return_value=smaller), self.assertRaises(AssertionError):
                exec(helper, {})
            path.unlink()
            other = Path(root) / "other"
            other.write_bytes(b"1")
            path.symlink_to(other)
            with mock.patch("sys.stdin", io.StringIO('{"paths":["authority.json"],"max_bytes":3}')), self.assertRaises(OSError):
                exec(helper, {})

    def make_restart_fixture(self, *, expire_during_reads=False, cross_deadline=False):
        fixture = rehearsal.Rehearsal.__new__(rehearsal.Rehearsal)
        fixture.authority, fixture.relays = {"id": "authority"}, [{}, {}, {}]
        fixture.authority_inventory, fixture.run_id = self.inventory, self.run_id
        fixture.states = {node: node for node in (*rehearsal.NODES, "authority")}
        fixture.checkpoint = mock.Mock(side_effect=AssertionError("active HTTP observer"))
        fixture.event = mock.Mock()
        clock, events = [100.0], []
        fixture.run = rehearsal.Runner(Path("unused"), mock.Mock())
        fixture.run.deadline = 500
        def guard():
            rehearsal.require(rehearsal.time.monotonic() < fixture.run.deadline, "controller_deadline")
        fixture.run.guard = guard
        fixture.docker = mock.Mock()
        fixture.docker.stop.side_effect = lambda item: events.append("stop")
        fixture.docker.start.side_effect = lambda item: events.append("start")
        fixture.docker.port.return_value = 8444
        publications = iter([self.stopped, self.stopped, self.fresh()])
        def read(volume, paths, *, max_bytes):
            events.append(("read", volume, max_bytes, fixture.run.deadline))
            if volume == "authority":
                return {paths[0]: rehearsal.canonical(next(publications))}
            if volume == "relay-c":
                if expire_during_reads:
                    clock[0] = 140
                elif cross_deadline:
                    clock[0] = 130
            return {paths[0]: rehearsal.canonical(self.relay(volume))}
        fixture.docker.read_volume.side_effect = read
        return fixture, clock, events

    def test_restart_observes_after_stop_without_http_then_all_three_fences(self):
        fixture, clock, events = self.make_restart_fixture()
        with mock.patch.object(rehearsal.time, "monotonic", side_effect=lambda: clock[0]), \
                mock.patch.object(rehearsal.time, "sleep", side_effect=lambda delay: clock.__setitem__(0, clock[0] + delay)), \
                mock.patch.object(rehearsal, "utc_ns", return_value=self.now):
            fixture.restart_authority()
        self.assertEqual(events[:3], ["stop", ("read", "authority", 256 * 1024, 500), "start"])
        self.assertEqual([event[1] for event in events[3:]], ["authority", "authority", *rehearsal.NODES])
        self.assertTrue(all(event[3] == 130 for event in events[3:]))
        self.assertEqual(fixture.run.deadline, 500)
        fixture.checkpoint.assert_not_called()
        adoption = fixture.event.call_args_list[-1]
        self.assertEqual(adoption.args, ("authority_passive_adoption",))
        self.assertEqual(adoption.kwargs["fixed_checkpoint_floor"], 13)

    def test_adoption_after_last_read_rechecks_expiry_and_original_deadline(self):
        for expired in (True, False):
            fixture, clock, events = self.make_restart_fixture(expire_during_reads=expired, cross_deadline=not expired)
            # Expiry has its own clock; preserve the30s monotonic budget when
            # advancing wall time to the fixed target's expiry.
            def monotonic():
                return 101 if expired and clock[0] == 140 else clock[0]
            with mock.patch.object(rehearsal.time, "monotonic", side_effect=monotonic), \
                    mock.patch.object(rehearsal.time, "sleep", side_effect=lambda delay: clock.__setitem__(0, clock[0] + delay)), \
                    mock.patch.object(rehearsal, "utc_ns", side_effect=lambda: self.now + (40 * 10**9 if expired and clock[0] == 140 else 0)), \
                    self.assertRaisesRegex(rehearsal.Refused, "adoption_target_expired" if expired else "controller_deadline"):
                fixture.restart_authority()
            self.assertEqual(fixture.run.deadline, 500)
            self.assertFalse(any(call.args == ("authority_passive_adoption",) for call in fixture.event.call_args_list))

    def test_scoped_budget_never_extends_parent_and_restores_on_failure(self):
        run = rehearsal.Runner(Path("unused"), mock.Mock())
        run.deadline, run.guard = 105, mock.Mock()
        with mock.patch.object(rehearsal.time, "monotonic", return_value=100):
            with self.assertRaisesRegex(rehearsal.Refused, "retained_failure"):
                with run.budget(30):
                    self.assertEqual(run.deadline, 105)
                    raise rehearsal.Refused("retained_failure")
        self.assertEqual(run.deadline, 105)

    def test_pending_publication_uses_one_original_thirty_second_budget(self):
        fixture, clock, events = self.make_restart_fixture()
        deadlines = []
        def pending(previous=None):
            deadlines.append(fixture.run.deadline)
            return self.observe(self.stopped, previous)
        fixture.publication = pending
        with mock.patch.object(rehearsal.time, "monotonic", side_effect=lambda: clock[0]), \
                mock.patch.object(rehearsal.time, "sleep", side_effect=lambda delay: clock.__setitem__(0, clock[0] + delay)), \
                self.assertRaisesRegex(rehearsal.Refused, "controller_deadline"):
            fixture.restart_authority()
        self.assertEqual(clock[0], 130)
        self.assertEqual(deadlines[0], 500)
        self.assertGreater(len(deadlines), 2)
        self.assertTrue(all(deadline == 130 for deadline in deadlines[1:]))
        self.assertEqual(fixture.run.deadline, 500)
        fixture.checkpoint.assert_not_called()


if __name__ == "__main__":
    unittest.main()
