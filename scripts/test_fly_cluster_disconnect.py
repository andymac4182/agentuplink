#!/usr/bin/env python3
"""Pure/mock disconnect lifetime controls; not a live Docker reproduction."""
from contextlib import nullcontext
import ast
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("disconnect_recovery", Path(__file__).with_name("fly_cluster_recovery_rehearsal.py"))
recovery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(recovery)
m = recovery.base


def diagnostic(command, result):
    return json.dumps({"schema_version": 1, "command": command, "ok": True,
                       "result": result, "error": None}).encode()


def status():
    return {"pid": 1, "state": "ready", "device_id": "device-0", "sessions": 1,
            "rotation_policy": {"interval_seconds": 300, "handshake_timeout_seconds": 10, "overlap_seconds": 30},
            "session": {"phase": "active", "session_id": "session", "epoch": 7, "active_generation": 2,
                        "candidate_generation": None, "rotations_completed": 1, "recovery_attempt": None,
                        "recovery_attempt_deadline_ms": None, "recovery_episode_deadline_ms": None}}


def stopped():
    return diagnostic("disconnect", {"pid": 1, "state": "stopped", "state_at_request": "ready", "waited_ms": 101})


class LifetimeDocker:
    """Model only the documented exec/PID1 lifetime; never invokes a process."""
    def __init__(self):
        self.images = {"client": "sha256:" + "b" * 64}
        self.volumes = ["owner-client-0"]
        self.target = {"id": "a" * 64, "name": "owner-client", "role": "client-0",
                       "image": self.images["client"], "mounts": [(self.volumes[0], "/profile", True)]}
        self.containers = [self.target]
        self.state = {"Running": True, "Status": "running", "Pid": 99, "ExitCode": 0,
                      "OOMKilled": False, "Error": ""}
        self.config = {"User": "client:client"}
        self.status = status()
        self.response = stopped()
        self.calls, self.helpers, self.removed, self.stops = [], [], [], []
        self.helper_error = None
        self.after_state = {"Running": False, "Status": "exited", "Pid": 0, "ExitCode": 0,
                            "OOMKilled": False, "Error": ""}

    def inspect(self, item):
        assert item is self.target
        return {"State": copy.deepcopy(self.state), "Config": copy.deepcopy(self.config)}

    def call(self, args, **kwargs):
        self.calls.append((args, kwargs))
        if args[:2] == ["container", "exec"] and "disconnect" in args:
            # Source-permitted schedule: stop finishes before the reporting
            # exec can print. This is deliberately modeled, not attribution
            # of PR291's otherwise unobserved kernel/daemon event ordering.
            self.state = copy.deepcopy(self.after_state)
            raise m.Refused("command_exit")
        assert args == ["container", "exec", self.target["id"], "/usr/local/bin/tunnel-client",
                        "status", "--config", "/profile/client.toml", "--json"]
        return diagnostic("status", self.status)

    def one_shot(self, role, image, **kwargs):
        self.helpers.append((role, image, kwargs))
        self.state = copy.deepcopy(self.after_state)
        if self.helper_error:
            raise self.helper_error
        return self.response

    def stop(self, item):
        self.stops.append(item)
        raise AssertionError("disconnect acceptance must not send a second stop")

    def remove_finished(self, item):
        self.removed.append(item)


class DisconnectLifetime(unittest.TestCase):
    def fixture(self):
        obj = object.__new__(recovery.RecoveryRehearsal)
        obj.docker = LifetimeDocker()
        obj.clients, obj.devices = [obj.docker.target], ["device-0"]
        obj.spare_device = "spare-device"
        obj.run = mock.Mock()
        obj.run.budget.side_effect = lambda _: nullcontext()
        obj.event = mock.Mock()
        return obj

    def test_completed_pid1_does_not_kill_independent_disconnect_reporter(self):
        obj = self.fixture()
        failure = None
        try:
            obj.disconnect(obj.docker.target)
        except m.Refused as error:
            failure = str(error)
        self.assertIsNone(failure, "reporting disconnect must outlive the target PID1")
        self.assertEqual(len(obj.docker.helpers), 1)
        self.assertFalse(obj.docker.stops)
        self.assertEqual(obj.docker.removed, [obj.docker.target])

    def test_helper_uses_same_image_default_user_readonly_profile_and_no_network(self):
        obj = self.fixture()
        obj.disconnect(obj.docker.target)
        self.assertEqual(obj.docker.helpers, [("client-disconnect", obj.docker.images["client"], {
            "network": False, "mounts": [("owner-client-0", "/profile", False)],
            "required_user": "client:client",
            "command": ["disconnect", "--config", "/profile/client.toml", "--json"]})])
        self.assertEqual(obj.run.budget.call_args_list, [mock.call(39), mock.call(34)])
        self.assertEqual(len(obj.docker.calls), 1)
        self.assertIn("status", obj.docker.calls[0][0])
        self.assertEqual(obj.event.call_args_list[0], mock.call("client_disconnect_requested",
            client_id=obj.docker.target["id"], role="client-0", supervisor_pid=1))
        done = obj.event.call_args_list[-1]
        self.assertEqual(done.args, ("client_disconnected",))
        self.assertEqual(done.kwargs["supervisor_pid"], 1)
        self.assertEqual(done.kwargs["waited_ms"], 101)
        self.assertEqual(done.kwargs["original_pid"], 0)

    def test_helper_error_or_timeout_is_not_retried_or_replaced_by_stop(self):
        for code in ("command_exit", "command_deadline", "container_oom", "client_disconnect_envelope"):
            obj = self.fixture()
            obj.docker.helper_error = m.Refused(code)
            with self.subTest(code=code), self.assertRaisesRegex(m.Refused, "^" + code + "$"):
                obj.disconnect(obj.docker.target)
            self.assertEqual(len(obj.docker.helpers), 1)
            self.assertFalse(obj.docker.stops)
            self.assertFalse(obj.docker.removed)
            self.assertFalse(any(call.args[0] == "client_disconnected" for call in obj.event.call_args_list))

    def test_stopped_receipt_cannot_rescue_original_unclean_exit(self):
        for field, value in (("ExitCode", 137), ("ExitCode", 130), ("ExitCode", False),
                             ("OOMKilled", True), ("OOMKilled", 0), ("Pid", 99), ("Pid", False),
                             ("Status", "dead"), ("Error", "private-daemon-detail")):
            obj = self.fixture()
            obj.docker.after_state[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(m.Refused):
                obj.disconnect(obj.docker.target)
            self.assertFalse(obj.docker.stops)
            self.assertFalse(obj.docker.removed)
            self.assertFalse(any(call.args[0] == "client_disconnected" for call in obj.event.call_args_list))

    def test_running_original_and_late_success_both_refused_at_unchanged_deadline(self):
        for running in (True, False):
            obj = self.fixture()
            if running:
                obj.docker.after_state = copy.deepcopy(obj.docker.state)
            with self.subTest(running=running), mock.patch.object(m.time, "monotonic", side_effect=[100, 100, 125]), \
                    self.assertRaisesRegex(m.Refused, "^client_disconnect_exit_deadline$"):
                obj.disconnect(obj.docker.target)
            self.assertFalse(obj.docker.stops)
            self.assertFalse(obj.docker.removed)

    def test_pending_original_is_observed_without_sending_another_stop(self):
        obj = self.fixture()
        observations = [copy.deepcopy(obj.docker.state), copy.deepcopy(obj.docker.state), copy.deepcopy(obj.docker.after_state)]
        obj.docker.inspect = mock.Mock(side_effect=[{"State": s, "Config": obj.docker.config} for s in observations])
        with mock.patch.object(m.time, "sleep") as sleep:
            obj.disconnect(obj.docker.target)
        sleep.assert_called_once_with(0.5)
        self.assertFalse(obj.docker.stops)
        self.assertEqual(obj.docker.inspect.call_count, 3)

    def test_status_pid_device_and_ready_state_are_bound_before_request(self):
        for field, value in (("pid", True), ("pid", 1.0), ("pid", 0), ("pid", 2**32),
                             ("state", "stopping"), ("device_id", "other"), ("session", None)):
            obj = self.fixture()
            obj.docker.status[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(m.Refused):
                obj.disconnect(obj.docker.target)
            self.assertFalse(obj.docker.helpers)
            self.assertFalse(obj.docker.stops)

    def test_refuses_foreign_image_volume_role_user_and_unowned_item(self):
        mutations = [lambda d: d.target.update(image="sha256:" + "c" * 64),
                     lambda d: d.target.update(role="foreign"), lambda d: d.containers.clear(),
                     lambda d: d.volumes.clear(), lambda d: d.config.update(User="root"),
                     lambda d: d.state.update(Running=False, Status="exited", Pid=0),
                     lambda d: d.target.update(mounts=[("owner-client-0", "/other", True)]),
                     lambda d: d.target.update(mounts=[("owner-client-0", "/profile", 1)]),
                     lambda d: d.target["mounts"].append(("owner-client-0", "/extra", True))]
        for index, change in enumerate(mutations):
            obj = self.fixture(); change(obj.docker)
            with self.subTest(index=index), self.assertRaises(m.Refused):
                obj.disconnect(obj.docker.target)
            self.assertFalse(obj.docker.helpers)

    def test_spare_profile_uses_its_expected_device_and_physical_inherits_same_path(self):
        obj = self.fixture()
        obj.docker.target["role"] = "spare-client-positive"
        obj.docker.status["device_id"] = obj.spare_device
        obj.clients = []
        obj.disconnect(obj.docker.target)
        self.assertEqual(len(obj.docker.helpers), 1)
        self.assertIs(recovery.PhysicalBackupRehearsal.disconnect, recovery.RecoveryRehearsal.disconnect)

    def test_base_restart_calls_shared_disconnect_without_success_path_stop(self):
        obj = self.fixture()
        obj.revoke_target_grant, obj.all_routes, obj.owner = mock.Mock(), mock.Mock(), mock.Mock()
        obj.user, obj.token = "synthetic-user", "private-token"
        class ReachedSharedDisconnect(Exception):
            pass
        obj.disconnect_client = mock.Mock(side_effect=ReachedSharedDisconnect)
        with self.assertRaises(ReachedSharedDisconnect):
            m.Rehearsal.restarts(obj)
        obj.disconnect_client.assert_called_once_with(obj.docker.target, "device-0")
        self.assertFalse(obj.docker.stops)
        self.assertFalse(obj.docker.calls)
        # Recovery's two independently implemented stop/restart methods and
        # the spare positive path all keep their existing shared callsites.
        tree = ast.parse(Path(recovery.__file__).read_text())
        sites = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Attribute) and node.func.attr == "disconnect"]
        self.assertEqual(len(sites), 3)


class DisconnectReceipt(unittest.TestCase):
    def test_accepts_exact_real_cli_shape_and_u64_counter(self):
        value = json.loads(stopped()); value["result"]["waited_ms"] = 2**64 - 1
        self.assertEqual(m.checked_disconnect(json.dumps(value).encode(), 1), value["result"])
        # The external command bound, not a synthetic truncation of the CLI's
        # u64 schema, governs elapsed time.

    def test_refuses_noncanonical_types_missing_and_extra_fields(self):
        alterations = [lambda v: v.update(schema_version=True), lambda v: v.update(schema_version=1.0),
                       lambda v: v.update(schema_version=2), lambda v: v.update(command="status"),
                       lambda v: v.update(ok=1), lambda v: v.update(ok=False),
                       lambda v: v.update(error={"message": "private"}), lambda v: v.update(extra=1),
                       lambda v: v.pop("error"), lambda v: v.update(result=None),
                       lambda v: v["result"].update(state="stopping"),
                       lambda v: v["result"].update(state_at_request="starting"),
                       lambda v: v["result"].update(extra=1), lambda v: v["result"].pop("waited_ms")]
        for field, values in (("pid", [True, 1.0, 0, 2, 2**32]), ("waited_ms", [True, 1.0, -1, 2**64])):
            for value in values:
                alterations.append(lambda v, field=field, value=value: v["result"].update({field: value}))
        for index, alter in enumerate(alterations):
            value = json.loads(stopped()); alter(value)
            with self.subTest(index=index), self.assertRaises(m.Refused):
                m.checked_disconnect(json.dumps(value).encode(), 1)

    def test_refuses_duplicate_nonfinite_truncated_multiline_and_oversized_receipt(self):
        for raw in (stopped().replace(b'"schema_version": 1', b'"schema_version": 1, "schema_version": 1'),
                    stopped().replace(b'101', b'NaN'), stopped()[:-1], stopped() + b'\n' + stopped(),
                    b'x' * (65536 + 1), b'[]'):
            with self.subTest(size=len(raw)), self.assertRaises(m.Refused):
                m.checked_disconnect(raw, 1)

    def test_missing_target_state_fields_never_mean_stopped_or_no_oom(self):
        state = LifetimeDocker().after_state
        self.assertTrue(m.client_exit_complete(state))
        for field in state:
            missing = state.copy(); del missing[field]
            with self.subTest(field=field), self.assertRaises(m.Refused):
                m.client_exit_complete(missing)

    def test_required_default_user_checked_in_actual_container_validator(self):
        expected = {"id": "a" * 64, "name": "owner-helper", "image": "sha256:" + "b" * 64,
                    "role": "client-disconnect", "mounts": [("profile", "/profile", False)],
                    "network": "none", "memory": 256 * 1024**2, "required_user": "client:client"}
        row = {"Id": expected["id"], "Name": "/" + expected["name"], "Image": expected["image"],
               "Config": {"User": "client:client", "Labels": {m.OWNER_LABEL: "owner", m.OWNER_LABEL + ".role": expected["role"]}},
               "Mounts": [{"Name": "profile", "Destination": "/profile", "RW": False}],
               "HostConfig": {"NetworkMode": "none", "Memory": expected["memory"], "MemorySwap": expected["memory"],
                              "PidsLimit": 256, "RestartPolicy": {"Name": "no"}, "LogConfig": m.LOG_CONFIG},
               "State": LifetimeDocker().after_state}
        m.check_container(row, expected, "owner")
        for user in (None, "", "root", "10003:10003"):
            changed = copy.deepcopy(row); changed["Config"]["User"] = user
            with self.subTest(user=user), self.assertRaisesRegex(m.Refused, "^container_default_user$"):
                m.check_container(changed, expected, "owner")

    def test_required_default_user_does_not_add_user_override_or_relax_limits(self):
        run = mock.Mock()
        docker = m.Docker(run, "owner", {"client": "sha256:" + "b" * 64})
        docker.call = mock.Mock(return_value=("a" * 64).encode())
        docker.inspect = mock.Mock()
        item = docker.create("client-disconnect", docker.images["client"], network=False,
                             required_user="client:client", mounts=[("profile", "/profile", False)],
                             command=["disconnect", "--config", "/profile/client.toml", "--json"])
        args = docker.call.call_args.args[0]
        self.assertNotIn("--user", args)
        self.assertNotIn("--entrypoint", args)
        self.assertEqual(args[args.index("--network") + 1], "none")
        self.assertEqual(args[args.index("--memory") + 1], str(256 * 1024**2))
        self.assertEqual(args[args.index("--memory-swap") + 1], str(256 * 1024**2))
        self.assertEqual(args[args.index("--mount") + 1], "type=volume,source=profile,target=/profile,volume-nocopy,readonly")
        self.assertEqual(item["subcommand"], "disconnect")
        self.assertEqual(item["required_user"], "client:client")
        docker.inspect.assert_called_once_with(item)

    def test_required_user_cannot_be_overridden_or_applied_to_another_image(self):
        for kwargs in ({"user": "0:0"}, {"required_user": "root"}, {"image": "sha256:" + "c" * 64}):
            docker = m.Docker(mock.Mock(), "owner", {"client": "sha256:" + "b" * 64})
            values = {"required_user": "client:client", "image": docker.images["client"], **kwargs}
            docker.call = mock.Mock()
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(m.Refused, "^container_required_user$"):
                docker.create("client-disconnect", network=False, **values)
            docker.call.assert_not_called()


if __name__ == "__main__":
    unittest.main()
