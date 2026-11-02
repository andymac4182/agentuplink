#!/usr/bin/env python3
"""Pure planned-restart orchestration controls; no service or native execution."""

import copy
import importlib.util
from pathlib import Path
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("planned_rehearsal", Path(__file__).with_name("fly_cluster_rehearsal.py"))
r = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(r)


class PlannedRestart(unittest.TestCase):
    def setUp(self):
        self.now = r.timestamp_ns("2026-11-02T00:00:00Z")
        self.inventory = {"schema_version": 1, "deployment_id": "deployment", "deployment_incarnation": "incarnation",
                          "revision": 1, "nodes": [{"node_id": n} for n in r.NODES]}
        self.run_id = "a" * 40

    def envelope(self, version, checkpoint=10):
        return {"schema_version": 1, "deployment_id": "deployment", "deployment_incarnation": "incarnation", "node_id": "relay-a",
                "state": {"checkpoint_version": checkpoint, "node_versions": {n: version for n in r.NODES}}}

    def authority(self, version, high=9, checkpoint=12):
        return {"schema_version": 1, "inventory": self.inventory, "expected_redis_run_id": self.run_id,
                "membership_high_water": high, "checkpoint_high_water": checkpoint, "known_node_ids": list(r.NODES),
                "confirmed": None if version is None else {"inventory_revision": 1, "membership_version": version,
                                                          "expires_at": "2026-11-02T00:00:40Z"}}

    def fixture(self):
        fixture = r.Rehearsal.__new__(r.Rehearsal)
        fixture.run = r.Runner(Path("/unused-pure-fixture"), mock.Mock())
        fixture.run.guard = lambda: r.require(r.time.monotonic() < fixture.run.deadline, "controller_deadline")
        fixture.authority_inventory, fixture.run_id = self.inventory, self.run_id
        fixture.membership_files = {"relay-a": "membership.json"}
        fixture.states = {"relay-a": "relay-volume", "authority": "authority-volume"}
        fixture.relays, fixture.clients, fixture.devices = [{"id": "relay-a"}], [{}], ["device-a"]
        fixture.user, fixture.token = "user", "token"
        fixture.consumer_ports, fixture.device_ports = [1, 2, 3], [4, 5, 6]
        fixture.event = mock.Mock()
        fixture.revoke_target_grant = mock.Mock(return_value={})
        fixture.disconnect_client = mock.Mock()
        fixture.all_routes, fixture.restart_authority = mock.Mock(), mock.Mock()
        fixture.owner = mock.Mock(side_effect=[{"boot_id": "old", "session_id": "old", "owner_epoch": 1},
                                              {"boot_id": "new", "session_id": "new", "owner_epoch": 2}])
        fixture.wait_ready, fixture.start_client = mock.Mock(), mock.Mock()
        fixture.redis = mock.Mock()
        fixture.redis.command.return_value = "run_id:" + self.run_id + "\r\n"
        fixture.docker = mock.Mock()
        state = {"stopped": False, "started": False, "confirmed": None, "reads": [], "rounds": [7, 8]}
        def stop(_item):
            state["stopped"] = True
        def read(volume, names, **kwargs):
            if volume == "authority-volume":
                version = state["rounds"].pop(0)
                state["confirmed"] = version
                value = self.authority(version)
            else:
                state["reads"].append((state["stopped"], state["started"]))
                # A last real reconcile before stop advanced N=6 to N=7.
                value = self.envelope(8, 13) if state["started"] else self.envelope(7 if state["stopped"] else 6)
            return {names[0]: r.canonical(value)}
        def start(_item):
            self.assertTrue(state["stopped"], "relay must stop before planned start")
            self.assertTrue(state["confirmed"] is not None and state["confirmed"] > 7,
                            "start must follow a confirmed round above FINAL stopped floors")
            state["started"] = True
        fixture.docker.stop.side_effect = stop
        fixture.docker.start.side_effect = start
        fixture.docker.read_volume.side_effect = read
        fixture.docker.port.return_value = 1
        return fixture, state

    def test_actual_restart_method_requires_final_stopped_floors_before_one_start(self):
        fixture, state = self.fixture()
        with mock.patch.object(r, "utc_ns", return_value=self.now), mock.patch.object(r.time, "sleep"):
            fixture.restarts()
        self.assertEqual(state["reads"], [(True, False), (True, True)])
        self.assertEqual(state["rounds"], [])
        fixture.docker.start.assert_called_once_with(fixture.relays[0])
        fixture.start_client.assert_called_once_with(0)
        self.assertEqual(fixture.all_routes.call_count, 3)
        fixture.restart_authority.assert_called_once()

    def floors(self, value=None):
        return r.stopped_relay_floors(r.canonical(self.envelope(7) if value is None else value), self.inventory, "relay-a")

    def observe(self, watch, value):
        current = r.publication_observation(r.canonical(value), self.inventory, self.run_id, self.now, watch.latest)
        return watch.observe(current)

    def test_final_floor_schema_identity_complete_positive_integer_and_exhaustion(self):
        changes = [lambda x: x.update(node_id="relay-b"), lambda x: x.update(deployment_incarnation="old"),
                   lambda x: x["state"]["node_versions"].pop("relay-c"),
                   lambda x: x["state"]["node_versions"].update(unknown=7)]
        for invalid in (None, 0, -1, True, 1.0, "1", 2**64 - 1, 2**64):
            changes.append(lambda x, v=invalid: x["state"].update(checkpoint_version=v))
            changes.append(lambda x, v=invalid: x["state"]["node_versions"].update({"relay-a": v}))
        for index, change in enumerate(changes):
            value = self.envelope(7)
            change(value)
            with self.subTest(index=index), self.assertRaises(r.Refused):
                self.floors(value)

    def test_final_floors_are_frozen_and_all_nodes_must_be_surpassed(self):
        floors = self.floors()
        floors["node_versions"]["relay-c"] = 9
        watch = r.PlannedRelayRestart(floors)
        floors["node_versions"]["relay-c"] = 1
        self.assertFalse(self.observe(watch, self.authority(8, high=10)))
        self.assertTrue(self.observe(watch, self.authority(10, high=10)))
        self.assertEqual(watch.target["membership_version"], 10)
        self.assertTrue(self.observe(watch, self.authority(11, high=11)))
        self.assertEqual(watch.target["membership_version"], 10)

    def test_old_none_or_spent_round_is_not_a_confirmed_new_round(self):
        watch = r.PlannedRelayRestart(self.floors())
        self.assertFalse(self.observe(watch, self.authority(None, high=20)))
        self.assertFalse(self.observe(watch, self.authority(7, high=20)))
        self.assertTrue(self.observe(watch, self.authority(8, high=20)))

    def test_allocator_rollback_or_exhaustion_is_immediate_refusal(self):
        for field, invalid in (("checkpoint_high_water", 9), ("membership_high_water", 6),
                               ("checkpoint_high_water", 2**64 - 1), ("membership_high_water", 2**64 - 1),
                               ("checkpoint_high_water", True), ("membership_high_water", 9.0)):
            value = self.authority(None)
            value[field] = invalid
            with self.subTest(field=field, invalid=invalid), self.assertRaises(r.Refused):
                self.observe(r.PlannedRelayRestart(self.floors()), value)

    def test_actual_authority_schema_run_inventory_and_window_are_checked(self):
        changes = [lambda x: x.update(expected_redis_run_id="b" * 40),
                   lambda x: x["inventory"].update(revision=True), lambda x: x.update(known_node_ids=["relay-a"]),
                   lambda x: x["confirmed"].update(expires_at="2026-11-02T00:00:00Z"),
                   lambda x: x["confirmed"].update(expires_at="2026-11-02T00:01:01Z")]
        for index, change in enumerate(changes):
            value = copy.deepcopy(self.authority(8))
            change(value)
            with self.subTest(index=index), self.assertRaises(r.Refused):
                self.observe(r.PlannedRelayRestart(self.floors()), value)

    def test_periodic_observations_cannot_roll_back_or_extend_same_version(self):
        for mutate in (lambda x: x.update(checkpoint_high_water=11),
                       lambda x: x.update(membership_high_water=8),
                       lambda x: x["confirmed"].update(expires_at="2026-11-02T00:00:41Z")):
            watch = r.PlannedRelayRestart(self.floors())
            self.observe(watch, self.authority(7))
            value = self.authority(7)
            mutate(value)
            with self.assertRaises(r.Refused):
                self.observe(watch, value)

    def test_poststart_requires_fresh_checkpoint_every_node_and_current_target(self):
        watch = r.PlannedRelayRestart(self.floors())
        self.observe(watch, self.authority(8))
        watch.adopted(self.envelope(8, 13)["state"], self.now)
        changes = [lambda x: x.update(checkpoint_version=10), lambda x: x.update(checkpoint_version=None),
                   lambda x: x["node_versions"].update({"relay-b": 7}), lambda x: x["node_versions"].pop("relay-c")]
        for index, change in enumerate(changes):
            state = self.envelope(8, 13)["state"]
            change(state)
            with self.subTest(index=index), self.assertRaisesRegex(r.Refused, "restart_verified_adoption"):
                watch.adopted(state, self.now)
        with self.assertRaisesRegex(r.Refused, "restart_target_expired"):
            watch.adopted(self.envelope(8, 13)["state"], watch.target["expires_ns"])

    def test_failed_single_start_never_retries_or_starts_client(self):
        fixture, _state = self.fixture()
        fixture.docker.start.side_effect = r.Refused("service_not_running")
        with mock.patch.object(r, "utc_ns", return_value=self.now), mock.patch.object(r.time, "sleep"), \
                self.assertRaisesRegex(r.Refused, "service_not_running"):
            fixture.restarts()
        fixture.docker.start.assert_called_once()
        fixture.start_client.assert_not_called()
        fixture.restart_authority.assert_not_called()

    def test_no_start_if_final_state_read_or_publication_uses_entire_budget(self):
        for volume in ("relay-volume", "authority-volume"):
            fixture, _state = self.fixture()
            clock = [100.0]
            fixture.run.deadline = 1500.0
            read = fixture.docker.read_volume.side_effect
            def slow_read(name, paths, **kwargs):
                result = read(name, paths, **kwargs)
                if name == volume:
                    clock[0] = 160.0
                return result
            fixture.docker.read_volume.side_effect = slow_read
            with self.subTest(volume=volume), mock.patch.object(r.time, "monotonic", side_effect=lambda: clock[0]), \
                    mock.patch.object(r, "utc_ns", return_value=self.now), self.assertRaisesRegex(r.Refused, "controller_deadline"):
                fixture.restarts()
            fixture.docker.start.assert_not_called()
            self.assertEqual(fixture.run.deadline, 1500.0)

    def test_expiry_before_start_and_after_adoption_reads_never_passes(self):
        for calls_before_expiry, expected_starts in ((2, 0), (3, 1)):
            fixture, _state = self.fixture()
            values = [self.now] * calls_before_expiry + [self.now + 40 * 10**9]
            with self.subTest(boundary=calls_before_expiry), mock.patch.object(r, "utc_ns", side_effect=values), \
                    mock.patch.object(r.time, "sleep"), self.assertRaisesRegex(r.Refused, "restart_target_expired"):
                fixture.restarts()
            self.assertEqual(fixture.docker.start.call_count, expected_starts)
            fixture.start_client.assert_not_called()
            fixture.restart_authority.assert_not_called()

    def test_earlier_network_deadline_also_refuses_non_network_work(self):
        fixture, _state = self.fixture()
        fixture.run.deadline = 1500.0
        clock = [100.0]
        with mock.patch.object(r.time, "monotonic", side_effect=lambda: clock[0]), \
                mock.patch.object(r, "NETWORK_DEADLINE", 155.0):
            with self.assertRaisesRegex(r.Refused, "controller_deadline"):
                with r.planned_restart_budget(fixture.run):
                    clock[0] = 155.0
                    fixture.run.guard()
            self.assertEqual(fixture.run.deadline, 1500.0)
            self.assertEqual(r.NETWORK_DEADLINE, 155.0)

    def test_scope_restores_both_deadlines_on_success_and_failure(self):
        for old_network, outer, expected in ((None, 1500, 160), (155, 1500, 155), (999, 130, 130)):
            for fail in (False, True):
                fixture, _state = self.fixture()
                fixture.run.deadline = outer
                with mock.patch.object(r, "NETWORK_DEADLINE", old_network), mock.patch.object(r.time, "monotonic", return_value=100):
                    try:
                        with r.planned_restart_budget(fixture.run):
                            self.assertEqual(fixture.run.deadline, expected)
                            self.assertEqual(r.NETWORK_DEADLINE, expected)
                            if fail:
                                raise r.Refused("sentinel_failure")
                    except r.Refused as error:
                        self.assertTrue(fail)
                        self.assertEqual(str(error), "sentinel_failure")
                    self.assertEqual(r.NETWORK_DEADLINE, old_network)
                    self.assertEqual(fixture.run.deadline, outer)

    def test_http_receives_only_remaining_scope_budget_and_refuses_at_deadline(self):
        fixture, _state = self.fixture()
        fixture.run.deadline = 1500
        clock = [100.0]
        with mock.patch.object(r.time, "monotonic", side_effect=lambda: clock[0]), \
                mock.patch.object(r, "NETWORK_DEADLINE", 1500), \
                mock.patch.object(r.signal, "getitimer", return_value=(0.0, 0.0)), \
                mock.patch.object(r.signal, "getsignal"), mock.patch.object(r.signal, "signal"), \
                mock.patch.object(r.signal, "setitimer") as timer:
            with self.assertRaisesRegex(r.Refused, "controller_deadline"):
                with r.planned_restart_budget(fixture.run):
                    clock[0] = 159.75
                    with r.bounded_network():
                        pass
                    self.assertEqual(timer.call_args_list[0].args, (r.signal.ITIMER_REAL, 0.25))
                    clock[0] = 160.0
                    with r.bounded_network():
                        self.fail("expired network body ran")
            self.assertEqual(fixture.run.deadline, 1500)
            self.assertEqual(r.NETWORK_DEADLINE, 1500)


if __name__ == "__main__":
    unittest.main()
