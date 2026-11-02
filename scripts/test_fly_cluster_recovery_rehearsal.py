#!/usr/bin/env python3
"""Offline controls only. A passing suite is not actual-image recovery proof."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("fly_recovery", Path(__file__).with_name("fly_cluster_recovery_rehearsal.py"))
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)

PREFIX = "tunnel-catalog:aur-123456789abc:"
TENANT = "00000000-0000-4000-8000-000000000001"
INV = {"deployment_id": "aur-123456789abc", "redis_namespace": "aur-123456789abc", "deployment_incarnation": "aur-123456789abc-recovered"}
RUN = "a" * 40
OBS = {"schema_version": 1, **INV, "redis_run_id": RUN, "catalog_digest": "d" * 64,
       "catalog_generation": "12", "key_count": 20, "byte_count": 1024, "quiescence": "unproven"}
FENCE = {"schema_version": 1, "deployment_id": INV["deployment_id"], "redis_namespace": INV["redis_namespace"], "highest_approval_version": 7}


class ObservationTests(unittest.TestCase):
    def test_exact_observation(self):
        self.assertEqual(m.checked_observation(m.canonical(OBS), INV, RUN), OBS)

    def test_all_scope_fields_are_bound(self):
        for key in ("deployment_id", "redis_namespace", "deployment_incarnation", "redis_run_id"):
            with self.subTest(key=key):
                value = dict(OBS, **{key: "wrong"})
                with self.assertRaises(m.Refused): m.checked_observation(m.canonical(value), INV, RUN)

    def test_missing_or_extra_field(self):
        for value in ({k: v for k, v in OBS.items() if k != "catalog_generation"}, dict(OBS, extra=True)):
            with self.assertRaises(m.Refused): m.checked_observation(m.canonical(value), INV, RUN)

    def test_duplicate_json_field(self):
        raw = m.canonical(OBS).rstrip()[:-1] + b',"quiescence":"unproven"}'
        with self.assertRaises(m.Refused): m.checked_observation(raw, INV, RUN)

    def test_no_inferred_quiescence(self):
        for value in (True, "proven", None):
            with self.assertRaises(m.Refused): m.checked_observation(m.canonical(dict(OBS, quiescence=value)), INV, RUN)

    def test_counter_and_digest_bounds(self):
        for key, value in [("schema_version", True), ("key_count", True), ("key_count", 0), ("key_count", 16385),
                           ("byte_count", 8 * 1024**2 + 1), ("catalog_digest", "D" * 64),
                           ("catalog_generation", "01"), ("catalog_generation", str(2**64)), ("catalog_generation", 12)]:
            with self.subTest(key=key, value=value), self.assertRaises(m.Refused):
                m.checked_observation(m.canonical(dict(OBS, **{key: value})), INV, RUN)

    def test_raw_byte_bound(self):
        with self.assertRaises(m.Refused): m.checked_observation(b" " * 16385, INV, RUN)


class FenceAndAuthorityTests(unittest.TestCase):
    def test_designated_existing_highwater(self):
        self.assertEqual(m.next_approval_version(m.canonical(FENCE), INV), 8)
        self.assertEqual(m.next_approval_version(m.canonical(dict(FENCE, highest_approval_version=None)), INV), 1)

    def test_wrong_domain_cannot_supply_empty_fence(self):
        for key in ("deployment_id", "redis_namespace"):
            with self.assertRaises(m.Refused): m.next_approval_version(m.canonical(dict(FENCE, **{key: "wrong", "highest_approval_version": None})), INV)

    def test_bad_highwater_refused(self):
        for value in (0, True, -1, "7", 2**64 - 1):
            with self.assertRaises(m.Refused): m.next_approval_version(m.canonical(dict(FENCE, highest_approval_version=value)), INV)

    def test_fence_schema_strict(self):
        for value in (dict(FENCE, extra=1), dict(FENCE, schema_version=True)):
            with self.assertRaises(m.Refused): m.check_fence(m.canonical(value), INV, 7)

    def test_approval_preserves_independent_allocators(self):
        before = {"membership_high_water": 20, "checkpoint_high_water": 80, "known_node_ids": list(m.base.NODES)}
        after = {**before, "schema_version": 1, "inventory": INV, "expected_redis_run_id": RUN, "confirmed": None}
        m.check_approved_state(before, after, INV, RUN)
        for key, value in (("membership_high_water", 0), ("checkpoint_high_water", 0), ("known_node_ids", []),
                           ("confirmed", {}), ("expected_redis_run_id", "b" * 40), ("inventory", {})):
            with self.subTest(key=key), self.assertRaises(m.Refused):
                m.check_approved_state(before, dict(after, **{key: value}), INV, RUN)

    def test_source_bounds_are_actual_and_exact(self):
        hashes = m.check_source_bounds()
        self.assertEqual(len(hashes), 2)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for relative in hashes:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((m.base.ROOT / relative).read_bytes())
            path = root / "crates/tunnel-relay/src/config.rs"
            path.write_text(path.read_text().replace("const MAX_CLUSTER_RECORD_LIFETIME_SECONDS: u64 = 60;", "const MAX_CLUSTER_RECORD_LIFETIME_SECONDS: u64 = 61;"))
            with self.assertRaisesRegex(m.Refused, "source_fencing_bound_changed"): m.check_source_bounds(root)


class RefusalTests(unittest.TestCase):
    def test_expected_run_refusal(self):
        result = m.check_refusal(b"", b"stage=authority_identity class=run_changed", 1, "old_relay_run")
        self.assertEqual(set(result), {"kind", "exit_code", "stdout_sha256", "stderr_sha256"})

    def test_unready_or_timeout_is_not_changed_run(self):
        for error in (b"unavailable", b"deadline", b"class=catalog", b"connection refused"):
            with self.assertRaises(m.Refused): m.check_refusal(b"", error, 1, "old_relay_run")

    def test_expected_marker_on_success_is_not_refusal(self):
        with self.assertRaises(m.Refused): m.check_refusal(b"", b"stage=authority_identity class=run_changed", 0, "old_relay_run")

    def test_entrypoint_missing_flag_is_separate(self):
        error = b"agentuplink-cluster-entrypoint: recovery fencing acknowledgements required"
        m.check_refusal(b"", error, 1, "missing_fences")
        with self.assertRaises(m.Refused): m.check_refusal(b"", error, 1, "wrong_nonce")

    def test_raw_error_bound(self):
        with self.assertRaises(m.Refused): m.check_refusal(b"a" * 65537, b"recovery approval was rejected", 1, "replay")


class NegativeDigestTests(unittest.TestCase):
    def args(self, **kw):
        values = dict(prefix=PREFIX, tenant=TENANT, before="Synthetic tenant", after="Synthetic tenant digest-negative",
                      generation="12", incarnation="aur-123456789abc-1", run_id=RUN)
        values.update(kw)
        return m.display_name_command(**values)

    def test_exact_four_keys_and_one_field(self):
        args = self.args()
        self.assertEqual(args[0], "EVAL")
        self.assertEqual(args[2:7], ["4", PREFIX + "tenant:" + TENANT, PREFIX + "meta:catalog_generation",
                                   PREFIX + "meta:active_incarnation", PREFIX + "meta:redis_run_id"])
        self.assertEqual(args[-4:], ["12", "13", "aur-123456789abc-1", RUN])
        self.assertNotIn("DEL", args[1])
        self.assertNotIn("INCR", args[1])  # no float/integer-overflow shortcut

    def test_wrong_owned_scope_and_identity_refused(self):
        for kw in ({"prefix": "tunnel-catalog:shared:"}, {"tenant": "not-uuid"}, {"incarnation": "new"}, {"run_id": "bad"}):
            with self.assertRaises((m.Refused, ValueError)): self.args(**kw)

    def test_no_arbitrary_or_revocation_value_mutation(self):
        for kw in ({"before": "active"}, {"after": "1"}, {"after": "Synthetic tenant"}):
            with self.assertRaises(m.Refused): self.args(**kw)

    def test_exact_decimal_above_float_integer_range(self):
        args = self.args(generation="9007199254740993")
        self.assertEqual(args[-4:-2], ["9007199254740993", "9007199254740994"])

    def test_generation_overflow_or_noncanonical_refused(self):
        for value in ("0", "01", "-1", str(2**64 - 1), "1e2"):
            with self.assertRaises(m.Refused): self.args(generation=value)

    def scenario(self):
        obj = object.__new__(m.RecoveryRehearsal)
        obj.inventory = dict(INV)
        obj.tenant = TENANT
        obj.stopped_bindings = ["aur-123456789abc-1", RUN, "12"]
        obj.stopped_observation = OBS
        obj.bindings = mock.Mock(return_value=obj.stopped_bindings)
        obj.redis = mock.Mock()
        obj.redis.command.side_effect = ["Synthetic tenant", ["ok", "Synthetic tenant digest-negative", "13"], ["ok", "Synthetic tenant", "14"]]
        obj.recover = mock.Mock()
        obj.fence_unchanged = mock.Mock()
        obj.revocation_flags = mock.Mock()
        obj.observe = mock.Mock(return_value=dict(OBS, catalog_generation="14"))
        obj.event = mock.Mock()
        return obj

    def test_real_refusal_precedes_known_field_restore(self):
        obj = self.scenario()
        obj.stale_digest_control("delivery", "nonce", b"fence")
        obj.recover.assert_called_once_with("delivery", "nonce", refusal="stale_digest")
        obj.fence_unchanged.assert_called_once_with(b"fence")
        args = obj.redis.command.call_args_list[-1].args
        self.assertEqual(args[-6:-2], ("Synthetic tenant digest-negative", "Synthetic tenant", "13", "14"))
        obj.observe.assert_called_once()

    def test_ambiguous_mutation_no_restore_sign_or_recovery(self):
        obj = self.scenario()
        obj.redis.command.side_effect = ["Synthetic tenant", TimeoutError("synthetic")]
        with self.assertRaises(TimeoutError): obj.stale_digest_control("delivery", "nonce", b"fence")
        self.assertEqual(obj.redis.command.call_count, 2)
        obj.recover.assert_not_called()
        obj.observe.assert_not_called()

    def test_wrong_mutation_result_no_restore(self):
        obj = self.scenario()
        obj.redis.command.side_effect = ["Synthetic tenant", ["refused"]]
        with self.assertRaisesRegex(m.Refused, "mutation_outcome"): obj.stale_digest_control("delivery", "nonce", b"fence")
        obj.recover.assert_not_called()
        obj.observe.assert_not_called()

    def test_wrong_refusal_no_restoration_or_new_observation(self):
        obj = self.scenario()
        obj.recover.side_effect = m.Refused("wrong-cause")
        with self.assertRaises(m.Refused): obj.stale_digest_control("delivery", "nonce", b"fence")
        self.assertEqual(obj.redis.command.call_count, 2)
        obj.observe.assert_not_called()

    def test_restoration_unknown_no_new_observation(self):
        obj = self.scenario()
        obj.redis.command.side_effect = ["Synthetic tenant", ["ok", "Synthetic tenant digest-negative", "13"], TimeoutError()]
        with self.assertRaises(TimeoutError): obj.stale_digest_control("delivery", "nonce", b"fence")
        obj.observe.assert_not_called()

    def test_generation_restoration_room_before_any_write(self):
        obj = self.scenario()
        obj.bindings.return_value = ["aur-123456789abc-1", RUN, str(2**64 - 2)]
        with self.assertRaises(m.Refused): obj.stale_digest_control("delivery", "nonce", b"fence")
        self.assertEqual(obj.redis.command.call_count, 1)

    def test_restore_not_a_counter_rollback(self):
        obj = self.scenario()
        obj.observe.return_value = OBS
        with self.assertRaisesRegex(m.Refused, "restored_field"): obj.stale_digest_control("delivery", "nonce", b"fence")


class RuntimeBoundaryTests(unittest.TestCase):
    def owner_inputs(self):
        old = {"boot_id": "old-boot", "session_id": "old-session", "owner_epoch": "4"}
        new = {"boot_id": "new-boot", "session_id": "new-session", "owner_epoch": "5", "deployment_incarnation": "new"}
        before = {"session": {"session_id": "old-session", "active_connection_id": "old-connection"}}
        after = {"session": {"phase": "active", "active_generation": 0, "session_id": "new-session", "epoch": 5, "active_connection_id": "new-connection"}}
        return old, new, before, after

    def test_actual_session_owner_and_connection_join(self):
        m.check_fresh_owner(*self.owner_inputs(), "new")

    def test_same_boot_session_connection_or_epoch_refused(self):
        for field, value in (("boot_id", "old-boot"), ("session_id", "old-session"), ("owner_epoch", "4"), ("deployment_incarnation", "old")):
            old, new, before, after = self.owner_inputs()
            new[field] = value
            with self.assertRaises(m.Refused): m.check_fresh_owner(old, new, before, after, "new")
        old, new, before, after = self.owner_inputs()
        after["session"]["active_connection_id"] = "old-connection"
        with self.assertRaises(m.Refused): m.check_fresh_owner(old, new, before, after, "new")

    def test_old_listener_positive_is_failure(self):
        with mock.patch.object(m.socket, "create_connection") as connection, mock.patch.object(m.base, "bounded_network", contextlib.nullcontext):
            with self.assertRaisesRegex(m.Refused, "listener_present"): m.absent_listener(1234)
            connection.return_value.close.assert_called_once()

    def test_connection_refused_only_not_timeout(self):
        with mock.patch.object(m.base, "bounded_network", contextlib.nullcontext):
            with mock.patch.object(m.socket, "create_connection", side_effect=ConnectionRefusedError): m.absent_listener(1234)
            with mock.patch.object(m.socket, "create_connection", side_effect=TimeoutError):
                with self.assertRaises(TimeoutError): m.absent_listener(1234)

    def test_cleanup_transient_breach_latched_but_not_raised(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = m.RecoveryRunner(Path(tmp), mock.Mock())
            run.initial = {}
            with mock.patch.object(m.base, "resource_sample", return_value={}), mock.patch.object(m.base, "check_resources", side_effect=[m.Refused("disk_guard"), None]):
                run.cleanup_sample()
                run.cleanup_sample()
            self.assertEqual(run.cleanup_guard_failures, ["disk_guard"])
            self.assertEqual(len(run.samples), 2)

    def test_wrong_owner_never_removed(self):
        run = mock.Mock()
        docker = m.RecoveryDocker(run, "owner", {})
        docker.inspect = mock.Mock(side_effect=m.Refused("container_owner"))
        docker.call = mock.Mock()
        with self.assertRaises(m.Refused): docker.remove_finished({"id": "a" * 64})
        docker.call.assert_not_called()

    def test_remove_requires_independent_absence(self):
        docker = m.RecoveryDocker(mock.Mock(), "owner", {})
        item = {"id": "a" * 64, "role": "role", "image": "sha256:" + "b" * 64}
        docker.containers = [item]
        docker.inspect = mock.Mock(return_value={"State": {"Running": False, "OOMKilled": False}})
        docker.call = mock.Mock(side_effect=[b"", b"still-present"])
        with self.assertRaisesRegex(m.Refused, "removed_container_present"): docker.remove_finished(item)
        self.assertEqual(docker.containers, [item])

    def test_unknown_backup_cli_option(self):
        # older-backup is now an explicit separate fixture. Supplying every
        # other required option ensures this refuses the unknown scenario,
        # rather than passing accidentally because image arguments are absent.
        arguments = ["--scenario", "unknown-backup", "--output", "/unused"]
        for role in ("relay", "authority", "redis", "client"):
            arguments += ["--" + role + "-image", "sha256:" + "a" * 64]
        with contextlib.redirect_stderr(io.StringIO()) as errors, self.assertRaises(SystemExit):
            m.main(arguments)
        self.assertIn("invalid choice", errors.getvalue())

    def test_exact_stage_order(self):
        obj = object.__new__(m.RecoveryRehearsal)
        obj.run = mock.Mock()
        calls = []
        for method in ("prepare", "bootstrap", "start_client", "all_routes", "setup_revocations", "stop_and_restart", "explicit_recovery", "restart_serving"):
            setattr(obj, method, lambda *args, name=method: calls.append((name, args)))
        obj.execute()
        self.assertEqual([name for name, _ in calls], ["prepare", "bootstrap", "start_client", "start_client", "start_client", "all_routes",
                         "setup_revocations", "stop_and_restart", "explicit_recovery", "restart_serving"])

    def test_first_failed_stage_stops_scenario(self):
        obj = object.__new__(m.RecoveryRehearsal)
        obj.run = mock.Mock()
        obj.prepare = mock.Mock()
        obj.bootstrap = mock.Mock(side_effect=m.Refused("first-failure"))
        obj.start_client = mock.Mock()
        with self.assertRaisesRegex(m.Refused, "first-failure"): obj.execute()
        obj.start_client.assert_not_called()


class IntegrationShapeTests(unittest.TestCase):
    def test_recovery_candidate_preserves_endpoints_secrets_and_stable_fences(self):
        renderer = m.base.load_renderer()
        inventory = json.loads((m.base.ROOT / "deploy/fly/cluster/inventory.example.json").read_bytes())
        inventory["deployment_id"] = "aur-123456789abc"
        inventory["deployment_incarnation"] = "aur-123456789abc-1"
        inventory["redis_namespace"] = "aur-123456789abc"
        obj = object.__new__(m.RecoveryRehearsal)
        obj.inventory, obj.prefix = inventory, "aur-123456789abc"
        obj.env, obj.membership_files = {}, {}
        old_files = renderer.render(inventory, example=True)
        for role in (*m.base.NODES, "authority"):
            env = m.tomllib.loads(old_files[role + "/fly.toml"].decode())["env"]
            obj.env[role] = {**env, "AT_REDIS_URL": "synthetic-private-endpoint", "AT_SECRET_PROBE": "synthetic-private-bytes"}
            if role in m.base.NODES:
                obj.membership_files[role] = m.base.membership_state_file(m.tomllib.loads(old_files[role + "/relay.toml"].decode()), inventory["deployment_incarnation"])
        obj.old_membership_files = obj.membership_files.copy()
        obj.event = mock.Mock()
        before = copy.deepcopy(obj.env)
        with tempfile.TemporaryDirectory() as tmp:
            obj.private = Path(tmp)
            obj.candidate()
            self.assertEqual(obj.inventory["membership"]["revision"], inventory["membership"]["revision"] + 1)
            self.assertEqual(obj.inventory["relays"], inventory["relays"])
            for role in before:
                self.assertEqual(obj.env[role]["AT_REDIS_URL"], before[role]["AT_REDIS_URL"])
                self.assertEqual(obj.env[role]["AT_SECRET_PROBE"], before[role]["AT_SECRET_PROBE"])
                self.assertEqual(obj.env[role]["AT_CLUSTER_REDIS_HOST"], before[role]["AT_CLUSTER_REDIS_HOST"])
            for node in m.base.NODES:
                config = m.tomllib.loads(m.base64.b64decode(obj.env[node]["AT_CLUSTER_CONFIG_B64"]).decode())
                self.assertEqual(config["recovery"]["fence_path"], "/var/lib/agent-tunnel/state/recovery-approval-fence.json")
                self.assertNotEqual(obj.membership_files[node], obj.old_membership_files[node])

    def test_offline_signer_mount_separation(self):
        obj = object.__new__(m.RecoveryRehearsal)
        obj.approval_sequence = 0
        obj.offline = "owned-offline-keys"
        obj.event = mock.Mock()
        obj.docker = mock.Mock()
        obj.docker.images = {"authority": "sha256:" + "a" * 64}
        obj.docker.volume.side_effect = ["owned-input", "owned-output", "owned-delivery"]
        obj.docker.read_volume.return_value = {"signed.json": b"synthetic-signed-bytes"}
        self.assertEqual(obj.sign(OBS, 8, "independent-nonce"), "owned-delivery")
        call = obj.docker.one_shot.call_args
        self.assertFalse(call.kwargs["network"])
        self.assertEqual(call.kwargs["entrypoint"], "/usr/local/bin/tunnel-authority")
        self.assertEqual(call.kwargs["mounts"], [("owned-offline-keys", "/offline", False), ("owned-input", "/input", False), ("owned-output", "/output", True)])
        # Delivery gets only the signed approval, never the recovery key.
        self.assertEqual(obj.docker.setup_volume.call_args.args, ("owned-delivery", 10001, 10001, {"signed.json": b"synthetic-signed-bytes"}))

    def test_entrypoint_accepts_exact_recovery_cli_and_refuses_missing_flags(self):
        entry = m.base.load_python(m.base.ROOT / "deploy/fly/cluster/images/entrypoint.py", "recovery_entrypoint_test")
        args = ["recover", "--approval", "/var/lib/agent-tunnel/operator/signed.json", "--expected-nonce", "nonce",
                "--acknowledgement-id", "fenced", "--old-primary-fenced", "--old-relays-fenced"]
        argv, _ = entry.command("relay", args, entry.BASES["relay"])
        self.assertEqual(argv[:4], ["/usr/local/bin/tunnel-relay", "recover", "--config", "/var/lib/agent-tunnel/secrets/relay.toml"])
        with self.assertRaisesRegex(entry.Refusal, "recovery fencing acknowledgements required"):
            entry.command("relay", args[:-2], entry.BASES["relay"])

    def test_old_startup_refusal_cannot_mutate_fences(self):
        obj = object.__new__(m.RecoveryRehearsal)
        obj.old_env = {node: {} for node in (*m.base.NODES, "authority")}
        obj.old_membership_files = {}
        obj.operator, obj.event = mock.Mock(), mock.Mock()
        obj.private_state = mock.Mock(return_value={"changed": True})
        obj.bindings = mock.Mock(return_value=["old", RUN, "12"])
        with self.assertRaisesRegex(m.Refused, "refused_relay_mutated_state"):
            obj.old_startups({"original": True}, ["old", RUN, "12"])
        self.assertEqual(obj.operator.call_count, 1)

    def test_cleanup_failure_preserves_first_main_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "receipt"
            docker = mock.Mock()
            docker.cleanup.return_value = [{"resource": "owned", "code": "cleanup-failure"}]
            docker.inventory = []
            with mock.patch.object(m, "RecoveryDocker", return_value=docker), \
                 mock.patch.object(m.base, "resource_sample", return_value={}), \
                 mock.patch.object(m.base, "check_resources"), \
                 mock.patch.object(m, "check_source_bounds", side_effect=m.Refused("first-main-failure")), \
                 contextlib.redirect_stdout(io.StringIO()):
                args = ["--scenario", "durable-restart", "--output", str(output)]
                for role in ("relay", "authority", "redis", "client"):
                    args += ["--" + role + "-image", "sha256:" + "a" * 64]
                self.assertEqual(m.main(args), 1)
            result = json.loads((output / "result.json").read_bytes())
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["first_failure"], "first-main-failure")
            self.assertEqual(result["cleanup_errors"], docker.cleanup.return_value)
            docker.engine_preflight.assert_not_called()
            docker.cleanup.assert_called_once()


class ReviewRegressionTests(unittest.TestCase):
    def test_observed_fence_boolean_not_expected_integer(self):
        with self.assertRaises(m.Refused):
            m.check_fence(m.canonical(dict(FENCE, highest_approval_version=True)), INV, 1)

    def test_observed_fence_float_not_expected_integer(self):
        with self.assertRaises(m.Refused):
            m.check_fence(m.canonical(dict(FENCE, highest_approval_version=1.0)), INV, 1)

    def authority_states(self):
        before = {"membership_high_water": 20, "checkpoint_high_water": 80, "known_node_ids": list(m.base.NODES)}
        after = {**before, "schema_version": 1, "inventory": INV, "expected_redis_run_id": RUN, "confirmed": None}
        return before, after

    def test_authority_observed_schema_exact_integer(self):
        before, after = self.authority_states()
        for value in (True, 1.0):
            with self.subTest(value=value), self.assertRaises(m.Refused):
                m.check_approved_state(before, dict(after, schema_version=value), INV, RUN)

    def test_authority_confirmed_must_be_present(self):
        before, after = self.authority_states()
        del after["confirmed"]
        with self.assertRaises(m.Refused): m.check_approved_state(before, after, INV, RUN)

    def test_authority_counters_required_in_both_snapshots(self):
        for key in ("membership_high_water", "checkpoint_high_water", "known_node_ids"):
            before, after = self.authority_states()
            del before[key]
            del after[key]
            with self.subTest(key=key), self.assertRaises(m.Refused):
                m.check_approved_state(before, after, INV, RUN)

    def test_authority_both_counters_are_actual_u64(self):
        for key in ("membership_high_water", "checkpoint_high_water"):
            for value in (True, 20.0, -1, 2**64, "20", None):
                before, after = self.authority_states()
                before[key] = after[key] = value
                with self.subTest(key=key, value=value), self.assertRaises(m.Refused):
                    m.check_approved_state(before, after, INV, RUN)

    def test_authority_observed_float_cannot_equal_baseline_integer(self):
        before, after = self.authority_states()
        after["membership_high_water"] = 20.0
        with self.assertRaises(m.Refused): m.check_approved_state(before, after, INV, RUN)

    def test_authority_baseline_float_cannot_equal_observed_integer(self):
        before, after = self.authority_states()
        before["checkpoint_high_water"] = 80.0
        with self.assertRaises(m.Refused): m.check_approved_state(before, after, INV, RUN)

    def test_authority_known_nodes_required_and_exact(self):
        for nodes in (None, [], ["relay-a", "relay-b", "relay-b"], ["relay-a", "relay-b", "foreign"],
                      "relay-a", [1, 2, 3], ["relay-a", "relay-b", "relay-c", "relay-a"]):
            before, after = self.authority_states()
            before["known_node_ids"] = after["known_node_ids"] = nodes
            with self.subTest(nodes=nodes), self.assertRaises(m.Refused):
                m.check_approved_state(before, after, INV, RUN)

    def test_authority_nested_inventory_types_are_not_coerced(self):
        before, after = self.authority_states()
        inventory = dict(INV, revision=1)
        after["inventory"] = dict(inventory, revision=True)
        with self.assertRaises(m.Refused): m.check_approved_state(before, after, inventory, RUN)

    def test_authority_unchanged_valid_zero_allocators(self):
        before, after = self.authority_states()
        for key in ("membership_high_water", "checkpoint_high_water"):
            before[key] = after[key] = 0
        m.check_approved_state(before, after, INV, RUN)

    def test_connection_ids_required_in_baseline_and_current(self):
        for side in (2, 3):
            args = RuntimeBoundaryTests().owner_inputs()
            del args[side]["session"]["active_connection_id"]
            with self.subTest(side=side), self.assertRaises(m.Refused): m.check_fresh_owner(*args, "new")

    def test_connection_ids_are_nonempty_strings_on_both_sides(self):
        for side in (2, 3):
            for value in (None, "", 1, True, ["id"], {"id": "value"}):
                args = RuntimeBoundaryTests().owner_inputs()
                args[side]["session"]["active_connection_id"] = value
                with self.subTest(side=side, value=value), self.assertRaises(m.Refused): m.check_fresh_owner(*args, "new")

    def outcome_scenario(self, **changes):
        obj = object.__new__(m.RecoveryRehearsal)
        obj.inventory, obj.run_id = dict(INV), RUN
        old_fence = m.canonical(dict(FENCE, highest_approval_version=None))
        consumed = m.canonical(dict(FENCE, highest_approval_version=1))
        obj.states = {node: node for node in m.base.NODES}
        obj.old_membership_files = {node: node + ".json" for node in m.base.NODES}
        obj.stopped_state = {node: {obj.old_membership_files[node]: b"membership", m.FENCE_FILE: old_fence}
                             for node in m.base.NODES}
        obj.stopped_state["authority"] = {"authority.json": b"state"}
        state = copy.deepcopy(obj.stopped_state)
        state["relay-a"][m.FENCE_FILE] = consumed
        obj.candidate, obj.fence_unchanged, obj.stale_digest_control = mock.Mock(), mock.Mock(), mock.Mock()
        obj.observe = mock.Mock(return_value=OBS)
        obj.sign = mock.Mock(return_value="delivery")
        outcome = {"schema_version": 1, "approval_version": 1, "deployment_incarnation": INV["deployment_incarnation"],
                   "redis_run_id": RUN, "catalog_digest": OBS["catalog_digest"], "quiescence_declared": True}
        outcome.update(changes)
        obj.recover = mock.Mock(return_value=m.canonical(outcome))
        obj.bindings = mock.Mock(return_value=[INV["deployment_incarnation"], RUN, "14"])
        obj.docker = mock.Mock()
        obj.docker.read_volume.return_value = {m.FENCE_FILE: consumed}
        obj.private_state = mock.Mock(return_value=state)
        obj.old_startups, obj.event = mock.Mock(), mock.Mock()
        return obj

    def test_exact_outcome_reaches_real_orchestration_boundary(self):
        obj = self.outcome_scenario()
        obj.explicit_recovery()
        obj.old_startups.assert_called_once()

    def test_outcome_integer_fields_not_boolean_or_float(self):
        for key in ("schema_version", "approval_version"):
            for value in (True, 1.0):
                obj = self.outcome_scenario(**{key: value})
                with self.subTest(key=key, value=value):
                    with self.assertRaisesRegex(m.Refused, "recovery_outcome_identity"):
                        obj.explicit_recovery()
                    obj.bindings.assert_not_called()

    def test_outcome_quiescence_is_actual_boolean(self):
        for value in (1, 1.0):
            obj = self.outcome_scenario(quiescence_declared=value)
            with self.subTest(value=value):
                with self.assertRaisesRegex(m.Refused, "recovery_outcome_identity"):
                    obj.explicit_recovery()
                obj.bindings.assert_not_called()

    def test_outcome_missing_and_extra_fields_refused(self):
        for remove, extra in (("schema_version", False), ("approval_version", False), ("quiescence_declared", False), (None, True)):
            obj = self.outcome_scenario()
            outcome = json.loads(obj.recover.return_value)
            if remove:
                del outcome[remove]
            if extra:
                outcome["unexpected"] = 1
            obj.recover.return_value = m.canonical(outcome)
            with self.subTest(remove=remove, extra=extra), self.assertRaisesRegex(m.Refused, "recovery_outcome_identity"):
                obj.explicit_recovery()


class PeerAddressCompositionTests(unittest.TestCase):
    def test_recovery_unique_names_keep_exact_role_and_reuse_ip_only_after_owned_removal(self):
        run = mock.Mock(index=1)
        image = "sha256:" + "b" * 64
        docker = m.RecoveryDocker(run, "owner", {"relay": image})
        docker.network = {"id": "network", "subnet": "fd42:1234:5678::/64"}
        docker.peer_ipv6 = m.base.peer_ipv6_addresses(docker.network["subnet"])
        commands = []
        def command(args, **_kwargs):
            commands.append(args)
            run.index += 1
            return (("a" if run.index < 5 else "b") * 64).encode() if args[:2] == ["container", "create"] else b""
        docker.call = command
        docker.inspect = mock.Mock(return_value={"State": {"Running": False, "OOMKilled": False, "ExitCode": 0}})
        address = docker.peer_ipv6["relay-a"]
        first = docker.create("relay-a", image, peer_ipv6=address)
        self.assertEqual(first["role"], "relay-a")
        self.assertTrue(first["name"].endswith("-relay-a-r1"))
        with self.assertRaises(m.Refused):
            docker.create("relay-a", image, peer_ipv6=address)
        docker.remove_finished(first)
        second = docker.create("relay-a", image, peer_ipv6=address)
        self.assertEqual(second["role"], "relay-a")
        self.assertEqual(second["peer_ipv6"], first["peer_ipv6"])
        self.assertNotEqual(second["name"], first["name"])
        self.assertEqual(docker.containers, [second])
        creates = [args for args in commands if args[:2] == ["container", "create"]]
        self.assertEqual(len(creates), 2)
        for args in creates:
            self.assertIn(m.base.OWNER_LABEL + ".role=relay-a", args)
            self.assertEqual(args[args.index("--ip6") + 1], address)

    def test_recovery_restart_passes_all_three_original_reviewed_addresses(self):
        obj = object.__new__(m.RecoveryRehearsal)
        addresses = m.base.peer_ipv6_addresses("fd42:1234:5678::/64")
        obj.inventory = {"relays": [{"node_id": node, "app": "owned-" + node, "peer_ipv6": addresses[node]}
                                   for node in m.base.NODES]}
        obj.authority_inventory, obj.run_id = dict(INV, revision=2), RUN
        obj.stopped_authority = {"inventory": {"revision": 1}, "membership_high_water": 20,
                                 "checkpoint_high_water": 80, "known_node_ids": list(m.base.NODES)}
        approved = {**obj.stopped_authority, "inventory": obj.authority_inventory,
                    "schema_version": 1, "expected_redis_run_id": RUN, "confirmed": None}
        obj.states = {node: node for node in (*m.base.NODES, "authority")}
        obj.env = {node: {} for node in m.base.NODES}
        obj.public_hosts, obj.relays = ["a.invalid", "b.invalid", "c.invalid"], []
        obj.operator, obj.start_authority = mock.Mock(), mock.Mock()
        obj.publication = mock.Mock(return_value={"confirmed": {"membership_version": 21}})
        obj.run = mock.Mock()
        obj.run.budget.side_effect = lambda _seconds: contextlib.nullcontext()
        obj.docker = mock.Mock()
        obj.docker.images = {"relay": "sha256:" + "b" * 64}
        obj.docker.read_volume.return_value = {"authority.json": m.canonical(approved)}
        obj.docker.create.side_effect = lambda node, *_args, **_kwargs: {"id": node}
        obj.docker.port.return_value = 12345
        obj.adopt = mock.Mock(side_effect=RuntimeError("stop after real relay creation wiring"))
        with self.assertRaisesRegex(RuntimeError, "stop after real relay creation wiring"):
            obj.restart_serving()
        self.assertEqual(obj.docker.create.call_count, 3)
        for call, node in zip(obj.docker.create.call_args_list, m.base.NODES, strict=True):
            self.assertEqual(call.args[0], node)
            self.assertEqual(call.kwargs["peer_ipv6"], addresses[node])
        obj.run.budget.assert_called_once_with(30)


if __name__ == "__main__":
    unittest.main()
