#!/usr/bin/env python3
"""Pure/mock authorization scenario controls; no native or network execution."""
import base64
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("authorization_rehearsal", Path(__file__).with_name("fly_cluster_rehearsal.py"))
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


class AuthorizationScenario(unittest.TestCase):
    def fixture(self):
        obj = object.__new__(m.Rehearsal)
        obj.run = mock.Mock(stage="restart_revocation")
        obj.run.echo_response_diagnostic_failure = None
        obj.tenant, obj.user = "tenant", "primary-user"
        obj.inventory = {"redis_namespace": "owned-namespace"}
        obj.devices, obj.services = ["device-" + str(i) for i in range(3)], ["service-" + str(i) for i in range(3)]
        obj.consumer_ports, obj.public_hosts = [8443, 8444, 8445], ["a.invalid", "b.invalid", "c.invalid"]
        obj.public_context, obj.token, obj.scope_token = object(), "normal-private-token", "scope-private-token"
        obj.canaries = ["private-canary-" + str(i) for i in range(3)]
        obj.event, obj.owner = mock.Mock(), mock.Mock()
        obj.grant_revoked = False
        obj.grant_revocation = {"before": {"active": True, "revision": 7}, "after": {"active": False, "revision": 8}}
        return obj

    def test_revoked_sole_grant_routes_remain_exact_and_other_six_routes_positive(self):
        obj = self.fixture()
        obj.grant_revoked = True
        obj.assert_grant_revocation = mock.Mock()
        def response(_port, _host, _context, path, **kwargs):
            index = next(i for i in range(3) if "/" + obj.devices[i] + "/" in path)
            if index == 0:
                return 404, b'{"code":"DEVICE_NOT_FOUND","execution":"not_dispatched"}'
            return 200, obj.canaries[index].encode() + kwargs["data"]
        failure = None
        with mock.patch.object(m, "http_request", side_effect=response) as request:
            try:
                obj.all_routes()
            except m.Refused as error:
                failure = str(error)
        self.assertIsNone(failure, "fixture sole-grant revocation must use the documented exact visibility outcome")
        self.assertEqual(request.call_count, 9)
        self.assertEqual(obj.owner.call_args_list, [mock.call(0), mock.call(1), mock.call(2)])
        obj.assert_grant_revocation.assert_called_once_with(obj.user, obj.grant_revocation)
        self.assertEqual(obj.event.call_count, 3)
        for event in obj.event.call_args_list:
            self.assertEqual(event.kwargs["status"], 404)
            self.assertEqual(event.kwargs["expected_status"], 404)
            self.assertTrue(event.kwargs["expected_denial_fields_match"])
            self.assertFalse(event.kwargs["expected_echo_body_match"])

    def discovery(self):
        return [{"tenant_id": "tenant", "device_id": "device-0", "active": True,
                 "services": [{"tenant_id": "tenant", "device_id": "device-0", "service_id": "service-0",
                               "service_type": "echo", "active": True}]}]

    def test_scope_token_reuses_original_signer_claims_and_jwks_without_regeneration(self):
        with tempfile.TemporaryDirectory() as directory:
            pki = object.__new__(m.PKI)
            pki.root = Path(directory)
            calls = []
            def openssl(args, data=None):
                calls.append((args, data))
                if args[0] == "rsa":
                    return b"Modulus=01020304"
                return b"synthetic-signature"
            pki.openssl = openssl
            with mock.patch.object(m.time, "time", return_value=1000):
                jwks, normal = pki.jwt("https://issuer.invalid", "synthetic-user")
                scoped = pki.scope_refusal_token()
            def decode(token, index):
                part = token.split(".")[index]
                return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
            self.assertEqual(decode(normal, 0), decode(scoped, 0))
            self.assertEqual(decode(normal, 0)["kid"], json.loads(jwks)["keys"][0]["kid"])
            normal_claims, scope_claims = decode(normal, 1), decode(scoped, 1)
            self.assertEqual(normal_claims.pop("scope"), "echo:invoke")
            self.assertEqual(normal_claims, scope_claims)
            self.assertEqual(pki.primary_claims["scope"], "echo:invoke")
            self.assertEqual(sum(args[0] == "genpkey" for args, _ in calls), 1)
            signs = [(args, data) for args, data in calls if args[0] == "dgst"]
            self.assertEqual(len(signs), 2)
            self.assertTrue(all(args == ["dgst", "-sha256", "-sign", str(pki.root / "oidc.key")] for args, _ in signs))

    def test_scope_refusal_has_discovery_and_normal_token_positive_before_after(self):
        obj = self.fixture()
        obj.grant_state = mock.Mock(return_value={"active": True, "revision": 7})
        calls = []
        def response(_port, _host, _context, path, **kwargs):
            token = kwargs["headers"]["Authorization"]
            calls.append((path, token))
            if path == "/v1/devices":
                return 200, json.dumps(self.discovery()).encode()
            if token == "Bearer " + obj.scope_token:
                return 403, b'{"code":"FORBIDDEN","execution":"not_dispatched"}'
            return 200, obj.canaries[0].encode() + kwargs["data"]
        original = obj.token
        with mock.patch.object(m, "http_request", side_effect=response) as request:
            obj.scope_refusal()
        self.assertEqual(request.call_count, 4)
        self.assertEqual([token for _, token in calls], ["Bearer " + original, "Bearer " + obj.scope_token,
                                                       "Bearer " + obj.scope_token, "Bearer " + original])
        self.assertEqual(calls[1][0], "/v1/devices")
        self.assertEqual(obj.token, original)
        self.assertEqual(obj.grant_state.call_args_list, [mock.call(obj.user), mock.call(obj.user)])
        self.assertEqual(obj.event.call_args.args[0], "consumer_scope_refusal")
        self.assertTrue(obj.event.call_args.kwargs["exact_echo_before_after"])
        self.assertNotIn(original, json.dumps(obj.event.call_args.kwargs))

    def test_scope_denial_refuses_other_statuses_and_always_restores_normal_token(self):
        for status in (200, 401, 404, 503):
            obj = self.fixture()
            obj.grant_state = mock.Mock(return_value={"active": True, "revision": 7})
            def response(_port, _host, _context, path, **kwargs):
                if path == "/v1/devices":
                    return 200, json.dumps(self.discovery()).encode()
                if kwargs["headers"]["Authorization"] == "Bearer " + obj.scope_token:
                    return status, b'{"code":"FORBIDDEN","execution":"not_dispatched"}'
                return 200, obj.canaries[0].encode() + kwargs["data"]
            saved = obj.token
            with self.subTest(status=status), mock.patch.object(m, "http_request", side_effect=response):
                with self.assertRaisesRegex(m.Refused, "^authorization_negative_status$"):
                    obj.scope_refusal()
            self.assertEqual(obj.token, saved)
            self.assertFalse(any(call.args[0] == "consumer_scope_refusal" for call in obj.event.call_args_list))

    def test_scope_control_refuses_inactive_or_changed_grant_without_mutation(self):
        for after in ({"active": False, "revision": 7}, {"active": True, "revision": 8}):
            obj = self.fixture()
            obj.grant_state = mock.Mock(side_effect=[{"active": True, "revision": 7}, after])
            obj.echo, obj.visible_echo_target, obj.relay_command = mock.Mock(), mock.Mock(), mock.Mock()
            with self.assertRaisesRegex(m.Refused, "^scope_control_grant_changed$"):
                obj.scope_refusal()
            obj.relay_command.assert_not_called()
        obj = self.fixture()
        obj.grant_state = mock.Mock(return_value={"active": False, "revision": 7})
        obj.echo = mock.Mock()
        with self.assertRaisesRegex(m.Refused, "^scope_control_grant_inactive$"):
            obj.scope_refusal()
        obj.echo.assert_not_called()

    def test_discovery_requires_exact_active_sole_echo_target(self):
        m.check_visible_echo_target(self.discovery(), "tenant", "device-0", "service-0")
        changes = [lambda v: v.clear(), lambda v: v.append(copy.deepcopy(v[0])),
                   lambda v: v[0].update(tenant_id="other"), lambda v: v[0].update(device_id="other"),
                   lambda v: v[0].update(active=1), lambda v: v[0].update(services=[]),
                   lambda v: v[0]["services"].append(copy.deepcopy(v[0]["services"][0]))]
        for field, value in (("tenant_id", "other"), ("device_id", "other"), ("service_id", "other"),
                             ("service_type", "fs"), ("active", False), ("active", 1)):
            changes.append(lambda v, field=field, value=value: v[0]["services"][0].update({field: value}))
        for index, change in enumerate(changes):
            value = self.discovery(); change(value)
            with self.subTest(index=index), self.assertRaises(m.Refused):
                m.check_visible_echo_target(value, "tenant", "device-0", "service-0")

    def test_discovery_error_retains_original_failure_and_closed_secondary_diagnostic(self):
        obj = self.fixture()
        obj.event.side_effect = OSError("private-output-path")
        with mock.patch.object(m, "http_request", return_value=(403, b'{"message":"private"}')):
            with self.assertRaisesRegex(m.Refused, "^grant_discovery_status$"):
                obj.visible_echo_target(obj.scope_token)
        self.assertEqual(obj.run.echo_response_diagnostic_failure, {"code": "echo_response_observation_failed"})

    def test_grant_state_is_atomic_exact_scoped_and_strict_u64(self):
        obj = self.fixture(); obj.redis = mock.Mock()
        obj.redis.command.return_value = ["1", "18446744073709551615"]
        self.assertEqual(obj.grant_state(obj.user), {"active": True, "revision": 2**64 - 1})
        obj.redis.command.assert_called_once_with("HMGET", "tunnel-catalog:owned-namespace:grant:tenant:primary-user:device-0:service-0", "active", "revision")
        for value in (None, [], ["1"], ["1", "2", "extra"], [True, "2"], [1, "2"], ["true", "2"],
                      ["0", 2], ["0", "0"], ["0", "02"], ["0", "-2"], ["0", "2.0"],
                      ["0", str(2**64)], ["0", None]):
            with self.subTest(value=value), self.assertRaises(m.Refused):
                m.checked_grant_state(value)

    def test_revocation_requires_inactive_higher_revision_not_a_permission_substitute(self):
        before = {"active": True, "revision": 7}
        m.check_grant_revocation(before, {"active": False, "revision": 8})
        for after in ({"active": True, "revision": 8}, {"active": False, "revision": 7},
                      {"active": False, "revision": 6}, {"active": 0, "revision": 8},
                      {"active": False, "revision": 8.0}, {"active": False, "revision": True},
                      {"active": False, "revision": 2**64}, {"active": False}):
            with self.subTest(after=after), self.assertRaises(m.Refused):
                m.check_grant_revocation(before, after)
        with self.assertRaises(m.Refused):
            m.check_grant_revocation({"active": False, "revision": 7}, {"active": False, "revision": 8})

    def test_real_revoke_command_is_once_between_bound_observations(self):
        obj = self.fixture(); order = []
        obj.visible_echo_target = lambda token: order.append(("visible", token))
        states = iter([{"active": True, "revision": 7}, {"active": False, "revision": 8}])
        def read(principal):
            order.append(("state", principal)); return next(states)
        obj.grant_state = read
        obj.relay_command = lambda node, command: order.append(("command", node, command))
        proof = obj.revoke_target_grant(obj.user, obj.token)
        self.assertEqual(proof, obj.grant_revocation)
        self.assertEqual([row[0] for row in order], ["visible", "state", "command", "state"])
        self.assertEqual(order[2], ("command", "relay-a", ["revoke-grant", "--tenant", obj.tenant, "--user", obj.user,
                                                         "--device", obj.devices[0], "--service", obj.services[0]]))
        self.assertEqual(obj.event.call_args.kwargs, {"active": False, "before_revision": 7, "revision": 8})

    def test_lost_revoke_result_is_not_retried_or_relabelled_success(self):
        obj = self.fixture()
        obj.visible_echo_target = mock.Mock()
        obj.grant_state = mock.Mock(return_value={"active": True, "revision": 7})
        obj.relay_command = mock.Mock(side_effect=m.Refused("command_exit"))
        with self.assertRaisesRegex(m.Refused, "^command_exit$"):
            obj.revoke_target_grant(obj.user, obj.token)
        obj.relay_command.assert_called_once()
        obj.grant_state.assert_called_once()
        obj.event.assert_not_called()

    def test_persisted_revocation_refuses_reactivation_revision_change_and_invalid_proof(self):
        obj = self.fixture();obj.grant_state = mock.Mock(return_value=obj.grant_revocation["after"])
        obj.assert_grant_revocation(obj.user, obj.grant_revocation)
        for current in ({"active": True, "revision": 8}, {"active": False, "revision": 7}, {"active": False, "revision": 9}):
            obj.grant_state.return_value = current
            with self.subTest(current=current), self.assertRaisesRegex(m.Refused, "^grant_revocation_not_preserved$"):
                obj.assert_grant_revocation(obj.user, obj.grant_revocation)
        with self.assertRaisesRegex(m.Refused, "^grant_revocation_proof$"):
            obj.assert_grant_revocation(obj.user, {"after": obj.grant_revocation["after"]})

    def test_revocation_refuses_every_other_status_or_denial_identity(self):
        cases = [(status, {"code": "DEVICE_NOT_FOUND", "execution": "not_dispatched"}) for status in (200, 401, 403, 503)]
        cases += [(404, {"code": "SERVICE_NOT_FOUND", "execution": "not_dispatched"}),
                  (404, {"code": "DEVICE_NOT_FOUND", "execution": "unknown"})]
        for status, fields in cases:
            obj = self.fixture()
            with self.subTest(status=status, fields=fields), mock.patch.object(m, "http_request", return_value=(status, json.dumps(fields).encode())):
                with self.assertRaises(m.Refused):
                    obj.echo(0, 0, revoked=True)
        obj = self.fixture()
        with mock.patch.object(m, "http_request") as request:
            with self.assertRaisesRegex(m.Refused, "^echo_expectation$"):
                obj.echo(0, 0, denied=True, revoked=True)
        request.assert_not_called()

    def test_primary_all_routes_remain_nine_positive_when_only_secondary_grant_revoked(self):
        obj = self.fixture();obj.echo = mock.Mock();obj.assert_grant_revocation = mock.Mock()
        obj.all_routes()
        self.assertEqual(obj.echo.call_args_list, [mock.call(ingress, device, revoked=False) for device in range(3) for ingress in range(3)])
        obj.assert_grant_revocation.assert_not_called()


class RecoveryAuthorizationScenario(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("authorization_recovery", Path(__file__).with_name("fly_cluster_recovery_rehearsal.py"))
        cls.module = importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.module)

    def fixture(self):
        obj = object.__new__(self.module.RecoveryRehearsal)
        obj.tenant, obj.user, obj.denied_user = "tenant", "primary", "secondary"
        obj.devices, obj.services = ["device"], ["service"]
        obj.spare_device, obj.spare_credential = "spare-device", "spare-credential"
        obj.token, obj.denied_token = "normal-private", "secondary-private"
        obj.grant_revoked = False
        return obj

    def test_secondary_grant_probe_uses_exact_revocation_case_and_restores_token(self):
        for denied in (False, True):
            obj = self.fixture();calls = []
            obj.echo = lambda ingress, device, **kw: calls.append((ingress, device, obj.token, kw))
            obj.grant_probe(denied)
            self.assertEqual(calls, [(i, 0, obj.denied_token, {"revoked": denied}) for i in range(3)])
            self.assertEqual(obj.token, "normal-private")
            self.assertFalse(obj.grant_revoked)
        obj = self.fixture();obj.echo = mock.Mock(side_effect=RuntimeError("synthetic failure"))
        with self.assertRaises(RuntimeError):obj.grant_probe(True)
        self.assertEqual(obj.token, "normal-private")

    def test_secondary_setup_keeps_credential_revoke_and_stores_real_grant_proof(self):
        obj = self.fixture()
        obj.relay_command, obj.revocation_flags, obj.spare_probe, obj.grant_probe = [mock.Mock() for _ in range(4)]
        obj.revoke_target_grant = mock.Mock(return_value={"before": {"active": True, "revision": 1}, "after": {"active": False, "revision": 2}})
        obj.assert_revocations, obj.event = mock.Mock(), mock.Mock()
        obj.setup_revocations()
        self.assertEqual([call.args[1][0] for call in obj.relay_command.call_args_list],
                         ["add-device", "add-service", "add-user", "set-grant", "revoke-credential"])
        obj.revoke_target_grant.assert_called_once_with(obj.denied_user, obj.denied_token)
        self.assertEqual(obj.denied_grant_revocation, obj.revoke_target_grant.return_value)
        obj.assert_revocations.assert_called_once()
        self.assertFalse(obj.grant_revoked)

    def test_recovery_each_assertion_keeps_primary_positives_both_flags_and_revision_proof(self):
        obj = self.fixture();calls = []
        obj.denied_grant_revocation = {"before": {"active": True, "revision": 1}, "after": {"active": False, "revision": 2}}
        for method in ("all_routes", "revocation_flags", "assert_grant_revocation", "spare_probe", "grant_probe"):
            setattr(obj, method, lambda *args, method=method: calls.append((method, args)))
        obj.assert_revocations()
        self.assertEqual(calls, [("all_routes", ()), ("revocation_flags", ("0",)),
                                ("assert_grant_revocation", (obj.denied_user, obj.denied_grant_revocation)),
                                ("spare_probe", (True,)), ("grant_probe", (True,))])


if __name__ == "__main__":
    unittest.main()
