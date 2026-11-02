#!/usr/bin/env python3
"""Mock the physical-recovery/authorization boundary without external services."""
import importlib.util
from pathlib import Path
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "successor_recovery", Path(__file__).with_name("fly_cluster_recovery_rehearsal.py")
)
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


class PhysicalSecondaryRevocation(unittest.TestCase):
    def fixture(self):
        obj = object.__new__(m.PhysicalBackupRehearsal)
        obj.tenant, obj.denied_user, obj.denied_token = "tenant", "secondary-user", "synthetic-token"
        obj.spare_device, obj.spare_credential = "spare-device", "spare-credential"
        obj.devices, obj.services = ["device-0"], ["service-0"]
        obj.denied_grant_revocation = object()  # An earlier proof must not be reused.
        for name in ("relay_command", "revocation_flags", "spare_probe", "grant_probe",
                     "all_routes", "assert_grant_revocation", "event"):
            setattr(obj, name, mock.Mock())
        obj.revoke_target_grant = mock.Mock(return_value={
            "before": {"active": True, "revision": 7},
            "after": {"active": False, "revision": 8},
        })
        return obj

    def test_physical_setup_passes_new_secondary_revocation_proof_to_inherited_assertion(self):
        obj = self.fixture()
        obj.setup_revocations()
        obj.revoke_target_grant.assert_called_once_with(obj.denied_user, obj.denied_token)
        self.assertIs(obj.denied_grant_revocation, obj.revoke_target_grant.return_value)
        obj.assert_grant_revocation.assert_called_once_with(
            obj.denied_user, obj.revoke_target_grant.return_value
        )
        self.assertEqual([call.args[1][0] for call in obj.relay_command.call_args_list],
                         ["revoke-credential"])
        self.assertEqual(obj.revocation_flags.call_args_list, [mock.call("1"), mock.call("0")])
        self.assertEqual(obj.spare_probe.call_args_list, [mock.call(False), mock.call(True)])
        self.assertEqual(obj.grant_probe.call_args_list, [mock.call(False), mock.call(True)])
        obj.all_routes.assert_called_once_with()
        obj.event.assert_called_once()

    def test_failed_secondary_revocation_cannot_use_old_proof_or_claim_completed_setup(self):
        obj = self.fixture()
        previous = obj.denied_grant_revocation
        obj.revoke_target_grant.side_effect = m.Refused("synthetic_revocation_failure")
        with self.assertRaisesRegex(m.Refused, "^synthetic_revocation_failure$"):
            obj.setup_revocations()
        self.assertIs(obj.denied_grant_revocation, previous)
        obj.assert_grant_revocation.assert_not_called()
        obj.all_routes.assert_not_called()
        obj.event.assert_not_called()
        self.assertEqual(obj.revocation_flags.call_args_list, [mock.call("1")])
        self.assertEqual(obj.spare_probe.call_args_list, [mock.call(False)])
        self.assertEqual(obj.grant_probe.call_args_list, [mock.call(False)])


if __name__ == "__main__":
    unittest.main()
