"""Static controls for the separate Fly cluster profile; no service execution."""
import base64
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import tomllib
import unittest


REPO = Path(__file__).resolve().parents[1]
PROFILE = REPO / 'deploy/fly/cluster'
SPEC = importlib.util.spec_from_file_location('fly_cluster_render', PROFILE / 'render.py')
renderer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(renderer)


class FlyClusterTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((PROFILE / 'inventory.example.json').read_bytes())
        self.temp = tempfile.TemporaryDirectory(prefix='fly-cluster-static-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def render(self, data=None):
        return renderer.render(self.data if data is None else data, example=True)

    def production(self):
        data = copy.deepcopy(self.data)
        data['purpose'] = 'deployment'
        data['oidc']['issuer'] = 'https://identity.cluster-owner.net/'
        for row in data['relays']:
            row['public_hostname'] = row['node_id'] + '.cluster-owner.net'
        return data

    def refused(self, mutate, example=True):
        data = copy.deepcopy(self.data if example else self.production())
        mutate(data)
        with self.assertRaises(renderer.ProfileError):
            renderer.render_to(data, self.root / 'output', example=example)
        self.assertFalse((self.root / 'output').exists())

    def test_five_profiles_have_exact_state_mounts_and_digest_images(self):
        files = self.render()
        manifest = json.loads(files['manifest.json'])
        self.assertEqual(set(manifest['roles']), {*renderer.NODES, 'redis', 'authority'})
        self.assertEqual(len(manifest['files']), 10)
        self.assertTrue(manifest['example_only'])
        self.assertFalse(manifest['live_deployment_authorized'])
        for name, role in manifest['roles'].items():
            fly = tomllib.loads(files[role['fly_config']].decode())
            self.assertEqual(fly['build']['image'], self.data['images'][role['role']])
            self.assertEqual(fly['mounts'], {'source': role['volume'], 'destination': role['state_dir']})
            self.assertEqual(role['required_machines'], 1)
            self.assertEqual(fly['vm'], [{'cpu_kind': 'shared', 'cpus': 1, 'memory': 512}])
            self.assertNotIn('initial_size', fly['mounts'])
            self.assertEqual(fly['deploy']['strategy'], 'immediate')
            self.assertEqual(fly['kill_signal'], 'SIGTERM')
        for name, digest in manifest['files'].items():
            self.assertEqual(hashlib.sha256(files[name]).hexdigest(), digest)

    def test_render_is_deterministic_and_every_file_is_valid_structured_data(self):
        first, second = self.render(), self.render(copy.deepcopy(self.data))
        self.assertEqual(first, second)
        for name, data in first.items():
            if name.endswith('.toml'):
                tomllib.loads(data.decode())
            else:
                json.loads(data)

    def test_new_incarnation_uses_fresh_membership_path_without_moving_other_state(self):
        old = self.render()
        candidate = copy.deepcopy(self.data)
        candidate['deployment_incarnation'] += '-recovered'
        candidate['membership']['revision'] += 1
        new = self.render(candidate)
        self.assertEqual(old['authority/authority.toml'], new['authority/authority.toml'])
        for node in renderer.NODES:
            before = tomllib.loads(old[node + '/relay.toml'].decode())
            after = tomllib.loads(new[node + '/relay.toml'].decode())
            self.assertEqual(before['recovery'], after['recovery'])
            self.assertEqual(tomllib.loads(old[node + '/fly.toml'].decode())['mounts'],
                             tomllib.loads(new[node + '/fly.toml'].decode())['mounts'])
            self.assertNotEqual(before['cluster']['membership_version_state_path'],
                                after['cluster']['membership_version_state_path'])
            for config, incarnation in ((before, self.data['deployment_incarnation']),
                                        (after, candidate['deployment_incarnation'])):
                expected = '/var/lib/agent-tunnel/state/membership-version-' + hashlib.sha256(
                    incarnation.encode('utf-8')).hexdigest() + '.json'
                self.assertEqual(config['cluster']['membership_version_state_path'], expected)

    def test_same_incarnation_image_update_keeps_membership_path_and_state_volume(self):
        before = self.render()
        update = copy.deepcopy(self.data)
        update['images']['relay'] = 'sha256:' + 'a' * 64
        after = self.render(update)
        for node in renderer.NODES:
            old = tomllib.loads(before[node + '/relay.toml'].decode())
            new = tomllib.loads(after[node + '/relay.toml'].decode())
            self.assertEqual(old['cluster']['membership_version_state_path'],
                             new['cluster']['membership_version_state_path'])
            self.assertEqual(old['recovery'], new['recovery'])
            self.assertEqual(tomllib.loads(before[node + '/fly.toml'].decode())['mounts'],
                             tomllib.loads(after[node + '/fly.toml'].decode())['mounts'])

    def test_membership_path_derivation_refuses_unvalidated_incarnations(self):
        for value in ('', '../old', '/outside', 'x' * 65, 'x\n', 'é', None, True, 1):
            with self.subTest(value=value), self.assertRaises(renderer.ProfileError):
                renderer.membership_state_path(value)

    def test_readiness_metrics_remain_container_loopback_without_fly_service(self):
        files = self.render()
        for node in ('relay-a', 'relay-b', 'relay-c'):
            config = tomllib.loads(files[node + '/relay.toml'].decode())
            fly = tomllib.loads(files[node + '/fly.toml'].decode())
            self.assertEqual(config['metrics_bind'], '[::1]:9100')
            self.assertEqual({service['internal_port'] for service in fly['services']}, {8443, 9443})
            self.assertNotIn('9100', files[node + '/fly.toml'].decode())

    def test_three_hosts_and_shared_authority_scope_match_without_override_slots(self):
        files = self.render()
        hosts = [r['app'] + '.internal' for r in self.data['relays']]
        inventory = json.loads(files['authority/inventory.json'])
        authority = tomllib.loads(files['authority/authority.toml'].decode())
        self.assertEqual(authority['bind'], '[::]:8444')
        self.assertEqual(authority['endpoint_policy'], {
            'allowed_hosts': hosts, 'allowed_server_names': hosts, 'allowed_ports': [7443]})
        for relay in self.data['relays']:
            name = relay['node_id']
            config = tomllib.loads(files[name + '/relay.toml'].decode())
            self.assertEqual(config['node_id'], name)
            self.assertEqual(config['consumer_bind'], '[::]:8443')
            self.assertEqual(config['device_bind'], '[::]:9443')
            self.assertEqual(config['deployment_incarnation'], inventory['deployment_incarnation'])
            self.assertEqual(config['redis_namespace'], inventory['redis_namespace'])
            self.assertEqual(config['cluster']['deployment_id'], inventory['deployment_id'])
            self.assertEqual(config['cluster']['peer_bind'], '[::]:7443')
            self.assertEqual(config['cluster']['endpoint_policy']['allowed_hosts'], hosts)
            self.assertEqual(config['cluster']['endpoint_policy']['allowed_server_names'], hosts)
            self.assertEqual(config['cluster']['endpoint_policy']['allowed_ports'], [7443])
            self.assertEqual(config['cluster']['checkpoint_authority_endpoint'],
                             'https://' + self.data['authority']['app'] + '.internal:8444/v1/checkpoint')
            self.assertNotIn('boot_id', config)
            self.assertNotIn('redis_restart_continuity_seconds', config)
            self.assertNotIn('redis_url', config)
            self.assertEqual(config['rotation'], {'interval_seconds': 300,
                                                 'handshake_timeout_seconds': 10,
                                                 'overlap_seconds': 30})
            self.assertEqual(config['listener_max_connections'], 64)
            node = next(n for n in inventory['nodes'] if n['node_id'] == name)
            self.assertEqual(node['peer_endpoint'], relay['app'] + '.internal:7443')
            self.assertEqual(node['server_name'], relay['app'] + '.internal')
            self.assertEqual(node['checkpoint_client_spkis'], [relay['checkpoint_client_spki']])

    def test_tls_passthrough_and_verified_consumer_readiness_gate_are_retained(self):
        files = self.render()
        for relay in self.data['relays']:
            fly = tomllib.loads(files[relay['node_id'] + '/fly.toml'].decode())
            self.assertEqual(len(fly['services']), 2)
            consumer, device = fly['services']
            for service, port, internal in ((consumer, 443, 8443), (device, 9443, 9443)):
                self.assertEqual(service['protocol'], 'tcp')
                self.assertEqual(service['ports'], [{'port': port}])
                self.assertEqual(service['internal_port'], internal)
                self.assertEqual(service['auto_stop_machines'], 'off')
                self.assertFalse(service['auto_start_machines'])
                self.assertEqual(service['min_machines_running'], 1)
            check = consumer['http_checks'][0]
            self.assertEqual(check['path'], '/readyz')
            self.assertEqual(check['protocol'], 'https')
            self.assertEqual(check['tls_server_name'], relay['public_hostname'])
            self.assertIs(check['tls_skip_verify'], False)
        for role in ('redis', 'authority'):
            private = tomllib.loads(files[role + '/fly.toml'].decode())
            self.assertNotIn('services', private)
            self.assertNotIn('http_service', private)

    def test_entrypoint_environment_and_paths_are_bound_to_rendered_bytes(self):
        files = self.render()
        for node in renderer.NODES:
            fly = tomllib.loads(files[node + '/fly.toml'].decode())
            env = fly['env']
            self.assertEqual(base64.b64decode(env['AT_CLUSTER_CONFIG_B64']), files[node + '/relay.toml'])
            self.assertEqual(env['AT_CLUSTER_REDIS_HOST'], self.data['redis']['app'] + '.internal')
            self.assertEqual(env['AT_CLUSTER_PUBLISHER_USER'], self.data['redis']['publisher_user'])
            self.assertNotIn('AT_REDIS_URL', env)
            config = tomllib.loads(files[node + '/relay.toml'].decode())
            self.assertEqual(config['cluster']['membership_version_state_path'],
                             '/var/lib/agent-tunnel/state/membership-version-' + hashlib.sha256(
                                 self.data['deployment_incarnation'].encode('utf-8')).hexdigest() + '.json')
            self.assertEqual(config['recovery']['fence_path'],
                             '/var/lib/agent-tunnel/state/recovery-approval-fence.json')
            self.assertTrue(config['cluster']['checkpoint_authority_client_private_key'].endswith(
                '/secrets/checkpoint-client-key.pem'))
        authority = tomllib.loads(files['authority/fly.toml'].decode())['env']
        self.assertEqual(base64.b64decode(authority['AT_CLUSTER_INVENTORY_B64']),
                         files['authority/inventory.json'])
        self.assertEqual(base64.b64decode(authority['AT_CLUSTER_CONFIG_B64']),
                         files['authority/authority.toml'])
        redis = tomllib.loads(files['redis/fly.toml'].decode())['env']
        self.assertEqual(redis, {'AT_CLUSTER_REDIS_NAMESPACE': self.data['redis_namespace'],
                                'AT_CLUSTER_PUBLISHER_USER': self.data['redis']['publisher_user']})

    def test_supported_http_profiles_are_explicit_and_cua_is_disabled(self):
        config = tomllib.loads(self.render()['relay-a/relay.toml'].decode())
        self.assertEqual(config['http_forward']['profiles'],
                         ['mcp-2026-07-28', 'mcp-2025-11-25', 'acp-http-v1'])

    def test_example_cannot_be_rendered_without_explicit_selection(self):
        with self.assertRaises(renderer.ProfileError):
            renderer.render(self.data)
        with self.assertRaises(renderer.ProfileError):
            renderer.render(self.production(), example=True)
        manifest = json.loads(renderer.render(self.production())['manifest.json'])
        self.assertEqual(manifest['purpose'], 'deployment')
        self.assertFalse(manifest['example_only'])
        self.assertFalse(manifest['live_deployment_authorized'])

    def test_docker_config_identity_is_example_only_and_never_registry_provenance(self):
        data = copy.deepcopy(self.data)
        data['images']['relay'] = 'sha256:' + 'a' * 64
        manifest = json.loads(self.render(data)['manifest.json'])
        self.assertEqual(manifest['image_identity_kind']['relay'], 'docker-config')
        self.assertEqual(manifest['image_identity_kind']['redis'], 'registry-manifest')
        self.refused(lambda d: d['images'].update(relay='sha256:' + 'a' * 64), example=False)
        self.refused(lambda d: d.update(image_identity_kind={'relay': 'registry-manifest'}))

    def test_mutable_images_and_image_injection_are_refused_in_both_modes(self):
        for example in (True, False):
            for value in ('registry.fly.io/app:latest', 'registry.fly.io/app:main',
                          'https://registry.fly.io/app@sha256:' + 'a' * 64,
                          'registry.fly.io/app@sha256:' + '0' * 64,
                          'registry.fly.io/app@sha256:' + 'A' * 64,
                          'sha256:short', 'secret\n[env]\nTOKEN="sentinel"'):
                with self.subTest(example=example, value=value):
                    self.refused(lambda d: d['images'].update(relay=value), example)

    def test_missing_extra_and_colliding_nodes_apps_volumes_are_refused(self):
        cases = [lambda d: d['relays'].pop(),
                 lambda d: d['relays'].append(copy.deepcopy(d['relays'][0])),
                 lambda d: d['relays'][1].update(node_id='relay-a'),
                 lambda d: d['relays'][0].update(node_id='../redis'),
                 lambda d: d['redis'].update(app=d['authority']['app']),
                 lambda d: d['redis'].update(volume=d['relays'][0]['volume']),
                 lambda d: d['relays'][1].update(public_hostname=d['relays'][0]['public_hostname'])]
        for index, change in enumerate(cases):
            with self.subTest(index=index):
                self.refused(change)

    def test_unknown_fields_include_secrets_and_shared_identity_overrides(self):
        for change in (
            lambda d: d.update(password='DO-NOT-ECHO'),
            lambda d: d['relays'][0].update(deployment_id='another-deployment'),
            lambda d: d['membership'].update(private_key='DO-NOT-ECHO'),
            lambda d: d['redis'].update(redis_url='rediss://default:' + 'DO-NOT-ECHO' + '@host/0'),
            lambda d: d['authority'].update(allowed_hosts=['unapproved.internal']),
            lambda d: d['relays'][0]['peer_key'].update(revoked=False),
            lambda d: d['images'].update(client='sha256:' + 'a' * 64),
        ):
            self.refused(change)

    def test_private_routes_and_authority_require_explicit_ipv6_binds(self):
        for key, values in [('peer_bind', ['0.0.0.0:7443', '127.0.0.1:7443', '[::1]:7443', '[::]:443']),
                            ('authority_bind', ['0.0.0.0:8444', '[::1]:8444', '[::]:443'])]:
            for value in values:
                with self.subTest(key=key, value=value):
                    self.refused(lambda d: d.update({key: value}))

    def test_public_readiness_refuses_private_ca_assertion_or_bad_names(self):
        self.refused(lambda d: d['relays'][0].update(consumer_certificate_trust='private'))
        for host in ['*.example.net', 'relay.internal', '127.0.0.1', 'host/path',
                     'host:443', 'Relay.example.net', 'relay..example.net', 'secret\nvalue']:
            self.refused(lambda d: d['relays'][0].update(public_hostname=host))
        self.refused(lambda d: d['relays'][0].update(public_hostname='relay.synthetic.invalid'), False)

    def test_oidc_refuses_credentials_http_query_fragment_and_duplicate_audiences(self):
        for issuer in ['http://issuer.test/', 'https://name:' + 'DO-NOT-ECHO' + '@issuer.test/',
                       'https://issuer.test/?token=DO-NOT-ECHO', 'https://issuer.test/#fragment',
                       'https://issuer.test:8443/', 'https://issuer.test/\n[env]',
                       'https://issuer.test:invalid/']:
            self.refused(lambda d: d['oidc'].update(issuer=issuer))
        for audiences in [[], ['a', 'a'], ['a'] * 9, ['DO-NOT-ECHO\n'], 'a']:
            self.refused(lambda d: d['oidc'].update(audiences=audiences))

    def test_key_window_identity_and_revision_refusals_are_not_time_relaxations(self):
        for change in (
            lambda d: d['relays'][0]['peer_key'].update(not_before='2030-01-03T00:00:00Z'),
            lambda d: d['relays'][0]['peer_key'].update(expires_at=d['evaluation_time']),
            lambda d: d['relays'][0]['peer_key'].update(expires_at='2030-02-30T00:00:00Z'),
            lambda d: d['relays'][0]['peer_key'].update(spki_sha256='0' * 64),
            lambda d: d['relays'][0].update(checkpoint_client_spki=d['relays'][0]['peer_key']['spki_sha256']),
            lambda d: d['relays'][1].update(checkpoint_client_spki=d['relays'][0]['checkpoint_client_spki']),
            lambda d: d['membership'].update(revision=0),
            lambda d: d['membership'].update(revision=True),
            lambda d: d['membership'].update(publisher_public_key='not-a-key'),
        ):
            self.refused(change)

    def test_resource_and_namespace_values_are_explicit_bounded_and_not_booleans(self):
        for change in (
            lambda d: d.pop('region'), lambda d: d.update(region='SYD'),
            lambda d: d.update(redis_namespace='wrong:namespace'),
            lambda d: d['redis'].update(publisher_user='default'),
            lambda d: d['redis'].update(publisher_user='name\ncommand'),
            lambda d: d['authority'].update(memory_mb=True),
            lambda d: d['authority'].update(memory_mb=255),
            lambda d: d['authority'].update(memory_mb=513),
            lambda d: d['authority'].update(volume_size_gb=0),
        ):
            self.refused(change)

    def test_duplicate_json_fields_and_oversized_files_are_refused(self):
        path = self.root / 'input.json'
        path.write_text('{"schema_version":1,"schema_version":1}')
        with self.assertRaisesRegex(renderer.ProfileError, 'duplicate-json-key'):
            renderer.load_inventory(path)
        path.write_bytes(b'x' * (renderer.MAX_INPUT + 1))
        with self.assertRaises(renderer.ProfileError):
            renderer.load_inventory(path)

    def test_create_only_output_keeps_previous_manifest_and_files(self):
        path = self.root / 'output'
        manifest = renderer.render_to(self.data, path, example=True)
        original = {p.relative_to(path): p.read_bytes() for p in path.rglob('*') if p.is_file()}
        with self.assertRaisesRegex(renderer.ProfileError, 'output-already-exists'):
            renderer.render_to(self.data, path, example=True)
        self.assertEqual(original, {p.relative_to(path): p.read_bytes() for p in path.rglob('*') if p.is_file()})
        self.assertEqual(json.loads((path / 'manifest.json').read_bytes()), manifest)

    def test_symlink_input_output_and_parent_are_refused(self):
        source = self.root / 'inventory.json'
        source.write_text(json.dumps(self.data))
        link = self.root / 'input-link'
        try:
            link.symlink_to(source)
        except (OSError, NotImplementedError):
            self.skipTest('host does not permit creating a symlink')
        with self.assertRaises(renderer.ProfileError):
            renderer.load_inventory(link)
        out = self.root / 'output-link'
        out.symlink_to(self.root / 'absent')
        with self.assertRaises(renderer.ProfileError):
            renderer.render_to(self.data, out, example=True)
        parent = self.root / 'parent-link'
        parent.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(renderer.ProfileError):
            renderer.render_to(self.data, parent / 'output', example=True)
        self.assertFalse((self.root / 'output').exists())

    def test_refusal_diagnostics_never_echo_sentinel_credentials(self):
        self.data['oidc']['issuer'] = 'https://user:' + 'SECRET-SENTINEL' + '@issuer.test/'
        source = self.root / 'input.json'
        source.write_text(json.dumps(self.data))
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = renderer.main(['--inventory', str(source), '--output', str(self.root / 'out'), '--example'])
        self.assertEqual(status, 1)
        self.assertEqual(stdout.getvalue(), '')
        self.assertNotIn('SECRET-SENTINEL', stderr.getvalue())
        self.assertTrue(stderr.getvalue().startswith('fly-cluster: invalid-oidc-issuer'))
        self.assertFalse((self.root / 'out').exists())


if __name__ == '__main__':
    unittest.main()
