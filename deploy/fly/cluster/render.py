#!/usr/bin/env python3
"""Render an explicit three-relay Fly profile without credentials or network I/O."""
import argparse
import base64
import datetime
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import stat
import string
import sys
import tomllib
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parent
NODES = ('relay-a', 'relay-b', 'relay-c')
MAX_INPUT = 128 * 1024
RELAY_BASE = '/var/lib/agent-tunnel'
AUTHORITY_BASE = '/var/lib/agentuplink-authority'


class ProfileError(ValueError):
    """A closed diagnostic label, never an input value or credential."""


def require(condition, label):
    if not condition:
        raise ProfileError(label)


def fields(value, expected, label):
    require(type(value) is dict and set(value) == set(expected), label)


def text(value, pattern, label):
    require(type(value) is str and re.fullmatch(pattern, value) is not None, label)


def number(value, minimum, maximum, label):
    require(type(value) is int and minimum <= value <= maximum, label)


def membership_state_path(incarnation):
    text(incarnation, r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}', 'invalid-shared-identity')
    return RELAY_BASE + '/state/membership-version-' + hashlib.sha256(
        incarnation.encode('utf-8')).hexdigest() + '.json'


def digest(value, label):
    text(value, r'[0-9a-f]{64}', label)
    require(value != '0' * 64, label)


def hostname(value, example, label):
    text(value, r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?', label)
    require('.' in value and all(
        re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
        for part in value.split('.')), label)
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ProfileError(label)
    require(not value.endswith(('.internal', '.localhost')) and value != 'localhost', label)
    if not example:
        require(not value.endswith(('.test', '.invalid', '.example'))
                and value not in ('example.com', 'example.net', 'example.org')
                and not value.endswith(('.example.com', '.example.net', '.example.org')), label)


def instant(value):
    text(value, r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', 'invalid-key-time')
    try:
        return datetime.datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ')
    except ValueError:
        raise ProfileError('invalid-key-time') from None


def service(value, extra):
    fields(value, {'app', 'volume', 'memory_mb', 'volume_size_gb'} | set(extra),
           'invalid-service-fields')
    text(value['app'], r'[a-z][a-z0-9-]{1,61}[a-z0-9]', 'invalid-app')
    text(value['volume'], r'[a-z][a-z0-9_]{0,29}', 'invalid-volume')
    number(value['memory_mb'], 256, 32768, 'invalid-memory')
    require(value['memory_mb'] % 256 == 0, 'invalid-memory')
    number(value['volume_size_gb'], 1, 1024, 'invalid-volume-size')


def validate_inventory(data, example=False):
    fields(data, {'schema_version', 'purpose', 'region', 'deployment_id',
                  'deployment_incarnation', 'redis_namespace', 'evaluation_time',
                  'peer_bind', 'authority_bind', 'images', 'oidc', 'membership',
                  'relays', 'redis', 'authority'}, 'invalid-inventory-fields')
    require(type(data['schema_version']) is int and data['schema_version'] == 1,
            'unsupported-schema')
    require(data['purpose'] == ('example' if example else 'deployment'),
            'purpose-requires-explicit-example-selection')
    text(data['region'], r'[a-z]{3}', 'invalid-region')
    for key in ('deployment_id', 'deployment_incarnation', 'redis_namespace'):
        text(data[key], r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}', 'invalid-shared-identity')
    # Explicit IPv6 binds also set the outbound QUIC address family in serve.
    require(data['peer_bind'] == '[::]:7443', 'private-peer-bind-must-be-ipv6-7443')
    require(data['authority_bind'] == '[::]:8444', 'authority-bind-must-be-ipv6-8444')
    at = instant(data['evaluation_time'])
    fields(data['images'], {'relay', 'redis', 'authority'}, 'invalid-image-fields')
    for value in data['images'].values():
        if example and type(value) is str and re.fullmatch(r'sha256:[0-9a-f]{64}', value):
            digest(value[7:], 'invalid-image-digest')
            continue
        text(value, r'registry\.fly\.io/[a-z][a-z0-9-]{1,61}[a-z0-9]@sha256:[0-9a-f]{64}',
             'immutable-fly-image-required')
        digest(value.rsplit(':', 1)[1], 'invalid-image-digest')
    fields(data['oidc'], {'issuer', 'audiences'}, 'invalid-oidc-fields')
    issuer = data['oidc']['issuer']
    require(type(issuer) is str and len(issuer) <= 1024 and issuer.isascii()
            and not any(c.isspace() for c in issuer), 'invalid-oidc-issuer')
    try:
        parsed = urlsplit(issuer)
        require(parsed.scheme == 'https' and parsed.hostname is not None
                and parsed.username is None and parsed.password is None
                and not parsed.query and not parsed.fragment and parsed.port in (None, 443),
                'invalid-oidc-issuer')
        hostname(parsed.hostname, example, 'invalid-oidc-host')
    except ValueError:
        raise ProfileError('invalid-oidc-issuer') from None
    audiences = data['oidc']['audiences']
    require(type(audiences) is list and 1 <= len(audiences) <= 8, 'invalid-oidc-audiences')
    for audience in audiences:
        text(audience, r'[a-zA-Z0-9][a-zA-Z0-9:/_.-]{0,127}', 'invalid-oidc-audience')
    require(len(set(audiences)) == len(audiences), 'duplicate-oidc-audience')
    fields(data['membership'], {'revision', 'publisher_key_id', 'publisher_public_key'},
           'invalid-membership-fields')
    number(data['membership']['revision'], 1, 2**63 - 1, 'invalid-membership-revision')
    text(data['membership']['publisher_key_id'], r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}',
         'invalid-publisher-key-id')
    digest(data['membership']['publisher_public_key'], 'invalid-publisher-public-key')
    require(type(data['relays']) is list and len(data['relays']) == 3, 'exactly-three-relays-required')
    pins = []
    for relay in data['relays']:
        service(relay, {'node_id', 'public_hostname', 'consumer_certificate_trust',
                        'peer_key', 'checkpoint_client_spki'})
        require(relay['node_id'] in NODES, 'invalid-node-id')
        hostname(relay['public_hostname'], example, 'invalid-public-hostname')
        require(relay['consumer_certificate_trust'] == 'public',
                'publicly-trusted-consumer-certificate-required-for-fly-readiness')
        fields(relay['peer_key'], {'key_id', 'spki_sha256', 'not_before', 'expires_at'},
               'invalid-peer-key-fields')
        key = relay['peer_key']
        text(key['key_id'], r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}', 'invalid-peer-key-id')
        digest(key['spki_sha256'], 'invalid-peer-spki')
        digest(relay['checkpoint_client_spki'], 'invalid-checkpoint-spki')
        require(instant(key['not_before']) <= at < instant(key['expires_at']),
                'peer-key-inactive-at-evaluation-time')
        pins.extend([key['spki_sha256'], relay['checkpoint_client_spki']])
    require({r['node_id'] for r in data['relays']} == set(NODES), 'duplicate-node-id')
    require(len({r['public_hostname'] for r in data['relays']}) == 3, 'duplicate-public-hostname')
    require(len(set(pins)) == 6, 'distinct-peer-and-checkpoint-identities-required')
    service(data['redis'], {'publisher_user'})
    text(data['redis']['publisher_user'], r'[a-z][a-z0-9_-]{0,31}', 'invalid-publisher-user')
    require(data['redis']['publisher_user'] != 'default', 'publisher-must-be-named-user')
    service(data['authority'], set())
    services = [*data['relays'], data['redis'], data['authority']]
    for key in ('app', 'volume'):
        require(len({s[key] for s in services}) == 5, 'duplicate-' + key)
    return data


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate-json-key')
        result[key] = value
    return result


def no_symlink(path):
    for part in (path, *path.parents):
        require(not part.is_symlink(), 'symlink-path-refused')


def load_inventory(path):
    path = Path(path).absolute()
    no_symlink(path)
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= MAX_INPUT, 'invalid-inventory-file')
    with path.open('rb') as source:
        raw = source.read(MAX_INPUT + 1)
    require(0 < len(raw) <= MAX_INPUT, 'invalid-inventory-file')
    try:
        return json.loads(raw, object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError):
        raise ProfileError('invalid-inventory-json') from None


def encoded(data):
    return base64.b64encode(data).decode('ascii')


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def render(data, example=False):
    validate_inventory(data, example)
    relays = sorted(data['relays'], key=lambda r: r['node_id'])
    hosts = [r['app'] + '.internal' for r in relays]
    redis_host = data['redis']['app'] + '.internal'
    publisher = data['redis']['publisher_user']
    output, template_hashes, roles = {}, {}, {}

    def template(name, values):
        source = (ROOT / 'templates' / name).read_bytes()
        template_hashes[name] = sha(source)
        # Every substituted value is encoded as a TOML value, not raw syntax.
        result = string.Template(source.decode()).substitute(
            {key: json.dumps(value, ensure_ascii=True) for key, value in values.items()})
        tomllib.loads(result)
        return result.encode()

    inventory = {
        'schema_version': 1, 'deployment_id': data['deployment_id'],
        'redis_namespace': data['redis_namespace'],
        'deployment_incarnation': data['deployment_incarnation'],
        **data['membership'], 'nodes': [
            {'node_id': r['node_id'], 'peer_endpoint': r['app'] + '.internal:7443',
             'server_name': r['app'] + '.internal',
             'keys': [{**r['peer_key'], 'revoked': False}],
             'checkpoint_client_spkis': [r['checkpoint_client_spki']]}
            for r in relays],
    }
    authority_inventory = json_bytes(inventory)
    for name, role, item in [*( (r['node_id'], 'relay', r) for r in relays),
                             ('authority', 'authority', data['authority']),
                             ('redis', 'redis', data['redis'])]:
        base = RELAY_BASE if role == 'relay' else AUTHORITY_BASE
        state_dir = base + '/state' if role != 'redis' else '/data'
        values = {'app': item['app'], 'region': data['region'], 'image': data['images'][role],
                  'memory_mb': item['memory_mb'], 'volume': item['volume'],
                  'state_dir': state_dir, 'redis_host': redis_host,
                  'publisher_user': publisher, 'redis_namespace': data['redis_namespace']}
        config_path = None
        if role == 'relay':
            config = template('relay.toml.in', {
                'issuer': data['oidc']['issuer'], 'audiences': data['oidc']['audiences'],
                'namespace': data['redis_namespace'], 'node_id': name,
                'deployment_id': data['deployment_id'],
                'incarnation': data['deployment_incarnation'], 'peer_bind': data['peer_bind'],
                'membership_state_path': membership_state_path(data['deployment_incarnation']),
                'hosts': hosts, 'checkpoint_endpoint': 'https://' + data['authority']['app']
                    + '.internal:8444/v1/checkpoint'})
            config_path = name + '/relay.toml'
            output[config_path] = config
            values.update(config_b64=encoded(config), public_hostname=item['public_hostname'])
            fly = template('relay-fly.toml.in', values)
        elif role == 'authority':
            config = template('authority.toml.in', {'bind': data['authority_bind'], 'hosts': hosts})
            config_path = 'authority/authority.toml'
            output[config_path] = config
            output['authority/inventory.json'] = authority_inventory
            values.update(config_b64=encoded(config), inventory_b64=encoded(authority_inventory))
            fly = template('authority-fly.toml.in', values)
        else:
            fly = template('redis-fly.toml.in', values)
        output[name + '/fly.toml'] = fly
        roles[name] = {'app': item['app'], 'role': role, 'node_id': name if role == 'relay' else None,
                       'fly_config': name + '/fly.toml', 'config': config_path,
                       'volume': item['volume'], 'volume_size_gb': item['volume_size_gb'],
                       'state_dir': state_dir, 'required_machines': 1}
    manifest = {'schema_version': 1, 'purpose': data['purpose'],
                'example_only': example, 'live_deployment_authorized': False,
                'image_identity_kind': {role: 'docker-config' if value.startswith('sha256:')
                                        else 'registry-manifest' for role, value in data['images'].items()},
                'scope': 'rendered configuration only; no registry, PKI, Fly, runtime or readiness verification',
                'evaluation_time': data['evaluation_time'],
                'deployment': {k: data[k] for k in
                               ('deployment_id', 'redis_namespace', 'deployment_incarnation')},
                'images': data['images'], 'roles': roles,
                'inputs': {'inventory_sha256': sha(json_bytes(data)),
                           'renderer_sha256': sha(Path(__file__).read_bytes()),
                           'templates': template_hashes},
                'files': {name: sha(value) for name, value in sorted(output.items())}}
    output['manifest.json'] = json_bytes(manifest)
    return output


def render_to(data, output, example=False):
    files = render(data, example)
    output = Path(output).absolute()
    no_symlink(output)
    require(output.parent.is_dir(), 'output-parent-missing')
    require(not output.exists(), 'output-already-exists')
    # Reserve the directory create-only. The manifest is written last: an I/O
    # failure retains an incomplete directory, never overwrites an earlier run.
    output.mkdir(mode=0o700)
    for name in sorted(files, key=lambda p: (p == 'manifest.json', p)):
        destination = output / name
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with destination.open('xb') as target:
            target.write(files[name])
        destination.chmod(0o600)
    return json.loads(files['manifest.json'])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--example', action='store_true', help='explicitly render synthetic example inputs')
    args = parser.parse_args(argv)
    try:
        manifest = render_to(load_inventory(args.inventory), args.output, args.example)
    except (OSError, ValueError, TypeError, KeyError, OverflowError) as error:
        label = str(error) if isinstance(error, ProfileError) else 'profile-input-or-output-refused'
        print('fly-cluster: ' + label, file=sys.stderr)
        return 1
    print('Rendered five ' + manifest['purpose'] + ' profiles; no deployment or readiness verified.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
