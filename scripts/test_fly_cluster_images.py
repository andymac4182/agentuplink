#!/usr/bin/env python3
"""Static/temporary-file cluster image checks; never execute a service/container."""
import ast
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import tomllib
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
IMAGES = ROOT / "deploy/fly/cluster/images"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


entry = load("cluster_image_entrypoint", IMAGES / "entrypoint.py")
renderer = load("cluster_image_test_renderer", ROOT / "deploy/fly/cluster/render.py")


def encoded(value):
    return base64.b64encode(value).decode("ascii")


class ImageBoundary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inventory = json.loads((ROOT / "deploy/fly/cluster/inventory.example.json").read_text())
        cls.rendered = renderer.render(cls.inventory, example=True)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="agentuplink-cluster-images-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.uid = os.geteuid()

    def fixture(self, role, name=None):
        base = self.root / (name or role)
        base.mkdir(mode=0o700)
        (base / "state").mkdir(mode=0o700)
        key = "relay-a" if role == "relay" else role
        env = dict(tomllib.loads(self.rendered[f"{key}/fly.toml"].decode())["env"])
        if role != "redis":
            data = base64.b64decode(env["AT_CLUSTER_CONFIG_B64"])
            data = data.replace(str(entry.BASES[role]).encode(), str(base).encode())
            env["AT_CLUSTER_CONFIG_B64"] = encoded(data)
            user = "default" if role == "relay" else env["AT_CLUSTER_PUBLISHER_USER"]
            env["AT_REDIS_URL"] = f"rediss://{user}:{'A' * 40}@{env['AT_CLUSTER_REDIS_HOST']}:6379/0"
        else:
            env.update(REDIS_PASSWORD="A" * 40, REDIS_PUBLISHER_PASSWORD="B" * 40)
        secret_map = entry.RELAY_SECRETS if role == "relay" else entry.AUTHORITY_SECRETS if role == "authority" else entry.REDIS_SECRETS
        for variable in secret_map:
            env[variable] = encoded(("synthetic fixture only " + variable).encode())
        env.update(PATH="/usr/bin:/bin", HTTP_PROXY="http://synthetic-proxy.invalid", PYTHONPATH="untrusted")
        return base, env

    def prepare(self, role, base, env, args=None):
        return entry.prepare(role, args or [], env, base=base, uid=self.uid, redis_data=base / "state")

    def test_actual_renderer_contract_all_roles_and_secret_scrub(self):
        for role in entry.BASES:
            with self.subTest(role=role):
                base, env = self.fixture(role)
                (base / "state/sentinel").write_bytes(b"persistent state must survive")
                argv, clean = self.prepare(role, base, env)
                expected = "/usr/local/bin/redis-server" if role == "redis" else "/usr/local/bin/tunnel-" + role
                self.assertEqual(argv[0], expected)
                self.assertNotIn("initialize", argv)
                self.assertEqual((base / "state/sentinel").read_bytes(), b"persistent state must survive")
                self.assertEqual(sorted(p.name for p in (base / "state").iterdir()), ["sentinel"])
                expected_env = {"PATH": env["PATH"], "HTTP_PROXY": env["HTTP_PROXY"]}
                if role == "relay":
                    expected_env["RUST_LOG"] = "info"
                self.assertEqual(clean, expected_env)
                self.assertEqual(stat.S_IMODE((base / "secrets").stat().st_mode), 0o700)
                for path in (base / "secrets").iterdir():
                    value = path.lstat()
                    self.assertTrue(stat.S_ISREG(value.st_mode))
                    self.assertEqual((value.st_uid, value.st_nlink, stat.S_IMODE(value.st_mode)), (self.uid, 1, 0o600))
                if role == "relay":
                    config = tomllib.loads((base / "secrets/relay.toml").read_text())
                    self.assertEqual(config["redis_url"], env["AT_REDIS_URL"])
                    self.assertEqual(config["cluster"]["peer_bind"], "[::]:7443")
                if role == "authority":
                    self.assertFalse((base / "secrets/inventory.json").exists())
                    self.assertEqual((base / "secrets/redis-url").read_text(), env["AT_REDIS_URL"])

    def test_repeat_materialization_is_atomic_and_never_truncates_state(self):
        base, env = self.fixture("relay")
        self.prepare("relay", base, env)
        path = base / "secrets/device-server-key.pem"
        inode = path.stat().st_ino
        env["AT_DEVICE_TLS_KEY_B64"] = encoded(b"new synthetic key bytes")
        self.prepare("relay", base, env)
        self.assertNotEqual(inode, path.stat().st_ino)
        self.assertEqual(path.read_bytes(), b"new synthetic key bytes")
        self.assertFalse(list((base / "secrets").glob(".materialize-*")))

    def test_new_incarnation_materialization_preserves_old_membership_and_recovery_fence(self):
        base, env = self.fixture("relay")
        original = base64.b64decode(env["AT_CLUSTER_CONFIG_B64"])
        old = tomllib.loads(original.decode())
        old_name = Path(old["cluster"]["membership_version_state_path"]).name
        preserved = {old_name: b'{"checkpoint_version":19}', old_name + '.lock': b'',
                     'recovery-approval-fence.json': b'{"highest_approval_version":7}',
                     'recovery-approval-fence.json.lock': b''}
        for name, data in preserved.items():
            (base / "state" / name).write_bytes(data)
            (base / "state" / name).chmod(0o600)
        before = {name: ((base / "state" / name).stat().st_ino, data) for name, data in preserved.items()}
        candidate = json.loads(json.dumps(self.inventory))
        candidate['deployment_incarnation'] += '-recovered'
        candidate['membership']['revision'] += 1
        rendered = renderer.render(candidate, example=True)
        data = rendered['relay-a/relay.toml'].replace(str(entry.BASES['relay']).encode(), str(base).encode())
        env['AT_CLUSTER_CONFIG_B64'] = encoded(data)
        new_name = Path(tomllib.loads(data.decode())['cluster']['membership_version_state_path']).name
        self.assertNotEqual(new_name, old_name)
        for arguments in (['serve'], ['initialize']):
            argv, _ = self.prepare('relay', base, env, arguments)
            self.assertEqual(argv[1], arguments[0])
            self.assertEqual(set(p.name for p in (base / 'state').iterdir()), set(preserved))
            self.assertFalse((base / 'state' / new_name).exists())
            for name, (inode, value) in before.items():
                self.assertEqual((base / 'state' / name).stat().st_ino, inode)
                self.assertEqual((base / 'state' / name).read_bytes(), value)
        # Only preparation ran: it never executes Rust or initializes state.

    def test_membership_paths_reject_old_incarnation_legacy_aliases_and_fence_changes(self):
        base, env = self.fixture('relay')
        original = base64.b64decode(env['AT_CLUSTER_CONFIG_B64']).decode()
        config = tomllib.loads(original)
        path = config['cluster']['membership_version_state_path']
        old_digest = hashlib.sha256(b'independently-different-incarnation').hexdigest()
        variants = [str(base / 'state' / ('membership-version-' + old_digest + '.json')),
                    str(base / 'state/membership-version-state.json'),
                    str(base / 'state/arbitrary.json'), str(base / 'state/../outside.json'),
                    str(base / 'state' / ('membership-version-' + '0' * 64 + '.json'))]
        for replacement in variants:
            with self.subTest(path=replacement), self.assertRaises(entry.Refusal):
                entry.validate_config('relay', original.replace(path, replacement).encode(), base)
        with self.assertRaises(entry.Refusal):
            entry.validate_config('relay', original.replace('recovery-approval-fence.json', 'new-fence.json').encode(), base)
        for incarnation in ('', '../old', 'x' * 65, 'é'):
            data = original.replace(json.dumps(config['deployment_incarnation']), json.dumps(incarnation, ensure_ascii=False))
            with self.subTest(incarnation=incarnation), self.assertRaises(entry.Refusal):
                entry.validate_config('relay', data.encode(), base)

    def test_authority_preparation_never_moves_or_resets_allocator_state(self):
        base, env = self.fixture('authority')
        preserved = {'authority.json': b'{"membership_high_water":29,"checkpoint_high_water":31}',
                     'authority.json.lock': b''}
        for name, value in preserved.items():
            (base / 'state' / name).write_bytes(value)
            (base / 'state' / name).chmod(0o600)
        before = {name: (base / 'state' / name).stat().st_ino for name in preserved}
        for arguments in (['serve'], ['approve-membership', '--expected-redis-run-id', 'a' * 40, '--expected-revision', '1']):
            argv, _ = self.prepare('authority', base, env, arguments)
            self.assertEqual(argv[1], arguments[0])
            self.assertEqual(set(p.name for p in (base / 'state').iterdir()), set(preserved))
            for name, value in preserved.items():
                self.assertEqual((base / 'state' / name).stat().st_ino, before[name])
                self.assertEqual((base / 'state' / name).read_bytes(), value)

    def test_metrics_require_exact_container_loopback_without_alternate_listener(self):
        for index, address in enumerate(('[::]:9100', '0.0.0.0:9100', '127.0.0.1:9100', '[::1]:9101', '192.0.2.1:9100')):
            with self.subTest(address=address):
                base, env = self.fixture("relay", f"metrics-{index}")
                config = base64.b64decode(env["AT_CLUSTER_CONFIG_B64"]).decode()
                self.assertIn('metrics_bind = "[::1]:9100"', config)
                env["AT_CLUSTER_CONFIG_B64"] = encoded(config.replace('[::1]:9100', address).encode())
                with self.assertRaisesRegex(entry.Refusal, "relay metrics must use container loopback"):
                    self.prepare("relay", base, env)

    def test_failed_atomic_write_retains_old_file_and_cleans_only_own_temp(self):
        base, env = self.fixture("relay")
        self.prepare("relay", base, env)
        path = base / "secrets/device-server-key.pem"
        original = path.read_bytes()
        with mock.patch.object(entry.os, "fsync", side_effect=OSError("synthetic I/O failure")):
            with self.assertRaises(OSError):
                entry.write_private(base / "secrets", path.name, b"replacement", self.uid)
        self.assertEqual(path.read_bytes(), original)
        self.assertFalse(list((base / "secrets").glob(".materialize-*")))

    def test_missing_unsafe_and_symlink_state_never_created_or_repaired(self):
        for kind in ("missing", "mode", "symlink", "wrong-owner"):
            with self.subTest(kind=kind):
                base, env = self.fixture("authority", kind)
                state = base / "state"
                if kind == "missing":
                    state.rmdir()
                elif kind == "mode":
                    state.chmod(0o755)
                elif kind == "symlink":
                    state.rmdir()
                    state.symlink_to(self.root, target_is_directory=True)
                with self.assertRaises((entry.Refusal, OSError)):
                    entry.prepare("authority", [], env, base=base, uid=self.uid + (kind == "wrong-owner"))
                self.assertFalse((base / "secrets").exists())
                if kind == "missing":
                    self.assertFalse(state.exists())
                elif kind == "mode":
                    self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o755)
                elif kind == "symlink":
                    self.assertTrue(state.is_symlink())

    def test_secret_symlink_hardlink_fifo_mode_and_oversize_refused(self):
        for kind in ("symlink", "dangling", "hardlink", "fifo", "mode", "oversize"):
            with self.subTest(kind=kind):
                base, env = self.fixture("relay", kind)
                secrets = base / "secrets"
                secrets.mkdir(mode=0o700)
                target = self.root / (kind + "-outside")
                target.write_bytes(b"outside unchanged")
                target.chmod(0o600)
                path = secrets / "device-server-chain.pem"
                if kind in {"symlink", "dangling"}:
                    path.symlink_to(target if kind == "symlink" else self.root / "absent")
                elif kind == "hardlink":
                    os.link(target, path)
                elif kind == "fifo":
                    os.mkfifo(path, 0o600)
                else:
                    path.write_bytes(b"x" * (entry.MAX_FILE + 1 if kind == "oversize" else 1))
                    path.chmod(0o600 if kind == "oversize" else 0o644)
                with self.assertRaises(entry.Refusal):
                    self.prepare("relay", base, env)
                self.assertEqual(target.read_bytes(), b"outside unchanged")

    def test_symlink_ancestor_and_existing_unsafe_secret_directory(self):
        base, env = self.fixture("relay")
        alias = self.root / "alias"
        alias.symlink_to(base, target_is_directory=True)
        with self.assertRaises(entry.Refusal):
            entry.private_directory(alias / "state", self.uid)
        (base / "secrets").mkdir(mode=0o755)
        (base / "secrets").chmod(0o755)
        with self.assertRaises(entry.Refusal):
            self.prepare("relay", base, env)
        self.assertEqual(stat.S_IMODE((base / "secrets").stat().st_mode), 0o755)

    def test_bounded_base64_and_missing_input_fail_before_materialization(self):
        for value in ("", "not base64!", "====", encoded(b""), "A" * (4 * entry.MAX_FILE)):
            with self.subTest(length=len(value)):
                base, env = self.fixture("relay", "case" + str(len(list(self.root.iterdir()))))
                env["AT_RECOVERY_TRUST_B64"] = value
                with self.assertRaises(entry.Refusal):
                    self.prepare("relay", base, env)
                self.assertFalse((base / "secrets").exists())

    def test_url_identity_tls_port_user_and_injection_refused(self):
        base, env = self.fixture("relay")
        valid = env["AT_REDIS_URL"]
        for bad in (valid.replace("rediss:", "redis:"), valid.replace("default:", "publisher:"),
                    valid.replace(":6379/0", ":6380/0"), valid.replace(".internal", ".invalid"),
                    valid + "?insecure=1", valid + '\"\nboot_id="bad"', valid.replace("A" * 40, "short")):
            with self.subTest(url_case=bad[:6]):
                changed = dict(env, AT_REDIS_URL=bad)
                with self.assertRaises(entry.Refusal):
                    self.prepare("relay", base, changed)
        authority, authority_env = self.fixture("authority")
        authority_env["AT_REDIS_URL"] = authority_env["AT_REDIS_URL"].replace(entry.publisher(authority_env) + ":", "default:")
        with self.assertRaises(entry.Refusal):
            self.prepare("authority", authority, authority_env)

    def test_redis_host_matches_renderer_app_length_and_terminal_character(self):
        base, env = self.fixture("relay")
        old_host = env["AT_CLUSTER_REDIS_HOST"]
        for length in (3, 62, 63):
            host = "r" * length + ".internal"
            changed = dict(env, AT_CLUSTER_REDIS_HOST=host,
                           AT_REDIS_URL=env["AT_REDIS_URL"].replace(old_host, host))
            self.assertEqual(entry.redis_url(changed, "relay"), changed["AT_REDIS_URL"])
            # Exercise the renderer's same service/app acceptance boundary.
            renderer.service({"app": "r" * length, "volume": "volume", "memory_mb": 512,
                              "volume_size_gb": 1}, set())
        for app in ("rr", "r" * 64, "rr-", "-rr", "Rrr"):
            host = app + ".internal"
            changed = dict(env, AT_CLUSTER_REDIS_HOST=host,
                           AT_REDIS_URL=env["AT_REDIS_URL"].replace(old_host, host))
            with self.assertRaises(entry.Refusal):
                entry.redis_url(changed, "relay")

    def test_unknown_or_interrupted_materialization_is_not_removed_or_ignored(self):
        for name in (".materialize-interrupted", "unrelated-key.pem"):
            base, env = self.fixture("relay", "case" + str(len(list(self.root.iterdir()))))
            self.prepare("relay", base, env)
            path = base / "secrets" / name
            path.write_bytes(b"retained for operator inspection")
            path.chmod(0o600)
            before = {p.name: p.read_bytes() for p in (base / "secrets").iterdir()}
            with self.assertRaises(entry.Refusal):
                self.prepare("relay", base, env)
            self.assertEqual(before, {p.name: p.read_bytes() for p in (base / "secrets").iterdir()})

    def test_config_path_alias_continuity_and_ipv4_private_bind_refused(self):
        base, env = self.fixture("relay")
        original = base64.b64decode(env["AT_CLUSTER_CONFIG_B64"]).decode()
        variants = ["redis_url='rediss://injected'\n" + original,
                    "redis_restart_continuity_seconds=5\n" + original, "boot_id='old'\n" + original,
                    original.replace("[::]:7443", "0.0.0.0:7443"),
                    original.replace("peer-key.pem", "../outside.pem"),
                    original.replace("[recovery]", "[recovery]\nredis_url='rediss://other'"),
                    "redis_tls_client_key_path='/other/key'\n" + original]
        for data in variants:
            with self.subTest(case=hashlib.sha256(data.encode()).hexdigest()[:8]):
                with self.assertRaises(entry.Refusal):
                    self.prepare("relay", base, dict(env, AT_CLUSTER_CONFIG_B64=encoded(data.encode())))
        authority, env = self.fixture("authority")
        config = base64.b64decode(env["AT_CLUSTER_CONFIG_B64"])
        for altered in (config.replace(b"[::]:8444", b"0.0.0.0:8444"),
                        config.replace(b"membership.der", b"recovery.der"), b"unknown='field'\n" + config):
            with self.assertRaises(entry.Refusal):
                self.prepare("authority", authority, dict(env, AT_CLUSTER_CONFIG_B64=encoded(altered)))

    def test_online_roles_refuse_offline_keys_and_cross_role_credentials(self):
        for role, forbidden in (("relay", "AT_MEMBERSHIP_SIGNING_KEY_B64"),
                                ("authority", "AT_RECOVERY_SIGNING_KEY_B64"),
                                ("relay", "REDIS_PUBLISHER_PASSWORD")):
            base, env = self.fixture(role, forbidden)
            env[forbidden] = "SENSITIVE-SENTINEL"
            with self.assertRaises(entry.Refusal) as caught:
                self.prepare(role, base, env)
            self.assertNotIn("SENSITIVE-SENTINEL", str(caught.exception))

    def test_exact_operator_allowlist_no_config_override_or_shell(self):
        base = entry.BASES["relay"]
        for name in ("serve", "check-serve-config", "initialize", "recovery-initialize", "recovery-observe", "activate-first-incarnation"):
            argv, _ = entry.command("relay", [name], base)
            self.assertEqual(argv, ["/usr/local/bin/tunnel-relay", name, "--config", str(base / "secrets/relay.toml")])
        for args in (["rebind-redis-run", "--redis-restarted-in-place"], ["sh", "-c", "true"],
                     ["serve", "--config", "/other"], ["serve", "--config=/other"],
                     ["provision-catalog", "--records", "/x", "--force"],
                     ["add-user", "--records", "/x", "--records", "/y"],
                     ["recover", "--approval", "/x"], ["--help", "extra"], ["serve", "--"]):
            with self.subTest(args=args):
                with self.assertRaises(entry.Refusal):
                    entry.command("relay", args, base)
        for name in ("generate-key", "sign-recovery-approval", "sh"):
            with self.assertRaises(entry.Refusal):
                entry.command("authority", [name], entry.BASES["authority"])
        for args in (["redis-server"], ["serve", "--requirepass", "x"], ["initialize"]):
            with self.assertRaises(entry.Refusal):
                entry.command("redis", args, entry.BASES["redis"])

    def test_operator_records_and_recovery_use_protected_mounted_inputs(self):
        base, env = self.fixture("relay")
        operator = base / "operator"
        operator.mkdir(mode=0o700)
        path = operator / "records.toml"
        path.write_bytes(b"synthetic records")
        path.chmod(0o600)
        for name in ("provision-catalog", "add-user", "add-device", "add-service", "set-grant"):
            argv, _ = self.prepare("relay", base, env, [name, "--records", str(path), "--dry-run"])
            self.assertEqual(argv[-3:], ["--records", str(path), "--dry-run"])
        args = ["recover", "--approval", str(path), "--expected-nonce", "synthetic-nonce",
                "--acknowledgement-id", "synthetic-ack", "--old-primary-fenced", "--old-relays-fenced"]
        argv, _ = self.prepare("relay", base, env, args)
        self.assertEqual(argv[4:], args[1:])
        with self.assertRaises(entry.Refusal):
            self.prepare("relay", base, env, ["add-user", "--records", str(base / "state/records.toml")])
        path.chmod(0o644)
        with self.assertRaises(entry.Refusal):
            self.prepare("relay", base, env, ["add-user", "--records", str(path)])

    def test_authority_initialization_is_explicit_and_run_bound(self):
        base, env = self.fixture("authority")
        for name in ("initialize-membership", "approve-membership"):
            args = [name, "--expected-redis-run-id", "a" * 40]
            if name == "approve-membership":
                args += ["--expected-revision", "1"]
            argv, _ = self.prepare("authority", base, env, args)
            self.assertEqual(argv[1], name)
            self.assertIn(str(base / "secrets/inventory.json"), argv)
            self.assertEqual(json.loads((base / "secrets/inventory.json").read_bytes())["schema_version"], 1)
        for args in (["initialize-membership"], ["initialize-membership", "--expected-redis-run-id", "bad"],
                     ["approve-membership", "--expected-redis-run-id", "a" * 40, "--expected-revision", "0"],
                     ["initialize-membership", "--inventory", "/other", "--expected-redis-run-id", "a" * 40]):
            with self.assertRaises(entry.Refusal):
                entry.command("authority", args, base)

    def test_redis_acl_and_durability_exact_scope_and_secret_separation(self):
        base, env = self.fixture("redis")
        self.prepare("redis", base, env)
        acl = (base / "secrets/users.acl").read_text().splitlines()
        self.assertEqual(len(acl), 2)
        self.assertEqual(acl[0].split(), ["user", "default", "reset", "on", "#" + hashlib.sha256(env["REDIS_PASSWORD"].encode()).hexdigest(), "~*", "&*", "+@all"])
        self.assertEqual(acl[1].split(), ["user", env["AT_CLUSTER_PUBLISHER_USER"], "reset", "on", "#" + hashlib.sha256(env["REDIS_PUBLISHER_PASSWORD"].encode()).hexdigest(), "~tunnel-catalog:" + env["AT_CLUSTER_REDIS_NAMESPACE"] + ":membership:operator:*", "-@all", "+ping", "+info", "+eval", "+hget", "+hlen", "+hset", "+expire"])
        config = (base / "secrets/redis.conf").read_text()
        for line in ("port 0", "tls-port 6379", "bind ::", "appendonly yes", "appendfsync always",
                     "no-appendfsync-on-rewrite no", "aof-load-truncated no", "maxmemory 96mb", "maxmemory-policy noeviction"):
            self.assertIn(line, config.splitlines())
        self.assertNotIn(env["REDIS_PASSWORD"], config + "\n".join(acl))
        original = (base / "secrets/users.acl").read_bytes()
        self.prepare("redis", base, env)
        self.assertEqual((base / "secrets/users.acl").read_bytes(), original)
        for changed in ({"REDIS_PUBLISHER_PASSWORD": env["REDIS_PASSWORD"]},
                        {"AT_CLUSTER_PUBLISHER_USER": "default"}, {"AT_CLUSTER_REDIS_NAMESPACE": "x* ~*"},
                        {"REDIS_PASSWORD": "x\nuser default nopass"}):
            with self.assertRaises(entry.Refusal):
                self.prepare("redis", base, dict(env, **changed))

    def test_main_redacts_errors_and_execs_only_fixed_argv(self):
        class ExecObserved(BaseException):
            pass
        with mock.patch.object(entry.sys, "argv", ["entrypoint", "relay"]), \
                mock.patch.object(entry.os, "geteuid", return_value=10001), \
                mock.patch.object(entry.os, "umask"), \
                mock.patch.object(entry, "prepare", side_effect=ValueError("SENSITIVE-SENTINEL")), \
                mock.patch.object(entry.sys, "stderr", new_callable=io.StringIO) as stderr:
            self.assertEqual(entry.main(), 1)
            self.assertNotIn("SENSITIVE-SENTINEL", stderr.getvalue())
        wanted = ["/usr/local/bin/tunnel-relay", "serve", "--config", "/fixed"]
        with mock.patch.object(entry.sys, "argv", ["entrypoint", "relay"]), \
                mock.patch.object(entry.os, "geteuid", return_value=10001), \
                mock.patch.object(entry.os, "umask"), \
                mock.patch.object(entry, "prepare", return_value=(wanted, {"PATH": "/usr/bin"})), \
                mock.patch.object(entry.os, "execve", side_effect=ExecObserved) as execute:
            with self.assertRaises(ExecObserved):
                entry.main()
            execute.assert_called_once_with(wanted[0], wanted, {"PATH": "/usr/bin"})

    def test_main_refuses_root_or_wrong_role_uid_before_materialization(self):
        for role, uid in (("relay", 0), ("relay", 10002), ("authority", 10001)):
            with self.subTest(role=role, uid=uid), \
                    mock.patch.object(entry.sys, "argv", ["entrypoint", role]), \
                    mock.patch.object(entry.os, "geteuid", return_value=uid), \
                    mock.patch.object(entry, "prepare") as prepare, \
                    mock.patch.object(entry.os, "execve") as execute, \
                    mock.patch.object(entry.sys, "stderr", new_callable=io.StringIO):
                self.assertEqual(entry.main(), 1)
                prepare.assert_not_called()
                execute.assert_not_called()

    def test_redis_retained_notice_manifest_matches_new_pinned_recipe(self):
        notices = load("cluster_image_notice_validator", ROOT / "scripts/container_notices.py")
        result = notices.verify_redis(ROOT / "deploy/fly/redis/notices", ROOT / "LICENSE",
                                      IMAGES / "redis/Dockerfile")
        self.assertEqual(result["source_commit"], "60ba86f3c8b4e1ec96451171753a0a38e5c45a0c")
        self.assertIn("externally built modules", result["coverage"])

    def test_docker_sources_pins_full_stdlib_notices_and_context_exclusions(self):
        imports = {node.names[0].name for node in ast.parse((IMAGES / "entrypoint.py").read_text()).body if isinstance(node, ast.Import)}
        imports.add("pathlib")
        for role in ("relay", "authority", "redis", "rehearsal-client"):
            with self.subTest(role=role):
                docker = (IMAGES / role / "Dockerfile").read_text()
                self.assertTrue(all("@sha256:" in line for line in docker.splitlines() if line.startswith("FROM ")))
                self.assertIn("LABEL org.opencontainers.image.revision=$VCS_REF", docker)
                self.assertIn("USER ", docker)
                self.assertIn("STOPSIGNAL SIGTERM", docker)
                self.assertNotRegex(docker, r"(?m)^ARG (?:AT_|REDIS_PASSWORD)")
                ignore = (IMAGES / role / "Dockerfile.dockerignore").read_text()
                self.assertEqual(next(line for line in ignore.splitlines() if line and not line.startswith("#")), "*")
                for excluded in ("**/target", "**/*.key", "**/*.pem", "**/*.der", "**/.env", "**/.env.*"):
                    self.assertIn(excluded, ignore.splitlines())
                if role != "rehearsal-client":
                    probe = re.search(r"python3 -I -c 'import ([^']+)'", docker)
                    self.assertIsNotNone(probe)
                    self.assertEqual(set(probe.group(1).split(", ")), imports)
                    self.assertIn('"/usr/bin/python3", "-I"', docker)
                if role in {"relay", "authority"}:
                    self.assertIn("apt-get install -y --no-install-recommends python3 ", docker)
                    self.assertIn("container_notices.py stage --root /source", docker)
                    self.assertIn("--mount=type=secret,id=cargo_ca", docker)
                    self.assertIn("--locked --release -p tunnel-" + role, docker)
                    self.assertNotIn("tunnel-client", docker)
                if role == "redis":
                    self.assertIn("sha256sum -c SHA256SUMS", docker)
                    self.assertIn("apk info -vv", docker)
        # Historical recipes remain separate; the cluster copies, not rewrites,
        # their notices. No runtime/container success is inferred by this test.
        self.assertIn("rebind-redis-run", (ROOT / "deploy/fly/relay/entrypoint.sh").read_text())


if __name__ == "__main__":
    unittest.main()
