#!/usr/bin/python3
"""Fly cluster secret/config boundary. No initialization or permission repair.

The command line selects an image role, never a binary path. prepare() is also
used by temporary-file tests; main() alone execs a fixed installed binary.
"""
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import sys
import tomllib
import uuid


MAX_FILE = 128 * 1024
BASES = {"relay": Path("/var/lib/agent-tunnel"),
         "authority": Path("/var/lib/agentuplink-authority"),
         "redis": Path("/var/lib/agentuplink-redis")}
RELAY_SECRETS = {
    "AT_DEVICE_TLS_CERT_CHAIN_B64": "device-server-chain.pem",
    "AT_DEVICE_TLS_KEY_B64": "device-server-key.pem",
    "AT_DEVICE_CLIENT_CA_B64": "device-client-ca.pem",
    "AT_CONSUMER_TLS_CERT_CHAIN_B64": "consumer-server-chain.pem",
    "AT_CONSUMER_TLS_KEY_B64": "consumer-server-key.pem",
    "AT_REDIS_CA_B64": "redis-ca.pem", "AT_OIDC_JWKS_B64": "oidc-jwks.json",
    "AT_PEER_TLS_CERT_CHAIN_B64": "peer-chain.pem", "AT_PEER_TLS_KEY_B64": "peer-key.pem",
    "AT_PEER_CLIENT_CA_B64": "peer-ca.pem",
    "AT_MEMBERSHIP_SIGNER_TRUST_B64": "membership-signers.json",
    "AT_CHECKPOINT_CA_B64": "checkpoint-ca.pem",
    "AT_CHECKPOINT_CLIENT_CERT_CHAIN_B64": "checkpoint-client-chain.pem",
    "AT_CHECKPOINT_CLIENT_KEY_B64": "checkpoint-client-key.pem",
    "AT_RECOVERY_TRUST_B64": "recovery-approval-keys.json",
}
AUTHORITY_SECRETS = {
    "AT_MEMBERSHIP_SIGNING_KEY_B64": "membership.der", "AT_REDIS_CA_B64": "redis-ca.pem",
    "AT_AUTHORITY_TLS_CERT_CHAIN_B64": "https-chain.pem",
    "AT_AUTHORITY_TLS_KEY_B64": "https-key.pem",
    "AT_CHECKPOINT_CLIENT_CA_B64": "checkpoint-client-ca.pem",
}
REDIS_SECRETS = {"REDIS_TLS_CERT_CHAIN_B64": "tls-chain.pem", "REDIS_TLS_KEY_B64": "tls-key.pem"}


class Refusal(Exception):
    """Messages are fixed vocabulary; never include an input value."""


def require(condition, reason):
    if not condition:
        raise Refusal(reason)


def decode(env, name, maximum=MAX_FILE):
    value = env.get(name, "")
    require(isinstance(value, str) and 0 < len(value) <= 4 * ((maximum + 2) // 3),
            "missing or oversized encoded input")
    try:
        result = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise Refusal("invalid base64 input") from None
    require(0 < len(result) <= maximum, "empty or oversized decoded input")
    return result


def safe_ancestors(path):
    require(path.is_absolute() and ".." not in path.parts, "invalid filesystem path")
    for parent in reversed((path, *path.parents)):
        require(stat.S_ISDIR(parent.lstat().st_mode), "directory missing or symlink")


def private_directory(path, uid, create=False):
    # Every existing component must be a real directory. Creation only occurs
    # inside a previously validated owned private parent, never in state.
    if create:
        safe_ancestors(path.parent)
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            pass
    safe_ancestors(path)
    value = path.lstat()
    require(value.st_uid == uid and stat.S_IMODE(value.st_mode) == 0o700,
            "directory ownership or permissions refused")


def private_file(value, uid, maximum=MAX_FILE):
    require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1 and value.st_uid == uid
            and stat.S_IMODE(value.st_mode) == 0o600 and value.st_size <= maximum,
            "file type ownership links permissions or size refused")


def write_private(directory, name, data, uid):
    require(re.fullmatch(r"[a-z0-9][a-z0-9.-]*", name) is not None and 0 < len(data) <= MAX_FILE,
            "invalid materialized file")
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary = ".materialize-" + uuid.uuid4().hex
    created = False
    try:
        try:
            before = os.stat(name, dir_fd=fd, follow_symlinks=False)
            private_file(before, uid)
        except FileNotFoundError:
            before = None
        output = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=fd)
        created = True
        with os.fdopen(output, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            current = os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            current = None
        require((before is None and current is None) or
                (before is not None and current is not None and
                 (before.st_dev, before.st_ino, before.st_ctime_ns) ==
                 (current.st_dev, current.st_ino, current.st_ctime_ns)), "file changed during materialization")
        os.rename(temporary, name, src_dir_fd=fd, dst_dir_fd=fd)
        created = False
        os.fsync(fd)
    finally:
        if created:
            os.unlink(temporary, dir_fd=fd)
        os.close(fd)


def publisher(env):
    name = env.get("AT_CLUSTER_PUBLISHER_USER", "")
    require(re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", name) is not None and name != "default",
            "invalid named publisher user")
    return name


def redis_url(env, role):
    host = env.get("AT_CLUSTER_REDIS_HOST", "")
    require(re.fullmatch(r"[a-z][a-z0-9-]{1,61}[a-z0-9]\.internal", host) is not None, "invalid Redis host")
    user = "default" if role == "relay" else publisher(env)
    # This profile generates alphanumeric passwords; refusing percent escapes,
    # userinfo delimiters and arbitrary ports also prevents TOML injection.
    url = env.get("AT_REDIS_URL", "")
    require(re.fullmatch(r"rediss://" + re.escape(user) + r":[A-Za-z0-9]{32,128}@" +
                         re.escape(host) + r":6379/0", url) is not None, "Redis credential URL refused")
    return url


def options(arguments, required=(), optional=(), switches=()):
    values = {}
    index = 0
    while index < len(arguments):
        flag = arguments[index]
        require(flag in (*required, *optional, *switches) and flag not in values,
                "unknown or duplicate command option")
        index += 1
        if flag in switches:
            values[flag] = True
        else:
            require(index < len(arguments), "command option needs a value")
            value = arguments[index]
            require(0 < len(value) <= 4096 and not value.startswith("-") and
                    not any(ord(c) < 32 or ord(c) == 127 for c in value), "invalid command value")
            values[flag] = value
            index += 1
    require(all(flag in values for flag in required), "missing command option")
    return values


def command(role, arguments, base):
    args = arguments or ["serve"]
    name, rest = args[0], args[1:]
    require(isinstance(name, str) and len(args) <= 20, "invalid command")
    config = str(base / "secrets" / (role + ".toml"))
    if role == "redis":
        require(name == "serve" and not rest, "Redis accepts only serve")
        return ["/usr/local/bin/redis-server", str(base / "secrets/redis.conf")], {}
    binary = "/usr/local/bin/tunnel-" + role
    if name == "--help":
        require(not rest, "help takes no arguments")
        return [binary, "--help"], {}
    if role == "relay":
        if name in {"serve", "check-serve-config", "initialize", "recovery-initialize",
                    "recovery-observe", "activate-first-incarnation"}:
            parsed = options(rest)
        elif name in {"provision-catalog", "add-user", "add-device", "add-service", "set-grant"}:
            parsed = options(rest, required=("--records",), switches=("--dry-run",))
        elif name == "recover":
            parsed = options(rest, required=("--approval", "--expected-nonce", "--acknowledgement-id"),
                             switches=("--old-primary-fenced", "--old-relays-fenced"))
            require(parsed.get("--old-primary-fenced") and parsed.get("--old-relays-fenced"),
                    "recovery fencing acknowledgements required")
        elif name in {"revoke-grant", "revoke-device", "revoke-credential"}:
            required = {"revoke-grant": ("--tenant", "--user", "--device", "--service"),
                        "revoke-device": ("--tenant", "--device"),
                        "revoke-credential": ("--tenant", "--device", "--credential")}[name]
            parsed = options(rest, required=required, switches=("--dry-run",))
        else:
            raise Refusal("command not allowed in cluster relay image")
    else:
        if name in {"serve", "check-config"}:
            parsed = options(rest)
        elif name in {"initialize-membership", "approve-membership"}:
            required = ("--expected-redis-run-id",) + (("--expected-revision",) if name == "approve-membership" else ())
            parsed = options(rest, required=required)
            require(re.fullmatch(r"[0-9a-f]{40}", parsed["--expected-redis-run-id"]) is not None,
                    "invalid independently supplied Redis run identity")
            if "--expected-revision" in parsed:
                require(re.fullmatch(r"[1-9][0-9]{0,19}", parsed["--expected-revision"]) is not None
                        and int(parsed["--expected-revision"]) <= 2**64 - 1, "invalid expected revision")
            rest = ["--inventory", str(base / "secrets/inventory.json"), *rest]
        else:
            raise Refusal("command not allowed in serving authority image")
    return [binary, name, "--config", config, *rest], parsed


def validate_config(role, data, base):
    try:
        config = tomllib.loads(data.decode("utf-8"))
    except (UnicodeError, ValueError):
        raise Refusal("invalid configuration encoding or TOML") from None
    secrets = base / "secrets"
    if role == "authority":
        paths = {"state_path": base / "state/authority.json", "signing_key_path": secrets / "membership.der",
                 "redis_url_path": secrets / "redis-url", "redis_ca_path": secrets / "redis-ca.pem",
                 "tls_cert_chain": secrets / "https-chain.pem", "tls_private_key": secrets / "https-key.pem",
                 "tls_client_ca": secrets / "checkpoint-client-ca.pem"}
        require(config.get("bind") == "[::]:8444" and config.get("schema_version") == 1,
                "authority IPv6 bind or schema refused")
        require(set(config) == {*paths, "bind", "schema_version", "endpoint_policy"}, "authority configuration fields refused")
        for key, path in paths.items():
            require(config.get(key) == str(path), "authority path differs from image contract")
    else:
        require(not any(key in config for key in ("redis_url", "redis_restart_continuity_seconds", "boot_id")),
                "relay generated-only or continuity field refused")
        require(config.get("consumer_bind") in {"0.0.0.0:8443", "[::]:8443"}
                and config.get("device_bind") in {"0.0.0.0:9443", "[::]:9443"},
                "relay public listeners refused")
        cluster, recovery = config.get("cluster", {}), config.get("recovery", {})
        require(isinstance(cluster, dict) and isinstance(recovery, dict), "cluster and recovery sections required")
        require(cluster.get("peer_bind") == "[::]:7443", "peer IPv6 listener required")
        sections = [(config, {
            "device_tls_cert_chain": "device-server-chain.pem", "device_tls_private_key": "device-server-key.pem",
            "device_tls_client_ca": "device-client-ca.pem", "consumer_tls_cert_chain": "consumer-server-chain.pem",
            "consumer_tls_private_key": "consumer-server-key.pem", "redis_tls_root_ca_path": "redis-ca.pem",
            "oidc_jwks_path": "oidc-jwks.json"}), (cluster, {
            "peer_tls_cert_chain": "peer-chain.pem", "peer_tls_private_key": "peer-key.pem", "peer_tls_client_ca": "peer-ca.pem",
            "membership_signer_trust_path": "membership-signers.json", "checkpoint_authority_trust_path": "checkpoint-ca.pem",
            "checkpoint_authority_client_cert_chain": "checkpoint-client-chain.pem",
            "checkpoint_authority_client_private_key": "checkpoint-client-key.pem"}),
            (recovery, {"trusted_keys_path": "recovery-approval-keys.json"})]
        for section, paths in sections:
            for key, name in paths.items():
                require(section.get(key) == str(secrets / name), "relay secret path differs from image contract")
        require(cluster.get("membership_version_state_path") == str(base / "state/membership-version-state.json")
                and recovery.get("fence_path") == str(base / "state/recovery-approval-fence.json"), "relay state paths refused")
        require(set(recovery) == {"fence_path", "trusted_keys_path"}, "recovery credential overrides refused")
        # Additional credential paths/aliases must not bypass materialization.
        permitted_paths = {key for _, paths in sections for key in paths} | {"membership_version_state_path"}
        for section in (config, cluster):
            for key in section:
                if key.endswith(("_path", "_chain", "_key", "_ca", "_file")):
                    require(key in permitted_paths, "unmanaged relay credential path refused")
    return config


def redis_files(env, base, data):
    namespace = env.get("AT_CLUSTER_REDIS_NAMESPACE", "")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", namespace) is not None,
            "invalid catalog namespace")
    user = publisher(env)
    passwords = [env.get("REDIS_PASSWORD", ""), env.get("REDIS_PUBLISHER_PASSWORD", "")]
    require(all(re.fullmatch(r"[A-Za-z0-9]{32,128}", value) for value in passwords)
            and passwords[0] != passwords[1], "invalid or shared Redis passwords")
    hashes = [hashlib.sha256(value.encode("ascii")).hexdigest() for value in passwords]
    # default on is intentional: Redis8.4 AOF transaction replay with default
    # off previously lost catalog data. Publisher is NOT the relay credential.
    acl = (f"user default reset on #{hashes[0]} ~* &* +@all\n"
           f"user {user} reset on #{hashes[1]} ~tunnel-catalog:{namespace}:membership:operator:* "
           "-@all +ping +info +eval +hget +hlen +hset +expire\n")
    secret = base / "secrets"
    conf = (f"port 0\ntls-port 6379\nbind ::\nprotected-mode yes\n"
            f"tls-cert-file {secret}/tls-chain.pem\ntls-key-file {secret}/tls-key.pem\n"
            "tls-auth-clients no\ntls-protocols \"TLSv1.2 TLSv1.3\"\n"
            "appendonly yes\nappendfsync always\nno-appendfsync-on-rewrite no\naof-load-truncated no\n"
            "maxmemory 96mb\nmaxmemory-policy noeviction\ndaemonize no\nlogfile \"\"\n"
            f"dir {data}\naclfile {secret}/users.acl\n")
    return {"users.acl": acl.encode(), "redis.conf": conf.encode()}


def prepare(role, arguments, env, *, base=None, uid=None, redis_data=None):
    """Materialize only; returns fixed argv and sanitized env, never starts it.

    Alternate paths/UID are Python-call-only test parameters, not environment
    or CLI switches. Production main fixes every role path and effective UID.
    """
    require(role in BASES, "unknown image role")
    base = BASES[role] if base is None else base
    uid = os.geteuid() if uid is None else uid
    argv, parsed = command(role, arguments, base)
    sanitized = {key: value for key, value in env.items()
                 if not key.startswith(("AT_", "REDIS_", "PYTHON"))}
    if argv[-1] == "--help":
        return argv, sanitized
    private_directory(base, uid)
    state = (Path("/data/redis") if redis_data is None else redis_data) if role == "redis" else base / "state"
    private_directory(state, uid)  # Must already be provisioned while stopped.
    inputs = RELAY_SECRETS if role == "relay" else AUTHORITY_SECRETS if role == "authority" else REDIS_SECRETS
    allowed = set(inputs) | ({"AT_CLUSTER_REDIS_NAMESPACE", "AT_CLUSTER_PUBLISHER_USER"} if role == "redis" else
                            {"AT_CLUSTER_CONFIG_B64", "AT_CLUSTER_REDIS_HOST", "AT_CLUSTER_PUBLISHER_USER", "AT_REDIS_URL"})
    if role == "authority":
        allowed.add("AT_CLUSTER_INVENTORY_B64")
    require(not any(key.startswith("AT_") and key not in allowed for key in env), "unexpected role input refused")
    if role != "redis":
        require(not any(key in env for key in ("REDIS_PASSWORD", "REDIS_PUBLISHER_PASSWORD")), "Redis server credentials refused in this role")
        publisher(env)
    files = {name: decode(env, variable, 4096 if name == "membership.der" else MAX_FILE)
             for variable, name in inputs.items()}
    if role == "redis":
        files.update(redis_files(env, base, state))
    else:
        config_data = decode(env, "AT_CLUSTER_CONFIG_B64", 32 * 1024)
        validate_config(role, config_data, base)
        url = redis_url(env, role)
        if role == "relay":
            config_data = ("redis_url = " + json.dumps(url) + "\n").encode() + config_data
        else:
            files["redis-url"] = url.encode()
            if argv[1] in {"initialize-membership", "approve-membership"}:
                inventory = decode(env, "AT_CLUSTER_INVENTORY_B64")
                try:
                    require(isinstance(json.loads(inventory), dict), "inventory must be a JSON object")
                except (ValueError, UnicodeError):
                    raise Refusal("invalid inventory JSON") from None
                files["inventory.json"] = inventory
        files[role + ".toml"] = config_data
    for flag in ("--records", "--approval"):
        if flag in parsed:
            path = Path(parsed[flag])
            require(path.parent == base / "operator" and path.name not in {"", ".", ".."}, "operator input path refused")
            private_directory(path.parent, uid)
            private_file(path.lstat(), uid, 1024 * 1024)
    directory = base / "secrets"
    private_directory(directory, uid, create=True)
    allowed_files = set(files) | ({"inventory.json"} if role == "authority" else set())
    # Do not accumulate abandoned temporary files after interrupted startup or
    # silently accept unrelated credential material. An operator inspects any
    # incomplete materialization; the entrypoint never removes unknown files.
    existing = list(directory.iterdir())
    require(len(existing) <= len(allowed_files), "unexpected private directory entries")
    for path in existing:
        require(path.name in allowed_files, "unexpected private directory entry")
        private_file(path.lstat(), uid)
    for name, data in files.items():
        write_private(directory, name, data, uid)
    return argv, sanitized


def main():
    try:
        require(len(sys.argv) >= 2 and sys.argv[1] in BASES, "image role required")
        role = sys.argv[1]
        expected = {"relay": 10001, "authority": 10002}
        expected_uid = expected[role] if role in expected else pwd.getpwnam("redis").pw_uid
        require(os.geteuid() != 0 and os.geteuid() == expected_uid, "runtime UID refused")
        os.umask(0o077)
        argv, env = prepare(role, sys.argv[2:], dict(os.environ))
        os.execve(argv[0], argv, env)
    except Refusal as error:
        print("agentuplink-cluster-entrypoint: " + str(error), file=sys.stderr)
    except Exception:
        # No exception repr: malformed TOML/URL/OS errors can carry input bytes.
        print("agentuplink-cluster-entrypoint: materialization or exec refused", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
