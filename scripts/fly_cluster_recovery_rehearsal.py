#!/usr/bin/env python3
"""Actual-image, explicitly approved same-AOF cluster restart rehearsal.

This is NOT physical older-backup restoration, automatic failover, a Fly deploy,
or crash/fsync acceptance. Only source.json, images.json, events.jsonl and
result.json are uploadable. Raw commands, generated keys and approvals remain
in the separately owned private temporary directory. No build/pull/native fallback.
"""
from __future__ import annotations

import argparse
import base64
import copy
import datetime as dt
import importlib.util
import json
from pathlib import Path
import re
import secrets
import signal
import shutil
import socket
import tempfile
import time
import tomllib
import uuid

_spec = importlib.util.spec_from_file_location("fly_recovery_base", Path(__file__).with_name("fly_cluster_rehearsal.py"))
base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)
require, Refused, canonical, digest = base.require, base.Refused, base.canonical, base.digest
FENCE_FILE = "recovery-approval-fence.json"
FENCING_SECONDS = 65
OBSERVATION_FIELDS = {"schema_version", "deployment_id", "redis_namespace", "deployment_incarnation", "redis_run_id",
                      "catalog_digest", "catalog_generation", "key_count", "byte_count", "quiescence"}
LIMITATIONS = [
    "synthetic local Docker IPv6 and fixture CAs, not actual Fly routing or public trust",
    "orchestrated all-role stop and same AOF volume restart; not crash/fsync or older-backup restoration",
    "externally chosen synthetic incarnation and offline approval; no automatic recovery or rebind",
    "fresh sessions and exact echo only; no replay of interrupted operations or uninterrupted rotation claim",
    "physical older-backup restoration and independent later-revocation reconciliation remain required",
]

# A negative-only mutation on ONE known synthetic tenant. Decimal arithmetic
# stays exact above Lua's floating-point integer range. No key is created and
# all shape/identity/prior-value/overflow checks precede both writes.
DISPLAY_NAME_CAS = r'''
local function next_decimal(s)
 if not s or not string.match(s, '^[1-9][0-9]*$') or #s>20 or
    (#s==20 and s>='18446744073709551615') then return nil end
 local carry=1; local result=''
 for i=#s,1,-1 do
  local n=tonumber(string.sub(s,i,i))+carry
  if n==10 then n=0; carry=1 else carry=0 end
  result=tostring(n)..result
 end
 if carry==1 then result='1'..result end
 return result
end
if #KEYS~=4 or #ARGV~=6 then return {'refused'} end
if redis.call('TYPE',KEYS[1]).ok~='hash' or redis.call('TYPE',KEYS[2]).ok~='string'
 or redis.call('TYPE',KEYS[3]).ok~='string' or redis.call('TYPE',KEYS[4]).ok~='string'
 or redis.call('HGET',KEYS[1],'display_name')~=ARGV[1] or redis.call('GET',KEYS[2])~=ARGV[3]
 or redis.call('GET',KEYS[3])~=ARGV[5] or redis.call('GET',KEYS[4])~=ARGV[6]
 or #ARGV[1]>128 or #ARGV[2]>128 then return {'refused'} end
local n=next_decimal(ARGV[3]); if not n or n~=ARGV[4] then return {'refused'} end
redis.call('HSET',KEYS[1],'display_name',ARGV[2]); redis.call('SET',KEYS[2],n)
return {'ok',redis.call('HGET',KEYS[1],'display_name'),redis.call('GET',KEYS[2])}
'''


def display_name_command(prefix, tenant, before, after, generation, incarnation, run_id):
    require(re.fullmatch(r"tunnel-catalog:aur-[0-9a-f]{12}:", prefix) and str(uuid.UUID(tenant)) == tenant,
            "negative_catalog_owned_scope")
    require(before in {"Synthetic tenant", "Synthetic tenant digest-negative"}
            and after in {"Synthetic tenant", "Synthetic tenant digest-negative"} and before != after,
            "negative_catalog_field_values")
    require(isinstance(generation, str) and re.fullmatch(r"[1-9][0-9]{0,19}", generation)
            and int(generation) < 2**64 - 1, "negative_catalog_generation")
    require(incarnation == prefix[len("tunnel-catalog:"):-1] + "-1"
            and re.fullmatch(r"[0-9a-f]{40}", run_id), "negative_catalog_old_binding")
    return ["EVAL", DISPLAY_NAME_CAS, "4", prefix + "tenant:" + tenant, prefix + "meta:catalog_generation",
            prefix + "meta:active_incarnation", prefix + "meta:redis_run_id", before, after, generation,
            str(int(generation) + 1), incarnation, run_id]


def checked_observation(raw, inventory, run_id):
    value = base.observation_json(raw, 16 * 1024)
    require(isinstance(value, dict) and set(value) == OBSERVATION_FIELDS, "recovery_observation_schema")
    require(type(value["schema_version"]) is int and value["schema_version"] == 1, "recovery_observation_version")
    require(all(value[k] == inventory[k] for k in ("deployment_id", "redis_namespace", "deployment_incarnation"))
            and value["redis_run_id"] == run_id and re.fullmatch(r"[0-9a-f]{40}", run_id), "recovery_observation_identity")
    require(value["quiescence"] == "unproven", "recovery_observation_quiescence")
    require(isinstance(value["catalog_digest"], str) and re.fullmatch(r"[0-9a-f]{64}", value["catalog_digest"]), "recovery_observation_digest")
    require(isinstance(value["catalog_generation"], str) and re.fullmatch(r"0|[1-9][0-9]{0,19}", value["catalog_generation"])
            and int(value["catalog_generation"]) < 2**64, "recovery_observation_generation")
    require(type(value["key_count"]) is int and 0 < value["key_count"] <= 16384
            and type(value["byte_count"]) is int and 0 < value["byte_count"] <= 8 * 1024**2, "recovery_observation_bound")
    return value


def check_refusal(output, error, exit_code, kind):
    markers = {
        "old_relay_run": b"stage=authority_identity class=run_changed",
        "old_relay_incarnation": b"stage=authority_identity class=catalog",
        "old_authority_run": b"Redis run differs from independent durable approval; recovery required",
        "missing_fences": b"agentuplink-cluster-entrypoint: recovery fencing acknowledgements required",
        "wrong_nonce": b"recovery approval was rejected",
        "stale_digest": b"recovery approval does not match the live catalog observation",
        "replay": b"recovery approval was rejected",
    }
    require(kind in markers, "refusal_kind")
    require(exit_code == 1 and len(output) + len(error) <= 64 * 1024
            and markers[kind] in error, "recovery_expected_refusal_" + kind)
    # Only closed kinds and hashes leave this function; raw errors stay private.
    return {"kind": kind, "exit_code": exit_code, "stdout_sha256": digest(output), "stderr_sha256": digest(error)}


def check_fence(raw, inventory, highest):
    value = base.observation_json(raw, 4096)
    require(isinstance(value, dict) and set(value) == {"schema_version", "deployment_id", "redis_namespace", "highest_approval_version"}
            and type(value.get("schema_version")) is int and value["schema_version"] == 1
            and value.get("deployment_id") == inventory["deployment_id"]
            and value.get("redis_namespace") == inventory["redis_namespace"]
            and value.get("highest_approval_version") == highest, "recovery_fence_identity_or_version")
    require(highest is None or (base.u64(highest) and highest > 0), "recovery_fence_counter")
    observed = value["highest_approval_version"]
    require(observed is None or (base.u64(observed) and observed > 0), "recovery_fence_counter")
    return value


def next_approval_version(raw, inventory):
    value = base.observation_json(raw, 4096)
    highest = value.get("highest_approval_version")
    check_fence(raw, inventory, highest)
    require(highest is None or highest < 2**64 - 1, "recovery_fence_exhausted")
    return 1 if highest is None else highest + 1


def check_approved_state(before, after, inventory, run_id):
    counters = {"membership_high_water", "checkpoint_high_water", "known_node_ids"}
    fields = counters | {"schema_version", "inventory", "expected_redis_run_id", "confirmed"}
    require(isinstance(before, dict) and counters <= set(before)
            and isinstance(after, dict) and set(after) == fields, "authority_approved_schema")
    require(type(after["schema_version"]) is int and after["schema_version"] == 1
            and isinstance(after["inventory"], dict) and canonical(after["inventory"]) == canonical(inventory)
            and after["expected_redis_run_id"] == run_id and after["confirmed"] is None,
            "authority_approved_identity")
    for state in (before, after):
        require(base.u64(state["membership_high_water"]) and base.u64(state["checkpoint_high_water"]),
                "authority_approved_counter")
        nodes = state["known_node_ids"]
        require(isinstance(nodes, list) and len(nodes) == len(base.NODES)
                and all(isinstance(node, str) for node in nodes) and set(nodes) == set(base.NODES),
                "authority_approved_nodes")
    require(all(after[k] == before[k] for k in counters),
            "authority_allocator_reset")


def check_fresh_owner(old, new, old_status, new_status, incarnation):
    require(new.get("deployment_incarnation") == incarnation
            and all(new.get(k) and new[k] != old.get(k) for k in ("boot_id", "session_id"))
            and int(new["owner_epoch"]) > int(old["owner_epoch"]), "recovery_owner_not_fresh")
    before, after = old_status["session"], new_status["session"]
    require(all(isinstance(state.get("active_connection_id"), str) and state["active_connection_id"]
                for state in (before, after)), "recovery_connection_identity_missing")
    require(base.ready_session(new_status) and after["session_id"] == new["session_id"]
            and after["epoch"] == int(new["owner_epoch"])
            and after["active_connection_id"] != before["active_connection_id"],
            "recovery_connection_not_fresh")


def check_source_bounds(root=base.ROOT):
    specs = [("crates/tunnel-relay/src/config.rs", r"const MAX_CLUSTER_RECORD_LIFETIME_SECONDS: u64 = (\d+);", 60),
             ("crates/tunnel-relay/src/config.rs", r"const MAX_OWNER_LEASE: Duration = Duration::from_secs\((\d+)\);", 30),
             ("crates/tunnel-catalog/src/clock.rs", r"const MAX_CLUSTER_CLOCK_SKEW_SECONDS: u64 = (\d+);", 5)]
    receipts = {}
    for path, pattern, expected in specs:
        data = (root / path).read_bytes()
        require(re.findall(pattern, data.decode()) == [str(expected)], "recovery_source_fencing_bound_changed")
        receipts[path] = digest(data)
    require(FENCING_SECONDS == 60 + 5 and base.MAIN_SECONDS == 1500 and base.CLEANUP_SECONDS == 180
            and base.COMMAND_SECONDS == 30, "recovery_controller_bounds_changed")
    return receipts


def absent_listener(port):
    with base.bounded_network():
        try:
            connection = socket.create_connection((base.HOST_LOOPBACK, port), timeout=5)
        except ConnectionRefusedError:
            return
        else:
            connection.close()
            raise Refused("recovery_old_listener_present")


class RecoveryRunner(base.Runner):
    """Keep cleanup running, but latch every observed resource-floor violation."""
    def __init__(self, *args):
        super().__init__(*args)
        self.cleanup_guard_failures = []
        self.docker_root = None

    def docker_disk(self):
        if self.docker_root is not None:
            require(shutil.disk_usage(self.docker_root).free >= 1536 * 1024**2, "docker_disk_guard")

    def guard(self):
        super().guard()
        self.docker_disk()

    def cleanup_sample(self):
        try:
            sample = base.resource_sample(self.private)
            self.samples.append({**sample, "monotonic": round(time.monotonic(), 3), "cleanup": True})
            base.check_resources(sample, self.initial)
            self.docker_disk()
        except BaseException as exc:
            code = base.error_code(exc)
            if code not in self.cleanup_guard_failures:
                self.cleanup_guard_failures.append(code)

    def __call__(self, *args, **kwargs):
        if self.cleanup:
            self.cleanup_sample()
        try:
            return super().__call__(*args, **kwargs)
        finally:
            if self.cleanup:
                self.cleanup_sample()


class RecoveryDocker(base.Docker):
    """Promptly remove finished helpers; retain all identities in the receipt."""
    def engine_preflight(self):
        result = super().engine_preflight()
        raw = self.run(base.DOCKER + ["info", "--format", "{{json .DockerRootDir}}"])
        root = json.loads(raw)
        require(isinstance(root, str) and Path(root).is_absolute() and Path(root).is_dir(), "docker_root_observation")
        self.run.docker_root = Path(root)
        self.run.docker_disk()
        result["docker_disk_free"] = shutil.disk_usage(root).free
        return result

    def remove_finished(self, item):
        row = self.inspect(item, identity_only=True)
        state = row["State"]
        require(not state.get("Running") and not state.get("OOMKilled"), "recovery_remove_not_stopped")
        self.call(["container", "rm", item["id"]])
        require(not self.call(["container", "ls", "--all", "--quiet", "--no-trunc", "--filter", "id=" + item["id"]]).strip(),
                "recovery_removed_container_present")
        self.inventory.append({"role": item["role"], "id": item["id"], "image": item["image"], "removed_early": True,
                               "exit_code_before_cleanup": state.get("ExitCode"), "oom_killed": False})
        self.containers.remove(item)
        self.run.event("owned_container_removed", role=item["role"], id=item["id"], independently_absent=True)

    def create(self, role, image, **kwargs):
        # base names use the current list length; roles get a monotonic suffix
        # so prompt removal cannot collide with retained live-container names.
        role = role + "-r" + str(self.run.index)
        return super().create(role, image, **kwargs)

    def one_shot(self, role, image, **kwargs):
        data, expected = kwargs.pop("data", None), kwargs.pop("expected_exit", 0)
        item = self.create(role, image, interactive=True, **kwargs)
        result = self.start(item, attached=True, data=data, expected_exit=expected)
        self.remove_finished(item)
        return result

    def capture(self, role, image, *, expected_exit, **kwargs):
        item = self.create(role, image, interactive=True, **kwargs)
        self.inspect(item)
        output = self.call(["container", "start", "--attach", "--interactive", item["id"]], allowed=(expected_exit,))
        error = (self.run.private / f"command-{self.run.index:04d}.stderr").read_bytes()
        state = self.inspect(item)["State"]
        require(state.get("Running") is False and state.get("ExitCode") == expected_exit, "recovery_captured_exit")
        self.remove_finished(item)
        return output, error, expected_exit

    def artifact_receipt(self, role):
        old = {id(item) for item in self.containers}
        result = super().artifact_receipt(role)
        created = [item for item in self.containers if id(item) not in old]
        require(len(created) == 1, "recovery_artifact_helper_count")
        self.remove_finished(created[0])
        return result


class RecoveryRehearsal(base.Rehearsal):
    def __init__(self, *args):
        super().__init__(*args)
        self.spare_device, self.spare_service, self.spare_credential, self.denied_user = [str(uuid.uuid4()) for _ in range(4)]
        self.approval_sequence = 0

    def catalog_files(self):
        files = super().catalog_files()
        self.spare_identity = self.pki.leaf("revocation-device", "device", ["URI:urn:agent-tunnel:device:" + self.spare_device], "clientAuth")
        files["spare.pem"] = self.spare_identity[0].read_bytes()
        files["spare.toml"] = f'''[device]
tenant = "{self.tenant}"
owner = "{self.user}"
id = "{self.spare_device}"
credential_id = "{self.spare_credential}"
display_name = "Synthetic revocation probe"
certificate = "spare.pem"
'''.encode()
        files["spare-service.toml"] = f'''[service]
tenant = "{self.tenant}"
device = "{self.spare_device}"
id = "{self.spare_service}"
type = "echo"
display_name = "Synthetic spare echo"
operations = ["echo:invoke"]
'''.encode()
        files["denied-user.toml"] = f'''[user]
tenant = "{self.tenant}"
id = "{self.denied_user}"
display_name = "Synthetic revoked principal"
oidc_subject = "synthetic-revoked-user"
'''.encode()
        files["denied-grant.toml"] = f'''[grant]
tenant = "{self.tenant}"
user = "{self.denied_user}"
device = "{self.devices[0]}"
service = "{self.services[0]}"
operations = ["echo:invoke"]
'''.encode()
        return files

    def prepare(self):
        super().prepare()
        self.offline = self.prefix + "-offline"
        require(self.offline in self.docker.volumes, "offline_volume_identity")
        self.spare_volume = self.docker.volume("spare-client")
        # No service invocation is needed for the credential-positive control:
        # actual authenticated CLI ready/status establishes this enrolled identity.
        config = self.client_config(0).replace(self.devices[0], self.spare_device).replace(self.services[0], self.spare_service)
        self.docker.setup_volume(self.spare_volume, 10003, 10003, {
            "client.toml": config.encode(), "credentials/device-chain.pem": self.spare_identity[0].read_bytes(),
            "credentials/device-key.pem": self.spare_identity[1].read_bytes(),
            "credentials/public-ca.pem": self.pki.cas["public"][0].read_bytes()})
        b64 = lambda value: base64.urlsafe_b64encode(value).rstrip(b"=")
        now = int(time.time())
        claims = {"iss": self.inventory["oidc"]["issuer"], "sub": "synthetic-revoked-user", "aud": "agent-tunnel",
                  "iat": now - 5, "exp": now + 3600, "scope": "echo:invoke"}
        unsigned = b64(canonical({"alg": "RS256", "kid": "synthetic", "typ": "JWT"})) + b"." + b64(canonical(claims))
        self.denied_token = (unsigned + b"." + b64(self.pki.openssl(["dgst", "-sha256", "-sign", str(self.private / "oidc.key")], unsigned))).decode()

    @property
    def catalog_prefix(self):
        return "tunnel-catalog:" + self.inventory["redis_namespace"] + ":"

    def flag_keys(self):
        return [self.catalog_prefix + "credential:" + ":".join((self.tenant, self.spare_device, self.spare_credential)),
                self.catalog_prefix + "grant:" + ":".join((self.tenant, self.denied_user, self.devices[0], self.services[0]))]

    def revocation_flags(self, expected):
        require([self.redis.command("HGET", key, "active") for key in self.flag_keys()] == [expected, expected], "recovery_revocation_flags")

    def grant_probe(self, denied):
        saved = self.token
        try:
            self.token = self.denied_token
            for ingress in range(3):
                self.echo(ingress, 0, denied=denied)
        finally:
            self.token = saved

    def spare_probe(self, denied):
        kwargs = {"mounts": [(self.spare_volume, "/profile", True)],
                  "command": ["connect", "--no-reconnect", "--config", "/profile/client.toml", "--json"]}
        if denied:
            raw = self.docker.one_shot("revoked-client", self.docker.images["client"], expected_exit=3, **kwargs)
            base.check_identity_refusal(raw)
            return
        item = self.docker.create("spare-client-positive", self.docker.images["client"], **kwargs)
        self.docker.start(item)
        def ready():
            raw = self.docker.call(["container", "exec", item["id"], "/usr/local/bin/tunnel-client", "status", "--config", "/profile/client.toml", "--json"], allowed=(0, 8))
            value = json.loads(raw)
            if not value.get("ok"):
                require(value.get("error", {}).get("code") == "SUPERVISOR_ABSENT", "spare_start_cause")
                return False
            return base.ready_session(base.checked_status(raw, self.spare_device))
        base.wait_until(self.run, ready, 30, "spare_positive_ready")
        self.disconnect(item)
        self.event("spare_credential_positive", device_id=self.spare_device, authenticated_ready=True)

    def disconnect(self, item):
        self.docker.call(["container", "exec", item["id"], "/usr/local/bin/tunnel-client", "disconnect", "--config", "/profile/client.toml", "--json"])
        self.docker.stop(item)
        self.docker.remove_finished(item)

    def setup_revocations(self):
        operator = base.ROLE_BASE["relay"] + "/operator/"
        for command, name in (("add-device", "spare"), ("add-service", "spare-service"),
                              ("add-user", "denied-user"), ("set-grant", "denied-grant")):
            self.relay_command("relay-a", [command, "--records", operator + name + ".toml"])
        self.revocation_flags("1")
        self.spare_probe(False)
        self.grant_probe(False)
        self.relay_command("relay-a", ["revoke-credential", "--tenant", self.tenant, "--device", self.spare_device, "--credential", self.spare_credential])
        self.relay_command("relay-a", ["revoke-grant", "--tenant", self.tenant, "--user", self.denied_user, "--device", self.devices[0], "--service", self.services[0]])
        self.assert_revocations()
        self.event("baseline_revocations", positive_devices=3, positive_routes=9, revoked_spare_device=self.spare_device,
                   revoked_grant_principal=self.denied_user, credential_was_ready=True, grant_was_permitted=True)

    def assert_revocations(self):
        self.all_routes()
        self.revocation_flags("0")
        self.spare_probe(True)
        self.grant_probe(True)

    def private_state(self, names=None):
        names = self.membership_files if names is None else names
        state = {node: self.docker.read_volume(self.states[node], [names[node], FENCE_FILE], max_bytes=20 * 1024) for node in base.NODES}
        state["authority"] = self.docker.read_volume(self.states["authority"], ["authority.json"], max_bytes=base.MAX_AUTHORITY_OBSERVATION)
        return state

    def bindings(self):
        return [self.redis.command("GET", self.catalog_prefix + "meta:" + suffix)
                for suffix in ("active_incarnation", "redis_run_id", "catalog_generation")]

    def run_identity(self):
        ids = re.findall(r"^run_id:([0-9a-f]{40})\r?$", self.redis.command("INFO", "server"), re.MULTILINE)
        require(len(ids) == 1, "recovery_redis_run_id")
        return ids[0]

    def observe(self, env=None, inventory=None):
        raw = self.operator("relay-a", ["recovery-observe"], env=env)
        return checked_observation(raw, self.inventory if inventory is None else inventory, self.run_id)

    def operator(self, role, command, *, env=None, refusal=None, extra_mounts=()):
        image_role = "authority" if role == "authority" else "relay"
        kwargs = {"env": self.env[role] if env is None else env,
                  "mounts": [(self.states[role], base.ROLE_BASE[image_role] + "/state", True), *extra_mounts], "command": command}
        if refusal:
            result = self.docker.capture("recovery-operator", self.docker.images[image_role], expected_exit=1, **kwargs)
            self.event("operator_refusal", **check_refusal(*result, refusal))
            return None
        return self.docker.one_shot("recovery-operator", self.docker.images[image_role], **kwargs)

    def old_startups(self, state, bindings, *, activated=False):
        for node in base.NODES:
            self.operator(node, ["serve"], env=self.old_env[node], refusal="old_relay_incarnation" if activated else "old_relay_run")
            require(self.private_state(self.old_membership_files) == state and self.bindings() == bindings,
                    "refused_relay_mutated_state")
        self.operator("authority", ["serve"], env=self.old_env["authority"], refusal="old_authority_run")
        require(self.private_state(self.old_membership_files) == state and self.bindings() == bindings, "refused_authority_mutated_state")
        self.event("old_startups_refused", relays=3, authority=1, exact_causes=True, state_bytes_unchanged=True, activated=activated)

    def stop_and_restart(self):
        self.old_env = copy.deepcopy(self.env)
        self.old_inventory = copy.deepcopy(self.inventory)
        self.old_membership_files = self.membership_files.copy()
        self.old_owners = [self.owner(i) for i in range(3)]
        self.old_status = [self.status(i) for i in range(3)]
        old_ports = [*self.consumer_ports, *self.device_ports, self.authority_port]
        for item in self.clients:
            self.disconnect(item)
        for item in [*self.relays, self.authority]:
            self.docker.stop(item)
            self.docker.remove_finished(item)
        self.clients, self.relays = [], []
        for port in old_ports:
            absent_listener(port)
        self.stopped_state = self.private_state()
        self.stopped_authority = json.loads(self.stopped_state["authority"]["authority.json"])
        self.stopped_bindings = self.bindings()
        self.stopped_epochs = self.epoch_values()
        self.stopped_observation = self.observe()
        self.revocation_flags("0")
        old_run = self.run_id
        old_id = self.redis_container["id"]
        old_pid = self.docker.inspect(self.redis_container)["State"]["Pid"]
        require(type(old_pid) is int and old_pid > 0, "recovery_old_redis_pid")
        self.docker.stop(self.redis_container)
        fenced_at = time.monotonic()
        # Exact same stopped container, exact same owned /data mount. No empty
        # bootstrap, new Redis volume, catalog import, or run rebinding occurs.
        self.docker.start(self.redis_container)
        new_pid = self.docker.inspect(self.redis_container)["State"]["Pid"]
        require(type(new_pid) is int and new_pid > 0 and new_pid != old_pid, "recovery_redis_process_not_fresh")
        self.redis = base.Redis(self.docker.port(self.redis_container, 6379), self.redis_host,
                                base.tls_context(self.pki.cas["redis"][0]), self.password)
        def ping():
            try:
                return self.redis.command("PING") == "PONG"
            except (ConnectionError, OSError):
                return False
        base.wait_until(self.run, ping, 20, "recovery_same_aof_start")
        self.run_id = self.run_identity()
        require(self.run_id != old_run and self.redis_container["id"] == old_id, "recovery_same_aof_identity")
        require(self.bindings() == self.stopped_bindings, "recovery_same_aof_bindings_changed")
        now = self.observe()
        require(all(now[k] == self.stopped_observation[k] for k in ("catalog_digest", "catalog_generation", "key_count", "byte_count")),
                "recovery_same_aof_catalog_changed")
        self.revocation_flags("0")
        require(self.epoch_values() == self.stopped_epochs, "recovery_same_aof_epoch_changed")
        require(all(int(epoch) >= int(owner["owner_epoch"]) for epoch, owner in zip(self.stopped_epochs, self.old_owners)), "recovery_epoch_rollback")
        self.old_startups(self.stopped_state, self.stopped_bindings)
        while time.monotonic() - fenced_at < FENCING_SECONDS:
            self.run.guard()
            time.sleep(min(0.5, FENCING_SECONDS - (time.monotonic() - fenced_at)))
        require(self.run_identity() == self.run_id, "recovery_redis_restarted_again")
        self.old_ephemeral_absent()
        self.event("same_aof_restart", old_run_id=old_run, new_run_id=self.run_id, redis_id=old_id,
                   old_pid=old_pid, new_pid=new_pid, old_listeners_absent=7,
                   aof_volume=self.states["redis"], catalog_digest=now["catalog_digest"], catalog_generation=now["catalog_generation"],
                   fenced_seconds=round(time.monotonic() - fenced_at, 3), no_catalog_restore=True)

    def epoch_values(self):
        values = [self.redis.command("GET", self.catalog_prefix + "coord:epoch:" + self.tenant + ":" + device) for device in self.devices]
        require(all(isinstance(v, str) and re.fullmatch(r"[1-9][0-9]{0,19}", v) and int(v) < 2**64 for v in values), "recovery_epoch_shape")
        return values

    def old_ephemeral_absent(self):
        for kind in ("owner", "ticket", "tickets"):
            cursor = "0"
            for _ in range(64):
                result = self.redis.command("SCAN", cursor, "MATCH", self.catalog_prefix + "coord:" + kind + ":" + self.old_inventory["deployment_incarnation"] + ":*", "COUNT", "256")
                require(isinstance(result, list) and len(result) == 2 and isinstance(result[0], str)
                        and re.fullmatch(r"[0-9]{1,20}", result[0]) and result[1] == [], "recovery_old_ephemeral_present")
                cursor = result[0]
                if cursor == "0":
                    break
            else:
                raise Refused("recovery_old_ephemeral_scan_bound")

    def candidate(self):
        inv = copy.deepcopy(self.inventory)
        inv["deployment_incarnation"] = self.prefix + "-recovered-" + secrets.token_hex(4)
        inv["membership"]["revision"] += 1
        rendered = self.private / "recovered-rendered"
        manifest = base.load_renderer().render_to(inv, rendered, example=True)
        for path, sha in manifest["files"].items():
            require(digest((rendered / path).read_bytes()) == sha, "recovery_rendered_hash")
        self.inventory = inv
        self.authority_inventory = json.loads((rendered / "authority/inventory.json").read_bytes())
        for role in (*base.NODES, "authority"):
            public = tomllib.loads((rendered / role / "fly.toml").read_text())["env"]
            self.env[role] = {**self.env[role], **public}
            if role in base.NODES:
                self.membership_files[role] = base.membership_state_file(tomllib.loads((rendered / role / "relay.toml").read_text()), inv["deployment_incarnation"])
                require(self.membership_files[role] != self.old_membership_files[role], "recovery_membership_path_reused")
        self.event("recovery_candidate", deployment_incarnation=inv["deployment_incarnation"], inventory_revision=inv["membership"]["revision"],
                   manifest_sha256=digest(canonical(manifest)))

    def sign(self, observed, version, nonce):
        self.approval_sequence += 1
        seq = str(self.approval_sequence)
        now = dt.datetime.now(dt.timezone.utc)
        approval = {key: observed[key] for key in ("deployment_id", "redis_namespace", "redis_run_id", "deployment_incarnation", "catalog_digest")}
        approval.update(schema_version=1, approval_version=version, nonce=nonce,
                        issued_at=now.isoformat(), not_before=now.isoformat(), expires_at=(now + dt.timedelta(seconds=60)).isoformat())
        inputs, outputs = self.docker.volume("approval-input-" + seq), self.docker.volume("approval-output-" + seq)
        self.docker.setup_volume(inputs, 10002, 10002, {"observed.json": canonical(observed), "approval.json": canonical(approval)})
        self.docker.setup_volume(outputs, 10002, 10002)
        self.docker.one_shot("offline-approval", self.docker.images["authority"], network=False,
            mounts=[(self.offline, "/offline", False), (inputs, "/input", False), (outputs, "/output", True)],
            entrypoint="/usr/local/bin/tunnel-authority", command=["sign-recovery-approval", "--key", "/offline/recovery.der",
                "--key-id", "synthetic-recovery", "--observation", "/input/observed.json", "--approval", "/input/approval.json",
                "--expected-nonce", nonce, "--output", "/output/signed.json"])
        signed = self.docker.read_volume(outputs, ["signed.json"], max_bytes=16 * 1024)["signed.json"]
        delivery = self.docker.volume("approval-delivery-" + seq)
        self.docker.setup_volume(delivery, 10001, 10001, {"signed.json": signed})
        self.event("offline_approval", approval_version=version, catalog_digest=observed["catalog_digest"],
                   nonce_sha256=digest(nonce.encode()), signed_sha256=digest(signed), network_none=True)
        return delivery

    def recover(self, delivery, nonce, *, refusal=None, acknowledgements=True):
        command = ["recover", "--approval", base.ROLE_BASE["relay"] + "/operator/signed.json", "--expected-nonce", nonce,
                   "--acknowledgement-id", self.prefix + "-stopped-all-roles"]
        if acknowledgements:
            command += ["--old-primary-fenced", "--old-relays-fenced"]
        return self.operator("relay-a", command, refusal=refusal,
                             extra_mounts=[(delivery, base.ROLE_BASE["relay"] + "/operator", False)])

    def fence_unchanged(self, expected):
        raw = self.docker.read_volume(self.states["relay-a"], [FENCE_FILE], max_bytes=4096)[FENCE_FILE]
        require(raw == expected, "recovery_refusal_consumed_fence")
        require(self.bindings()[:2] == self.stopped_bindings[:2], "recovery_refusal_activated")

    def explicit_recovery(self):
        self.candidate()
        designated = self.stopped_state["relay-a"][FENCE_FILE]
        version = next_approval_version(designated, self.inventory)
        observed = self.observe()
        nonce = secrets.token_hex(24)  # independently chosen, not copied from observation
        delivery = self.sign(observed, version, nonce)
        self.recover(delivery, nonce, refusal="missing_fences", acknowledgements=False)
        self.fence_unchanged(designated)
        self.recover(delivery, secrets.token_hex(24), refusal="wrong_nonce")
        self.fence_unchanged(designated)
        self.stale_digest_control(delivery, nonce, designated)
        fresh = self.observe()
        final_nonce = secrets.token_hex(24)
        final_delivery = self.sign(fresh, version, final_nonce)
        raw = self.recover(final_delivery, final_nonce)  # one dispatch; unknown outcome is terminal
        result = base.observation_json(raw, 16 * 1024)
        expected = {"schema_version": 1, "approval_version": version, "deployment_incarnation": self.inventory["deployment_incarnation"],
                    "redis_run_id": self.run_id, "catalog_digest": fresh["catalog_digest"], "quiescence_declared": True}
        require(isinstance(result, dict) and set(result) == set(expected)
                and type(result["schema_version"]) is int and result["schema_version"] == 1
                and base.u64(result["approval_version"]) and result["approval_version"] > 0
                and result["quiescence_declared"] is True and result == expected, "recovery_outcome_identity")
        require(self.bindings()[:2] == [self.inventory["deployment_incarnation"], self.run_id], "recovery_active_bindings")
        self.consumed_fence = self.docker.read_volume(self.states["relay-a"], [FENCE_FILE], max_bytes=4096)[FENCE_FILE]
        check_fence(self.consumed_fence, self.inventory, version)
        self.recover(final_delivery, final_nonce, refusal="replay")
        require(self.docker.read_volume(self.states["relay-a"], [FENCE_FILE], max_bytes=4096)[FENCE_FILE] == self.consumed_fence, "recovery_replay_changed_fence")
        state = self.private_state(self.old_membership_files)
        require(state["authority"] == self.stopped_state["authority"], "recovery_authority_mutated_early")
        for node in base.NODES:
            require(state[node][self.old_membership_files[node]] == self.stopped_state[node][self.old_membership_files[node]], "recovery_old_membership_mutated")
            require(state[node][FENCE_FILE] == (self.consumed_fence if node == "relay-a" else self.stopped_state[node][FENCE_FILE]), "recovery_independent_fence_mutated")
        self.old_startups(state, self.bindings(), activated=True)
        self.event("explicit_recovery", approval_version=version, designated_fence_node="relay-a", replay_refused=True,
                   deployment_incarnation=self.inventory["deployment_incarnation"], redis_run_id=self.run_id)

    def stale_digest_control(self, delivery, nonce, fence):
        # This is a synthetic concurrency negative, NOT backup reconciliation.
        # Unknown Redis outcomes end the scenario: do not restore/retry/sign.
        before = self.redis.command("HGET", self.catalog_prefix + "tenant:" + self.tenant, "display_name")
        generation = self.bindings()[2]
        require(isinstance(generation, str) and generation.isdecimal() and int(generation) <= 2**64 - 3,
                "negative_catalog_restore_generation_reserve")
        after = "Synthetic tenant digest-negative"
        args = display_name_command(self.catalog_prefix, self.tenant, before, after, generation,
                                    self.stopped_bindings[0], self.stopped_bindings[1])
        reply = self.redis.command(*args)
        require(reply == ["ok", after, str(int(generation) + 1)], "negative_catalog_mutation_outcome")
        self.recover(delivery, nonce, refusal="stale_digest")
        self.fence_unchanged(fence)
        self.revocation_flags("0")
        restore = display_name_command(self.catalog_prefix, self.tenant, after, before, reply[2],
                                       self.stopped_bindings[0], self.stopped_bindings[1])
        require(self.redis.command(*restore) == ["ok", before, str(int(generation) + 2)], "negative_catalog_restore_outcome")
        self.revocation_flags("0")
        fresh = self.observe()
        require(fresh["catalog_digest"] == self.stopped_observation["catalog_digest"]
                and fresh["catalog_generation"] == str(int(generation) + 2), "negative_catalog_restored_field")
        self.event("stale_digest_negative", field="synthetic_tenant_display_name", generation_before=generation,
                   generation_after=fresh["catalog_generation"], fence_unchanged=True, backup_restore=False)

    def adopt(self, previous, round_number):
        watch = base.PublicationWatch(previous)
        def poll():
            current = self.publication(watch.latest)
            watch.observe(current)
            if watch.target is None:
                return False
            require(base.utc_ns() < watch.target["expires_ns"], "adoption_target_expired")
            states = {}
            for node in base.NODES:
                name = self.membership_files[node]
                raw = self.docker.read_volume(self.states[node], [name], max_bytes=base.MAX_RELAY_OBSERVATION)[name]
                self.run.guard()
                states[node] = base.relay_observation(raw, self.authority_inventory, node)
            self.run.guard()
            if not watch.adopted(states, base.utc_ns()):
                return False
            self.event("recovery_passive_adoption", round=round_number, membership_version=watch.target["membership_version"],
                       checkpoint_floor=watch.target["checkpoint_version"], nodes=list(base.NODES), states=states)
            return True
        with self.run.budget(30):
            base.wait_until(self.run, poll, 30, "recovery_adoption_deadline")
        return watch.latest

    def restart_serving(self):
        self.operator("authority", ["approve-membership", "--expected-revision", str(self.stopped_authority["inventory"]["revision"]),
                                    "--expected-redis-run-id", self.run_id])
        raw = self.docker.read_volume(self.states["authority"], ["authority.json"], max_bytes=base.MAX_AUTHORITY_OBSERVATION)["authority.json"]
        approved = json.loads(raw)
        check_approved_state(self.stopped_authority, approved, self.authority_inventory, self.run_id)
        for node in base.NODES:
            self.operator(node, ["initialize"])  # explicit new-incarnation path; never recovery-initialize
        self.start_authority()
        def confirmed():
            current = self.publication(approved)
            return current["confirmed"] is not None and current["confirmed"]["membership_version"] > approved["membership_high_water"]
        with self.run.budget(30):
            base.wait_until(self.run, confirmed, 30, "recovery_first_confirmation")
        for i, relay in enumerate(self.inventory["relays"]):
            node = relay["node_id"]
            item = self.docker.create(node, self.docker.images["relay"], memory=512, env=self.env[node],
                mounts=[(self.states[node], base.ROLE_BASE["relay"] + "/state", True)],
                aliases=[relay["app"] + ".internal", self.public_hosts[i]], ports=[8443, 9443])
            self.docker.start(item)
            self.relays.append(item)
        self.consumer_ports = [self.docker.port(item, 8443) for item in self.relays]
        self.device_ports = [self.docker.port(item, 9443) for item in self.relays]
        publication = self.adopt(approved, 1)
        require(publication["membership_high_water"] > self.stopped_authority["membership_high_water"]
                and publication["checkpoint_high_water"] > self.stopped_authority["checkpoint_high_water"], "recovery_allocators_not_advanced")
        self.wait_ready()
        for i in range(3):
            self.start_client(i)
            check_fresh_owner(self.old_owners[i], self.owner(i), self.old_status[i], self.status(i), self.inventory["deployment_incarnation"])
        require(all(int(new) > int(old) for old, new in zip(self.stopped_epochs, self.epoch_values())), "recovery_epoch_not_advanced")
        for round_number in range(1, 4):
            if round_number > 1:
                publication = self.adopt(publication, round_number)
            self.assert_revocations()
            self.event("recovery_routes_and_revocations", round=round_number, positive_routes=9, remote_positive_routes=6,
                       fresh_cli_clients=3, revoked_grant_routes=3, revoked_spare_credential=True)
        after = self.private_state(self.old_membership_files)
        for node in base.NODES:
            require(after[node][self.old_membership_files[node]] == self.stopped_state[node][self.old_membership_files[node]], "recovery_old_membership_changed_final")
            require(after[node][FENCE_FILE] == (self.consumed_fence if node == "relay-a" else self.stopped_state[node][FENCE_FILE]), "recovery_fence_changed_final")
        require(self.run_identity() == self.run_id, "recovery_run_changed_final")
        self.old_ephemeral_absent()

    def execute(self):
        for stage, method in (("prepare", self.prepare), ("bootstrap", self.bootstrap)):
            self.run.stage = stage
            method()
        self.run.stage = "baseline_routes"
        for i in range(3):
            self.start_client(i)
        self.all_routes()
        self.run.stage = "baseline_revocations"
        self.setup_revocations()
        self.run.stage = "same_aof_restart"
        self.stop_and_restart()
        self.run.stage = "explicit_recovery"
        self.explicit_recovery()
        self.run.stage = "recovered_adoption"
        self.restart_serving()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", required=True, choices=["durable-restart"])
    for role in ("relay", "authority", "redis", "client"):
        parser.add_argument("--" + role + "-image", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    images = {role: getattr(args, role + "_image") for role in ("relay", "authority", "redis", "client")}
    require(all(base.IMAGE_RE.fullmatch(value) for value in images.values()), "immutable_image_id_required")
    args.output.mkdir(mode=0o700)
    started = time.monotonic()
    result = {"schema_version": 1, "status": "failed", "scope": "same-aof-three-relay-recovery", "scenario": args.scenario,
              "limitations": LIMITATIONS, "main_bound_seconds": base.MAIN_SECONDS, "cleanup_bound_seconds": base.CLEANUP_SECONDS}
    def event(kind, **fields):
        with (args.output / "events.jsonl").open("ab") as file:
            file.write(canonical({"event": kind, "elapsed_seconds": round(time.monotonic() - started, 3), **fields}))
    with tempfile.TemporaryDirectory(prefix="agentuplink-fly-recovery-private-") as tmp:
        private = Path(tmp)
        run = RecoveryRunner(private, event)
        base.NETWORK_DEADLINE = run.deadline
        docker = RecoveryDocker(run, "aur-" + secrets.token_hex(6), images)
        first_error, source, receipts = None, None, {}
        interruptions = []
        def interrupted(signum, _frame):
            run.stop_requested = True
            interruptions.append({"signal": signum, "stage": run.stage, "operation": run.operation, "during_cleanup": run.cleanup})
        previous_signals = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)}
        try:
            run.initial = base.resource_sample(private)
            base.check_resources(run.initial, run.initial, startup=True)
            result["fencing_source_sha256"] = check_source_bounds()
            source = base.source_receipt(run)
            base.private_write(args.output / "source.json", canonical(source))
            result["docker_engine"] = docker.engine_preflight()
            sizes = {}
            for role, identity in images.items():
                rows = json.loads(docker.call(["image", "inspect", identity]))
                require(len(rows) == 1, "image_inspection_cardinality")
                receipts[role] = base.check_image(rows[0], identity, source["commit"])
                require(type(rows[0].get("Size")) is int and rows[0]["Size"] > 0, "image_size_observation")
                sizes[role] = rows[0]["Size"]
            # Conservative writable-copy estimate, not a measured guarantee.
            # Nine serving/probe copies plus one helper at peak; actual disk
            # floors remain enforced on every guarded command afterwards.
            reserve = (3 * sizes["relay"] + 4 * sizes["client"] + sizes["authority"] + sizes["redis"]
                       + max(sizes.values()) + base.MAX_PRIVATE + 64 * 1024**2 + 1536 * 1024**2)
            require(shutil.disk_usage(run.docker_root).free >= reserve, "recovery_image_copy_reserve")
            result["image_copy_reserve"] = {"estimated_required_free": reserve, "image_sizes": sizes, "guaranteed_peak": False}
            for role in images:
                receipts[role]["artifacts"] = docker.artifact_receipt(role)
            base.private_write(args.output / "images.json", canonical(receipts))
            RecoveryRehearsal(run, docker, private, event).execute()
        except BaseException as exc:
            first_error = base.error_code(exc)
        if run.stop_requested and first_error is None:
            first_error = "controller_interrupted"
        result.update(failure_stage=run.stage if first_error else None, failure_operation=run.operation if first_error else None,
                      failure_subcommand=run.subcommand if first_error else None)
        cleanup_errors = docker.cleanup()
        try:
            result["final_resources"] = base.resource_sample(private)
            base.check_resources(result["final_resources"], run.initial)
            require(all(not base.group_present(pid) for pid in run.processes), "owned_process_group_remains")
        except BaseException as exc:
            cleanup_errors.append({"resource": "final-observation", "code": base.error_code(exc)})
        try:
            if source is not None:
                require(base.source_receipt(run) == source, "final_source_changed")
                require(check_source_bounds() == result["fencing_source_sha256"], "final_fencing_source_changed")
                for role in receipts:
                    base.check_image(json.loads(docker.call(["image", "inspect", images[role]]))[0], images[role], source["commit"])
                result["final_source_images_unchanged"] = True
        except BaseException as exc:
            cleanup_errors.append({"resource": "final-inputs", "code": base.error_code(exc)})
        cleanup_errors += [{"resource": "cleanup-observation", "code": code} for code in run.cleanup_guard_failures]
        if interruptions and first_error is None:
            first_error = "controller_interrupted"
        result.update(first_failure=first_error, cleanup_errors=cleanup_errors, containers=docker.inventory,
                      process_groups=len(run.processes), resource_samples=run.samples, interruptions=interruptions,
                      readiness_diagnostic_failures=run.readiness_diagnostic_failures,
                      elapsed_seconds=round(time.monotonic() - started, 3))
        if first_error is None and not cleanup_errors and not interruptions:
            result["status"] = "passed"
        base.private_write(args.output / "result.json", canonical(result))
        for sig, handler in previous_signals.items():
            signal.signal(sig, handler)
        base.NETWORK_DEADLINE = None
    print("Fly same-AOF recovery rehearsal: " + result["status"] + "; sanitized receipt: " + str(args.output / "result.json"))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
