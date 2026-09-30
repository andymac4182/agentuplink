#!/usr/bin/env bash
# Task11 integration runner: reuse the existing approved synthetic VM.
# No VM clone/delete, host desktop input, or task10 backend termination.
# Needs explicit approval and Linux ARM64 binaries; see docs/demo/cua.md.
set -euo pipefail
# Preparation only until the operator has the explicit bundled approval.
[ "${CUA_REUSE_APPROVED:-}" = 1 ] || { echo 'refusing: explicit reused-guest CUA approval required' >&2; exit 2; }
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TART="${TART:-tart}"
TOOLS="${ROOT}/scripts/m5-cua-demo.py"
NONCE="$(openssl rand -hex 6)"
HEAD="$(git -C "${ROOT}" rev-parse HEAD)"
[ -z "$(git -C "${ROOT}" status --porcelain)" ] || { echo "refusing dirty source" >&2; exit 2; }
VM="${CUA_VM:?name of the explicitly approved running synthetic Tart VM}"
EXPECTED_GUEST_IP="${CUA_GUEST_IP:?approved Tart NAT address}"
GD="${CUA_GUEST_WORKSPACE:?new guest-only workspace under /home/cua}"
[[ "${VM}" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "invalid VM name" >&2; exit 2; }
[[ "${EXPECTED_GUEST_IP}" =~ ^192\.168\.64\.[0-9]+$ ]] || { echo "expected a Tart NAT address" >&2; exit 2; }
[[ "${GD}" =~ ^/home/cua/[A-Za-z0-9._-]+$ ]] || { echo "invalid guest-only workspace" >&2; exit 2; }
case "${GD##*/}" in .|..) echo "invalid guest workspace" >&2; exit 2;; esac
# Physical path: `tunnel-relay` refuses a Redis CA path through a symlink,
# and macOS's TMPDIR (/var -> /private/var) is one.
WORK="$(cd "$(mktemp -d "/tmp/agentuplink-cua-reuse-${NONCE}.XXXX")" && pwd -P)"
OUT="${1:-${WORK}/evidence}"
RELAY_HOST="localhost"
ISSUER="https://issuer.m5-cua-demo.invalid/"
AUDIENCE="agent-tunnel"
RECORDS="${ROOT}/examples/m6-catalog-cua.toml"
DEVICE="33333333-3333-4333-8333-333333333333"
SERVICE="77777777-7777-4777-8777-777777777777"
SUBJECT="trial-user"
NAMESPACE="m5-cua-demo-${NONCE}"
DEMO_TEXT="agentuplink-demo"

die() { echo "m5-cua-demo: $*" >&2; exit 1; }
log() { echo "m5-cua-demo: $*" >&2; }

: "${TEST_REDIS_URL:?TEST_REDIS_URL (a disposable plaintext Redis) is required}"
REDIS_HOSTPORT="${TEST_REDIS_URL#redis://}"; REDIS_HOSTPORT="${REDIS_HOSTPORT%%/*}"
REDIS_DB="${TEST_REDIS_URL##*/}"; [ -n "${REDIS_DB}" ] && [ "${REDIS_DB}" != "${TEST_REDIS_URL}" ] || REDIS_DB=0
: "${GUEST_BIN_DIR:?GUEST_BIN_DIR must hold aarch64 tunnel-client (--features cua) and tunnel-deadman}"
for bin in tunnel-client tunnel-deadman; do
  [ -x "${GUEST_BIN_DIR}/${bin}" ] || die "${GUEST_BIN_DIR}/${bin} is missing"
  file "${GUEST_BIN_DIR}/${bin}" | grep -q 'ELF 64-bit.*aarch64' || die "${bin} is not an aarch64 ELF"
done

mkdir -p "${OUT}"
echo "nonce=${NONCE} head=${HEAD} m5-cua-demo start $(date +%Y-%m-%dT%H:%M:%S%z) vm=${VM} namespace=${NAMESPACE}" | tee "${OUT}/run.txt" >&2

CLEANUP=()
stop_host_jobs() {
  local pid remaining attempt
  # Catch a signal between starting a child and registering its normal cleanup.
  # These jobs belong to this script, never another terminal or host service.
  for pid in $(jobs -pr); do kill -TERM "${pid}" 2>/dev/null || true; done
  for attempt in $(seq 1 20); do
    remaining="$(jobs -pr)"
    [ -n "${remaining}" ] || break
    sleep 0.1
  done
  for pid in $(jobs -pr); do kill -KILL "${pid}" 2>/dev/null || true; done
  for pid in $(jobs -p); do wait "${pid}" 2>/dev/null || true; done
  [ -z "$(jobs -pr)" ]
}

on_exit() {
  local code=$? i cleanup_failed=0
  trap - EXIT
  trap '' INT TERM
  for ((i = ${#CLEANUP[@]} - 1; i >= 0; i--)); do
    if [ "${i}" = 0 ]; then stop_host_jobs || cleanup_failed=1; fi
    ( eval "${CLEANUP[i]}" ) || { log "cleanup step ${i} failed; inspect task-owned resources"; cleanup_failed=1; }
  done
  [ "${cleanup_failed}" = 0 ] || code=1
  exit "${code}"
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
CLEANUP+=("rm -rf $(printf %q "${WORK}/secrets") $(printf %q "${WORK}/redis"); rm -f $(printf %q "${WORK}/fixture-state-before.json")")

# ---- host binaries ---------------------------------------------------------
if [ -z "${RELAY_BIN:-}" ]; then
  log "building tunnel-relay"
  cargo build --offline --locked -p tunnel-relay --bin tunnel-relay --manifest-path "${ROOT}/Cargo.toml" >&2
  RELAY_BIN="${CARGO_TARGET_DIR:-${ROOT}/target}/debug/tunnel-relay"
fi
[ -x "${RELAY_BIN}" ] || die "no tunnel-relay at ${RELAY_BIN}"

# ---- reuse the existing approved guest; no VM lifecycle mutations ---------
GUEST_IP="$("${TART}" ip "${VM}")"
[ "${GUEST_IP}" = "${EXPECTED_GUEST_IP}" ] || die "guest address changed: ${GUEST_IP}"
gexec() { "${TART}" exec "${VM}" "$@"; }
gexec_in() { "${TART}" exec -i "${VM}" "$@"; }
stop_guest() {
  local pid port
  pid="$(gexec sudo -u cua cat "${GD}/client.pid")"
  [[ "${pid}" =~ ^[0-9]+$ ]] || return 1
  gexec sudo -u cua bash -c "if kill -0 ${pid} 2>/dev/null; then [ \"\$(ps -o pgid= -p ${pid} | tr -d ' ')\" = ${pid} ] && kill -TERM -- -${pid}; fi"
  sleep 2
  if gexec sudo -u cua pgrep -f "${GD}/(tunnel-client|tunnel-deadman|cua-backend-supervised)" >/dev/null; then
    log "guest processes remain; preserve runtime directory for inspection"
    return 1
  fi
  if port="$(gexec sudo -u cua cat "${GD}/workspace/backend.address" 2>/dev/null)"; then
    port="${port##*:}"
    [ -z "$(gexec ss -Hltn "sport = :${port}")" ] || { log "backend listener remains on ${port}"; return 1; }
  fi
}
gexec sudo bash /opt/cua-fixture/guest-manifest.sh >"${OUT}/manifest.json"
gexec cat /tmp/cua-fixture/state.json >"${WORK}/fixture-state-before.json"
# Reserve fixed approval endpoints by checking; actual binds must fail on collision.
python3 - <<'PORTS'
import socket
for port in (18443, 18444, 16398, 18445):
    with socket.socket() as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('127.0.0.1', port))
PORTS
[ "${TEST_REDIS_URL}" = redis://127.0.0.1:16398/0 ] || die "Redis must be dedicated approved endpoint"
: "${REDIS_BIN:?existing redis-server binary required}"
mkdir -m 700 "${WORK}/redis"
"${REDIS_BIN}" --bind 127.0.0.1 --port 16398 --save '' --appendonly no --dir "${WORK}/redis" >"${WORK}/redis.log" 2>&1 &
REDIS_PID=$!
CLEANUP+=("kill ${REDIS_PID} 2>/dev/null || true; wait ${REDIS_PID} 2>/dev/null || true")
for _ in $(seq 1 50); do grep -q 'Ready to accept connections' "${WORK}/redis.log" && break; kill -0 "${REDIS_PID}" || die "Redis exited"; sleep 0.1; done
owners="$(lsof -nP -iTCP:16398 -sTCP:LISTEN -t | sort -u)"
[ "${owners}" = "${REDIS_PID}" ] || die "Redis port ownership mismatch"

# ---- synthetic PKI and identity issuer (host, in WORK/secrets) -------------
S="${WORK}/secrets"; mkdir -m 700 -p "${S}"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=m5-cua-demo synthetic server CA" \
  -keyout "${S}/server-ca-key.pem" -out "${S}/server-ca.pem" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=m5-cua-demo synthetic relay" \
  -keyout "${S}/relay-key.pem" -out "${S}/relay.csr" 2>/dev/null
printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:%s,DNS:localhost,IP:127.0.0.1\n' \
  "${RELAY_HOST}" >"${S}/relay-ext.cnf"
openssl x509 -req -in "${S}/relay.csr" -CA "${S}/server-ca.pem" -CAkey "${S}/server-ca-key.pem" \
  -CAcreateserial -days 1 -extfile "${S}/relay-ext.cnf" -out "${S}/relay-cert.pem" 2>/dev/null
cat "${S}/relay-cert.pem" "${S}/server-ca.pem" >"${S}/relay-chain.pem"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=m5-cua-demo synthetic device CA" \
  -keyout "${S}/device-ca-key.pem" -out "${S}/device-ca.pem" 2>/dev/null
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${S}/issuer-key.pem" 2>/dev/null
python3 "${TOOLS}" jwks "${S}/issuer-key.pem" "${S}/jwks.json"

# ---- Redis TLS terminator ----------------------------------------------------
python3 "${TOOLS}" tls-forward "${S}/relay-chain.pem" "${S}/relay-key.pem" "${REDIS_HOSTPORT}" "${S}/redis-tls.port" --bind-port 18445 &
CLEANUP+=("kill $! 2>/dev/null")
for _ in $(seq 1 50); do [ -s "${S}/redis-tls.port" ] && break; sleep 0.1; done
REDIS_TLS_PORT="$(cat "${S}/redis-tls.port")"
CLEANUP+=("python3 $(printf %q "${TOOLS}") redis-clean $(printf %q "${REDIS_HOSTPORT}") ${REDIS_DB} $(printf %q "${NAMESPACE}") >&2")

# ---- relay configuration -------------------------------------------------------
free_port() { python3 -c 'import socket,sys; s=socket.socket(); s.bind((sys.argv[1], 0)); print(s.getsockname()[1]); s.close()' "$1"; }
CONSUMER_PORT=18443
DEVICE_PORT=18444
python3 - "${ROOT}/examples/m1-relay.toml" "${WORK}/relay.toml" <<EOF
import re, sys
text = open(sys.argv[1]).read()
values = {
    "consumer_bind": '"127.0.0.1:${CONSUMER_PORT}"',
    "device_bind": '"127.0.0.1:${DEVICE_PORT}"',
    "oidc_issuer": '"${ISSUER}"',
    "oidc_jwks_path": '"${S}/jwks.json"',
    "redis_url": '"rediss://localhost:${REDIS_TLS_PORT}/${REDIS_DB}"',
    "redis_namespace": '"${NAMESPACE}"',
    "device_tls_cert_chain": '"${S}/relay-chain.pem"',
    "device_tls_private_key": '"${S}/relay-key.pem"',
    "device_tls_client_ca": '"${S}/device-ca.pem"',
    "consumer_tls_cert_chain": '"${S}/relay-chain.pem"',
    "consumer_tls_private_key": '"${S}/relay-key.pem"',
    "node_id": '"relay-m5-cua-demo"',
    "boot_id": '"m5-cua-demo-boot-${NONCE}"',
    "deployment_incarnation": '"${NAMESPACE}"',
}
for key, value in values.items():
    text, count = re.subn(rf"(?m)^{key} = .*$", f"{key} = {value}", text)
    assert count == 1, key
text = 'redis_tls_root_ca_path = "${S}/server-ca.pem"\n' + text + '\n[http_forward]\nprofiles = ["computer-v1"]\n'
open(sys.argv[2], "w").write(text)
EOF

# ---- the device (guest): binaries, relay name, key, CSR ---------------------
log "installing the device binaries and the backend wrapper in the guest"
gexec sudo -u cua mkdir -m 700 "${GD}"
# Only this new task directory is owned by this run. Cleanup leaves task10 intact.
cleanup_guest_runtime() {
  if gexec sudo -u cua test -f "${GD}/client.pid"; then stop_guest || return 1; fi
  gexec sudo -u cua rm -rf -- "${GD}"
}
CLEANUP+=("cleanup_guest_runtime")
COPYFILE_DISABLE=1 tar -C "${GUEST_BIN_DIR}" -cf - tunnel-client tunnel-deadman \
  | gexec_in sudo -u cua tar -C "${GD}" -xf -
gexec_in sudo -u cua tee "${GD}/cua-backend-supervised.sh" >/dev/null <"${ROOT}/tests/cua-fixture/cua-backend-supervised.sh"
gexec sudo -u cua chmod 0755 "${GD}/cua-backend-supervised.sh"
GUEST_PORT=18444
gexec python3 -c 'import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("127.0.0.1",18444)); s.close()'
SSH_STATE="${M5_CUA_VM_STATE:-${HOME}/.local/state/agentuplink-m5-cua-vm}"
[ -f "${SSH_STATE}/id_ed25519" ] || die "no probe SSH key at ${SSH_STATE}/id_ed25519 (built with cua-golden)"
hostkey="$(gexec cat /etc/ssh/ssh_host_ed25519_key.pub | awk '{print $1, $2}')"
case "${hostkey}" in "ssh-ed25519 "?*) ;; *) die "could not read the guest's ed25519 host key";; esac
echo "${GUEST_IP} ${hostkey}" >"${S}/known_hosts"
gexec sudo -u cua mkdir -m 700 "${GD}/workspace"
gexec_in sudo -u cua tee "${GD}/server-ca.pem" >/dev/null <"${S}/server-ca.pem"
python3 - "${ROOT}/examples/m1-client.toml" <<EOF | gexec_in sudo -u cua tee "${GD}/client.toml" >/dev/null
import re, sys
text = open(sys.argv[1]).read()
text = re.sub(r'(?m)^relay_url = .*$', 'relay_url = "wss://${RELAY_HOST}:${GUEST_PORT}/v1/tunnel/control"', text)
start = text.index("[exports.")
end = text.index("\n\n", start)
export = '''[exports."${SERVICE}"]
type = "http-forward"

[exports."${SERVICE}".cua]
profile = "computer-v1"
point_width = 1280
point_height = 800
operations = ["describe", "capture", "screen_info", "cursor_position", "click", "double_click", "move", "drag", "scroll", "type_text", "press_key", "hotkey"]

[exports."${SERVICE}".cua.backend]
command = "${GD}/cua-backend-supervised.sh"
args = ["${GD}/workspace/backend.address"]
workspace = "${GD}/workspace"
address_file = "${GD}/workspace/backend.address"
env = { PATH = "/usr/local/bin:/usr/bin:/bin", HOME = "/home/cua" }
startup_seconds = 90'''
sys.stdout.write(text[:start] + export + text[end:])
EOF
gexec sudo -u cua ${GD}/tunnel-client credentials create --config "${GD}/client.toml" --csr-out device.csr >&2
gexec sudo -u cua cat "${GD}/device.csr" >"${S}/device.csr"

# ---- the issuer's step (host): sign the device CSR ---------------------------
printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\nsubjectAltName=URI:urn:agent-tunnel:device:%s\n' "${DEVICE}" >"${S}/device-ext.cnf"
openssl x509 -req -in "${S}/device.csr" -CA "${S}/device-ca.pem" -CAkey "${S}/device-ca-key.pem" \
  -CAcreateserial -days 1 -extfile "${S}/device-ext.cnf" -out "${S}/device-cert.pem" 2>/dev/null
gexec_in sudo -u cua tee "${GD}/device-cert.pem" >/dev/null <"${S}/device-cert.pem"
gexec sudo -u cua ${GD}/tunnel-client credentials import --config "${GD}/client.toml" \
  --certificate device-cert.pem --server-ca "${GD}/server-ca.pem" >&2

# ---- the operator's steps (host): provision and serve --------------------------
cp "${RECORDS}" "${S}/catalog.toml"
( cd "${S}" && "${RELAY_BIN}" provision-catalog --config "${WORK}/relay.toml" --records catalog.toml --dry-run ) >&2
"${RELAY_BIN}" activate-first-incarnation --config "${WORK}/relay.toml" >&2
( cd "${S}" && "${RELAY_BIN}" provision-catalog --config "${WORK}/relay.toml" --records catalog.toml ) >&2
RUST_LOG=warn "${RELAY_BIN}" serve --config "${WORK}/relay.toml" 2>"${WORK}/relay.log" &
RELAY_PID=$!
CLEANUP+=("kill ${RELAY_PID} 2>/dev/null; sleep 1")
for _ in $(seq 1 100); do grep -q "tunnel-relay listening" "${WORK}/relay.log" && break; kill -0 "${RELAY_PID}" || die "relay exited: $(tail -5 "${WORK}/relay.log")"; sleep 0.2; done
grep -q "tunnel-relay listening" "${WORK}/relay.log" || die "relay never listened"

# The ownership gate: each relay port has the relay as its ONLY listener.
for port in "${CONSUMER_PORT}" "${DEVICE_PORT}"; do
  owners="$({ lsof -nP -iTCP:"${port}" -sTCP:LISTEN -t 2>/dev/null || true; } | sort -u | tr '\n' ' ')"
  [ "${owners}" = "${RELAY_PID} " ] || die "port ${port} listeners are '${owners}', expected only the relay ${RELAY_PID}"
done
log "relay ${RELAY_PID} owns consumer 127.0.0.1:${CONSUMER_PORT} and device 127.0.0.1:${DEVICE_PORT}"
ssh -i "${SSH_STATE}/id_ed25519" -o StrictHostKeyChecking=yes -o UserKnownHostsFile="${S}/known_hosts" \
    -o HostKeyAlgorithms=ssh-ed25519 -o IdentitiesOnly=yes -o LogLevel=ERROR \
    -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 -N \
    -R "127.0.0.1:${GUEST_PORT}:127.0.0.1:${DEVICE_PORT}" "admin@${GUEST_IP}" &
SSH_PID=$!
CLEANUP+=("kill ${SSH_PID} 2>/dev/null")
# The guest-side ownership gate: the forwarded port's only listener is sshd.
owner=""
for _ in $(seq 1 40); do
  kill -0 "${SSH_PID}" 2>/dev/null || die "ssh reverse forward exited"
  forward_state="$(gexec sudo ss -Hltnp "sport = :${GUEST_PORT}" 2>/dev/null)"
  owner="$(printf '%s\n' "${forward_state}" | grep -o 'users:(("[a-z-]*"' | sort -u | tr '\n' ' ' || true)"
  [ -n "${owner}" ] && break
  sleep 0.5
done
case "${owner}" in 'users:(("sshd" '|'users:(("sshd-session" ') ;; *) false;; esac || die "guest port ${GUEST_PORT} listeners are '${owner}', expected only sshd"
binding="$(printf '%s\n' "${forward_state}" | awk '{print $4}')"
[ "${binding}" = "127.0.0.1:${GUEST_PORT}" ] || die "guest forward is not the approved loopback binding: ${binding}"
log "guest 127.0.0.1:${GUEST_PORT} forwards to the relay's device listener over SSH"

# ---- connect the device (guest), opted in to Lane B ----------------------------
gexec sudo -u cua bash -c "setsid env AGENT_TUNNEL_CUA_LANE_B=1 TUNNEL_DEADMAN_BIN=${GD}/tunnel-deadman ${GD}/tunnel-client connect --config ${GD}/client.toml --json >${GD}/connect.log 2>&1 </dev/null & echo \$! >${GD}/client.pid"
# Signal only the process group started by this run, never broad pkill.
CLEANUP+=("stop_guest")
for _ in $(seq 1 100); do
  gexec sudo -u cua grep -q '"ready"' "${GD}/connect.log" 2>/dev/null && break
  sleep 0.3
done
gexec sudo -u cua grep -q '"ready"' "${GD}/connect.log" || die "device not ready: $(gexec sudo -u cua tail -5 "${GD}/connect.log")"
log "device session ready"

# ---- the consumer (host) ---------------------------------------------------------
python3 "${TOOLS}" token "${S}/issuer-key.pem" "${ISSUER}" "${AUDIENCE}" "${SUBJECT}" >"${S}/token"
chmod 600 "${S}/token"
gexec cat /tmp/cua-fixture/state.json >"${S}/state.json"
set +e
python3 "${TOOLS}" consumer --consumer-port "${CONSUMER_PORT}" --device "${DEVICE}" --service "${SERVICE}" \
  --ca "${S}/server-ca.pem" --token-file "${S}/token" --state "${S}/state.json" --out "${OUT}" --text "${DEMO_TEXT}" --reset-entry
consumer_exit=$?
set -e
gexec sudo -u cua cat "${GD}/workspace/backend.address" >"${OUT}/backend.address"
sleep 1
gexec cat /tmp/cua-fixture/state.json >"${OUT}/fixture-state-after.json"
gexec sudo -u cua cat "${GD}/connect.log" | grep -v '^\s*$' >"${OUT}/connect.log" || true
grep -v 'token\|Bearer' "${WORK}/relay.log" >"${OUT}/relay.log" || true

# ---- the verdict, from the application's own state file --------------------------
python3 - "${OUT}" "${DEMO_TEXT}" "${consumer_exit}" "${WORK}/fixture-state-before.json" <<'EOF'
import json, sys
out, text, consumer_exit = sys.argv[1], sys.argv[2], int(sys.argv[3])
before = json.load(open(sys.argv[4]))
after = json.load(open(f"{out}/fixture-state-after.json"))
consumer = json.load(open(f"{out}/consumer.json"))
verdict = {
    "consumer_exit": consumer_exit,
    "clicks_before": before["clicks"], "clicks_after": after["clicks"],
    "text_before_chars": len(before["text"]),
    "text_matches": after["text"] == text,
    "markers_match_fixture": consumer.get("markers_match_fixture"),
    "unleased_click": consumer.get("unleased_click"),
    "stale_click": consumer.get("stale_click"),
}
verdict["ok"] = (consumer_exit == 0 and verdict["clicks_after"] == verdict["clicks_before"] + 1
                 and verdict["text_matches"] and verdict["markers_match_fixture"]
                 and verdict["unleased_click"] == "lease_not_held"
                 and verdict["stale_click"] == "capture_superseded"
                 and consumer.get("post_release_click") == "lease_not_held"
                 and consumer.get("lease") == "answered_locally" and consumer.get("release") == "answered_locally")
json.dump(verdict, open(f"{out}/verdict.json", "w"), indent=2, sort_keys=True)
# Typed text is never kept, even synthetic: replace it with its length and
# digest once the verdict has compared it.
import hashlib
typed = after["text"]
after["text"] = f"<redacted: {len(typed)} chars, sha256 {hashlib.sha256(typed.encode()).hexdigest()}>"
json.dump(after, open(f"{out}/fixture-state-after.json", "w"), sort_keys=True)
print("m5-cua-demo verdict: " + json.dumps(verdict, sort_keys=True))
sys.exit(0 if verdict["ok"] else 1)
EOF
log "evidence in ${OUT}"
