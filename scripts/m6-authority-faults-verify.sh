#!/usr/bin/env bash

# Exercise the actual online authority against committed lost replies and a
# restarted isolated Redis process. The Rust tests verify exact container
# ownership before issuing any restart; the shared development Redis is unused.
#
# This script owns only the container it labels with the run ID, and it never
# touches the shared development Redis: the harness command connects to the
# fixed loopback port published below. Tests own the guarded restart and every
# assertion; this script removes only its labeled disposable container.

set -euo pipefail

readonly REDIS_IMAGE="redis:8.4.0-alpine@sha256:6cbef353e480a8a6e7f10ec545f13d7d3fa85a212cdcc5ffaf5a1c818b9d3798"

if ! command -v docker >/dev/null 2>&1; then
    printf '%s\n' 'the online-authority Redis fault gate requires Docker' >&2
    exit 1
fi

readonly RUN_ID="$(python3 -c 'import uuid; print(uuid.uuid4().hex)')"
readonly CONTAINER_NAME="agentuplink-authority-faults-${RUN_ID}"
readonly CONTAINER_LABEL="agentuplink.authority-fault-owner=${RUN_ID}"

container_started=0
harness_pid=""
readonly GATE_LOG="$(mktemp "${TMPDIR:-/tmp}/agentuplink-authority-faults.XXXXXX")"

cleanup() {
    if [[ -n "${harness_pid}" ]] && kill -0 "${harness_pid}" 2>/dev/null; then
        kill "${harness_pid}" 2>/dev/null || true
        wait "${harness_pid}" 2>/dev/null || true
    fi
    rm -f "${GATE_LOG}"
    if [[ "${container_started}" != 1 ]]; then
        return
    fi
    # The name is generated above and the label check prevents this trap from
    # removing a container that a separate process happens to have created.
    local owner_label
    owner_label="$(docker inspect --format '{{index .Config.Labels "agentuplink.authority-fault-owner"}}' "${CONTAINER_NAME}" 2>/dev/null || true)"
    if [[ "${owner_label}" == "${RUN_ID}" ]]; then
        docker rm --force --volumes "${CONTAINER_NAME}" >/dev/null
    fi
}
trap cleanup EXIT

if [[ "${CONTAINER_NAME}" != agentuplink-authority-faults-[0-9A-Fa-f]* ]]; then
    printf '%s\n' 'refusing an unexpected generated container name' >&2
    exit 1
fi

# The live catalog keeps one URL across the restart, so the published host
# port must be fixed rather than reassigned by Docker on restart.  A port
# found free by a probe can be taken by anything else on the host before
# Docker publishes it (task row M7-C119), so a publish refused with "address
# already in use" -- and only that -- is retried on a fresh port, a bounded
# number of times.  Nothing about the restart under test is retried.
pick_port() {
    python3 - <<'PY'
import socket

probe = socket.socket()
probe.bind(("127.0.0.1", 0))
print(probe.getsockname()[1])
probe.close()
PY
}

remove_owned_container() {
    local owner_label
    owner_label="$(docker inspect --format '{{index .Config.Labels "agentuplink.authority-fault-owner"}}' "${CONTAINER_NAME}" 2>/dev/null || true)"
    if [[ "${owner_label}" == "${RUN_ID}" ]]; then
        docker rm --force --volumes "${CONTAINER_NAME}" >/dev/null
    fi
}

REDIS_PORT=""
for publish_attempt in 1 2 3 4 5; do
    candidate_port="$(pick_port)"
    if [[ -z "${candidate_port}" ]]; then
        printf '%s\n' 'could not reserve a loopback port for the fixture Redis' >&2
        exit 1
    fi
    # From here the container may exist, so the exit trap must remove it.
    container_started=1
    # This disposable fixture disables Redis protected mode inside the
    # container; the published listener remains bound to 127.0.0.1 and
    # contains only synthetic data.
    if run_error="$(docker run --detach \
        --name "${CONTAINER_NAME}" \
        --label "${CONTAINER_LABEL}" \
        --publish "127.0.0.1:${candidate_port}:6379/tcp" \
        --memory 256m \
        --cpus 1.0 \
        --pids-limit 64 \
        --ulimit nofile=1024:1024 \
        "${REDIS_IMAGE}" \
        sh -c 'if [ ! -e /data/users.acl ]; then printf "user default on nopass ~* &* +@all\n" > /data/users.acl; fi; exec redis-server "$@"' sh \
        --aclfile /data/users.acl \
        --appendonly yes \
        --appendfsync always \
        --aof-load-truncated no \
        --save "" \
        --maxmemory 64mb \
        --maxmemory-policy noeviction \
        --protected-mode no \
        --bind 0.0.0.0 \
        2>&1 >/dev/null)"; then
        REDIS_PORT="${candidate_port}"
        break
    fi
    if [[ "${run_error}" != *"address already in use"* ]]; then
        printf '%s\n' "${run_error}" >&2
        exit 1
    fi
    printf 'authority-faults: loopback port %s was taken before Docker published it (attempt %s); retrying on a fresh port\n' \
        "${candidate_port}" "${publish_attempt}" >&2
    remove_owned_container
done
if [[ -z "${REDIS_PORT}" ]]; then
    printf '%s\n' 'every probed loopback port was taken before Docker could publish it' >&2
    exit 1
fi
readonly REDIS_PORT

wait_for_redis() {
    local attempt
    for attempt in $(seq 1 60); do
        if docker exec "${CONTAINER_NAME}" redis-cli ping 2>/dev/null | grep -qx PONG; then
            return 0
        fi
        sleep 1
    done
    return 1
}

if ! wait_for_redis; then
    printf '%s\n' 'Redis did not become ready' >&2
    exit 1
fi

readonly REDIS_URL="redis://127.0.0.1:${REDIS_PORT}"

export TEST_REDIS_URL="${REDIS_URL}"
export TUNNEL_CATALOG_REDIS_URL="${REDIS_URL}"
export TUNNEL_AUTHORITY_REDIS_CONTAINER="${CONTAINER_NAME}"
export TUNNEL_AUTHORITY_REDIS_OWNER="${RUN_ID}"

cargo build --locked -p tunnel-authority -p tunnel-relay --bins
cargo test --locked -p tunnel-test-harness --test m6_online_authority \
    online_authority_fault_ -- --ignored --test-threads=1 --nocapture >"${GATE_LOG}" 2>&1 &
harness_pid=$!
set +e
wait "${harness_pid}"
harness_status=$?
set -e
harness_pid=""
cat "${GATE_LOG}"
if [[ "${harness_status}" != 0 ]]; then
    exit "${harness_status}"
fi
if ! grep -q '^test result: ok\. 2 passed; 0 failed; 0 ignored;' "${GATE_LOG}"; then
    printf '%s\n' 'authority fault gate did not execute both required tests' >&2
    exit 1
fi
printf 'online-authority committed-write and Redis-restart fault acceptance passed\n'
