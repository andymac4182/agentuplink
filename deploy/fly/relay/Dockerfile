# syntax=docker/dockerfile:1
#
# The agent-tunnel relay image for Fly.io (docs/deploy-fly.md, task row M6-C70).
# Build from the repository root:
#
#   docker build -f deploy/fly/relay/Dockerfile -t agentuplink-relay .
#
# BuildKit reads the context allowlist Dockerfile.dockerignore beside this file.
# `fly deploy` is given the same file with `--ignorefile` on its command line
# (docs/deploy-fly.md section 6.1); fly.toml has no [build] section.
#
# The image holds no key, certificate, password or deployment secret. The
# entrypoint writes them at start-up from Fly secrets (environment variables)
# into a directory only the relay user can read.

# Toolchain pinned to rust-toolchain.toml (1.95.0). The digest is the
# multi-architecture index, so the same line builds arm64 locally and amd64 on
# Fly's builders.
FROM rust:1.95.0@sha256:f49565f188ee00bc2a18dd418183f2c5f23ef7d6e691890517ed341a598f67c3 AS build
# rust-toolchain.toml also lists rustfmt and clippy. Naming the toolchain here
# stops rustup from downloading components a release build does not use.
ENV RUSTUP_TOOLCHAIN=1.95.0 \
    CARGO_TERM_COLOR=never
ARG CARGO_BUILD_JOBS=2
# Optional CA bundle for builders behind an HTTPS proxy. It is mounted only
# for Cargo and never copied into the image. Ordinary builders use system CAs.
# Keep source read-only, with no intermediate whole-builder COPY layer. The
# /src/target cache stays compatible with the authority image's build cache.
RUN --mount=type=bind,source=.,target=/source,readonly \
    --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    --mount=type=secret,id=cargo_ca \
    if ! python3 -c 'import argparse, hashlib, json, pathlib, tempfile, tomllib' >/dev/null 2>&1; then \
      apt-get update && apt-get install -y --no-install-recommends python3 \
      && rm -rf /var/lib/apt/lists/*; \
    fi \
 && if [ -f /run/secrets/cargo_ca ]; then export CARGO_HTTP_CAINFO=/run/secrets/cargo_ca; fi \
 && cargo build --manifest-path /source/Cargo.toml --target-dir /src/target \
      --locked --release -p tunnel-relay --bin tunnel-relay \
 && install -m 0755 /src/target/release/tunnel-relay /usr/local/bin/tunnel-relay \
 && python3 /source/scripts/container_notices.py stage --root /source --package tunnel-relay \
      --binary /usr/local/bin/tunnel-relay --output /usr/local/share/licenses/agentuplink

FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a
# A fixed, unprivileged identity. The secrets directory is owner-only because
# the relay's Redis TLS loader refuses a private key readable by anyone else,
# and it sits under /var/lib because the loader also refuses any path with a
# symlink in it (/var/run and /var/lock are symlinks on Debian).
RUN useradd --system --uid 10001 --user-group --home-dir /var/lib/agent-tunnel \
      --shell /usr/sbin/nologin relay \
 && install -d -m 0700 -o relay -g relay /var/lib/agent-tunnel /var/lib/agent-tunnel/run
COPY --from=build /usr/local/bin/tunnel-relay /usr/local/bin/tunnel-relay
COPY --from=build /usr/local/share/licenses/agentuplink /usr/local/share/licenses/agentuplink
COPY deploy/fly/relay/entrypoint.sh /usr/local/bin/agent-tunnel-relay-entrypoint
COPY deploy/fly/relay/relay.toml /etc/agent-tunnel/relay.toml.in
RUN chmod 0755 /usr/local/bin/agent-tunnel-relay-entrypoint \
 && chmod 0644 /etc/agent-tunnel/relay.toml.in
USER relay:relay
WORKDIR /var/lib/agent-tunnel
# Consumer HTTPS (public, relay-terminated TLS) and device mTLS WebSocket.
EXPOSE 8443 9443
# Exec form: the entrypoint `exec`s tunnel-relay, so the relay itself receives
# the stop signal. `serve` drains and exits 0 on SIGTERM or SIGINT.
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/agent-tunnel-relay-entrypoint"]
CMD ["serve"]
