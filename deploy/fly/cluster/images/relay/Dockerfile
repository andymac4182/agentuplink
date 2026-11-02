# syntax=docker/dockerfile:1
# Separate cluster image; build from repository root. See ../README.md.
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
ARG VCS_REF
LABEL org.opencontainers.image.revision=$VCS_REF
RUN test "${#VCS_REF}" -eq 40 \
 && case "$VCS_REF" in *[!0-9a-f]*) exit 1;; esac \
 && apt-get update && apt-get install -y --no-install-recommends python3 \
 && rm -rf /var/lib/apt/lists/* \
 && python3 -I -c 'import base64, binascii, hashlib, json, os, pathlib, pwd, re, stat, sys, tomllib, uuid' \
 && useradd --system --uid 10001 --user-group --home-dir /var/lib/agent-tunnel --shell /usr/sbin/nologin relay \
 && install -d -m 0700 -o relay -g relay /var/lib/agent-tunnel /var/lib/agent-tunnel/state /var/lib/agent-tunnel/secrets \
 && install -d /usr/local/share/agentuplink-runtime-provenance \
 && dpkg-query -W -f='${Package}\t${Version}\n' > /usr/local/share/agentuplink-runtime-provenance/os-packages.tsv
COPY --from=build /usr/local/bin/tunnel-relay /usr/local/bin/tunnel-relay
COPY --from=build /usr/local/share/licenses/agentuplink /usr/local/share/licenses/agentuplink
COPY deploy/fly/cluster/images/entrypoint.py /usr/local/libexec/agentuplink-cluster-entrypoint.py
COPY deploy/fly/cluster/images/PROVENANCE.md /usr/local/share/agentuplink-runtime-provenance/README.md
USER relay:relay
WORKDIR /var/lib/agent-tunnel
EXPOSE 8443 9443 7443/udp
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/bin/python3", "-I", "/usr/local/libexec/agentuplink-cluster-entrypoint.py", "relay"]
CMD ["serve"]
