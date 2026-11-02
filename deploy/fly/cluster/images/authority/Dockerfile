# syntax=docker/dockerfile:1
# Separate cluster image; build from repository root. See ../README.md.
FROM rust:1.95.0@sha256:f49565f188ee00bc2a18dd418183f2c5f23ef7d6e691890517ed341a598f67c3 AS build
ENV RUSTUP_TOOLCHAIN=1.95.0 CARGO_TERM_COLOR=never
ARG CARGO_BUILD_JOBS=2
# Bind the allowlisted source read-only for this build. It need not occupy a
# separate intermediate image layer; keep generated files in the target cache.
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
      --locked --release -p tunnel-authority --bin tunnel-authority \
 && install -m 0755 /src/target/release/tunnel-authority /usr/local/bin/tunnel-authority \
 && python3 /source/scripts/container_notices.py stage --root /source \
      --package tunnel-authority --binary /usr/local/bin/tunnel-authority \
      --output /usr/local/share/licenses/agentuplink


FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a
ARG VCS_REF
LABEL org.opencontainers.image.revision=$VCS_REF
RUN test "${#VCS_REF}" -eq 40 \
 && case "$VCS_REF" in *[!0-9a-f]*) exit 1;; esac \
 && apt-get update && apt-get install -y --no-install-recommends python3 \
 && rm -rf /var/lib/apt/lists/* \
 && python3 -I -c 'import base64, binascii, hashlib, json, os, pathlib, pwd, re, stat, sys, tomllib, uuid' \
 && useradd --system --uid 10002 --user-group --home-dir /var/lib/agentuplink-authority --shell /usr/sbin/nologin authority \
 && install -d -m 0700 -o authority -g authority /var/lib/agentuplink-authority /var/lib/agentuplink-authority/state /var/lib/agentuplink-authority/secrets \
 && install -d /usr/local/share/agentuplink-runtime-provenance \
 && dpkg-query -W -f='${Package}\t${Version}\n' > /usr/local/share/agentuplink-runtime-provenance/os-packages.tsv
COPY --from=build /usr/local/bin/tunnel-authority /usr/local/bin/tunnel-authority
COPY --from=build /usr/local/share/licenses/agentuplink /usr/local/share/licenses/agentuplink
COPY deploy/fly/cluster/images/entrypoint.py /usr/local/libexec/agentuplink-cluster-entrypoint.py
COPY deploy/fly/cluster/images/PROVENANCE.md /usr/local/share/agentuplink-runtime-provenance/README.md
USER authority:authority
WORKDIR /var/lib/agentuplink-authority
EXPOSE 8444
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/bin/python3", "-I", "/usr/local/libexec/agentuplink-cluster-entrypoint.py", "authority"]
CMD ["serve"]
