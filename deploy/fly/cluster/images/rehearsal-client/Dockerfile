# syntax=docker/dockerfile:1
# Synthetic rehearsal only. No client binary is added to a serving relay image.
FROM rust:1.95.0@sha256:f49565f188ee00bc2a18dd418183f2c5f23ef7d6e691890517ed341a598f67c3 AS build
ENV RUSTUP_TOOLCHAIN=1.95.0 CARGO_TERM_COLOR=never
ARG CARGO_BUILD_JOBS=2
RUN --mount=type=bind,source=.,target=/source,readonly \
    --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    --mount=type=secret,id=cargo_ca \
    if ! python3 -c 'import argparse, hashlib, json, pathlib, tempfile, tomllib' >/dev/null 2>&1; then \
      apt-get update && apt-get install -y --no-install-recommends python3 \
      && rm -rf /var/lib/apt/lists/*; \
    fi \
 && if [ -f /run/secrets/cargo_ca ]; then export CARGO_HTTP_CAINFO=/run/secrets/cargo_ca; fi \
 && cargo build --manifest-path /source/Cargo.toml --target-dir /src/target --locked --release \
      -p tunnel-client -p tunnel-deadman --bins \
 && install -m 0755 /src/target/release/tunnel-client /usr/local/bin/tunnel-client \
 && install -m 0755 /src/target/release/tunnel-deadman /usr/local/bin/tunnel-deadman \
 && python3 /source/scripts/container_notices.py stage --root /source --package tunnel-client \
      --binary /usr/local/bin/tunnel-client --output /usr/local/share/licenses/agentuplink-client \
 && python3 /source/scripts/container_notices.py stage --root /source --package tunnel-deadman \
      --binary /usr/local/bin/tunnel-deadman --output /usr/local/share/licenses/agentuplink-deadman

FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a
ARG VCS_REF
LABEL org.opencontainers.image.revision=$VCS_REF
RUN test "${#VCS_REF}" -eq 40 \
 && case "$VCS_REF" in *[!0-9a-f]*) exit 1;; esac \
 && useradd --system --uid 10003 --user-group --home-dir /var/lib/agentuplink-client --shell /usr/sbin/nologin client \
 && install -d -m 0700 -o client -g client /var/lib/agentuplink-client
COPY --from=build /usr/local/bin/tunnel-client /usr/local/bin/tunnel-client
COPY --from=build /usr/local/bin/tunnel-deadman /usr/local/bin/tunnel-deadman
COPY --from=build /usr/local/share/licenses/agentuplink-client /usr/local/share/licenses/agentuplink-client
COPY --from=build /usr/local/share/licenses/agentuplink-deadman /usr/local/share/licenses/agentuplink-deadman
USER client:client
WORKDIR /var/lib/agentuplink-client
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/tunnel-client"]
CMD ["--help"]
