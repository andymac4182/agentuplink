# syntax=docker/dockerfile:1
# Build from the repository root. No runtime secrets belong in the context.
FROM rust:1.95.0@sha256:f49565f188ee00bc2a18dd418183f2c5f23ef7d6e691890517ed341a598f67c3 AS build
ENV RUSTUP_TOOLCHAIN=1.95.0 CARGO_TERM_COLOR=never
ARG CARGO_BUILD_JOBS=2
# Bind the allowlisted source read-only for this build. It need not occupy a
# separate intermediate image layer; keep generated files in the target cache.
RUN --mount=type=bind,source=.,target=/source,readonly \
    --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    --mount=type=secret,id=cargo_ca \
    if [ -f /run/secrets/cargo_ca ]; then export CARGO_HTTP_CAINFO=/run/secrets/cargo_ca; fi \
 && cargo build --manifest-path /source/Cargo.toml --target-dir /src/target \
      --locked --release -p tunnel-authority --bin tunnel-authority \
 && install -m 0755 /src/target/release/tunnel-authority /usr/local/bin/tunnel-authority

FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a
RUN useradd --system --uid 10002 --user-group --home-dir /var/lib/agentuplink-authority \
      --shell /usr/sbin/nologin authority \
 && install -d -m 0700 -o authority -g authority /var/lib/agentuplink-authority \
      /var/lib/agentuplink-authority/state /var/lib/agentuplink-authority/secrets
COPY --from=build /usr/local/bin/tunnel-authority /usr/local/bin/tunnel-authority
USER authority:authority
WORKDIR /var/lib/agentuplink-authority
EXPOSE 8444
STOPSIGNAL SIGTERM
# Mount operator-provisioned owner-only secrets read-only and durable state
# read-write. This entrypoint never generates keys, approves a run or initializes.
ENTRYPOINT ["/usr/local/bin/tunnel-authority"]
CMD ["serve", "--config", "/var/lib/agentuplink-authority/secrets/authority.toml"]
