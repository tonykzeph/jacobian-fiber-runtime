# syntax=docker/dockerfile:1.7
FROM rust:1.97.0-bookworm AS builder
WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY migrations ./migrations
COPY web ./web
COPY src ./src

RUN --mount=type=cache,id=jfr-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=jfr-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=jfr-cargo-target,target=/build/target,sharing=locked \
    cargo build --locked --release --bin jfr-server \
    && cp /build/target/release/jfr-server /build/jfr-server

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 jfr \
    && useradd --system --uid 10001 --gid jfr --home-dir /nonexistent jfr

COPY --from=builder /build/jfr-server /usr/local/bin/jfr-server

USER 10001:10001
EXPOSE 8080
ENV JFR_BIND=0.0.0.0:8080
ENV JFR_LOG_FORMAT=json
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=4 \
  CMD ["curl", "--fail", "--silent", "http://127.0.0.1:8080/health/ready"]

ENTRYPOINT ["/usr/local/bin/jfr-server"]
