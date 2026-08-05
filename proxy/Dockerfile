FROM rust:1.94-bookworm AS builder

RUN apt-get update \
    && apt-get install --yes --no-install-recommends cmake libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/denbrowser-proxy
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release

FROM debian:bookworm-slim AS runtime

LABEL org.opencontainers.image.title="DenBrowser Attestation Proxy" \
      org.opencontainers.image.description="Attestation-verifying reverse proxy for DenBrowser"

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 denbrowser \
    && useradd --system --uid 10001 --gid denbrowser --no-create-home denbrowser

COPY --from=builder /usr/src/denbrowser-proxy/target/release/denbrowser-proxy \
    /usr/local/bin/denbrowser-proxy

USER denbrowser
ENTRYPOINT ["/usr/local/bin/denbrowser-proxy"]
