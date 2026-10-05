FROM rust:1.94-bookworm AS builder

# OpenSSL is built from source and linked statically (see the `openssl` entry in
# Cargo.toml), so no libssl development package is needed.  cmake is for
# libz-ng-sys, a build dependency of pingora's flate2.
RUN apt-get update \
    && apt-get install --yes --no-install-recommends cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/denbrowser-proxy
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release

FROM debian:bookworm-slim AS runtime

LABEL org.opencontainers.image.title="DenBrowser Attestation Proxy" \
      org.opencontainers.image.description="Attestation-verifying reverse proxy for DenBrowser"

# ca-certificates provides the trust store for upstream TLS verification.  The
# proxy's own libssl is statically linked, so no libssl package is listed; apt
# may still install one as a dependency of ca-certificates, unused by the proxy.
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 denbrowser \
    && useradd --system --uid 10001 --gid denbrowser --no-create-home denbrowser

COPY --from=builder /usr/src/denbrowser-proxy/target/release/denbrowser-proxy \
    /usr/local/bin/denbrowser-proxy

USER denbrowser
ENTRYPOINT ["/usr/local/bin/denbrowser-proxy"]
