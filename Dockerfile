FROM rust:latest AS builder

RUN apt-get update && apt-get install -y \
    musl-tools \
    musl-dev \
    pkg-config \
    cmake \
    build-essential \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Target musl untuk static binary
RUN rustup target add x86_64-unknown-linux-musl

# OpenSSL vendored — di-compile static bersama binary, tidak butuh libssl di runtime
ENV OPENSSL_STATIC=1
ENV OPENSSL_VENDORED=1
ENV PKG_CONFIG_ALLOW_CROSS=1
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true

WORKDIR /app

# Cache deps layer
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main(){}" > src/main.rs \
    && cargo build --release --target x86_64-unknown-linux-musl \
    && rm -rf src

# Build asli
COPY . .
RUN touch src/main.rs \
    && cargo build --release --target x86_64-unknown-linux-musl

# ── Runtime: Alpine — GLIBC tidak dipakai sama sekali ────────────────────────
FROM alpine:latest

RUN apk add --no-cache \
    ca-certificates \
    curl

WORKDIR /app
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/kinetic-proxy /usr/local/bin/kinetic-proxy
COPY config.yaml /app/config.yaml

RUN sed -i 's/daemon: true/daemon: false/g' /app/config.yaml 2>/dev/null || true

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -f http://localhost/health || exit 1

EXPOSE 80 443
CMD ["/usr/local/bin/kinetic-proxy"]