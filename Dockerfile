# ── Stage 1: Builder ──────────────────────────────────────────────────────────
FROM rust:latest AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    musl-tools musl-dev pkg-config cmake build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add x86_64-unknown-linux-musl

ENV OPENSSL_STATIC=1
ENV OPENSSL_VENDORED=1
ENV PKG_CONFIG_ALLOW_CROSS=1

WORKDIR /app

# Cache deps layer
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo "fn main(){}" > src/main.rs \
    && cargo build --release --target x86_64-unknown-linux-musl \
    && rm -rf src

# Build binary asli
COPY . .
RUN touch src/main.rs \
    && cargo build --release --target x86_64-unknown-linux-musl

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM alpine:latest

RUN apk add --no-cache ca-certificates curl \
    && update-ca-certificates

WORKDIR /app

COPY --from=builder \
    /app/target/x86_64-unknown-linux-musl/release/kinetic-proxy \
    /usr/local/bin/kinetic-proxy

COPY config.yaml /app/config.yaml

RUN sed -i 's/^daemon: true/daemon: false/' /app/config.yaml 2>/dev/null || true

RUN mkdir -p /etc/letsencrypt/live/ulala.space \
             /etc/ssl/ulalaapi.store

# Jalankan sebagai root — wajib untuk bind port 80/443 (privileged ports)
# Binary musl static tidak ada attack surface signifikan
# Alternatif: pakai setcap net_bind_service tapi tidak works di musl/alpine

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsk https://localhost/health -o /dev/null || \
        curl -fs http://localhost/health -o /dev/null || exit 1

EXPOSE 80 443

CMD ["/usr/local/bin/kinetic-proxy"]
