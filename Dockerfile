# ── Stage 1: Builder ──────────────────────────────────────────────────────────
# Rust 1.85+ wajib — edition2024 (dipakai chacha20 & pingora deps) stable sejak 1.85
FROM rust:latest AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    musl-tools musl-dev pkg-config cmake build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add x86_64-unknown-linux-musl

# OpenSSL vendored — compile static, tidak butuh libssl di runtime image
ENV OPENSSL_STATIC=1
ENV OPENSSL_VENDORED=1
ENV PKG_CONFIG_ALLOW_CROSS=1

WORKDIR /app

# ── Cache layer deps ──────────────────────────────────────────────────────────
# Copy manifest dulu, build deps sekali. Layer ini di-cache Docker sampai
# Cargo.toml/Cargo.lock berubah → tidak rebuild semua deps saat hanya src berubah.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo "fn main(){}" > src/main.rs \
    && cargo build --release --target x86_64-unknown-linux-musl \
    && rm -rf src

# ── Build binary asli ─────────────────────────────────────────────────────────
COPY . .
RUN touch src/main.rs \
    && cargo build --release --target x86_64-unknown-linux-musl

# ── Stage 2: Runtime — Alpine minimal ────────────────────────────────────────
FROM alpine:latest

RUN apk add --no-cache ca-certificates curl \
    && update-ca-certificates

# Non-root untuk keamanan
RUN addgroup -g 1000 proxy && adduser -u 1000 -G proxy -s /bin/sh -D proxy

WORKDIR /app

COPY --from=builder \
    /app/target/x86_64-unknown-linux-musl/release/kinetic-proxy \
    /usr/local/bin/kinetic-proxy

COPY config.yaml /app/config.yaml

# Pastikan daemon: false — wajib untuk container, tidak boleh fork ke background
RUN sed -i 's/^daemon: true/daemon: false/' /app/config.yaml 2>/dev/null || true

# Buat direktori cert mount (Let's Encrypt standard path)
RUN mkdir -p /etc/letsencrypt/live/ulala.space \
             /etc/ssl/ulalaapi.store \
    && chown -R proxy:proxy /app

USER proxy

# Health check — coba HTTPS dulu, fallback HTTP
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsk https://localhost/health -o /dev/null || \
        curl -fs http://localhost/health -o /dev/null || exit 1

EXPOSE 80 443

# PENTING: mount cert saat docker run:
#   docker run -v /etc/letsencrypt:/etc/letsencrypt:ro \
#              -v /etc/ssl/ulalaapi.store:/etc/ssl/ulalaapi.store:ro \
#              -p 80:80 -p 443:443 kinetic-proxy

CMD ["/usr/local/bin/kinetic-proxy"]
