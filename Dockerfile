# =========================
# Stage 1: Builder
# =========================
FROM rust:latest AS builder

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    pkg-config \
    libssl-dev \
    zlib1g-dev \
    protobuf-compiler \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# -------------------------
# 1. Cache dependencies
# -------------------------
COPY Cargo.toml Cargo.lock ./

# Dummy src to cache deps
RUN mkdir src && echo "fn main(){}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# -------------------------
# 2. Copy full source
# -------------------------
COPY . .

# -------------------------
# 3. Build real binary
# -------------------------
RUN cargo build --release

# =========================
# Stage 2: Runtime (minimal)
# =========================
# =========================
# Stage 2: Runtime (minimal)
# =========================
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/pingora /usr/local/bin/pingora

# allow bind to 443 without root
RUN setcap 'cap_net_bind_service=+ep' /usr/local/bin/pingora

ENV BIND_HOST=0.0.0.0
ENV BIND_PORT=443

EXPOSE 443

CMD ["pingora"]