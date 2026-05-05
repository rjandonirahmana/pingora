# =========================
# Stage 1: Builder
# =========================
FROM rust:latest AS builder

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

# Cache deps
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main(){}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy source
COPY . .

# Build
RUN cargo build --release

# =========================
# Stage 2: Runtime
# =========================
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Binary
COPY --from=builder /app/target/release/pingora /usr/local/bin/pingora

# Config
COPY config.yaml /app/config.yaml

# Allow port 443
RUN setcap 'cap_net_bind_service=+ep' /usr/local/bin/pingora

ENV BIND_HOST=0.0.0.0
ENV BIND_PORT=443
ENV CONFIG_PATH=/app/config.yaml

EXPOSE 443

CMD ["pingora"]