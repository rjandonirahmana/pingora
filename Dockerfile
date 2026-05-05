FROM rust:latest AS builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    cmake \
    build-essential \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

# Build - menghasilkan binary "kinetic-proxy"
RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary (nama: kinetic-proxy)
COPY --from=builder /app/target/release/kinetic-proxy /usr/local/bin/kinetic-proxy

# Copy config
COPY config.yaml /app/config.yaml

# Pastikan daemon: false
RUN sed -i 's/daemon: true/daemon: false/g' /app/config.yaml 2>/dev/null || true

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -f http://localhost/health || exit 1

EXPOSE 80 443

CMD ["/usr/local/bin/kinetic-proxy"]