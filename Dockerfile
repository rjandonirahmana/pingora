FROM rust:latest AS builder
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    cmake \
    build-essential \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# Cache dependencies dulu
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main(){}" > src/main.rs \
    && cargo build --release \
    && rm -rf src
# Build asli
COPY . .
RUN touch src/main.rs && cargo build --release

# Runtime harus sama Debian version dengan builder (keduanya bookworm)
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/kinetic-proxy /usr/local/bin/kinetic-proxy
COPY config.yaml /app/config.yaml
RUN sed -i 's/daemon: true/daemon: false/g' /app/config.yaml 2>/dev/null || true
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -f http://localhost/health || exit 1
EXPOSE 80 443
CMD ["/usr/local/bin/kinetic-proxy"]