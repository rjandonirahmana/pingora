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

# Cache deps - handle missing Cargo.lock
COPY Cargo.toml ./
# Cargo.lock optional, create if not exists
RUN if [ ! -f Cargo.lock ]; then cargo generate-lockfile; fi
RUN mkdir src && echo "fn main(){}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy source code
COPY . .

# Build dengan binary name "pingora"
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

# Copy binary (nama binary dari Cargo.toml)
COPY --from=builder /app/target/release/pingora /usr/local/bin/pingora

# Copy config
COPY config.yaml /app/config.yaml

# Allow binding to privileged ports (80, 443)
RUN setcap 'cap_net_bind_service=+ep' /usr/local/bin/pingora

# Environment variables
ENV RUST_LOG=info
ENV CONFIG_PATH=/app/config.yaml

# Expose ports
EXPOSE 80 443

# Run dengan config path
CMD ["/usr/local/bin/pingora", "--config", "/app/config.yaml"]