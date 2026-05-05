# =========================
# Stage 1: Builder
# =========================
FROM rust:latest AS builder

# Install semua build dependencies yang diperlukan
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    cmake \
    build-essential \
    make \
    gcc \
    g++ \
    protobuf-compiler \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Cache dependencies - INI KUNCI BUILD CEPAT
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy source code
COPY . .

# Build dengan optimization
RUN cargo build --release && \
    strip /app/target/release/pingora  # Reduce binary size

# =========================
# Stage 2: Runtime  
# =========================
FROM debian:bookworm-slim

# Install runtime dependencies minimal
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && update-ca-certificates

WORKDIR /app

# Create non-root user untuk security
RUN groupadd -r pingora && useradd -r -g pingora pingora

# Copy binary dan config
COPY --from=builder /app/target/release/pingora /usr/local/bin/pingora
COPY --from=builder /app/config.yaml /app/config.yaml

# Fix daemon setting
RUN sed -i 's/daemon: true/daemon: false/g' /app/config.yaml 2>/dev/null || true

# Set permissions
RUN chown -R pingora:pingora /app && \
    chmod +x /usr/local/bin/pingora

# Switch ke non-root user
USER pingora

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:80/health || exit 1

EXPOSE 80 443

# Run
CMD ["/usr/local/bin/pingora", "--config", "/app/config.yaml"]