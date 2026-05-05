FROM rust:latest AS builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary - nama binary adalah "pingora" (bukan kinetic-proxy)
COPY --from=builder /app/target/release/pingora /usr/local/bin/pingora

# Copy config
COPY config.yaml /app/config.yaml

# Set daemon: false di config (pastikan sudah ada)
RUN sed -i 's/daemon: true/daemon: false/g' /app/config.yaml || true

EXPOSE 80 443

# Jalankan binary pingora
CMD ["/usr/local/bin/pingora", "--config", "/app/config.yaml"]