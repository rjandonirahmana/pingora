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

# Build dengan static linking untuk musl (tidak tergantung GLIBC)
RUN cargo build --release --target x86_64-unknown-linux-musl

FROM alpine:latest

RUN apk add --no-cache ca-certificates libssl3

WORKDIR /app

# Copy binary static
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/kinetic-proxy /usr/local/bin/kinetic-proxy
COPY config.yaml /app/config.yaml

EXPOSE 80 443

CMD ["/usr/local/bin/kinetic-proxy"]