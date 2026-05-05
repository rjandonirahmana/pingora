FROM rust:latest AS builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    cmake \
    build-essential \
    protobuf-compiler \
    musl-tools \
    && rm -rf /var/lib/apt/lists/*

# Add musl target
RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /app
COPY . .

# Build dengan musl (static)
RUN cargo build --release --target x86_64-unknown-linux-musl

FROM alpine:latest

RUN apk add --no-cache ca-certificates libssl3

WORKDIR /app

# Copy binary static
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/kinetic-proxy /usr/local/bin/kinetic-proxy
COPY config.yaml /app/config.yaml

EXPOSE 80 443

CMD ["/usr/local/bin/kinetic-proxy"]