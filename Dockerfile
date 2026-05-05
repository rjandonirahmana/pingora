# Stage 1: Builder
FROM rustlang/rust:nightly-alpine AS builder

RUN apk add --no-cache \
    musl-dev g++ make perl pkgconfig \
    openssl-dev openssl-libs-static \
    zlib-dev zlib-static \
    protobuf protobuf-dev \
    curl

RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /app

ENV OPENSSL_STATIC=1
ENV PKG_CONFIG_ALLOW_CROSS=1

# 1. Cache deps (tanpa build.rs)
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main(){}" > src/main.rs && \
    cargo build --release --target x86_64-unknown-linux-musl && \
    rm -rf src/ \
           target/x86_64-unknown-linux-musl/release/build/pingora-* \
           target/x86_64-unknown-linux-musl/release/deps/e_ticketing-* \
           target/x86_64-unknown-linux-musl/release/e_ticketing*

# 2. Copy full source (build.rs + proto + src)
COPY . .

# 3. Final build — build.rs jalan, protoc generate auth.rs
RUN cargo build --release --target x86_64-unknown-linux-musl

# Stage 2: Runtime
FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/pingora /pingora

EXPOSE 8080
ENV BIND_HOST=0.0.0.0
ENV BIND_PORT=443
CMD ["/pingora"]
