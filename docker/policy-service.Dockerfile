# Policy Service Dockerfile
FROM rust:1.84-slim AS builder

RUN apt-get update && apt-get install -y \
    protobuf-compiler \
    libclang-dev \
    pkg-config \
    cmake \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN cargo build --release --package pcm-policy-service

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/pcm-policy-service /usr/local/bin/
EXPOSE 50052
ENTRYPOINT ["pcm-policy-service"]
