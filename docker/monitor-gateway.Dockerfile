# Monitor Gateway Dockerfile
FROM rust:1.84-slim AS builder

RUN apt-get update && apt-get install -y protobuf-compiler libclang-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN cargo build --release --package pcm-monitor-gateway

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /app/target/release/pcm-monitor-gateway /
EXPOSE 50051
ENTRYPOINT ["/pcm-monitor-gateway"]
