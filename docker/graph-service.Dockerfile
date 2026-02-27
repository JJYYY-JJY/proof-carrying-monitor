FROM rust:1.84-slim AS builder
RUN apt-get update && apt-get install -y protobuf-compiler libclang-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
RUN cargo build --release --package pcm-graph-service

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /app/target/release/pcm-graph-service /
EXPOSE 50053
ENTRYPOINT ["/pcm-graph-service"]
