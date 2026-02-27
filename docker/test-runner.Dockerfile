# Test Runner Dockerfile — CI 集成测试用
FROM rust:1.84-slim

RUN apt-get update && apt-get install -y \
    protobuf-compiler \
    libclang-dev \
    pkg-config \
    cmake \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

# 运行标记为 ignored 的集成测试（需要数据库等外部依赖）
CMD ["cargo", "test", "--workspace", "--", "--ignored"]
