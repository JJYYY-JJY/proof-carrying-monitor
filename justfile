# justfile — proof-carrying-monitor
# 运行 `just` 或 `just --list` 查看所有 recipe

# 默认 recipe
default: build

# 构建整个 workspace
build:
    cargo build --workspace

# 运行所有测试
test:
    cargo test --workspace

# 格式化代码
fmt:
    cargo fmt --all

# Clippy 检查（warning 即失败）
lint:
    cargo clippy --workspace -- -D warnings

# 构建 Lean 规范
lean-build:
    cd lean && lake build PCM

# 构建 Lean 证明
lean-proofs:
    cd lean && lake build PCMProofs

# 启动 Docker 服务
docker-up:
    docker compose up -d

# 停止 Docker 服务
docker-down:
    docker compose down

# 运行完整的 build + test + lint
all: build test lint
