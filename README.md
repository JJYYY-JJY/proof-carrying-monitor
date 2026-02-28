# Proof-Carrying Monitor (PCM)

> 可验证的运行时参考监控器 — 每次安全决策都附带可机检证书

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.84+-orange.svg)](https://www.rust-lang.org/)
[![Lean 4](https://img.shields.io/badge/Lean_4-formal_proofs-green.svg)](https://lean-lang.org/)

PCM 是一个面向 AI Agent 和微服务的**证书化安全监控平台**。与传统策略引擎（OPA/Cedar）不同，PCM 的每次 allow/deny 决策都生成**可独立验证的密码学证书**，验证器的正确性由 Lean 4 形式化证明（极小 TCB）。

## 特性亮点

- 🔒 **证书化安全决策** — Allow → 推导树证书（Certificate）；Deny → 可解释反例（Witness）
- 🔍 **Lean 4 形式化验证** — checker soundness 定理证明，TCB ≈ Lean kernel + 2000 行 checker
- 📊 **策略语义差分分析** — 自动发现升权（Deny→Allow）/ 破坏性变更（Allow→Deny）的最小反例集
- 🛡️ **架构级 Complete Mediation** — 所有外部副作用必须经过 monitor-gateway，不可绕过
- ⚡ **P99 ≤ 5ms 运行时延迟** — Rust 高性能运行时，策略评估 + 证书生成在 5ms 内完成
- 📝 **不可抵赖审计** — 签名链 / 哈希链审计日志，离线可验证

---

## 快速开始

> 💡 详细的分步指南请参阅 [docs/QUICKSTART.md](docs/QUICKSTART.md)（15 分钟跑通 demo）

### 前置条件

- [Docker](https://docs.docker.com/get-docker/) + Docker Compose v2
- [Rust 1.84+](https://rustup.rs/)（可选，用于本地开发）
- [grpcurl](https://github.com/fullstorydev/grpcurl/releases)（可选，用于手动测试 gRPC）

### 一键启动

```bash
# 启动所有服务（PostgreSQL + policy-service + graph-service + audit-service + monitor-gateway）
docker compose up --build -d
```

等待约 30 秒，所有服务启动完毕后：

### 验证服务健康

```bash
grpcurl -plaintext -import-path proto -proto pcm/v1/services.proto \
  localhost:50051 pcm.v1.MonitorService/Health
```

预期输出：
```json
{
  "healthy": true,
  "policyVersion": "...",
  "uptimeSeconds": "..."
}
```

### 发送 Allow 请求

构造一个有 `http_allowed` 角色的用户发起 HTTP 外发请求：

```bash
grpcurl -plaintext -import-path proto -proto pcm/v1/services.proto \
  -d '{
    "request": {
      "request_id": "demo-allow-001",
      "action_type": 2,
      "principal": "http_allowed_user",
      "target": "https://api.example.com"
    }
  }' \
  localhost:50051 pcm.v1.MonitorService/Evaluate
```

预期返回 `ALLOW` + Certificate（推导树证书）。

### 触发 Deny 请求

构造一个**无授权**的用户发起 HTTP 外发请求：

```bash
grpcurl -plaintext -import-path proto -proto pcm/v1/services.proto \
  -d '{
    "request": {
      "request_id": "demo-deny-002",
      "action_type": 2,
      "principal": "unauthorized_user",
      "target": "https://api.example.com"
    }
  }' \
  localhost:50051 pcm.v1.MonitorService/Evaluate
```

预期返回 `DENY` + Witness（可解释反例：`unauthorized_http`）。

### 策略编译（CLI）

```bash
cargo run -p pcm-cli -- compile --file policies/default.pcm
```

### 停止服务

```bash
docker compose down
```

---

## 架构概览

```
┌─────────────────────────────────────────────────────────────────────┐
│                        PCM 平台架构                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   Agent / 微服务                                                     │
│       │                                                              │
│       ▼ gRPC                                                         │
│   ┌──────────────────────────────────────┐                           │
│   │      Monitor Gateway (:50051)        │──────────────────────┐    │
│   │  策略评估 + 证书生成 + Fail-closed   │                      │    │
│   └──────┬───────────┬───────────────────┘                      │    │
│          │           │                                           │    │
│    ┌─────▼──────┐  ┌─▼────────────┐  ┌──────────────────┐      │    │
│    │  Policy     │  │  Graph       │  │  Audit Service   │◄─────┘    │
│    │  Service    │  │  Service     │  │  (:50054)        │           │
│    │  (:50052)   │  │  (:50053)    │  │  签名链审计日志    │           │
│    │  策略CRUD   │  │  依赖图维护   │  └──────────────────┘           │
│    └──────┬──────┘  └──────────────┘                                 │
│           │                                                          │
│    ┌──────▼──────┐                                                   │
│    │  PostgreSQL │  策略版本 + 审计记录                                │
│    └─────────────┘                                                   │
│                                                                      │
│   ┌───────────────────────────────────────┐                          │
│   │  Lean 4 形式化验证层                     │                          │
│   │  Spec → Cert → Checker → Proofs       │                          │
│   │  cert_soundness / witness_soundness   │                          │
│   └───────────────────────────────────────┘                          │
└─────────────────────────────────────────────────────────────────────┘
```

详细设计请参阅 [docs/DESIGN.md](docs/DESIGN.md)。

---

## 项目结构

```
proof-carrying-monitor/
├── lean/                         # Lean 4 形式化（Spec + Cert + Proofs）
│   └── src/PCM/
│       ├── Spec/                 #   语义定义（Basic, Policy, Diff）
│       ├── Cert/                 #   证书结构 + Checker + FFI
│       └── Proofs.lean           #   Soundness 定理（cert/witness/diff）
├── crates/                       # Rust 工作区
│   ├── pcm-common/               #   共享类型与 proto 生成
│   ├── pcm-policy-dsl/           #   策略 DSL 解析器与编译器
│   ├── pcm-datalog-engine/       #   Datalog 评估引擎
│   ├── pcm-cert/                 #   证书生成与序列化
│   ├── pcm-cert-checker-ffi/     #   Lean-extracted checker FFI
│   ├── pcm-monitor-gateway/      #   参考监控器网关 (gRPC)
│   ├── pcm-policy-service/       #   策略管理服务
│   ├── pcm-graph-service/        #   依赖图服务（RocksDB）
│   ├── pcm-audit-service/        #   审计日志服务（签名链）
│   └── pcm-cli/                  #   命令行工具
├── proto/pcm/v1/                 # Protobuf 服务 & 类型定义
│   ├── services.proto            #   5 个 gRPC 服务定义
│   └── types.proto               #   核心数据类型
├── policies/                     # 策略 DSL 示例
│   ├── default.pcm               #   默认最小安全策略
│   └── examples/                 #   更多场景示例
├── python/                       # Python 差分分析器
├── deploy/k8s/                   # K8s 网络策略
├── docker/                       # Dockerfiles
├── scripts/                      # 构建 & 测试脚本
├── tests/e2e/                    # 端到端测试
└── docs/                         # 设计文档
    ├── DESIGN.md                 #   总体设计文档
    ├── QUICKSTART.md             #   15 分钟快速上手
    └── POLICY_DSL_REFERENCE.md   #   策略 DSL 参考手册
```

---

## 开发指南

### 本地构建

```bash
# 构建整个 Rust 工作区
cargo build --workspace

# 构建 Lean 形式化 + 验证定理
cd lean && lake build PCM
```

### 运行测试

```bash
# 单元测试 + 集成测试
cargo test --workspace

# 代码风格检查
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings

# 端到端测试（需要 Docker）
docker compose -f docker-compose.test.yml up --build --abort-on-container-exit

# 冒烟测试
# Linux/macOS:
bash scripts/smoke-test.sh
# Windows:
powershell scripts/smoke-test.ps1
```

### 性能基准

```bash
cargo bench --workspace
```

### 添加新策略

1. 在 `policies/` 目录创建 `.pcm` 文件
2. 使用 CLI 验证语法：`cargo run -p pcm-cli -- validate --file policies/my_policy.pcm`
3. 编译策略：`cargo run -p pcm-cli -- compile --file policies/my_policy.pcm`
4. 将策略文件挂载到 Docker Compose 或通过 PolicyService gRPC API 上传

---

## 策略 DSL 速览

PCM 使用基于 Datalog 子集的策略 DSL，所有规则头必须为 `deny`。无 deny 匹配 = Allow。

```prolog
// 禁止未授权的 HTTP 外发调用
deny(Req, "unauthorized_http") :-
    action(Req, http_out, P, _),
    !has_role(P, "http_allowed").

// 信息流约束：Confidential 数据不可流向 Public 端点
deny(Req, "label_violation") :-
    action(Req, HttpOut, _, Target),
    graph_edge(DataNode, TargetNode, data_flow),
    graph_label(DataNode, Confidential),
    graph_label(TargetNode, Public).

// 时序约束：写数据库前必须先经过验证
deny(Req, "missing_validation") :-
    action(Req, DbWrite, _, _),
    !precedes(validate_action, Req).
```

完整语法参考请见 [docs/POLICY_DSL_REFERENCE.md](docs/POLICY_DSL_REFERENCE.md)。

---

## CLI 工具

```bash
pcm-cli <COMMAND>
```

| 命令 | 说明 | 示例 |
|------|------|------|
| `compile` | 编译策略 DSL 为 JSON | `pcm-cli compile --file policy.pcm --output compiled.json` |
| `validate` | 验证策略 DSL 语法正确性 | `pcm-cli validate --file policy.pcm` |
| `verify` | 离线验证证书 | `pcm-cli verify --cert cert.json --policy policy.pcm` |
| `diff` | 策略差异分析 | `pcm-cli diff --old v1.pcm --new v2.pcm` |
| `audit` | 查询审计日志 | `pcm-cli audit --query '{"limit":10}' --endpoint localhost:50054` |

> 使用 `cargo run -p pcm-cli --` 替代 `pcm-cli` 即可在开发环境运行。

---

## API 参考

PCM 提供 5 个 gRPC 服务，Proto 定义位于 [`proto/pcm/v1/`](proto/pcm/v1/)：

| 服务 | 端口 | 说明 |
|------|------|------|
| `MonitorService` | 50051 | 参考监控器（Evaluate / Health） |
| `PolicyService` | 50052 | 策略 CRUD + 编译 + 激活 |
| `GraphService` | 50053 | 依赖图追加 / 快照 / 可达性查询 |
| `AuditService` | 50054 | 审计日志查询 / 导出 / 哈希链验证 |
| `CertCheckerService` | — | 证书 / Witness / Diff 证书验证 |

Proto 文件：
- [proto/pcm/v1/services.proto](proto/pcm/v1/services.proto) — 服务定义
- [proto/pcm/v1/types.proto](proto/pcm/v1/types.proto) — 数据类型定义

---

## 路线图

| 阶段 | 时间 | 关键特性 |
|------|------|----------|
| **MVP** | 8 周 | 单节点 gateway + 策略 DSL + 证书生成 + Lean checker + CLI + Docker Compose |
| **V1** | +8 周 | 依赖图服务 + diff-analyzer + CI Gate + 审计签名链 + K8s 部署 |
| **V2** | +12 周 | 增量图评估 + Sidecar 模式 + 策略热更新 + Web UI + 多租户 |

详细路线图见 [docs/DESIGN.md §2.7](docs/DESIGN.md)。

---

## 贡献指南

1. Fork 本仓库
2. 创建功能分支：`git checkout -b feature/my-feature`
3. 确保通过所有检查：
   ```bash
   cargo fmt --all
   cargo clippy --workspace -- -D warnings
   cargo test --workspace
   ```
4. 提交 Pull Request

### 代码规范

- Rust 代码遵循 `rustfmt.toml` 和 `clippy.toml` 配置
- 策略文件使用 `//` 行注释，每条规则附中文说明
- Commit message 使用 [Conventional Commits](https://www.conventionalcommits.org/)

---

## 许可证

[Apache License 2.0](LICENSE)
