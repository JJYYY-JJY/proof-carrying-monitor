# Proof-Carrying Monitor (PCM)

**可证明的外置参考监控器 + 策略变更影响分析平台**

> 每一次放行/拒绝都生成可独立验证的 Lean 证书。信任边界极小：仅 Lean kernel + checker。

## 核心特性

- **运行时参考监控器**：对 Agent/微服务的高风险动作执行 complete mediation，不可绕过
- **证书化决策**：Allow → 推导树证书（Certificate）；Deny → 可解释反例（Witness）
- **极小 TCB**：证书验证器的 soundness 由 Lean 4 证明，TCB ≈ Lean kernel + 2000 行 checker
- **策略差分分析**：自动发现升权/破坏性变更的最小反例 + 可机检证据
- **CI Gate**：策略 PR 自动运行 diff-analyzer，阻止未经验证的变更

## 项目结构

```
├── lean/                     # Lean 4 形式化（Spec + Cert + Proofs）
│   └── src/PCM/
│       ├── Spec/             #   语义定义（Basic, Policy, Diff）
│       ├── Cert/             #   证书结构 + Checker
│       └── Proofs.lean       #   Soundness 定理
├── crates/                   # Rust 工作区
│   ├── pcm-common/           #   共享类型与工具
│   ├── pcm-policy-dsl/       #   策略 DSL 解析器与编译器
│   ├── pcm-datalog-engine/   #   Datalog 评估引擎
│   ├── pcm-cert/             #   证书生成与序列化
│   ├── pcm-cert-checker-ffi/ #   Lean-extracted checker FFI
│   ├── pcm-monitor-gateway/  #   参考监控器网关 (gRPC)
│   ├── pcm-policy-service/   #   策略管理服务
│   ├── pcm-graph-service/    #   依赖图服务
│   ├── pcm-audit-service/    #   审计日志服务
│   └── pcm-cli/              #   命令行工具
├── proto/                    # Protobuf 定义
├── policies/                 # 策略 DSL 示例
├── deploy/                   # K8s / Helm 部署清单
├── docker/                   # Dockerfiles
└── docs/                     # 设计文档
```

## 快速开始

```bash
# 编译 Rust 工作区
cargo build --workspace

# 编译 Lean 形式化 + 验证定理
cd lean && lake build PCM

# 运行测试
cargo test --workspace

# 本地部署（Docker Compose）
docker compose up
```

## 设计文档

详见 [docs/DESIGN.md](docs/DESIGN.md) — 包含完整的 PRD、系统架构、API 规格、安全审计、Lean 形式化计划与 Backlog。

## License

Apache-2.0
