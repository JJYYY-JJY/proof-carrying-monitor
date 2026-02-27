# Proof-Carrying Monitor — 总体设计文档

> **版本**：0.1.0-draft | **日期**：2026-02-26 | **作者**：Project Team

---

# 1. 假设与输入摘要

## 1.1 代码库现状

| 项 | 状态 |
|---|---|
| 仓库 | `proof-carrying-monitor`，Apache-2.0 |
| 现有代码 | **空白**（仅 README / LICENSE / .gitignore） |
| .gitignore 偏向 | Python（`__pycache__`、`.egg` 等） |
| 可复用资产 | 无 — 全部从零构建 |

## 1.2 显式假设（待确认标"⬜"）

| # | 假设 | 待确认 |
|---|---|---|
| A1 | 运行环境以容器化为主（Docker / K8s），本地开发支持 Docker Compose | ⬜ |
| A2 | CI 平台：GitHub Actions（可替换 GitLab CI） | ⬜ |
| A3 | 主要语言栈：**Rust**（高性能运行时 + monitor-gateway + cert-checker 可执行层）、**Python**（diff-analyzer 求解器调用、developer-portal CLI）、**Lean 4**（形式化证明 + checker 抽取） | ⬜ |
| A4 | 消息总线/事件：先用 gRPC 同步调用；V2 可选 NATS/Kafka | ⬜ |
| A5 | 存储：PostgreSQL（策略/审计）、RocksDB 嵌入式（图、证书缓存）；S3 兼容存储归档 | ⬜ |
| A6 | SLA 目标：monitor-gateway P99 ≤ 5 ms（本地评估）；diff-analyzer P99 ≤ 30 s（批处理） | ⬜ |
| A7 | 策略 DSL 语义子集：有限 Horn/Datalog（无否定/无递增策略值域），保证可判定 | ⬜ |
| A8 | 初始部署规模：≤ 100 agent 实例、≤ 500 条策略规则 | ⬜ |
| A9 | Lean 工具链版本：Lean 4 stable (≥ 4.x)，Mathlib 可选引入 | ⬜ |
| A10 | 产品初期面向内部平台团队自用，后续开源；暂无多租户需求 | ⬜ |
| A11 | 监控器部署模式：sidecar（每 agent 一个），或集中式 gateway（agent 数较少时）；MVP 先做集中式 | ⬜ |
| A12 | 图结构上限假设：每个评估窗口内节点 ≤ 10k、边 ≤ 100k；超限则归档和快照 | ⬜ |

## 1.3 输入汇总

- **策略样例**：自行给出最小可行策略 DSL（§3.4）
- **目标运行环境**：K8s + Docker Compose 本地开发
- **合规要求**：SOC2 / ISO-27001 参考控制项，非强制

---

# 2. PRD（产品需求文档）

## 2.1 背景与问题陈述

### 问题

现有 AI Agent / 微服务安全架构存在三个系统性缺陷：

1. **不可验证的策略执行**：OPA/Cedar 等引擎的"allow/deny"结论是黑盒，调用方无法独立验证其正确性；一旦引擎实现 bug，安全结论静默失效。
2. **策略变更无影响分析**：安全策略的修改依赖人工 review，缺乏自动化的"升权/降权"反例发现，高风险变更容易滑入生产。
3. **旁路风险**：Agent 可直接调用外部 API/数据库而不经过策略检查点，缺乏架构层面的 complete mediation 保证。

### 解决方案

构建 **Proof-Carrying Monitor (PCM)** 平台——一个同时提供 **运行时参考监控器** 和 **策略变更影响分析器** 的统一系统，核心原则：

- 每次放行/拒绝都生成**可独立验证的证书**（proof-carrying execution），验证器的正确性由 Lean 证明（极小 TCB）
- 策略变更自动产出最小反例集合 + 可机检证据
- 架构/部署层面保证 complete mediation

## 2.2 用户画像与使用场景

| 画像 | 核心诉求 | 关键场景 |
|---|---|---|
| **平台工程团队** | 零旁路安全屏障 + 可观测审计 | 部署 monitor sidecar；配置网络策略隔离；查看审计日志和证书验证报告 |
| **安全团队** | 策略正确性 + 变更影响可视化 | 编写/审核策略 DSL；在 PR 中查看 diff-analyzer 输出的升权/破坏性变更反例；离线证书审计 |
| **Agent/应用开发者** | 快速集成 + 清晰错误解释 | 通过 SDK 发起受监控的 action；收到 deny 时获得可解释反例（witness）；本地调试策略 |

## 2.3 目标与非目标

### 目标（In Scope）

| ID | 目标 |
|---|---|
| G1 | 运行时 complete mediation：所有外部副作用必须经过 monitor-gateway |
| G2 | 证书化决策：Allow → Certificate；Deny → Witness（可解释反例） |
| G3 | 证书验证器 soundness 由 Lean 证明，TCB 仅含 Lean kernel + checker |
| G4 | 策略 DSL：有限 Datalog 子集，支持依赖图约束、信息流标签、时序前置条件 |
| G5 | 策略 Diff 分析：自动计算 Deny→Allow（升权）/ Allow→Deny（破坏性）最小反例集 |
| G6 | Diff 结论可机检：每个反例附证书；可选"无差异" UNSAT 证书 |
| G7 | 审计不可抵赖：签名链 / WORM 存储 |
| G8 | CI Gate 集成：策略 PR 必须通过 diff-analyzer + cert-checker |
| G9 | P99 ≤ 5 ms 运行时拦截延迟（策略评估 + 证书生成，不含网络） |

### 非目标（Out of Scope for V1）

| ID | 非目标 |
|---|---|
| N1 | 多租户 SaaS 部署（V2+） |
| N2 | 策略学习/自动生成（不做 ML-based policy synthesis） |
| N3 | 支持非 Datalog 策略语言（如完整一阶逻辑） |
| N4 | 取代 IAM/AuthN（PCM 处理 AuthZ 策略执行，不做身份认证） |
| N5 | GUI 策略编辑器（V1 仅 CLI + 文本 DSL） |

## 2.4 核心功能

### F1: 运行时参考监控器

- **Action 拦截**：工具调用（tool_call）、HTTP 外发、数据库写/读敏感字段、文件系统操作
- **依赖图构建**：实时维护当前执行上下文的数据流/控制流图
- **策略评估**：在图上执行已编译的 Datalog 规则
- **证书生成**：Allow → 推导树证书（Certificate）；Deny → 最小反例路径（Witness）
- **Fail-closed**：评估超时/错误一律 Deny + 告警

### F2: 证书验证

- **可执行 Checker**：从 Lean 定义抽取的确定性验证函数
- **在线模式**：monitor-gateway 自验证（fast path）
- **离线模式**：CLI / CI 工具独立验证存档证书
- **Soundness 保证**：`check(cert, request, policy, graph) = true → AllowedSpec(request, policy, graph)`

### F3: 策略管理

- **DSL 定义**：Datalog 子集 + 图约束原语（见 §3.4）
- **版本控制**：Git-native 策略仓库
- **编译与校验**：语法/类型检查 + 可判定性验证
- **Schema 感知**：策略引用的 action type / attribute 必须匹配 schema

### F4: 策略 Diff 分析

- **语义差分**：找出 (policyV1, policyV2) 在所有可能请求空间中的行为差异
- **分类**：Deny→Allow（升权）/ Allow→Deny（破坏性变更）
- **最小反例**：对每类差异输出最少/最小的具体请求样例
- **证书化**：反例附可机检证书（`checkDiff(witness, P, Q) = true → dec_P(r) ≠ dec_Q(r)`）
- **UNSAT 证书**：可选输出"无差异"证明

### F5: 审计与可观测性

- 每个决策的完整记录：请求、图快照哈希、策略版本哈希、证书、时间戳、签名
- 签名链（可选 Merkle tree）
- Prometheus 指标 + OpenTelemetry trace
- 审计回放工具

### F6: CI/CD Gate

- GitHub Actions / GitLab CI 插件
- 策略 PR → 自动运行 diff-analyzer → 输出报告 + 证书
- Release gate：cert-checker 验证通过为合并必要条件

## 2.5 关键指标

| 维度 | 指标 | 目标 |
|---|---|---|
| 安全 | 旁路率 | 0（架构保证） |
| 正确性 | Checker soundness | Lean 证明覆盖（§6） |
| 性能 | monitor-gateway P99 延迟 | ≤ 5 ms |
| 性能 | diff-analyzer 中等策略（≤200 规则） | ≤ 30 s |
| 可用性 | monitor-gateway 可用率 | 99.99%（fail-closed 不算不可用） |
| 证书 | 平均证书大小 | ≤ 8 KB（allow）；≤ 2 KB（deny witness） |
| 可观测 | 审计覆盖率 | 100% 决策有日志 |

## 2.6 竞品与相关工作对比

| 维度 | Cedar (AWS) | OPA/Rego | 传统 RBAC/ABAC | **PCM (本项目)** |
|---|---|---|---|---|
| 策略语言 | Cedar DSL | Rego | 配置/规则引擎 | Datalog 子集（可判定） |
| 决策可验证性 | ❌ 信任引擎 | ❌ 信任引擎 | ❌ 信任引擎 | ✅ 证书 + Lean 验证 |
| TCB 大小 | 大（引擎全量） | 大 | 大 | **极小**（Lean kernel + checker） |
| 策略 Diff 分析 | 有限（Cedar analyzer） | ❌ | ❌ | ✅ 语义差分 + 证书化 |
| 反例/解释 | 部分 | 部分（trace） | ❌ | ✅ 可机检 Witness |
| 依赖图感知 | ❌ | ❌ | ❌ | ✅ 数据流图策略 |
| Complete Mediation | 应用层 | 应用层 | 应用层 | ✅ 架构 + 网络层 |

## 2.7 路线图

### MVP（M0）— 8 周

- 单节点 monitor-gateway（Rust）
- 最小策略 DSL（纯 Datalog，≤5 内置谓词）
- 证书生成 + Lean-extracted checker（soundness 定理已证）
- 基本 deny witness
- CLI 工具：策略编译、证书离线验证
- Docker Compose 部署

### V1 — +8 周（M0 后）

- 依赖图服务（graph-service）+ 图约束策略
- diff-analyzer（升权/破坏性反例 + 证书）
- CI Gate（GitHub Actions 插件）
- 审计签名链
- K8s Helm Chart + 网络策略隔离
- Prometheus / OTel 集成

### V2 — +12 周（V1 后）

- 增量图评估（性能优化）
- UNSAT 无差异证书
- Sidecar 模式部署
- 策略热更新（零停机）
- Developer Portal（Web UI）
- 多租户基础支持

## 2.8 风险清单与缓解

| 风险 | 影响 | 概率 | 缓解 |
|---|---|---|---|
| 策略 DSL 表达力不足 | 用户无法编写需要的规则 | 中 | 以实际场景驱动迭代；保持 Datalog 扩展路径 |
| 证书体积过大 | P99 延迟/带宽超标 | 中 | Hash-consing + Merkleization 压缩；分级证书（轻量 hash-cert / 完整 proof-cert） |
| 图规模爆炸 | 内存/评估超时 | 中 | 滑动窗口 + 归档快照；增量评估（V2） |
| Lean 证明工程复杂度 | 里程碑延期 | 高 | 先证核心 soundness（≤3 定理）；其余逐步补全 |
| 运维复杂度 | 部署/debug 困难 | 中 | Docker Compose 一键启动；充分日志/trace |
| 误报（false deny） | 开发者体验差 | 低 | Witness 提供详细解释；dry-run 模式 |
| 供应链攻击 | 证书伪造/checker 替换 | 低 | Checker 二进制签名 + 哈希校验；CI 重新从 Lean 构建 |

---

# 3. 系统架构与微服务设计

## 3.1 系统总览（一页式架构）

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Agent / 应用进程                               │
│  ┌──────────┐  SDK/拦截层    ┌──────────────────────┐               │
│  │ tool_call├──────────────►│  monitor-gateway     │               │
│  │ http_out │               │  (Rust gRPC server)  │               │
│  │ db_write │               │  ┌────────────────┐  │               │
│  │ file_op  │               │  │ Policy Engine  │  │               │
│  └──────────┘               │  │ (compiled DL)  │  │               │
│                             │  ├────────────────┤  │               │
│                             │  │ Cert Generator │  │               │
│                             │  ├────────────────┤  │               │
│                             │  │ Graph Client   │──┼──►graph-svc   │
│                             │  └────────────────┘  │               │
│                             │        │ cert        │               │
│                             │        ▼             │               │
│                             │  ┌────────────────┐  │               │
│                             │  │ Cert Checker   │  │               │
│                             │  │ (Lean extract) │  │               │
│                             │  └────────────────┘  │               │
│                             └──────┬───────────────┘               │
│                                    │ decision + cert/witness        │
│                                    ▼                                │
│                             ┌──────────────┐                       │
│                             │ audit-log-svc│──► PostgreSQL/S3      │
│                             └──────────────┘                       │
└──────────────────────────────────────────────────────────────────────┘

    ┌──────────────┐      ┌──────────────┐       ┌────────────┐
    │ policy-svc   │      │ diff-analyzer│       │ dev CLI /  │
    │ (CRUD+compile│◄────►│ (solver+cert)│       │ portal     │
    │  版本管理)    │      └──────────────┘       └────────────┘
    └──────────────┘
           │ compiled policy
           ▼
     monitor-gateway (hot-reload)
```

## 3.2 核心数据流（运行时时序）

```
Agent          SDK/Interceptor     monitor-gateway      graph-svc    policy-engine   cert-gen   cert-checker   audit-log
  │                 │                    │                  │              │             │            │            │
  │──action(req)──►│                    │                  │              │             │            │            │
  │                 │──Evaluate(req)───►│                  │              │             │            │            │
  │                 │                    │──UpdateGraph(req)►             │             │            │            │
  │                 │                    │◄─GraphSnapshot──│              │             │            │            │
  │                 │                    │──EvalPolicy(req,graph)────────►│             │            │            │
  │                 │                    │◄─RawDecision(allow/deny,trace)─│             │            │            │
  │                 │                    │                  │              │             │            │            │
  │                 │                    │──GenCert(decision,trace)──────────────────────►           │            │
  │                 │                    │◄─Certificate/Witness──────────────────────────│           │            │
  │                 │                    │                  │              │             │            │            │
  │                 │                    │──VerifyCert(cert)────────────────────────────────────────►│            │
  │                 │                    │◄─VerifyResult(ok/fail)───────────────────────────────────│            │
  │                 │                    │                  │              │             │            │            │
  │                 │                    │──LogDecision(req,decision,cert,ts,sig)────────────────────────────────►│
  │                 │                    │                  │              │             │            │            │
  │                 │◄─Decision(allow+cert / deny+witness)─│              │             │            │            │
  │◄─result/error──│                    │                  │              │             │            │            │
```

## 3.3 服务清单

### 3.3.1 monitor-gateway

| 项 | 说明 |
|---|---|
| **职责** | 参考监控器入口；强制拦截所有外部副作用；评估策略；生成/验证证书 |
| **语言** | Rust |
| **部署** | 集中式 gRPC server（MVP）→ sidecar（V2） |
| **内嵌模块** | Policy Engine（编译后 Datalog 评估器）、Cert Generator、Cert Checker（Lean-extracted FFI 或 WASM） |
| **关键特性** | fail-closed；零拷贝图查询；并发安全 |

### 3.3.2 policy-service

| 项 | 说明 |
|---|---|
| **职责** | 策略 CRUD、版本管理、DSL 编译（→ 中间表示）、schema 校验 |
| **语言** | Rust |
| **存储** | PostgreSQL（策略元数据 + 版本）；编译产物缓存 |
| **输出** | CompiledPolicy（二进制序列化的规则索引 + 事实表结构） |

### 3.3.3 graph-service

| 项 | 说明 |
|---|---|
| **职责** | 维护运行时依赖图；append-only 事件追加；快照/归档 |
| **语言** | Rust |
| **存储** | RocksDB 嵌入式（热数据）；S3（归档快照） |
| **图模型** | 有向标记图（节点=实体/动作/数据，边=数据流/控制流/因果） |

### 3.3.4 cert-checker

| 项 | 说明 |
|---|---|
| **职责** | 证书验证（核心 TCB 组件）；可作为库/sidecar/CLI |
| **语言** | Lean 4 定义 → 抽取为可执行代码（C / Rust FFI） |
| **代码量目标** | ≤ 2000 行 Lean（checker 逻辑） |
| **部署** | 嵌入 monitor-gateway（FFI）；独立 CLI（CI 用）；WASM（浏览器验证） |

### 3.3.5 diff-analyzer

| 项 | 说明 |
|---|---|
| **职责** | 策略语义差分、最小反例生成、差分证书输出 |
| **语言** | Python（Z3/CVC5 求解器绑定）+ Rust（证书序列化） |
| **输入** | (PolicyV1, PolicyV2, Schema) |
| **输出** | `List<DiffResult>` — 每个含反例请求 + 分类 + 证书 |

### 3.3.6 audit-log-service

| 项 | 说明 |
|---|---|
| **职责** | 不可抵赖审计日志存储；签名链 |
| **语言** | Rust |
| **存储** | PostgreSQL（结构化日志）+ S3（WORM 归档） |
| **特性** | Ed25519 签名；Merkle 聚合根（每批）；保留期策略 |

### 3.3.7 developer-cli

| 项 | 说明 |
|---|---|
| **职责** | 策略编写/编译/测试；证书离线验证；diff 分析触发；审计查询 |
| **语言** | Rust CLI（clap） |

## 3.4 策略 DSL 设计

### 最小可行策略 DSL（Datalog 子集）

```
// === 类型声明 ===
.type ActionType = ToolCall | HttpOut | DbWrite | DbReadSensitive | FileWrite
.type Label = Public | Internal | Confidential | Secret
.type Principal = String

// === Schema 声明 ===
.decl action(id: RequestId, type: ActionType, principal: Principal, target: String)
.decl data_label(data: String, label: Label)
.decl has_role(principal: Principal, role: String)
.decl graph_edge(src: NodeId, dst: NodeId, kind: EdgeKind)
.decl graph_label(node: NodeId, label: Label)
.decl precedes(a: RequestId, b: RequestId)  // 时序：a 先于 b

// === 策略规则（Horn 子句，头部为 deny/require） ===

// R1: 禁止未授权的外部 HTTP 调用
deny(Req, "unauthorized_http") :-
    action(Req, HttpOut, P, _),
    !has_role(P, "http_allowed").

// R2: 信息流标签约束 — Confidential 数据不可流向 Public 端点
deny(Req, "label_violation") :-
    action(Req, HttpOut, _, Target),
    graph_edge(DataNode, TargetNode, data_flow),
    graph_label(DataNode, Confidential),
    graph_label(TargetNode, Public).

// R3: 时序前置条件 — 写数据库前必须先经过 validate
deny(Req, "missing_validation") :-
    action(Req, DbWrite, _, _),
    !precedes(validate_action, Req).

// R4: 敏感数据读取需要 audit_read 角色
deny(Req, "sensitive_read_unauthorized") :-
    action(Req, DbReadSensitive, P, _),
    !has_role(P, "audit_read").

// === 默认策略 ===
// 无 deny 规则匹配 → allow
```

### DSL 编译产物

```
CompiledPolicy {
    rules: Vec<CompiledRule>,      // 索引化规则
    fact_schema: FactSchema,        // 字段类型与约束
    strata: Vec<Stratum>,           // 分层（保证无递归否定）
    hash: Blake3Hash,               // 策略内容哈希
    version: SemVer,
}
```

---

# 4. API 与数据模型

## 4.1 核心对象 Schema

### Request（动作请求）

```protobuf
message Request {
    string request_id = 1;       // UUID v7
    ActionType action_type = 2;
    string principal = 3;         // 调用者身份
    string target = 4;            // 目标资源
    map<string, string> attributes = 5;
    google.protobuf.Timestamp timestamp = 6;
    bytes context_hash = 7;       // 调用上下文的 blake3 摘要
}

enum ActionType {
    TOOL_CALL = 0;
    HTTP_OUT = 1;
    DB_WRITE = 2;
    DB_READ_SENSITIVE = 3;
    FILE_WRITE = 4;
    FILE_READ = 5;
    CUSTOM = 15;
}
```

### Decision（决策）

```protobuf
message Decision {
    string request_id = 1;
    Verdict verdict = 2;
    oneof evidence {
        Certificate certificate = 3;
        Witness witness = 4;
    }
    string policy_version_hash = 5;
    bytes graph_snapshot_hash = 6;
    google.protobuf.Timestamp decided_at = 7;
    bytes signature = 8;           // Ed25519 签名
}

enum Verdict {
    ALLOW = 0;
    DENY = 1;
    ERROR = 2;  // fail-closed: 被视为 DENY
}
```

### Certificate（允许证书）

```protobuf
message Certificate {
    // 推导树：从事实到结论的规则应用序列
    repeated DerivationStep steps = 1;
    bytes policy_hash = 2;
    bytes graph_hash = 3;
    bytes request_hash = 4;
    
    message DerivationStep {
        uint32 rule_index = 1;          // 所应用的规则编号
        repeated FactRef premises = 2;   // 前提事实引用
        Fact conclusion = 3;             // 推导出的结论
    }
}
```

### Witness（拒绝反例/解释）

```protobuf
message Witness {
    string deny_rule_id = 1;            // 触发拒绝的规则
    string human_readable_reason = 2;   // 人可读解释
    repeated Fact matched_facts = 3;    // 匹配到的事实
    repeated GraphPath violation_paths = 4; // 违规路径（图约束时）
    bytes policy_hash = 5;
    bytes request_hash = 6;
}
```

### Graph（依赖图）

```protobuf
message GraphNode {
    string node_id = 1;          // blake3(content)
    NodeKind kind = 2;
    string label = 3;            // 敏感级别标签
    map<string, string> attrs = 4;
    google.protobuf.Timestamp created_at = 5;
}

enum NodeKind {
    ENTITY = 0;    // agent / service / user
    ACTION = 1;    // 执行的动作
    DATA = 2;      // 数据对象
    RESOURCE = 3;  // 外部资源 (API / DB / file)
}

message GraphEdge {
    string src = 1;
    string dst = 2;
    EdgeKind kind = 3;
    google.protobuf.Timestamp created_at = 4;
}

enum EdgeKind {
    DATA_FLOW = 0;
    CONTROL_FLOW = 1;
    CAUSAL = 2;
    TEMPORAL = 3;
}

message GraphSnapshot {
    bytes snapshot_hash = 1;     // Merkle root
    repeated GraphNode nodes = 2;
    repeated GraphEdge edges = 3;
    google.protobuf.Timestamp as_of = 4;
}
```

### PolicyVersion

```protobuf
message PolicyVersion {
    string policy_id = 1;
    string version = 2;            // semver
    bytes content_hash = 3;        // blake3(source)
    string source_dsl = 4;
    CompiledPolicy compiled = 5;
    google.protobuf.Timestamp created_at = 6;
    string author = 7;
    string commit_sha = 8;
}
```

### DiffResult

```protobuf
message DiffResult {
    DiffKind kind = 1;
    Request example_request = 2;       // 最小反例请求
    Verdict verdict_old = 3;
    Verdict verdict_new = 4;
    DiffCertificate diff_certificate = 5;
    
    enum DiffKind {
        ESCALATION = 0;    // Deny → Allow（升权）
        BREAKING = 1;      // Allow → Deny（破坏性变更）
    }
}

message DiffCertificate {
    Certificate cert_old = 1;   // 旧策略下的证书/witness
    Certificate cert_new = 2;   // 新策略下的证书/witness
    bytes policy_old_hash = 3;
    bytes policy_new_hash = 4;
}

message DiffReport {
    repeated DiffResult diffs = 1;
    bool is_equivalent = 2;             // 是否语义等价
    Certificate equivalence_cert = 3;   // 当 is_equivalent=true 时的 UNSAT 证书
    string summary = 4;
}
```

## 4.2 gRPC API 规格

### monitor-gateway (MonitorService)

```protobuf
service MonitorService {
    // 核心：评估一个动作请求，返回决策+证书/反例
    rpc Evaluate(EvaluateRequest) returns (EvaluateResponse);
    
    // 批量评估（用于回放/测试）
    rpc EvaluateBatch(EvaluateBatchRequest) returns (EvaluateBatchResponse);
    
    // 健康检查
    rpc Health(HealthRequest) returns (HealthResponse);
}

message EvaluateRequest {
    Request request = 1;
    bool dry_run = 2;                // dry_run 不执行实际拦截
}

message EvaluateResponse {
    Decision decision = 1;
    uint64 evaluation_duration_us = 2;  // 评估耗时（微秒）
}
```

**错误码**：

| gRPC Code | 场景 | 行为 |
|---|---|---|
| OK | 正常评估完成 | — |
| INVALID_ARGUMENT | 请求格式错误 | Deny |
| INTERNAL | 评估器内部错误 | Deny (fail-closed) |
| UNAVAILABLE | 图服务/策略不可用 | Deny (fail-closed) |
| DEADLINE_EXCEEDED | 评估超时 | Deny (fail-closed) |

### policy-service (PolicyService)

```protobuf
service PolicyService {
    rpc CreatePolicy(CreatePolicyRequest) returns (PolicyVersion);
    rpc GetPolicy(GetPolicyRequest) returns (PolicyVersion);
    rpc ListPolicyVersions(ListRequest) returns (ListPolicyVersionsResponse);
    rpc CompilePolicy(CompilePolicyRequest) returns (CompilePolicyResponse);
    rpc ValidatePolicy(ValidatePolicyRequest) returns (ValidatePolicyResponse);
    rpc ActivatePolicy(ActivatePolicyRequest) returns (ActivatePolicyResponse);
}

message CompilePolicyResponse {
    CompiledPolicy compiled = 1;
    repeated CompileWarning warnings = 2;
    bool decidable = 3;  // 可判定性检查结果
}
```

### graph-service (GraphService)

```protobuf
service GraphService {
    rpc AppendEvent(AppendEventRequest) returns (AppendEventResponse);
    rpc GetSnapshot(GetSnapshotRequest) returns (GraphSnapshot);
    rpc QueryReachable(ReachableRequest) returns (ReachableResponse);
    rpc ArchiveSnapshot(ArchiveRequest) returns (ArchiveResponse);
}
```

### cert-checker (CertCheckerService)

```protobuf
service CertCheckerService {
    rpc VerifyCertificate(VerifyCertRequest) returns (VerifyCertResponse);
    rpc VerifyDiffCertificate(VerifyDiffCertRequest) returns (VerifyDiffCertResponse);
}

message VerifyCertResponse {
    bool valid = 1;
    string error_detail = 2;   // 当 valid=false 时的失败原因
}
```

### diff-analyzer (DiffAnalyzerService)

```protobuf
service DiffAnalyzerService {
    rpc AnalyzeDiff(AnalyzeDiffRequest) returns (DiffReport);
    rpc AnalyzeDiffStream(AnalyzeDiffRequest) returns (stream DiffResult);
}

message AnalyzeDiffRequest {
    string policy_old_version = 1;
    string policy_new_version = 2;
    AnalysisConfig config = 3;
}

message AnalysisConfig {
    uint32 max_examples = 1;        // 每类最多反例数（默认 10）
    bool prove_equivalence = 2;     // 是否尝试 UNSAT 证明
    uint32 timeout_seconds = 3;     // 求解超时
}
```

### audit-log-service (AuditService)

```protobuf
service AuditService {
    rpc LogDecision(LogDecisionRequest) returns (LogDecisionResponse);
    rpc QueryLogs(QueryLogsRequest) returns (QueryLogsResponse);
    rpc ExportLogs(ExportRequest) returns (stream AuditRecord);
    rpc VerifyChain(VerifyChainRequest) returns (VerifyChainResponse);
}
```

## 4.3 数据存储方案

| 服务 | 存储 | 内容 | 备注 |
|---|---|---|---|
| policy-service | PostgreSQL | 策略源码、版本元数据、编译产物 BLOB | 按 content_hash 去重 |
| graph-service | RocksDB | 热图数据（节点/边/索引） | Column Family 按 EdgeKind 分区 |
| graph-service | S3 | 归档快照（protobuf 序列化） | 按时间前缀分桶 |
| audit-log-service | PostgreSQL | 审计记录（结构化）、签名链 | 分区表按日期 |
| audit-log-service | S3 (WORM) | 长期归档 | 合规保留 |
| cert-checker | 无持久化 | 无状态验证 | — |

## 4.4 证书格式详细设计

### 证书压缩策略

```
Certificate (wire format):
┌──────────────────────────────────────┐
│ Header (8 bytes)                     │
│  - magic: "PCMC" (4B)               │
│  - version: u16                      │
│  - flags: u16 (compressed, etc.)     │
├──────────────────────────────────────┤
│ Policy Hash (32 bytes, blake3)       │
├──────────────────────────────────────┤
│ Graph Merkle Root (32 bytes)         │
├──────────────────────────────────────┤
│ Request Hash (32 bytes)              │
├──────────────────────────────────────┤
│ Derivation Steps (variable)          │
│  - Hash-consed: 重复子树用 ref 引用  │
│  - 规则索引: varint encoded          │
│  - 事实引用: 相对偏移量              │
├──────────────────────────────────────┤
│ Signature (64 bytes, Ed25519)        │
└──────────────────────────────────────┘
```

**Hash-consing**：推导树中重复出现的子推导用 32 字节哈希引用替代，节省空间。

**Merkleization**：图快照按 Merkle 树组织，证书仅引用 Merkle 路径（而非全量图），验证时按需提供 Merkle 证明。

---

# 5. 安全审计与威胁建模

## 5.1 威胁模型（STRIDE 框架）

### 攻击面总览

```
┌─────────────────────────────────────────────────────┐
│                    信任边界                           │
│  ╔══════════════════════════════╗                    │
│  ║ TCB (必须被信任)             ║                    │
│  ║ - Lean 4 kernel             ║                    │
│  ║ - cert-checker (Lean 抽取)  ║                    │
│  ║ - 部署平台内核/容器运行时     ║                    │
│  ╚══════════════════════════════╝                    │
│                                                      │
│  ┌────────────────────────────────────────┐         │
│  │ 不在 TCB（可不信任）                     │         │
│  │ - monitor-gateway (Rust)               │         │
│  │ - policy-service                       │         │
│  │ - graph-service                        │         │
│  │ - diff-analyzer / solver               │         │
│  │ - audit-log-service                    │         │
│  │ - agent 应用                            │         │
│  └────────────────────────────────────────┘         │
└─────────────────────────────────────────────────────┘
```

### STRIDE 分析

| 威胁 | 类别 | 攻击场景 | 影响 | 缓解措施 |
|---|---|---|---|---|
| T1: Agent 绕过 monitor-gateway 直接外发 | **Tampering / Elevation** | Agent 容器直接开 TCP 连接到外部 | 安全策略失效 | **网络策略**：K8s NetworkPolicy 仅允许 agent 容器出口到 monitor-gateway；iptables/eBPF 强制；sidecar 模式下共享 netns |
| T2: 伪造/篡改证书 | **Spoofing** | 攻击者构造假证书让 checker 接受 | 非法操作被视为合法 | **Lean soundness 定理**保证无法构造通过 checker 但语义不成立的证书；证书签名验证（Ed25519） |
| T3: 图数据篡改 | **Tampering** | 恶意修改 graph-service 中的边/标签 | 策略评估基于错误图，放行违规请求 | 图节点/边带 blake3 哈希；Merkle 快照；审计对比；graph-service 只接受 authenticated append |
| T4: 策略回滚/降级 | **Tampering** | 将策略版本回滚到宽松旧版 | 升权 | 策略版本号单调递增；policy-service 禁止降级；激活需签名审批 |
| T5: 重放攻击 | **Replay** | 重放旧的 Allow 证书授权新请求 | 对过期上下文授权 | 证书绑定 request_id (UUID v7, 含时间戳) + graph_snapshot_hash；验证时检查时间窗口 |
| T6: monitor-gateway 被攻陷 | **Elevation** | RCE 导致攻击者控制 gateway | 可发 allow 决策 | gateway 不在 TCB；下游/审计独立验证证书；异常检测（成功率突变告警）；定期证书抽样复验 |
| T7: 供应链攻击 — checker 二进制替换 | **Tampering** | 替换 cert-checker 为恶意版本 | 假证书被接受 | CI 从 Lean 源码重新构建 checker；二进制哈希写入 Sigstore/Rekor 透明日志；运行时校验哈希 |
| T8: 审计日志篡改 | **Repudiation** | 删除/修改审计记录掩盖攻击 | 无法追溯 | WORM 存储；签名链（每条记录签名 + 前一条哈希）；异地备份 |
| T9: 策略 DSL 注入 | **Tampering** | 在策略中注入恶意规则 | 升权 | DSL 编译器严格解析（无 eval）；策略变更必须经 diff-analyzer + 人工审批 |
| T10: 权限提升 — 内部服务间 | **Elevation** | 被攻陷的 agent 调用 policy-service 修改策略 | 自我授权 | mTLS 服务间认证；RBAC：agent 无策略写权限；policy-service 仅从 CI/管理 API 可写 |

## 5.2 信任边界与 TCB 列表

### TCB（必须被信任的组件）

| 组件 | 理由 | 大小控制 |
|---|---|---|
| **Lean 4 type-checker / kernel** | 所有证明的最终验证基础 | Lean 官方维护；kernel ≈ 6k LoC |
| **cert-checker（Lean 定义 + 抽取）** | 运行时/离线证书验证 | ≤ 2000 LoC Lean；定理保证 soundness |
| **操作系统内核 + 容器运行时** | 网络隔离、进程隔离的执行基础 | 通用基础设施；不可避免 |
| **Ed25519 签名库** | 证书签名验证 | 使用审计过的实现（ring / dalek） |

### 不在 TCB（可不信任）

| 组件 | 理由 |
|---|---|
| monitor-gateway | 其输出（证书）由独立 checker 验证；即使被攻陷也无法伪造通过验证的证书 |
| policy-service / 编译器 | 编译产物正确性由策略评估+证书验证间接保证 |
| graph-service | 图数据带 Merkle 证明，篡改可检测 |
| diff-analyzer / Z3 solver | 其输出的反例+证书由 checker 独立验证 |
| agent 应用 | 被监控对象，完全不信任 |

## 5.3 关键安全控制

### 5.3.1 部署与隔离

```yaml
# K8s NetworkPolicy 示例 — Agent Pod
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: agent-egress-only-monitor
spec:
  podSelector:
    matchLabels:
      role: agent
  policyTypes:
    - Egress
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: monitor-gateway
      ports:
        - port: 50051
          protocol: TCP
    # DNS 解析
    - to:
        - namespaceSelector: {}
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - port: 53
          protocol: UDP
```

**控制项清单**：

| 控制 | 实现 |
|---|---|
| 网络隔离 | K8s NetworkPolicy 白名单出口；Calico/Cilium eBPF 强制 |
| mTLS | 服务间通信全量 mTLS（cert-manager + Istio/Linkerd 或自管理） |
| 最小权限 | 容器以非 root 运行；只读根文件系统；`securityContext.readOnlyRootFilesystem: true` |
| 密钥管理 | 签名密钥存 K8s Secret（Sealed Secrets / Vault）；checker 不持有密钥 |
| 镜像安全 | 最小基础镜像（distroless / scratch）；Trivy 扫描；签名（cosign） |
| Sidecar 强制出口 | V2 sidecar 模式下 agent 和 monitor 共享 network namespace |

### 5.3.2 数据完整性

| 数据 | 完整性机制 |
|---|---|
| 图节点/边 | 每节点/边内容 blake3 哈希；Merkle 快照根 |
| 策略 | content_hash = blake3(source)；版本链不可回退 |
| 证书 | 内含 policy_hash + graph_hash + request_hash；Ed25519 签名 |
| 审计日志 | 每条记录链式签名：`sig_i = sign(hash(record_i || sig_{i-1}))` |

### 5.3.3 旁路防护

1. **网络层**：Agent 容器唯一出口 = monitor-gateway:50051
2. **数据库层**：数据库凭据只在 monitor-gateway 内部保存；agent 无直接 DB 连接
3. **文件系统**：受控挂载卷（只读 + 限定路径）；写操作通过 monitor API
4. **SDK 层**：Agent SDK 将标准库 I/O 操作替换为 monitor-gateway 代理调用
5. **运行时检测**：eBPF 内核探针检测未经 monitor 的出站连接 → 告警 + kill

### 5.3.4 证书验证策略

| 场景 | 策略 | 失败处理 |
|---|---|---|
| 运行时（在线） | monitor-gateway 内嵌 checker；每次评估后自验证 | 验证失败 → 记录告警 + 仍执行原决策（证书问题不影响 deny 安全性） |
| CI Gate | 独立 checker CLI 验证策略变更证书 | 验证失败 → 阻止合并 |
| 离线审计 | 批量回放证书验证 | 发现无效证书 → 安全事件 |
| 降级模式 | checker 不可用 → fail-closed | 所有请求 Deny |

## 5.4 安全测试计划

| 测试类型 | 目标 | 工具/方法 |
|---|---|---|
| **旁路测试** | 验证 agent 无法绕过 monitor | 在 agent 容器内尝试直接 TCP 外连；验证 NetworkPolicy 拦截 |
| **证书 Fuzzing** | 验证 checker 不接受畸形/伪造证书 | AFL++/libFuzzer 对 checker 输入 fuzzing |
| **策略 Fuzzing** | 验证 DSL 编译器健壮性 | 随机策略生成 + 编译 |
| **差分测试** | 验证证书生成器与 checker 一致 | 对相同输入：生成证书 → checker 验证 → 断言 100% 通过 |
| **回放测试** | 验证证书可离线重现 | 收集生产审计日志 → 离线 checker 全量回放 |
| **渗透测试** | 端到端攻击模拟 | 年度第三方渗透；重点：旁路、策略注入、权限提升 |
| **混沌工程** | 验证 fail-closed 行为 | 随机终止 checker/graph-service → 验证 gateway 全部 Deny |
| **性能压力** | 高并发下安全性不降级 | 10k QPS 下无旁路、无证书跳过 |

## 5.5 合规与隐私

| 项 | 策略 |
|---|---|
| **数据最小化** | 审计日志记录决策元数据，不存请求 body 原文；可选脱敏 |
| **PII 标记** | 策略 DSL 支持 `data_label(X, PII)` 标签；PII 数据流受限 |
| **Secret 防泄露** | 请求中的 secret 字段在日志中自动 redact；标签传播 |
| **保留期** | 审计日志默认保留 90 天（可配置）；过期自动归档/删除 |
| **访问审计** | 审计日志本身的读访问亦被记录（meta-audit） |

---

# 6. Lean 形式化与证书体系

## 6.1 总体策略

```
┌───────────────────────────────────────┐
│  Lean 4 形式化层                       │
│                                        │
│  ┌────────────┐  ┌────────────────┐   │
│  │ Spec 层    │  │ Checker 层     │   │
│  │ (语义定义) │  │ (可执行验证)    │   │
│  ├────────────┤  ├────────────────┤   │
│  │ PolicySem  │  │ checkCert      │   │
│  │ GraphSem   │  │ checkWitness   │   │
│  │ AllowedSpec│  │ checkDiffCert  │   │
│  │ DiffSpec   │  │                │   │
│  └──────┬─────┘  └──────┬─────────┘   │
│         │               │              │
│  ┌──────┴───────────────┴──────────┐  │
│  │ Soundness Theorems              │  │
│  │ check=true → Spec holds         │  │
│  └─────────────────────────────────┘  │
│                │ code extraction       │
│                ▼                       │
│  ┌─────────────────────────────────┐  │
│  │ Executable Checker (C/Rust FFI) │  │
│  └─────────────────────────────────┘  │
└───────────────────────────────────────┘
```

## 6.2 Spec 层定义

### 6.2.1 基础类型

```lean
-- PCM.Spec.Basic

/-- 动作类型 -/
inductive ActionType where
  | toolCall | httpOut | dbWrite | dbReadSensitive | fileWrite | fileRead | custom (tag : String)
  deriving DecidableEq, Repr

/-- 敏感级别标签 -/
inductive Label where
  | public | internal | confidential | secret
  deriving DecidableEq, Repr, Ord

/-- 标签偏序：public ≤ internal ≤ confidential ≤ secret -/
instance : LE Label where
  le a b := a.toNat ≤ b.toNat

/-- 请求 -/
structure Request where
  id        : String
  action    : ActionType
  principal : String
  target    : String
  attrs     : List (String × String)
  deriving DecidableEq, Repr

/-- 图节点 -/
structure GNode where
  id    : String
  kind  : NodeKind
  label : Label
  deriving DecidableEq

/-- 图边 -/
structure GEdge where
  src  : String
  dst  : String
  kind : EdgeKind
  deriving DecidableEq

/-- 依赖图 -/
structure Graph where
  nodes : List GNode
  edges : List GEdge
  deriving DecidableEq
```

### 6.2.2 策略语义

```lean
-- PCM.Spec.Policy

/-- 原子事实 -/
inductive Atom where
  | action (id : String) (ty : ActionType) (princ : String) (tgt : String)
  | dataLabel (data : String) (l : Label)
  | hasRole (princ : String) (role : String)
  | graphEdge (src dst : String) (kind : EdgeKind)
  | graphLabel (node : String) (l : Label)
  | precedes (a b : String)
  | deny (req : String) (reason : String)
  deriving DecidableEq

/-- 规则体中的文字（正/负） -/
inductive Literal where
  | pos (a : Atom)
  | neg (a : Atom)
  deriving DecidableEq

/-- Datalog 规则（Horn 子句） -/
structure Rule where
  head : Atom
  body : List Literal
  deriving DecidableEq

/-- 策略 = 规则集合 -/
structure Policy where
  rules : List Rule
  deriving DecidableEq

/-- 事实数据库（从请求+图导出的基础事实） -/
def baseFacts (req : Request) (g : Graph) (roles : List (String × String)) : List Atom :=
  [Atom.action req.id req.action req.principal req.target]
  ++ roles.map (fun (p, r) => Atom.hasRole p r)
  ++ g.edges.map (fun e => Atom.graphEdge e.src e.dst e.kind)
  ++ g.nodes.map (fun n => Atom.graphLabel n.id n.label)
  -- ... 时序事实从图推导

/-- Datalog 最小模型语义（朴素自底向上不动点） -/
def minimalModel (p : Policy) (base : List Atom) : List Atom :=
  sorry -- 标准 Datalog 不动点计算

/-- 判定：请求在 (policy, graph) 下是否被允许 -/
def AllowedSpec (req : Request) (pol : Policy) (g : Graph)
    (roles : List (String × String)) : Prop :=
  let model := minimalModel pol (baseFacts req g roles)
  ∀ reason, Atom.deny req.id reason ∉ model
```

### 6.2.3 diff 语义

```lean
-- PCM.Spec.Diff

/-- 差分类型 -/
inductive DiffKind where
  | escalation  -- Deny → Allow
  | breaking    -- Allow → Deny

/-- 差分规约：存在请求 r 使得两个策略给出不同判定 -/
def DiffSpec (polOld polNew : Policy) (g : Graph)
    (roles : List (String × String)) (r : Request) (k : DiffKind) : Prop :=
  match k with
  | .escalation =>
      ¬AllowedSpec r polOld g roles ∧ AllowedSpec r polNew g roles
  | .breaking =>
      AllowedSpec r polOld g roles ∧ ¬AllowedSpec r polNew g roles
```

## 6.3 Cert 层（可执行 Checker）

### 6.3.1 证书数据结构

```lean
-- PCM.Cert.Certificate

/-- 推导步骤 -/
structure DerivStep where
  ruleIdx   : Nat               -- 规则编号
  premises  : List Nat          -- 前提事实索引
  conclusion: Atom              -- 推导出的原子

/-- Allow 证书 -/
structure Certificate where
  steps       : List DerivStep
  policyHash  : ByteArray       -- blake3(policy)
  graphHash   : ByteArray       -- Merkle root
  requestHash : ByteArray       -- blake3(request)

/-- Deny 反例 -/
structure Witness where
  denyRuleIdx    : Nat
  matchedFacts   : List Atom
  violationPath  : List (String × String)  -- 图路径
  policyHash     : ByteArray
  requestHash    : ByteArray
```

### 6.3.2 可执行 Checker

```lean
-- PCM.Cert.Checker

/-- 验证推导步骤的合法性 -/
def checkStep (pol : Policy) (derived : List Atom) (step : DerivStep) : Bool :=
  -- 1. 规则索引有效
  match pol.rules.get? step.ruleIdx with
  | none => false
  | some rule =>
    -- 2. 结论匹配规则头部（模式匹配/统一）
    matchAtom rule.head step.conclusion &&
    -- 3. 所有正文字的前提已被推导
    rule.body.all (fun lit =>
      match lit with
      | .pos a => step.premises.any (fun i => derived.get? i == some a)
      | .neg a => derived.all (fun d => d != a)  -- 安全否定
    )

/-- 证书检查器（核心 TCB 函数） -/
def checkCert (cert : Certificate) (req : Request) (pol : Policy) (g : Graph)
    (roles : List (String × String)) : Bool :=
  -- 1. 哈希一致性（绑定证书到具体输入）
  verify_hash cert.policyHash pol &&
  verify_hash cert.graphHash g &&
  verify_hash cert.requestHash req &&
  -- 2. 归纳验证每个推导步骤
  let base := baseFacts req g roles
  let (allValid, derived) := cert.steps.foldl
    (fun (ok, acc) step =>
      if ok && checkStep pol acc step
      then (true, acc ++ [step.conclusion])
      else (false, acc))
    (true, base)
  -- 3. 最终模型中不含任何 deny
  allValid &&
  derived.all (fun a => match a with | .deny _ _ => false | _ => true) &&
  -- 4. deny 规则的否定前提确实不可推出 => 无 deny 可被推导
  pol.rules.all (fun r =>
    match r.head with
    | .deny _ _ => ¬(r.body.all (fun lit => checkLitSatisfied lit derived))
    |  _ => true)

/-- Witness 检查器 -/
def checkWitness (w : Witness) (req : Request) (pol : Policy) (g : Graph)
    (roles : List (String × String)) : Bool :=
  verify_hash w.policyHash pol &&
  verify_hash w.requestHash req &&
  match pol.rules.get? w.denyRuleIdx with
  | none => false
  | some rule =>
    -- 该规则头部是 deny
    match rule.head with
    | .deny _ _ =>
      -- Witness 提供的事实确实能匹配规则体
      rule.body.all (fun lit =>
        match lit with
        | .pos a => a ∈ w.matchedFacts
        | .neg a => a ∉ (baseFacts req g roles ++ w.matchedFacts))
      &&
      -- Witness 中的事实确实是基础事实的子集或可推导
      w.matchedFacts.all (fun a => a ∈ baseFacts req g roles)
    | _ => false

/-- Diff 证书检查器 -/
def checkDiffCert (w : DiffWitness) (polOld polNew : Policy) : Bool :=
  -- 对同一请求，旧策略和新策略给出不同判定
  let reqOldResult := checkCert w.certOld w.request polOld w.graph w.roles
  let reqNewResult := checkCert w.certNew w.request polNew w.graph w.roles
  match w.kind with
  | .escalation =>
      -- 旧策略 deny (witness 有效) 且新策略 allow (cert 有效)
      checkWitness w.witnessOld w.request polOld w.graph w.roles &&
      checkCert w.certNew w.request polNew w.graph w.roles
  | .breaking =>
      checkCert w.certOld w.request polOld w.graph w.roles &&
      checkWitness w.witnessNew w.request polNew w.graph w.roles
```

## 6.4 Soundness 定理

### 定理 1：Allow 证书 Soundness

```lean
-- PCM.Proofs.CertSoundness

theorem cert_soundness
    (req : Request) (pol : Policy) (g : Graph)
    (roles : List (String × String))
    (cert : Certificate)
    (h : checkCert cert req pol g roles = true)
    : AllowedSpec req pol g roles := by
  /- 证明路线：
     1. checkCert = true 意味着所有推导步骤合法
     2. 由步骤合法性，归纳证明 cert.steps 构造的模型 M ⊆ minimalModel
     3. M 中不含 deny 原子
     4. 由 Datalog 最小模型唯一性，minimalModel 中也不含 deny
     5. 即 AllowedSpec 成立
  -/
  sorry -- 待完成
```

### 定理 2：Deny Witness Soundness

```lean
theorem witness_soundness
    (req : Request) (pol : Policy) (g : Graph)
    (roles : List (String × String))
    (w : Witness)
    (h : checkWitness w req pol g roles = true)
    : ¬AllowedSpec req pol g roles := by
  /- 证明路线：
     1. checkWitness = true 意味着存在 deny 规则 r，其体部所有文字在基础事实中被满足
     2. 由 Datalog 语义，deny(req.id, reason) ∈ minimalModel
     3. 与 AllowedSpec (∀ reason, deny ∉ model) 矛盾
  -/
  sorry
```

### 定理 3：Diff Witness Soundness

```lean
theorem diff_witness_soundness
    (polOld polNew : Policy) (g : Graph)
    (roles : List (String × String))
    (w : DiffWitness)
    (h : checkDiffCert w polOld polNew = true)
    : DiffSpec polOld polNew g roles w.request w.kind := by
  /- 证明路线：
     组合 cert_soundness 和 witness_soundness
     - escalation: witness_soundness(old) ∧ cert_soundness(new)
     - breaking:   cert_soundness(old) ∧ witness_soundness(new)
  -/
  sorry
```

### 定理 4：Complete Mediation（模型层）

```lean
/-- 系统模型：所有外部效果必须经过 Monitor -/
structure SystemModel where
  actions    : List Request
  decisions  : Request → Decision
  executed   : List Request  -- 实际执行的动作

/-- Complete mediation 性质 -/
def CompleteMediationSpec (sys : SystemModel) : Prop :=
  ∀ req ∈ sys.executed,
    sys.decisions req |>.verdict = .allow ∧
    checkCert (sys.decisions req |>.certificate) req pol graph roles = true

theorem complete_mediation_model
    (sys : SystemModel) (inv : SystemInvariant sys)
    : CompleteMediationSpec sys := by
  /- 证明路线：
     由 SystemInvariant（所有 I/O 操作通过 monitor gateway）
     + gateway 逻辑（只放行 allow 决策且证书验证通过的请求）
     推出性质成立。
     注：实现层面的保证需要网络隔离+部署约束（不在纯 Lean 证明范围内，
     但 Lean 模型可刻画"前提条件"供部署验证对照）。
  -/
  sorry
```

## 6.5 Lean 与非 Lean 组件的接口

### 6.5.1 代码抽取

```
Lean 4 定义
    │
    ├─► lean4 compiler ──► C 代码 ──► 编译为 .so / .dll
    │                                   │
    │                                   ├── cert_checker_ffi.h
    │                                   └── libcert_checker.{so,dll}
    │
    └─► 可选：手写 Rust FFI wrapper
            └── cert-checker-rs crate
                  │
                  └── 嵌入 monitor-gateway (Rust)
```

### 6.5.2 运行时集成

```rust
// Rust 侧 FFI 调用示例
extern "C" {
    fn lean_check_cert(
        cert_buf: *const u8, cert_len: usize,
        req_buf: *const u8,  req_len: usize,
        pol_buf: *const u8,  pol_len: usize,
        graph_buf: *const u8, graph_len: usize,
    ) -> bool;
}

pub fn verify_certificate(cert: &Certificate, req: &Request,
                          pol: &CompiledPolicy, graph: &GraphSnapshot) -> bool {
    let cert_bytes = cert.serialize();
    let req_bytes = req.serialize();
    // ... 序列化并调用 FFI
    unsafe {
        lean_check_cert(
            cert_bytes.as_ptr(), cert_bytes.len(),
            req_bytes.as_ptr(), req_bytes.len(),
            pol_bytes.as_ptr(), pol_bytes.len(),
            graph_bytes.as_ptr(), graph_bytes.len(),
        )
    }
}
```

### 6.5.3 CI 集成

```yaml
# .github/workflows/lean-verify.yml
- name: Build cert-checker from Lean
  run: |
    cd lean/
    lake build PCM.Cert.Checker
    lake build PCM.Proofs  # 编译即验证所有定理
    
- name: Extract executable checker
  run: |
    lake exe extract-checker --output ../artifacts/libcert_checker.so
    sha256sum ../artifacts/libcert_checker.so > ../artifacts/checker.sha256
```

## 6.6 证明规模控制与自动化策略

| 层级 | 自动化程度 | 工具 |
|---|---|---|
| 基础类型 `DecidableEq` / `Repr` | 全自动 | `deriving` |
| 列表成员判定 / 布尔反射 | 半自动 | `simp`、`decide`、`omega` |
| Datalog 不动点性质 | 手工 + 辅助 | 手写归纳，`induction` + `simp` |
| Soundness 主定理 | 主要手工 | 结构化证明；拆分 lemma |
| 哈希一致性引理 | 公理化 | `axiom blake3_collision_free` |

**关键 lemma 拆分**（预计 15-25 个手工 lemma）：

1. `minimalModel_membership`：不动点中的元素必可推导
2. `step_preserves_derivable`：单步推导保持可推导集
3. `no_deny_in_model`：证书验证通过 → 模型中无 deny
4. `witness_implies_deny_in_model`：witness 匹配 → deny 在模型中
5. `datalog_model_unique`：分层 Datalog 的最小模型唯一
6. `baseFacts_subset_model`：基础事实 ⊆ 最小模型

---

# 7. 测试、CI/CD 与发布策略

## 7.1 测试金字塔

```
          ┌────────────┐
          │  E2E 测试   │  ← Docker Compose 全链路
          │  (10)       │
         ┌┴────────────┴┐
         │  集成测试      │  ← 服务间 gRPC 交互
         │  (50)         │
        ┌┴──────────────┴┐
        │  属性测试/Fuzz   │  ← proptest / AFL++
        │  (100+)         │
       ┌┴────────────────┴┐
       │  单元测试          │  ← 每服务/模块
       │  (500+)           │
      ┌┴──────────────────┴┐
      │  Lean 定理证明验证   │  ← lake build 即验证
      │  (soundness)        │
      └────────────────────┘
```

## 7.2 CI Pipeline

```yaml
# .github/workflows/ci.yml
name: PCM CI
on: [push, pull_request]

jobs:
  lean-proofs:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: leanprover/lean4-action@v1
      - run: cd lean && lake build PCM
      - run: cd lean && lake build PCM.Proofs  # 所有定理验证

  rust-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo fmt --check
      - run: cargo clippy -- -D warnings
      - run: cargo test --workspace
      - run: cargo bench --workspace -- --test  # 性能回归检测

  python-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install -e ".[dev]"
      - run: ruff check .
      - run: mypy .
      - run: pytest --cov

  security-scan:
    runs-on: ubuntu-latest
    steps:
      - run: cargo audit
      - run: trivy fs --severity HIGH,CRITICAL .
      - run: pip-audit

  integration-tests:
    needs: [rust-check, python-check, lean-proofs]
    runs-on: ubuntu-latest
    steps:
      - run: docker compose -f docker-compose.test.yml up --build --abort-on-container-exit

  cert-fuzz:
    needs: [rust-check]
    runs-on: ubuntu-latest
    steps:
      - run: cargo +nightly fuzz run fuzz_cert_checker -- -max_total_time=300

  # 策略 PR 自动 diff 分析
  policy-diff:
    if: github.event_name == 'pull_request'
    needs: [rust-check, python-check]
    runs-on: ubuntu-latest
    steps:
      - run: pcm-cli diff --old main --new HEAD --output report.json
      - run: pcm-cli cert-verify report.json
      - uses: actions/github-script@v7
        with:
          script: |
            // 将 diff 报告写入 PR comment
```

## 7.3 发布策略

| 阶段 | 触发 | 验证 | 产物 |
|---|---|---|---|
| Dev | 每次 push | 全量 CI | Docker 镜像 (tag: sha) |
| Staging | merge to main | CI + 集成测试 + 性能基准 | 镜像 (tag: staging-date) |
| Release | Git tag (v*) | 全量 CI + E2E + Lean 证明重建 + checker 哈希比对 | 签名镜像 (tag: vX.Y.Z)；checker 二进制 + SHA256 |

---

# 8. 里程碑与 Backlog（含 DoD）

## 8.1 里程碑概览

| 里程碑 | 周期 | 核心交付 |
|---|---|---|
| **M0: Foundation** | Week 1-2 | 项目骨架、Lean 基础定义、策略 DSL 解析器 |
| **M1: Core Monitor** | Week 3-5 | monitor-gateway、策略评估、证书生成 |
| **M2: Lean Proofs** | Week 4-6 | Checker soundness 定理证明、代码抽取 |
| **M3: Graph & Policy Service** | Week 5-7 | graph-service、policy-service、完整运行时流程 |
| **M4: MVP Release** | Week 7-8 | Docker Compose 部署、CLI、基础审计、E2E 测试 |
| **M5: Diff Analyzer** | Week 9-12 | diff-analyzer、CI Gate、diff 证书 |
| **M6: Production Hardening** | Week 13-16 | K8s Helm、网络隔离、审计签名链、性能优化 |

## 8.2 详细 Backlog

### M0: Foundation（Week 1-2）

| ID | 任务 | 估时 | DoD |
|---|---|---|---|
| M0-1 | 初始化 monorepo 目录结构、CI 配置 | 1d | CI 绿；所有服务目录创建 |
| M0-2 | Lean 4 项目初始化 (lakefile.lean) | 0.5d | `lake build` 通过 |
| M0-3 | Lean Spec 基础类型定义（ActionType, Label, Request, Graph） | 1d | 类型编译通过 + DecidableEq 推导 |
| M0-4 | Lean Policy/Rule 类型定义 | 1d | 编译通过 |
| M0-5 | 策略 DSL 语法设计 + PEG/nom 解析器（Rust） | 2d | 解析 5 个示例策略成功 |
| M0-6 | Protobuf schema 定义（Request, Decision, Certificate, Witness） | 1d | `protoc` 编译通过；Rust/Python 代码生成 |
| M0-7 | 基础 Rust workspace 初始化（Cargo workspace） | 0.5d | `cargo build` 通过 |
| M0-8 | Python diff-analyzer 项目初始化 | 0.5d | `pytest` 通过空测试 |
| M0-9 | Docker Compose 基础配置 | 0.5d | `docker compose up` 启动空服务 |

### M1: Core Monitor（Week 3-5）

| ID | 任务 | 估时 | DoD |
|---|---|---|---|
| M1-1 | Datalog 评估器（朴素自底向上不动点，Rust） | 3d | 10 个策略+事实组合单测通过 |
| M1-2 | monitor-gateway gRPC 框架（tonic） | 1d | Evaluate RPC 可调通（硬编码 allow） |
| M1-3 | 策略编译器（DSL → CompiledPolicy） | 2d | 编译+反编译 round-trip 测试通过 |
| M1-4 | 证书生成器（推导追踪 → Certificate） | 2d | 对 allow 决策生成证书；手动验证结构正确 |
| M1-5 | Witness 生成器（deny 规则匹配 → Witness） | 1d | 对 deny 决策生成 witness；人可读输出 |
| M1-6 | 运行时 Checker（Rust 侧 Lean FFI 或纯 Rust 镜像） | 2d | 证书验证 100% 自洽（生成后立即验证通过） |
| M1-7 | 属性测试：随机策略+请求 → 证书/witness 总有一个 | 1d | proptest 1000 轮无失败 |

### M2: Lean Proofs（Week 4-6）

| ID | 任务 | 估时 | DoD |
|---|---|---|---|
| M2-1 | Lean: Datalog 语义 minimalModel 定义 + 基础引理 | 2d | 编译通过 + 2 个引理证明 |
| M2-2 | Lean: AllowedSpec 定义 + baseFacts | 1d | 编译通过 |
| M2-3 | Lean: checkCert 可执行定义 | 2d | `#eval` 示例通过 |
| M2-4 | Lean: cert_soundness 定理证明 | 3d | `lake build PCM.Proofs.CertSoundness` 通过 |
| M2-5 | Lean: checkWitness + witness_soundness | 2d | 定理证明通过 |
| M2-6 | Lean: 代码抽取 → C 代码 → FFI 集成测试 | 2d | Rust 通过 FFI 调用 Lean checker 验证 10 个证书 |

### M3: Graph & Policy Service（Week 5-7）

| ID | 任务 | 估时 | DoD |
|---|---|---|---|
| M3-1 | graph-service RocksDB 存储层 | 2d | CRUD + 快照单测通过 |
| M3-2 | graph-service gRPC API | 1d | AppendEvent + GetSnapshot 集成测试 |
| M3-3 | policy-service PostgreSQL 存储 | 1d | 策略 CRUD 单测通过 |
| M3-4 | policy-service gRPC API（含编译触发） | 1d | CreatePolicy + CompilePolicy 集成测试 |
| M3-5 | monitor-gateway 集成 graph-service | 1d | 评估时实时查图 |
| M3-6 | 策略热加载（watch + reload） | 1d | 更新策略后下一个请求使用新策略 |

### M4: MVP Release（Week 7-8）

| ID | 任务 | 估时 | DoD |
|---|---|---|---|
| M4-1 | audit-log-service 基础实现 | 2d | 每个决策记录完整日志 |
| M4-2 | pcm-cli：策略编译、证书验证、日志查询 | 2d | 3 个子命令 E2E 通过 |
| M4-3 | Docker Compose 全链路部署 | 1d | `docker compose up` 后全流程 E2E 通过 |
| M4-4 | E2E 测试套件（5个场景） | 2d | 全部绿 |
| M4-5 | 性能基准测试 | 1d | P99 ≤ 5ms（Evaluate）；输出 benchmark 报告 |
| M4-6 | README / 快速上手文档 | 1d | 新用户可在 15 分钟内跑通 demo |

### M5: Diff Analyzer（Week 9-12）

| ID | 任务 | 估时 | DoD |
|---|---|---|---|
| M5-1 | 策略→Z3 编码器（Python） | 3d | 5 个策略对的编码正确性测试通过 |
| M5-2 | 语义差分求解器（枚举反例 + 最小化） | 3d | 对已知差异策略对找到正确反例 |
| M5-3 | DiffCertificate 生成 | 2d | 每个反例附带可验证证书 |
| M5-4 | Lean: checkDiffCert + diff_witness_soundness | 3d | 定理通过 |
| M5-5 | diff-analyzer gRPC 服务 | 1d | AnalyzeDiff RPC 集成测试 |
| M5-6 | CI Gate：GitHub Actions 集成 | 2d | 策略 PR 自动分析 + 评论 |
| M5-7 | UNSAT 等价证书（可选） | 3d | 对等价策略对输出证书 |

### M6: Production Hardening（Week 13-16）

| ID | 任务 | 估时 | DoD |
|---|---|---|---|
| M6-1 | K8s Helm Chart | 2d | `helm install` 在测试集群部署成功 |
| M6-2 | NetworkPolicy 配置 + 旁路测试 | 2d | agent 容器无法绕过 monitor |
| M6-3 | mTLS 配置（cert-manager） | 1d | 服务间通信全量加密 |
| M6-4 | 审计签名链 | 2d | 签名链验证通过；篡改检测测试通过 |
| M6-5 | Prometheus / OTel 指标埋点 | 2d | Grafana dashboard 展示核心指标 |
| M6-6 | 证书 Fuzzing | 2d | AFL++ 10 万轮无 checker crash |
| M6-7 | 性能优化（增量评估预研） | 3d | 输出技术报告 + 原型 |
| M6-8 | 安全加固 checklist 执行 | 2d | 所有 §5.3 控制项实施确认 |

---

# 9. 待我确认的问题清单

| # | 问题 | 影响范围 | 默认假设 |
|---|---|---|---|
| Q1 | 主语言栈确认：Rust + Python + Lean 4 是否可接受？ | 全局 | 是 |
| Q2 | 运行环境确认：K8s + Docker Compose 本地？是否需要支持 Nomad 或其他？ | 部署 | 仅 K8s + Docker Compose |
| Q3 | CI 平台：GitHub Actions 还是 GitLab CI？ | CI/CD | GitHub Actions |
| Q4 | Agent SDK 目标语言：初期仅 Python SDK？是否需要 TypeScript/Go？ | M4 | Python 优先 |
| Q5 | 策略仓库模式：与应用 monorepo 还是独立仓库？ | policy-service | monorepo 下 `policies/` 目录 |
| Q6 | 图存储选择确认：RocksDB 嵌入式还是外部图数据库（如 DGraph）？ | graph-service | RocksDB（简单、低延迟） |
| Q7 | 审计合规要求等级：SOC2 / HIPAA / 无特定要求？ | 安全 | SOC2 参考，非强制 |
| Q8 | 证书签名密钥管理：K8s Secrets / HashiCorp Vault / 云 KMS？ | 安全 | K8s Secrets（MVP）→ Vault（V1） |
| Q9 | 初始部署规模确认：≤ 100 agent / ≤ 500 规则是否合理？ | 性能设计 | 是 |
| Q10 | 策略 DSL 的否定支持：安全分层否定还是完全禁止否定？ | 语义/证明 | 安全分层否定（stratified negation） |
| Q11 | 是否需要 Web UI（Developer Portal）在 V1 就提供？ | 产品 | V2 再做 |
| Q12 | Lean 证明的完成度预期：MVP 是否允许 `sorry`（标记为 TODO）？ | M2 | MVP 允许辅助 lemma 用 sorry；核心 soundness 必须完成 |

---

*文档结束。下一步：基于确认结果初始化代码骨架。*
