# PCM 快速上手指南

> ⏱️ 预计用时：15 分钟 | 前置条件：Docker + Docker Compose v2

本指南带你从零跑通 Proof-Carrying Monitor 的完整 demo，包括启动服务、发送请求、理解证书、编写策略和查看审计日志。

---

## 第 1 步：启动环境（2 分钟）

### 1.1 克隆仓库

```bash
git clone https://github.com/your-org/proof-carrying-monitor.git
cd proof-carrying-monitor
```

### 1.2 启动所有服务

```bash
docker compose up --build -d
```

此命令将启动 5 个容器：

| 服务 | 端口 | 说明 |
|------|------|------|
| `postgres` | 5432 | PostgreSQL 数据库 |
| `policy-service` | 50052 | 策略管理服务 |
| `graph-service` | 50053 | 依赖图服务 |
| `audit-service` | 50054 | 审计日志服务 |
| `monitor-gateway` | 50051 | 参考监控器网关 |

### 1.3 确认服务就绪

等待约 30 秒后，检查所有容器是否运行正常：

```bash
docker compose ps
```

预期输出（所有服务状态为 `running (healthy)`）：

```
NAME                              STATUS
pcm-postgres-1                    running (healthy)
pcm-policy-service-1              running (healthy)
pcm-graph-service-1               running (healthy)
pcm-audit-service-1               running (healthy)
pcm-monitor-gateway-1             running (healthy)
```

### 1.4 健康检查

```bash
grpcurl -plaintext -import-path proto -proto pcm/v1/services.proto \
  localhost:50051 pcm.v1.MonitorService/Health
```

预期输出：

```json
{
  "healthy": true,
  "policyVersion": "a1b2c3...",
  "uptimeSeconds": "15"
}
```

> 💡 如果没有安装 `grpcurl`，可从 [GitHub Releases](https://github.com/fullstorydev/grpcurl/releases) 下载。

---

## 第 2 步：理解默认策略（3 分钟）

打开 `policies/default.pcm` 文件：

```prolog
// === R1: 禁止未授权的外部 HTTP 调用 ===
deny(Req, "unauthorized_http") :-
    action(Req, http_out, P, _),       // 匹配 HTTP 外发动作
    !has_role(P, "http_allowed").      // 发起者没有 "http_allowed" 角色

// === R2: 敏感数据读取需要 audit_read 角色 ===
deny(Req, "sensitive_read_unauthorized") :-
    action(Req, db_read_sensitive, P, _),  // 匹配敏感数据读取动作
    !has_role(P, "audit_read").            // 发起者没有 "audit_read" 角色
```

### 策略逻辑解读

| 规则 | 含义 | 触发条件 |
|------|------|----------|
| R1 | 拒绝未授权的 HTTP 外发 | action_type = HTTP_OUT 且 principal 没有 `http_allowed` 角色 |
| R2 | 拒绝未授权的敏感数据读取 | action_type = DB_READ_SENSITIVE 且 principal 没有 `audit_read` 角色 |

**核心原则**：PCM 策略采用"否定即拒绝"模型 — 只定义 `deny` 规则，不匹配任何 deny 规则的请求自动放行（Allow）。

---

## 第 3 步：发送 Allow 请求（2 分钟）

构造一个**有授权**的 HTTP 外发请求。`principal` 设为 `"http_allowed_user"`，该用户拥有 `http_allowed` 角色：

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

> 📌 `action_type: 2` 对应 `HTTP_OUT`（见 `proto/pcm/v1/types.proto` 中的 `ActionType` 枚举）

预期输出：

```json
{
  "decision": {
    "requestId": "demo-allow-001",
    "verdict": "ALLOW",
    "certificate": {
      "steps": [
        {
          "ruleIndex": 0,
          "conclusion": "allow(demo-allow-001)"
        }
      ],
      "policyHash": "...",
      "graphHash": "...",
      "requestHash": "..."
    },
    "policyVersionHash": "...",
    "decidedAt": "2026-02-27T..."
  },
  "evaluationDurationUs": "42"
}
```

### 理解 Certificate

- **verdict = ALLOW**：请求被放行
- **certificate.steps**：推导树——从事实出发，通过哪些规则步骤推导出 "该请求不违反任何 deny 规则"
- **policyHash / graphHash / requestHash**：三个哈希值将证书绑定到特定的策略版本、图快照和请求，防止证书被重放

---

## 第 4 步：触发 Deny（2 分钟）

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

预期输出：

```json
{
  "decision": {
    "requestId": "demo-deny-002",
    "verdict": "DENY",
    "witness": {
      "denyRuleId": "R0",
      "humanReadableReason": "unauthorized_http",
      "matchedFacts": [
        "action(demo-deny-002, http_out, unauthorized_user, https://api.example.com)",
        "!has_role(unauthorized_user, http_allowed)"
      ],
      "policyHash": "...",
      "requestHash": "..."
    },
    "policyVersionHash": "...",
    "decidedAt": "2026-02-27T..."
  },
  "evaluationDurationUs": "38"
}
```

### 理解 Witness

- **verdict = DENY**：请求被拒绝
- **witness.denyRuleId**：触发的 deny 规则编号
- **witness.humanReadableReason**：人类可读的拒绝原因（`"unauthorized_http"`）
- **witness.matchedFacts**：匹配到的具体事实 — 这正是该请求被拒绝的证据
  - 事实 1：存在一个 `http_out` 动作
  - 事实 2：该用户确实没有 `http_allowed` 角色

> 🔑 与传统策略引擎的区别：PCM 不仅告诉你"被拒绝了"，还给出**为什么被拒绝的可验证证据**。

---

## 第 5 步：编写自定义策略（3 分钟）

### 5.1 创建策略文件

创建 `policies/my_policy.pcm`：

```prolog
// 自定义策略示例

// R1: 文件写入需要 file_writer 角色
deny(Req, "file_write_denied") :-
    action(Req, file_write, P, _),
    !has_role(P, "file_writer").

// R2: 写数据库前必须先经过认证步骤
deny(Req, "no_auth_before_write") :-
    action(Req, db_write, P, _),
    !precedes(auth_check, Req).

// R3: 机密数据不可流向公开端点
deny(Req, "data_leak") :-
    action(Req, http_out, _, Target),
    graph_edge(Src, Target, data_flow),
    graph_label(Src, Confidential),
    graph_label(Target, Public).
```

### 5.2 验证语法

```bash
cargo run -p pcm-cli -- validate --file policies/my_policy.pcm
```

预期输出：

```
✓ Policy is valid (3 rules, 0 errors, 0 warnings)
```

### 5.3 编译策略

```bash
cargo run -p pcm-cli -- compile --file policies/my_policy.pcm
```

预期输出（编译产物 JSON）：

```json
{
  "rules": [ ... ],
  "strata": [ [0, 1, 2] ],
  "fact_schema": { ... },
  "content_hash": "a3f2e1...",
  "version": "1.0.0",
  "decidable": true
}
```

### 5.4 在 Docker Compose 中使用

修改 `docker-compose.yml` 中 `monitor-gateway` 的环境变量：

```yaml
PCM_POLICY_FILE: /policies/my_policy.pcm
```

然后重启：

```bash
docker compose restart monitor-gateway
```

---

## 第 6 步：使用 CLI 验证证书（2 分钟）

PCM CLI 支持离线验证证书，无需连接运行中的服务。

### 6.1 保存证书

先将上面 Allow 请求的证书输出保存到文件：

```bash
# 发送请求并保存完整响应
grpcurl -plaintext -import-path proto -proto pcm/v1/services.proto \
  -d '{
    "request": {
      "request_id": "verify-demo-001",
      "action_type": 2,
      "principal": "http_allowed_user",
      "target": "https://api.example.com"
    }
  }' \
  localhost:50051 pcm.v1.MonitorService/Evaluate > /tmp/cert.json
```

### 6.2 离线验证

```bash
cargo run -p pcm-cli -- verify \
  --cert /tmp/cert.json \
  --policy policies/default.pcm \
  --format json
```

预期输出：

```
✓ Certificate verification PASSED
  Policy hash: a1b2c3...
  Request ID:  verify-demo-001
  Verdict:     ALLOW
  Steps verified: 1
```

> 🔑 离线验证的核心意义：任何第三方都可以独立验证证书的正确性，无需信任 PCM 服务本身。

---

## 第 7 步：查看审计日志（1 分钟）

每次 Evaluate 调用都会自动记录到审计日志（签名链）。

### 7.1 查询最近的审计记录

```bash
cargo run -p pcm-cli -- audit \
  --query '{"limit": 10}' \
  --endpoint http://localhost:50054 \
  --format table
```

预期输出：

```
┌────────────────┬──────────────┬─────────┬──────────────────────┐
│ Record ID      │ Request ID   │ Verdict │ Time                 │
├────────────────┼──────────────┼─────────┼──────────────────────┤
│ rec-001        │ demo-allow-001│ ALLOW  │ 2026-02-27T10:00:01Z │
│ rec-002        │ demo-deny-002 │ DENY   │ 2026-02-27T10:00:05Z │
│ rec-003        │ verify-demo-001│ ALLOW  │ 2026-02-27T10:01:00Z │
└────────────────┴──────────────┴─────────┴──────────────────────┘
```

### 7.2 验证审计链完整性

```bash
cargo run -p pcm-cli -- audit \
  --endpoint http://localhost:50054 \
  --verify-chain
```

预期输出：

```
✓ Audit chain integrity verified
  Records checked: 3
  Chain valid: true
  First record: rec-001
  Last record:  rec-003
```

---

## 恭喜！🎉

你已经完成了 PCM 的快速上手体验。下面是你已经掌握的内容：

| 步骤 | 你学到了 |
|------|----------|
| 1 | Docker Compose 一键部署 PCM 全栈 |
| 2 | PCM 策略 DSL 的基本语法（deny 规则 + 内置谓词） |
| 3 | Allow 请求如何生成 Certificate（推导树证书） |
| 4 | Deny 请求如何生成 Witness（可解释反例） |
| 5 | 编写、验证、编译自定义策略 |
| 6 | CLI 离线验证证书 |
| 7 | 审计日志查询 + 哈希链完整性验证 |

---

## 下一步

- 📖 **[策略 DSL 完整参考](POLICY_DSL_REFERENCE.md)** — 了解所有内置谓词、类型系统和高级模式
- 📐 **[总体设计文档](DESIGN.md)** — 深入理解系统架构、安全模型和 Lean 形式化
- 🔬 **Lean 形式化** — 阅读 `lean/src/PCM/` 下的 Spec / Cert / Proofs
- 🚀 **生产部署** — 参考 `deploy/k8s/` 下的 K8s 网络策略和 Helm Chart
- 🧪 **策略差分分析** — 使用 `pcm-cli diff` 比较两个策略版本的安全影响

---

## 常见问题

### Q: 服务启动失败怎么办？

```bash
# 查看日志
docker compose logs -f monitor-gateway

# 确认 PostgreSQL 已就绪
docker compose logs postgres
```

### Q: grpcurl 不可用？

可以使用 Docker Compose 内置的冒烟测试脚本：

```bash
# Linux/macOS
bash scripts/smoke-test.sh

# Windows
powershell scripts/smoke-test.ps1
```

### Q: 如何重置环境？

```bash
docker compose down -v  # -v 会删除数据卷（PostgreSQL 数据）
docker compose up --build -d
```
