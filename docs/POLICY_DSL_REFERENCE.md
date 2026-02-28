# PCM 策略 DSL 参考手册

> Proof-Carrying Monitor 策略语言完整参考

PCM 采用基于 **Datalog 子集**的策略 DSL，设计目标是保证**可判定性**（所有策略评估必定终止）和**可验证性**（评估结果附带可机检证书）。

---

## 目录

- [语法概览](#语法概览)
- [类型系统](#类型系统)
- [内置谓词](#内置谓词)
- [规则语法](#规则语法)
- [否定（! 前缀）](#否定-前缀)
- [变量与常量](#变量与常量)
- [通配符](#通配符)
- [编译产物](#编译产物)
- [完整示例](#完整示例)
- [常见模式](#常见模式)
- [错误消息指南](#错误消息指南)

---

## 语法概览

PCM 策略文件（`.pcm`）由零或多条**规则**组成。每条规则定义一个拒绝条件。

```ebnf
policy    ::= rule*
rule      ::= atom ':-' literal (',' literal)* '.'
literal   ::= atom | '!' atom
atom      ::= predicate '(' term (',' term)* ')'
term      ::= Variable | constant | string_literal | '_'
comment   ::= '//' <任意文本至行尾>
```

**核心原则**：

- 所有规则的头部（head）必须是 `deny` 谓词
- 无 deny 规则匹配 = **自动放行**（Allow）
- 支持**分层否定**（stratified negation），禁止否定递归

---

## 类型系统

### ActionType — 动作类型

| 值 | DSL 常量 | 说明 |
|---|---|---|
| 工具调用 | `tool_call` | Agent 调用工具 |
| HTTP 外发 | `http_out` | 发起 HTTP 请求 |
| 数据库写入 | `db_write` | 数据库写操作 |
| 敏感数据读取 | `db_read_sensitive` | 读取标记为敏感的数据 |
| 文件写入 | `file_write` | 文件系统写操作 |
| 文件读取 | `file_read` | 文件系统读操作 |
| 自定义 | `custom` | 自定义动作类型 |

对应 Proto 定义中的 `ActionType` 枚举。

### Label — 敏感标签

标签具有全序关系：`Public < Internal < Confidential < Secret`

| 值 | DSL 常量 | 说明 |
|---|---|---|
| 公开 | `Public` | 可公开访问的数据/端点 |
| 内部 | `Internal` | 仅内部可见 |
| 机密 | `Confidential` | 机密数据，需要授权 |
| 秘密 | `Secret` | 最高密级 |

### EdgeKind — 依赖图边类型

| 值 | DSL 常量 | 说明 |
|---|---|---|
| 数据流 | `data_flow` | 数据从 src 流向 dst |
| 控制流 | `control_flow` | 控制依赖关系 |
| 因果 | `causal` | 因果关系 |
| 时序 | `temporal` | 时间先后关系 |

---

## 内置谓词

PCM DSL 提供 7 个内置谓词，分为 4 类：

### 动作谓词

#### `action(Id, Type, Principal, Target)`

匹配当前待评估的动作请求。

| 参数 | 类型 | 说明 |
|------|------|------|
| `Id` | RequestId | 请求唯一标识符 |
| `Type` | ActionType | 动作类型（见上表） |
| `Principal` | String | 发起者身份标识 |
| `Target` | String | 目标资源 |

```prolog
// 匹配所有 HTTP 外发动作
action(Req, http_out, P, _)

// 匹配特定用户的数据库写入
action(Req, db_write, "admin_user", Target)
```

### 身份与角色谓词

#### `has_role(Principal, Role)`

检查发起者是否拥有指定角色。

| 参数 | 类型 | 说明 |
|------|------|------|
| `Principal` | String | 发起者身份标识 |
| `Role` | String | 角色名称 |

```prolog
// 检查用户是否有 http_allowed 角色
has_role(P, "http_allowed")

// 否定：检查用户是否 *没有* 某角色
!has_role(P, "audit_read")
```

### 数据标签谓词

#### `data_label(Data, Label)`

查询数据对象的敏感标签。

| 参数 | 类型 | 说明 |
|------|------|------|
| `Data` | String | 数据对象标识 |
| `Label` | Label | 敏感标签 |

```prolog
// 匹配标记为 Secret 的数据
data_label(Target, Secret)
```

### 图约束谓词

#### `graph_edge(Src, Dst, Kind)`

匹配依赖图中的边。

| 参数 | 类型 | 说明 |
|------|------|------|
| `Src` | NodeId | 源节点 |
| `Dst` | NodeId | 目标节点 |
| `Kind` | EdgeKind | 边类型 |

```prolog
// 匹配数据流边
graph_edge(DataNode, TargetNode, data_flow)

// 匹配控制流边
graph_edge(A, B, control_flow)
```

#### `graph_label(Node, Label)`

查询依赖图中节点的标签。

| 参数 | 类型 | 说明 |
|------|------|------|
| `Node` | NodeId | 节点标识 |
| `Label` | Label | 敏感标签 |

```prolog
// 匹配标记为 Confidential 的节点
graph_label(DataNode, Confidential)
```

### 时序谓词

#### `precedes(Before, After)`

检查时序关系——某个动作是否在另一个动作之前执行。

| 参数 | 类型 | 说明 |
|------|------|------|
| `Before` | RequestId | 应先执行的动作 |
| `After` | RequestId | 应后执行的动作 |

```prolog
// 检查 validate_action 是否在 Req 之前
precedes(validate_action, Req)

// 否定：检查 auth_check 是否 *未* 在 Req 之前执行
!precedes(auth_check, Req)
```

### 决策谓词

#### `deny(RequestId, Reason)`

声明拒绝决策。这是唯一允许出现在规则头部的谓词。

| 参数 | 类型 | 说明 |
|------|------|------|
| `RequestId` | RequestId | 被拒绝的请求 |
| `Reason` | String | 人类可读的拒绝原因 |

```prolog
// 规则头部：声明拒绝原因
deny(Req, "unauthorized_http") :- ...
```

---

## 规则语法

每条规则由**头部**（head）和**体部**（body）组成：

```
head :- body_literal_1, body_literal_2, ..., body_literal_n.
```

- **头部**必须是 `deny(RequestId, Reason)` 谓词
- **体部**由一个或多个文字（literal）组成，用逗号 `,` 分隔
- 规则以 `.` 结尾（句号）
- 体部中的**所有文字**必须同时满足（逻辑与 AND）

### 规则示例

```prolog
// 单条件规则
deny(Req, "no_tool_call") :-
    action(Req, tool_call, P, _),
    !has_role(P, "tool_user").

// 多条件规则（4 个条件的逻辑与）
deny(Req, "data_leak") :-
    action(Req, http_out, _, Target),
    graph_edge(Src, Target, data_flow),
    graph_label(Src, Confidential),
    graph_label(Target, Public).
```

### 安全性约束

编译器会验证以下安全性约束：

1. **头部限制**：规则头部必须是 `deny` 谓词
2. **范围限制**：头部中的所有变量必须在体部的某个**正文字**中出现
3. **否定安全性**：否定文字中的变量必须在同一规则体部的某个正文字中出现
4. **分层否定**：不允许否定递归（编译器通过 Tarjan SCC + 拓扑排序检测）

---

## 否定（! 前缀）

PCM DSL 支持**分层否定**（stratified negation），使用 `!` 前缀表示否定。

```prolog
// 正文字：has_role 为真时匹配
has_role(P, "admin")

// 否定文字：has_role 为假时匹配（即用户 *没有* 该角色）
!has_role(P, "admin")
```

### 否定的安全性要求

否定文字中的**每个变量**都必须在同一规则体部的某个正文字中**也出现**。这确保否定查询总是在有限域上进行。

```prolog
// ✅ 正确：P 在正文字 action(...) 中已绑定
deny(Req, "reason") :-
    action(Req, http_out, P, _),
    !has_role(P, "http_allowed").

// ❌ 错误：X 仅出现在否定文字中，未绑定
deny(Req, "reason") :-
    action(Req, http_out, _, _),
    !has_role(X, "http_allowed").
```

### 可否定的谓词

所有内置谓词都可以出现在否定中：

| 谓词 | 否定含义 |
|------|----------|
| `!has_role(P, R)` | P 没有角色 R |
| `!data_label(D, L)` | 数据 D 没有标签 L |
| `!graph_edge(S, D, K)` | 图中不存在 S→D 的 K 类型边 |
| `!graph_label(N, L)` | 节点 N 没有标签 L |
| `!precedes(A, B)` | 动作 A 没有在 B 之前执行 |

> ⚠️ `deny` 和 `action` 通常不在否定中使用。

---

## 变量与常量

### 变量

- **以大写字母开头**的标识符是变量
- 变量在规则作用域内绑定值
- 命名规范：使用有意义的名称（`Req`, `P`, `Target`, `Src`, `Dst`）

```prolog
// Req, P, Target 都是变量
deny(Req, "reason") :-
    action(Req, http_out, P, Target).
```

### 常量

常量有两种形式：

1. **标识符常量**：以小写字母开头（`http_out`, `data_flow`, `Confidential`）
2. **字符串常量**：用双引号括起（`"http_allowed"`, `"unauthorized_http"`）

```prolog
// http_out 是标识符常量
// "http_allowed" 是字符串常量
action(Req, http_out, P, _),
!has_role(P, "http_allowed").
```

### 内置常量

| 类别 | 常量 |
|------|------|
| ActionType | `tool_call`, `http_out`, `db_write`, `db_read_sensitive`, `file_write`, `file_read`, `custom` |
| Label | `Public`, `Internal`, `Confidential`, `Secret` |
| EdgeKind | `data_flow`, `control_flow`, `causal`, `temporal` |

---

## 通配符

使用 `_` 作为通配符，匹配任意值且不绑定变量。每个 `_` 是独立的——两个 `_` 不要求匹配相同的值。

```prolog
// 不关心 target 是什么
action(Req, http_out, P, _)

// 不关心 principal 和 target
action(Req, db_write, _, _)
```

---

## 编译产物

使用 `pcm-cli compile` 将 `.pcm` 文件编译为 JSON 格式的 `CompiledPolicy`：

```bash
cargo run -p pcm-cli -- compile --file policy.pcm --output compiled.json
```

### CompiledPolicy 结构

```json
{
  "rules": [
    {
      "head": { "Deny": { "request": { "Var": "Req" }, "reason": { "Const": "unauthorized_http" } } },
      "body": [
        { "Pos": { "Action": { "id": { "Var": "Req" }, "action_type": { "Const": "http_out" }, "principal": { "Var": "P" }, "target": { "Const": "_" } } } },
        { "Neg": { "HasRole": { "principal": { "Var": "P" }, "role": { "Const": "http_allowed" } } } }
      ]
    }
  ],
  "strata": [ [0] ],
  "fact_schema": {
    "action": 4,
    "has_role": 2,
    "deny": 2
  },
  "content_hash": "a3f2e1d4...",
  "version": "1.0.0",
  "decidable": true
}
```

| 字段 | 说明 |
|------|------|
| `rules` | 索引化的规则列表 |
| `strata` | 分层信息（保证无递归否定） |
| `fact_schema` | 每个谓词的参数数量 |
| `content_hash` | Blake3 内容哈希 |
| `version` | 策略版本号 |
| `decidable` | 可判定性验证结果（应始终为 `true`） |

### 编译器检查项

编译器在编译过程中执行以下检查：

| 检查 | 说明 | 错误级别 |
|------|------|----------|
| 头部限制 | 规则头部必须是 `deny` | Error |
| 范围限制 | 头部变量必须出现在正文字中 | Error |
| 否定安全性 | 否定文字的变量必须有正文字绑定 | Error |
| 否定递归 | 通过 SCC 检测循环否定 | Error |
| 单例变量 | 只出现一次的命名变量（应使用 `_`） | Warning |
| 冗余规则 | 可被其他规则完全包含的规则 | Warning |
| 矛盾文字 | 同一 atom 同时出现正/否定 | Warning |

---

## 完整示例

### 示例 1：默认最小策略

```prolog
// policies/default.pcm
// 最小安全策略 — 两条基础规则

// 禁止未授权的 HTTP 外发调用
deny(Req, "unauthorized_http") :-
    action(Req, http_out, P, _),
    !has_role(P, "http_allowed").

// 敏感数据读取需要 audit_read 角色
deny(Req, "sensitive_read_unauthorized") :-
    action(Req, db_read_sensitive, P, _),
    !has_role(P, "audit_read").
```

### 示例 2：信息流约束

```prolog
// 利用依赖图的信息流约束

// 机密数据不可通过数据流到达公开端点
deny(Req, "data_leak") :-
    action(Req, http_out, _, Target),
    graph_edge(Src, Target, data_flow),
    graph_label(Src, Confidential),
    graph_label(Target, Public).

// 秘密节点间不允许控制流到文件写入
deny(Req, "control_flow_violation") :-
    graph_edge(A, B, control_flow),
    graph_label(A, Secret),
    action(Req, file_write, _, B).
```

### 示例 3：时序约束

```prolog
// 使用 precedes 谓词的时序约束

// 写数据库前必须经过认证
deny(Req, "no_auth_before_write") :-
    action(Req, db_write, P, _),
    !precedes(auth_check, Req).

// 文件写入前必须经过验证步骤
deny(Req, "no_validation") :-
    action(Req, file_write, P, _),
    !precedes(validation_step, Req).
```

### 示例 4：综合策略（严格模式）

```prolog
// 严格安全策略 — 多维度防护

// R1: HTTP 外发需要授权角色
deny(Req, "no_http") :-
    action(Req, http_out, P, _),
    !has_role(P, "http_allowed").

// R2: 工具调用需要 tool_user 角色
deny(Req, "no_tool") :-
    action(Req, tool_call, P, _),
    !has_role(P, "tool_user").

// R3: 数据库写入需要 db_writer 角色
deny(Req, "no_db_write") :-
    action(Req, db_write, P, _),
    !has_role(P, "db_writer").

// R4: 敏感数据标签约束
deny(Req, "label_leak") :-
    action(Req, http_out, _, Target),
    data_label(Target, Secret).

// R5: 审计角色要求
deny(Req, "needs_audit") :-
    action(Req, db_read_sensitive, P, _),
    !has_role(P, "auditor").

// R6: 文件写入权限
deny(Req, "file_write_denied") :-
    action(Req, file_write, P, _),
    !has_role(P, "file_writer").

// R7: 信息流约束
deny(Req, "data_leak") :-
    action(Req, http_out, _, Target),
    graph_edge(Src, Target, data_flow),
    graph_label(Src, Confidential),
    graph_label(Target, Public).

// R8: 时序约束
deny(Req, "no_auth_before_write") :-
    action(Req, db_write, P, _),
    !precedes(auth_check, Req).
```

---

## 常见模式

### 模式 1：基于角色的访问控制（RBAC）

```prolog
// 为每种动作类型指定角色要求
deny(Req, "no_http") :-
    action(Req, http_out, P, _),
    !has_role(P, "http_allowed").

deny(Req, "no_tool") :-
    action(Req, tool_call, P, _),
    !has_role(P, "tool_user").
```

### 模式 2：最小权限原则

```prolog
// 敏感操作需要特定角色 + 时序验证
deny(Req, "sensitive_write_unauthorized") :-
    action(Req, db_write, P, _),
    !has_role(P, "db_writer").

deny(Req, "sensitive_write_no_auth") :-
    action(Req, db_write, P, _),
    !precedes(auth_check, Req).
```

### 模式 3：信息流隔离

```prolog
// 阻止高密级数据流向低密级端点
deny(Req, "secret_leak") :-
    action(Req, http_out, _, Target),
    graph_edge(Src, Target, data_flow),
    graph_label(Src, Secret),
    graph_label(Target, Public).

deny(Req, "confidential_leak") :-
    action(Req, http_out, _, Target),
    graph_edge(Src, Target, data_flow),
    graph_label(Src, Confidential),
    graph_label(Target, Public).
```

### 模式 4：操作前置条件

```prolog
// 确保关键操作前有必要的前置步骤
deny(Req, "no_validation_before_write") :-
    action(Req, db_write, _, _),
    !precedes(validate_action, Req).

deny(Req, "no_approval_before_deploy") :-
    action(Req, tool_call, _, _),
    !precedes(approval_action, Req).
```

---

## 错误消息指南

### 编译错误

| 错误信息 | 原因 | 修复方法 |
|----------|------|----------|
| `rule head must be 'deny'` | 规则头部使用了非 `deny` 谓词 | 将头部改为 `deny(Req, "reason")` |
| `unsafe variable in head` | 头部变量未在正文字中绑定 | 确保头部的每个变量都出现在某个正文字中 |
| `unsafe variable in negation` | 否定文字中有未绑定的变量 | 添加一个包含该变量的正文字 |
| `negative cycle detected` | 存在否定递归 | 重构规则，消除否定循环 |
| `unknown predicate` | 使用了未定义的谓词名 | 使用 7 个内置谓词之一 |
| `arity mismatch` | 谓词参数数量不正确 | 检查参数数量（如 `action` 需要 4 个参数） |

### 编译警告

| 警告信息 | 含义 | 建议 |
|----------|------|------|
| `singleton variable 'X'` | 变量 `X` 只出现一次 | 如果不需要绑定，使用 `_` 代替 |
| `redundant rule` | 某条规则完全被另一条包含 | 考虑删除冗余规则 |
| `contradictory literals` | 规则体中同一 atom 同时为正和否定 | 该规则永远不会匹配，考虑移除 |

### 运行时错误

| 错误 | 场景 | 说明 |
|------|------|------|
| `evaluation timeout` | 策略评估超时 | Fail-closed：默认 DENY + 告警 |
| `policy not found` | 未加载策略文件 | 检查 `PCM_POLICY_FILE` 环境变量 |
| `invalid certificate` | 证书验证失败 | 策略版本或图快照可能已变更 |

---

## 附录：Proto ActionType 枚举对照

```
ActionType 枚举值  →  DSL 常量
──────────────────────────────
0: UNSPECIFIED     →  (不使用)
1: TOOL_CALL       →  tool_call
2: HTTP_OUT        →  http_out
3: DB_WRITE        →  db_write
4: DB_READ_SENSITIVE → db_read_sensitive
5: FILE_WRITE      →  file_write
6: FILE_READ       →  file_read
15: CUSTOM         →  custom
```
