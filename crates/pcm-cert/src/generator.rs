//! 证书与反例生成器
//!
//! 从 Datalog 评估器的推导追踪中构建结构化的 `Certificate`，
//! 可序列化为二进制 wire format 或转换为 proto 消息。

use pcm_common::error::PcmError;
use pcm_datalog_engine::engine::{DerivationTrace, EvalResult};
use pcm_policy_dsl::ast::{Atom, Literal, Rule, Term};
use serde::{Deserialize, Serialize};

// ──────────────────────────────────────────────
// 数据结构
// ──────────────────────────────────────────────

/// 内部证书表示（可在 Rust 内直接操作）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateData {
    pub steps: Vec<CertStep>,
    pub policy_hash: [u8; 32],
    pub graph_hash: [u8; 32],
    pub request_hash: [u8; 32],
}

/// 推导步骤
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertStep {
    pub rule_index: u32,
    /// 前提在 steps + base_facts 中的全局索引
    pub premise_indices: Vec<u32>,
    /// 结论原子的结构化序列化
    pub conclusion: SerializedAtom,
}

/// 原子的可序列化表示
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializedAtom {
    /// 谓词名称: "action", "has_role", "deny" 等
    pub predicate: String,
    /// 参数值列表（常量）
    pub args: Vec<String>,
}

/// Deny Witness 数据
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessData {
    /// 触发 deny 的规则索引
    pub deny_rule_index: u32,
    /// 规则 ID（如 "R1: unauthorized_http"）
    pub deny_rule_id: String,
    /// 人可读的拒绝原因
    pub human_readable_reason: String,
    /// 匹配到的事实列表
    pub matched_facts: Vec<SerializedAtom>,
    /// 违规图路径（如果规则涉及 graph_edge/graph_label）
    pub violation_paths: Vec<ViolationPath>,
    /// 策略哈希
    pub policy_hash: [u8; 32],
    /// 请求哈希
    pub request_hash: [u8; 32],
}

/// 违规路径
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViolationPath {
    /// 路径描述（如 "data_flow: node_A → node_B"）
    pub description: String,
    /// 路径上的边列表
    pub edges: Vec<(String, String, String)>, // (src, dst, edge_kind)
}

// ──────────────────────────────────────────────
// Atom 序列化
// ──────────────────────────────────────────────

/// 将 Term 转为字符串，仅接受 Const。
/// 证书中不应有未绑定变量。
fn term_to_string(t: &Term) -> String {
    match t {
        Term::Const(s) => s.clone(),
        Term::Var(v) => panic!("证书中不应有未绑定变量: {}", v),
    }
}

/// 将 ground Atom 转为 SerializedAtom
pub fn serialize_atom(atom: &Atom) -> SerializedAtom {
    match atom {
        Atom::Action {
            id,
            action_type,
            principal,
            target,
        } => SerializedAtom {
            predicate: "action".to_string(),
            args: vec![
                term_to_string(id),
                term_to_string(action_type),
                term_to_string(principal),
                term_to_string(target),
            ],
        },
        Atom::DataLabel { data, label } => SerializedAtom {
            predicate: "data_label".to_string(),
            args: vec![term_to_string(data), term_to_string(label)],
        },
        Atom::HasRole { principal, role } => SerializedAtom {
            predicate: "has_role".to_string(),
            args: vec![term_to_string(principal), term_to_string(role)],
        },
        Atom::GraphEdge { src, dst, kind } => SerializedAtom {
            predicate: "graph_edge".to_string(),
            args: vec![
                term_to_string(src),
                term_to_string(dst),
                term_to_string(kind),
            ],
        },
        Atom::GraphLabel { node, label } => SerializedAtom {
            predicate: "graph_label".to_string(),
            args: vec![term_to_string(node), term_to_string(label)],
        },
        Atom::Precedes { before, after } => SerializedAtom {
            predicate: "precedes".to_string(),
            args: vec![term_to_string(before), term_to_string(after)],
        },
        Atom::Deny { request, reason } => SerializedAtom {
            predicate: "deny".to_string(),
            args: vec![term_to_string(request), term_to_string(reason)],
        },
    }
}

// ──────────────────────────────────────────────
// 证书生成
// ──────────────────────────────────────────────

/// 从评估结果生成 Allow 证书。
///
/// 只为 Allow 决策生成证书；如果 `eval.has_deny` 为 true 则返回错误。
pub fn generate_certificate(
    eval: &EvalResult,
    rules: &[Rule],
    policy_hash: [u8; 32],
    graph_hash: [u8; 32],
    request_hash: [u8; 32],
) -> Result<CertificateData, PcmError> {
    // 1. 断言：只为 Allow 决策生成证书
    if eval.has_deny {
        return Err(PcmError::CertVerification(
            "cannot generate allow certificate for a deny evaluation".to_string(),
        ));
    }

    // 2. 转换推导追踪
    let num_base_facts = eval.facts.len();
    let steps: Vec<CertStep> = eval
        .trace
        .iter()
        .map(|t| {
            // 验证 rule_index 合法性
            if t.rule_index >= rules.len() {
                return Err(PcmError::CertVerification(format!(
                    "rule_index {} out of bounds (total rules: {})",
                    t.rule_index,
                    rules.len()
                )));
            }

            let premise_indices: Vec<u32> =
                t.premises.iter().map(|&idx| idx as u32).collect();

            let conclusion = serialize_atom(&t.conclusion);

            Ok(CertStep {
                rule_index: t.rule_index as u32,
                premise_indices,
                conclusion,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    // 3. 验证完整性：每个 step 的 premise_indices 指向有效的基础事实或前序 step
    let total_bound = num_base_facts + steps.len();
    for (i, step) in steps.iter().enumerate() {
        for &pidx in &step.premise_indices {
            let pidx_usize = pidx as usize;
            // premise 可以指向基础事实 [0, num_base_facts) 或前序步骤结论 [num_base_facts, num_base_facts + i)
            if pidx_usize >= num_base_facts + i && pidx_usize < total_bound {
                return Err(PcmError::CertVerification(format!(
                    "step {} has premise_index {} that refers to a non-preceding step",
                    i, pidx
                )));
            }
            if pidx_usize >= total_bound {
                return Err(PcmError::CertVerification(format!(
                    "step {} has premise_index {} out of bounds (total: {})",
                    i, pidx, total_bound
                )));
            }
        }
    }

    Ok(CertificateData {
        steps,
        policy_hash,
        graph_hash,
        request_hash,
    })
}

// ──────────────────────────────────────────────
// Proto 互转
// ──────────────────────────────────────────────

impl CertificateData {
    /// 转为 proto 消息（用于 gRPC 传输）
    pub fn to_proto(&self) -> pcm_common::proto::pcm_v1::Certificate {
        let steps = self
            .steps
            .iter()
            .map(|s| pcm_common::proto::pcm_v1::DerivationStep {
                rule_index: s.rule_index,
                premise_indices: s.premise_indices.clone(),
                conclusion: serde_json::to_string(&s.conclusion)
                    .unwrap_or_default(),
            })
            .collect();

        pcm_common::proto::pcm_v1::Certificate {
            steps,
            policy_hash: self.policy_hash.to_vec(),
            graph_hash: self.graph_hash.to_vec(),
            request_hash: self.request_hash.to_vec(),
        }
    }

    /// 从 proto 消息还原
    pub fn from_proto(
        proto: &pcm_common::proto::pcm_v1::Certificate,
    ) -> Result<Self, PcmError> {
        let steps = proto
            .steps
            .iter()
            .map(|s| {
                let conclusion: SerializedAtom =
                    serde_json::from_str(&s.conclusion).map_err(|e| {
                        PcmError::CertVerification(format!(
                            "failed to deserialize conclusion: {}",
                            e
                        ))
                    })?;
                Ok(CertStep {
                    rule_index: s.rule_index,
                    premise_indices: s.premise_indices.clone(),
                    conclusion,
                })
            })
            .collect::<Result<Vec<_>, PcmError>>()?;

        let policy_hash = try_into_hash(&proto.policy_hash, "policy_hash")?;
        let graph_hash = try_into_hash(&proto.graph_hash, "graph_hash")?;
        let request_hash = try_into_hash(&proto.request_hash, "request_hash")?;

        Ok(CertificateData {
            steps,
            policy_hash,
            graph_hash,
            request_hash,
        })
    }
}

/// 将 Vec<u8> 转为 [u8; 32]，长度不匹配则报错
fn try_into_hash(bytes: &[u8], field: &str) -> Result<[u8; 32], PcmError> {
    bytes.try_into().map_err(|_| {
        PcmError::CertVerification(format!(
            "{} has invalid length: expected 32, got {}",
            field,
            bytes.len()
        ))
    })
}

// ──────────────────────────────────────────────
// Witness 生成
// ──────────────────────────────────────────────

/// 从评估结果生成 Deny Witness（取第一个 deny 原因）。
///
/// 只为 Deny 决策生成 witness；如果 `eval.has_deny` 为 false 则返回错误。
pub fn generate_witness(
    eval: &EvalResult,
    rules: &[Rule],
    policy_hash: [u8; 32],
    request_hash: [u8; 32],
) -> Result<WitnessData, PcmError> {
    if !eval.has_deny {
        return Err(PcmError::CertVerification(
            "cannot generate witness for a non-deny evaluation".to_string(),
        ));
    }
    if eval.deny_reasons.is_empty() {
        return Err(PcmError::CertVerification(
            "deny evaluation has no deny reasons".to_string(),
        ));
    }

    let (request_id, reason) = &eval.deny_reasons[0];
    generate_witness_for_reason(eval, rules, request_id, reason, policy_hash, request_hash)
}

/// 为所有 deny 原因生成 Witness 列表
pub fn generate_all_witnesses(
    eval: &EvalResult,
    rules: &[Rule],
    policy_hash: [u8; 32],
    request_hash: [u8; 32],
) -> Result<Vec<WitnessData>, PcmError> {
    if !eval.has_deny {
        return Err(PcmError::CertVerification(
            "cannot generate witnesses for a non-deny evaluation".to_string(),
        ));
    }

    eval.deny_reasons
        .iter()
        .map(|(request_id, reason)| {
            generate_witness_for_reason(eval, rules, request_id, reason, policy_hash, request_hash)
        })
        .collect()
}

/// 为单个 deny 原因生成 Witness
fn generate_witness_for_reason(
    eval: &EvalResult,
    rules: &[Rule],
    request_id: &str,
    reason: &str,
    policy_hash: [u8; 32],
    request_hash: [u8; 32],
) -> Result<WitnessData, PcmError> {
    let num_base_facts = eval.facts.len();

    // 在 trace 中查找匹配的 deny 推导步骤
    let deny_trace = eval.trace.iter().find(|t| {
        matches!(
            &t.conclusion,
            Atom::Deny { request, reason: r }
                if matches!(request, Term::Const(rid) if rid == request_id)
                && matches!(r, Term::Const(rr) if rr == reason)
        )
    });

    let (deny_rule_index, matched_facts, violation_paths, rule_for_format) =
        if let Some(trace_step) = deny_trace {
            let rule_idx = trace_step.rule_index;

            // 递归收集基础事实
            let base_fact_indices =
                collect_base_facts(trace_step, &eval.trace, num_base_facts);
            let matched: Vec<SerializedAtom> = base_fact_indices
                .iter()
                .filter_map(|&idx| eval.facts.get(idx).map(serialize_atom))
                .collect();

            // 构建违规路径
            let paths = build_violation_paths(rules.get(rule_idx), &matched);

            let rule_ref = rules.get(rule_idx);
            (rule_idx as u32, matched, paths, rule_ref)
        } else {
            // 没有找到匹配的 trace 步骤, 使用所有事实
            let matched: Vec<SerializedAtom> = eval.facts.iter().map(serialize_atom).collect();
            (0u32, matched, vec![], None)
        };

    let deny_rule_id = format!("R{}: {}", deny_rule_index, reason);
    let human_readable_reason = format_deny_reason(rule_for_format, &matched_facts, reason);

    Ok(WitnessData {
        deny_rule_index,
        deny_rule_id,
        human_readable_reason,
        matched_facts,
        violation_paths,
        policy_hash,
        request_hash,
    })
}

/// 递归收集推导步骤引用的基础事实索引
fn collect_base_facts(
    step: &DerivationTrace,
    all_traces: &[DerivationTrace],
    num_base_facts: usize,
) -> Vec<usize> {
    let mut result = Vec::new();
    let mut visited = std::collections::HashSet::new();
    collect_base_facts_recursive(step, all_traces, num_base_facts, &mut result, &mut visited);
    result
}

fn collect_base_facts_recursive(
    step: &DerivationTrace,
    all_traces: &[DerivationTrace],
    num_base_facts: usize,
    result: &mut Vec<usize>,
    visited: &mut std::collections::HashSet<usize>,
) {
    for &premise_idx in &step.premises {
        if premise_idx < num_base_facts {
            if visited.insert(premise_idx) {
                result.push(premise_idx);
            }
        } else {
            let trace_idx = premise_idx - num_base_facts;
            if trace_idx < all_traces.len() && visited.insert(premise_idx) {
                collect_base_facts_recursive(
                    &all_traces[trace_idx],
                    all_traces,
                    num_base_facts,
                    result,
                    visited,
                );
            }
        }
    }
}

/// 从规则和匹配事实构建违规路径
fn build_violation_paths(
    rule: Option<&Rule>,
    matched_facts: &[SerializedAtom],
) -> Vec<ViolationPath> {
    let rule = match rule {
        Some(r) => r,
        None => return vec![],
    };

    // 检查规则体中是否含有 graph_edge / graph_label
    let has_graph = rule.body.iter().any(|lit| {
        let atom = match lit {
            Literal::Pos(a) => a,
            Literal::Neg(a) => a,
        };
        matches!(atom, Atom::GraphEdge { .. } | Atom::GraphLabel { .. })
    });

    if !has_graph {
        return vec![];
    }

    // 从匹配的事实中提取 graph_edge 事实
    let graph_edges: Vec<&SerializedAtom> = matched_facts
        .iter()
        .filter(|f| f.predicate == "graph_edge")
        .collect();

    if graph_edges.is_empty() {
        return vec![];
    }

    let edges: Vec<(String, String, String)> = graph_edges
        .iter()
        .map(|e| {
            let src = e.args.first().cloned().unwrap_or_default();
            let dst = e.args.get(1).cloned().unwrap_or_default();
            let kind = e.args.get(2).cloned().unwrap_or_default();
            (src, dst, kind)
        })
        .collect();

    let description = edges
        .iter()
        .map(|(src, dst, kind)| format!("{}: {} → {}", kind, src, dst))
        .collect::<Vec<_>>()
        .join(", ");

    vec![ViolationPath { description, edges }]
}

// ──────────────────────────────────────────────
// 人可读原因生成
// ──────────────────────────────────────────────

/// 根据 deny 规则的结构生成解释性文本
fn format_deny_reason(
    rule: Option<&Rule>,
    matched_facts: &[SerializedAtom],
    deny_reason: &str,
) -> String {
    let mut lines = Vec::new();
    lines.push(format!("请求被拒绝: {}", deny_reason));

    if let Some(rule) = rule {
        lines.push(format!("触发规则: {}", format_rule(rule)));

        let mut positive_matches = Vec::new();
        let mut negative_conditions = Vec::new();

        for lit in &rule.body {
            match lit {
                Literal::Pos(atom) => {
                    let pred = atom_predicate(atom);
                    for fact in matched_facts {
                        if fact.predicate == pred {
                            positive_matches
                                .push(format!("  - {}", format_serialized_atom(fact)));
                        }
                    }
                }
                Literal::Neg(atom) => {
                    negative_conditions.push(format!(
                        "  - {} [不存在]",
                        format_atom_pattern(atom)
                    ));
                }
            }
        }

        positive_matches.dedup();
        negative_conditions.dedup();

        if !positive_matches.is_empty() {
            lines.push("匹配事实:".to_string());
            lines.extend(positive_matches);
        }

        if !negative_conditions.is_empty() {
            lines.push("缺失条件:".to_string());
            lines.extend(negative_conditions);
        }
    }

    lines.join("\n")
}

/// 格式化规则为字符串
fn format_rule(rule: &Rule) -> String {
    let head = format_atom_pattern(&rule.head);
    if rule.body.is_empty() {
        return head;
    }
    let body = rule
        .body
        .iter()
        .map(|lit| match lit {
            Literal::Pos(a) => format_atom_pattern(a),
            Literal::Neg(a) => format!("!{}", format_atom_pattern(a)),
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!("{} :- {}", head, body)
}

/// 格式化 Atom 模式（可含变量）
fn format_atom_pattern(atom: &Atom) -> String {
    let (pred, args) = match atom {
        Atom::Action {
            id,
            action_type,
            principal,
            target,
        } => (
            "action",
            vec![
                format_term(id),
                format_term(action_type),
                format_term(principal),
                format_term(target),
            ],
        ),
        Atom::DataLabel { data, label } => (
            "data_label",
            vec![format_term(data), format_term(label)],
        ),
        Atom::HasRole { principal, role } => (
            "has_role",
            vec![format_term(principal), format_term(role)],
        ),
        Atom::GraphEdge { src, dst, kind } => (
            "graph_edge",
            vec![format_term(src), format_term(dst), format_term(kind)],
        ),
        Atom::GraphLabel { node, label } => (
            "graph_label",
            vec![format_term(node), format_term(label)],
        ),
        Atom::Precedes { before, after } => (
            "precedes",
            vec![format_term(before), format_term(after)],
        ),
        Atom::Deny { request, reason } => (
            "deny",
            vec![format_term(request), format_term(reason)],
        ),
    };
    format!("{}({})", pred, args.join(", "))
}

fn format_term(t: &Term) -> String {
    match t {
        Term::Const(s) => format!("\"{}\"", s),
        Term::Var(v) => v.clone(),
    }
}

/// 获取 Atom 的谓词名
fn atom_predicate(atom: &Atom) -> &str {
    match atom {
        Atom::Action { .. } => "action",
        Atom::DataLabel { .. } => "data_label",
        Atom::HasRole { .. } => "has_role",
        Atom::GraphEdge { .. } => "graph_edge",
        Atom::GraphLabel { .. } => "graph_label",
        Atom::Precedes { .. } => "precedes",
        Atom::Deny { .. } => "deny",
    }
}

/// 格式化 SerializedAtom（已序列化版本）
fn format_serialized_atom(atom: &SerializedAtom) -> String {
    let args = atom
        .args
        .iter()
        .map(|a| format!("\"{}\"", a))
        .collect::<Vec<_>>()
        .join(", ");
    format!("{}({})", atom.predicate, args)
}

// ──────────────────────────────────────────────
// Witness Proto 互转
// ──────────────────────────────────────────────

impl WitnessData {
    /// 转为 proto 消息（用于 gRPC 传输）
    pub fn to_proto(&self) -> pcm_common::proto::pcm_v1::Witness {
        let matched_facts = self
            .matched_facts
            .iter()
            .map(|f| serde_json::to_string(f).unwrap_or_default())
            .collect();

        let violation_paths = self
            .violation_paths
            .iter()
            .map(|p| {
                let mut node_ids = vec![p.description.clone()];
                for (src, dst, kind) in &p.edges {
                    node_ids.push(format!("{}|{}|{}", src, dst, kind));
                }
                pcm_common::proto::pcm_v1::GraphPath { node_ids }
            })
            .collect();

        pcm_common::proto::pcm_v1::Witness {
            deny_rule_id: self.deny_rule_id.clone(),
            human_readable_reason: self.human_readable_reason.clone(),
            matched_facts,
            violation_paths,
            policy_hash: self.policy_hash.to_vec(),
            request_hash: self.request_hash.to_vec(),
        }
    }

    /// 从 proto 消息还原
    pub fn from_proto(
        proto: &pcm_common::proto::pcm_v1::Witness,
    ) -> Result<Self, PcmError> {
        let matched_facts = proto
            .matched_facts
            .iter()
            .map(|s| {
                serde_json::from_str(s).map_err(|e| {
                    PcmError::CertVerification(format!(
                        "failed to deserialize matched fact: {}",
                        e
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let violation_paths = proto
            .violation_paths
            .iter()
            .map(|gp| {
                let description = gp.node_ids.first().cloned().unwrap_or_default();
                let edges = gp.node_ids[1..]
                    .iter()
                    .map(|s| {
                        let parts: Vec<&str> = s.splitn(3, '|').collect();
                        (
                            parts.first().unwrap_or(&"").to_string(),
                            parts.get(1).unwrap_or(&"").to_string(),
                            parts.get(2).unwrap_or(&"").to_string(),
                        )
                    })
                    .collect();
                ViolationPath { description, edges }
            })
            .collect();

        let policy_hash = try_into_hash(&proto.policy_hash, "policy_hash")?;
        let request_hash = try_into_hash(&proto.request_hash, "request_hash")?;

        // 从 deny_rule_id 解析 deny_rule_index（格式: "R{index}: {reason}"）
        let deny_rule_index = proto
            .deny_rule_id
            .strip_prefix('R')
            .and_then(|s| s.split(':').next())
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);

        Ok(WitnessData {
            deny_rule_index,
            deny_rule_id: proto.deny_rule_id.clone(),
            human_readable_reason: proto.human_readable_reason.clone(),
            matched_facts,
            violation_paths,
            policy_hash,
            request_hash,
        })
    }
}

// ──────────────────────────────────────────────
// 测试
// ──────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use pcm_datalog_engine::engine::{DerivationTrace, EvalResult};
    use pcm_policy_dsl::ast::{Atom, Literal, Rule, Term};

    fn c(s: &str) -> Term {
        Term::Const(s.to_string())
    }

    fn v(s: &str) -> Term {
        Term::Var(s.to_string())
    }

    fn make_eval(
        facts: Vec<Atom>,
        trace: Vec<DerivationTrace>,
        has_deny: bool,
        deny_reasons: Vec<(String, String)>,
    ) -> EvalResult {
        EvalResult {
            facts,
            trace,
            has_deny,
            deny_reasons,
        }
    }

    fn dummy_rules(n: usize) -> Vec<Rule> {
        (0..n)
            .map(|_| Rule {
                head: Atom::HasRole {
                    principal: c("x"),
                    role: c("r"),
                },
                body: vec![],
            })
            .collect()
    }

    fn zero_hash() -> [u8; 32] {
        [0u8; 32]
    }

    // ══════════════════════════════════════════
    // Certificate 测试（保留原有）
    // ══════════════════════════════════════════

    #[test]
    fn test_generate_empty_trace() {
        let eval = make_eval(vec![], vec![], false, vec![]);
        let rules = dummy_rules(0);
        let cert =
            generate_certificate(&eval, &rules, zero_hash(), zero_hash(), zero_hash()).unwrap();
        assert!(cert.steps.is_empty());
        assert_eq!(cert.policy_hash, zero_hash());
        assert_eq!(cert.graph_hash, zero_hash());
        assert_eq!(cert.request_hash, zero_hash());
    }

    #[test]
    fn test_generate_single_step() {
        let conclusion = Atom::HasRole {
            principal: c("alice"),
            role: c("admin"),
        };
        let trace = vec![DerivationTrace {
            rule_index: 0,
            premises: vec![],
            conclusion: conclusion.clone(),
        }];
        let eval = make_eval(vec![], trace, false, vec![]);
        let rules = dummy_rules(1);

        let cert =
            generate_certificate(&eval, &rules, zero_hash(), zero_hash(), zero_hash()).unwrap();

        assert_eq!(cert.steps.len(), 1);
        assert_eq!(cert.steps[0].rule_index, 0);
        assert_eq!(cert.steps[0].conclusion.predicate, "has_role");
        assert_eq!(
            cert.steps[0].conclusion.args,
            vec!["alice".to_string(), "admin".to_string()]
        );
    }

    #[test]
    fn test_generate_multi_steps() {
        let base_fact = Atom::HasRole {
            principal: c("alice"),
            role: c("dev"),
        };
        let step0_conclusion = Atom::HasRole {
            principal: c("alice"),
            role: c("admin"),
        };
        let step1_conclusion = Atom::Action {
            id: c("req1"),
            action_type: c("tool_call"),
            principal: c("alice"),
            target: c("deploy"),
        };

        let trace = vec![
            DerivationTrace {
                rule_index: 0,
                premises: vec![0],
                conclusion: step0_conclusion.clone(),
            },
            DerivationTrace {
                rule_index: 1,
                premises: vec![0, 1],
                conclusion: step1_conclusion.clone(),
            },
        ];
        let eval = make_eval(vec![base_fact], trace, false, vec![]);
        let rules = dummy_rules(2);

        let cert =
            generate_certificate(&eval, &rules, zero_hash(), zero_hash(), zero_hash()).unwrap();

        assert_eq!(cert.steps.len(), 2);
        assert_eq!(cert.steps[0].rule_index, 0);
        assert_eq!(cert.steps[0].premise_indices, vec![0]);
        assert_eq!(cert.steps[1].rule_index, 1);
        assert_eq!(cert.steps[1].premise_indices, vec![0, 1]);
        assert_eq!(cert.steps[1].conclusion.predicate, "action");
    }

    #[test]
    fn test_deny_eval_rejected_cert() {
        let eval = make_eval(
            vec![],
            vec![],
            true,
            vec![("req1".to_string(), "forbidden".to_string())],
        );
        let rules = dummy_rules(0);
        let result =
            generate_certificate(&eval, &rules, zero_hash(), zero_hash(), zero_hash());
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("deny"));
    }

    #[test]
    fn test_atom_serialization() {
        let atom = Atom::Action {
            id: c("r1"),
            action_type: c("tool_call"),
            principal: c("alice"),
            target: c("db"),
        };
        let sa = serialize_atom(&atom);
        assert_eq!(sa.predicate, "action");
        assert_eq!(sa.args, vec!["r1", "tool_call", "alice", "db"]);

        let atom = Atom::Deny {
            request: c("req1"),
            reason: c("policy_violation"),
        };
        let sa = serialize_atom(&atom);
        assert_eq!(sa.predicate, "deny");
        assert_eq!(sa.args, vec!["req1", "policy_violation"]);
    }

    #[test]
    fn test_cert_proto_roundtrip() {
        let cert = CertificateData {
            steps: vec![
                CertStep {
                    rule_index: 0,
                    premise_indices: vec![],
                    conclusion: SerializedAtom {
                        predicate: "has_role".to_string(),
                        args: vec!["alice".to_string(), "admin".to_string()],
                    },
                },
                CertStep {
                    rule_index: 1,
                    premise_indices: vec![0, 1],
                    conclusion: SerializedAtom {
                        predicate: "action".to_string(),
                        args: vec![
                            "r1".to_string(),
                            "tool_call".to_string(),
                            "alice".to_string(),
                            "db".to_string(),
                        ],
                    },
                },
            ],
            policy_hash: [1u8; 32],
            graph_hash: [2u8; 32],
            request_hash: [3u8; 32],
        };

        let proto = cert.to_proto();
        let restored = CertificateData::from_proto(&proto).unwrap();
        assert_eq!(cert, restored);
    }

    // ══════════════════════════════════════════
    // Witness 测试（M1-5）
    // ══════════════════════════════════════════

    /// 辅助：构建一条简单 deny 规则
    fn make_deny_rule_simple() -> Rule {
        Rule {
            head: Atom::Deny {
                request: v("Req"),
                reason: c("unauthorized_http"),
            },
            body: vec![Literal::Pos(Atom::Action {
                id: v("Req"),
                action_type: c("HttpOut"),
                principal: v("P"),
                target: v("_"),
            })],
        }
    }

    /// 辅助：构建含负文字的 deny 规则
    fn make_deny_rule_with_negation() -> Rule {
        Rule {
            head: Atom::Deny {
                request: v("Req"),
                reason: c("unauthorized_http"),
            },
            body: vec![
                Literal::Pos(Atom::Action {
                    id: v("Req"),
                    action_type: c("HttpOut"),
                    principal: v("P"),
                    target: v("_"),
                }),
                Literal::Neg(Atom::HasRole {
                    principal: v("P"),
                    role: c("http_allowed"),
                }),
            ],
        }
    }

    /// 辅助：构建含 graph 约束的 deny 规则
    fn make_deny_rule_graph() -> Rule {
        Rule {
            head: Atom::Deny {
                request: v("Req"),
                reason: c("data_leak"),
            },
            body: vec![
                Literal::Pos(Atom::Action {
                    id: v("Req"),
                    action_type: c("HttpOut"),
                    principal: v("P"),
                    target: v("T"),
                }),
                Literal::Pos(Atom::GraphEdge {
                    src: v("A"),
                    dst: v("B"),
                    kind: c("data_flow"),
                }),
                Literal::Pos(Atom::GraphLabel {
                    node: v("A"),
                    label: c("secret"),
                }),
            ],
        }
    }

    /// 辅助：构建含 precedes 约束的 deny 规则
    fn make_deny_rule_temporal() -> Rule {
        Rule {
            head: Atom::Deny {
                request: v("Req"),
                reason: c("missing_approval"),
            },
            body: vec![
                Literal::Pos(Atom::Action {
                    id: v("Req"),
                    action_type: c("DbWrite"),
                    principal: v("P"),
                    target: v("T"),
                }),
                Literal::Neg(Atom::Precedes {
                    before: c("approval"),
                    after: v("Req"),
                }),
            ],
        }
    }

    // ── test_generate_witness_simple ──

    #[test]
    fn test_generate_witness_simple() {
        let base_facts = vec![Atom::Action {
            id: c("req-1"),
            action_type: c("HttpOut"),
            principal: c("alice"),
            target: c("api.external.com"),
        }];
        let trace = vec![DerivationTrace {
            rule_index: 0,
            premises: vec![0],
            conclusion: Atom::Deny {
                request: c("req-1"),
                reason: c("unauthorized_http"),
            },
        }];
        let eval = make_eval(
            base_facts,
            trace,
            true,
            vec![("req-1".to_string(), "unauthorized_http".to_string())],
        );
        let rules = vec![make_deny_rule_simple()];

        let witness = generate_witness(&eval, &rules, zero_hash(), zero_hash()).unwrap();

        assert_eq!(witness.deny_rule_index, 0);
        assert!(witness.deny_rule_id.contains("unauthorized_http"));
        assert_eq!(witness.matched_facts.len(), 1);
        assert_eq!(witness.matched_facts[0].predicate, "action");
        assert_eq!(witness.matched_facts[0].args[0], "req-1");
        assert_eq!(witness.policy_hash, zero_hash());
        assert_eq!(witness.request_hash, zero_hash());
    }

    // ── test_generate_witness_with_negation ──

    #[test]
    fn test_generate_witness_with_negation() {
        let base_facts = vec![Atom::Action {
            id: c("req-1"),
            action_type: c("HttpOut"),
            principal: c("alice"),
            target: c("api.external.com"),
        }];
        let trace = vec![DerivationTrace {
            rule_index: 0,
            premises: vec![0],
            conclusion: Atom::Deny {
                request: c("req-1"),
                reason: c("unauthorized_http"),
            },
        }];
        let eval = make_eval(
            base_facts,
            trace,
            true,
            vec![("req-1".to_string(), "unauthorized_http".to_string())],
        );
        let rules = vec![make_deny_rule_with_negation()];

        let witness = generate_witness(&eval, &rules, zero_hash(), zero_hash()).unwrap();

        // 人可读原因应提到缺失的角色
        assert!(
            witness.human_readable_reason.contains("http_allowed"),
            "reason should mention missing role: {}",
            witness.human_readable_reason
        );
        assert!(
            witness.human_readable_reason.contains("不存在"),
            "reason should mention non-existence: {}",
            witness.human_readable_reason
        );
    }

    // ── test_generate_witness_graph_violation ──

    #[test]
    fn test_generate_witness_graph_violation() {
        let base_facts = vec![
            Atom::Action {
                id: c("req-1"),
                action_type: c("HttpOut"),
                principal: c("alice"),
                target: c("external"),
            },
            Atom::GraphEdge {
                src: c("node_A"),
                dst: c("node_B"),
                kind: c("data_flow"),
            },
            Atom::GraphLabel {
                node: c("node_A"),
                label: c("secret"),
            },
        ];
        let trace = vec![DerivationTrace {
            rule_index: 0,
            premises: vec![0, 1, 2],
            conclusion: Atom::Deny {
                request: c("req-1"),
                reason: c("data_leak"),
            },
        }];
        let eval = make_eval(
            base_facts,
            trace,
            true,
            vec![("req-1".to_string(), "data_leak".to_string())],
        );
        let rules = vec![make_deny_rule_graph()];

        let witness = generate_witness(&eval, &rules, zero_hash(), zero_hash()).unwrap();

        assert!(
            !witness.violation_paths.is_empty(),
            "should have violation paths for graph rules"
        );
        let path = &witness.violation_paths[0];
        assert!(
            path.description.contains("node_A"),
            "path description should mention node_A: {}",
            path.description
        );
        assert!(
            path.description.contains("node_B"),
            "path description should mention node_B: {}",
            path.description
        );
        assert_eq!(path.edges.len(), 1);
        assert_eq!(path.edges[0], ("node_A".to_string(), "node_B".to_string(), "data_flow".to_string()));
    }

    // ── test_generate_witness_temporal ──

    #[test]
    fn test_generate_witness_temporal() {
        let base_facts = vec![Atom::Action {
            id: c("req-1"),
            action_type: c("DbWrite"),
            principal: c("alice"),
            target: c("users_table"),
        }];
        let trace = vec![DerivationTrace {
            rule_index: 0,
            premises: vec![0],
            conclusion: Atom::Deny {
                request: c("req-1"),
                reason: c("missing_approval"),
            },
        }];
        let eval = make_eval(
            base_facts,
            trace,
            true,
            vec![("req-1".to_string(), "missing_approval".to_string())],
        );
        let rules = vec![make_deny_rule_temporal()];

        let witness = generate_witness(&eval, &rules, zero_hash(), zero_hash()).unwrap();

        // 人可读原因应提到缺少前置条件
        assert!(
            witness.human_readable_reason.contains("precedes"),
            "reason should mention precedes: {}",
            witness.human_readable_reason
        );
        assert!(
            witness.human_readable_reason.contains("不存在"),
            "reason should mention missing condition: {}",
            witness.human_readable_reason
        );
    }

    // ── test_generate_all_witnesses ──

    #[test]
    fn test_generate_all_witnesses() {
        let base_facts = vec![
            Atom::Action {
                id: c("req-1"),
                action_type: c("HttpOut"),
                principal: c("alice"),
                target: c("external"),
            },
            Atom::Action {
                id: c("req-2"),
                action_type: c("DbWrite"),
                principal: c("bob"),
                target: c("users_table"),
            },
        ];
        let trace = vec![
            DerivationTrace {
                rule_index: 0,
                premises: vec![0],
                conclusion: Atom::Deny {
                    request: c("req-1"),
                    reason: c("unauthorized_http"),
                },
            },
            DerivationTrace {
                rule_index: 1,
                premises: vec![1],
                conclusion: Atom::Deny {
                    request: c("req-2"),
                    reason: c("missing_approval"),
                },
            },
        ];
        let eval = make_eval(
            base_facts,
            trace,
            true,
            vec![
                ("req-1".to_string(), "unauthorized_http".to_string()),
                ("req-2".to_string(), "missing_approval".to_string()),
            ],
        );
        let rules = vec![make_deny_rule_with_negation(), make_deny_rule_temporal()];

        let witnesses =
            generate_all_witnesses(&eval, &rules, zero_hash(), zero_hash()).unwrap();

        assert_eq!(
            witnesses.len(),
            2,
            "should generate one witness per deny reason"
        );
        assert!(witnesses[0].deny_rule_id.contains("unauthorized_http"));
        assert!(witnesses[1].deny_rule_id.contains("missing_approval"));
    }

    // ── test_witness_human_readable ──

    #[test]
    #[ignore] // 手动运行以人工确认可读性
    fn test_witness_human_readable() {
        let base_facts = vec![Atom::Action {
            id: c("req-1"),
            action_type: c("HttpOut"),
            principal: c("alice"),
            target: c("api.external.com"),
        }];
        let trace = vec![DerivationTrace {
            rule_index: 0,
            premises: vec![0],
            conclusion: Atom::Deny {
                request: c("req-1"),
                reason: c("unauthorized_http"),
            },
        }];
        let eval = make_eval(
            base_facts,
            trace,
            true,
            vec![("req-1".to_string(), "unauthorized_http".to_string())],
        );
        let rules = vec![make_deny_rule_with_negation()];

        let witness = generate_witness(&eval, &rules, zero_hash(), zero_hash()).unwrap();
        println!("=== Human-Readable Witness ===");
        println!("{}", witness.human_readable_reason);
        println!("==============================");
    }

    // ── test_allow_eval_rejected ──

    #[test]
    fn test_allow_eval_rejected() {
        let eval = make_eval(vec![], vec![], false, vec![]);
        let rules = dummy_rules(0);
        let result = generate_witness(&eval, &rules, zero_hash(), zero_hash());
        assert!(
            result.is_err(),
            "generate_witness should fail for non-deny eval"
        );
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("non-deny"),
            "error should mention non-deny: {}",
            err_msg
        );
    }

    // ── test_witness_proto_roundtrip ──

    #[test]
    fn test_witness_proto_roundtrip() {
        let witness = WitnessData {
            deny_rule_index: 2,
            deny_rule_id: "R2: data_leak".to_string(),
            human_readable_reason: "请求被拒绝: data_leak".to_string(),
            matched_facts: vec![
                SerializedAtom {
                    predicate: "action".to_string(),
                    args: vec![
                        "req-1".to_string(),
                        "HttpOut".to_string(),
                        "alice".to_string(),
                        "external".to_string(),
                    ],
                },
                SerializedAtom {
                    predicate: "graph_edge".to_string(),
                    args: vec![
                        "node_A".to_string(),
                        "node_B".to_string(),
                        "data_flow".to_string(),
                    ],
                },
            ],
            violation_paths: vec![ViolationPath {
                description: "data_flow: node_A → node_B".to_string(),
                edges: vec![(
                    "node_A".to_string(),
                    "node_B".to_string(),
                    "data_flow".to_string(),
                )],
            }],
            policy_hash: [1u8; 32],
            request_hash: [3u8; 32],
        };

        let proto = witness.to_proto();
        let restored = WitnessData::from_proto(&proto).unwrap();
        assert_eq!(witness, restored);
    }
}
