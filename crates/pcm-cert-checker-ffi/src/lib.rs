//! PCM Cert Checker FFI — Lean 抽取的证书验证器绑定
//!
//! 在 Lean 代码抽取完成前，本 crate 提供镜像 Rust 实现作为临时替代。
//! 最终将通过 C FFI 调用 Lean-extracted checker。
//!
//! 实现逻辑等价于 DESIGN.md §6.3.2 中的 Lean `checkCert` / `checkWitness`。

use std::collections::HashMap;
use std::time::Instant;

use pcm_cert::generator::{CertificateData, SerializedAtom, WitnessData};
use pcm_common::error::PcmError;
use pcm_common::hash::blake3_hash;
use pcm_policy_dsl::ast::{Atom, Literal, Rule, Term};

pub mod lean_checker;

// ──────────────────────────────────────────────
// 类型定义
// ──────────────────────────────────────────────

/// 变量替换映射
pub type Substitution = HashMap<String, String>;

/// 证书验证结果
#[derive(Debug, Clone)]
pub struct VerifyResult {
    pub valid: bool,
    pub error: Option<String>,
    /// 验证失败时的详细步骤索引
    pub failed_step: Option<usize>,
    /// 验证耗时（微秒）
    pub duration_us: u64,
}

impl VerifyResult {
    fn ok(duration_us: u64) -> Self {
        Self {
            valid: true,
            error: None,
            failed_step: None,
            duration_us,
        }
    }

    fn fail(error: impl Into<String>, duration_us: u64) -> Self {
        Self {
            valid: false,
            error: Some(error.into()),
            failed_step: None,
            duration_us,
        }
    }

    fn fail_at_step(error: impl Into<String>, step: usize, duration_us: u64) -> Self {
        Self {
            valid: false,
            error: Some(error.into()),
            failed_step: Some(step),
            duration_us,
        }
    }
}

// ──────────────────────────────────────────────
// 辅助函数
// ──────────────────────────────────────────────

/// 将 SerializedAtom 还原为 Atom
pub fn deserialize_atom(sa: &SerializedAtom) -> Result<Atom, PcmError> {
    let args = &sa.args;
    match sa.predicate.as_str() {
        "action" => {
            if args.len() != 4 {
                return Err(PcmError::CertVerification(format!(
                    "action atom expects 4 args, got {}",
                    args.len()
                )));
            }
            Ok(Atom::Action {
                id: Term::Const(args[0].clone()),
                action_type: Term::Const(args[1].clone()),
                principal: Term::Const(args[2].clone()),
                target: Term::Const(args[3].clone()),
            })
        }
        "data_label" => {
            if args.len() != 2 {
                return Err(PcmError::CertVerification(format!(
                    "data_label atom expects 2 args, got {}",
                    args.len()
                )));
            }
            Ok(Atom::DataLabel {
                data: Term::Const(args[0].clone()),
                label: Term::Const(args[1].clone()),
            })
        }
        "has_role" => {
            if args.len() != 2 {
                return Err(PcmError::CertVerification(format!(
                    "has_role atom expects 2 args, got {}",
                    args.len()
                )));
            }
            Ok(Atom::HasRole {
                principal: Term::Const(args[0].clone()),
                role: Term::Const(args[1].clone()),
            })
        }
        "graph_edge" => {
            if args.len() != 3 {
                return Err(PcmError::CertVerification(format!(
                    "graph_edge atom expects 3 args, got {}",
                    args.len()
                )));
            }
            Ok(Atom::GraphEdge {
                src: Term::Const(args[0].clone()),
                dst: Term::Const(args[1].clone()),
                kind: Term::Const(args[2].clone()),
            })
        }
        "graph_label" => {
            if args.len() != 2 {
                return Err(PcmError::CertVerification(format!(
                    "graph_label atom expects 2 args, got {}",
                    args.len()
                )));
            }
            Ok(Atom::GraphLabel {
                node: Term::Const(args[0].clone()),
                label: Term::Const(args[1].clone()),
            })
        }
        "precedes" => {
            if args.len() != 2 {
                return Err(PcmError::CertVerification(format!(
                    "precedes atom expects 2 args, got {}",
                    args.len()
                )));
            }
            Ok(Atom::Precedes {
                before: Term::Const(args[0].clone()),
                after: Term::Const(args[1].clone()),
            })
        }
        "deny" => {
            if args.len() != 2 {
                return Err(PcmError::CertVerification(format!(
                    "deny atom expects 2 args, got {}",
                    args.len()
                )));
            }
            Ok(Atom::Deny {
                request: Term::Const(args[0].clone()),
                reason: Term::Const(args[1].clone()),
            })
        }
        other => Err(PcmError::CertVerification(format!(
            "unknown predicate: {}",
            other
        ))),
    }
}

/// 从 rule head（可含变量）和 ground conclusion 推断替换 σ。
///
/// 返回 `Some(σ)` 当且仅当 `apply(σ, rule_head) == conclusion`。
pub fn find_substitution(rule_head: &Atom, conclusion: &Atom) -> Option<Substitution> {
    let mut subst = Substitution::new();

    /// 统一单个 Term 对：pattern（可含变量）vs ground（必须是常量）
    fn unify_term(pattern: &Term, ground: &Term, subst: &mut Substitution) -> bool {
        match (pattern, ground) {
            (Term::Var(v), Term::Const(c)) => {
                if v == "_" {
                    return true;
                }
                if let Some(existing) = subst.get(v) {
                    existing == c
                } else {
                    subst.insert(v.clone(), c.clone());
                    true
                }
            }
            (Term::Const(a), Term::Const(b)) => a == b,
            // ground 不应含变量；如果含变量则不匹配
            (Term::Var(_), Term::Var(_)) | (Term::Const(_), Term::Var(_)) => false,
        }
    }

    let ok = match (rule_head, conclusion) {
        (
            Atom::Action {
                id: id1,
                action_type: at1,
                principal: p1,
                target: t1,
            },
            Atom::Action {
                id: id2,
                action_type: at2,
                principal: p2,
                target: t2,
            },
        ) => {
            unify_term(id1, id2, &mut subst)
                && unify_term(at1, at2, &mut subst)
                && unify_term(p1, p2, &mut subst)
                && unify_term(t1, t2, &mut subst)
        }
        (
            Atom::DataLabel {
                data: d1,
                label: l1,
            },
            Atom::DataLabel {
                data: d2,
                label: l2,
            },
        ) => unify_term(d1, d2, &mut subst) && unify_term(l1, l2, &mut subst),
        (
            Atom::HasRole {
                principal: p1,
                role: r1,
            },
            Atom::HasRole {
                principal: p2,
                role: r2,
            },
        ) => unify_term(p1, p2, &mut subst) && unify_term(r1, r2, &mut subst),
        (
            Atom::GraphEdge {
                src: s1,
                dst: d1,
                kind: k1,
            },
            Atom::GraphEdge {
                src: s2,
                dst: d2,
                kind: k2,
            },
        ) => {
            unify_term(s1, s2, &mut subst)
                && unify_term(d1, d2, &mut subst)
                && unify_term(k1, k2, &mut subst)
        }
        (
            Atom::GraphLabel {
                node: n1,
                label: l1,
            },
            Atom::GraphLabel {
                node: n2,
                label: l2,
            },
        ) => unify_term(n1, n2, &mut subst) && unify_term(l1, l2, &mut subst),
        (
            Atom::Precedes {
                before: b1,
                after: a1,
            },
            Atom::Precedes {
                before: b2,
                after: a2,
            },
        ) => unify_term(b1, b2, &mut subst) && unify_term(a1, a2, &mut subst),
        (
            Atom::Deny {
                request: r1,
                reason: re1,
            },
            Atom::Deny {
                request: r2,
                reason: re2,
            },
        ) => unify_term(r1, r2, &mut subst) && unify_term(re1, re2, &mut subst),
        _ => false,
    };

    if ok { Some(subst) } else { None }
}

/// 将替换 σ 应用到 Atom，将变量替换为对应的常量
pub fn apply_substitution(atom: &Atom, subst: &Substitution) -> Atom {
    let sub = |t: &Term| -> Term {
        match t {
            Term::Var(v) if v != "_" => {
                if let Some(val) = subst.get(v) {
                    Term::Const(val.clone())
                } else {
                    t.clone()
                }
            }
            other => other.clone(),
        }
    };

    match atom {
        Atom::Action {
            id,
            action_type,
            principal,
            target,
        } => Atom::Action {
            id: sub(id),
            action_type: sub(action_type),
            principal: sub(principal),
            target: sub(target),
        },
        Atom::DataLabel { data, label } => Atom::DataLabel {
            data: sub(data),
            label: sub(label),
        },
        Atom::HasRole { principal, role } => Atom::HasRole {
            principal: sub(principal),
            role: sub(role),
        },
        Atom::GraphEdge { src, dst, kind } => Atom::GraphEdge {
            src: sub(src),
            dst: sub(dst),
            kind: sub(kind),
        },
        Atom::GraphLabel { node, label } => Atom::GraphLabel {
            node: sub(node),
            label: sub(label),
        },
        Atom::Precedes { before, after } => Atom::Precedes {
            before: sub(before),
            after: sub(after),
        },
        Atom::Deny { request, reason } => Atom::Deny {
            request: sub(request),
            reason: sub(reason),
        },
    }
}

/// 检查一个可能含变量的 atom pattern 是否能匹配一个 ground atom
pub fn atom_matches(pattern: &Atom, ground: &Atom) -> bool {
    find_substitution(pattern, ground).is_some()
}

/// 检测 Atom 是否为 Deny 变体
fn is_deny_atom(atom: &Atom) -> bool {
    matches!(atom, Atom::Deny { .. })
}

/// 序列化规则列表用于哈希
fn serialize_rules_for_hash(rules: &[Rule]) -> Vec<u8> {
    serde_json::to_vec(rules).unwrap_or_default()
}

/// 序列化 Atom 列表用于哈希
fn serialize_atoms_for_hash(atoms: &[Atom]) -> Vec<u8> {
    serde_json::to_vec(atoms).unwrap_or_default()
}

// ──────────────────────────────────────────────
// 高层 API：结构化类型
// ──────────────────────────────────────────────

/// 验证 Allow 证书（checkCert 的 Rust 镜像）
///
/// 实现 DESIGN.md §6.3.2 中的 `checkCert`：
/// 1. 哈希一致性检查
/// 2. 归纳验证每个推导步骤
/// 3. 最终检查无 deny 原子
/// 4. 验证不存在可被满足的 deny 规则
pub fn verify_certificate_structured(
    cert: &CertificateData,
    request_facts: &[Atom],
    rules: &[Rule],
    all_base_facts: &[Atom],
) -> VerifyResult {
    let start = Instant::now();

    // ── 1. 哈希一致性检查 ──
    let policy_bytes = serialize_rules_for_hash(rules);
    let expected_policy_hash = blake3_hash(&policy_bytes);
    if cert.policy_hash != expected_policy_hash {
        return VerifyResult::fail(
            "policy hash mismatch",
            start.elapsed().as_micros() as u64,
        );
    }

    let request_bytes = serialize_atoms_for_hash(request_facts);
    let expected_request_hash = blake3_hash(&request_bytes);
    if cert.request_hash != expected_request_hash {
        return VerifyResult::fail(
            "request hash mismatch",
            start.elapsed().as_micros() as u64,
        );
    }

    // graph_hash: 从 all_base_facts 中减去 request_facts 得到的 "graph+roles" 部分
    // 但实际中 graph_hash 在生成时基于单独传入的 graph facts，
    // 这里我们基于 all_base_facts 减 request_facts 来计算
    let graph_facts: Vec<&Atom> = all_base_facts
        .iter()
        .filter(|a| !request_facts.contains(a))
        .collect();
    let graph_bytes = serde_json::to_vec(&graph_facts).unwrap_or_default();
    let expected_graph_hash = blake3_hash(&graph_bytes);
    if cert.graph_hash != expected_graph_hash {
        return VerifyResult::fail(
            "graph hash mismatch",
            start.elapsed().as_micros() as u64,
        );
    }

    // ── 2. 归纳验证每个推导步骤 ──
    let mut derived: Vec<Atom> = all_base_facts.to_vec();

    for (step_idx, step) in cert.steps.iter().enumerate() {
        // 2a. rule_index 有效
        let rule_index = step.rule_index as usize;
        if rule_index >= rules.len() {
            return VerifyResult::fail_at_step(
                format!(
                    "step {}: rule_index {} out of bounds (total rules: {})",
                    step_idx,
                    rule_index,
                    rules.len()
                ),
                step_idx,
                start.elapsed().as_micros() as u64,
            );
        }
        let rule = &rules[rule_index];

        // 2b. 反序列化 conclusion
        let conclusion = match deserialize_atom(&step.conclusion) {
            Ok(a) => a,
            Err(e) => {
                return VerifyResult::fail_at_step(
                    format!("step {}: failed to deserialize conclusion: {}", step_idx, e),
                    step_idx,
                    start.elapsed().as_micros() as u64,
                );
            }
        };

        // 2c. conclusion 可以由 rule.head 通过某个替换 σ 得到
        let subst = match find_substitution(&rule.head, &conclusion) {
            Some(s) => s,
            None => {
                return VerifyResult::fail_at_step(
                    format!(
                        "step {}: conclusion {:?} does not unify with rule head {:?}",
                        step_idx, conclusion, rule.head
                    ),
                    step_idx,
                    start.elapsed().as_micros() as u64,
                );
            }
        };

        // 2d. 正文字：apply(σ, body_atom) 必须存在于 derived 中
        // 2e. 负文字：apply(σ, body_atom) 不在 derived 中
        for (lit_idx, lit) in rule.body.iter().enumerate() {
            match lit {
                Literal::Pos(body_atom) => {
                    let ground = apply_substitution(body_atom, &subst);
                    if !derived.contains(&ground) {
                        return VerifyResult::fail_at_step(
                            format!(
                                "step {}: positive literal {} not found in derived facts (ground: {:?})",
                                step_idx, lit_idx, ground
                            ),
                            step_idx,
                            start.elapsed().as_micros() as u64,
                        );
                    }
                }
                Literal::Neg(body_atom) => {
                    let ground = apply_substitution(body_atom, &subst);
                    if derived.contains(&ground) {
                        return VerifyResult::fail_at_step(
                            format!(
                                "step {}: negative literal {} found in derived facts (ground: {:?})",
                                step_idx, lit_idx, ground
                            ),
                            step_idx,
                            start.elapsed().as_micros() as u64,
                        );
                    }
                }
            }
        }

        // 2f. 验证通过 → 加入 derived
        derived.push(conclusion);
    }

    // ── 3. derived 中不含任何 Deny 原子 ──
    for atom in &derived {
        if is_deny_atom(atom) {
            return VerifyResult::fail(
                format!("derived facts contain deny atom: {:?}", atom),
                start.elapsed().as_micros() as u64,
            );
        }
    }

    // ── 4. 对策略中每条头部为 deny 的规则，验证规则体不被 derived 完全满足 ──
    //    即不存在某个替换 σ 使得规则体的所有文字都在 derived 中被满足
    for (rule_idx, rule) in rules.iter().enumerate() {
        if !is_deny_atom(&rule.head) {
            continue;
        }
        // 尝试找一个替换使得规则体完全满足
        if check_deny_rule_satisfiable(rule, &derived) {
            return VerifyResult::fail(
                format!(
                    "deny rule {} is fully satisfiable in derived facts, but no deny atom was derived",
                    rule_idx
                ),
                start.elapsed().as_micros() as u64,
            );
        }
    }

    VerifyResult::ok(start.elapsed().as_micros() as u64)
}

/// 检查一个 deny 规则是否在给定的事实集中可被完全满足
fn check_deny_rule_satisfiable(rule: &Rule, facts: &[Atom]) -> bool {
    let pos_lits: Vec<&Atom> = rule
        .body
        .iter()
        .filter_map(|l| {
            if let Literal::Pos(a) = l { Some(a) } else { None }
        })
        .collect();
    let neg_lits: Vec<&Atom> = rule
        .body
        .iter()
        .filter_map(|l| {
            if let Literal::Neg(a) = l { Some(a) } else { None }
        })
        .collect();

    // 尝试所有可能的替换组合
    let substitutions = find_all_substitutions(&pos_lits, facts);
    for subst in &substitutions {
        let neg_ok = neg_lits.iter().all(|neg_atom| {
            let ground = apply_substitution(neg_atom, subst);
            !facts.contains(&ground)
        });
        if neg_ok {
            return true; // 找到一个满足的替换
        }
    }
    false
}

/// 对正文字列表，在事实集中找出所有有效的 Substitution
fn find_all_substitutions(pos_lits: &[&Atom], facts: &[Atom]) -> Vec<Substitution> {
    if pos_lits.is_empty() {
        return vec![Substitution::new()];
    }

    let mut candidates: Vec<Substitution> = Vec::new();
    for fact in facts {
        if let Some(subst) = find_substitution(pos_lits[0], fact) {
            candidates.push(subst);
        }
    }

    for &lit in &pos_lits[1..] {
        let mut new_candidates = Vec::new();
        for subst in &candidates {
            for fact in facts {
                // 先 apply 当前 subst 到 lit，然后尝试统一
                let partially_ground = apply_substitution(lit, subst);
                if let Some(new_subst) = find_substitution(&partially_ground, fact) {
                    let mut merged = subst.clone();
                    // 合并新的绑定，检查一致性
                    let mut consistent = true;
                    for (k, v) in &new_subst {
                        if let Some(existing) = merged.get(k) {
                            if existing != v {
                                consistent = false;
                                break;
                            }
                        } else {
                            merged.insert(k.clone(), v.clone());
                        }
                    }
                    if consistent {
                        new_candidates.push(merged);
                    }
                }
            }
        }
        candidates = new_candidates;
    }

    candidates
}

/// 验证 Deny Witness（checkWitness 的 Rust 镜像）
///
/// 实现 DESIGN.md §6.3.2 中的 `checkWitness`：
/// 1. 哈希一致性检查
/// 2. 规则检查（deny_rule_index 有效，头部是 Deny）
/// 3. 事实匹配检查
pub fn verify_witness_structured(
    witness: &WitnessData,
    rules: &[Rule],
    all_base_facts: &[Atom],
) -> VerifyResult {
    let start = Instant::now();

    // ── 1. 哈希一致性检查 ──
    let policy_bytes = serialize_rules_for_hash(rules);
    let expected_policy_hash = blake3_hash(&policy_bytes);
    if witness.policy_hash != expected_policy_hash {
        return VerifyResult::fail(
            "witness policy hash mismatch",
            start.elapsed().as_micros() as u64,
        );
    }

    // request_hash: 从 all_base_facts 中过滤 Action 原子
    let request_facts: Vec<&Atom> = all_base_facts
        .iter()
        .filter(|a| matches!(a, Atom::Action { .. }))
        .collect();
    let request_bytes = serde_json::to_vec(&request_facts).unwrap_or_default();
    let expected_request_hash = blake3_hash(&request_bytes);
    if witness.request_hash != expected_request_hash {
        return VerifyResult::fail(
            "witness request hash mismatch",
            start.elapsed().as_micros() as u64,
        );
    }

    // ── 2. 规则检查 ──
    let rule_index = witness.deny_rule_index as usize;
    if rule_index >= rules.len() {
        return VerifyResult::fail(
            format!(
                "deny_rule_index {} out of bounds (total rules: {})",
                rule_index,
                rules.len()
            ),
            start.elapsed().as_micros() as u64,
        );
    }
    let rule = &rules[rule_index];

    // 规则头部必须是 Deny
    if !is_deny_atom(&rule.head) {
        return VerifyResult::fail(
            format!(
                "rule at index {} is not a deny rule (head: {:?})",
                rule_index, rule.head
            ),
            start.elapsed().as_micros() as u64,
        );
    }

    // ── 3. 事实匹配检查 ──
    // 反序列化 matched_facts
    let mut matched_atoms: Vec<Atom> = Vec::new();
    for (i, sa) in witness.matched_facts.iter().enumerate() {
        match deserialize_atom(sa) {
            Ok(a) => matched_atoms.push(a),
            Err(e) => {
                return VerifyResult::fail(
                    format!("failed to deserialize matched_fact {}: {}", i, e),
                    start.elapsed().as_micros() as u64,
                );
            }
        }
    }

    // matched_facts 必须是 all_base_facts 的子集
    for (i, atom) in matched_atoms.iter().enumerate() {
        if !all_base_facts.contains(atom) {
            return VerifyResult::fail(
                format!(
                    "matched_fact {} ({:?}) is not in base facts",
                    i, atom
                ),
                start.elapsed().as_micros() as u64,
            );
        }
    }

    // 规则体的每个文字都必须被满足：
    // - 正文字: 在 matched_facts 中能找到对应的 ground 原子
    // - 负文字: apply 后的 ground 原子不在 all_base_facts 中
    //
    // 要找一个替换 σ 使得规则体完全满足
    let pos_body: Vec<&Atom> = rule
        .body
        .iter()
        .filter_map(|l| {
            if let Literal::Pos(a) = l { Some(a) } else { None }
        })
        .collect();
    let neg_body: Vec<&Atom> = rule
        .body
        .iter()
        .filter_map(|l| {
            if let Literal::Neg(a) = l { Some(a) } else { None }
        })
        .collect();

    // 尝试在 matched_atoms 上找到满足所有正文字的替换
    let substitutions = find_all_substitutions(&pos_body, &matched_atoms);

    let mut found_valid_subst = false;
    for subst in &substitutions {
        // 检查负文字
        let neg_ok = neg_body.iter().all(|neg_atom| {
            let ground = apply_substitution(neg_atom, subst);
            !all_base_facts.contains(&ground)
        });
        if neg_ok {
            found_valid_subst = true;
            break;
        }
    }

    if !found_valid_subst {
        return VerifyResult::fail(
            "witness matched_facts do not satisfy the deny rule body",
            start.elapsed().as_micros() as u64,
        );
    }

    VerifyResult::ok(start.elapsed().as_micros() as u64)
}

// ──────────────────────────────────────────────
// 低层 API：从字节反序列化后调用高层 API
// ──────────────────────────────────────────────

/// 验证 Allow 证书（低层 API，保持 FFI 兼容签名）
///
/// TODO: 替换为 Lean FFI 调用
pub fn verify_certificate(
    cert_bytes: &[u8],
    request_bytes: &[u8],
    policy_bytes: &[u8],
    graph_bytes: &[u8],
) -> VerifyResult {
    let start = Instant::now();

    // 反序列化证书
    let cert: CertificateData = match serde_json::from_slice(cert_bytes) {
        Ok(c) => c,
        Err(e) => {
            return VerifyResult::fail(
                format!("failed to deserialize certificate: {}", e),
                start.elapsed().as_micros() as u64,
            );
        }
    };

    // 反序列化请求事实
    let request_facts: Vec<Atom> = match serde_json::from_slice(request_bytes) {
        Ok(f) => f,
        Err(e) => {
            return VerifyResult::fail(
                format!("failed to deserialize request facts: {}", e),
                start.elapsed().as_micros() as u64,
            );
        }
    };

    // 反序列化策略规则
    let rules: Vec<Rule> = match serde_json::from_slice(policy_bytes) {
        Ok(r) => r,
        Err(e) => {
            return VerifyResult::fail(
                format!("failed to deserialize policy rules: {}", e),
                start.elapsed().as_micros() as u64,
            );
        }
    };

    // 反序列化图事实
    let graph_facts: Vec<Atom> = match serde_json::from_slice(graph_bytes) {
        Ok(f) => f,
        Err(e) => {
            return VerifyResult::fail(
                format!("failed to deserialize graph facts: {}", e),
                start.elapsed().as_micros() as u64,
            );
        }
    };

    // 合并所有基础事实
    let mut all_base_facts = request_facts.clone();
    all_base_facts.extend(graph_facts);

    verify_certificate_structured(&cert, &request_facts, &rules, &all_base_facts)
}

/// 验证 Deny Witness（低层 API，保持 FFI 兼容签名）
pub fn verify_witness(
    witness_bytes: &[u8],
    request_bytes: &[u8],
    policy_bytes: &[u8],
    graph_bytes: &[u8],
) -> VerifyResult {
    let start = Instant::now();

    let witness: WitnessData = match serde_json::from_slice(witness_bytes) {
        Ok(w) => w,
        Err(e) => {
            return VerifyResult::fail(
                format!("failed to deserialize witness: {}", e),
                start.elapsed().as_micros() as u64,
            );
        }
    };

    let _request_facts: Vec<Atom> = match serde_json::from_slice(request_bytes) {
        Ok(f) => f,
        Err(e) => {
            return VerifyResult::fail(
                format!("failed to deserialize request facts: {}", e),
                start.elapsed().as_micros() as u64,
            );
        }
    };

    let rules: Vec<Rule> = match serde_json::from_slice(policy_bytes) {
        Ok(r) => r,
        Err(e) => {
            return VerifyResult::fail(
                format!("failed to deserialize policy rules: {}", e),
                start.elapsed().as_micros() as u64,
            );
        }
    };

    let graph_facts: Vec<Atom> = match serde_json::from_slice(graph_bytes) {
        Ok(f) => f,
        Err(e) => {
            return VerifyResult::fail(
                format!("failed to deserialize graph facts: {}", e),
                start.elapsed().as_micros() as u64,
            );
        }
    };

    let mut all_base_facts = _request_facts;
    all_base_facts.extend(graph_facts);

    verify_witness_structured(&witness, &rules, &all_base_facts)
}

// ──────────────────────────────────────────────
// 测试
// ──────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use pcm_cert::generator::{
        generate_certificate, generate_witness, serialize_atom, CertStep, SerializedAtom,
    };
    use pcm_common::hash::blake3_hash;
    use pcm_datalog_engine::engine::DatalogEngine;
    use pcm_policy_dsl::ast::{Atom, Literal, Rule, Term};

    // ── 辅助函数 ──

    fn c(s: &str) -> Term {
        Term::Const(s.to_string())
    }

    fn v(s: &str) -> Term {
        Term::Var(s.to_string())
    }

    fn action_fact(id: &str, at: &str, prin: &str, tgt: &str) -> Atom {
        Atom::Action {
            id: c(id),
            action_type: c(at),
            principal: c(prin),
            target: c(tgt),
        }
    }

    fn has_role(principal: &str, role: &str) -> Atom {
        Atom::HasRole {
            principal: c(principal),
            role: c(role),
        }
    }

    fn graph_edge(src: &str, dst: &str, kind: &str) -> Atom {
        Atom::GraphEdge {
            src: c(src),
            dst: c(dst),
            kind: c(kind),
        }
    }

    fn graph_label(node: &str, label: &str) -> Atom {
        Atom::GraphLabel {
            node: c(node),
            label: c(label),
        }
    }

    fn data_label(data: &str, label: &str) -> Atom {
        Atom::DataLabel {
            data: c(data),
            label: c(label),
        }
    }

    fn deny_atom_ground(req: &str, reason: &str) -> Atom {
        Atom::Deny {
            request: c(req),
            reason: c(reason),
        }
    }

    /// 计算证书验证所需的哈希值
    fn compute_hashes(
        rules: &[Rule],
        request_facts: &[Atom],
        all_base_facts: &[Atom],
    ) -> ([u8; 32], [u8; 32], [u8; 32]) {
        let policy_hash = blake3_hash(&serialize_rules_for_hash(rules));
        let request_hash = blake3_hash(&serialize_atoms_for_hash(request_facts));
        let graph_facts: Vec<&Atom> = all_base_facts
            .iter()
            .filter(|a| !request_facts.contains(a))
            .collect();
        let graph_hash = blake3_hash(&serde_json::to_vec(&graph_facts).unwrap());
        (policy_hash, graph_hash, request_hash)
    }

    /// 执行完整的 allow 流程：evaluate → generate_certificate → verify
    fn run_allow_flow(
        rules: &[Rule],
        request_facts: &[Atom],
        extra_facts: &[Atom],
    ) -> VerifyResult {
        let mut all_base_facts = request_facts.to_vec();
        all_base_facts.extend_from_slice(extra_facts);

        let engine = DatalogEngine::new(rules.to_vec(), 100);
        let eval = engine.evaluate(all_base_facts.clone()).unwrap();
        assert!(
            !eval.has_deny,
            "expected allow but got deny: {:?}",
            eval.deny_reasons
        );

        let (policy_hash, graph_hash, request_hash) =
            compute_hashes(rules, request_facts, &all_base_facts);

        let cert = generate_certificate(&eval, rules, policy_hash, graph_hash, request_hash)
            .expect("certificate generation should succeed");

        verify_certificate_structured(&cert, request_facts, rules, &all_base_facts)
    }

    /// 执行完整的 deny 流程：evaluate → generate_witness → verify
    fn run_deny_flow(
        rules: &[Rule],
        request_facts: &[Atom],
        extra_facts: &[Atom],
    ) -> VerifyResult {
        let mut all_base_facts = request_facts.to_vec();
        all_base_facts.extend_from_slice(extra_facts);

        let engine = DatalogEngine::new(rules.to_vec(), 100);
        let eval = engine.evaluate(all_base_facts.clone()).unwrap();
        assert!(
            eval.has_deny,
            "expected deny but got allow"
        );

        let (policy_hash, _graph_hash, request_hash) =
            compute_hashes(rules, request_facts, &all_base_facts);

        let witness = generate_witness(&eval, rules, policy_hash, request_hash)
            .expect("witness generation should succeed");

        verify_witness_structured(&witness, rules, &all_base_facts)
    }

    // ════════════════════════════════════════════
    // 端到端自洽测试
    // ════════════════════════════════════════════

    #[test]
    fn test_allow_cert_self_consistency() {
        // 规则: deny(Req, "no_role") :- action(Req, "HttpOut", P, _), !has_role(P, "http_allowed")
        let rules = vec![Rule {
            head: Atom::Deny {
                request: v("Req"),
                reason: c("no_role"),
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
        }];

        let request_facts = vec![action_fact("r1", "HttpOut", "alice", "api.com")];
        let extra_facts = vec![has_role("alice", "http_allowed")];

        let result = run_allow_flow(&rules, &request_facts, &extra_facts);
        assert!(result.valid, "expected valid, got: {:?}", result.error);
    }

    #[test]
    fn test_deny_witness_self_consistency() {
        // 同一规则但 alice 没有 http_allowed 角色
        let rules = vec![Rule {
            head: Atom::Deny {
                request: v("Req"),
                reason: c("no_role"),
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
        }];

        let request_facts = vec![action_fact("r1", "HttpOut", "alice", "api.com")];
        let extra_facts: Vec<Atom> = vec![]; // 没有角色

        let result = run_deny_flow(&rules, &request_facts, &extra_facts);
        assert!(result.valid, "expected valid witness, got: {:?}", result.error);
    }

    #[test]
    fn test_allow_5_policies() {
        // Policy 1: HTTP 权限检查 - alice 有权限
        {
            let rules = vec![Rule {
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
            }];
            let req = vec![action_fact("r1", "HttpOut", "alice", "api.com")];
            let extra = vec![has_role("alice", "http_allowed")];
            let r = run_allow_flow(&rules, &req, &extra);
            assert!(r.valid, "policy 1 failed: {:?}", r.error);
        }

        // Policy 2: DB 写入权限 — bob 有 db_writer 角色
        {
            let rules = vec![Rule {
                head: Atom::Deny {
                    request: v("Req"),
                    reason: c("unauthorized_db_write"),
                },
                body: vec![
                    Literal::Pos(Atom::Action {
                        id: v("Req"),
                        action_type: c("DbWrite"),
                        principal: v("P"),
                        target: v("_"),
                    }),
                    Literal::Neg(Atom::HasRole {
                        principal: v("P"),
                        role: c("db_writer"),
                    }),
                ],
            }];
            let req = vec![action_fact("r1", "DbWrite", "bob", "users_table")];
            let extra = vec![has_role("bob", "db_writer")];
            let r = run_allow_flow(&rules, &req, &extra);
            assert!(r.valid, "policy 2 failed: {:?}", r.error);
        }

        // Policy 3: 文件读取 — carol 有 file_reader 角色
        {
            let rules = vec![Rule {
                head: Atom::Deny {
                    request: v("Req"),
                    reason: c("unauthorized_file_read"),
                },
                body: vec![
                    Literal::Pos(Atom::Action {
                        id: v("Req"),
                        action_type: c("FileRead"),
                        principal: v("P"),
                        target: v("_"),
                    }),
                    Literal::Neg(Atom::HasRole {
                        principal: v("P"),
                        role: c("file_reader"),
                    }),
                ],
            }];
            let req = vec![action_fact("r1", "FileRead", "carol", "/etc/config")];
            let extra = vec![has_role("carol", "file_reader")];
            let r = run_allow_flow(&rules, &req, &extra);
            assert!(r.valid, "policy 3 failed: {:?}", r.error);
        }

        // Policy 4: ToolCall 权限 — dave 有 tool_user 角色
        {
            let rules = vec![Rule {
                head: Atom::Deny {
                    request: v("Req"),
                    reason: c("unauthorized_tool_call"),
                },
                body: vec![
                    Literal::Pos(Atom::Action {
                        id: v("Req"),
                        action_type: c("ToolCall"),
                        principal: v("P"),
                        target: v("_"),
                    }),
                    Literal::Neg(Atom::HasRole {
                        principal: v("P"),
                        role: c("tool_user"),
                    }),
                ],
            }];
            let req = vec![action_fact("r1", "ToolCall", "dave", "compiler")];
            let extra = vec![has_role("dave", "tool_user")];
            let r = run_allow_flow(&rules, &req, &extra);
            assert!(r.valid, "policy 4 failed: {:?}", r.error);
        }

        // Policy 5: 多条件策略 — action + graph_label 都满足但有角色豁免
        {
            let rules = vec![Rule {
                head: Atom::Deny {
                    request: v("Req"),
                    reason: c("sensitive_target_access"),
                },
                body: vec![
                    Literal::Pos(Atom::Action {
                        id: v("Req"),
                        action_type: c("DbReadSensitive"),
                        principal: v("P"),
                        target: v("T"),
                    }),
                    Literal::Pos(Atom::DataLabel {
                        data: v("T"),
                        label: c("Confidential"),
                    }),
                    Literal::Neg(Atom::HasRole {
                        principal: v("P"),
                        role: c("data_officer"),
                    }),
                ],
            }];
            let req = vec![action_fact("r1", "DbReadSensitive", "eve", "customer_pii")];
            let extra = vec![
                data_label("customer_pii", "Confidential"),
                has_role("eve", "data_officer"),
            ];
            let r = run_allow_flow(&rules, &req, &extra);
            assert!(r.valid, "policy 5 failed: {:?}", r.error);
        }
    }

    #[test]
    fn test_deny_5_policies() {
        // Policy 1: HTTP 权限 — alice 没有权限
        {
            let rules = vec![Rule {
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
            }];
            let req = vec![action_fact("r1", "HttpOut", "alice", "api.com")];
            let r = run_deny_flow(&rules, &req, &[]);
            assert!(r.valid, "deny policy 1 failed: {:?}", r.error);
        }

        // Policy 2: DB 写入 — bob 没有 db_writer 角色
        {
            let rules = vec![Rule {
                head: Atom::Deny {
                    request: v("Req"),
                    reason: c("unauthorized_db_write"),
                },
                body: vec![
                    Literal::Pos(Atom::Action {
                        id: v("Req"),
                        action_type: c("DbWrite"),
                        principal: v("P"),
                        target: v("_"),
                    }),
                    Literal::Neg(Atom::HasRole {
                        principal: v("P"),
                        role: c("db_writer"),
                    }),
                ],
            }];
            let req = vec![action_fact("r1", "DbWrite", "bob", "users_table")];
            let r = run_deny_flow(&rules, &req, &[]);
            assert!(r.valid, "deny policy 2 failed: {:?}", r.error);
        }

        // Policy 3: 文件写入 + 敏感标签 → deny
        {
            let rules = vec![Rule {
                head: Atom::Deny {
                    request: v("Req"),
                    reason: c("sensitive_file_write"),
                },
                body: vec![
                    Literal::Pos(Atom::Action {
                        id: v("Req"),
                        action_type: c("FileWrite"),
                        principal: v("P"),
                        target: v("T"),
                    }),
                    Literal::Pos(Atom::DataLabel {
                        data: v("T"),
                        label: c("Secret"),
                    }),
                ],
            }];
            let req = vec![action_fact("r1", "FileWrite", "carol", "/secrets/key")];
            let extra = vec![data_label("/secrets/key", "Secret")];
            let r = run_deny_flow(&rules, &req, &extra);
            assert!(r.valid, "deny policy 3 failed: {:?}", r.error);
        }

        // Policy 4: 图路径禁止 — data flow from internal to external
        {
            let rules = vec![Rule {
                head: Atom::Deny {
                    request: v("Req"),
                    reason: c("data_exfiltration"),
                },
                body: vec![
                    Literal::Pos(Atom::Action {
                        id: v("Req"),
                        action_type: c("HttpOut"),
                        principal: v("P"),
                        target: v("Dst"),
                    }),
                    Literal::Pos(Atom::GraphEdge {
                        src: v("P"),
                        dst: v("Dst"),
                        kind: c("DataFlow"),
                    }),
                ],
            }];
            let req = vec![action_fact("r1", "HttpOut", "agent", "external.com")];
            let extra = vec![graph_edge("agent", "external.com", "DataFlow")];
            let r = run_deny_flow(&rules, &req, &extra);
            assert!(r.valid, "deny policy 4 failed: {:?}", r.error);
        }

        // Policy 5: 纯 ground deny 规则
        {
            let rules = vec![Rule {
                head: Atom::Deny {
                    request: c("r1"),
                    reason: c("blocked"),
                },
                body: vec![Literal::Pos(action_fact("r1", "HttpOut", "mallory", "evil.com"))],
            }];
            let req = vec![action_fact("r1", "HttpOut", "mallory", "evil.com")];
            let r = run_deny_flow(&rules, &req, &[]);
            assert!(r.valid, "deny policy 5 failed: {:?}", r.error);
        }
    }

    // ════════════════════════════════════════════
    // 负面测试
    // ════════════════════════════════════════════

    #[test]
    fn test_tampered_cert_rejected() {
        let rules = vec![Rule {
            head: Atom::Deny {
                request: v("Req"),
                reason: c("no_role"),
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
        }];

        let request_facts = vec![action_fact("r1", "HttpOut", "alice", "api.com")];
        let extra_facts = vec![has_role("alice", "http_allowed")];
        let mut all_base_facts = request_facts.clone();
        all_base_facts.extend_from_slice(&extra_facts);

        let (policy_hash, graph_hash, request_hash) =
            compute_hashes(&rules, &request_facts, &all_base_facts);

        let engine = DatalogEngine::new(rules.clone(), 100);
        let eval = engine.evaluate(all_base_facts.clone()).unwrap();
        let mut cert =
            generate_certificate(&eval, &rules, policy_hash, graph_hash, request_hash).unwrap();

        // 篡改 policy_hash
        cert.policy_hash = [0u8; 32];

        let result = verify_certificate_structured(&cert, &request_facts, &rules, &all_base_facts);
        assert!(!result.valid, "tampered cert should be rejected");
        assert!(
            result.error.as_ref().unwrap().contains("policy hash"),
            "error should mention policy hash"
        );
    }

    #[test]
    fn test_wrong_rule_index() {
        let rules = vec![Rule {
            head: Atom::Deny {
                request: v("Req"),
                reason: c("no_role"),
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
        }];

        let request_facts = vec![action_fact("r1", "HttpOut", "alice", "api.com")];
        let extra_facts = vec![has_role("alice", "http_allowed")];
        let mut all_base_facts = request_facts.clone();
        all_base_facts.extend_from_slice(&extra_facts);

        let (policy_hash, graph_hash, request_hash) =
            compute_hashes(&rules, &request_facts, &all_base_facts);

        // 手动构建一个包含无效 rule_index 的证书
        let cert = CertificateData {
            steps: vec![CertStep {
                rule_index: 99, // 无效索引
                premise_indices: vec![],
                conclusion: SerializedAtom {
                    predicate: "action".to_string(),
                    args: vec![
                        "r1".to_string(),
                        "HttpOut".to_string(),
                        "alice".to_string(),
                        "api.com".to_string(),
                    ],
                },
            }],
            policy_hash,
            graph_hash,
            request_hash,
        };

        let result = verify_certificate_structured(&cert, &request_facts, &rules, &all_base_facts);
        assert!(!result.valid, "wrong rule_index should be rejected");
        assert!(result.failed_step.is_some());
        assert!(
            result.error.as_ref().unwrap().contains("rule_index"),
            "error should mention rule_index"
        );
    }

    #[test]
    fn test_missing_premise() {
        // 构建一条规则需要正文字前提，但证书的前提集缺失
        let rules = vec![Rule {
            head: Atom::Deny {
                request: v("Req"),
                reason: c("no_role"),
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
        }];

        let request_facts = vec![action_fact("r1", "HttpOut", "alice", "api.com")];
        let extra_facts = vec![has_role("alice", "http_allowed")];
        let mut all_base_facts = request_facts.clone();
        all_base_facts.extend_from_slice(&extra_facts);

        let (policy_hash, graph_hash, request_hash) =
            compute_hashes(&rules, &request_facts, &all_base_facts);

        let engine = DatalogEngine::new(rules.clone(), 100);
        let _eval = engine.evaluate(all_base_facts.clone()).unwrap();

        // 在这种 allow 的情况下不应有推导步骤输出 deny
        // 构建一个假的证书步骤，其结论是 deny 但前提不够
        let cert = CertificateData {
            steps: vec![CertStep {
                rule_index: 0,
                premise_indices: vec![0],
                // 用 deny 作为结论
                conclusion: serialize_atom(&deny_atom_ground("r1", "no_role")),
            }],
            policy_hash,
            graph_hash,
            request_hash,
        };

        let result = verify_certificate_structured(&cert, &request_facts, &rules, &all_base_facts);
        // 即使通过了步骤验证（如果能通过），最终 derived 包含 deny → 应该失败
        assert!(!result.valid, "cert with deny conclusion should be rejected");
    }

    #[test]
    fn test_tampered_witness_rejected() {
        let rules = vec![Rule {
            head: Atom::Deny {
                request: v("Req"),
                reason: c("no_role"),
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
        }];

        let request_facts = vec![action_fact("r1", "HttpOut", "alice", "api.com")];
        let all_base_facts = request_facts.clone();

        let (policy_hash, _graph_hash, request_hash) =
            compute_hashes(&rules, &request_facts, &all_base_facts);

        let engine = DatalogEngine::new(rules.clone(), 100);
        let eval = engine.evaluate(all_base_facts.clone()).unwrap();
        assert!(eval.has_deny);

        let mut witness = generate_witness(&eval, &rules, policy_hash, request_hash).unwrap();

        // 篡改 deny_rule_index
        witness.deny_rule_index = 99;

        let result = verify_witness_structured(&witness, &rules, &all_base_facts);
        assert!(!result.valid, "tampered witness should be rejected");
        assert!(
            result.error.as_ref().unwrap().contains("deny_rule_index")
                || result.error.as_ref().unwrap().contains("out of bounds"),
            "error should mention deny_rule_index: {:?}",
            result.error
        );
    }

    #[test]
    fn test_extra_deny_not_in_cert() {
        // 构建一个策略有 deny 规则可被满足，但是证书声称 allow
        // 规则: deny(Req, "blocked") :- action(Req, "HttpOut", P, _)
        // 注意这个规则没有负文字，所以任何 HttpOut action 都会被 deny
        let rules = vec![Rule {
            head: Atom::Deny {
                request: v("Req"),
                reason: c("blocked"),
            },
            body: vec![Literal::Pos(Atom::Action {
                id: v("Req"),
                action_type: c("HttpOut"),
                principal: v("P"),
                target: v("_"),
            })],
        }];

        let request_facts = vec![action_fact("r1", "HttpOut", "alice", "api.com")];
        let all_base_facts = request_facts.clone();

        let (policy_hash, graph_hash, request_hash) =
            compute_hashes(&rules, &request_facts, &all_base_facts);

        // 构建一个声称 allow 的空证书（无推导步骤 → 无 deny）
        let cert = CertificateData {
            steps: vec![],
            policy_hash,
            graph_hash,
            request_hash,
        };

        let result = verify_certificate_structured(&cert, &request_facts, &rules, &all_base_facts);
        assert!(
            !result.valid,
            "cert claiming allow while deny rule is satisfiable should be rejected"
        );
        assert!(
            result.error.as_ref().unwrap().contains("deny rule"),
            "error should mention deny rule: {:?}",
            result.error
        );
    }

    // ════════════════════════════════════════════
    // 哈希一致性测试
    // ════════════════════════════════════════════

    #[test]
    fn test_hash_mismatch_policy() {
        let rules = vec![Rule {
            head: Atom::Deny {
                request: v("Req"),
                reason: c("no_role"),
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
        }];

        let request_facts = vec![action_fact("r1", "HttpOut", "alice", "api.com")];
        let extra_facts = vec![has_role("alice", "http_allowed")];
        let mut all_base_facts = request_facts.clone();
        all_base_facts.extend_from_slice(&extra_facts);

        let (_, graph_hash, request_hash) =
            compute_hashes(&rules, &request_facts, &all_base_facts);

        let cert = CertificateData {
            steps: vec![],
            policy_hash: [42u8; 32], // 错误的 policy hash
            graph_hash,
            request_hash,
        };

        let result = verify_certificate_structured(&cert, &request_facts, &rules, &all_base_facts);
        assert!(!result.valid);
        assert!(result.error.as_ref().unwrap().contains("policy hash mismatch"));
    }

    #[test]
    fn test_hash_mismatch_request() {
        let rules = vec![Rule {
            head: Atom::Deny {
                request: v("Req"),
                reason: c("no_role"),
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
        }];

        let request_facts = vec![action_fact("r1", "HttpOut", "alice", "api.com")];
        let extra_facts = vec![has_role("alice", "http_allowed")];
        let mut all_base_facts = request_facts.clone();
        all_base_facts.extend_from_slice(&extra_facts);

        let (policy_hash, graph_hash, _) =
            compute_hashes(&rules, &request_facts, &all_base_facts);

        let cert = CertificateData {
            steps: vec![],
            policy_hash,
            graph_hash,
            request_hash: [42u8; 32], // 错误的 request hash
        };

        let result = verify_certificate_structured(&cert, &request_facts, &rules, &all_base_facts);
        assert!(!result.valid);
        assert!(result.error.as_ref().unwrap().contains("request hash mismatch"));
    }

    // ════════════════════════════════════════════
    // 辅助函数单元测试
    // ════════════════════════════════════════════

    #[test]
    fn test_deserialize_atom_roundtrip() {
        let atoms = vec![
            action_fact("r1", "HttpOut", "alice", "api.com"),
            has_role("alice", "admin"),
            graph_edge("a", "b", "DataFlow"),
            graph_label("node1", "Internal"),
            data_label("file1", "Secret"),
            deny_atom_ground("r1", "blocked"),
        ];

        for atom in &atoms {
            let sa = serialize_atom(atom);
            let restored = deserialize_atom(&sa).unwrap();
            assert_eq!(*atom, restored, "roundtrip failed for {:?}", atom);
        }
    }

    #[test]
    fn test_find_substitution_basic() {
        let pattern = Atom::Action {
            id: v("Req"),
            action_type: c("HttpOut"),
            principal: v("P"),
            target: v("_"),
        };
        let ground = action_fact("r1", "HttpOut", "alice", "api.com");

        let subst = find_substitution(&pattern, &ground).unwrap();
        assert_eq!(subst.get("Req").unwrap(), "r1");
        assert_eq!(subst.get("P").unwrap(), "alice");
        // "_" is wildcard, should not be bound
        assert!(!subst.contains_key("_"));
    }

    #[test]
    fn test_find_substitution_mismatch() {
        let pattern = Atom::Action {
            id: v("Req"),
            action_type: c("DbWrite"),
            principal: v("P"),
            target: v("_"),
        };
        let ground = action_fact("r1", "HttpOut", "alice", "api.com");

        assert!(find_substitution(&pattern, &ground).is_none());
    }

    #[test]
    fn test_atom_matches() {
        let pattern = Atom::HasRole {
            principal: v("P"),
            role: c("admin"),
        };
        assert!(atom_matches(&pattern, &has_role("alice", "admin")));
        assert!(!atom_matches(&pattern, &has_role("alice", "user")));
    }
}
