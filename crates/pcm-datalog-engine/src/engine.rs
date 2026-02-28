//! Datalog 评估引擎核心
//!
//! 实现朴素自底向上不动点评估，支持：
//! - 含变量的规则统一/替换
//! - 分层否定（stratified negation）
//! - 推导追踪（用于证书生成）

use pcm_common::error::PcmError;
use pcm_policy_dsl::ast::{Atom, Literal, Rule, Term};
use std::collections::{HashMap, HashSet};

// ──────────────────────────────────────────────
// 类型定义
// ──────────────────────────────────────────────

/// 变量绑定环境
pub type Substitution = HashMap<String, Term>;

/// 评估引擎
pub struct DatalogEngine {
    rules: Vec<Rule>,
    max_iterations: usize,
}

/// 推导追踪记录
#[derive(Debug, Clone)]
pub struct DerivationTrace {
    pub rule_index: usize,
    /// 前提事实在 facts 列表中的索引（每个正文字对应一个）
    pub premises: Vec<usize>,
    /// apply_substitution 后的 ground 结论原子
    pub conclusion: Atom,
}

/// 评估结果
#[derive(Debug)]
pub struct EvalResult {
    /// 最终事实集合
    pub facts: Vec<Atom>,
    /// 推导追踪（用于证书生成）
    pub trace: Vec<DerivationTrace>,
    /// 是否包含 deny 原子
    pub has_deny: bool,
    /// deny 原因（如有）
    pub deny_reasons: Vec<(String, String)>, // (request_id, reason)
}

// ──────────────────────────────────────────────
// 统一 / 替换
// ──────────────────────────────────────────────

/// 统一一个 pattern Term 与一个 ground Term。
///
/// - `Const(a)` vs `Const(b)` → `a == b`
/// - `Var("_")` (通配符) → 始终成功，不产生绑定
/// - `Var(v)` → 若 `v` 已绑定则检查一致性，否则绑定 `v → ground`
pub fn unify_term(pattern: &Term, ground: &Term, subst: &mut Substitution) -> bool {
    match (pattern, ground) {
        // 通配符始终匹配
        (Term::Var(v), _) if v == "_" => true,
        (_, Term::Var(v)) if v == "_" => true,

        // 模式中的变量
        (Term::Var(v), _) => {
            if let Some(existing) = subst.get(v) {
                existing == ground
            } else {
                subst.insert(v.clone(), ground.clone());
                true
            }
        }

        // ground 中的变量（反向绑定）
        (Term::Const(a), Term::Var(v)) => {
            if let Some(existing) = subst.get(v) {
                *existing == Term::Const(a.clone())
            } else {
                subst.insert(v.clone(), Term::Const(a.clone()));
                true
            }
        }

        // 两个常量
        (Term::Const(a), Term::Const(b)) => a == b,
    }
}

/// 统一两个 Atom。两者必须是同一谓词变体，逐字段调用 `unify_term`。
pub fn unify_atom(pattern: &Atom, ground: &Atom, subst: &mut Substitution) -> bool {
    match (pattern, ground) {
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
            unify_term(id1, id2, subst)
                && unify_term(at1, at2, subst)
                && unify_term(p1, p2, subst)
                && unify_term(t1, t2, subst)
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
        ) => unify_term(d1, d2, subst) && unify_term(l1, l2, subst),

        (
            Atom::HasRole {
                principal: p1,
                role: r1,
            },
            Atom::HasRole {
                principal: p2,
                role: r2,
            },
        ) => unify_term(p1, p2, subst) && unify_term(r1, r2, subst),

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
        ) => unify_term(s1, s2, subst) && unify_term(d1, d2, subst) && unify_term(k1, k2, subst),

        (
            Atom::GraphLabel {
                node: n1,
                label: l1,
            },
            Atom::GraphLabel {
                node: n2,
                label: l2,
            },
        ) => unify_term(n1, n2, subst) && unify_term(l1, l2, subst),

        (
            Atom::Precedes {
                before: b1,
                after: a1,
            },
            Atom::Precedes {
                before: b2,
                after: a2,
            },
        ) => unify_term(b1, b2, subst) && unify_term(a1, a2, subst),

        (
            Atom::Deny {
                request: r1,
                reason: re1,
            },
            Atom::Deny {
                request: r2,
                reason: re2,
            },
        ) => unify_term(r1, r2, subst) && unify_term(re1, re2, subst),

        _ => false,
    }
}

/// 将 `Substitution` 应用到 `Atom`，替换所有已绑定的变量。
/// 未绑定的变量保留。
pub fn apply_substitution(atom: &Atom, subst: &Substitution) -> Atom {
    let sub = |t: &Term| -> Term {
        match t {
            Term::Var(v) if v != "_" => subst.get(v).cloned().unwrap_or_else(|| t.clone()),
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

// ──────────────────────────────────────────────
// 辅助函数
// ──────────────────────────────────────────────

/// 获取 Atom 的谓词名称字符串
fn predicate_name(atom: &Atom) -> &'static str {
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

// ──────────────────────────────────────────────
// 分层否定
// ──────────────────────────────────────────────

/// 对规则进行分层（Stratified Negation）。
///
/// 返回 `Vec<Vec<usize>>`，其中外层按 stratum 升序排列，
/// 每个内层为该层中规则在原始 `rules` 数组中的索引。
///
/// 若存在穿过否定边的环（不可分层），返回 `PcmError::PolicyValidation`。
pub fn stratify(rules: &[Rule]) -> Result<Vec<Vec<usize>>, PcmError> {
    if rules.is_empty() {
        return Ok(vec![]);
    }

    // 收集所有出现的谓词名称
    let mut all_preds: HashSet<&'static str> = HashSet::new();
    for rule in rules {
        all_preds.insert(predicate_name(&rule.head));
        for lit in &rule.body {
            let atom = match lit {
                Literal::Pos(a) | Literal::Neg(a) => a,
            };
            all_preds.insert(predicate_name(atom));
        }
    }

    // 初始化每个谓词的 stratum 为 0
    let mut stratum: HashMap<&str, usize> = HashMap::new();
    for &p in &all_preds {
        stratum.insert(p, 0);
    }

    // 迭代分配 stratum：
    // - 正依赖：head.stratum >= body_pred.stratum
    // - 负依赖：head.stratum >  body_pred.stratum
    let max_strata = all_preds.len() + 1;
    let mut changed = true;
    while changed {
        changed = false;
        for rule in rules {
            let head_pred = predicate_name(&rule.head);
            for lit in &rule.body {
                match lit {
                    Literal::Pos(a) => {
                        let body_pred = predicate_name(a);
                        let body_s = stratum[body_pred];
                        if stratum[head_pred] < body_s {
                            stratum.insert(head_pred, body_s);
                            changed = true;
                        }
                    }
                    Literal::Neg(a) => {
                        let body_pred = predicate_name(a);
                        let body_s = stratum[body_pred];
                        if stratum[head_pred] <= body_s {
                            let new_s = body_s + 1;
                            if new_s >= max_strata {
                                return Err(PcmError::PolicyValidation(
                                    "negative cycle detected in rules; stratification impossible"
                                        .to_string(),
                                ));
                            }
                            stratum.insert(head_pred, new_s);
                            changed = true;
                        }
                    }
                }
            }
        }
    }

    // 按 stratum 分组规则索引
    let num_strata = stratum.values().copied().max().unwrap_or(0) + 1;
    let mut strata: Vec<Vec<usize>> = vec![vec![]; num_strata];
    for (i, rule) in rules.iter().enumerate() {
        let s = stratum[predicate_name(&rule.head)];
        strata[s].push(i);
    }

    // 移除空 stratum
    strata.retain(|s| !s.is_empty());

    Ok(strata)
}

// ──────────────────────────────────────────────
// 评估引擎
// ──────────────────────────────────────────────

impl DatalogEngine {
    pub fn new(rules: Vec<Rule>, max_iterations: usize) -> Self {
        Self {
            rules,
            max_iterations,
        }
    }

    /// 在给定基础事实上进行分层朴素自底向上不动点求值。
    ///
    /// 每一层内反复触发规则直到无新事实产生（不动点），
    /// 然后进入下一层。超过 `max_iterations` 返回 `EvaluationTimeout`。
    pub fn evaluate(&self, base_facts: Vec<Atom>) -> Result<EvalResult, PcmError> {
        let strata = stratify(&self.rules)?;

        let mut facts = base_facts;
        let mut trace = Vec::new();
        let mut seen: HashSet<Atom> = HashSet::new();

        // 将基础事实加入去重集
        for f in &facts {
            seen.insert(f.clone());
        }

        // 按 stratum 顺序执行
        for stratum_rules in &strata {
            let mut iteration = 0;
            loop {
                if iteration >= self.max_iterations {
                    return Err(PcmError::EvaluationTimeout(iteration as u64));
                }

                let mut new_facts = Vec::new();

                for &rule_idx in stratum_rules {
                    let rule = &self.rules[rule_idx];

                    // 分离正文字和负文字
                    let pos_lits: Vec<&Atom> = rule
                        .body
                        .iter()
                        .filter_map(|l| {
                            if let Literal::Pos(a) = l {
                                Some(a)
                            } else {
                                None
                            }
                        })
                        .collect();
                    let neg_lits: Vec<&Atom> = rule
                        .body
                        .iter()
                        .filter_map(|l| {
                            if let Literal::Neg(a) = l {
                                Some(a)
                            } else {
                                None
                            }
                        })
                        .collect();

                    // 对正文字做笛卡尔积统一，找到所有有效替换
                    let substitutions = Self::find_substitutions(&pos_lits, &facts);

                    for (subst, premise_indices) in substitutions {
                        // 检查所有负文字：apply_substitution 后确认事实集中不存在
                        let neg_ok = neg_lits.iter().all(|neg_atom| {
                            let ground = apply_substitution(neg_atom, &subst);
                            !facts.contains(&ground)
                        });

                        if neg_ok {
                            let conclusion = apply_substitution(&rule.head, &subst);
                            if !seen.contains(&conclusion) {
                                seen.insert(conclusion.clone());
                                trace.push(DerivationTrace {
                                    rule_index: rule_idx,
                                    premises: premise_indices,
                                    conclusion: conclusion.clone(),
                                });
                                new_facts.push(conclusion);
                            }
                        }
                    }
                }

                if new_facts.is_empty() {
                    break; // 本层不动点已达
                }
                facts.extend(new_facts);
                iteration += 1;
            }
        }

        // 收集 deny 原因
        let mut deny_reasons = Vec::new();
        for f in &facts {
            if let Atom::Deny {
                request: Term::Const(rid),
                reason: Term::Const(r),
            } = f
            {
                deny_reasons.push((rid.clone(), r.clone()));
            }
        }
        let has_deny = !deny_reasons.is_empty();

        Ok(EvalResult {
            facts,
            trace,
            has_deny,
            deny_reasons,
        })
    }

    /// 对正文字列表，在当前事实集中找出所有有效的 (Substitution, premise_indices) 组合。
    ///
    /// 对第一个正文字逐一遍历事实尝试统一，得到候选；
    /// 对后续正文字在每个候选上继续统一（笛卡尔积 + 剪枝）。
    fn find_substitutions(pos_lits: &[&Atom], facts: &[Atom]) -> Vec<(Substitution, Vec<usize>)> {
        if pos_lits.is_empty() {
            // 无正文字 → 空替换（规则无条件触发或只有负文字）
            return vec![(HashMap::new(), vec![])];
        }

        // 第一个正文字：遍历事实尝试统一
        let mut candidates: Vec<(Substitution, Vec<usize>)> = Vec::new();
        for (fact_idx, fact) in facts.iter().enumerate() {
            let mut subst = Substitution::new();
            if unify_atom(pos_lits[0], fact, &mut subst) {
                candidates.push((subst, vec![fact_idx]));
            }
        }

        // 后续正文字：在每个候选上继续统一
        for &lit in &pos_lits[1..] {
            let mut new_candidates = Vec::new();
            for (subst, premises) in &candidates {
                for (fact_idx, fact) in facts.iter().enumerate() {
                    let mut new_subst = subst.clone();
                    if unify_atom(lit, fact, &mut new_subst) {
                        let mut new_premises = premises.clone();
                        new_premises.push(fact_idx);
                        new_candidates.push((new_subst, new_premises));
                    }
                }
            }
            candidates = new_candidates;
        }

        candidates
    }
}

// ──────────────────────────────────────────────
// 测试
// ──────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
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

    fn has_role_fact(principal: &str, role: &str) -> Atom {
        Atom::HasRole {
            principal: c(principal),
            role: c(role),
        }
    }

    fn deny_atom(req: Term, reason: Term) -> Atom {
        Atom::Deny {
            request: req,
            reason,
        }
    }

    fn graph_edge_fact(src: &str, dst: &str, kind: &str) -> Atom {
        Atom::GraphEdge {
            src: c(src),
            dst: c(dst),
            kind: c(kind),
        }
    }

    fn graph_label_fact(node: &str, label: &str) -> Atom {
        Atom::GraphLabel {
            node: c(node),
            label: c(label),
        }
    }

    fn precedes_fact(before: &str, after: &str) -> Atom {
        Atom::Precedes {
            before: c(before),
            after: c(after),
        }
    }

    // ── 1. test_ground_deny ──

    #[test]
    fn test_ground_deny() {
        // 纯 ground 规则：deny("r1","blocked") :- action("r1","HttpOut","alice","api.com").
        let rule = Rule {
            head: deny_atom(c("r1"), c("blocked")),
            body: vec![Literal::Pos(action_fact(
                "r1", "HttpOut", "alice", "api.com",
            ))],
        };
        let facts = vec![action_fact("r1", "HttpOut", "alice", "api.com")];
        let engine = DatalogEngine::new(vec![rule], 100);
        let result = engine.evaluate(facts).unwrap();
        assert!(result.has_deny);
        assert_eq!(result.deny_reasons.len(), 1);
        assert_eq!(result.deny_reasons[0], ("r1".into(), "blocked".into()));
    }

    // ── 2. test_ground_allow ──

    #[test]
    fn test_ground_allow() {
        // 同一 ground 规则，但事实不匹配（不同 principal）
        let rule = Rule {
            head: deny_atom(c("r1"), c("blocked")),
            body: vec![Literal::Pos(action_fact(
                "r1", "HttpOut", "alice", "api.com",
            ))],
        };
        let facts = vec![action_fact("r1", "HttpOut", "bob", "api.com")];
        let engine = DatalogEngine::new(vec![rule], 100);
        let result = engine.evaluate(facts).unwrap();
        assert!(!result.has_deny);
        assert!(result.deny_reasons.is_empty());
    }

    // ── 3. test_variable_binding ──

    #[test]
    fn test_variable_binding() {
        // deny(Req, "no_http") :- action(Req, "HttpOut", P, _), !has_role(P, "http_allowed").
        let rule = Rule {
            head: deny_atom(v("Req"), c("no_http")),
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
        };
        // alice 没有 http_allowed 角色
        let facts = vec![action_fact("r1", "HttpOut", "alice", "api.com")];
        let engine = DatalogEngine::new(vec![rule], 100);
        let result = engine.evaluate(facts).unwrap();
        assert!(result.has_deny);
        assert_eq!(result.deny_reasons[0], ("r1".into(), "no_http".into()));
        // 检查推导追踪
        assert_eq!(result.trace.len(), 1);
        assert_eq!(result.trace[0].rule_index, 0);
        assert_eq!(result.trace[0].premises, vec![0]); // action 事实在索引 0
    }

    // ── 4. test_variable_allow ──

    #[test]
    fn test_variable_allow() {
        // 同上规则，但 alice 有 http_allowed 角色 → 否定文字不满足 → 无 deny
        let rule = Rule {
            head: deny_atom(v("Req"), c("no_http")),
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
        };
        let facts = vec![
            action_fact("r1", "HttpOut", "alice", "api.com"),
            has_role_fact("alice", "http_allowed"),
        ];
        let engine = DatalogEngine::new(vec![rule], 100);
        let result = engine.evaluate(facts).unwrap();
        assert!(!result.has_deny);
    }

    // ── 5. test_multi_rule_mixed ──

    #[test]
    fn test_multi_rule_mixed() {
        // 4 条规则，部分匹配
        let rules = vec![
            // R0: deny(Req,"http") :- action(Req,"HttpOut",P,_), !has_role(P,"http_allowed").
            Rule {
                head: deny_atom(v("Req"), c("http")),
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
            },
            // R1: deny(Req,"db") :- action(Req,"DbWrite",P,_), !has_role(P,"db_writer").
            Rule {
                head: deny_atom(v("Req"), c("db")),
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
            },
            // R2: deny(Req,"file") :- action(Req,"FileWrite",P,_), !has_role(P,"file_writer").
            Rule {
                head: deny_atom(v("Req"), c("file")),
                body: vec![
                    Literal::Pos(Atom::Action {
                        id: v("Req"),
                        action_type: c("FileWrite"),
                        principal: v("P"),
                        target: v("_"),
                    }),
                    Literal::Neg(Atom::HasRole {
                        principal: v("P"),
                        role: c("file_writer"),
                    }),
                ],
            },
            // R3: deny(Req,"tool") :- action(Req,"ToolCall",P,_), !has_role(P,"tool_user").
            Rule {
                head: deny_atom(v("Req"), c("tool")),
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
            },
        ];

        let facts = vec![
            action_fact("r1", "HttpOut", "alice", "api.com"), // R0 匹配
            action_fact("r2", "DbWrite", "bob", "users"),     // R1 匹配（bob 没有 db_writer）
            action_fact("r3", "FileWrite", "carol", "/tmp"),  // R2：carol 有 file_writer → 不触发
            has_role_fact("carol", "file_writer"),
            // 没有 ToolCall action → R3 不触发
        ];

        let engine = DatalogEngine::new(rules, 100);
        let result = engine.evaluate(facts).unwrap();
        assert!(result.has_deny);
        assert_eq!(result.deny_reasons.len(), 2);
        let reasons: HashSet<(String, String)> = result.deny_reasons.into_iter().collect();
        assert!(reasons.contains(&("r1".into(), "http".into())));
        assert!(reasons.contains(&("r2".into(), "db".into())));
    }

    // ── 6. test_graph_constraint ──

    #[test]
    fn test_graph_constraint() {
        // 信息流违规：存在从 Confidential 到 Public 的数据流边
        // deny(Src,"info_leak") :- graph_edge(Src,Dst,"DataFlow"),
        //                          graph_label(Src,"Confidential"),
        //                          graph_label(Dst,"Public").
        let rule = Rule {
            head: deny_atom(v("Src"), c("info_leak")),
            body: vec![
                Literal::Pos(Atom::GraphEdge {
                    src: v("Src"),
                    dst: v("Dst"),
                    kind: c("DataFlow"),
                }),
                Literal::Pos(Atom::GraphLabel {
                    node: v("Src"),
                    label: c("Confidential"),
                }),
                Literal::Pos(Atom::GraphLabel {
                    node: v("Dst"),
                    label: c("Public"),
                }),
            ],
        };

        let facts = vec![
            graph_edge_fact("node_a", "node_b", "DataFlow"),
            graph_label_fact("node_a", "Confidential"),
            graph_label_fact("node_b", "Public"),
        ];

        let engine = DatalogEngine::new(vec![rule], 100);
        let result = engine.evaluate(facts).unwrap();
        assert!(result.has_deny);
        assert_eq!(
            result.deny_reasons[0],
            ("node_a".into(), "info_leak".into())
        );
    }

    // ── 7. test_graph_constraint_no_violation ──

    #[test]
    fn test_graph_constraint_no_violation() {
        // 同上规则，但两端都是 Internal → 不匹配
        let rule = Rule {
            head: deny_atom(v("Src"), c("info_leak")),
            body: vec![
                Literal::Pos(Atom::GraphEdge {
                    src: v("Src"),
                    dst: v("Dst"),
                    kind: c("DataFlow"),
                }),
                Literal::Pos(Atom::GraphLabel {
                    node: v("Src"),
                    label: c("Confidential"),
                }),
                Literal::Pos(Atom::GraphLabel {
                    node: v("Dst"),
                    label: c("Public"),
                }),
            ],
        };

        let facts = vec![
            graph_edge_fact("node_a", "node_b", "DataFlow"),
            graph_label_fact("node_a", "Internal"),
            graph_label_fact("node_b", "Internal"),
        ];

        let engine = DatalogEngine::new(vec![rule], 100);
        let result = engine.evaluate(facts).unwrap();
        assert!(!result.has_deny);
    }

    // ── 8. test_temporal_precedes ──

    #[test]
    fn test_temporal_precedes() {
        // deny(Req,"missing_auth") :- action(Req,"DbWrite",P,_), !precedes("auth_check",Req).
        let rule = Rule {
            head: deny_atom(v("Req"), c("missing_auth")),
            body: vec![
                Literal::Pos(Atom::Action {
                    id: v("Req"),
                    action_type: c("DbWrite"),
                    principal: v("P"),
                    target: v("_"),
                }),
                Literal::Neg(Atom::Precedes {
                    before: c("auth_check"),
                    after: v("Req"),
                }),
            ],
        };

        // 没有 precedes("auth_check", "r1") 事实
        let facts = vec![action_fact("r1", "DbWrite", "alice", "users")];
        let engine = DatalogEngine::new(vec![rule], 100);
        let result = engine.evaluate(facts).unwrap();
        assert!(result.has_deny);
        assert_eq!(result.deny_reasons[0], ("r1".into(), "missing_auth".into()));
    }

    // ── 9. test_temporal_satisfied ──

    #[test]
    fn test_temporal_satisfied() {
        // 同上规则，但有 precedes("auth_check", "r1") → 否定不满足 → allow
        let rule = Rule {
            head: deny_atom(v("Req"), c("missing_auth")),
            body: vec![
                Literal::Pos(Atom::Action {
                    id: v("Req"),
                    action_type: c("DbWrite"),
                    principal: v("P"),
                    target: v("_"),
                }),
                Literal::Neg(Atom::Precedes {
                    before: c("auth_check"),
                    after: v("Req"),
                }),
            ],
        };

        let facts = vec![
            action_fact("r1", "DbWrite", "alice", "users"),
            precedes_fact("auth_check", "r1"),
        ];
        let engine = DatalogEngine::new(vec![rule], 100);
        let result = engine.evaluate(facts).unwrap();
        assert!(!result.has_deny);
    }

    // ── 10. test_fixpoint_convergence ──

    #[test]
    fn test_fixpoint_convergence() {
        // 传递闭包：reachable via graph_edge
        // graph_edge(X, Y, "DataFlow") :- graph_edge(X, Z, "DataFlow"), graph_edge(Z, Y, "DataFlow").
        // 然后检查是否能从 a 到 d
        // deny("path","reachable") :- graph_edge("a","d","DataFlow").
        let rules = vec![
            // R0: 传递闭包 — 推导新的 graph_edge
            Rule {
                head: Atom::GraphEdge {
                    src: v("X"),
                    dst: v("Y"),
                    kind: c("DataFlow"),
                },
                body: vec![
                    Literal::Pos(Atom::GraphEdge {
                        src: v("X"),
                        dst: v("Z"),
                        kind: c("DataFlow"),
                    }),
                    Literal::Pos(Atom::GraphEdge {
                        src: v("Z"),
                        dst: v("Y"),
                        kind: c("DataFlow"),
                    }),
                ],
            },
            // R1: 如果 a 可达 d，则 deny
            Rule {
                head: deny_atom(c("path"), c("reachable")),
                body: vec![Literal::Pos(Atom::GraphEdge {
                    src: c("a"),
                    dst: c("d"),
                    kind: c("DataFlow"),
                })],
            },
        ];

        // a→b, b→c, c→d — 需要多轮迭代推导 a→c, b→d, a→d
        let facts = vec![
            graph_edge_fact("a", "b", "DataFlow"),
            graph_edge_fact("b", "c", "DataFlow"),
            graph_edge_fact("c", "d", "DataFlow"),
        ];

        let engine = DatalogEngine::new(rules, 100);
        let result = engine.evaluate(facts).unwrap();

        // 应该推导出 a→c, b→d, a→d 等传递边
        assert!(result.has_deny);
        assert_eq!(result.deny_reasons[0], ("path".into(), "reachable".into()));

        // 至少有原始 3 条 + 推导出的传递边 + deny
        assert!(result.facts.len() > 4);

        // 验证推导追踪非空
        assert!(!result.trace.is_empty());
    }

    // ── 额外：基础测试 ──

    #[test]
    fn test_empty_rules_no_deny() {
        let engine = DatalogEngine::new(vec![], 100);
        let result = engine.evaluate(vec![]).unwrap();
        assert!(!result.has_deny);
        assert!(result.facts.is_empty());
    }

    #[test]
    fn test_stratification_no_negative_cycle() {
        // 简单分层：deny 依赖 has_role（否定）
        let rules = vec![Rule {
            head: deny_atom(v("R"), c("x")),
            body: vec![
                Literal::Pos(Atom::Action {
                    id: v("R"),
                    action_type: c("HttpOut"),
                    principal: v("P"),
                    target: v("_"),
                }),
                Literal::Neg(Atom::HasRole {
                    principal: v("P"),
                    role: c("admin"),
                }),
            ],
        }];
        let strata = stratify(&rules).unwrap();
        assert!(!strata.is_empty());
    }
}
