//! Datalog 评估引擎核心

use pcm_policy_dsl::ast::{Atom, Literal, Rule};
use std::collections::HashSet;

/// 评估引擎
pub struct DatalogEngine {
    rules: Vec<Rule>,
    max_iterations: usize,
}

/// 推导追踪记录
#[derive(Debug, Clone)]
pub struct DerivationTrace {
    pub rule_index: usize,
    pub premises: Vec<usize>, // 前提事实在 facts 列表中的索引
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

impl DatalogEngine {
    pub fn new(rules: Vec<Rule>, max_iterations: usize) -> Self {
        Self {
            rules,
            max_iterations,
        }
    }

    /// 在给定基础事实上求不动点
    pub fn evaluate(&self, base_facts: Vec<Atom>) -> EvalResult {
        let mut facts = base_facts;
        let mut trace = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();

        // 将基础事实加入 seen 集
        for f in &facts {
            seen.insert(format!("{:?}", f));
        }

        for _ in 0..self.max_iterations {
            let mut new_facts = Vec::new();

            for (rule_idx, rule) in self.rules.iter().enumerate() {
                // 简化：对 ground 规则，检查 body 是否全满足
                // TODO: 完整的变量绑定/统一
                if self.body_satisfied(&rule.body, &facts) {
                    let key = format!("{:?}", rule.head);
                    if !seen.contains(&key) {
                        seen.insert(key);
                        let premise_indices: Vec<usize> = rule
                            .body
                            .iter()
                            .filter_map(|lit| match lit {
                                Literal::Pos(a) => facts.iter().position(|f| f == a),
                                Literal::Neg(_) => None,
                            })
                            .collect();
                        trace.push(DerivationTrace {
                            rule_index: rule_idx,
                            premises: premise_indices,
                            conclusion: rule.head.clone(),
                        });
                        new_facts.push(rule.head.clone());
                    }
                }
            }

            if new_facts.is_empty() {
                break; // 不动点已达
            }
            facts.extend(new_facts);
        }

        // 检查 deny
        let mut deny_reasons = Vec::new();
        for f in &facts {
            if let Atom::Deny { request, reason } = f
                && let (pcm_policy_dsl::ast::Term::Const(rid), pcm_policy_dsl::ast::Term::Const(r)) =
                    (request, reason)
            {
                deny_reasons.push((rid.clone(), r.clone()));
            }
        }
        let has_deny = !deny_reasons.is_empty();

        EvalResult {
            facts,
            trace,
            has_deny,
            deny_reasons,
        }
    }

    fn body_satisfied(&self, body: &[Literal], facts: &[Atom]) -> bool {
        body.iter().all(|lit| match lit {
            Literal::Pos(a) => facts.contains(a),
            Literal::Neg(a) => !facts.contains(a),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_rules_no_deny() {
        let engine = DatalogEngine::new(vec![], 100);
        let result = engine.evaluate(vec![]);
        assert!(!result.has_deny);
        assert!(result.facts.is_empty());
    }
}
