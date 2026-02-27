//! 属性测试：随机策略 + 请求 → 证书/witness 总有一个
//!
//! 使用 proptest 框架验证核心不变量：
//! 对任意合法的策略+请求组合，系统总是能产出一个有效的证书（Allow）
//! 或一个有效的 witness（Deny），且验证通过。

use std::collections::HashSet;

use proptest::prelude::*;

use pcm_cert::generator::{generate_certificate, generate_witness};
use pcm_cert_checker_ffi::{verify_certificate_structured, verify_witness_structured};
use pcm_common::hash::blake3_hash;
use pcm_datalog_engine::DatalogEngine;
use pcm_policy_dsl::ast::{Atom, Literal, Rule, Term};

// ──────────────────────────────────────────────
// Proptest Strategies
// ──────────────────────────────────────────────

fn arb_request_id() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("req1".to_string()),
        Just("req2".to_string()),
        Just("req3".to_string()),
        Just("req4".to_string()),
        Just("req5".to_string()),
    ]
}

fn arb_action_type() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("ToolCall".to_string()),
        Just("HttpOut".to_string()),
        Just("DbWrite".to_string()),
        Just("DbReadSensitive".to_string()),
        Just("FileWrite".to_string()),
    ]
}

fn arb_principal() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("alice".to_string()),
        Just("bob".to_string()),
        Just("charlie".to_string()),
        Just("dave".to_string()),
        Just("eve".to_string()),
    ]
}

fn arb_target() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("api.com".to_string()),
        Just("db.internal".to_string()),
        Just("file.txt".to_string()),
        Just("service.local".to_string()),
    ]
}

fn arb_role() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("http_allowed".to_string()),
        Just("tool_user".to_string()),
        Just("auditor".to_string()),
        Just("admin".to_string()),
        Just("reader".to_string()),
    ]
}

fn arb_label() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("Public".to_string()),
        Just("Internal".to_string()),
        Just("Confidential".to_string()),
        Just("Secret".to_string()),
    ]
}

fn arb_node_id() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("n1".to_string()),
        Just("n2".to_string()),
        Just("n3".to_string()),
        Just("n4".to_string()),
        Just("n5".to_string()),
    ]
}

fn arb_edge_kind() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("data_flow".to_string()),
        Just("control_flow".to_string()),
        Just("causal".to_string()),
        Just("temporal".to_string()),
    ]
}

fn arb_data_name() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("user_data".to_string()),
        Just("payment_info".to_string()),
        Just("log_entry".to_string()),
        Just("config".to_string()),
    ]
}

fn arb_reason() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("unauthorized_http".to_string()),
        Just("sensitive_data_leak".to_string()),
        Just("role_violation".to_string()),
        Just("flow_violation".to_string()),
        Just("access_denied".to_string()),
    ]
}

/// 随机生成 ground atom（仅常量，用于事实）
fn arb_ground_atom() -> impl Strategy<Value = Atom> {
    prop_oneof![
        // action(id, type, principal, target)
        (arb_request_id(), arb_action_type(), arb_principal(), arb_target())
            .prop_map(|(id, at, p, t)| Atom::Action {
                id: Term::Const(id),
                action_type: Term::Const(at),
                principal: Term::Const(p),
                target: Term::Const(t),
            }),
        // has_role(principal, role)
        (arb_principal(), arb_role())
            .prop_map(|(p, r)| Atom::HasRole {
                principal: Term::Const(p),
                role: Term::Const(r),
            }),
        // data_label(data, label)
        (arb_data_name(), arb_label())
            .prop_map(|(d, l)| Atom::DataLabel {
                data: Term::Const(d),
                label: Term::Const(l),
            }),
        // graph_edge(src, dst, kind)
        (arb_node_id(), arb_node_id(), arb_edge_kind())
            .prop_map(|(s, d, k)| Atom::GraphEdge {
                src: Term::Const(s),
                dst: Term::Const(d),
                kind: Term::Const(k),
            }),
        // graph_label(node, label)
        (arb_node_id(), arb_label())
            .prop_map(|(n, l)| Atom::GraphLabel {
                node: Term::Const(n),
                label: Term::Const(l),
            }),
    ]
}

/// 额外 body 文字（除了首个 Action 文字外）。
/// 使用变量 P（从 Action 绑定）来约束 has_role。
fn arb_extra_body_literal() -> impl Strategy<Value = Literal> {
    prop_oneof![
        // 正 has_role — P 引用 Action 中的 principal
        arb_role().prop_map(|r| Literal::Pos(Atom::HasRole {
            principal: Term::Var("P".to_string()),
            role: Term::Const(r),
        })),
        // 负 has_role — P 引用 Action 中的 principal
        arb_role().prop_map(|r| Literal::Neg(Atom::HasRole {
            principal: Term::Var("P".to_string()),
            role: Term::Const(r),
        })),
        // 正 data_label（ground）
        (arb_data_name(), arb_label())
            .prop_map(|(d, l)| Literal::Pos(Atom::DataLabel {
                data: Term::Const(d),
                label: Term::Const(l),
            })),
        // 正 graph_edge（ground）
        (arb_node_id(), arb_node_id(), arb_edge_kind())
            .prop_map(|(s, d, k)| Literal::Pos(Atom::GraphEdge {
                src: Term::Const(s),
                dst: Term::Const(d),
                kind: Term::Const(k),
            })),
        // 正 graph_label（ground）
        (arb_node_id(), arb_label())
            .prop_map(|(n, l)| Literal::Pos(Atom::GraphLabel {
                node: Term::Const(n),
                label: Term::Const(l),
            })),
    ]
}

/// 随机生成 deny 规则。
///
/// head = `deny(Req, "reason")`
/// body = `[action(Req, <const_type>, P, <const_target>), ...extra]`
///
/// 首个 body 文字始终是 Action，绑定 Req 和 P；
/// 后续 0–3 个额外约束可引用 P 或使用 ground 谓词。
fn arb_deny_rule() -> impl Strategy<Value = Rule> {
    (
        arb_reason(),
        arb_action_type(),
        arb_target(),
        prop::collection::vec(arb_extra_body_literal(), 0..=3),
    )
        .prop_map(|(reason, action_type, target, extra_lits)| {
            let mut body = vec![Literal::Pos(Atom::Action {
                id: Term::Var("Req".into()),
                action_type: Term::Const(action_type),
                principal: Term::Var("P".into()),
                target: Term::Const(target),
            })];
            body.extend(extra_lits);
            Rule {
                head: Atom::Deny {
                    request: Term::Var("Req".into()),
                    reason: Term::Const(reason),
                },
                body,
            }
        })
}

/// 随机策略（1–5 条 deny 规则）+ 事实（1–20 个 ground atom）
fn arb_policy_and_facts() -> impl Strategy<Value = (Vec<Rule>, Vec<Atom>)> {
    (
        prop::collection::vec(arb_deny_rule(), 1..=5),
        prop::collection::vec(arb_ground_atom(), 1..=20),
    )
}

// ──────────────────────────────────────────────
// 辅助函数
// ──────────────────────────────────────────────

/// 计算策略、图、请求哈希值（与 verify 端一致）。
///
/// - `policy_hash`  = blake3(serde_json(rules))
/// - `request_hash` = blake3(serde_json(Action atoms from base_facts))
/// - `graph_hash`   = blake3(serde_json(non-Action atoms from base_facts))
fn compute_hashes(rules: &[Rule], base_facts: &[Atom]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let policy_hash = blake3_hash(&serde_json::to_vec(rules).unwrap());

    let request_facts: Vec<&Atom> = base_facts
        .iter()
        .filter(|a| matches!(a, Atom::Action { .. }))
        .collect();
    let request_hash = blake3_hash(&serde_json::to_vec(&request_facts).unwrap());

    let graph_facts: Vec<&Atom> = base_facts
        .iter()
        .filter(|a| !matches!(a, Atom::Action { .. }))
        .collect();
    let graph_hash = blake3_hash(&serde_json::to_vec(&graph_facts).unwrap());

    (policy_hash, graph_hash, request_hash)
}

/// 从 base_facts 中提取 Action atoms（owned），用于 verify_certificate_structured 参数。
fn extract_request_facts(base_facts: &[Atom]) -> Vec<Atom> {
    base_facts
        .iter()
        .filter(|a| matches!(a, Atom::Action { .. }))
        .cloned()
        .collect()
}

// ──────────────────────────────────────────────
// 属性测试
// ──────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// 属性 1：完备性（Completeness）
    ///
    /// 对任意合法策略+请求，系统总是能产出一个有效的证书（Allow）
    /// 或一个有效的 witness（Deny），且验证通过。
    #[test]
    fn prop_always_cert_or_witness(
        (rules, base_facts) in arb_policy_and_facts()
    ) {
        let engine = DatalogEngine::new(rules.clone(), 1000);
        let eval = engine.evaluate(base_facts.clone())
            .expect("evaluate should succeed for well-formed rules");

        let (policy_hash, graph_hash, request_hash) = compute_hashes(&rules, &base_facts);

        if eval.has_deny {
            // 必须能生成有效 witness
            let witness = generate_witness(&eval, &rules, policy_hash, request_hash)
                .expect("witness generation should succeed for deny");
            let verify = verify_witness_structured(&witness, &rules, &base_facts);
            prop_assert!(verify.valid, "witness should be valid: {:?}", verify.error);
        } else {
            // 必须能生成有效证书
            let request_facts = extract_request_facts(&base_facts);
            let cert = generate_certificate(
                &eval, &rules, policy_hash, graph_hash, request_hash,
            )
            .expect("cert generation should succeed for allow");
            let verify = verify_certificate_structured(
                &cert, &request_facts, &rules, &base_facts,
            );
            prop_assert!(verify.valid, "certificate should be valid: {:?}", verify.error);
        }
    }

    /// 属性 2：互斥性（Mutual Exclusion）
    ///
    /// 证书和 witness 不会同时生成成功——恰好一个成功。
    #[test]
    fn prop_cert_and_witness_mutually_exclusive(
        (rules, base_facts) in arb_policy_and_facts()
    ) {
        let engine = DatalogEngine::new(rules.clone(), 1000);
        let eval = engine.evaluate(base_facts.clone())
            .expect("evaluate should succeed");

        let (policy_hash, graph_hash, request_hash) = compute_hashes(&rules, &base_facts);

        let cert_ok = generate_certificate(
            &eval, &rules, policy_hash, graph_hash, request_hash,
        )
        .is_ok();
        let witness_ok = generate_witness(&eval, &rules, policy_hash, request_hash).is_ok();

        prop_assert!(
            cert_ok != witness_ok,
            "exactly one of cert/witness should succeed (cert: {}, witness: {})",
            cert_ok,
            witness_ok
        );
    }

    /// 属性 3：确定性（Determinism）
    ///
    /// 相同输入产生相同评估结果。
    #[test]
    fn prop_evaluation_deterministic(
        (rules, base_facts) in arb_policy_and_facts()
    ) {
        let engine = DatalogEngine::new(rules.clone(), 1000);
        let eval1 = engine.evaluate(base_facts.clone())
            .expect("evaluate 1 should succeed");
        let eval2 = engine.evaluate(base_facts.clone())
            .expect("evaluate 2 should succeed");

        prop_assert_eq!(eval1.has_deny, eval2.has_deny);
        prop_assert_eq!(eval1.deny_reasons, eval2.deny_reasons);

        // 事实集可能顺序不同（理论上确定性引擎顺序也一致）但内容必须相同
        let set1: HashSet<_> = eval1.facts.iter().collect();
        let set2: HashSet<_> = eval2.facts.iter().collect();
        prop_assert_eq!(set1, set2);
    }

    /// 属性 4：篡改检测（Tamper Detection）
    ///
    /// 修改 policy_hash 后证书验证应失败。
    #[test]
    fn prop_tampered_cert_rejected(
        (rules, base_facts) in arb_policy_and_facts()
    ) {
        let engine = DatalogEngine::new(rules.clone(), 1000);
        let eval = engine.evaluate(base_facts.clone())
            .expect("evaluate should succeed");

        if !eval.has_deny {
            let (policy_hash, graph_hash, request_hash) =
                compute_hashes(&rules, &base_facts);
            let request_facts = extract_request_facts(&base_facts);

            let cert = generate_certificate(
                &eval, &rules, policy_hash, graph_hash, request_hash,
            )
            .expect("cert generation should succeed for allow");

            // 篡改 policy_hash
            let mut tampered = cert.clone();
            tampered.policy_hash[0] ^= 0xff;
            let verify = verify_certificate_structured(
                &tampered, &request_facts, &rules, &base_facts,
            );
            prop_assert!(!verify.valid, "tampered cert should be rejected");
        }
    }
}
