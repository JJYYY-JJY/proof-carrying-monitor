//! PCM 端到端集成测试 — 5 个 E2E 场景
//!
//! ## 运行方式
//!
//! **Docker Compose（推荐）**:
//! ```bash
//! docker compose -f docker-compose.test.yml up --build --abort-on-container-exit
//! ```
//!
//! **本地运行（需先启动所有服务）**:
//! ```bash
//! PCM_MONITOR_ENDPOINT=http://localhost:50051 \
//! PCM_POLICY_ENDPOINT=http://localhost:50052 \
//! PCM_GRAPH_ENDPOINT=http://localhost:50053 \
//! PCM_AUDIT_ENDPOINT=http://localhost:50054 \
//! cargo test -p pcm-e2e-tests --test e2e -- --test-threads=1
//! ```

use std::time::Duration;

use pcm_common::proto::pcm_v1::{
    ActionType, ActivatePolicyRequest, AppendEventRequest, CompilePolicyRequest,
    CreatePolicyRequest, EdgeKind, EvaluateBatchRequest, EvaluateRequest, GetPolicyRequest,
    GetSnapshotRequest, NodeKind, QueryLogsRequest, ReachableRequest, Request,
    ValidatePolicyRequest, Verdict, decision,
};
use pcm_e2e_tests::test_env::*;

// =====================================================================
// 场景 1: Allow 全流程（Happy Path）
// =====================================================================

/// 场景 1: 验证 ALLOW 全流程
///
/// 1. 使用默认策略（deny unauthorized_http）
/// 2. 发送 Evaluate：principal="admin" + role=http_allowed, action=HttpOut
/// 3. 断言 verdict = ALLOW
/// 4. 断言 evidence 包含有效 Certificate
/// 5. Certificate 的 policy_hash 非空
/// 6. 查询 audit-service → 决策已记录
#[tokio::test]
async fn scenario_1_allow_happy_path() {
    init_tracing();

    let mut env = TestEnv::connect().await;
    let req_id = unique_request_id("e2e-s1-allow");

    // 发送 Evaluate：admin 角色有 http_allowed → ALLOW
    let eval_req = make_evaluate_request_with_attrs(
        &req_id,
        ActionType::HttpOut,
        "admin",
        "https://api.example.com",
        vec![("role", "http_allowed")],
    );

    let resp = tokio::time::timeout(TEST_TIMEOUT, env.monitor.evaluate(eval_req))
        .await
        .expect("evaluate timed out")
        .expect("evaluate RPC failed")
        .into_inner();

    let decision = resp.decision.as_ref().expect("decision should be present");

    // verdict = ALLOW
    let cert = assert_allow(decision);

    // Certificate 的 policy_hash 非空
    assert!(
        !cert.policy_hash.is_empty(),
        "certificate policy_hash should not be empty"
    );
    assert!(
        !cert.request_hash.is_empty(),
        "certificate request_hash should not be empty"
    );

    // 评估时间合理
    assert!(
        resp.evaluation_duration_us < 5_000_000,
        "evaluation took too long: {} µs",
        resp.evaluation_duration_us,
    );

    tracing::info!(
        request_id = %req_id,
        policy_hash_len = cert.policy_hash.len(),
        steps = cert.steps.len(),
        duration_us = resp.evaluation_duration_us,
        "scenario 1: ALLOW happy path ✓"
    );

    // 查询 audit-service 验证决策已记录
    tokio::time::sleep(Duration::from_millis(500)).await;

    let audit_resp = tokio::time::timeout(
        TEST_TIMEOUT,
        env.audit.query_logs(QueryLogsRequest {
            principal: "admin".to_string(),
            limit: 10,
            ..Default::default()
        }),
    )
    .await
    .expect("audit query timed out")
    .expect("audit query RPC failed")
    .into_inner();

    let found = audit_resp.records.iter().any(|r| {
        r.request
            .as_ref()
            .is_some_and(|req| req.request_id == req_id)
    });

    assert!(
        found,
        "audit log should contain decision for request_id={}, found {} records",
        req_id,
        audit_resp.records.len(),
    );

    tracing::info!("scenario 1: audit record verified ✓");
}

// =====================================================================
// 场景 2: Deny 全流程 + Witness 验证
// =====================================================================

/// 场景 2: 验证 DENY + Witness 全流程
///
/// 1. 使用默认策略
/// 2. 发送 Evaluate：principal="guest"（无 http_allowed）, action=HttpOut
/// 3. 断言 verdict = DENY
/// 4. 断言 evidence 包含 Witness
/// 5. Witness 含 deny_rule_id 和 human_readable_reason
/// 6. 查询 audit-service → DENY 决策已记录
#[tokio::test]
async fn scenario_2_deny_with_witness() {
    init_tracing();

    let mut env = TestEnv::connect().await;
    let req_id = unique_request_id("e2e-s2-deny");

    // guest 没有 http_allowed → DENY
    let eval_req = make_evaluate_request(
        &req_id,
        ActionType::HttpOut,
        "guest",
        "https://api.example.com",
    );

    let resp = tokio::time::timeout(TEST_TIMEOUT, env.monitor.evaluate(eval_req))
        .await
        .expect("evaluate timed out")
        .expect("evaluate RPC failed")
        .into_inner();

    let decision = resp.decision.as_ref().expect("decision should be present");

    // verdict = DENY
    let witness = assert_deny(decision);

    // Witness 内容验证
    assert!(
        !witness.deny_rule_id.is_empty(),
        "witness deny_rule_id should not be empty"
    );
    assert!(
        !witness.human_readable_reason.is_empty(),
        "witness human_readable_reason should not be empty"
    );

    // 引用 unauthorized_http 规则
    let rule_matches = witness.deny_rule_id.contains("unauthorized_http")
        || witness.human_readable_reason.contains("unauthorized_http");
    assert!(
        rule_matches,
        "witness should reference 'unauthorized_http', got rule='{}', reason='{}'",
        witness.deny_rule_id, witness.human_readable_reason,
    );

    // policy_hash 和 request_hash 非空
    assert!(
        !witness.policy_hash.is_empty(),
        "witness policy_hash should not be empty"
    );
    assert!(
        !witness.request_hash.is_empty(),
        "witness request_hash should not be empty"
    );

    // decision 元数据
    assert!(
        !decision.policy_version_hash.is_empty(),
        "policy_version_hash should not be empty"
    );

    assert!(
        resp.evaluation_duration_us < 5_000_000,
        "evaluation took too long: {} µs",
        resp.evaluation_duration_us,
    );

    tracing::info!(
        request_id = %req_id,
        deny_rule_id = %witness.deny_rule_id,
        reason = %witness.human_readable_reason,
        "scenario 2: DENY with witness ✓"
    );

    // 查询 audit-service 确认 DENY 已记录
    tokio::time::sleep(Duration::from_millis(500)).await;

    let audit_resp = tokio::time::timeout(
        TEST_TIMEOUT,
        env.audit.query_logs(QueryLogsRequest {
            principal: "guest".to_string(),
            verdict: "DENY".to_string(),
            limit: 10,
            ..Default::default()
        }),
    )
    .await
    .expect("audit query timed out")
    .expect("audit query RPC failed")
    .into_inner();

    let found = audit_resp.records.iter().any(|r| {
        r.request
            .as_ref()
            .is_some_and(|req| req.request_id == req_id)
            && r.decision
                .as_ref()
                .is_some_and(|d| d.verdict == Verdict::Deny as i32)
    });

    assert!(
        found,
        "audit log should contain DENY for request_id={}",
        req_id
    );
    tracing::info!("scenario 2: audit record verified ✓");
}

// =====================================================================
// 场景 3: 图约束评估
// =====================================================================

/// 场景 3: 验证图约束评估
///
/// 1. 向 graph-service 追加节点和边
/// 2. 验证 GetSnapshot 返回正确数据
/// 3. 验证 QueryReachable 路径
/// 4. 验证不可达反向路径
/// 5. 追加更复杂的图结构
#[tokio::test]
async fn scenario_3_graph_constraint_evaluation() {
    init_tracing();

    let mut env = TestEnv::connect().await;
    let session_id = unique_request_id("e2e-s3-graph");

    // ── Step 1: 追加节点和边 ──
    let append_resp = tokio::time::timeout(
        TEST_TIMEOUT,
        env.graph.append_event(AppendEventRequest {
            new_nodes: vec![
                make_graph_node("data-node-1", NodeKind::Data, "Confidential"),
                make_graph_node("target-node-1", NodeKind::Resource, "Public"),
            ],
            new_edges: vec![make_graph_edge(
                "data-node-1",
                "target-node-1",
                EdgeKind::DataFlow,
            )],
            session_id: session_id.clone(),
        }),
    )
    .await
    .expect("append_event timed out")
    .expect("append_event RPC failed")
    .into_inner();

    assert_eq!(append_resp.node_count, 2, "expected 2 nodes");
    assert_eq!(append_resp.edge_count, 1, "expected 1 edge");
    assert!(!append_resp.updated_snapshot_hash.is_empty());

    tracing::info!(
        node_count = append_resp.node_count,
        edge_count = append_resp.edge_count,
        "graph appended ✓"
    );

    // ── Step 2: GetSnapshot 验证 ──
    let snapshot = tokio::time::timeout(
        TEST_TIMEOUT,
        env.graph.get_snapshot(GetSnapshotRequest {
            session_id: session_id.clone(),
        }),
    )
    .await
    .expect("get_snapshot timed out")
    .expect("get_snapshot RPC failed")
    .into_inner();

    assert!(!snapshot.snapshot_hash.is_empty());
    assert!(
        snapshot.nodes.len() >= 2,
        "expected ≥2 nodes, got {}",
        snapshot.nodes.len()
    );
    assert!(
        snapshot.edges.len() >= 1,
        "expected ≥1 edge, got {}",
        snapshot.edges.len()
    );

    // 验证节点标签
    let data_node = snapshot
        .nodes
        .iter()
        .find(|n| n.node_id == "data-node-1")
        .expect("data-node-1 should exist");
    assert_eq!(data_node.label, "Confidential");

    let target_node = snapshot
        .nodes
        .iter()
        .find(|n| n.node_id == "target-node-1")
        .expect("target-node-1 should exist");
    assert_eq!(target_node.label, "Public");

    // 验证边
    let edge = snapshot
        .edges
        .iter()
        .find(|e| e.src == "data-node-1" && e.dst == "target-node-1")
        .expect("edge data-node-1 → target-node-1 should exist");
    assert_eq!(edge.kind, EdgeKind::DataFlow as i32);

    tracing::info!("snapshot verified ✓");

    // ── Step 3: QueryReachable ──
    let reachable = tokio::time::timeout(
        TEST_TIMEOUT,
        env.graph.query_reachable(ReachableRequest {
            from_node: "data-node-1".to_string(),
            to_node: "target-node-1".to_string(),
            edge_filter: vec![],
        }),
    )
    .await
    .expect("query_reachable timed out")
    .expect("query_reachable RPC failed")
    .into_inner();

    assert!(
        reachable.reachable,
        "data-node-1 → target-node-1 should be reachable"
    );
    assert!(!reachable.paths.is_empty(), "paths should not be empty");

    let path = &reachable.paths[0];
    assert!(path.node_ids.contains(&"data-node-1".to_string()));
    assert!(path.node_ids.contains(&"target-node-1".to_string()));

    tracing::info!(paths = reachable.paths.len(), "reachability ✓");

    // ── Step 4: 反向不可达 ──
    let unreachable = tokio::time::timeout(
        TEST_TIMEOUT,
        env.graph.query_reachable(ReachableRequest {
            from_node: "target-node-1".to_string(),
            to_node: "data-node-1".to_string(),
            edge_filter: vec![],
        }),
    )
    .await
    .expect("reverse query timed out")
    .expect("reverse query RPC failed")
    .into_inner();

    assert!(
        !unreachable.reachable,
        "reverse path should NOT be reachable"
    );

    // ── Step 5: 追加更复杂结构 ──
    let append2 = tokio::time::timeout(
        TEST_TIMEOUT,
        env.graph.append_event(AppendEventRequest {
            new_nodes: vec![
                make_graph_node("entity-admin", NodeKind::Entity, "Admin"),
                make_graph_node("action-http-out", NodeKind::Action, "HttpOut"),
            ],
            new_edges: vec![
                make_graph_edge("entity-admin", "action-http-out", EdgeKind::ControlFlow),
                make_graph_edge("action-http-out", "target-node-1", EdgeKind::DataFlow),
            ],
            session_id: session_id.clone(),
        }),
    )
    .await
    .expect("second append timed out")
    .expect("second append RPC failed")
    .into_inner();

    assert!(
        append2.node_count >= 4,
        "expected ≥4 nodes, got {}",
        append2.node_count
    );

    // entity-admin 经 action-http-out 到 target-node-1 可达
    let multi_hop = tokio::time::timeout(
        TEST_TIMEOUT,
        env.graph.query_reachable(ReachableRequest {
            from_node: "entity-admin".to_string(),
            to_node: "target-node-1".to_string(),
            edge_filter: vec![],
        }),
    )
    .await
    .expect("multi-hop query timed out")
    .expect("multi-hop query RPC failed")
    .into_inner();

    assert!(
        multi_hop.reachable,
        "entity-admin → target-node-1 should be reachable"
    );

    tracing::info!("scenario 3: graph constraint evaluation ✓");
}

// =====================================================================
// 场景 4: 策略编译 + 版本管理
// =====================================================================

/// 合法策略 DSL
const VALID_POLICY: &str =
    r#"deny(Req, "e2e_test_rule") :- action(Req, HttpOut, P, _), !has_role(P, "admin")."#;

/// 非法策略 DSL
const INVALID_POLICY: &str = "this is absolutely not valid policy DSL syntax !!!";

/// 场景 4: 策略编译 + 版本管理全流程
///
/// 1. CreatePolicy 创建策略
/// 2. 返回 PolicyVersion 含 content_hash、compiled
/// 3. CompilePolicy 编译同一策略 → 结果一致
/// 4. ValidatePolicy 验证合法策略 → valid = true
/// 5. ValidatePolicy 验证非法策略 → valid = false, errors 非空
/// 6. ActivatePolicy → 激活成功
#[tokio::test]
async fn scenario_4_policy_compile_and_version_management() {
    init_tracing();

    let mut env = TestEnv::connect().await;

    // ── Step 1: CreatePolicy ──
    let created = tokio::time::timeout(
        TEST_TIMEOUT,
        env.policy.create_policy(CreatePolicyRequest {
            source_dsl: VALID_POLICY.to_string(),
            author: "e2e-test-author".to_string(),
            commit_sha: "e2e-test-sha".to_string(),
        }),
    )
    .await
    .expect("create_policy timed out")
    .expect("create_policy RPC failed")
    .into_inner();

    // ── Step 2: 验证 PolicyVersion ──
    assert!(
        !created.policy_id.is_empty(),
        "policy_id should not be empty"
    );
    assert!(!created.version.is_empty(), "version should not be empty");
    assert!(
        !created.content_hash.is_empty(),
        "content_hash should not be empty"
    );
    assert!(created.compiled.is_some(), "compiled should be present");

    let compiled_v = created.compiled.as_ref().unwrap();
    assert!(
        !compiled_v.content.is_empty(),
        "compiled content should not be empty"
    );
    assert!(
        !compiled_v.content_hash.is_empty(),
        "compiled content_hash should not be empty"
    );

    assert_eq!(created.author, "e2e-test-author");
    assert_eq!(created.commit_sha, "e2e-test-sha");
    assert_eq!(created.source_dsl, VALID_POLICY);

    tracing::info!(
        policy_id = %created.policy_id,
        version = %created.version,
        "policy created ✓"
    );

    // ── Step 3: CompilePolicy → 结果一致 ──
    let compile_resp = tokio::time::timeout(
        TEST_TIMEOUT,
        env.policy.compile_policy(CompilePolicyRequest {
            source_dsl: VALID_POLICY.to_string(),
        }),
    )
    .await
    .expect("compile_policy timed out")
    .expect("compile_policy RPC failed")
    .into_inner();

    assert!(
        compile_resp.compiled.is_some(),
        "compiled should be present"
    );

    let compiled = compile_resp.compiled.as_ref().unwrap();
    assert!(!compiled.content.is_empty());
    assert!(!compiled.content_hash.is_empty());
    assert!(compile_resp.decidable, "simple policy should be decidable");

    // content_hash 一致
    assert_eq!(
        compiled.content_hash, compiled_v.content_hash,
        "CompilePolicy and CreatePolicy hash should match"
    );

    tracing::info!("compile matches create ✓");

    // ── Step 4: ValidatePolicy — 合法 ──
    let valid_resp = tokio::time::timeout(
        TEST_TIMEOUT,
        env.policy.validate_policy(ValidatePolicyRequest {
            source_dsl: VALID_POLICY.to_string(),
        }),
    )
    .await
    .expect("validate_policy timed out")
    .expect("validate_policy RPC failed")
    .into_inner();

    assert!(valid_resp.valid, "valid policy should pass validation");
    assert!(
        valid_resp.errors.is_empty(),
        "should have no errors: {:?}",
        valid_resp.errors
    );

    tracing::info!("validate valid DSL ✓");

    // ── Step 5: ValidatePolicy — 非法 ──
    let invalid_resp = tokio::time::timeout(
        TEST_TIMEOUT,
        env.policy.validate_policy(ValidatePolicyRequest {
            source_dsl: INVALID_POLICY.to_string(),
        }),
    )
    .await
    .expect("validate_policy (invalid) timed out")
    .expect("validate_policy (invalid) RPC failed")
    .into_inner();

    assert!(!invalid_resp.valid, "invalid policy should fail validation");
    assert!(!invalid_resp.errors.is_empty(), "should have errors");

    tracing::info!(errors = ?invalid_resp.errors, "validate invalid DSL ✓");

    // ── Step 6: ActivatePolicy ──
    let activate_resp = tokio::time::timeout(
        TEST_TIMEOUT,
        env.policy.activate_policy(ActivatePolicyRequest {
            policy_id: created.policy_id.clone(),
            version: created.version.clone(),
        }),
    )
    .await
    .expect("activate_policy timed out")
    .expect("activate_policy RPC failed")
    .into_inner();

    assert!(activate_resp.activated, "activation should succeed");
    assert_eq!(activate_resp.active_version, created.version);

    tracing::info!(
        active_version = %activate_resp.active_version,
        "policy activated ✓"
    );

    // ── 额外验证: GetPolicy 持久化 ──
    let fetched = tokio::time::timeout(
        TEST_TIMEOUT,
        env.policy.get_policy(GetPolicyRequest {
            policy_id: created.policy_id.clone(),
            version: created.version.clone(),
        }),
    )
    .await
    .expect("get_policy timed out")
    .expect("get_policy RPC failed")
    .into_inner();

    assert_eq!(fetched.policy_id, created.policy_id);
    assert_eq!(fetched.version, created.version);
    assert_eq!(fetched.source_dsl, VALID_POLICY);

    tracing::info!("scenario 4: policy lifecycle ✓");
}

// =====================================================================
// 场景 5: Fail-Closed 行为
// =====================================================================

/// 场景 5a: 缺少 request → INVALID_ARGUMENT
#[tokio::test]
async fn scenario_5_fail_closed_missing_request() {
    init_tracing();

    let mut env = TestEnv::connect().await;

    let req = EvaluateRequest {
        request: None,
        dry_run: false,
    };

    let result = tokio::time::timeout(TEST_TIMEOUT, env.monitor.evaluate(req))
        .await
        .expect("evaluate timed out");

    match result {
        Err(status) => {
            assert_eq!(
                status.code(),
                tonic::Code::InvalidArgument,
                "missing request → INVALID_ARGUMENT, got {:?}: {}",
                status.code(),
                status.message(),
            );
            tracing::info!("missing request → INVALID_ARGUMENT ✓");
        }
        Ok(resp) => {
            let d = resp.into_inner().decision;
            if let Some(d) = &d {
                assert_ne!(
                    d.verdict,
                    Verdict::Allow as i32,
                    "fail-closed: must not ALLOW"
                );
            }
        }
    }
}

/// 场景 5b: 空 request_id → INVALID_ARGUMENT
#[tokio::test]
async fn scenario_5_fail_closed_empty_request_id() {
    init_tracing();

    let mut env = TestEnv::connect().await;

    let req = EvaluateRequest {
        request: Some(Request {
            request_id: String::new(),
            action_type: ActionType::ToolCall.into(),
            principal: "agent-1".to_string(),
            target: "resource-1".to_string(),
            attributes: Default::default(),
            timestamp: None,
            context_hash: vec![],
        }),
        dry_run: false,
    };

    let result = tokio::time::timeout(TEST_TIMEOUT, env.monitor.evaluate(req))
        .await
        .expect("evaluate timed out");

    match result {
        Err(status) => {
            assert_eq!(
                status.code(),
                tonic::Code::InvalidArgument,
                "empty request_id → INVALID_ARGUMENT, got {:?}: {}",
                status.code(),
                status.message(),
            );
            assert!(
                status.message().contains("request_id"),
                "error should mention request_id: {}",
                status.message(),
            );
            tracing::info!("empty request_id → INVALID_ARGUMENT ✓");
        }
        Ok(resp) => {
            let d = resp.into_inner().decision;
            if let Some(d) = &d {
                assert_ne!(
                    d.verdict,
                    Verdict::Allow as i32,
                    "fail-closed: must not ALLOW"
                );
            }
        }
    }
}

/// 场景 5c: UNSPECIFIED action_type → INVALID_ARGUMENT
#[tokio::test]
async fn scenario_5_fail_closed_unspecified_action_type() {
    init_tracing();

    let mut env = TestEnv::connect().await;

    let req = EvaluateRequest {
        request: Some(Request {
            request_id: unique_request_id("e2e-s5-unspec"),
            action_type: ActionType::Unspecified.into(),
            principal: "agent-1".to_string(),
            target: "resource-1".to_string(),
            attributes: Default::default(),
            timestamp: None,
            context_hash: vec![],
        }),
        dry_run: false,
    };

    let result = tokio::time::timeout(TEST_TIMEOUT, env.monitor.evaluate(req))
        .await
        .expect("evaluate timed out");

    match result {
        Err(status) => {
            assert_eq!(
                status.code(),
                tonic::Code::InvalidArgument,
                "UNSPECIFIED → INVALID_ARGUMENT, got {:?}: {}",
                status.code(),
                status.message(),
            );
            assert!(
                status.message().contains("action_type"),
                "error should mention action_type: {}",
                status.message(),
            );
            tracing::info!("UNSPECIFIED action_type → INVALID_ARGUMENT ✓");
        }
        Ok(resp) => {
            let d = resp.into_inner().decision;
            if let Some(d) = &d {
                assert_ne!(
                    d.verdict,
                    Verdict::Allow as i32,
                    "fail-closed: must not ALLOW"
                );
            }
        }
    }
}

/// 场景 5d: 综合检查无 ALLOW 泄漏
#[tokio::test]
async fn scenario_5_no_allow_leaks() {
    init_tracing();

    let mut env = TestEnv::connect().await;

    let bad_requests: Vec<(&str, EvaluateRequest)> = vec![
        (
            "missing_request",
            EvaluateRequest {
                request: None,
                dry_run: false,
            },
        ),
        (
            "empty_request_id",
            EvaluateRequest {
                request: Some(Request {
                    request_id: String::new(),
                    action_type: ActionType::HttpOut.into(),
                    principal: "test".to_string(),
                    target: "test".to_string(),
                    attributes: Default::default(),
                    timestamp: None,
                    context_hash: vec![],
                }),
                dry_run: false,
            },
        ),
        (
            "unspecified_action",
            EvaluateRequest {
                request: Some(Request {
                    request_id: unique_request_id("e2e-s5-bad"),
                    action_type: ActionType::Unspecified.into(),
                    principal: "test".to_string(),
                    target: "test".to_string(),
                    attributes: Default::default(),
                    timestamp: None,
                    context_hash: vec![],
                }),
                dry_run: false,
            },
        ),
    ];

    for (label, req) in bad_requests {
        let result = tokio::time::timeout(TEST_TIMEOUT, env.monitor.evaluate(req))
            .await
            .expect("evaluate timed out");

        match result {
            Err(status) => {
                tracing::info!(label, code = ?status.code(), "error (fail-closed) ✓");
            }
            Ok(resp) => {
                if let Some(d) = &resp.into_inner().decision {
                    assert_ne!(
                        d.verdict,
                        Verdict::Allow as i32,
                        "fail-closed violation: '{}' returned ALLOW",
                        label,
                    );
                }
            }
        }
    }

    tracing::info!("no ALLOW leaks ✓");
}

/// 场景 5e: 批量评估：正常 + 异常请求结果独立
#[tokio::test]
async fn scenario_5_batch_mixed_requests() {
    init_tracing();

    let mut env = TestEnv::connect().await;

    let good_id = unique_request_id("e2e-s5-batch-good");
    let deny_id = unique_request_id("e2e-s5-batch-deny");

    // ToolCall → ALLOW（不匹配默认 deny 规则）
    let good_req = make_evaluate_request(&good_id, ActionType::ToolCall, "admin", "resource-1");

    // HttpOut guest → DENY（匹配 unauthorized_http）
    let deny_req = make_evaluate_request(
        &deny_id,
        ActionType::HttpOut,
        "guest",
        "https://evil.example.com",
    );

    let batch = EvaluateBatchRequest {
        requests: vec![good_req, deny_req],
    };

    let resp = tokio::time::timeout(TEST_TIMEOUT, env.monitor.evaluate_batch(batch))
        .await
        .expect("batch timed out")
        .expect("batch RPC failed")
        .into_inner();

    assert_eq!(resp.responses.len(), 2, "batch should return 2 responses");

    // 第一个：ToolCall → ALLOW
    let d1 = resp.responses[0].decision.as_ref().expect("decision 0");
    assert_eq!(d1.request_id, good_id);
    assert_eq!(d1.verdict, Verdict::Allow as i32, "ToolCall → ALLOW");
    match &d1.evidence {
        Some(decision::Evidence::Certificate(_)) => {}
        other => panic!("ALLOW should have Certificate, got {:?}", other),
    }

    // 第二个：HttpOut guest → DENY
    let d2 = resp.responses[1].decision.as_ref().expect("decision 1");
    assert_eq!(d2.request_id, deny_id);
    assert_eq!(d2.verdict, Verdict::Deny as i32, "HttpOut guest → DENY");
    match &d2.evidence {
        Some(decision::Evidence::Witness(w)) => {
            assert!(!w.deny_rule_id.is_empty());
            assert!(!w.human_readable_reason.is_empty());
        }
        other => panic!("DENY should have Witness, got {:?}", other),
    }

    tracing::info!("scenario 5: batch mixed requests ✓");
}
