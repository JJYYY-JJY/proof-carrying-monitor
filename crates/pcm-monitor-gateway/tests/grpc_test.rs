//! 集成测试：MonitorService gRPC

use pcm_common::proto::pcm_v1::{
    ActionType, EvaluateRequest, HealthRequest, Request, Verdict,
    monitor_service_client::MonitorServiceClient, monitor_service_server::MonitorServiceServer,
};
use pcm_monitor_gateway::service::MonitorServiceImpl;
use tonic::transport::Server;

/// 在随机端口启动测试服务器，返回 (连接地址, 服务实例 Arc)
async fn start_test_server() -> String {
    let svc = MonitorServiceImpl::new();
    start_test_server_with(svc).await
}

/// 启动带自定义服务实例的测试服务器
async fn start_test_server_with(svc: MonitorServiceImpl) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        Server::builder()
            .add_service(MonitorServiceServer::new(svc))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    format!("http://{addr}")
}

/// 启动带策略的测试服务器
async fn start_test_server_with_policy(policy_src: &str) -> String {
    let svc = MonitorServiceImpl::new();
    svc.load_policy(policy_src).expect("policy should compile");
    start_test_server_with(svc).await
}

/// 构造一个合法的 EvaluateRequest
fn make_evaluate_request(request_id: &str) -> EvaluateRequest {
    EvaluateRequest {
        request: Some(Request {
            request_id: request_id.to_string(),
            action_type: ActionType::ToolCall.into(),
            principal: "agent-1".to_string(),
            target: "resource-1".to_string(),
            attributes: Default::default(),
            timestamp: None,
            context_hash: vec![],
        }),
        dry_run: false,
    }
}

/// 构造带自定义参数的 EvaluateRequest
fn make_evaluate_request_custom(
    request_id: &str,
    action_type: ActionType,
    principal: &str,
    target: &str,
) -> EvaluateRequest {
    EvaluateRequest {
        request: Some(Request {
            request_id: request_id.to_string(),
            action_type: action_type.into(),
            principal: principal.to_string(),
            target: target.to_string(),
            attributes: Default::default(),
            timestamp: None,
            context_hash: vec![],
        }),
        dry_run: false,
    }
}

// ──────────────────────────────────────────────
// 基础测试（无策略 → 默认 Allow）
// ──────────────────────────────────────────────

#[tokio::test]
async fn test_evaluate_allow_no_policy() {
    // 无策略加载时，无 deny 规则 → 应该 Allow
    let addr = start_test_server().await;
    let mut client = MonitorServiceClient::connect(addr).await.unwrap();

    let resp = client
        .evaluate(make_evaluate_request("req-001"))
        .await
        .unwrap()
        .into_inner();

    let decision = resp.decision.expect("decision should be present");
    assert_eq!(decision.request_id, "req-001");
    assert_eq!(decision.verdict, Verdict::Allow as i32);
    assert!(resp.evaluation_duration_us < 1_000_000); // 应在 1 秒内

    // Allow 时应有 Certificate evidence
    assert!(
        decision.evidence.is_some(),
        "Allow decision should have evidence"
    );
    match decision.evidence.unwrap() {
        pcm_common::proto::pcm_v1::decision::Evidence::Certificate(_cert) => {
            // OK — 空策略的 Allow 证书
        }
        _ => panic!("expected Certificate evidence for Allow verdict"),
    }
}

#[tokio::test]
async fn test_evaluate_missing_request() {
    let addr = start_test_server().await;
    let mut client = MonitorServiceClient::connect(addr).await.unwrap();

    let req = EvaluateRequest {
        request: None,
        dry_run: false,
    };

    let status = client.evaluate(req).await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert!(status.message().contains("missing request"));
}

#[tokio::test]
async fn test_evaluate_empty_request_id() {
    let addr = start_test_server().await;
    let mut client = MonitorServiceClient::connect(addr).await.unwrap();

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

    let status = client.evaluate(req).await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert!(status.message().contains("empty request_id"));
}

#[tokio::test]
async fn test_evaluate_unspecified_action_type() {
    let addr = start_test_server().await;
    let mut client = MonitorServiceClient::connect(addr).await.unwrap();

    let req = EvaluateRequest {
        request: Some(Request {
            request_id: "req-bad-action".to_string(),
            action_type: ActionType::Unspecified.into(),
            principal: "agent-1".to_string(),
            target: "resource-1".to_string(),
            attributes: Default::default(),
            timestamp: None,
            context_hash: vec![],
        }),
        dry_run: false,
    };

    let status = client.evaluate(req).await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert!(status.message().contains("action_type"));
}

#[tokio::test]
async fn test_health() {
    let addr = start_test_server().await;
    let mut client = MonitorServiceClient::connect(addr).await.unwrap();

    let resp = client.health(HealthRequest {}).await.unwrap().into_inner();

    assert!(resp.healthy);
    // policy_version 应为非空（默认策略的哈希）
    assert!(!resp.policy_version.is_empty());
}

#[tokio::test]
async fn test_evaluate_batch() {
    let addr = start_test_server().await;
    let mut client = MonitorServiceClient::connect(addr).await.unwrap();

    let batch_req = pcm_common::proto::pcm_v1::EvaluateBatchRequest {
        requests: vec![
            make_evaluate_request("batch-001"),
            make_evaluate_request("batch-002"),
        ],
    };

    let resp = client.evaluate_batch(batch_req).await.unwrap().into_inner();

    assert_eq!(resp.responses.len(), 2);
    for (i, r) in resp.responses.iter().enumerate() {
        let decision = r.decision.as_ref().expect("decision should be present");
        assert_eq!(decision.verdict, Verdict::Allow as i32);
        assert_eq!(decision.request_id, format!("batch-{:03}", i + 1));
    }
}

// ──────────────────────────────────────────────
// 策略评估测试
// ──────────────────────────────────────────────

#[tokio::test]
async fn test_evaluate_deny_with_policy() {
    // 加载一条简单 deny 规则：所有 HttpOut 动作被拒绝
    let policy_src = r#"deny(Req, "http_blocked") :- action(Req, "HttpOut", _, _)."#;
    let addr = start_test_server_with_policy(policy_src).await;
    let mut client = MonitorServiceClient::connect(addr).await.unwrap();

    // HttpOut 请求应被 deny
    let resp = client
        .evaluate(make_evaluate_request_custom(
            "req-deny-001",
            ActionType::HttpOut,
            "agent-1",
            "external-api",
        ))
        .await
        .unwrap()
        .into_inner();

    let decision = resp.decision.expect("decision should be present");
    assert_eq!(decision.request_id, "req-deny-001");
    assert_eq!(decision.verdict, Verdict::Deny as i32);

    // Deny 时应有 Witness evidence
    match decision.evidence {
        Some(pcm_common::proto::pcm_v1::decision::Evidence::Witness(witness)) => {
            assert!(!witness.deny_rule_id.is_empty());
            assert!(!witness.human_readable_reason.is_empty());
        }
        _ => panic!("expected Witness evidence for Deny verdict"),
    }
}

#[tokio::test]
async fn test_evaluate_allow_with_policy_non_matching() {
    // 加载一条 deny 规则：只拒绝 HttpOut
    let policy_src = r#"deny(Req, "http_blocked") :- action(Req, "HttpOut", _, _)."#;
    let addr = start_test_server_with_policy(policy_src).await;
    let mut client = MonitorServiceClient::connect(addr).await.unwrap();

    // ToolCall 请求不匹配 deny 规则 → 应该 Allow
    let resp = client
        .evaluate(make_evaluate_request_custom(
            "req-allow-001",
            ActionType::ToolCall,
            "agent-1",
            "resource-1",
        ))
        .await
        .unwrap()
        .into_inner();

    let decision = resp.decision.expect("decision should be present");
    assert_eq!(decision.request_id, "req-allow-001");
    assert_eq!(decision.verdict, Verdict::Allow as i32);

    // Allow 时应有 Certificate evidence
    match decision.evidence {
        Some(pcm_common::proto::pcm_v1::decision::Evidence::Certificate(cert)) => {
            // 有规则的 Allow 证书应有有效的哈希
            assert!(!cert.policy_hash.is_empty());
            assert!(!cert.request_hash.is_empty());
        }
        _ => panic!("expected Certificate evidence for Allow verdict"),
    }
}

#[tokio::test]
async fn test_evaluate_dry_run() {
    // dry_run 模式仍应正常评估
    let policy_src = r#"deny(Req, "http_blocked") :- action(Req, "HttpOut", _, _)."#;
    let addr = start_test_server_with_policy(policy_src).await;
    let mut client = MonitorServiceClient::connect(addr).await.unwrap();

    let mut req = make_evaluate_request_custom(
        "req-dry-001",
        ActionType::HttpOut,
        "agent-1",
        "external-api",
    );
    req.dry_run = true;

    let resp = client.evaluate(req).await.unwrap().into_inner();
    let decision = resp.decision.expect("decision should be present");

    // dry_run 不影响评估结果
    assert_eq!(decision.verdict, Verdict::Deny as i32);
}

// ──────────────────────────────────────────────
// graph-service 降级测试
// ──────────────────────────────────────────────

#[tokio::test]
async fn test_evaluate_without_graph_service() {
    // 无 graph-service 连接时仍正常工作（降级模式）
    let addr = start_test_server().await;
    let mut client = MonitorServiceClient::connect(addr).await.unwrap();

    let resp = client
        .evaluate(make_evaluate_request("req-degraded-001"))
        .await
        .unwrap()
        .into_inner();

    let decision = resp.decision.expect("decision should be present");
    assert_eq!(decision.verdict, Verdict::Allow as i32);
    // 降级模式下 graph_snapshot_hash 为空
    assert!(decision.graph_snapshot_hash.is_empty());
}

// ──────────────────────────────────────────────
// 策略版本与 policy_version_hash 测试
// ──────────────────────────────────────────────

#[tokio::test]
async fn test_decision_has_policy_version_hash() {
    let policy_src = r#"deny(Req, "test") :- action(Req, "HttpOut", _, _)."#;
    let addr = start_test_server_with_policy(policy_src).await;
    let mut client = MonitorServiceClient::connect(addr).await.unwrap();

    let resp = client
        .evaluate(make_evaluate_request("req-hash-001"))
        .await
        .unwrap()
        .into_inner();

    let decision = resp.decision.expect("decision should be present");
    // policy_version_hash 应非空
    assert!(
        !decision.policy_version_hash.is_empty(),
        "policy_version_hash should be set"
    );
}
