//! 测试环境管理 — 连接已运行的 PCM 服务
//!
//! 从环境变量读取各服务端点，提供 gRPC 客户端封装。
//! 包含 wait-for-ready 轮询逻辑以等待服务可用。

use std::time::Duration;

use pcm_common::proto::pcm_v1::{
    ActionType, Decision, EvaluateBatchRequest, EvaluateRequest, GraphEdge, GraphNode,
    HealthRequest, Request, Verdict, audit_service_client::AuditServiceClient,
    graph_service_client::GraphServiceClient, monitor_service_client::MonitorServiceClient,
    policy_service_client::PolicyServiceClient,
};
use tonic::transport::Channel;

/// 默认服务端点
const DEFAULT_MONITOR_ENDPOINT: &str = "http://localhost:50051";
const DEFAULT_POLICY_ENDPOINT: &str = "http://localhost:50052";
const DEFAULT_GRAPH_ENDPOINT: &str = "http://localhost:50053";
const DEFAULT_AUDIT_ENDPOINT: &str = "http://localhost:50054";
const RUN_E2E_ENV: &str = "PCM_RUN_E2E";

/// 健康检查最大重试次数
const HEALTH_CHECK_MAX_RETRIES: u32 = 30;
/// 健康检查重试间隔
const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(2);
/// 单个测试超时
pub const TEST_TIMEOUT: Duration = Duration::from_secs(30);

/// 端到端测试环境，封装所有 gRPC 客户端连接
pub struct TestEnv {
    pub monitor: MonitorServiceClient<Channel>,
    pub policy: PolicyServiceClient<Channel>,
    pub graph: GraphServiceClient<Channel>,
    pub audit: AuditServiceClient<Channel>,
}

impl TestEnv {
    pub async fn connect_if_enabled() -> Option<Self> {
        if !live_e2e_enabled() {
            eprintln!(
                "skipping live e2e test: set {RUN_E2E_ENV}=1 and start the PCM services to run it"
            );
            return None;
        }

        Some(Self::connect().await)
    }

    /// 连接所有服务，等待它们就绪
    pub async fn connect() -> Self {
        let monitor_endpoint = std::env::var("PCM_MONITOR_ENDPOINT")
            .unwrap_or_else(|_| DEFAULT_MONITOR_ENDPOINT.to_string());
        let policy_endpoint = std::env::var("PCM_POLICY_ENDPOINT")
            .unwrap_or_else(|_| DEFAULT_POLICY_ENDPOINT.to_string());
        let graph_endpoint = std::env::var("PCM_GRAPH_ENDPOINT")
            .unwrap_or_else(|_| DEFAULT_GRAPH_ENDPOINT.to_string());
        let audit_endpoint = std::env::var("PCM_AUDIT_ENDPOINT")
            .unwrap_or_else(|_| DEFAULT_AUDIT_ENDPOINT.to_string());

        tracing::info!(
            monitor = %monitor_endpoint,
            policy = %policy_endpoint,
            graph = %graph_endpoint,
            audit = %audit_endpoint,
            "connecting to PCM services"
        );

        let monitor = MonitorServiceClient::connect(monitor_endpoint.clone())
            .await
            .unwrap_or_else(|e| {
                panic!("failed to connect to monitor-gateway at {monitor_endpoint}: {e}")
            });

        let policy = PolicyServiceClient::connect(policy_endpoint.clone())
            .await
            .unwrap_or_else(|e| {
                panic!("failed to connect to policy-service at {policy_endpoint}: {e}")
            });

        let graph = GraphServiceClient::connect(graph_endpoint.clone())
            .await
            .unwrap_or_else(|e| {
                panic!("failed to connect to graph-service at {graph_endpoint}: {e}")
            });

        let audit = AuditServiceClient::connect(audit_endpoint.clone())
            .await
            .unwrap_or_else(|e| {
                panic!("failed to connect to audit-service at {audit_endpoint}: {e}")
            });

        let mut env = Self {
            monitor,
            policy,
            graph,
            audit,
        };

        // 等待 monitor-gateway 健康
        env.wait_for_ready().await;

        env
    }

    /// 轮询 Health RPC 直到 monitor-gateway 可用
    async fn wait_for_ready(&mut self) {
        for attempt in 1..=HEALTH_CHECK_MAX_RETRIES {
            match self.monitor.health(HealthRequest {}).await {
                Ok(resp) => {
                    let health = resp.into_inner();
                    if health.healthy {
                        tracing::info!(
                            attempt,
                            policy_version = %health.policy_version,
                            "monitor-gateway is ready"
                        );
                        return;
                    }
                }
                Err(e) => {
                    tracing::debug!(attempt, error = %e, "health check failed, retrying...");
                }
            }
            tokio::time::sleep(HEALTH_CHECK_INTERVAL).await;
        }
        panic!(
            "monitor-gateway did not become healthy after {} attempts",
            HEALTH_CHECK_MAX_RETRIES
        );
    }
}

// ─────────────────────────────────────────────────────────────
// 请求构建辅助函数
// ─────────────────────────────────────────────────────────────

/// 构造标准的 EvaluateRequest
fn live_e2e_enabled() -> bool {
    std::env::var(RUN_E2E_ENV).is_ok_and(|value| {
        value == "1" || value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("yes")
    })
}

/// 鏋勯€犳爣鍑嗙殑 EvaluateRequest
pub fn make_evaluate_request(
    request_id: &str,
    action_type: ActionType,
    principal: &str,
    target: &str,
) -> EvaluateRequest {
    EvaluateRequest {
        request: Some(make_request(request_id, action_type, principal, target)),
        dry_run: false,
    }
}

/// 构造带 attributes 的 EvaluateRequest
pub fn make_evaluate_request_with_attrs(
    request_id: &str,
    action_type: ActionType,
    principal: &str,
    target: &str,
    attrs: Vec<(&str, &str)>,
) -> EvaluateRequest {
    let mut req = make_request(request_id, action_type, principal, target);
    for (k, v) in attrs {
        req.attributes.insert(k.to_string(), v.to_string());
    }
    EvaluateRequest {
        request: Some(req),
        dry_run: false,
    }
}

/// 构造内部 Request 消息
pub fn make_request(
    request_id: &str,
    action_type: ActionType,
    principal: &str,
    target: &str,
) -> Request {
    Request {
        request_id: request_id.to_string(),
        action_type: action_type.into(),
        principal: principal.to_string(),
        target: target.to_string(),
        attributes: Default::default(),
        timestamp: Some(prost_types::Timestamp {
            seconds: chrono::Utc::now().timestamp(),
            nanos: 0,
        }),
        context_hash: vec![],
    }
}

/// 构造 EvaluateBatchRequest
pub fn make_batch_request(requests: Vec<EvaluateRequest>) -> EvaluateBatchRequest {
    EvaluateBatchRequest { requests }
}

/// 构造 GraphNode
pub fn make_graph_node(
    node_id: &str,
    kind: pcm_common::proto::pcm_v1::NodeKind,
    label: &str,
) -> GraphNode {
    GraphNode {
        node_id: node_id.to_string(),
        kind: kind.into(),
        label: label.to_string(),
        attrs: Default::default(),
        created_at: None,
    }
}

/// 构造 GraphEdge
pub fn make_graph_edge(
    src: &str,
    dst: &str,
    kind: pcm_common::proto::pcm_v1::EdgeKind,
) -> GraphEdge {
    GraphEdge {
        src: src.to_string(),
        dst: dst.to_string(),
        kind: kind.into(),
        created_at: None,
    }
}

/// 生成唯一的请求 ID
pub fn unique_request_id(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4())
}

// ─────────────────────────────────────────────────────────────
// 断言辅助函数
// ─────────────────────────────────────────────────────────────

/// 断言决策为 ALLOW 并返回 Certificate
pub fn assert_allow(decision: &Decision) -> &pcm_common::proto::pcm_v1::Certificate {
    assert_eq!(
        decision.verdict,
        Verdict::Allow as i32,
        "expected ALLOW verdict, got {:?} (request_id={})",
        Verdict::try_from(decision.verdict),
        decision.request_id,
    );
    match &decision.evidence {
        Some(pcm_common::proto::pcm_v1::decision::Evidence::Certificate(cert)) => cert,
        other => panic!(
            "expected Certificate evidence for ALLOW, got {:?} (request_id={})",
            other, decision.request_id,
        ),
    }
}

/// 断言决策为 DENY 并返回 Witness
pub fn assert_deny(decision: &Decision) -> &pcm_common::proto::pcm_v1::Witness {
    assert_eq!(
        decision.verdict,
        Verdict::Deny as i32,
        "expected DENY verdict, got {:?} (request_id={})",
        Verdict::try_from(decision.verdict),
        decision.request_id,
    );
    match &decision.evidence {
        Some(pcm_common::proto::pcm_v1::decision::Evidence::Witness(witness)) => witness,
        other => panic!(
            "expected Witness evidence for DENY, got {:?} (request_id={})",
            other, decision.request_id,
        ),
    }
}

/// 断言 gRPC 错误码
pub fn assert_grpc_error(
    result: Result<tonic::Response<impl std::fmt::Debug>, tonic::Status>,
    expected_code: tonic::Code,
) {
    match result {
        Err(status) => {
            assert_eq!(
                status.code(),
                expected_code,
                "expected gRPC code {:?}, got {:?}: {}",
                expected_code,
                status.code(),
                status.message(),
            );
        }
        Ok(resp) => {
            // 某些错误场景可能返回 DENY 而非 gRPC error
            // 这也是 fail-closed 的可接受行为
            panic!(
                "expected gRPC error {:?}, got OK: {:?}",
                expected_code, resp
            );
        }
    }
}

/// 初始化 tracing（仅首次调用生效）
pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("pcm_e2e=debug,info")
        .with_test_writer()
        .try_init();
}
