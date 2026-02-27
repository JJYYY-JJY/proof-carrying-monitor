//! 集成测试：MonitorService gRPC

use pcm_common::proto::pcm_v1::{
    monitor_service_client::MonitorServiceClient,
    monitor_service_server::MonitorServiceServer,
    ActionType, EvaluateRequest, HealthRequest, Request, Verdict,
};
use pcm_monitor_gateway::service::MonitorServiceImpl;
use tonic::transport::Server;

/// 在随机端口启动测试服务器，返回连接地址
async fn start_test_server() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        Server::builder()
            .add_service(MonitorServiceServer::new(MonitorServiceImpl::new()))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    format!("http://{addr}")
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

#[tokio::test]
async fn test_evaluate_allow() {
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

    let resp = client
        .health(HealthRequest {})
        .await
        .unwrap()
        .into_inner();

    assert!(resp.healthy);
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

    let resp = client
        .evaluate_batch(batch_req)
        .await
        .unwrap()
        .into_inner();

    assert_eq!(resp.responses.len(), 2);
    for (i, r) in resp.responses.iter().enumerate() {
        let decision = r.decision.as_ref().expect("decision should be present");
        assert_eq!(decision.verdict, Verdict::Allow as i32);
        assert_eq!(
            decision.request_id,
            format!("batch-{:03}", i + 1)
        );
    }
}
