//! 集成测试：AuditService gRPC
//!
//! 这些测试需要 PostgreSQL 数据库。
//! 使用 `#[cfg(feature = "integration")]` 条件编译，
//! 运行方式：`cargo test -p pcm-audit-service --features integration`

#![cfg(feature = "integration")]

use std::sync::Arc;

use chrono::Utc;
use ed25519_dalek::SigningKey;
use pcm_audit_service::service::AuditServiceImpl;
use pcm_audit_service::store::AuditStore;
use pcm_common::proto::pcm_v1::{
    Decision, ExportLogsRequest, LogDecisionRequest, QueryLogsRequest, Request as PcmRequest,
    Verdict, VerifyChainRequest, audit_service_client::AuditServiceClient,
    audit_service_server::AuditServiceServer,
};
use sqlx_core::query::query;
use sqlx_postgres::PgPoolOptions;
use tonic::transport::Server;

// =========================================================================
// 辅助函数
// =========================================================================

/// 在随机端口启动测试服务器（需要 PostgreSQL）。
async fn start_test_server() -> (String, Arc<AuditStore>) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://pcm:pcm@localhost:5432/pcm_audit".to_string());

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("failed to connect to database");

    // Clean up previous test data
    query("DELETE FROM audit_records")
        .execute(&pool)
        .await
        .expect("failed to clean test data");

    let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let store = Arc::new(
        AuditStore::new(pool, signing_key)
            .await
            .expect("failed to create AuditStore"),
    );

    let svc = AuditServiceImpl::new(Arc::clone(&store));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        Server::builder()
            .add_service(AuditServiceServer::new(svc))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    (format!("http://{addr}"), store)
}

/// Create a sample LogDecisionRequest.
fn make_log_request(principal: &str, verdict: i32, action_type: i32) -> LogDecisionRequest {
    let now = Utc::now();
    LogDecisionRequest {
        request: Some(PcmRequest {
            request_id: uuid::Uuid::new_v4().to_string(),
            action_type,
            principal: principal.to_string(),
            target: "resource:test".to_string(),
            attributes: Default::default(),
            timestamp: Some(prost_types::Timestamp {
                seconds: now.timestamp(),
                nanos: now.timestamp_subsec_nanos() as i32,
            }),
            context_hash: vec![],
        }),
        decision: Some(Decision {
            request_id: String::new(),
            verdict,
            evidence: None,
            policy_version_hash: "test-policy-hash".to_string(),
            graph_snapshot_hash: vec![],
            decided_at: Some(prost_types::Timestamp {
                seconds: now.timestamp(),
                nanos: now.timestamp_subsec_nanos() as i32,
            }),
            signature: vec![],
        }),
    }
}

// =========================================================================
// LogDecision + QueryLogs round-trip
// =========================================================================

#[tokio::test]
async fn test_log_and_query_roundtrip() {
    let (addr, _store) = start_test_server().await;
    let mut client = AuditServiceClient::connect(addr).await.unwrap();

    // Log a decision
    let req = make_log_request("alice", Verdict::Allow as i32, 1);
    let resp = client.log_decision(req).await.unwrap().into_inner();

    assert!(!resp.record_id.is_empty());
    assert!(!resp.record_hash.is_empty());

    // Query it back
    let query_resp = client
        .query_logs(QueryLogsRequest {
            principal: "alice".to_string(),
            limit: 10,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();

    assert_eq!(query_resp.records.len(), 1);
    assert_eq!(query_resp.records[0].record_id, resp.record_id);
    assert!(query_resp.records[0].request.is_some());
    assert!(query_resp.records[0].decision.is_some());
}

// =========================================================================
// Signature chain: 3 records → verify passes
// =========================================================================

#[tokio::test]
async fn test_signature_chain_valid() {
    let (addr, _store) = start_test_server().await;
    let mut client = AuditServiceClient::connect(addr).await.unwrap();

    let mut record_ids = Vec::new();
    for i in 0..3 {
        let req = make_log_request(&format!("user-{i}"), Verdict::Allow as i32, 1);
        let resp = client.log_decision(req).await.unwrap().into_inner();
        record_ids.push(resp.record_id);
    }

    let verify_resp = client
        .verify_chain(VerifyChainRequest {
            start_record_id: record_ids[0].clone(),
            end_record_id: record_ids[2].clone(),
        })
        .await
        .unwrap()
        .into_inner();

    assert!(verify_resp.valid);
    assert_eq!(verify_resp.records_verified, 3);
    assert!(verify_resp.first_invalid_record_id.is_empty());
}

// =========================================================================
// Signature chain tamper detection
// =========================================================================

#[tokio::test]
async fn test_signature_chain_tamper_detected() {
    let (addr, store) = start_test_server().await;
    let mut client = AuditServiceClient::connect(addr).await.unwrap();

    let mut record_ids = Vec::new();
    for i in 0..3 {
        let req = make_log_request(&format!("user-{i}"), Verdict::Allow as i32, 1);
        let resp = client.log_decision(req).await.unwrap().into_inner();
        record_ids.push(resp.record_id);
    }

    // Tamper with the middle record's hash in the database
    let fake_hash = vec![0u8; 32];
    query("UPDATE audit_records SET record_hash = $1 WHERE record_id = $2")
        .bind(&fake_hash)
        .bind(&record_ids[1])
        .execute(store.pool())
        .await
        .unwrap();

    let verify_resp = client
        .verify_chain(VerifyChainRequest {
            start_record_id: record_ids[0].clone(),
            end_record_id: record_ids[2].clone(),
        })
        .await
        .unwrap()
        .into_inner();

    assert!(!verify_resp.valid);
}

// =========================================================================
// Filter queries: by principal, verdict, time range
// =========================================================================

#[tokio::test]
async fn test_filter_by_principal() {
    let (addr, _store) = start_test_server().await;
    let mut client = AuditServiceClient::connect(addr).await.unwrap();

    // Log decisions for different principals
    for _ in 0..2 {
        let req = make_log_request("alice", Verdict::Allow as i32, 1);
        client.log_decision(req).await.unwrap();
    }
    let req = make_log_request("bob", Verdict::Deny as i32, 2);
    client.log_decision(req).await.unwrap();

    // Query only alice
    let resp = client
        .query_logs(QueryLogsRequest {
            principal: "alice".to_string(),
            limit: 100,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();

    assert_eq!(resp.records.len(), 2);
}

#[tokio::test]
async fn test_filter_by_verdict() {
    let (addr, _store) = start_test_server().await;
    let mut client = AuditServiceClient::connect(addr).await.unwrap();

    let req = make_log_request("alice", Verdict::Allow as i32, 1);
    client.log_decision(req).await.unwrap();
    let req = make_log_request("bob", Verdict::Deny as i32, 2);
    client.log_decision(req).await.unwrap();

    let resp = client
        .query_logs(QueryLogsRequest {
            verdict: "DENY".to_string(),
            limit: 100,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();

    assert_eq!(resp.records.len(), 1);
}

// =========================================================================
// Pagination
// =========================================================================

#[tokio::test]
async fn test_pagination() {
    let (addr, _store) = start_test_server().await;
    let mut client = AuditServiceClient::connect(addr).await.unwrap();

    // Insert 5 records
    for i in 0..5 {
        let req = make_log_request(&format!("user-{i}"), Verdict::Allow as i32, 1);
        client.log_decision(req).await.unwrap();
    }

    // Fetch first page of 2
    let page1 = client
        .query_logs(QueryLogsRequest {
            limit: 2,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();

    assert_eq!(page1.records.len(), 2);
    assert!(!page1.next_page_token.is_empty());

    // Fetch second page
    let page2 = client
        .query_logs(QueryLogsRequest {
            limit: 2,
            page_token: page1.next_page_token,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();

    assert_eq!(page2.records.len(), 2);

    // Pages should contain different records
    assert_ne!(page1.records[0].record_id, page2.records[0].record_id);
}

// =========================================================================
// ExportLogs
// =========================================================================

#[tokio::test]
async fn test_export_logs() {
    let (addr, _store) = start_test_server().await;
    let mut client = AuditServiceClient::connect(addr).await.unwrap();

    let start = Utc::now();

    // Insert records
    for i in 0..3 {
        let req = make_log_request(&format!("export-user-{i}"), Verdict::Allow as i32, 1);
        client.log_decision(req).await.unwrap();
    }

    let end = Utc::now() + chrono::Duration::seconds(1);

    let mut stream = client
        .export_logs(ExportLogsRequest {
            start_time: start.to_rfc3339(),
            end_time: end.to_rfc3339(),
            format: "protobuf".to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    let mut count = 0;
    while let Some(record) = tokio_stream::StreamExt::next(&mut stream).await {
        assert!(record.is_ok());
        count += 1;
    }

    assert_eq!(count, 3);
}
