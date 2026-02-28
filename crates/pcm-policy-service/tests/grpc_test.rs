//! 集成测试：PolicyService gRPC
//!
//! 这些测试需要 PostgreSQL 数据库。
//! 使用 `#[cfg(feature = "integration")]` 条件编译，
//! 运行方式：`cargo test -p pcm-policy-service --features integration`

#![cfg(feature = "integration")]

use std::sync::Arc;

use pcm_common::proto::pcm_v1::{
    policy_service_client::PolicyServiceClient,
    policy_service_server::PolicyServiceServer,
    ActivatePolicyRequest, CompilePolicyRequest, CreatePolicyRequest,
    GetPolicyRequest, ValidatePolicyRequest,
};
use pcm_policy_service::service::PolicyServiceImpl;
use pcm_policy_service::store::PolicyStore;
use sqlx::postgres::PgPoolOptions;
use tonic::transport::Server;

// =========================================================================
// 辅助函数
// =========================================================================

/// 在随机端口启动测试服务器（需要 PostgreSQL）。
async fn start_test_server() -> String {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://pcm:pcm@localhost:5432/pcm_policies".to_string());

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("failed to connect to database");

    let store = Arc::new(PolicyStore::new(pool));
    let svc = PolicyServiceImpl::new(store);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        Server::builder()
            .add_service(PolicyServiceServer::new(svc))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    format!("http://{addr}")
}

// =========================================================================
// 合法 / 非法 DSL 常量
// =========================================================================

const VALID_DSL: &str = r#"deny(Req, "blocked") :- action(Req, HttpOut, P, _)."#;
const VALID_DSL_2: &str =
    r#"deny(Req, "no_role") :- action(Req, HttpOut, P, _), !has_role(P, "admin")."#;
const INVALID_DSL: &str = "this is not valid policy DSL !!!";

// =========================================================================
// CompilePolicy
// =========================================================================

#[tokio::test]
async fn test_compile_policy_valid() {
    let addr = start_test_server().await;
    let mut client = PolicyServiceClient::connect(addr).await.unwrap();

    let resp = client
        .compile_policy(CompilePolicyRequest {
            source_dsl: VALID_DSL.to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    assert!(resp.compiled.is_some());
    let compiled = resp.compiled.unwrap();
    assert!(!compiled.content.is_empty());
    assert!(!compiled.content_hash.is_empty());
    assert!(resp.decidable);
}

#[tokio::test]
async fn test_compile_policy_invalid_syntax() {
    let addr = start_test_server().await;
    let mut client = PolicyServiceClient::connect(addr).await.unwrap();

    let status = client
        .compile_policy(CompilePolicyRequest {
            source_dsl: INVALID_DSL.to_string(),
        })
        .await
        .unwrap_err();

    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert!(status.message().contains("syntax error"));
}

#[tokio::test]
async fn test_compile_policy_with_warnings() {
    let addr = start_test_server().await;
    let mut client = PolicyServiceClient::connect(addr).await.unwrap();

    let dsl = r#"deny(Req, "test") :- action(Req, HttpOut, P, _)."#;

    let resp = client
        .compile_policy(CompilePolicyRequest {
            source_dsl: dsl.to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    assert!(resp.compiled.is_some());
    assert!(resp.decidable);
}

// =========================================================================
// ValidatePolicy
// =========================================================================

#[tokio::test]
async fn test_validate_policy_valid() {
    let addr = start_test_server().await;
    let mut client = PolicyServiceClient::connect(addr).await.unwrap();

    let resp = client
        .validate_policy(ValidatePolicyRequest {
            source_dsl: VALID_DSL.to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    assert!(resp.valid);
    assert!(resp.errors.is_empty());
}

#[tokio::test]
async fn test_validate_policy_invalid() {
    let addr = start_test_server().await;
    let mut client = PolicyServiceClient::connect(addr).await.unwrap();

    let resp = client
        .validate_policy(ValidatePolicyRequest {
            source_dsl: INVALID_DSL.to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    assert!(!resp.valid);
    assert!(!resp.errors.is_empty());
}

#[tokio::test]
async fn test_validate_policy_empty() {
    let addr = start_test_server().await;
    let mut client = PolicyServiceClient::connect(addr).await.unwrap();

    let resp = client
        .validate_policy(ValidatePolicyRequest {
            source_dsl: String::new(),
        })
        .await
        .unwrap()
        .into_inner();

    // Empty policy is valid (zero rules)
    assert!(resp.valid);
    assert!(resp.errors.is_empty());
}

// =========================================================================
// CreatePolicy → GetPolicy round-trip
// =========================================================================

#[tokio::test]
async fn test_create_and_get_policy() {
    let addr = start_test_server().await;
    let mut client = PolicyServiceClient::connect(addr).await.unwrap();

    // Create
    let created = client
        .create_policy(CreatePolicyRequest {
            source_dsl: VALID_DSL.to_string(),
            author: "test-author".to_string(),
            commit_sha: "abc123".to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    assert!(!created.policy_id.is_empty());
    assert_eq!(created.version, "0.1.0");
    assert_eq!(created.author, "test-author");
    assert_eq!(created.commit_sha, "abc123");
    assert!(created.compiled.is_some());

    // Get by policy_id + version
    let fetched = client
        .get_policy(GetPolicyRequest {
            policy_id: created.policy_id.clone(),
            version: created.version.clone(),
        })
        .await
        .unwrap()
        .into_inner();

    assert_eq!(fetched.policy_id, created.policy_id);
    assert_eq!(fetched.version, created.version);
    assert_eq!(fetched.source_dsl, VALID_DSL);

    // Get latest (empty version)
    let latest = client
        .get_policy(GetPolicyRequest {
            policy_id: created.policy_id.clone(),
            version: String::new(),
        })
        .await
        .unwrap()
        .into_inner();

    assert_eq!(latest.policy_id, created.policy_id);
}

// =========================================================================
// CreatePolicy with invalid DSL
// =========================================================================

#[tokio::test]
async fn test_create_policy_invalid_dsl() {
    let addr = start_test_server().await;
    let mut client = PolicyServiceClient::connect(addr).await.unwrap();

    let status = client
        .create_policy(CreatePolicyRequest {
            source_dsl: INVALID_DSL.to_string(),
            author: "test".to_string(),
            commit_sha: "bad".to_string(),
        })
        .await
        .unwrap_err();

    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

// =========================================================================
// GetPolicy not found
// =========================================================================

#[tokio::test]
async fn test_get_policy_not_found() {
    let addr = start_test_server().await;
    let mut client = PolicyServiceClient::connect(addr).await.unwrap();

    let status = client
        .get_policy(GetPolicyRequest {
            policy_id: "nonexistent-policy-id".to_string(),
            version: "0.1.0".to_string(),
        })
        .await
        .unwrap_err();

    assert_eq!(status.code(), tonic::Code::NotFound);
}

// =========================================================================
// ActivatePolicy
// =========================================================================

#[tokio::test]
async fn test_activate_policy() {
    let addr = start_test_server().await;
    let mut client = PolicyServiceClient::connect(addr).await.unwrap();

    // Create a policy
    let created = client
        .create_policy(CreatePolicyRequest {
            source_dsl: VALID_DSL_2.to_string(),
            author: "activator".to_string(),
            commit_sha: "def456".to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    // Activate
    let resp = client
        .activate_policy(ActivatePolicyRequest {
            policy_id: created.policy_id.clone(),
            version: created.version.clone(),
        })
        .await
        .unwrap()
        .into_inner();

    assert!(resp.activated);
    assert_eq!(resp.active_version, created.version);
}

// =========================================================================
// ActivatePolicy — not found
// =========================================================================

#[tokio::test]
async fn test_activate_policy_not_found() {
    let addr = start_test_server().await;
    let mut client = PolicyServiceClient::connect(addr).await.unwrap();

    let status = client
        .activate_policy(ActivatePolicyRequest {
            policy_id: "nonexistent".to_string(),
            version: "0.1.0".to_string(),
        })
        .await
        .unwrap_err();

    assert_eq!(status.code(), tonic::Code::NotFound);
}
