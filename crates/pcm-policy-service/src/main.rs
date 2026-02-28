//! PCM Policy Service — 策略管理服务
//!
//! gRPC 服务入口，暴露 PolicyService 的 6 个 RPC 方法。

use std::sync::Arc;

use anyhow::Result;
use pcm_common::proto::pcm_v1::policy_service_server::PolicyServiceServer;
use sqlx::postgres::PgPoolOptions;
use tonic::transport::Server;

use pcm_policy_service::service::PolicyServiceImpl;
use pcm_policy_service::store::PolicyStore;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .json()
        .init();

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://pcm:pcm@localhost:5432/pcm_policies".to_string());

    let max_connections: u32 = std::env::var("PCM_DB_MAX_CONNECTIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10);

    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .connect(&database_url)
        .await?;

    let store = Arc::new(PolicyStore::new(pool));
    let svc = PolicyServiceImpl::new(store);

    let port: u16 = std::env::var("PCM_POLICY_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50052);
    let addr: std::net::SocketAddr = format!("[::]:{port}").parse()?;

    tracing::info!(%addr, "pcm-policy-service listening");

    Server::builder()
        .add_service(PolicyServiceServer::new(svc))
        .serve(addr)
        .await?;

    Ok(())
}
