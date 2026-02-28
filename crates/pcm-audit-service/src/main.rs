//! PCM Audit Service — 审计日志服务入口
//!
//! gRPC 服务入口，暴露 AuditService 的 4 个 RPC 方法。

use std::sync::Arc;

use anyhow::Result;
use ed25519_dalek::SigningKey;
use pcm_common::proto::pcm_v1::audit_service_server::AuditServiceServer;
use sqlx_postgres::PgPoolOptions;
use tonic::transport::Server;

use pcm_audit_service::service::AuditServiceImpl;
use pcm_audit_service::store::AuditStore;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .json()
        .init();

    // ---- Database ----
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://pcm:pcm@localhost:5432/pcm_audit".to_string());

    let max_connections: u32 = std::env::var("PCM_DB_MAX_CONNECTIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10);

    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .connect(&database_url)
        .await?;

    // ---- Signing key ----
    let signing_key = load_or_generate_signing_key();

    // ---- Store (recovers chain head from DB) ----
    let store = Arc::new(AuditStore::new(pool, signing_key).await?);

    let svc = AuditServiceImpl::new(store);

    // ---- gRPC server ----
    let port: u16 = std::env::var("PCM_AUDIT_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50054);
    let addr: std::net::SocketAddr = format!("[::]:{port}").parse()?;

    tracing::info!(%addr, "pcm-audit-service listening");

    Server::builder()
        .add_service(AuditServiceServer::new(svc))
        .serve(addr)
        .await?;

    Ok(())
}

/// Load the Ed25519 signing key from `PCM_AUDIT_SIGNING_KEY` (hex-encoded
/// 32-byte seed) or generate an ephemeral one for development / MVP usage.
fn load_or_generate_signing_key() -> SigningKey {
    match std::env::var("PCM_AUDIT_SIGNING_KEY") {
        Ok(hex_str) => {
            let bytes = hex_decode(&hex_str)
                .expect("PCM_AUDIT_SIGNING_KEY must be a 64-char hex string (32 bytes)");
            let seed: [u8; 32] = bytes
                .try_into()
                .expect("PCM_AUDIT_SIGNING_KEY must be exactly 32 bytes");
            tracing::info!("loaded signing key from PCM_AUDIT_SIGNING_KEY");
            SigningKey::from_bytes(&seed)
        }
        Err(_) => {
            let key = SigningKey::generate(&mut rand::rngs::OsRng);
            tracing::warn!(
                "PCM_AUDIT_SIGNING_KEY not set — using ephemeral key (not suitable for production)"
            );
            key
        }
    }
}

/// Minimal hex decoder (avoids pulling in the `hex` crate).
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}
