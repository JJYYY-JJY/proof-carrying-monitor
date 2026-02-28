//! PCM Graph Service — 依赖图存储与 gRPC 服务

use std::sync::Arc;

use anyhow::Result;
use pcm_common::proto::pcm_v1::graph_service_server::GraphServiceServer;
use pcm_graph_service::service::GraphServiceImpl;
use pcm_graph_service::store::GraphStore;
use tonic::transport::Server;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("pcm=debug,info")
        .json()
        .init();

    tracing::info!("PCM Graph Service starting...");

    let data_dir =
        std::env::var("PCM_GRAPH_DATA_DIR").unwrap_or_else(|_| "/tmp/pcm-graph-data".to_string());
    let store = Arc::new(GraphStore::open(&data_dir)?);

    let port: u16 = std::env::var("PCM_GRAPH_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50053);
    let addr: std::net::SocketAddr = format!("[::]:{port}").parse()?;

    let svc = GraphServiceImpl::new(store);
    tracing::info!(%addr, %data_dir, "listening");

    Server::builder()
        .add_service(GraphServiceServer::new(svc))
        .serve(addr)
        .await?;

    Ok(())
}
