//! PCM Monitor Gateway — 参考监控器入口
//!
//! 提供 gRPC MonitorService，实现 complete mediation。
//! 所有外部副作用必须经过此服务的 Evaluate RPC。

use pcm_common::proto::pcm_v1::monitor_service_server::MonitorServiceServer;
use pcm_monitor_gateway::service::MonitorServiceImpl;
use tonic::transport::Server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("pcm=debug,info")
        .json()
        .init();

    tracing::info!("PCM Monitor Gateway starting...");

    let port: u16 = std::env::var("PCM_GATEWAY_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50051);
    let addr: std::net::SocketAddr = format!("[::]:{port}").parse()?;

    let svc = MonitorServiceImpl::new();
    tracing::info!(%addr, "listening");

    Server::builder()
        .add_service(MonitorServiceServer::new(svc))
        .serve(addr)
        .await?;

    Ok(())
}
