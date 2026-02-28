//! PCM Monitor Gateway — 参考监控器入口
//!
//! 提供 gRPC MonitorService，实现 complete mediation。
//! 所有外部副作用必须经过此服务的 Evaluate RPC。

use std::path::Path;
use std::sync::Arc;

use pcm_common::proto::pcm_v1::{
    graph_service_client::GraphServiceClient, monitor_service_server::MonitorServiceServer,
};
use pcm_monitor_gateway::policy_loader::PolicyLoader;
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

    // ── 策略加载 ──
    let policy_path =
        std::env::var("PCM_POLICY_FILE").unwrap_or_else(|_| "policies/example.pcm".to_string());

    let loader = match PolicyLoader::load_from_file(Path::new(&policy_path)) {
        Ok(l) => {
            tracing::info!(path = %policy_path, "policy loaded from file");
            Arc::new(l)
        }
        Err(e) => {
            tracing::warn!(
                path = %policy_path,
                error = %e,
                "failed to load policy file, starting with empty policy"
            );
            Arc::new(PolicyLoader::empty())
        }
    };

    // 启动策略文件热加载后台任务
    let _watcher = loader
        .clone()
        .watch_file(std::path::PathBuf::from(&policy_path));

    // 从 loader 的共享状态构建 service
    let mut svc = MonitorServiceImpl::new_with_policy(loader.policy(), loader.policy_ast());

    // 连接 graph-service（可选）
    let graph_endpoint = std::env::var("PCM_GRAPH_ENDPOINT")
        .unwrap_or_else(|_| "http://localhost:50053".to_string());

    match GraphServiceClient::connect(graph_endpoint.clone()).await {
        Ok(client) => {
            tracing::info!(endpoint = %graph_endpoint, "connected to graph-service");
            svc = svc.with_graph_client(client);
        }
        Err(e) => {
            tracing::warn!(
                endpoint = %graph_endpoint,
                error = %e,
                "failed to connect to graph-service, running in degraded mode"
            );
        }
    }

    tracing::info!(%addr, "listening");

    Server::builder()
        .add_service(MonitorServiceServer::new(svc))
        .serve(addr)
        .await?;

    Ok(())
}
