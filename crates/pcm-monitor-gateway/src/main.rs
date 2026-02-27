//! PCM Monitor Gateway — 参考监控器入口
//!
//! 提供 gRPC MonitorService，实现 complete mediation。
//! 所有外部副作用必须经过此服务的 Evaluate RPC。

use anyhow::Result;

mod service;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("pcm=debug,info")
        .json()
        .init();

    tracing::info!("PCM Monitor Gateway starting...");

    // TODO: 加载策略、初始化引擎、启动 gRPC 服务
    let addr: std::net::SocketAddr = "[::]:50051".parse()?;
    tracing::info!(%addr, "listening");

    // 占位：保持进程运行
    tokio::signal::ctrl_c().await?;
    Ok(())
}
