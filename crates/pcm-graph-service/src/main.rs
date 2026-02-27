//! PCM Graph Service — 依赖图存储 (placeholder)

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    eprintln!("pcm-graph-service: placeholder listening on [::]:50053");

    let listener = tokio::net::TcpListener::bind("[::]:50053").await?;
    loop {
        // Accept and immediately drop connections (placeholder)
        let _ = listener.accept().await;
    }
}
