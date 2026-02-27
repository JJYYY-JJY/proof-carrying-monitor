//! PCM Policy Service — 策略管理服务 (placeholder)

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    eprintln!("pcm-policy-service: placeholder listening on [::]:50052");

    let listener = tokio::net::TcpListener::bind("[::]:50052").await?;
    loop {
        // Accept and immediately drop connections (placeholder)
        let _ = listener.accept().await;
    }
}
