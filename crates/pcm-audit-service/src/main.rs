//! PCM Audit Service — 审计日志 (placeholder)

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    eprintln!("pcm-audit-service: placeholder listening on [::]:50054");

    let listener = tokio::net::TcpListener::bind("[::]:50054").await?;
    loop {
        // Accept and immediately drop connections (placeholder)
        let _ = listener.accept().await;
    }
}
