//! `pcm verify` — 离线证书验证

use anyhow::{Context, Result};
use serde_json::json;

/// 运行 verify 子命令
pub fn run(
    cert_path: String,
    policy_path: String,
    request_path: Option<String>,
    format: String,
) -> Result<()> {
    tracing::info!(%cert_path, %policy_path, ?request_path, "verifying certificate");

    // ── 1. 读取并反序列化证书 ──
    let cert_bytes = std::fs::read(&cert_path)
        .with_context(|| format!("failed to read certificate file '{}'", cert_path))?;

    // 尝试二进制反序列化，失败则尝试 JSON
    let cert_data: pcm_cert::CertificateData = match pcm_cert::deserialize_certificate(&cert_bytes)
    {
        Ok(c) => {
            tracing::debug!("certificate loaded via binary deserialization");
            c
        }
        Err(_) => {
            tracing::debug!("binary deserialization failed, trying JSON");
            serde_json::from_slice(&cert_bytes)
                .with_context(|| "certificate file is neither valid binary nor valid JSON format")?
        }
    };

    // ── 2. 读取并编译策略 ──
    let policy_source = std::fs::read_to_string(&policy_path)
        .with_context(|| format!("failed to read policy file '{}'", policy_path))?;
    let ast = pcm_policy_dsl::parser::parse_policy(&policy_source)
        .map_err(|e| anyhow::anyhow!("policy parse error: {}", e))?;
    let compiled = pcm_policy_dsl::compiler::compile(&ast, "0.1.0")
        .map_err(|e| anyhow::anyhow!("policy compile error: {}", e))?;

    let rules: Vec<pcm_policy_dsl::ast::Rule> = compiled
        .policy
        .rules
        .iter()
        .map(|ir| ir.rule.clone())
        .collect();

    // ── 3. 读取请求 JSON（如果提供） ──
    let request_facts: Vec<pcm_policy_dsl::ast::Atom> = if let Some(ref req_path) = request_path {
        let req_bytes = std::fs::read(req_path)
            .with_context(|| format!("failed to read request file '{}'", req_path))?;
        serde_json::from_slice(&req_bytes)
            .with_context(|| format!("failed to parse request JSON from '{}'", req_path))?
    } else {
        Vec::new()
    };

    // ── 4. 构造 all_base_facts 并验证 ──
    // 对于离线验证，base facts = request_facts
    // 用户可以在 request JSON 中包含所有需要的 facts（包括 graph facts）
    let all_base_facts = request_facts.clone();

    let result = pcm_cert_checker_ffi::verify_certificate_structured(
        &cert_data,
        &request_facts,
        &rules,
        &all_base_facts,
    );

    // ── 5. 输出结果 ──
    let policy_hash_hex = hex::encode(compiled.policy.content_hash);

    match format.as_str() {
        "json" => {
            let output = if result.valid {
                json!({
                    "valid": true,
                    "policy_hash": policy_hash_hex,
                    "duration_us": result.duration_us,
                })
            } else {
                json!({
                    "valid": false,
                    "error": result.error.as_deref().unwrap_or("unknown"),
                    "failed_step": result.failed_step,
                    "policy_hash": policy_hash_hex,
                    "duration_us": result.duration_us,
                })
            };
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        _ => {
            if result.valid {
                println!("Certificate VALID \u{2713}");
                println!("  Policy hash: {}", policy_hash_hex);
                println!("  Verified in {} \u{00B5}s", result.duration_us);
            } else {
                eprintln!(
                    "Certificate INVALID: {}",
                    result.error.as_deref().unwrap_or("unknown error")
                );
                if let Some(step) = result.failed_step {
                    eprintln!("  Failed at derivation step {}", step);
                }
            }
        }
    }

    // ── 6. 退出码 ──
    if result.valid {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

/// 格式化 [u8; 32] 为 hex 字符串
mod hex {
    pub fn encode(bytes: [u8; 32]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
