//! `pcm audit` — 审计日志查询

use anyhow::{Context, Result};
use pcm_common::proto::pcm_v1::audit_service_client::AuditServiceClient;
use pcm_common::proto::pcm_v1::{QueryLogsRequest, VerifyChainRequest};
use serde_json::json;

/// 运行 audit 子命令
pub fn run(
    query: Option<String>,
    endpoint: String,
    limit: u32,
    format: String,
    verify_chain: bool,
) -> Result<()> {
    tracing::info!(?query, %endpoint, %limit, "querying audit logs");

    // 使用 tokio runtime 驱动异步 gRPC 调用
    let rt = tokio::runtime::Runtime::new().context("failed to create tokio runtime")?;

    rt.block_on(async { run_async(query, endpoint, limit, format, verify_chain).await })
}

async fn run_async(
    query: Option<String>,
    endpoint: String,
    limit: u32,
    format: String,
    verify_chain: bool,
) -> Result<()> {
    // ── 1. 连接 audit-service ──
    let mut client = AuditServiceClient::connect(endpoint.clone())
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "failed to connect to audit service at '{}': {}\n\
                 Hint: ensure the audit service is running (docker-compose up audit-service)",
                endpoint,
                e
            )
        })?;

    tracing::debug!("connected to audit service at {}", endpoint);

    // ── 2. verify-chain 模式 ──
    if verify_chain {
        return run_verify_chain(&mut client, &query, &format).await;
    }

    // ── 3. 正常查询模式 ──
    let filters = parse_query_filters(query.as_deref());

    let request = QueryLogsRequest {
        principal: filters.principal.unwrap_or_default(),
        action_type: filters.action_type.unwrap_or_default(),
        verdict: filters.verdict.unwrap_or_default(),
        start_time: filters.after.unwrap_or_default(),
        end_time: filters.before.unwrap_or_default(),
        limit,
        page_token: String::new(),
    };

    let response = client
        .query_logs(request)
        .await
        .map_err(|e| anyhow::anyhow!("QueryLogs RPC failed: {}", e))?
        .into_inner();

    let records = response.records;

    // ── 4. 格式化输出 ──
    match format.as_str() {
        "json" => {
            let json_records: Vec<serde_json::Value> =
                records.iter().map(|r| record_to_json(r)).collect();
            println!("{}", serde_json::to_string_pretty(&json_records)?);
        }
        _ => {
            if records.is_empty() {
                println!("No audit records found.");
                return Ok(());
            }

            // 表格格式
            println!(
                "{:<36} {:<36} {:<16} {:<10} {:<24}",
                "RECORD_ID", "REQUEST_ID", "PRINCIPAL", "VERDICT", "TIME"
            );
            println!("{}", "-".repeat(122));

            for record in &records {
                let request_id = record
                    .request
                    .as_ref()
                    .map(|r| r.request_id.as_str())
                    .unwrap_or("-");
                let principal = record
                    .request
                    .as_ref()
                    .map(|r| r.principal.as_str())
                    .unwrap_or("-");
                let verdict = record
                    .decision
                    .as_ref()
                    .map(|d| verdict_str(d.verdict))
                    .unwrap_or("-");
                let time = record
                    .recorded_at
                    .as_ref()
                    .map(|t| format_timestamp(t))
                    .unwrap_or_else(|| "-".to_string());

                println!(
                    "{:<36} {:<36} {:<16} {:<10} {:<24}",
                    record.record_id, request_id, principal, verdict, time
                );
            }

            if !response.next_page_token.is_empty() {
                println!();
                println!(
                    "More records available. Use --query 'page_token={}' to fetch next page.",
                    response.next_page_token
                );
            }
        }
    }

    Ok(())
}

/// verify-chain 模式
async fn run_verify_chain(
    client: &mut AuditServiceClient<tonic::transport::Channel>,
    query: &Option<String>,
    format: &str,
) -> Result<()> {
    // 从 query 中解析 start/end record IDs
    let filters = parse_query_filters(query.as_deref());
    let start_id = filters.start_record_id.unwrap_or_default();
    let end_id = filters.end_record_id.unwrap_or_default();

    if start_id.is_empty() || end_id.is_empty() {
        anyhow::bail!(
            "verify-chain requires start and end record IDs.\n\
             Usage: pcm audit --verify-chain --query 'start_record_id=<id>,end_record_id=<id>'"
        );
    }

    let request = VerifyChainRequest {
        start_record_id: start_id.clone(),
        end_record_id: end_id.clone(),
    };

    let response = client
        .verify_chain(request)
        .await
        .map_err(|e| anyhow::anyhow!("VerifyChain RPC failed: {}", e))?
        .into_inner();

    match format {
        "json" => {
            let output = json!({
                "valid": response.valid,
                "records_verified": response.records_verified,
                "first_invalid_record_id": if response.first_invalid_record_id.is_empty() {
                    None
                } else {
                    Some(&response.first_invalid_record_id)
                },
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        _ => {
            if response.valid {
                println!("Chain integrity VALID \u{2713}");
                println!("  Records verified: {}", response.records_verified);
                println!("  Range: {} .. {}", start_id, end_id);
            } else {
                eprintln!("Chain integrity INVALID");
                eprintln!("  Records verified: {}", response.records_verified);
                if !response.first_invalid_record_id.is_empty() {
                    eprintln!(
                        "  First invalid record: {}",
                        response.first_invalid_record_id
                    );
                }
            }
        }
    }

    if response.valid {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

/// 查询过滤条件
#[derive(Debug, Default)]
struct QueryFilters {
    principal: Option<String>,
    action_type: Option<String>,
    verdict: Option<String>,
    after: Option<String>,
    before: Option<String>,
    start_record_id: Option<String>,
    end_record_id: Option<String>,
}

/// 解析 "key=value,key=value" 格式的查询字符串
fn parse_query_filters(query: Option<&str>) -> QueryFilters {
    let mut filters = QueryFilters::default();
    let Some(q) = query else {
        return filters;
    };

    for pair in q.split(',') {
        let pair = pair.trim();
        if let Some((key, value)) = pair.split_once('=') {
            let key = key.trim();
            let value = value.trim().to_string();
            match key {
                "principal" => filters.principal = Some(value),
                "action_type" => filters.action_type = Some(value),
                "verdict" => filters.verdict = Some(value),
                "after" => filters.after = Some(value),
                "before" => filters.before = Some(value),
                "start_record_id" => filters.start_record_id = Some(value),
                "end_record_id" => filters.end_record_id = Some(value),
                other => {
                    tracing::warn!("unknown query filter key: '{}'", other);
                }
            }
        }
    }

    filters
}

/// 将 AuditRecord 转为 JSON Value
fn record_to_json(record: &pcm_common::proto::pcm_v1::AuditRecord) -> serde_json::Value {
    json!({
        "record_id": record.record_id,
        "request_id": record.request.as_ref().map(|r| &r.request_id),
        "principal": record.request.as_ref().map(|r| &r.principal),
        "action_type": record.request.as_ref().map(|r| r.action_type),
        "verdict": record.decision.as_ref().map(|d| verdict_str(d.verdict)),
        "recorded_at": record.recorded_at.as_ref().map(format_timestamp),
    })
}

/// Verdict 枚举值转字符串
fn verdict_str(v: i32) -> &'static str {
    match v {
        1 => "allow",
        2 => "deny",
        3 => "error",
        _ => "unknown",
    }
}

/// 格式化 protobuf Timestamp 为 RFC3339 字符串
fn format_timestamp(ts: &prost_types::Timestamp) -> String {
    let dt = chrono::DateTime::from_timestamp(ts.seconds, ts.nanos as u32);
    match dt {
        Some(d) => d.to_rfc3339(),
        None => format!("{}s", ts.seconds),
    }
}
