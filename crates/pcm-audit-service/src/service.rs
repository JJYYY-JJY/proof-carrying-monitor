//! AuditService gRPC implementation.
//!
//! Maps the four proto RPCs (LogDecision, QueryLogs, ExportLogs, VerifyChain)
//! onto [`crate::store::AuditStore`].

use std::sync::Arc;

use chrono::DateTime;
use pcm_common::proto::pcm_v1::{
    AuditRecord, ExportLogsRequest, LogDecisionRequest, LogDecisionResponse, QueryLogsRequest,
    QueryLogsResponse, VerifyChainRequest, VerifyChainResponse, audit_service_server::AuditService,
};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::store::{AuditStore, QueryFilter};

/// gRPC AuditService implementation backed by [`AuditStore`].
pub struct AuditServiceImpl {
    store: Arc<AuditStore>,
}

impl AuditServiceImpl {
    pub fn new(store: Arc<AuditStore>) -> Self {
        Self { store }
    }
}

#[tonic::async_trait]
impl AuditService for AuditServiceImpl {
    // ----------------------------------------------------------------
    // LogDecision
    // ----------------------------------------------------------------

    #[tracing::instrument(skip(self, request), fields(rpc = "LogDecision"))]
    async fn log_decision(
        &self,
        request: Request<LogDecisionRequest>,
    ) -> Result<Response<LogDecisionResponse>, Status> {
        let inner = request.into_inner();

        let pcm_request = inner
            .request
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("missing request"))?;

        let decision = inner
            .decision
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("missing decision"))?;

        tracing::info!(
            request_id = %pcm_request.request_id,
            principal = %pcm_request.principal,
            verdict = decision.verdict,
            "LogDecision"
        );

        let (record_id, record_hash) = self
            .store
            .log_decision(pcm_request, decision)
            .await
            .map_err(|e| Status::internal(format!("failed to log decision: {e}")))?;

        Ok(Response::new(LogDecisionResponse {
            record_id,
            record_hash,
        }))
    }

    // ----------------------------------------------------------------
    // QueryLogs
    // ----------------------------------------------------------------

    #[tracing::instrument(skip(self, request), fields(rpc = "QueryLogs"))]
    async fn query_logs(
        &self,
        request: Request<QueryLogsRequest>,
    ) -> Result<Response<QueryLogsResponse>, Status> {
        let req = request.into_inner();

        tracing::info!(
            principal = %req.principal,
            limit = req.limit,
            "QueryLogs"
        );

        let filter = QueryFilter {
            principal: non_empty(req.principal),
            action_type: parse_action_type(&req.action_type),
            verdict: parse_verdict(&req.verdict),
            start_time: parse_rfc3339(&req.start_time),
            end_time: parse_rfc3339(&req.end_time),
        };

        let page_token = non_empty(req.page_token);

        let (records, next_page_token) = self
            .store
            .query_logs(filter, req.limit, page_token.as_deref())
            .await
            .map_err(|e| Status::internal(format!("query failed: {e}")))?;

        Ok(Response::new(QueryLogsResponse {
            records,
            next_page_token: next_page_token.unwrap_or_default(),
        }))
    }

    // ----------------------------------------------------------------
    // ExportLogs  (server-streaming)
    // ----------------------------------------------------------------

    type ExportLogsStream = ReceiverStream<Result<AuditRecord, Status>>;

    #[tracing::instrument(skip(self, request), fields(rpc = "ExportLogs"))]
    async fn export_logs(
        &self,
        request: Request<ExportLogsRequest>,
    ) -> Result<Response<Self::ExportLogsStream>, Status> {
        let req = request.into_inner();

        let start = parse_rfc3339(&req.start_time)
            .ok_or_else(|| Status::invalid_argument("invalid or missing start_time (RFC3339)"))?;
        let end = parse_rfc3339(&req.end_time)
            .ok_or_else(|| Status::invalid_argument("invalid or missing end_time (RFC3339)"))?;

        tracing::info!(%start, %end, "ExportLogs");

        let store = Arc::clone(&self.store);
        let (tx, rx) = tokio::sync::mpsc::channel(128);

        tokio::spawn(async move {
            match store.export_logs(start, end).await {
                Ok(records) => {
                    for record in records {
                        if tx.send(Ok(record)).await.is_err() {
                            break; // client disconnected
                        }
                    }
                }
                Err(e) => {
                    let _ = tx
                        .send(Err(Status::internal(format!("export failed: {e}"))))
                        .await;
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    // ----------------------------------------------------------------
    // VerifyChain
    // ----------------------------------------------------------------

    #[tracing::instrument(skip(self, request), fields(rpc = "VerifyChain"))]
    async fn verify_chain(
        &self,
        request: Request<VerifyChainRequest>,
    ) -> Result<Response<VerifyChainResponse>, Status> {
        let req = request.into_inner();

        if req.start_record_id.is_empty() || req.end_record_id.is_empty() {
            return Err(Status::invalid_argument(
                "start_record_id and end_record_id are required",
            ));
        }

        tracing::info!(
            start = %req.start_record_id,
            end = %req.end_record_id,
            "VerifyChain"
        );

        let (valid, records_verified, first_invalid) = self
            .store
            .verify_chain(&req.start_record_id, &req.end_record_id)
            .await
            .map_err(|e| Status::internal(format!("verify failed: {e}")))?;

        Ok(Response::new(VerifyChainResponse {
            valid,
            records_verified,
            first_invalid_record_id: first_invalid.unwrap_or_default(),
        }))
    }
}

// ============================================================
// Parsing helpers
// ============================================================

fn non_empty(s: String) -> Option<String> {
    if s.is_empty() { None } else { Some(s) }
}

fn parse_rfc3339(s: &str) -> Option<DateTime<chrono::Utc>> {
    if s.is_empty() {
        return None;
    }
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc))
}

/// Map the string representation of action_type to the proto enum value.
fn parse_action_type(s: &str) -> Option<i32> {
    if s.is_empty() {
        return None;
    }
    // Accept both numeric and symbolic names
    if let Ok(n) = s.parse::<i32>() {
        return Some(n);
    }
    match s.to_uppercase().as_str() {
        "TOOL_CALL" => Some(1),
        "HTTP_OUT" => Some(2),
        "DB_WRITE" => Some(3),
        "DB_READ_SENSITIVE" => Some(4),
        "FILE_WRITE" => Some(5),
        "FILE_READ" => Some(6),
        "CUSTOM" => Some(15),
        _ => None,
    }
}

/// Map the string representation of verdict to the proto enum value.
fn parse_verdict(s: &str) -> Option<i32> {
    if s.is_empty() {
        return None;
    }
    if let Ok(n) = s.parse::<i32>() {
        return Some(n);
    }
    match s.to_uppercase().as_str() {
        "ALLOW" => Some(1),
        "DENY" => Some(2),
        "ERROR" => Some(3),
        _ => None,
    }
}
