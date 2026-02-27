//! MonitorService gRPC 实现

use std::time::Instant;

use pcm_common::proto::pcm_v1::{
    monitor_service_server::MonitorService, ActionType, Certificate, Decision, EvaluateBatchRequest,
    EvaluateBatchResponse, EvaluateRequest, EvaluateResponse, HealthRequest, HealthResponse,
    Verdict,
};
use tonic::{Request, Response, Status};

/// Monitor 服务实现
pub struct MonitorServiceImpl {
    start_time: Instant,
}

impl MonitorServiceImpl {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
        }
    }

    /// 验证 EvaluateRequest 中的 Request 字段
    fn validate_request(req: &pcm_common::proto::pcm_v1::Request) -> Result<(), Status> {
        if req.request_id.is_empty() {
            return Err(Status::invalid_argument("empty request_id"));
        }
        // action_type == 0 means ACTION_TYPE_UNSPECIFIED
        if ActionType::try_from(req.action_type) == Ok(ActionType::Unspecified) {
            return Err(Status::invalid_argument("unspecified action_type"));
        }
        Ok(())
    }

    /// 执行单次评估（当前阶段：硬编码 Allow）
    fn evaluate_single(
        req: &pcm_common::proto::pcm_v1::Request,
        _dry_run: bool,
    ) -> EvaluateResponse {
        let start = Instant::now();

        // 硬编码 Allow 决策 — 后续集成真实策略引擎
        let decision = Decision {
            request_id: req.request_id.clone(),
            verdict: Verdict::Allow.into(),
            evidence: Some(
                pcm_common::proto::pcm_v1::decision::Evidence::Certificate(Certificate {
                    steps: vec![],
                    policy_hash: vec![],
                    graph_hash: vec![],
                    request_hash: vec![],
                }),
            ),
            policy_version_hash: String::new(),
            graph_snapshot_hash: vec![],
            decided_at: None,
            signature: vec![],
        };

        let duration_us = start.elapsed().as_micros() as u64;

        EvaluateResponse {
            decision: Some(decision),
            evaluation_duration_us: duration_us,
        }
    }
}

#[tonic::async_trait]
impl MonitorService for MonitorServiceImpl {
    async fn evaluate(
        &self,
        request: Request<EvaluateRequest>,
    ) -> Result<Response<EvaluateResponse>, Status> {
        let eval_req = request.into_inner();

        let inner_req = eval_req
            .request
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("missing request"))?;

        Self::validate_request(inner_req)?;

        tracing::info!(
            request_id = %inner_req.request_id,
            action_type = inner_req.action_type,
            principal = %inner_req.principal,
            dry_run = eval_req.dry_run,
            "evaluating request"
        );

        let response = Self::evaluate_single(inner_req, eval_req.dry_run);
        Ok(Response::new(response))
    }

    async fn evaluate_batch(
        &self,
        request: Request<EvaluateBatchRequest>,
    ) -> Result<Response<EvaluateBatchResponse>, Status> {
        let batch = request.into_inner();

        let mut responses = Vec::with_capacity(batch.requests.len());
        for eval_req in &batch.requests {
            let inner_req = eval_req
                .request
                .as_ref()
                .ok_or_else(|| Status::invalid_argument("missing request"))?;

            Self::validate_request(inner_req)?;

            tracing::info!(
                request_id = %inner_req.request_id,
                action_type = inner_req.action_type,
                principal = %inner_req.principal,
                dry_run = eval_req.dry_run,
                "evaluating request (batch)"
            );

            responses.push(Self::evaluate_single(inner_req, eval_req.dry_run));
        }

        Ok(Response::new(EvaluateBatchResponse { responses }))
    }

    async fn health(
        &self,
        _request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        let uptime = self.start_time.elapsed().as_secs();
        Ok(Response::new(HealthResponse {
            healthy: true,
            policy_version: String::new(),
            uptime_seconds: uptime,
        }))
    }
}
