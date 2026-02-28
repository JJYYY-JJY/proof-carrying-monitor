//! MonitorService gRPC 实现
//!
//! 完整运行时评估流程：查询依赖图 → Datalog 策略评估 → 证书/Witness 生成 → 证书自验证。

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use pcm_cert::generator::{generate_certificate, generate_witness};
use pcm_cert_checker_ffi::{verify_certificate_structured, verify_witness_structured};
use pcm_common::hash::blake3_hash;
use pcm_common::proto::pcm_v1::{
    ActionType, Decision, EdgeKind as ProtoEdgeKind, EvaluateBatchRequest, EvaluateBatchResponse,
    EvaluateRequest, EvaluateResponse, GetSnapshotRequest, GraphSnapshot, HealthRequest,
    HealthResponse, Verdict, graph_service_client::GraphServiceClient,
    monitor_service_server::MonitorService,
};
use pcm_datalog_engine::engine::DatalogEngine;
use pcm_datalog_engine::facts;
use pcm_policy_dsl::ast::{Atom, PolicyAst, Rule};
use pcm_policy_dsl::compiler::{CompiledPolicy, compile, decompile};
use tonic::transport::Channel;
use tonic::{Request, Response, Status};

/// 评估超时默认值（毫秒）
const DEFAULT_EVAL_TIMEOUT_MS: u64 = 5000;

/// graph-service gRPC 调用超时（毫秒）
const GRAPH_RPC_TIMEOUT_MS: u64 = 500;

/// DatalogEngine 最大迭代次数
const MAX_ITERATIONS: usize = 1000;

// ──────────────────────────────────────────────
// 辅助函数
// ──────────────────────────────────────────────

/// 将 proto ActionType 枚举转为 Datalog 字符串常量
fn action_type_to_string(at: i32) -> String {
    match ActionType::try_from(at) {
        Ok(ActionType::ToolCall) => "ToolCall".to_string(),
        Ok(ActionType::HttpOut) => "HttpOut".to_string(),
        Ok(ActionType::DbWrite) => "DbWrite".to_string(),
        Ok(ActionType::DbReadSensitive) => "DbReadSensitive".to_string(),
        Ok(ActionType::FileWrite) => "FileWrite".to_string(),
        Ok(ActionType::FileRead) => "FileRead".to_string(),
        Ok(ActionType::Custom) => "Custom".to_string(),
        _ => "Unknown".to_string(),
    }
}

/// 将 proto EdgeKind 转为 Datalog 字符串
fn edge_kind_to_string(ek: i32) -> String {
    match ProtoEdgeKind::try_from(ek) {
        Ok(ProtoEdgeKind::DataFlow) => "data_flow".to_string(),
        Ok(ProtoEdgeKind::ControlFlow) => "control_flow".to_string(),
        Ok(ProtoEdgeKind::Causal) => "causal".to_string(),
        Ok(ProtoEdgeKind::Temporal) => "temporal".to_string(),
        _ => "unknown".to_string(),
    }
}

/// 从 GraphSnapshot 构建 Datalog 事实
fn build_graph_facts(snapshot: &GraphSnapshot) -> Vec<Atom> {
    let mut graph_facts = Vec::new();

    // graph_edge 事实
    for edge in &snapshot.edges {
        graph_facts.push(facts::build_graph_edge(
            &edge.src,
            &edge.dst,
            &edge_kind_to_string(edge.kind),
        ));
    }

    // graph_label 事实
    for node in &snapshot.nodes {
        if !node.label.is_empty() {
            graph_facts.push(facts::build_graph_label(&node.node_id, &node.label));
        }
    }

    graph_facts
}

/// 序列化规则列表用于哈希（与 cert-checker-ffi 保持一致）
fn serialize_rules_for_hash(rules: &[Rule]) -> Vec<u8> {
    serde_json::to_vec(rules).unwrap_or_default()
}

/// 序列化 Atom 列表用于哈希
fn serialize_atoms_for_hash(atoms: &[Atom]) -> Vec<u8> {
    serde_json::to_vec(atoms).unwrap_or_default()
}

/// 获取评估超时
fn eval_timeout() -> Duration {
    let ms: u64 = std::env::var("PCM_EVAL_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_EVAL_TIMEOUT_MS);
    Duration::from_millis(ms)
}

// ──────────────────────────────────────────────
// MonitorServiceImpl
// ──────────────────────────────────────────────

/// Monitor 服务实现
pub struct MonitorServiceImpl {
    start_time: Instant,
    /// 已编译策略（热加载用）
    policy: Arc<RwLock<CompiledPolicy>>,
    /// 策略 AST
    policy_source: Arc<RwLock<PolicyAst>>,
    /// graph-service gRPC 客户端
    graph_client: Option<GraphServiceClient<Channel>>,
    /// 角色映射表 (principal, role)
    roles: Arc<RwLock<Vec<(String, String)>>>,
}

impl MonitorServiceImpl {
    /// 创建新实例（无策略、无图客户端）
    pub fn new() -> Self {
        // 空策略 — 无规则 → 无 deny → 默认 Allow
        let empty_ast = PolicyAst { rules: vec![] };
        let compiled = default_compiled_policy();

        Self {
            start_time: Instant::now(),
            policy: Arc::new(RwLock::new(compiled)),
            policy_source: Arc::new(RwLock::new(empty_ast)),
            graph_client: None,
            roles: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// 从外部共享的策略状态创建实例（配合 PolicyLoader 使用）
    pub fn new_with_policy(
        policy: Arc<RwLock<CompiledPolicy>>,
        policy_source: Arc<RwLock<PolicyAst>>,
    ) -> Self {
        Self {
            start_time: Instant::now(),
            policy,
            policy_source,
            graph_client: None,
            roles: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// 带 graph 客户端的构造函数
    pub fn with_graph_client(mut self, client: GraphServiceClient<Channel>) -> Self {
        self.graph_client = Some(client);
        self
    }

    /// 加载策略（线程安全）
    pub fn load_policy(&self, source: &str) -> Result<(), String> {
        let ast = pcm_policy_dsl::parse_policy(source).map_err(|e| format!("{e}"))?;
        let result = compile(&ast, "runtime").map_err(|e| format!("{e}"))?;

        {
            let mut policy = self.policy.write().unwrap();
            *policy = result.policy;
        }
        {
            let mut src = self.policy_source.write().unwrap();
            *src = ast;
        }

        tracing::info!("policy loaded successfully");
        Ok(())
    }

    /// 设置角色映射
    pub fn set_roles(&self, new_roles: Vec<(String, String)>) {
        let mut roles = self.roles.write().unwrap();
        *roles = new_roles;
    }

    /// 验证 EvaluateRequest 中的 Request 字段
    fn validate_request(req: &pcm_common::proto::pcm_v1::Request) -> Result<(), Box<Status>> {
        if req.request_id.is_empty() {
            return Err(Box::new(Status::invalid_argument("empty request_id")));
        }
        // action_type == 0 means ACTION_TYPE_UNSPECIFIED
        if ActionType::try_from(req.action_type) == Ok(ActionType::Unspecified) {
            return Err(Box::new(Status::invalid_argument(
                "unspecified action_type",
            )));
        }
        Ok(())
    }

    /// 直接评估单个请求，可选注入本地 GraphSnapshot（不经过 graph-service）。
    pub async fn evaluate_direct(
        &self,
        req: &pcm_common::proto::pcm_v1::Request,
        dry_run: bool,
        graph_snapshot: Option<&GraphSnapshot>,
    ) -> Result<EvaluateResponse, Status> {
        Self::validate_request(req).map_err(|status| *status)?;
        Ok(self
            .evaluate_single_with_snapshot(req, dry_run, graph_snapshot)
            .await)
    }

    /// 查询 graph-service 获取图快照（降级模式：返回空快照）
    #[tracing::instrument(skip(self), level = "debug")]
    async fn fetch_graph_snapshot(&self) -> GraphSnapshot {
        if let Some(client) = &self.graph_client {
            let mut client = client.clone();
            let req = tonic::Request::new(GetSnapshotRequest {
                session_id: String::new(),
            });

            let timeout = Duration::from_millis(GRAPH_RPC_TIMEOUT_MS);
            match tokio::time::timeout(timeout, client.get_snapshot(req)).await {
                Ok(Ok(resp)) => {
                    tracing::debug!("graph snapshot fetched successfully");
                    return resp.into_inner();
                }
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, "graph-service RPC failed, using empty graph");
                }
                Err(_) => {
                    tracing::warn!("graph-service RPC timed out, using empty graph");
                }
            }
        }

        // 降级模式：返回空快照
        GraphSnapshot {
            snapshot_hash: vec![],
            nodes: vec![],
            edges: vec![],
            as_of: None,
        }
    }

    /// 执行单次评估 — 完整运行时评估流程
    ///
    /// 1. 构建基础事实（baseFacts）
    /// 2. 查询图数据
    /// 3. 策略评估（DatalogEngine）
    /// 4. 生成证书/Witness
    /// 5. 证书自验证
    /// 6. 构造 Decision 返回
    #[tracing::instrument(skip(self, req), fields(request_id = %req.request_id))]
    async fn evaluate_single_with_snapshot(
        &self,
        req: &pcm_common::proto::pcm_v1::Request,
        _dry_run: bool,
        graph_snapshot: Option<&GraphSnapshot>,
    ) -> EvaluateResponse {
        let start = Instant::now();
        let timeout = eval_timeout();

        // ── 1. 读取当前策略 ──
        let (compiled_policy, rules) = {
            let policy = self.policy.read().unwrap();
            let ast = decompile(&policy);
            let rules: Vec<Rule> = ast.rules;
            (policy.clone(), rules)
        };

        // ── 2. 构建请求事实 ──
        let action_str = action_type_to_string(req.action_type);
        let request_fact =
            facts::build_request_fact(&req.request_id, &action_str, &req.principal, &req.target);
        let request_facts = vec![request_fact.clone()];

        // ── 3. 构建角色事实 ──
        let role_facts = {
            let roles = self.roles.read().unwrap();
            facts::build_role_facts(&roles)
        };

        // ── 4. 查询图数据 ──
        let graph_snapshot = match graph_snapshot {
            Some(snapshot) => snapshot.clone(),
            None => self.fetch_graph_snapshot().await,
        };
        let graph_facts = build_graph_facts(&graph_snapshot);

        // ── 5. 组装所有基础事实 ──
        let mut all_base_facts = Vec::with_capacity(1 + role_facts.len() + graph_facts.len());
        all_base_facts.push(request_fact);
        all_base_facts.extend(role_facts);
        all_base_facts.extend(graph_facts.iter().cloned());

        // ── 6. 计算哈希 ──
        let policy_hash = blake3_hash(&serialize_rules_for_hash(&rules));
        let request_hash = blake3_hash(&serialize_atoms_for_hash(&request_facts));
        let graph_atoms_for_hash: Vec<&Atom> = all_base_facts
            .iter()
            .filter(|a| !request_facts.contains(a))
            .collect();
        let graph_hash =
            blake3_hash(&serde_json::to_vec(&graph_atoms_for_hash).unwrap_or_default());

        // ── 7. 策略评估（带超时） ──
        let engine = DatalogEngine::new(rules.clone(), MAX_ITERATIONS);
        let base_facts_clone = all_base_facts.clone();

        let eval_result = {
            let eval_future =
                tokio::task::spawn_blocking(move || engine.evaluate(base_facts_clone));

            match tokio::time::timeout(timeout, eval_future).await {
                Ok(Ok(Ok(result))) => result,
                Ok(Ok(Err(e))) => {
                    tracing::warn!(error = %e, "DatalogEngine evaluation error");
                    return Self::make_error_response(req, start, &compiled_policy);
                }
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, "DatalogEngine task panicked");
                    return Self::make_error_response(req, start, &compiled_policy);
                }
                Err(_) => {
                    tracing::warn!("evaluation timed out");
                    return Self::make_error_response(req, start, &compiled_policy);
                }
            }
        };

        // ── 8. 确定 verdict ──
        let verdict = if eval_result.has_deny {
            Verdict::Deny
        } else {
            Verdict::Allow
        };

        // ── 9. 生成证书/Witness ──
        let evidence = if !eval_result.has_deny {
            // Allow → 证书
            match generate_certificate(&eval_result, &rules, policy_hash, graph_hash, request_hash)
            {
                Ok(cert_data) => {
                    // 自验证
                    let verify_result = verify_certificate_structured(
                        &cert_data,
                        &request_facts,
                        &rules,
                        &all_base_facts,
                    );
                    if !verify_result.valid {
                        tracing::warn!(
                            error = ?verify_result.error,
                            "certificate self-verification FAILED (decision unchanged)"
                        );
                    }
                    Some(pcm_common::proto::pcm_v1::decision::Evidence::Certificate(
                        cert_data.to_proto(),
                    ))
                }
                Err(e) => {
                    tracing::warn!(error = %e, "certificate generation failed");
                    None
                }
            }
        } else {
            // Deny → Witness
            match generate_witness(&eval_result, &rules, policy_hash, request_hash) {
                Ok(witness_data) => {
                    // 自验证
                    let verify_result =
                        verify_witness_structured(&witness_data, &rules, &all_base_facts);
                    if !verify_result.valid {
                        tracing::warn!(
                            error = ?verify_result.error,
                            "witness self-verification FAILED (decision unchanged)"
                        );
                    }
                    Some(pcm_common::proto::pcm_v1::decision::Evidence::Witness(
                        witness_data.to_proto(),
                    ))
                }
                Err(e) => {
                    tracing::warn!(error = %e, "witness generation failed");
                    None
                }
            }
        };

        // ── 10. 构造 Decision ──
        let policy_version_hash = hex::encode(compiled_policy.content_hash);
        let decided_at = Some(prost_types::Timestamp {
            seconds: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
            nanos: 0,
        });

        let decision = Decision {
            request_id: req.request_id.clone(),
            verdict: verdict.into(),
            evidence,
            policy_version_hash,
            graph_snapshot_hash: graph_snapshot.snapshot_hash,
            decided_at,
            signature: vec![],
        };

        let duration_us = start.elapsed().as_micros() as u64;

        EvaluateResponse {
            decision: Some(decision),
            evaluation_duration_us: duration_us,
        }
    }

    /// 构造 Error verdict 响应（fail-closed）
    fn make_error_response(
        req: &pcm_common::proto::pcm_v1::Request,
        start: Instant,
        policy: &CompiledPolicy,
    ) -> EvaluateResponse {
        let decision = Decision {
            request_id: req.request_id.clone(),
            verdict: Verdict::Error.into(),
            evidence: None,
            policy_version_hash: hex::encode(policy.content_hash),
            graph_snapshot_hash: vec![],
            decided_at: None,
            signature: vec![],
        };
        EvaluateResponse {
            decision: Some(decision),
            evaluation_duration_us: start.elapsed().as_micros() as u64,
        }
    }
}

impl Default for MonitorServiceImpl {
    fn default() -> Self {
        Self::new()
    }
}

/// 创建带空规则的默认 CompiledPolicy
fn default_compiled_policy() -> CompiledPolicy {
    let empty_ast = PolicyAst { rules: vec![] };
    // compile 不接受空策略时使用手动构造
    match compile(&empty_ast, "default") {
        Ok(result) => result.policy,
        Err(_) => CompiledPolicy {
            rules: vec![],
            strata: vec![],
            fact_schema: pcm_policy_dsl::compiler::FactSchema { predicates: vec![] },
            content_hash: [0u8; 32],
            version: "default".to_string(),
            decidable: true,
        },
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

        Self::validate_request(inner_req).map_err(|status| *status)?;

        tracing::info!(
            request_id = %inner_req.request_id,
            action_type = inner_req.action_type,
            principal = %inner_req.principal,
            dry_run = eval_req.dry_run,
            "evaluating request"
        );

        let response = self
            .evaluate_direct(inner_req, eval_req.dry_run, None)
            .await?;
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

            Self::validate_request(inner_req).map_err(|status| *status)?;

            tracing::info!(
                request_id = %inner_req.request_id,
                action_type = inner_req.action_type,
                principal = %inner_req.principal,
                dry_run = eval_req.dry_run,
                "evaluating request (batch)"
            );

            responses.push(
                self.evaluate_direct(inner_req, eval_req.dry_run, None)
                    .await?,
            );
        }

        Ok(Response::new(EvaluateBatchResponse { responses }))
    }

    async fn health(
        &self,
        _request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        let uptime = self.start_time.elapsed().as_secs();

        // 策略版本哈希
        let policy_version = {
            let policy = self.policy.read().unwrap();
            hex::encode(policy.content_hash)
        };

        // graph-service 连接状态检查
        let graph_ok = if let Some(client) = &self.graph_client {
            let mut client = client.clone();
            let req = tonic::Request::new(GetSnapshotRequest {
                session_id: String::new(),
            });
            let timeout = Duration::from_millis(GRAPH_RPC_TIMEOUT_MS);
            tokio::time::timeout(timeout, client.get_snapshot(req))
                .await
                .is_ok()
        } else {
            true // 无图客户端时仍健康（降级模式）
        };

        Ok(Response::new(HealthResponse {
            healthy: graph_ok,
            policy_version,
            uptime_seconds: uptime,
        }))
    }
}
