//! PolicyService gRPC 实现

use std::sync::Arc;

use pcm_common::proto::pcm_v1::{
    ActivatePolicyRequest, ActivatePolicyResponse, CompilePolicyRequest, CompilePolicyResponse,
    CreatePolicyRequest, GetPolicyRequest, ListPolicyVersionsRequest, ListPolicyVersionsResponse,
    ValidatePolicyRequest, ValidatePolicyResponse, policy_service_server::PolicyService,
};
use tonic::{Request, Response, Status};

use crate::store::{PolicyStore, StoreError};

/// gRPC PolicyService 实现，内部持有共享的 PolicyStore。
pub struct PolicyServiceImpl {
    store: Arc<PolicyStore>,
}

impl PolicyServiceImpl {
    pub fn new(store: Arc<PolicyStore>) -> Self {
        Self { store }
    }
}

#[tonic::async_trait]
impl PolicyService for PolicyServiceImpl {
    #[tracing::instrument(skip(self, request), fields(rpc = "CreatePolicy"))]
    async fn create_policy(
        &self,
        request: Request<CreatePolicyRequest>,
    ) -> Result<Response<pcm_common::proto::pcm_v1::PolicyVersion>, Status> {
        let req = request.into_inner();

        tracing::info!(
            author = %req.author,
            commit_sha = %req.commit_sha,
            "CreatePolicy"
        );

        let record = self
            .store
            .create_policy(&req.source_dsl, &req.author, &req.commit_sha)
            .await
            .map_err(|e| {
                // Check if it's a compilation error
                if let Some(StoreError::CompilationFailed(msg)) = e.downcast_ref::<StoreError>() {
                    return Status::invalid_argument(format!("policy compilation failed: {msg}"));
                }
                Status::internal(format!("failed to create policy: {e}"))
            })?;

        Ok(Response::new(record.to_proto()))
    }

    #[tracing::instrument(skip(self, request), fields(rpc = "GetPolicy"))]
    async fn get_policy(
        &self,
        request: Request<GetPolicyRequest>,
    ) -> Result<Response<pcm_common::proto::pcm_v1::PolicyVersion>, Status> {
        let req = request.into_inner();

        tracing::info!(
            policy_id = %req.policy_id,
            version = %req.version,
            "GetPolicy"
        );

        let version = if req.version.is_empty() {
            None
        } else {
            Some(req.version.as_str())
        };

        let record = self
            .store
            .get_policy(&req.policy_id, version)
            .await
            .map_err(|e| Status::internal(format!("failed to get policy: {e}")))?
            .ok_or_else(|| {
                Status::not_found(format!(
                    "policy not found: {}{}",
                    req.policy_id,
                    if let Some(v) = version {
                        format!("@{v}")
                    } else {
                        String::new()
                    }
                ))
            })?;

        Ok(Response::new(record.to_proto()))
    }

    #[tracing::instrument(skip(self, request), fields(rpc = "ListPolicyVersions"))]
    async fn list_policy_versions(
        &self,
        request: Request<ListPolicyVersionsRequest>,
    ) -> Result<Response<ListPolicyVersionsResponse>, Status> {
        let req = request.into_inner();

        tracing::info!(
            policy_id = %req.policy_id,
            limit = req.limit,
            page_token = %req.page_token,
            "ListPolicyVersions"
        );

        let page_token = if req.page_token.is_empty() {
            None
        } else {
            Some(req.page_token.as_str())
        };

        let (records, next_page_token) = self
            .store
            .list_versions(&req.policy_id, req.limit, page_token)
            .await
            .map_err(|e| Status::internal(format!("failed to list versions: {e}")))?;

        let versions = records.iter().map(|r| r.to_proto()).collect();

        Ok(Response::new(ListPolicyVersionsResponse {
            versions,
            next_page_token: next_page_token.unwrap_or_default(),
        }))
    }

    #[tracing::instrument(skip(self, request), fields(rpc = "CompilePolicy"))]
    async fn compile_policy(
        &self,
        request: Request<CompilePolicyRequest>,
    ) -> Result<Response<CompilePolicyResponse>, Status> {
        let req = request.into_inner();

        tracing::info!("CompilePolicy");

        // 1. Parse
        let ast = pcm_policy_dsl::parse_policy(&req.source_dsl)
            .map_err(|e| Status::invalid_argument(format!("syntax error: {e}")))?;

        // 2. Compile
        let compile_result = pcm_policy_dsl::compile(&ast, "0.0.0")
            .map_err(|e| Status::invalid_argument(format!("compilation error: {e}")))?;

        // 3. Serialize compiled policy
        let compiled_bytes = serde_json::to_vec(&compile_result.policy)
            .map_err(|e| Status::internal(format!("failed to serialize compiled policy: {e}")))?;
        let content_hash = pcm_common::hash::blake3_hash(&compiled_bytes).to_vec();

        let compiled = pcm_common::proto::pcm_v1::CompiledPolicy {
            content: compiled_bytes,
            content_hash,
            version: compile_result.policy.version.clone(),
        };

        let warnings: Vec<String> = compile_result
            .warnings
            .iter()
            .map(|w| w.message.clone())
            .collect();

        Ok(Response::new(CompilePolicyResponse {
            compiled: Some(compiled),
            warnings,
            decidable: compile_result.policy.decidable,
        }))
    }

    #[tracing::instrument(skip(self, request), fields(rpc = "ValidatePolicy"))]
    async fn validate_policy(
        &self,
        request: Request<ValidatePolicyRequest>,
    ) -> Result<Response<ValidatePolicyResponse>, Status> {
        let req = request.into_inner();

        tracing::info!("ValidatePolicy");

        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        // 1. Parse
        let ast = match pcm_policy_dsl::parse_policy(&req.source_dsl) {
            Ok(ast) => ast,
            Err(e) => {
                errors.push(format!("syntax error: {e}"));
                return Ok(Response::new(ValidatePolicyResponse {
                    valid: false,
                    errors,
                    warnings,
                }));
            }
        };

        // 2. Compile (semantic validation)
        match pcm_policy_dsl::compile(&ast, "0.0.0") {
            Ok(result) => {
                warnings.extend(result.warnings.iter().map(|w| w.message.clone()));
            }
            Err(e) => {
                errors.push(format!("semantic error: {e}"));
                return Ok(Response::new(ValidatePolicyResponse {
                    valid: false,
                    errors,
                    warnings,
                }));
            }
        }

        Ok(Response::new(ValidatePolicyResponse {
            valid: true,
            errors,
            warnings,
        }))
    }

    #[tracing::instrument(skip(self, request), fields(rpc = "ActivatePolicy"))]
    async fn activate_policy(
        &self,
        request: Request<ActivatePolicyRequest>,
    ) -> Result<Response<ActivatePolicyResponse>, Status> {
        let req = request.into_inner();

        tracing::info!(
            policy_id = %req.policy_id,
            version = %req.version,
            "ActivatePolicy"
        );

        let activated = self
            .store
            .activate_policy(&req.policy_id, &req.version)
            .await
            .map_err(|e| {
                if let Some(store_err) = e.downcast_ref::<StoreError>() {
                    match store_err {
                        StoreError::NotFound(msg) => {
                            return Status::not_found(format!("policy not found: {msg}"));
                        }
                        StoreError::VersionDowngrade {
                            active, requested, ..
                        } => {
                            return Status::failed_precondition(format!(
                                "version downgrade rejected: active={active}, requested={requested}"
                            ));
                        }
                        _ => {}
                    }
                }
                Status::internal(format!("failed to activate policy: {e}"))
            })?;

        Ok(Response::new(ActivatePolicyResponse {
            activated,
            active_version: req.version,
        }))
    }
}
