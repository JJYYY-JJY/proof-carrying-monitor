//! GraphService gRPC 实现

use std::sync::Arc;

use pcm_common::proto::pcm_v1::{
    AppendEventRequest, AppendEventResponse, ArchiveRequest, ArchiveResponse, GetSnapshotRequest,
    GraphSnapshot, ReachableRequest, ReachableResponse, graph_service_server::GraphService,
};
use prost::Message;
use tonic::{Request, Response, Status};

use crate::store::GraphStore;

/// gRPC GraphService 实现，内部持有共享的 GraphStore。
pub struct GraphServiceImpl {
    store: Arc<GraphStore>,
}

impl GraphServiceImpl {
    pub fn new(store: Arc<GraphStore>) -> Self {
        Self { store }
    }
}

#[tonic::async_trait]
impl GraphService for GraphServiceImpl {
    async fn append_event(
        &self,
        request: Request<AppendEventRequest>,
    ) -> Result<Response<AppendEventResponse>, Status> {
        let req = request.into_inner();
        let session_id = &req.session_id;

        tracing::info!(
            session_id = %session_id,
            new_nodes = req.new_nodes.len(),
            new_edges = req.new_edges.len(),
            "AppendEvent"
        );

        // Add nodes
        if !req.new_nodes.is_empty() {
            self.store
                .add_nodes(session_id, &req.new_nodes)
                .map_err(|e| Status::invalid_argument(format!("invalid node data: {e}")))?;
        }

        // Add edges
        if !req.new_edges.is_empty() {
            self.store
                .add_edges(session_id, &req.new_edges)
                .map_err(|e| Status::invalid_argument(format!("invalid edge data: {e}")))?;
        }

        // Compute snapshot hash
        let snapshot = self
            .store
            .get_snapshot(session_id)
            .map_err(|e| Status::internal(format!("failed to compute snapshot: {e}")))?;

        let node_count = self
            .store
            .node_count(session_id)
            .map_err(|e| Status::internal(format!("failed to count nodes: {e}")))?;
        let edge_count = self
            .store
            .edge_count(session_id)
            .map_err(|e| Status::internal(format!("failed to count edges: {e}")))?;

        Ok(Response::new(AppendEventResponse {
            updated_snapshot_hash: snapshot.snapshot_hash,
            node_count,
            edge_count,
        }))
    }

    async fn get_snapshot(
        &self,
        request: Request<GetSnapshotRequest>,
    ) -> Result<Response<GraphSnapshot>, Status> {
        let req = request.into_inner();
        let session_id = &req.session_id;

        tracing::info!(session_id = %session_id, "GetSnapshot");

        let snapshot = self
            .store
            .get_snapshot(session_id)
            .map_err(|e| Status::internal(format!("failed to get snapshot: {e}")))?;

        Ok(Response::new(snapshot))
    }

    async fn query_reachable(
        &self,
        request: Request<ReachableRequest>,
    ) -> Result<Response<ReachableResponse>, Status> {
        let req = request.into_inner();

        tracing::info!(
            from = %req.from_node,
            to = %req.to_node,
            edge_filter_count = req.edge_filter.len(),
            "QueryReachable"
        );

        if req.from_node.is_empty() || req.to_node.is_empty() {
            return Err(Status::invalid_argument(
                "from_node and to_node must not be empty",
            ));
        }

        // Convert i32 edge_filter values to EdgeKind enum
        let edge_filter: Vec<pcm_common::proto::pcm_v1::EdgeKind> = req
            .edge_filter
            .iter()
            .filter_map(|&v| pcm_common::proto::pcm_v1::EdgeKind::try_from(v).ok())
            .collect();

        // Use default session for reachability queries
        let session_id = "";

        let (reachable, paths) = self
            .store
            .query_reachable(session_id, &req.from_node, &req.to_node, &edge_filter)
            .map_err(|e| Status::internal(format!("reachability query failed: {e}")))?;

        Ok(Response::new(ReachableResponse { reachable, paths }))
    }

    async fn archive_snapshot(
        &self,
        request: Request<ArchiveRequest>,
    ) -> Result<Response<ArchiveResponse>, Status> {
        let req = request.into_inner();
        let session_id = &req.session_id;

        tracing::info!(session_id = %session_id, "ArchiveSnapshot");

        let snapshot = self
            .store
            .get_snapshot(session_id)
            .map_err(|e| Status::internal(format!("failed to get snapshot: {e}")))?;

        let snapshot_hash = snapshot.snapshot_hash.clone();

        // MVP: serialize snapshot to a local file (simulating S3 archive)
        let archive_key = format!(
            "/tmp/pcm-archive/{}-{}.bin",
            if session_id.is_empty() {
                "default"
            } else {
                session_id
            },
            hex::encode(&snapshot_hash)
        );

        // Ensure parent directory exists
        if let Some(parent) = std::path::Path::new(&archive_key).parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Status::internal(format!("failed to create archive dir: {e}")))?;
        }

        let encoded = snapshot.encode_to_vec();
        std::fs::write(&archive_key, &encoded)
            .map_err(|e| Status::internal(format!("failed to write archive: {e}")))?;

        tracing::info!(archive_key = %archive_key, "snapshot archived");

        Ok(Response::new(ArchiveResponse {
            archive_key,
            snapshot_hash,
        }))
    }
}
