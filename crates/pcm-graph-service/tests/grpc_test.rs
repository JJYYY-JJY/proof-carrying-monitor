//! 集成测试：GraphService gRPC

use std::sync::Arc;

use pcm_common::proto::pcm_v1::{
    AppendEventRequest, ArchiveRequest, EdgeKind, GetSnapshotRequest, GraphEdge, GraphNode,
    NodeKind, ReachableRequest, graph_service_client::GraphServiceClient,
    graph_service_server::GraphServiceServer,
};
use pcm_graph_service::service::GraphServiceImpl;
use pcm_graph_service::store::GraphStore;
use tonic::transport::Server;

use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Create a fresh temporary GraphStore for each test.
fn temp_store() -> Arc<GraphStore> {
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir =
        std::env::temp_dir().join(format!("pcm-graph-grpc-test-{}-{}", std::process::id(), id));
    Arc::new(GraphStore::open(dir.to_str().unwrap()).expect("open temp store"))
}

/// 在随机端口启动测试服务器，返回连接地址
async fn start_test_server() -> (String, Arc<GraphStore>) {
    let store = temp_store();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let svc = GraphServiceImpl::new(store.clone());
    tokio::spawn(async move {
        Server::builder()
            .add_service(GraphServiceServer::new(svc))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    (format!("http://{addr}"), store)
}

fn make_node(id: &str, kind: NodeKind, label: &str) -> GraphNode {
    GraphNode {
        node_id: id.to_string(),
        kind: kind as i32,
        label: label.to_string(),
        attrs: Default::default(),
        created_at: None,
    }
}

fn make_edge(src: &str, dst: &str, kind: EdgeKind) -> GraphEdge {
    GraphEdge {
        src: src.to_string(),
        dst: dst.to_string(),
        kind: kind as i32,
        created_at: None,
    }
}

// =========================================================================
// AppendEvent
// =========================================================================

#[tokio::test]
async fn test_append_event_nodes_and_edges() {
    let (addr, _store) = start_test_server().await;
    let mut client = GraphServiceClient::connect(addr).await.unwrap();

    let resp = client
        .append_event(AppendEventRequest {
            new_nodes: vec![
                make_node("a", NodeKind::Entity, "A"),
                make_node("b", NodeKind::Entity, "B"),
                make_node("c", NodeKind::Action, "C"),
            ],
            new_edges: vec![
                make_edge("a", "b", EdgeKind::DataFlow),
                make_edge("b", "c", EdgeKind::ControlFlow),
            ],
            session_id: String::new(),
        })
        .await
        .unwrap()
        .into_inner();

    assert_eq!(resp.node_count, 3);
    assert_eq!(resp.edge_count, 2);
    assert!(!resp.updated_snapshot_hash.is_empty());
}

#[tokio::test]
async fn test_append_event_only_nodes() {
    let (addr, _store) = start_test_server().await;
    let mut client = GraphServiceClient::connect(addr).await.unwrap();

    let resp = client
        .append_event(AppendEventRequest {
            new_nodes: vec![make_node("x", NodeKind::Data, "X")],
            new_edges: vec![],
            session_id: String::new(),
        })
        .await
        .unwrap()
        .into_inner();

    assert_eq!(resp.node_count, 1);
    assert_eq!(resp.edge_count, 0);
}

#[tokio::test]
async fn test_append_event_invalid_edge() {
    let (addr, _store) = start_test_server().await;
    let mut client = GraphServiceClient::connect(addr).await.unwrap();

    // Edge references non-existent nodes
    let status = client
        .append_event(AppendEventRequest {
            new_nodes: vec![],
            new_edges: vec![make_edge("missing_src", "missing_dst", EdgeKind::DataFlow)],
            session_id: String::new(),
        })
        .await
        .unwrap_err();

    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

// =========================================================================
// GetSnapshot
// =========================================================================

#[tokio::test]
async fn test_get_snapshot_after_append() {
    let (addr, _store) = start_test_server().await;
    let mut client = GraphServiceClient::connect(addr).await.unwrap();

    // Append some data
    client
        .append_event(AppendEventRequest {
            new_nodes: vec![
                make_node("n1", NodeKind::Entity, "Node1"),
                make_node("n2", NodeKind::Resource, "Node2"),
            ],
            new_edges: vec![make_edge("n1", "n2", EdgeKind::Causal)],
            session_id: "test-session".to_string(),
        })
        .await
        .unwrap();

    // Get snapshot
    let snapshot = client
        .get_snapshot(GetSnapshotRequest {
            session_id: "test-session".to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    assert_eq!(snapshot.nodes.len(), 2);
    assert_eq!(snapshot.edges.len(), 1);
    assert!(!snapshot.snapshot_hash.is_empty());
    assert!(snapshot.as_of.is_some());

    // Nodes should be sorted by node_id
    assert_eq!(snapshot.nodes[0].node_id, "n1");
    assert_eq!(snapshot.nodes[1].node_id, "n2");
}

#[tokio::test]
async fn test_get_snapshot_empty_session() {
    let (addr, _store) = start_test_server().await;
    let mut client = GraphServiceClient::connect(addr).await.unwrap();

    // An empty session should return an empty snapshot (not an error)
    let snapshot = client
        .get_snapshot(GetSnapshotRequest {
            session_id: String::new(),
        })
        .await
        .unwrap()
        .into_inner();

    assert!(snapshot.nodes.is_empty());
    assert!(snapshot.edges.is_empty());
}

// =========================================================================
// QueryReachable
// =========================================================================

#[tokio::test]
async fn test_query_reachable_chain() {
    let (addr, _store) = start_test_server().await;
    let mut client = GraphServiceClient::connect(addr).await.unwrap();

    // Build A → B → C chain in default session
    client
        .append_event(AppendEventRequest {
            new_nodes: vec![
                make_node("a", NodeKind::Entity, "A"),
                make_node("b", NodeKind::Entity, "B"),
                make_node("c", NodeKind::Entity, "C"),
            ],
            new_edges: vec![
                make_edge("a", "b", EdgeKind::DataFlow),
                make_edge("b", "c", EdgeKind::DataFlow),
            ],
            session_id: String::new(),
        })
        .await
        .unwrap();

    // Query A → C reachability
    let resp = client
        .query_reachable(ReachableRequest {
            from_node: "a".to_string(),
            to_node: "c".to_string(),
            edge_filter: vec![],
        })
        .await
        .unwrap()
        .into_inner();

    assert!(resp.reachable);
    assert!(!resp.paths.is_empty());
    assert_eq!(resp.paths[0].node_ids, vec!["a", "b", "c"]);
}

#[tokio::test]
async fn test_query_reachable_not_reachable() {
    let (addr, _store) = start_test_server().await;
    let mut client = GraphServiceClient::connect(addr).await.unwrap();

    // Add disconnected nodes
    client
        .append_event(AppendEventRequest {
            new_nodes: vec![
                make_node("x", NodeKind::Entity, "X"),
                make_node("y", NodeKind::Entity, "Y"),
            ],
            new_edges: vec![],
            session_id: String::new(),
        })
        .await
        .unwrap();

    let resp = client
        .query_reachable(ReachableRequest {
            from_node: "x".to_string(),
            to_node: "y".to_string(),
            edge_filter: vec![],
        })
        .await
        .unwrap()
        .into_inner();

    assert!(!resp.reachable);
    assert!(resp.paths.is_empty());
}

#[tokio::test]
async fn test_query_reachable_empty_nodes() {
    let (addr, _store) = start_test_server().await;
    let mut client = GraphServiceClient::connect(addr).await.unwrap();

    let status = client
        .query_reachable(ReachableRequest {
            from_node: String::new(),
            to_node: String::new(),
            edge_filter: vec![],
        })
        .await
        .unwrap_err();

    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

// =========================================================================
// ArchiveSnapshot
// =========================================================================

#[tokio::test]
async fn test_archive_snapshot() {
    let (addr, _store) = start_test_server().await;
    let mut client = GraphServiceClient::connect(addr).await.unwrap();

    // Add some data first
    client
        .append_event(AppendEventRequest {
            new_nodes: vec![make_node("ar1", NodeKind::Entity, "AR1")],
            new_edges: vec![],
            session_id: "archive-test".to_string(),
        })
        .await
        .unwrap();

    let resp = client
        .archive_snapshot(ArchiveRequest {
            session_id: "archive-test".to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    assert!(!resp.archive_key.is_empty());
    assert!(!resp.snapshot_hash.is_empty());
    // Verify the archive file was created
    assert!(std::path::Path::new(&resp.archive_key).exists());
}

// =========================================================================
// Incremental append
// =========================================================================

#[tokio::test]
async fn test_incremental_append() {
    let (addr, _store) = start_test_server().await;
    let mut client = GraphServiceClient::connect(addr).await.unwrap();

    // First append: add nodes
    let resp1 = client
        .append_event(AppendEventRequest {
            new_nodes: vec![
                make_node("p", NodeKind::Entity, "P"),
                make_node("q", NodeKind::Entity, "Q"),
            ],
            new_edges: vec![],
            session_id: "inc".to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    assert_eq!(resp1.node_count, 2);
    assert_eq!(resp1.edge_count, 0);

    // Second append: add an edge between existing nodes
    let resp2 = client
        .append_event(AppendEventRequest {
            new_nodes: vec![],
            new_edges: vec![make_edge("p", "q", EdgeKind::Temporal)],
            session_id: "inc".to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    assert_eq!(resp2.node_count, 2);
    assert_eq!(resp2.edge_count, 1);

    // Verify via snapshot
    let snap = client
        .get_snapshot(GetSnapshotRequest {
            session_id: "inc".to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    assert_eq!(snap.nodes.len(), 2);
    assert_eq!(snap.edges.len(), 1);
}
