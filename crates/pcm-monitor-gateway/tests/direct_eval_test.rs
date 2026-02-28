use pcm_common::proto::pcm_v1::{
    ActionType, EdgeKind, GraphEdge, GraphNode, GraphSnapshot, NodeKind, Request, Verdict,
};
use pcm_monitor_gateway::service::MonitorServiceImpl;

#[tokio::test]
async fn test_evaluate_direct_with_local_graph_snapshot() {
    let svc = MonitorServiceImpl::new();
    svc.load_policy(
        r#"
deny(Req, "graph_rule") :-
    action(Req, "HttpOut", _, _),
    graph_edge("node_0", "node_1", "data_flow"),
    graph_label("node_0", "secret"),
    graph_label("node_1", "external").
"#,
    )
    .expect("policy should compile");

    let request = Request {
        request_id: "req-local-graph".to_string(),
        action_type: ActionType::HttpOut.into(),
        principal: "agent-1".to_string(),
        target: "external-api".to_string(),
        attributes: Default::default(),
        timestamp: None,
        context_hash: vec![],
    };

    let snapshot = GraphSnapshot {
        snapshot_hash: vec![1, 2, 3, 4],
        nodes: vec![
            GraphNode {
                node_id: "node_0".to_string(),
                kind: NodeKind::Entity.into(),
                label: "secret".to_string(),
                attrs: Default::default(),
                created_at: None,
            },
            GraphNode {
                node_id: "node_1".to_string(),
                kind: NodeKind::Resource.into(),
                label: "external".to_string(),
                attrs: Default::default(),
                created_at: None,
            },
        ],
        edges: vec![GraphEdge {
            src: "node_0".to_string(),
            dst: "node_1".to_string(),
            kind: EdgeKind::DataFlow.into(),
            created_at: None,
        }],
        as_of: None,
    };

    let response = svc
        .evaluate_direct(&request, false, Some(&snapshot))
        .await
        .expect("request should be valid");

    let decision = response.decision.expect("decision should be present");
    assert_eq!(decision.verdict, Verdict::Deny as i32);
    assert_eq!(decision.graph_snapshot_hash, snapshot.snapshot_hash);
}
