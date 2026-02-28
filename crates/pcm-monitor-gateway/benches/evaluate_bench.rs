use std::collections::HashSet;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use pcm_cert::generator::{CertificateData, generate_certificate};
use pcm_cert_checker_ffi::verify_certificate_structured;
use pcm_common::hash::blake3_hash;
use pcm_common::proto::pcm_v1::{
    ActionType, EdgeKind, GraphEdge, GraphNode, GraphSnapshot, NodeKind, Request,
};
use pcm_datalog_engine::engine::{DatalogEngine, EvalResult};
use pcm_datalog_engine::facts;
use pcm_monitor_gateway::service::MonitorServiceImpl;
use pcm_policy_dsl::ast::{Atom, Rule};
use pcm_policy_dsl::{compile, parse_policy};
use tokio::runtime::{Builder, Runtime};

const MAX_EVAL_ITERATIONS: usize = 1_000;
const GRAPH_NODE_COUNT: usize = 100;
const GRAPH_EDGE_COUNT: usize = 500;

struct PreparedCertificateCase {
    rules: Vec<Rule>,
    request_facts: Vec<Atom>,
    all_base_facts: Vec<Atom>,
    eval_result: EvalResult,
    certificate: CertificateData,
    policy_hash: [u8; 32],
    graph_hash: [u8; 32],
    request_hash: [u8; 32],
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn env_duration_ms(name: &str, default_ms: u64) -> Duration {
    Duration::from_millis(
        std::env::var(name)
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(default_ms),
    )
}

fn benchmark_config() -> Criterion {
    Criterion::default()
        .sample_size(env_usize("PCM_BENCH_SAMPLE_SIZE", 100))
        .warm_up_time(env_duration_ms("PCM_BENCH_WARMUP_MS", 100))
        .measurement_time(env_duration_ms("PCM_BENCH_MEASURE_MS", 20))
}

fn build_runtime() -> Runtime {
    Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("tokio runtime")
}

fn build_request(request_id: &str, principal: &str) -> Request {
    Request {
        request_id: request_id.to_string(),
        action_type: ActionType::HttpOut as i32,
        principal: principal.to_string(),
        target: "external-api".to_string(),
        attributes: Default::default(),
        timestamp: None,
        context_hash: vec![],
    }
}

fn roles_for(principal: &str, num_roles: usize) -> Vec<(String, String)> {
    (0..num_roles)
        .map(|idx| (principal.to_string(), format!("role_{idx}")))
        .collect()
}

fn generate_policy(num_rules: usize) -> String {
    let mut source = String::new();
    for idx in 0..num_rules {
        source.push_str(&format!(
            "deny(Req, \"rule_{idx}\") :- action(Req, \"HttpOut\", P, _), !has_role(P, \"role_{idx}\").\n"
        ));
    }
    source
}

fn generate_graph_policy() -> String {
    let mut source = generate_policy(4);
    source.push_str(
        "deny(Req, \"graph_rule\") :- action(Req, \"HttpOut\", _, _), graph_edge(\"node_0\", \"node_1\", \"data_flow\"), graph_label(\"node_0\", \"secret\"), graph_label(\"node_1\", \"external\").\n",
    );
    source
}

fn generate_graph(num_nodes: usize, num_edges: usize, leak_present: bool) -> GraphSnapshot {
    let nodes = (0..num_nodes)
        .map(|idx| {
            let label = if idx == 0 {
                if leak_present { "secret" } else { "internal" }
            } else if idx == 1 {
                "external"
            } else if idx % 7 == 0 {
                "sensitive"
            } else {
                "internal"
            };

            GraphNode {
                node_id: format!("node_{idx}"),
                kind: match idx % 4 {
                    0 => NodeKind::Entity as i32,
                    1 => NodeKind::Action as i32,
                    2 => NodeKind::Data as i32,
                    _ => NodeKind::Resource as i32,
                },
                label: label.to_string(),
                attrs: Default::default(),
                created_at: None,
            }
        })
        .collect();

    let mut seen = HashSet::new();
    let mut edges = Vec::with_capacity(num_edges);

    for idx in 0..num_nodes.saturating_sub(1) {
        let src = idx;
        let dst = idx + 1;
        if seen.insert((src, dst, EdgeKind::DataFlow as i32)) {
            edges.push(GraphEdge {
                src: format!("node_{src}"),
                dst: format!("node_{dst}"),
                kind: EdgeKind::DataFlow as i32,
                created_at: None,
            });
        }
    }

    let mut cursor = 0usize;
    while edges.len() < num_edges {
        let src = (cursor * 17 + 3) % num_nodes;
        let dst = (cursor * 29 + 11) % num_nodes;
        cursor += 1;

        if src == dst {
            continue;
        }

        let kind = match cursor % 4 {
            0 => EdgeKind::DataFlow as i32,
            1 => EdgeKind::ControlFlow as i32,
            2 => EdgeKind::Causal as i32,
            _ => EdgeKind::Temporal as i32,
        };

        if seen.insert((src, dst, kind)) {
            edges.push(GraphEdge {
                src: format!("node_{src}"),
                dst: format!("node_{dst}"),
                kind,
                created_at: None,
            });
        }
    }

    GraphSnapshot {
        snapshot_hash: blake3_hash(
            format!(
                "graph:{num_nodes}:{num_edges}:{}",
                if leak_present { 1 } else { 0 }
            )
            .as_bytes(),
        )
        .to_vec(),
        nodes,
        edges,
        as_of: None,
    }
}

fn build_service(policy_source: &str, roles: Vec<(String, String)>) -> MonitorServiceImpl {
    let service = MonitorServiceImpl::new();
    service
        .load_policy(policy_source)
        .expect("benchmark policy should compile");
    service.set_roles(roles);
    service
}

fn bench_service_evaluate(
    c: &mut Criterion,
    name: &str,
    service: MonitorServiceImpl,
    request: Request,
    graph_snapshot: Option<GraphSnapshot>,
) {
    let runtime = build_runtime();

    c.bench_function(name, move |b| {
        b.iter(|| {
            let snapshot = graph_snapshot.as_ref().map(|value| black_box(value));
            let response = runtime
                .block_on(service.evaluate_direct(black_box(&request), false, snapshot))
                .expect("benchmark request should be valid");
            black_box(response);
        });
    });
}

fn compute_hashes(
    rules: &[Rule],
    request_facts: &[Atom],
    all_base_facts: &[Atom],
) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let policy_hash = blake3_hash(&serde_json::to_vec(rules).expect("rules should serialize"));
    let request_hash =
        blake3_hash(&serde_json::to_vec(request_facts).expect("request facts should serialize"));
    let graph_atoms: Vec<&Atom> = all_base_facts
        .iter()
        .filter(|atom| !request_facts.contains(atom))
        .collect();
    let graph_hash =
        blake3_hash(&serde_json::to_vec(&graph_atoms).expect("graph facts should serialize"));

    (policy_hash, graph_hash, request_hash)
}

fn prepare_allow_certificate_case() -> PreparedCertificateCase {
    let policy_source = generate_policy(2);
    let ast = parse_policy(&policy_source).expect("policy parses");
    compile(&ast, "bench-cert").expect("policy compiles");
    let rules = ast.rules;

    let request_facts = vec![facts::build_request_fact(
        "cert-req",
        "HttpOut",
        "bench-agent",
        "external-api",
    )];
    let mut all_base_facts = request_facts.clone();
    all_base_facts.extend(facts::build_role_facts(&roles_for("bench-agent", 2)));

    let engine = DatalogEngine::new(rules.clone(), MAX_EVAL_ITERATIONS);
    let eval_result = engine
        .evaluate(all_base_facts.clone())
        .expect("allow evaluation should succeed");
    assert!(
        !eval_result.has_deny,
        "certificate benchmark needs an allow evaluation"
    );

    let (policy_hash, graph_hash, request_hash) =
        compute_hashes(&rules, &request_facts, &all_base_facts);
    let certificate =
        generate_certificate(&eval_result, &rules, policy_hash, graph_hash, request_hash)
            .expect("certificate should generate");

    PreparedCertificateCase {
        rules,
        request_facts,
        all_base_facts,
        eval_result,
        certificate,
        policy_hash,
        graph_hash,
        request_hash,
    }
}

fn compile_policy_source(source: &str) {
    let ast = parse_policy(source).expect("generated policy should parse");
    let compiled = compile(&ast, "bench-policy").expect("generated policy should compile");
    black_box(compiled);
}

fn bench_evaluate_simple_allow(c: &mut Criterion) {
    let principal = "simple-allow";
    let service = build_service(&generate_policy(2), roles_for(principal, 2));
    let request = build_request("simple-allow-req", principal);
    bench_service_evaluate(c, "evaluate_simple_allow", service, request, None);
}

fn bench_evaluate_simple_deny(c: &mut Criterion) {
    let principal = "simple-deny";
    let service = build_service(&generate_policy(2), vec![]);
    let request = build_request("simple-deny-req", principal);
    bench_service_evaluate(c, "evaluate_simple_deny", service, request, None);
}

fn bench_evaluate_medium_allow(c: &mut Criterion) {
    let principal = "medium-allow";
    let service = build_service(&generate_policy(20), roles_for(principal, 20));
    let request = build_request("medium-allow-req", principal);
    bench_service_evaluate(c, "evaluate_medium_allow", service, request, None);
}

fn bench_evaluate_medium_deny(c: &mut Criterion) {
    let principal = "medium-deny";
    let service = build_service(&generate_policy(20), vec![]);
    let request = build_request("medium-deny-req", principal);
    bench_service_evaluate(c, "evaluate_medium_deny", service, request, None);
}

fn bench_evaluate_graph_allow(c: &mut Criterion) {
    let principal = "graph-allow";
    let service = build_service(&generate_graph_policy(), roles_for(principal, 4));
    let request = build_request("graph-allow-req", principal);
    let graph = generate_graph(GRAPH_NODE_COUNT, GRAPH_EDGE_COUNT, false);
    bench_service_evaluate(c, "evaluate_graph_allow", service, request, Some(graph));
}

fn bench_evaluate_graph_deny(c: &mut Criterion) {
    let principal = "graph-deny";
    let service = build_service(&generate_graph_policy(), roles_for(principal, 4));
    let request = build_request("graph-deny-req", principal);
    let graph = generate_graph(GRAPH_NODE_COUNT, GRAPH_EDGE_COUNT, true);
    bench_service_evaluate(c, "evaluate_graph_deny", service, request, Some(graph));
}

fn bench_evaluate_large_policy(c: &mut Criterion) {
    let principal = "large-policy";
    let service = build_service(&generate_policy(200), vec![]);
    let request = build_request("large-policy-req", principal);
    bench_service_evaluate(c, "evaluate_large_policy", service, request, None);
}

fn bench_certificate_generation(c: &mut Criterion) {
    let prepared = prepare_allow_certificate_case();

    c.bench_function("certificate_generation", move |b| {
        b.iter(|| {
            let certificate = generate_certificate(
                black_box(&prepared.eval_result),
                black_box(&prepared.rules),
                black_box(prepared.policy_hash),
                black_box(prepared.graph_hash),
                black_box(prepared.request_hash),
            )
            .expect("certificate should generate");
            black_box(certificate);
        });
    });
}

fn bench_certificate_verification(c: &mut Criterion) {
    let prepared = prepare_allow_certificate_case();

    c.bench_function("certificate_verification", move |b| {
        b.iter(|| {
            let result = verify_certificate_structured(
                black_box(&prepared.certificate),
                black_box(&prepared.request_facts),
                black_box(&prepared.rules),
                black_box(&prepared.all_base_facts),
            );
            black_box(result);
        });
    });
}

fn bench_policy_compilation(c: &mut Criterion) {
    let sizes = [5usize, 20, 50, 100, 200];
    let mut group = c.benchmark_group("policy_compilation");

    for size in sizes {
        let policy_source = generate_policy(size);
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &policy_source,
            |b, source| {
                b.iter(|| compile_policy_source(black_box(source)));
            },
        );
    }

    group.finish();
}

criterion_group! {
    name = benches;
    config = benchmark_config();
    targets =
        bench_evaluate_simple_allow,
        bench_evaluate_simple_deny,
        bench_evaluate_medium_allow,
        bench_evaluate_medium_deny,
        bench_evaluate_graph_allow,
        bench_evaluate_graph_deny,
        bench_evaluate_large_policy,
        bench_certificate_generation,
        bench_certificate_verification,
        bench_policy_compilation
}
criterion_main!(benches);
