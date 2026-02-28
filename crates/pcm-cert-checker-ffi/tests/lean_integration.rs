use pcm_cert::generator::{CertStep, CertificateData, SerializedAtom, ViolationPath, WitnessData};
use pcm_cert_checker_ffi::{
    lean_checker, verify_certificate_structured, verify_witness_structured,
};
use pcm_common::hash::blake3_hash;
use pcm_policy_dsl::ast::{Atom, Literal, Rule, Term};

fn c(value: &str) -> Term {
    Term::Const(value.to_string())
}

fn action_fact(id: &str, action_type: &str, principal: &str, target: &str) -> Atom {
    Atom::Action {
        id: c(id),
        action_type: c(action_type),
        principal: c(principal),
        target: c(target),
    }
}

fn has_role(principal: &str, role: &str) -> Atom {
    Atom::HasRole {
        principal: c(principal),
        role: c(role),
    }
}

fn graph_edge(src: &str, dst: &str, kind: &str) -> Atom {
    Atom::GraphEdge {
        src: c(src),
        dst: c(dst),
        kind: c(kind),
    }
}

fn precedes(before: &str, after: &str) -> Atom {
    Atom::Precedes {
        before: c(before),
        after: c(after),
    }
}

fn deny_atom(request: &str, reason: &str) -> Atom {
    Atom::Deny {
        request: c(request),
        reason: c(reason),
    }
}

fn serialized(predicate: &str, args: &[&str]) -> SerializedAtom {
    SerializedAtom {
        predicate: predicate.to_string(),
        args: args.iter().map(|value| value.to_string()).collect(),
    }
}

fn serialize_rules_for_hash(rules: &[Rule]) -> Vec<u8> {
    serde_json::to_vec(rules).expect("policy should serialize")
}

fn serialize_atoms_for_hash(atoms: &[Atom]) -> Vec<u8> {
    serde_json::to_vec(atoms).expect("facts should serialize")
}

fn compute_hashes(
    rules: &[Rule],
    request_facts: &[Atom],
    all_base_facts: &[Atom],
) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let policy_hash = blake3_hash(&serialize_rules_for_hash(rules));
    let request_hash = blake3_hash(&serialize_atoms_for_hash(request_facts));
    let graph_facts: Vec<&Atom> = all_base_facts
        .iter()
        .filter(|atom| !request_facts.contains(atom))
        .collect();
    let graph_hash =
        blake3_hash(&serde_json::to_vec(&graph_facts).expect("graph facts should serialize"));

    (policy_hash, graph_hash, request_hash)
}

fn assert_cert_case(
    cert: CertificateData,
    request_facts: Vec<Atom>,
    rules: Vec<Rule>,
    extra_facts: Vec<Atom>,
    expected: bool,
) {
    let mut all_base_facts = request_facts.clone();
    all_base_facts.extend(extra_facts);

    let rust_result = verify_certificate_structured(&cert, &request_facts, &rules, &all_base_facts);
    let lean_result = lean_checker::verify_certificate_via_lean_checker(
        &cert,
        &request_facts,
        &rules,
        &all_base_facts,
    )
    .expect("build lean/.lake/build/bin/pcm_checker before running this test");

    assert_eq!(
        rust_result.valid, expected,
        "rust result: {:?}",
        rust_result.error
    );
    assert_eq!(
        lean_result.valid, expected,
        "lean result: {:?}",
        lean_result.error
    );
    assert_eq!(rust_result.valid, lean_result.valid);
}

fn assert_witness_case(
    witness: WitnessData,
    request_facts: Vec<Atom>,
    rules: Vec<Rule>,
    extra_facts: Vec<Atom>,
    expected: bool,
) {
    let mut all_base_facts = request_facts.clone();
    all_base_facts.extend(extra_facts);

    let rust_result = verify_witness_structured(&witness, &rules, &all_base_facts);
    let lean_result = lean_checker::verify_witness_via_lean_checker(
        &witness,
        &request_facts,
        &rules,
        &all_base_facts,
    )
    .expect("build lean/.lake/build/bin/pcm_checker before running this test");

    assert_eq!(
        rust_result.valid, expected,
        "rust result: {:?}",
        rust_result.error
    );
    assert_eq!(
        lean_result.valid, expected,
        "lean result: {:?}",
        lean_result.error
    );
    assert_eq!(rust_result.valid, lean_result.valid);
}

#[test]
fn empty_allow_certificate_passes() {
    let rules = vec![];
    let request_facts = vec![action_fact("r1", "HttpOut", "alice", "api.example.com")];
    let (policy_hash, graph_hash, request_hash) =
        compute_hashes(&rules, &request_facts, &request_facts);
    let cert = CertificateData {
        steps: vec![],
        policy_hash,
        graph_hash,
        request_hash,
    };

    assert_cert_case(cert, request_facts, rules, vec![], true);
}

#[test]
fn allow_certificate_with_role_rule_passes() {
    let rules = vec![Rule {
        head: precedes("a", "b"),
        body: vec![Literal::Pos(has_role("alice", "admin"))],
    }];
    let request_facts = vec![action_fact("r2", "HttpOut", "alice", "api.example.com")];
    let extra_facts = vec![has_role("alice", "admin")];
    let mut all_base_facts = request_facts.clone();
    all_base_facts.extend(extra_facts.clone());
    let (policy_hash, graph_hash, request_hash) =
        compute_hashes(&rules, &request_facts, &all_base_facts);
    let cert = CertificateData {
        steps: vec![CertStep {
            rule_index: 0,
            premise_indices: vec![],
            conclusion: serialized("precedes", &["a", "b"]),
        }],
        policy_hash,
        graph_hash,
        request_hash,
    };

    assert_cert_case(cert, request_facts, rules, extra_facts, true);
}

#[test]
fn allow_certificate_with_graph_rule_passes() {
    let rules = vec![Rule {
        head: precedes("start", "done"),
        body: vec![Literal::Pos(graph_edge(
            "alice",
            "api.example.com",
            "DataFlow",
        ))],
    }];
    let request_facts = vec![action_fact("r3", "HttpOut", "alice", "api.example.com")];
    let extra_facts = vec![graph_edge("alice", "api.example.com", "DataFlow")];
    let mut all_base_facts = request_facts.clone();
    all_base_facts.extend(extra_facts.clone());
    let (policy_hash, graph_hash, request_hash) =
        compute_hashes(&rules, &request_facts, &all_base_facts);
    let cert = CertificateData {
        steps: vec![CertStep {
            rule_index: 0,
            premise_indices: vec![],
            conclusion: serialized("precedes", &["start", "done"]),
        }],
        policy_hash,
        graph_hash,
        request_hash,
    };

    assert_cert_case(cert, request_facts, rules, extra_facts, true);
}

#[test]
fn invalid_rule_index_certificate_fails() {
    let rules = vec![];
    let request_facts = vec![action_fact("r4", "HttpOut", "alice", "api.example.com")];
    let (policy_hash, graph_hash, request_hash) =
        compute_hashes(&rules, &request_facts, &request_facts);
    let cert = CertificateData {
        steps: vec![CertStep {
            rule_index: 99,
            premise_indices: vec![],
            conclusion: serialized("deny", &["r4", "fake"]),
        }],
        policy_hash,
        graph_hash,
        request_hash,
    };

    assert_cert_case(cert, request_facts, rules, vec![], false);
}

#[test]
fn tampered_policy_hash_certificate_fails() {
    let rules = vec![];
    let request_facts = vec![action_fact("r5", "HttpOut", "alice", "api.example.com")];
    let (_, graph_hash, request_hash) = compute_hashes(&rules, &request_facts, &request_facts);
    let cert = CertificateData {
        steps: vec![],
        policy_hash: [42u8; 32],
        graph_hash,
        request_hash,
    };

    assert_cert_case(cert, request_facts, rules, vec![], false);
}

#[test]
fn tampered_graph_hash_certificate_fails() {
    let rules = vec![];
    let request_facts = vec![action_fact("r6", "HttpOut", "alice", "api.example.com")];
    let (policy_hash, _, request_hash) = compute_hashes(&rules, &request_facts, &request_facts);
    let cert = CertificateData {
        steps: vec![],
        policy_hash,
        graph_hash: [7u8; 32],
        request_hash,
    };

    assert_cert_case(cert, request_facts, rules, vec![], false);
}

#[test]
fn valid_deny_witness_passes() {
    let rules = vec![Rule {
        head: deny_atom("r7", "unauthorized_http"),
        body: vec![
            Literal::Pos(action_fact("r7", "HttpOut", "alice", "api.example.com")),
            Literal::Neg(has_role("alice", "http_allowed")),
        ],
    }];
    let request_facts = vec![action_fact("r7", "HttpOut", "alice", "api.example.com")];
    let (policy_hash, _, request_hash) = compute_hashes(&rules, &request_facts, &request_facts);
    let witness = WitnessData {
        deny_rule_index: 0,
        deny_rule_id: "R0: unauthorized_http".to_string(),
        human_readable_reason: "unauthorized_http".to_string(),
        matched_facts: vec![serialized(
            "action",
            &["r7", "HttpOut", "alice", "api.example.com"],
        )],
        violation_paths: vec![],
        policy_hash,
        request_hash,
    };

    assert_witness_case(witness, request_facts, rules, vec![], true);
}

#[test]
fn graph_deny_witness_passes() {
    let rules = vec![Rule {
        head: deny_atom("r8", "data_exfiltration"),
        body: vec![
            Literal::Pos(action_fact("r8", "HttpOut", "agent", "external.com")),
            Literal::Pos(graph_edge("agent", "external.com", "DataFlow")),
        ],
    }];
    let request_facts = vec![action_fact("r8", "HttpOut", "agent", "external.com")];
    let extra_facts = vec![graph_edge("agent", "external.com", "DataFlow")];
    let mut all_base_facts = request_facts.clone();
    all_base_facts.extend(extra_facts.clone());
    let (policy_hash, _, request_hash) = compute_hashes(&rules, &request_facts, &all_base_facts);
    let witness = WitnessData {
        deny_rule_index: 0,
        deny_rule_id: "R0: data_exfiltration".to_string(),
        human_readable_reason: "data_exfiltration".to_string(),
        matched_facts: vec![
            serialized("action", &["r8", "HttpOut", "agent", "external.com"]),
            serialized("graph_edge", &["agent", "external.com", "DataFlow"]),
        ],
        violation_paths: vec![ViolationPath {
            description: "data_flow: agent -> external.com".to_string(),
            edges: vec![(
                "agent".to_string(),
                "external.com".to_string(),
                "DataFlow".to_string(),
            )],
        }],
        policy_hash,
        request_hash,
    };

    assert_witness_case(witness, request_facts, rules, extra_facts, true);
}

#[test]
fn invalid_witness_base_fact_fails() {
    let rules = vec![Rule {
        head: deny_atom("r9", "unauthorized_http"),
        body: vec![
            Literal::Pos(action_fact("r9", "HttpOut", "alice", "api.example.com")),
            Literal::Neg(has_role("alice", "http_allowed")),
        ],
    }];
    let request_facts = vec![action_fact("r9", "HttpOut", "alice", "api.example.com")];
    let (policy_hash, _, request_hash) = compute_hashes(&rules, &request_facts, &request_facts);
    let witness = WitnessData {
        deny_rule_index: 0,
        deny_rule_id: "R0: unauthorized_http".to_string(),
        human_readable_reason: "unauthorized_http".to_string(),
        matched_facts: vec![serialized("has_role", &["alice", "nonexistent_role"])],
        violation_paths: vec![],
        policy_hash,
        request_hash,
    };

    assert_witness_case(witness, request_facts, rules, vec![], false);
}

#[test]
fn tampered_policy_hash_witness_fails() {
    let rules = vec![Rule {
        head: deny_atom("r10", "unauthorized_http"),
        body: vec![
            Literal::Pos(action_fact("r10", "HttpOut", "alice", "api.example.com")),
            Literal::Neg(has_role("alice", "http_allowed")),
        ],
    }];
    let request_facts = vec![action_fact("r10", "HttpOut", "alice", "api.example.com")];
    let (_, _, request_hash) = compute_hashes(&rules, &request_facts, &request_facts);
    let witness = WitnessData {
        deny_rule_index: 0,
        deny_rule_id: "R0: unauthorized_http".to_string(),
        human_readable_reason: "unauthorized_http".to_string(),
        matched_facts: vec![serialized(
            "action",
            &["r10", "HttpOut", "alice", "api.example.com"],
        )],
        violation_paths: vec![],
        policy_hash: [9u8; 32],
        request_hash,
    };

    assert_witness_case(witness, request_facts, rules, vec![], false);
}
