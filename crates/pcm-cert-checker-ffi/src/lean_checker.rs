use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use pcm_cert::generator::{CertificateData, WitnessData};
use pcm_common::hash::blake3_hash;
use pcm_policy_dsl::ast::{Atom, Literal, Rule, Term};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{VerifyResult, verify_certificate_structured, verify_witness_structured};

#[derive(Debug, Deserialize)]
struct CheckerOutput {
    valid: bool,
    error: Option<String>,
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .to_path_buf()
}

fn lean_dir() -> PathBuf {
    workspace_root().join("lean")
}

fn local_checker_binary() -> Option<PathBuf> {
    let candidates = [
        lean_dir()
            .join(".lake")
            .join("build")
            .join("bin")
            .join("pcm_checker.exe"),
        lean_dir()
            .join(".lake")
            .join("build")
            .join("bin")
            .join("pcm_checker"),
        lean_dir().join("build").join("bin").join("pcm_checker.exe"),
        lean_dir().join("build").join("bin").join("pcm_checker"),
    ];

    candidates.into_iter().find(|path| path.exists())
}

fn spawn_checker(payload: &[u8]) -> Result<CheckerOutput, String> {
    if let Ok(path) = std::env::var("PCM_CHECKER_BIN") {
        return run_checker_binary(Path::new(&path), payload)
            .map_err(|err| format!("failed to run {}: {}", path, err));
    }

    let Some(binary) = local_checker_binary() else {
        return Err(
            "pcm_checker not found. Build it with `cd lean && lake build pcm_checker` (expected under `lean/.lake/build/bin`) or set PCM_CHECKER_BIN"
                .to_string(),
        );
    };

    run_checker_via_lake(&binary, payload)
        .map_err(|err| format!("failed to run `lake env {}`: {}", binary.display(), err))
}

fn run_checker_binary(binary: &Path, payload: &[u8]) -> std::io::Result<CheckerOutput> {
    let mut child = Command::new(binary)
        .arg("--json")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    write_checker_input(&mut child, payload)?;
    parse_checker_output(child.wait_with_output()?)
}

fn run_checker_via_lake(binary: &Path, payload: &[u8]) -> std::io::Result<CheckerOutput> {
    let mut child = Command::new("lake")
        .arg("env")
        .arg(binary)
        .arg("--json")
        .current_dir(lean_dir())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    write_checker_input(&mut child, payload)?;
    parse_checker_output(child.wait_with_output()?)
}

fn write_checker_input(child: &mut std::process::Child, payload: &[u8]) -> std::io::Result<()> {
    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(payload)?;
    }

    Ok(())
}

fn parse_checker_output(output: std::process::Output) -> std::io::Result<CheckerOutput> {
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(std::io::Error::new(
            ErrorKind::Other,
            format!("exit {}: {}", output.status, stderr),
        ));
    }

    serde_json::from_slice(&output.stdout).map_err(|err| {
        std::io::Error::new(
            ErrorKind::InvalidData,
            format!(
                "invalid checker output: {} (stdout: {})",
                err,
                String::from_utf8_lossy(&output.stdout)
            ),
        )
    })
}

fn expect_const<'a>(term: &'a Term, ctx: &str) -> Result<&'a str, String> {
    match term {
        Term::Const(value) => Ok(value),
        Term::Var(name) => Err(format!(
            "Lean checker only supports ground inputs; found variable `{}` in {}",
            name, ctx
        )),
    }
}

fn encode_action_type(value: &str) -> Value {
    match value {
        "ToolCall" => Value::String("toolCall".to_string()),
        "HttpOut" => Value::String("httpOut".to_string()),
        "DbWrite" => Value::String("dbWrite".to_string()),
        "DbReadSensitive" => Value::String("dbReadSensitive".to_string()),
        "FileWrite" => Value::String("fileWrite".to_string()),
        "FileRead" => Value::String("fileRead".to_string()),
        other => json!({ "custom": { "tag": other } }),
    }
}

fn encode_label(value: &str) -> Result<Value, String> {
    match value {
        "Public" => Ok(Value::String("low".to_string())),
        "Internal" => Ok(Value::String("medium".to_string())),
        "Confidential" => Ok(Value::String("high".to_string())),
        "Secret" => Ok(Value::String("critical".to_string())),
        other => Err(format!("unsupported label `{}` for Lean checker", other)),
    }
}

fn encode_edge_kind(value: &str) -> Result<Value, String> {
    match value {
        "DataFlow" => Ok(Value::String("dataFlow".to_string())),
        "ControlFlow" => Ok(Value::String("controlFlow".to_string())),
        "Causal" => Ok(Value::String("causal".to_string())),
        "Temporal" => Ok(Value::String("temporal".to_string())),
        other => Err(format!(
            "unsupported edge kind `{}` for Lean checker",
            other
        )),
    }
}

fn encode_atom(atom: &Atom) -> Result<Value, String> {
    match atom {
        Atom::Action {
            id,
            action_type,
            principal,
            target,
        } => Ok(json!({
            "action": {
                "id": expect_const(id, "action.id")?,
                "ty": encode_action_type(expect_const(action_type, "action.action_type")?),
                "princ": expect_const(principal, "action.principal")?,
                "tgt": expect_const(target, "action.target")?
            }
        })),
        Atom::DataLabel { data, label } => Ok(json!({
            "dataLabel": {
                "data": expect_const(data, "data_label.data")?,
                "l": encode_label(expect_const(label, "data_label.label")?)?
            }
        })),
        Atom::HasRole { principal, role } => Ok(json!({
            "hasRole": {
                "princ": expect_const(principal, "has_role.principal")?,
                "role": expect_const(role, "has_role.role")?
            }
        })),
        Atom::GraphEdge { src, dst, kind } => Ok(json!({
            "graphEdge": {
                "src": expect_const(src, "graph_edge.src")?,
                "dst": expect_const(dst, "graph_edge.dst")?,
                "kind": encode_edge_kind(expect_const(kind, "graph_edge.kind")?)?
            }
        })),
        Atom::GraphLabel { node, label } => Ok(json!({
            "graphLabel": {
                "node": expect_const(node, "graph_label.node")?,
                "l": encode_label(expect_const(label, "graph_label.label")?)?
            }
        })),
        Atom::Precedes { before, after } => Ok(json!({
            "precedes": {
                "a": expect_const(before, "precedes.before")?,
                "b": expect_const(after, "precedes.after")?
            }
        })),
        Atom::Deny { request, reason } => Ok(json!({
            "deny": {
                "req": expect_const(request, "deny.request")?,
                "reason": expect_const(reason, "deny.reason")?
            }
        })),
    }
}

fn encode_literal(lit: &Literal) -> Result<Value, String> {
    match lit {
        Literal::Pos(atom) => Ok(json!({ "pos": { "a": encode_atom(atom)? } })),
        Literal::Neg(atom) => Ok(json!({ "neg": { "a": encode_atom(atom)? } })),
    }
}

fn encode_policy(rules: &[Rule]) -> Result<Value, String> {
    let encoded_rules = rules
        .iter()
        .map(|rule| {
            Ok(json!({
                "head": encode_atom(&rule.head)?,
                "body": rule
                    .body
                    .iter()
                    .map(encode_literal)
                    .collect::<Result<Vec<_>, _>>()?
            }))
        })
        .collect::<Result<Vec<_>, String>>()?;

    Ok(json!({ "rules": encoded_rules }))
}

fn encode_request(request_facts: &[Atom]) -> Result<Value, String> {
    if request_facts.len() != 1 {
        return Err(format!(
            "Lean checker expects exactly one request action fact, got {}",
            request_facts.len()
        ));
    }

    match &request_facts[0] {
        Atom::Action {
            id,
            action_type,
            principal,
            target,
        } => Ok(json!({
            "id": expect_const(id, "request.id")?,
            "action": encode_action_type(expect_const(action_type, "request.action")?),
            "principal": expect_const(principal, "request.principal")?,
            "target": expect_const(target, "request.target")?,
            "attrs": [],
        })),
        other => Err(format!(
            "Lean checker expects request_facts[0] to be an action atom, got {:?}",
            other
        )),
    }
}

fn partition_base_facts(
    request_facts: &[Atom],
    all_base_facts: &[Atom],
) -> Result<(Value, Value), String> {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut roles = Vec::new();

    for atom in all_base_facts
        .iter()
        .filter(|atom| !request_facts.contains(atom))
    {
        match atom {
            Atom::HasRole { principal, role } => roles.push(json!([
                expect_const(principal, "has_role.principal")?,
                expect_const(role, "has_role.role")?
            ])),
            Atom::GraphEdge { src, dst, kind } => edges.push(json!({
                "src": expect_const(src, "graph_edge.src")?,
                "dst": expect_const(dst, "graph_edge.dst")?,
                "kind": encode_edge_kind(expect_const(kind, "graph_edge.kind")?)?,
            })),
            Atom::GraphLabel { node, label } => nodes.push(json!({
                "id": expect_const(node, "graph_label.node")?,
                "kind": "entity",
                "label": encode_label(expect_const(label, "graph_label.label")?)?,
            })),
            Atom::Action { .. } => {
                return Err(
                    "Lean checker cannot encode multiple base action facts; keep exactly one request action"
                        .to_string(),
                );
            }
            Atom::DataLabel { .. } => {
                return Err(
                    "Lean checker cannot encode data_label as a base fact in the current MVP bridge"
                        .to_string(),
                );
            }
            Atom::Precedes { .. } => {
                return Err(
                    "Lean checker cannot encode precedes as a base fact in the current MVP bridge"
                        .to_string(),
                );
            }
            Atom::Deny { .. } => {
                return Err(
                    "Lean checker cannot encode deny as a base fact in the current MVP bridge"
                        .to_string(),
                );
            }
        }
    }

    Ok((
        json!({ "nodes": nodes, "edges": edges }),
        Value::Array(roles),
    ))
}

fn bytes_json(bytes: &[u8; 32]) -> Value {
    Value::Array(bytes.iter().map(|byte| Value::from(*byte)).collect())
}

fn encode_certificate(cert: &CertificateData) -> Result<Value, String> {
    let steps = cert
        .steps
        .iter()
        .map(|step| {
            Ok(json!({
                "ruleIdx": step.rule_index,
                "premises": step.premise_indices,
                "conclusion": encode_serialized_atom(&step.conclusion)?,
            }))
        })
        .collect::<Result<Vec<_>, String>>()?;

    Ok(json!({
        "steps": steps,
        "policyHash": bytes_json(&cert.policy_hash),
        "graphHash": bytes_json(&cert.graph_hash),
        "requestHash": bytes_json(&cert.request_hash),
    }))
}

fn encode_witness(witness: &WitnessData) -> Result<Value, String> {
    let matched_facts = witness
        .matched_facts
        .iter()
        .map(encode_serialized_atom)
        .collect::<Result<Vec<_>, String>>()?;
    let violation_paths = witness
        .violation_paths
        .iter()
        .map(|path| {
            path.edges
                .iter()
                .map(|(src, dst, _)| json!([src, dst]))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    Ok(json!({
        "denyRuleIdx": witness.deny_rule_index,
        "matchedFacts": matched_facts,
        "violationPaths": violation_paths,
        "policyHash": bytes_json(&witness.policy_hash),
        "requestHash": bytes_json(&witness.request_hash),
    }))
}

fn encode_serialized_atom(atom: &pcm_cert::generator::SerializedAtom) -> Result<Value, String> {
    let args = &atom.args;
    match atom.predicate.as_str() {
        "action" => {
            if args.len() != 4 {
                return Err(format!("action atom expects 4 args, got {}", args.len()));
            }
            Ok(json!({
                "action": {
                    "id": &args[0],
                    "ty": encode_action_type(&args[1]),
                    "princ": &args[2],
                    "tgt": &args[3]
                }
            }))
        }
        "data_label" => {
            if args.len() != 2 {
                return Err(format!(
                    "data_label atom expects 2 args, got {}",
                    args.len()
                ));
            }
            Ok(json!({
                "dataLabel": {
                    "data": &args[0],
                    "l": encode_label(&args[1])?
                }
            }))
        }
        "has_role" => {
            if args.len() != 2 {
                return Err(format!("has_role atom expects 2 args, got {}", args.len()));
            }
            Ok(json!({
                "hasRole": {
                    "princ": &args[0],
                    "role": &args[1]
                }
            }))
        }
        "graph_edge" => {
            if args.len() != 3 {
                return Err(format!(
                    "graph_edge atom expects 3 args, got {}",
                    args.len()
                ));
            }
            Ok(json!({
                "graphEdge": {
                    "src": &args[0],
                    "dst": &args[1],
                    "kind": encode_edge_kind(&args[2])?
                }
            }))
        }
        "graph_label" => {
            if args.len() != 2 {
                return Err(format!(
                    "graph_label atom expects 2 args, got {}",
                    args.len()
                ));
            }
            Ok(json!({
                "graphLabel": {
                    "node": &args[0],
                    "l": encode_label(&args[1])?
                }
            }))
        }
        "precedes" => {
            if args.len() != 2 {
                return Err(format!("precedes atom expects 2 args, got {}", args.len()));
            }
            Ok(json!({
                "precedes": {
                    "a": &args[0],
                    "b": &args[1]
                }
            }))
        }
        "deny" => {
            if args.len() != 2 {
                return Err(format!("deny atom expects 2 args, got {}", args.len()));
            }
            Ok(json!({
                "deny": {
                    "req": &args[0],
                    "reason": &args[1]
                }
            }))
        }
        other => Err(format!("unsupported serialized atom predicate `{}`", other)),
    }
}

fn expected_certificate_hashes(
    rules: &[Rule],
    request_facts: &[Atom],
    all_base_facts: &[Atom],
) -> Result<([u8; 32], [u8; 32], [u8; 32]), String> {
    let policy_bytes = serde_json::to_vec(rules)
        .map_err(|err| format!("failed to encode policy rules: {}", err))?;
    let request_bytes = serde_json::to_vec(request_facts)
        .map_err(|err| format!("failed to encode request facts: {}", err))?;
    let graph_facts: Vec<&Atom> = all_base_facts
        .iter()
        .filter(|atom| !request_facts.contains(atom))
        .collect();
    let graph_bytes = serde_json::to_vec(&graph_facts)
        .map_err(|err| format!("failed to encode graph facts: {}", err))?;

    Ok((
        blake3_hash(&policy_bytes),
        blake3_hash(&graph_bytes),
        blake3_hash(&request_bytes),
    ))
}

fn expected_witness_hashes(
    rules: &[Rule],
    request_facts: &[Atom],
) -> Result<([u8; 32], [u8; 32]), String> {
    let policy_bytes = serde_json::to_vec(rules)
        .map_err(|err| format!("failed to encode policy rules: {}", err))?;
    let request_bytes = serde_json::to_vec(request_facts)
        .map_err(|err| format!("failed to encode request facts: {}", err))?;

    Ok((blake3_hash(&policy_bytes), blake3_hash(&request_bytes)))
}

fn build_certificate_payload(
    cert: &CertificateData,
    request_facts: &[Atom],
    rules: &[Rule],
    all_base_facts: &[Atom],
) -> Result<Vec<u8>, String> {
    let request = encode_request(request_facts)?;
    let policy = encode_policy(rules)?;
    let (graph, roles) = partition_base_facts(request_facts, all_base_facts)?;
    let (expected_policy_hash, expected_graph_hash, expected_request_hash) =
        expected_certificate_hashes(rules, request_facts, all_base_facts)?;
    let payload = json!({
        "mode": "cert",
        "certificate": encode_certificate(cert)?,
        "witness": Value::Null,
        "request": request,
        "policy": policy,
        "graph": graph,
        "roles": roles,
        "expectedPolicyHash": bytes_json(&expected_policy_hash),
        "expectedGraphHash": bytes_json(&expected_graph_hash),
        "expectedRequestHash": bytes_json(&expected_request_hash),
    });

    serde_json::to_vec(&payload).map_err(|err| format!("failed to encode checker input: {}", err))
}

fn build_witness_payload(
    witness: &WitnessData,
    request_facts: &[Atom],
    rules: &[Rule],
    all_base_facts: &[Atom],
) -> Result<Vec<u8>, String> {
    let request = encode_request(request_facts)?;
    let policy = encode_policy(rules)?;
    let (graph, roles) = partition_base_facts(request_facts, all_base_facts)?;
    let (expected_policy_hash, expected_request_hash) =
        expected_witness_hashes(rules, request_facts)?;
    let payload = json!({
        "mode": "witness",
        "certificate": Value::Null,
        "witness": encode_witness(witness)?,
        "request": request,
        "policy": policy,
        "graph": graph,
        "roles": roles,
        "expectedPolicyHash": bytes_json(&expected_policy_hash),
        "expectedGraphHash": Value::Null,
        "expectedRequestHash": bytes_json(&expected_request_hash),
    });

    serde_json::to_vec(&payload).map_err(|err| format!("failed to encode checker input: {}", err))
}

pub fn verify_certificate_via_lean_checker(
    cert: &CertificateData,
    request_facts: &[Atom],
    rules: &[Rule],
    all_base_facts: &[Atom],
) -> Result<VerifyResult, String> {
    let start = Instant::now();
    let payload = build_certificate_payload(cert, request_facts, rules, all_base_facts)?;
    let output = spawn_checker(&payload)?;

    Ok(VerifyResult {
        valid: output.valid,
        error: output.error,
        failed_step: None,
        duration_us: start.elapsed().as_micros() as u64,
    })
}

pub fn verify_witness_via_lean_checker(
    witness: &WitnessData,
    request_facts: &[Atom],
    rules: &[Rule],
    all_base_facts: &[Atom],
) -> Result<VerifyResult, String> {
    let start = Instant::now();
    let payload = build_witness_payload(witness, request_facts, rules, all_base_facts)?;
    let output = spawn_checker(&payload)?;

    Ok(VerifyResult {
        valid: output.valid,
        error: output.error,
        failed_step: None,
        duration_us: start.elapsed().as_micros() as u64,
    })
}

pub fn verify_certificate_dual(
    cert: &CertificateData,
    request_facts: &[Atom],
    rules: &[Rule],
    all_base_facts: &[Atom],
) -> VerifyResult {
    let rust_result = verify_certificate_structured(cert, request_facts, rules, all_base_facts);

    match verify_certificate_via_lean_checker(cert, request_facts, rules, all_base_facts) {
        Ok(lean_result) if lean_result.valid == rust_result.valid => rust_result,
        Ok(lean_result) => VerifyResult {
            valid: false,
            error: Some(format!(
                "checker mismatch: rust valid={}, lean valid={}",
                rust_result.valid, lean_result.valid
            )),
            failed_step: rust_result.failed_step,
            duration_us: rust_result
                .duration_us
                .saturating_add(lean_result.duration_us),
        },
        Err(_) => rust_result,
    }
}

pub fn verify_witness_dual(
    witness: &WitnessData,
    request_facts: &[Atom],
    rules: &[Rule],
    all_base_facts: &[Atom],
) -> VerifyResult {
    let rust_result = verify_witness_structured(witness, rules, all_base_facts);

    match verify_witness_via_lean_checker(witness, request_facts, rules, all_base_facts) {
        Ok(lean_result) if lean_result.valid == rust_result.valid => rust_result,
        Ok(lean_result) => VerifyResult {
            valid: false,
            error: Some(format!(
                "checker mismatch: rust valid={}, lean valid={}",
                rust_result.valid, lean_result.valid
            )),
            failed_step: rust_result.failed_step,
            duration_us: rust_result
                .duration_us
                .saturating_add(lean_result.duration_us),
        },
        Err(_) => rust_result,
    }
}
