//! 策略编译器：AST → CompiledPolicy
//!
//! 实现完整的策略编译流程：
//! 1. 验证（头部必须是 deny、变量安全性、否定安全性）
//! 2. 索引化（为每条规则分配索引、提取谓词信息）
//! 3. 分层（构建谓词依赖图、检测否定环、拓扑排序）
//! 4. Schema 提取
//! 5. 哈希

use crate::ast::{Atom, Literal, PolicyAst, Rule, Term};
use pcm_common::PcmError;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

// ============================================================
// Data structures
// ============================================================

/// 编译后的策略（内部表示）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledPolicy {
    /// 规则列表（保留 AST Rule 结构，但增加索引信息）
    pub rules: Vec<IndexedRule>,
    /// 分层信息（规则分组，保证安全否定）
    pub strata: Vec<Stratum>,
    /// 事实 Schema 信息（谓词签名）
    pub fact_schema: FactSchema,
    /// 策略内容哈希 (blake3)
    pub content_hash: [u8; 32],
    /// 语义版本
    pub version: String,
    /// 是否通过可判定性检查
    pub decidable: bool,
}

/// 索引化规则
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedRule {
    pub index: usize,
    pub rule: Rule,
    /// 头部谓词名（用于快速查找）
    pub head_predicate: String,
    /// 体中引用的谓词名列表 (name, is_negated)
    pub body_predicates: Vec<(String, bool)>,
}

/// 一个分层
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stratum {
    pub level: usize,
    pub rule_indices: Vec<usize>,
}

/// 事实 Schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactSchema {
    /// 每种谓词的参数数量
    pub predicates: Vec<PredicateInfo>,
}

/// 谓词信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredicateInfo {
    pub name: String,
    pub arity: usize,
}

/// 编译警告
#[derive(Debug, Clone)]
pub struct CompileWarning {
    pub message: String,
    pub rule_index: Option<usize>,
}

/// 编译结果
#[derive(Debug)]
pub struct CompileResult {
    pub policy: CompiledPolicy,
    pub warnings: Vec<CompileWarning>,
}

// ============================================================
// Helper: extract predicate name and arity from Atom
// ============================================================

fn atom_predicate_name(atom: &Atom) -> &str {
    match atom {
        Atom::Action { .. } => "action",
        Atom::DataLabel { .. } => "data_label",
        Atom::HasRole { .. } => "has_role",
        Atom::GraphEdge { .. } => "graph_edge",
        Atom::GraphLabel { .. } => "graph_label",
        Atom::Precedes { .. } => "precedes",
        Atom::Deny { .. } => "deny",
    }
}

fn atom_arity(atom: &Atom) -> usize {
    match atom {
        Atom::Action { .. } => 4,
        Atom::DataLabel { .. } => 2,
        Atom::HasRole { .. } => 2,
        Atom::GraphEdge { .. } => 3,
        Atom::GraphLabel { .. } => 2,
        Atom::Precedes { .. } => 2,
        Atom::Deny { .. } => 2,
    }
}

/// Extract all terms from an atom.
fn atom_terms(atom: &Atom) -> Vec<&Term> {
    match atom {
        Atom::Action {
            id,
            action_type,
            principal,
            target,
        } => vec![id, action_type, principal, target],
        Atom::DataLabel { data, label } => vec![data, label],
        Atom::HasRole { principal, role } => vec![principal, role],
        Atom::GraphEdge { src, dst, kind } => vec![src, dst, kind],
        Atom::GraphLabel { node, label } => vec![node, label],
        Atom::Precedes { before, after } => vec![before, after],
        Atom::Deny { request, reason } => vec![request, reason],
    }
}

/// Collect variable names from a list of terms (excluding wildcards "_").
fn collect_vars<'a>(terms: impl IntoIterator<Item = &'a Term>) -> HashSet<String> {
    terms
        .into_iter()
        .filter_map(|t| match t {
            Term::Var(v) if v != "_" => Some(v.clone()),
            _ => None,
        })
        .collect()
}

// ============================================================
// Validation
// ============================================================

/// Validate that all rule heads are `deny`.
fn validate_heads(ast: &PolicyAst) -> Result<(), PcmError> {
    for (i, rule) in ast.rules.iter().enumerate() {
        if !matches!(&rule.head, Atom::Deny { .. }) {
            return Err(PcmError::PolicyCompilation(format!(
                "rule {} head must be 'deny', found '{}'",
                i,
                atom_predicate_name(&rule.head)
            )));
        }
    }
    Ok(())
}

/// Range restriction: every variable in the head must appear in at least one
/// positive body literal.
fn validate_range_restriction(ast: &PolicyAst) -> Result<(), PcmError> {
    for (i, rule) in ast.rules.iter().enumerate() {
        let head_vars = collect_vars(atom_terms(&rule.head));

        let mut positive_vars: HashSet<String> = HashSet::new();
        for lit in &rule.body {
            if let Literal::Pos(atom) = lit {
                positive_vars.extend(collect_vars(atom_terms(atom)));
            }
        }

        for var in &head_vars {
            if !positive_vars.contains(var) {
                return Err(PcmError::PolicyCompilation(format!(
                    "unsafe variable '{}' in head of rule {} — not in any positive body literal",
                    var, i
                )));
            }
        }
    }
    Ok(())
}

/// Negation safety: every variable in a negative literal must appear in at
/// least one positive literal of the same rule.
fn validate_negation_safety(ast: &PolicyAst) -> Result<(), PcmError> {
    for (i, rule) in ast.rules.iter().enumerate() {
        let mut positive_vars: HashSet<String> = HashSet::new();
        for lit in &rule.body {
            if let Literal::Pos(atom) = lit {
                positive_vars.extend(collect_vars(atom_terms(atom)));
            }
        }

        for lit in &rule.body {
            if let Literal::Neg(atom) = lit {
                let neg_vars = collect_vars(atom_terms(atom));
                for var in &neg_vars {
                    if !positive_vars.contains(var) {
                        return Err(PcmError::PolicyCompilation(format!(
                            "unsafe variable '{}' in negated literal of rule {} — not in any positive body literal",
                            var, i
                        )));
                    }
                }
            }
        }
    }
    Ok(())
}

// ============================================================
// Indexing
// ============================================================

fn build_indexed_rules(ast: &PolicyAst) -> Vec<IndexedRule> {
    ast.rules
        .iter()
        .enumerate()
        .map(|(index, rule)| {
            let head_predicate = atom_predicate_name(&rule.head).to_string();
            let body_predicates: Vec<(String, bool)> = rule
                .body
                .iter()
                .map(|lit| match lit {
                    Literal::Pos(atom) => (atom_predicate_name(atom).to_string(), false),
                    Literal::Neg(atom) => (atom_predicate_name(atom).to_string(), true),
                })
                .collect();

            IndexedRule {
                index,
                rule: rule.clone(),
                head_predicate,
                body_predicates,
            }
        })
        .collect()
}

// ============================================================
// Stratification
// ============================================================

/// Predicate dependency edge kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DepKind {
    Positive,
    Negative,
}

/// Build predicate dependency graph.
///
/// Returns a map: head_pred -> [(body_pred, DepKind)]
fn build_dependency_graph(
    indexed_rules: &[IndexedRule],
) -> HashMap<String, Vec<(String, DepKind)>> {
    let mut graph: HashMap<String, Vec<(String, DepKind)>> = HashMap::new();

    for ir in indexed_rules {
        let head = &ir.head_predicate;
        // Ensure the head is in the graph even with no edges
        graph.entry(head.clone()).or_default();

        for (body_pred, is_negated) in &ir.body_predicates {
            let kind = if *is_negated {
                DepKind::Negative
            } else {
                DepKind::Positive
            };
            graph
                .entry(head.clone())
                .or_default()
                .push((body_pred.clone(), kind));
            // Ensure body predicates are also nodes in the graph
            graph.entry(body_pred.clone()).or_default();
        }
    }

    graph
}

/// Compute strongly connected components using Tarjan's algorithm.
/// Returns SCCs in reverse topological order (i.e., leaves first).
fn tarjan_scc(graph: &HashMap<String, Vec<(String, DepKind)>>) -> Vec<Vec<String>> {
    struct State<'a> {
        graph: &'a HashMap<String, Vec<(String, DepKind)>>,
        index_counter: usize,
        stack: Vec<String>,
        on_stack: HashSet<String>,
        indices: HashMap<String, usize>,
        lowlinks: HashMap<String, usize>,
        result: Vec<Vec<String>>,
    }

    fn strongconnect(state: &mut State, v: &str) {
        let idx = state.index_counter;
        state.index_counter += 1;
        state.indices.insert(v.to_string(), idx);
        state.lowlinks.insert(v.to_string(), idx);
        state.stack.push(v.to_string());
        state.on_stack.insert(v.to_string());

        if let Some(edges) = state.graph.get(v) {
            for (w, _kind) in edges {
                if !state.indices.contains_key(w.as_str()) {
                    strongconnect(state, w);
                    let w_low = state.lowlinks[w.as_str()];
                    let v_low = state.lowlinks.get_mut(v).unwrap();
                    if w_low < *v_low {
                        *v_low = w_low;
                    }
                } else if state.on_stack.contains(w.as_str()) {
                    let w_idx = state.indices[w.as_str()];
                    let v_low = state.lowlinks.get_mut(v).unwrap();
                    if w_idx < *v_low {
                        *v_low = w_idx;
                    }
                }
            }
        }

        if state.lowlinks[v] == state.indices[v] {
            let mut scc = Vec::new();
            loop {
                let w = state.stack.pop().unwrap();
                state.on_stack.remove(&w);
                scc.push(w.clone());
                if w == v {
                    break;
                }
            }
            state.result.push(scc);
        }
    }

    // Sort node names for deterministic ordering
    let mut nodes: Vec<&String> = graph.keys().collect();
    nodes.sort();

    let mut state = State {
        graph,
        index_counter: 0,
        stack: Vec::new(),
        on_stack: HashSet::new(),
        indices: HashMap::new(),
        lowlinks: HashMap::new(),
        result: Vec::new(),
    };

    for node in nodes {
        if !state.indices.contains_key(node.as_str()) {
            strongconnect(&mut state, node);
        }
    }

    state.result
}

/// Perform stratification.
///
/// Returns strata (list of rule-index groups) or an error if a negative cycle
/// is found.
fn stratify(indexed_rules: &[IndexedRule]) -> Result<Vec<Stratum>, PcmError> {
    if indexed_rules.is_empty() {
        return Ok(vec![]);
    }

    let dep_graph = build_dependency_graph(indexed_rules);
    let sccs = tarjan_scc(&dep_graph);

    // Check for negative edges **within** an SCC — that's a negative cycle.
    for scc in &sccs {
        if scc.len() > 1 {
            let scc_set: HashSet<&str> = scc.iter().map(|s| s.as_str()).collect();
            for pred in scc {
                if let Some(edges) = dep_graph.get(pred) {
                    for (target, kind) in edges {
                        if *kind == DepKind::Negative && scc_set.contains(target.as_str()) {
                            return Err(PcmError::PolicyCompilation(
                                "negative cycle detected".to_string(),
                            ));
                        }
                    }
                }
            }
        } else {
            // Single-node SCC: check for self-loop with negative edge
            let pred = &scc[0];
            if let Some(edges) = dep_graph.get(pred) {
                for (target, kind) in edges {
                    if *kind == DepKind::Negative && target == pred {
                        return Err(PcmError::PolicyCompilation(
                            "negative cycle detected".to_string(),
                        ));
                    }
                }
            }
        }
    }

    // Map predicate -> SCC index
    let mut pred_to_scc: HashMap<&str, usize> = HashMap::new();
    for (i, scc) in sccs.iter().enumerate() {
        for pred in scc {
            pred_to_scc.insert(pred.as_str(), i);
        }
    }

    // Compute stratum level for each SCC.
    // Process in topological order (reverse of Tarjan's output).
    let num_sccs = sccs.len();
    let mut scc_level: Vec<usize> = vec![0; num_sccs];

    for scc_idx in (0..num_sccs).rev() {
        for pred in &sccs[scc_idx] {
            if let Some(edges) = dep_graph.get(pred) {
                for (target, kind) in edges {
                    let target_scc = pred_to_scc[target.as_str()];
                    if target_scc != scc_idx {
                        let base = scc_level[target_scc];
                        let required = if *kind == DepKind::Negative {
                            base + 1
                        } else {
                            base
                        };
                        if required > scc_level[scc_idx] {
                            scc_level[scc_idx] = required;
                        }
                    }
                }
            }
        }
    }

    // Build stratum mapping: predicate -> level
    let mut pred_level: HashMap<&str, usize> = HashMap::new();
    for (scc_idx, scc) in sccs.iter().enumerate() {
        for pred in scc {
            pred_level.insert(pred.as_str(), scc_level[scc_idx]);
        }
    }

    // Assign each rule to the stratum of its head predicate.
    let mut strata_rules: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for ir in indexed_rules {
        let level = pred_level
            .get(ir.head_predicate.as_str())
            .copied()
            .unwrap_or(0);
        strata_rules.entry(level).or_default().push(ir.index);
    }

    let strata: Vec<Stratum> = strata_rules
        .into_iter()
        .map(|(level, rule_indices)| Stratum {
            level,
            rule_indices,
        })
        .collect();

    Ok(strata)
}

// ============================================================
// Schema extraction
// ============================================================

fn extract_schema(indexed_rules: &[IndexedRule]) -> FactSchema {
    let mut predicates_map: BTreeMap<String, usize> = BTreeMap::new();

    for ir in indexed_rules {
        predicates_map
            .entry(ir.head_predicate.clone())
            .or_insert_with(|| atom_arity(&ir.rule.head));

        for lit in &ir.rule.body {
            let atom = match lit {
                Literal::Pos(a) => a,
                Literal::Neg(a) => a,
            };
            predicates_map
                .entry(atom_predicate_name(atom).to_string())
                .or_insert_with(|| atom_arity(atom));
        }
    }

    FactSchema {
        predicates: predicates_map
            .into_iter()
            .map(|(name, arity)| PredicateInfo { name, arity })
            .collect(),
    }
}

// ============================================================
// Warnings
// ============================================================

fn generate_warnings(indexed_rules: &[IndexedRule]) -> Vec<CompileWarning> {
    let mut warnings = Vec::new();

    for ir in indexed_rules {
        // --- Unused singleton variables ---
        let head_vars = collect_vars(atom_terms(&ir.rule.head));

        let mut body_vars: HashMap<String, usize> = HashMap::new();
        for lit in &ir.rule.body {
            let atom = match lit {
                Literal::Pos(a) => a,
                Literal::Neg(a) => a,
            };
            for t in atom_terms(atom) {
                if let Term::Var(v) = t
                    && v != "_"
                {
                    *body_vars.entry(v.clone()).or_insert(0) += 1;
                }
            }
        }

        for (var, count) in &body_vars {
            if *count == 1 && !head_vars.contains(var) {
                warnings.push(CompileWarning {
                    message: format!("unused singleton variable '{}' in rule {}", var, ir.index),
                    rule_index: Some(ir.index),
                });
            }
        }

        // --- Redundant rules ---
        for other in indexed_rules {
            if other.index > ir.index
                && other.rule.head == ir.rule.head
                && other.rule.body == ir.rule.body
            {
                warnings.push(CompileWarning {
                    message: format!(
                        "redundant rule: rule {} and rule {} are identical",
                        ir.index, other.index
                    ),
                    rule_index: Some(other.index),
                });
            }
        }

        // --- Contradictory literals ---
        let mut positive_atoms: HashSet<&Atom> = HashSet::new();
        let mut negative_atoms: HashSet<&Atom> = HashSet::new();
        for lit in &ir.rule.body {
            match lit {
                Literal::Pos(a) => {
                    positive_atoms.insert(a);
                }
                Literal::Neg(a) => {
                    negative_atoms.insert(a);
                }
            }
        }
        for neg_atom in &negative_atoms {
            if positive_atoms.contains(neg_atom) {
                warnings.push(CompileWarning {
                    message: format!(
                        "contradictory literals in rule {}: '{}' appears both positive and negated",
                        ir.index,
                        atom_predicate_name(neg_atom)
                    ),
                    rule_index: Some(ir.index),
                });
            }
        }
    }

    warnings
}

// ============================================================
// Content hash (deterministic)
// ============================================================

fn compute_content_hash(indexed_rules: &[IndexedRule]) -> [u8; 32] {
    let rules_for_hash: Vec<&Rule> = indexed_rules.iter().map(|ir| &ir.rule).collect();
    let serialized = serde_json::to_vec(&rules_for_hash).unwrap_or_default();
    pcm_common::hash::blake3_hash(&serialized)
}

// ============================================================
// Compile
// ============================================================

/// 编译策略 AST 为 CompiledPolicy
pub fn compile(ast: &PolicyAst, version: &str) -> Result<CompileResult, PcmError> {
    // 1. Validation
    validate_heads(ast)?;
    validate_range_restriction(ast)?;
    validate_negation_safety(ast)?;

    // 2. Indexing
    let indexed_rules = build_indexed_rules(ast);

    // 3. Stratification
    let strata = stratify(&indexed_rules)?;

    // 4. Schema extraction
    let fact_schema = extract_schema(&indexed_rules);

    // 5. Content hash
    let content_hash = compute_content_hash(&indexed_rules);

    // 6. Warnings
    let warnings = generate_warnings(&indexed_rules);

    Ok(CompileResult {
        policy: CompiledPolicy {
            rules: indexed_rules,
            strata,
            fact_schema,
            content_hash,
            version: version.to_string(),
            decidable: true,
        },
        warnings,
    })
}

// ============================================================
// Decompile
// ============================================================

/// 从 CompiledPolicy 还原为 PolicyAst
pub fn decompile(compiled: &CompiledPolicy) -> PolicyAst {
    let rules: Vec<Rule> = compiled.rules.iter().map(|ir| ir.rule.clone()).collect();
    PolicyAst { rules }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_policy;
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    /// Helper: resolve a policy file path relative to the workspace root.
    fn policy_path(name: &str) -> PathBuf {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        manifest.join("../../policies").join(name)
    }

    // ---- 1. test_compile_single_rule ----

    #[test]
    fn test_compile_single_rule() {
        let input = r#"deny(Req, "test") :- action(Req, HttpOut, P, _)."#;
        let ast = parse_policy(input).unwrap();
        let result = compile(&ast, "1.0.0").unwrap();
        assert_eq!(result.policy.rules.len(), 1);
        assert_eq!(result.policy.rules[0].head_predicate, "deny");
        assert_eq!(result.policy.rules[0].body_predicates.len(), 1);
        assert_eq!(result.policy.rules[0].body_predicates[0].0, "action");
        assert!(!result.policy.rules[0].body_predicates[0].1);
        assert_eq!(result.policy.version, "1.0.0");
        assert!(result.policy.decidable);
    }

    // ---- 2. test_compile_multi_rule ----

    #[test]
    fn test_compile_multi_rule() {
        let source = std::fs::read_to_string(policy_path("test_multi_rule.pcm")).unwrap();
        let ast = parse_policy(&source).unwrap();
        let result = compile(&ast, "1.0.0").unwrap();
        assert_eq!(result.policy.rules.len(), 4);

        // Verify strata exist and cover all rules
        let mut all_rule_indices: BTreeSet<usize> = BTreeSet::new();
        for stratum in &result.policy.strata {
            for &idx in &stratum.rule_indices {
                all_rule_indices.insert(idx);
            }
        }
        assert_eq!(all_rule_indices.len(), 4);
        for i in 0..4 {
            assert!(all_rule_indices.contains(&i));
        }
    }

    // ---- 3. test_roundtrip_single ----

    #[test]
    fn test_roundtrip_single() {
        let input = r#"deny(Req, "test") :- action(Req, HttpOut, P, _)."#;
        let ast = parse_policy(input).unwrap();
        let result = compile(&ast, "1.0.0").unwrap();
        let decompiled = decompile(&result.policy);
        assert_eq!(ast, decompiled);
    }

    // ---- 4. test_roundtrip_multi ----

    #[test]
    fn test_roundtrip_multi() {
        let source = std::fs::read_to_string(policy_path("example.pcm")).unwrap();
        let ast = parse_policy(&source).unwrap();
        let result = compile(&ast, "1.0.0").unwrap();
        let decompiled = decompile(&result.policy);
        assert_eq!(ast, decompiled);
    }

    // ---- 5. test_roundtrip_all_policies ----

    #[test]
    fn test_roundtrip_all_policies() {
        let policies_dir = {
            let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
            manifest.join("../../policies")
        };
        let entries = std::fs::read_dir(&policies_dir)
            .unwrap_or_else(|e| panic!("cannot read policies dir: {e}"));

        let mut count = 0;
        for entry in entries {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("pcm") {
                let source = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
                let ast = parse_policy(&source)
                    .unwrap_or_else(|e| panic!("parse error in {}: {e}", path.display()));

                if ast.rules.is_empty() {
                    let result = compile(&ast, "1.0.0").unwrap();
                    assert_eq!(decompile(&result.policy), ast);
                    count += 1;
                    continue;
                }

                let result = compile(&ast, "1.0.0")
                    .unwrap_or_else(|e| panic!("compile error in {}: {e}", path.display()));
                let decompiled = decompile(&result.policy);
                assert_eq!(ast, decompiled, "roundtrip failed for {}", path.display());
                count += 1;
            }
        }
        assert!(count > 0, "no .pcm files found");
    }

    // ---- 6. test_stratification_simple ----

    #[test]
    fn test_stratification_simple() {
        let input = r#"
            deny(Req, "a") :- action(Req, HttpOut, P, T).
            deny(Req, "b") :- action(Req, DbWrite, P, T).
        "#;
        let ast = parse_policy(input).unwrap();
        let result = compile(&ast, "1.0.0").unwrap();

        assert_eq!(result.policy.strata.len(), 1);
        assert_eq!(result.policy.strata[0].level, 0);
        assert_eq!(result.policy.strata[0].rule_indices.len(), 2);
    }

    // ---- 7. test_stratification_layered ----

    #[test]
    fn test_stratification_layered() {
        let input = r#"
            deny(Req, "no_role") :- action(Req, HttpOut, P, _), !has_role(P, "admin").
        "#;
        let ast = parse_policy(input).unwrap();
        let result = compile(&ast, "1.0.0").unwrap();

        assert!(
            result.policy.strata.len() >= 1,
            "should have at least 1 stratum"
        );

        let deny_stratum = result
            .policy
            .strata
            .iter()
            .find(|s| s.rule_indices.contains(&0))
            .unwrap();
        assert!(
            deny_stratum.level > 0,
            "deny should be at stratum > 0 due to negative dependency on has_role"
        );
    }

    // ---- 8. test_negative_cycle_rejected ----

    #[test]
    fn test_negative_cycle_rejected() {
        let ast = PolicyAst {
            rules: vec![
                Rule {
                    head: Atom::Deny {
                        request: Term::Var("X".to_string()),
                        reason: Term::Const("a".to_string()),
                    },
                    body: vec![
                        Literal::Pos(Atom::Action {
                            id: Term::Var("X".to_string()),
                            action_type: Term::Var("T".to_string()),
                            principal: Term::Var("P".to_string()),
                            target: Term::Var("G".to_string()),
                        }),
                        Literal::Neg(Atom::Deny {
                            request: Term::Var("X".to_string()),
                            reason: Term::Const("b".to_string()),
                        }),
                    ],
                },
                Rule {
                    head: Atom::Deny {
                        request: Term::Var("X".to_string()),
                        reason: Term::Const("b".to_string()),
                    },
                    body: vec![
                        Literal::Pos(Atom::Action {
                            id: Term::Var("X".to_string()),
                            action_type: Term::Var("T".to_string()),
                            principal: Term::Var("P".to_string()),
                            target: Term::Var("G".to_string()),
                        }),
                        Literal::Neg(Atom::Deny {
                            request: Term::Var("X".to_string()),
                            reason: Term::Const("a".to_string()),
                        }),
                    ],
                },
            ],
        };

        let err = compile(&ast, "1.0.0").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("negative cycle detected"),
            "expected negative cycle error, got: {msg}"
        );
    }

    // ---- 9. test_unsafe_variable_rejected ----

    #[test]
    fn test_unsafe_variable_rejected() {
        let ast = PolicyAst {
            rules: vec![Rule {
                head: Atom::Deny {
                    request: Term::Var("X".to_string()),
                    reason: Term::Const("bad".to_string()),
                },
                body: vec![Literal::Neg(Atom::HasRole {
                    principal: Term::Var("X".to_string()),
                    role: Term::Const("admin".to_string()),
                })],
            }],
        };

        let err = compile(&ast, "1.0.0").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unsafe variable"),
            "expected unsafe variable error, got: {msg}"
        );
    }

    // ---- 10. test_content_hash_deterministic ----

    #[test]
    fn test_content_hash_deterministic() {
        let input = r#"deny(Req, "test") :- action(Req, HttpOut, P, _)."#;
        let ast = parse_policy(input).unwrap();
        let r1 = compile(&ast, "1.0.0").unwrap();
        let r2 = compile(&ast, "1.0.0").unwrap();
        assert_eq!(r1.policy.content_hash, r2.policy.content_hash);
    }

    // ---- 11. test_content_hash_different ----

    #[test]
    fn test_content_hash_different() {
        let ast1 = parse_policy(r#"deny(Req, "a") :- action(Req, HttpOut, P, _)."#).unwrap();
        let ast2 = parse_policy(r#"deny(Req, "b") :- action(Req, DbWrite, P, _)."#).unwrap();
        let r1 = compile(&ast1, "1.0.0").unwrap();
        let r2 = compile(&ast2, "1.0.0").unwrap();
        assert_ne!(r1.policy.content_hash, r2.policy.content_hash);
    }

    // ---- Additional: warnings ----

    #[test]
    fn test_warning_contradictory_literals() {
        let ast = PolicyAst {
            rules: vec![Rule {
                head: Atom::Deny {
                    request: Term::Var("Req".to_string()),
                    reason: Term::Const("x".to_string()),
                },
                body: vec![
                    Literal::Pos(Atom::Action {
                        id: Term::Var("Req".to_string()),
                        action_type: Term::Var("T".to_string()),
                        principal: Term::Var("P".to_string()),
                        target: Term::Var("G".to_string()),
                    }),
                    Literal::Pos(Atom::HasRole {
                        principal: Term::Var("P".to_string()),
                        role: Term::Const("x".to_string()),
                    }),
                    Literal::Neg(Atom::HasRole {
                        principal: Term::Var("P".to_string()),
                        role: Term::Const("x".to_string()),
                    }),
                ],
            }],
        };
        let result = compile(&ast, "1.0.0").unwrap();
        let has_contradiction = result
            .warnings
            .iter()
            .any(|w| w.message.contains("contradictory"));
        assert!(
            has_contradiction,
            "should warn about contradictory literals"
        );
    }

    #[test]
    fn test_warning_redundant_rules() {
        let rule = Rule {
            head: Atom::Deny {
                request: Term::Var("Req".to_string()),
                reason: Term::Const("dup".to_string()),
            },
            body: vec![Literal::Pos(Atom::Action {
                id: Term::Var("Req".to_string()),
                action_type: Term::Var("T".to_string()),
                principal: Term::Var("P".to_string()),
                target: Term::Var("G".to_string()),
            })],
        };
        let ast = PolicyAst {
            rules: vec![rule.clone(), rule],
        };
        let result = compile(&ast, "1.0.0").unwrap();
        let has_redundant = result
            .warnings
            .iter()
            .any(|w| w.message.contains("redundant"));
        assert!(has_redundant, "should warn about redundant rules");
    }

    #[test]
    fn test_compile_empty_policy() {
        let ast = PolicyAst { rules: vec![] };
        let result = compile(&ast, "1.0.0").unwrap();
        assert!(result.policy.rules.is_empty());
        assert!(result.policy.strata.is_empty());
        assert!(result.policy.decidable);
    }

    #[test]
    fn test_non_deny_head_rejected() {
        let ast = PolicyAst {
            rules: vec![Rule {
                head: Atom::HasRole {
                    principal: Term::Var("P".to_string()),
                    role: Term::Const("admin".to_string()),
                },
                body: vec![Literal::Pos(Atom::Action {
                    id: Term::Var("X".to_string()),
                    action_type: Term::Var("T".to_string()),
                    principal: Term::Var("P".to_string()),
                    target: Term::Var("G".to_string()),
                })],
            }],
        };
        let err = compile(&ast, "1.0.0").unwrap_err();
        assert!(err.to_string().contains("deny"));
    }

    #[test]
    fn test_schema_extraction() {
        let input = r#"
            deny(Req, "a") :- action(Req, HttpOut, P, _), has_role(P, "admin").
        "#;
        let ast = parse_policy(input).unwrap();
        let result = compile(&ast, "1.0.0").unwrap();

        let schema = &result.policy.fact_schema;
        let pred_names: Vec<&str> = schema.predicates.iter().map(|p| p.name.as_str()).collect();
        assert!(pred_names.contains(&"deny"));
        assert!(pred_names.contains(&"action"));
        assert!(pred_names.contains(&"has_role"));

        for p in &schema.predicates {
            match p.name.as_str() {
                "deny" => assert_eq!(p.arity, 2),
                "action" => assert_eq!(p.arity, 4),
                "has_role" => assert_eq!(p.arity, 2),
                _ => {}
            }
        }
    }
}
