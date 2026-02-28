//! `pcm diff` — 策略规则级差异分析

use anyhow::{Context, Result};
use pcm_policy_dsl::ast::{Atom, Literal, Rule};
use serde::Serialize;

/// 差异类型
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Added,
    Removed,
    Modified,
}

/// 安全影响标记
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityImpact {
    /// 删除了 deny 规则，可能导致权限提升
    PotentialEscalation,
    /// 新增了 deny 规则，可能导致功能中断
    PotentialBreaking,
    /// 修改了 deny 条件，需要审查
    NeedsReview,
    /// 无安全影响
    None,
}

/// 一条规则差异
#[derive(Debug, Clone, Serialize)]
pub struct RuleDiff {
    pub kind: ChangeKind,
    pub rule_index: Option<usize>,
    pub head: String,
    pub security_impact: SecurityImpact,
    pub old_body: Option<String>,
    pub new_body: Option<String>,
}

/// 差异报告
#[derive(Debug, Clone, Serialize)]
pub struct DiffReport {
    pub added: Vec<RuleDiff>,
    pub removed: Vec<RuleDiff>,
    pub modified: Vec<RuleDiff>,
    pub summary: DiffSummary,
}

/// 差异摘要
#[derive(Debug, Clone, Serialize)]
pub struct DiffSummary {
    pub total_changes: usize,
    pub added_count: usize,
    pub removed_count: usize,
    pub modified_count: usize,
    pub has_security_impact: bool,
}

/// 运行 diff 子命令
pub fn run(
    old_path: String,
    new_path: String,
    output: Option<String>,
    format: String,
) -> Result<()> {
    tracing::info!(%old_path, %new_path, ?output, "analyzing policy diff");

    // ── 1. 读取并编译两个策略 ──
    let old_source = std::fs::read_to_string(&old_path)
        .with_context(|| format!("failed to read old policy '{}'", old_path))?;
    let new_source = std::fs::read_to_string(&new_path)
        .with_context(|| format!("failed to read new policy '{}'", new_path))?;

    let old_ast = pcm_policy_dsl::parser::parse_policy(&old_source)
        .map_err(|e| anyhow::anyhow!("old policy parse error: {}", e))?;
    let new_ast = pcm_policy_dsl::parser::parse_policy(&new_source)
        .map_err(|e| anyhow::anyhow!("new policy parse error: {}", e))?;

    let old_compiled = pcm_policy_dsl::compiler::compile(&old_ast, "0.1.0")
        .map_err(|e| anyhow::anyhow!("old policy compile error: {}", e))?;
    let new_compiled = pcm_policy_dsl::compiler::compile(&new_ast, "0.1.0")
        .map_err(|e| anyhow::anyhow!("new policy compile error: {}", e))?;

    let old_rules: Vec<Rule> = old_compiled
        .policy
        .rules
        .iter()
        .map(|ir| ir.rule.clone())
        .collect();
    let new_rules: Vec<Rule> = new_compiled
        .policy
        .rules
        .iter()
        .map(|ir| ir.rule.clone())
        .collect();

    // ── 2. 对比规则集 ──
    let report = compute_diff(&old_rules, &new_rules);

    // ── 3. 输出报告 ──
    match format.as_str() {
        "json" => {
            let json_str = serde_json::to_string_pretty(&report)?;
            println!("{}", json_str);
        }
        _ => {
            print_text_report(&report);
        }
    }

    // ── 4. 写入文件 ──
    if let Some(ref out_path) = output {
        let json_str = serde_json::to_string_pretty(&report)?;
        std::fs::write(out_path, &json_str)
            .with_context(|| format!("failed to write report to '{}'", out_path))?;
        eprintln!("Report written to {}", out_path);
    }

    Ok(())
}

/// 计算两个规则集的差异
fn compute_diff(old_rules: &[Rule], new_rules: &[Rule]) -> DiffReport {
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut modified = Vec::new();

    // 按头部进行匹配
    // 简单策略：比较头部的谓词+参数结构
    let mut matched_new: Vec<bool> = vec![false; new_rules.len()];

    for (old_idx, old_rule) in old_rules.iter().enumerate() {
        let mut found_match = false;

        for (new_idx, new_rule) in new_rules.iter().enumerate() {
            if matched_new[new_idx] {
                continue;
            }

            if heads_match(&old_rule.head, &new_rule.head) {
                matched_new[new_idx] = true;
                found_match = true;

                // 检查体部是否也相同
                if old_rule.body != new_rule.body {
                    let impact = if is_deny_atom(&old_rule.head) || is_deny_atom(&new_rule.head) {
                        SecurityImpact::NeedsReview
                    } else {
                        SecurityImpact::None
                    };

                    modified.push(RuleDiff {
                        kind: ChangeKind::Modified,
                        rule_index: Some(old_idx),
                        head: format_atom(&old_rule.head),
                        security_impact: impact,
                        old_body: Some(format_body(&old_rule.body)),
                        new_body: Some(format_body(&new_rule.body)),
                    });
                }
                break;
            }
        }

        if !found_match {
            // 规则被删除
            let impact = if is_deny_atom(&old_rule.head) {
                SecurityImpact::PotentialEscalation
            } else {
                SecurityImpact::None
            };

            removed.push(RuleDiff {
                kind: ChangeKind::Removed,
                rule_index: Some(old_idx),
                head: format_atom(&old_rule.head),
                security_impact: impact,
                old_body: Some(format_body(&old_rule.body)),
                new_body: None,
            });
        }
    }

    // 未匹配的 new rules = 新增
    for (new_idx, new_rule) in new_rules.iter().enumerate() {
        if !matched_new[new_idx] {
            let impact = if is_deny_atom(&new_rule.head) {
                SecurityImpact::PotentialBreaking
            } else {
                SecurityImpact::None
            };

            added.push(RuleDiff {
                kind: ChangeKind::Added,
                rule_index: Some(new_idx),
                head: format_atom(&new_rule.head),
                security_impact: impact,
                old_body: None,
                new_body: Some(format_body(&new_rule.body)),
            });
        }
    }

    let has_security_impact = added
        .iter()
        .chain(removed.iter())
        .chain(modified.iter())
        .any(|d| !matches!(d.security_impact, SecurityImpact::None));

    let total = added.len() + removed.len() + modified.len();

    DiffReport {
        summary: DiffSummary {
            total_changes: total,
            added_count: added.len(),
            removed_count: removed.len(),
            modified_count: modified.len(),
            has_security_impact,
        },
        added,
        removed,
        modified,
    }
}

/// 判断两个规则头部是否"相同"（谓词及参数模式匹配）
fn heads_match(a: &Atom, b: &Atom) -> bool {
    // 使用 PartialEq：完全相同的头部
    a == b
}

/// 判断 Atom 是否为 Deny 变体
fn is_deny_atom(atom: &Atom) -> bool {
    matches!(atom, Atom::Deny { .. })
}

/// 格式化 Atom 为可读字符串
fn format_atom(atom: &Atom) -> String {
    match atom {
        Atom::Action {
            id,
            action_type,
            principal,
            target,
        } => {
            format!(
                "action({}, {}, {}, {})",
                fmt_term(id),
                fmt_term(action_type),
                fmt_term(principal),
                fmt_term(target)
            )
        }
        Atom::DataLabel { data, label } => {
            format!("data_label({}, {})", fmt_term(data), fmt_term(label))
        }
        Atom::HasRole { principal, role } => {
            format!("has_role({}, {})", fmt_term(principal), fmt_term(role))
        }
        Atom::GraphEdge { src, dst, kind } => {
            format!(
                "graph_edge({}, {}, {})",
                fmt_term(src),
                fmt_term(dst),
                fmt_term(kind)
            )
        }
        Atom::GraphLabel { node, label } => {
            format!("graph_label({}, {})", fmt_term(node), fmt_term(label))
        }
        Atom::Precedes { before, after } => {
            format!("precedes({}, {})", fmt_term(before), fmt_term(after))
        }
        Atom::Deny { request, reason } => {
            format!("deny({}, {})", fmt_term(request), fmt_term(reason))
        }
    }
}

fn fmt_term(t: &pcm_policy_dsl::ast::Term) -> String {
    match t {
        pcm_policy_dsl::ast::Term::Var(v) => v.clone(),
        pcm_policy_dsl::ast::Term::Const(c) => format!("\"{}\"", c),
    }
}

/// 格式化规则体
fn format_body(body: &[Literal]) -> String {
    body.iter()
        .map(|lit| match lit {
            Literal::Pos(a) => format_atom(a),
            Literal::Neg(a) => format!("not {}", format_atom(a)),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// 打印彩色文本报告
fn print_text_report(report: &DiffReport) {
    println!("Policy Diff Report");
    println!("==================");
    println!();

    if report.summary.total_changes == 0 {
        println!("No changes detected.");
        return;
    }

    println!(
        "Summary: {} change(s) — {} added, {} removed, {} modified",
        report.summary.total_changes,
        report.summary.added_count,
        report.summary.removed_count,
        report.summary.modified_count,
    );

    if report.summary.has_security_impact {
        println!("  ⚠ Security-relevant changes detected!");
    }
    println!();

    if !report.added.is_empty() {
        println!("Added rules:");
        for d in &report.added {
            print!("  + {}", d.head);
            print_impact(&d.security_impact);
            if let Some(ref body) = d.new_body {
                println!("      body: {}", body);
            }
        }
        println!();
    }

    if !report.removed.is_empty() {
        println!("Removed rules:");
        for d in &report.removed {
            print!("  - {}", d.head);
            print_impact(&d.security_impact);
            if let Some(ref body) = d.old_body {
                println!("      body: {}", body);
            }
        }
        println!();
    }

    if !report.modified.is_empty() {
        println!("Modified rules:");
        for d in &report.modified {
            print!("  ~ {}", d.head);
            print_impact(&d.security_impact);
            if let Some(ref old) = d.old_body {
                println!("      old: {}", old);
            }
            if let Some(ref new) = d.new_body {
                println!("      new: {}", new);
            }
        }
        println!();
    }
}

fn print_impact(impact: &SecurityImpact) {
    match impact {
        SecurityImpact::PotentialEscalation => println!("  [POTENTIAL_ESCALATION]"),
        SecurityImpact::PotentialBreaking => println!("  [POTENTIAL_BREAKING]"),
        SecurityImpact::NeedsReview => println!("  [NEEDS_REVIEW]"),
        SecurityImpact::None => println!(),
    }
}
