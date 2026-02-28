//! E2E tests for pcm-cli subcommands

use std::process::Command;

/// Helper to get the cargo binary path for pcm-cli
fn pcm_bin() -> Command {
    let mut cmd = Command::new(env!("CARGO"));
    cmd.args(["run", "-p", "pcm-cli", "--"]);
    cmd
}

// ============================================================
// Validate 子命令 (已有功能，回归测试)
// ============================================================

#[test]
fn test_validate_valid_policy() {
    let mut cmd = pcm_bin();
    cmd.args(["validate", "-f", "../../policies/example.pcm"]);
    let output = cmd.output().expect("failed to run pcm validate");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Policy is valid"), "stdout: {}", stdout);
    assert!(output.status.success());
}

#[test]
fn test_validate_invalid_policy() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.pcm");
    std::fs::write(&path, "this is not valid policy syntax $$$$").unwrap();

    let mut cmd = pcm_bin();
    cmd.args(["validate", "-f", path.to_str().unwrap()]);
    let output = cmd.output().expect("failed to run pcm validate");
    assert!(!output.status.success());
}

// ============================================================
// Compile 子命令（回归测试）
// ============================================================

#[test]
fn test_compile_policy() {
    let dir = tempfile::tempdir().unwrap();
    let out_path = dir.path().join("out.json");

    let mut cmd = pcm_bin();
    cmd.args([
        "compile",
        "-f",
        "../../policies/example.pcm",
        "-o",
        out_path.to_str().unwrap(),
    ]);
    let output = cmd.output().expect("failed to run pcm compile");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("Compiled policy written to"),
        "stdout: {}",
        stdout
    );
    assert!(out_path.exists());

    // 输出应该是合法 JSON
    let content = std::fs::read_to_string(&out_path).unwrap();
    let _: serde_json::Value = serde_json::from_str(&content).expect("output should be valid JSON");
}

// ============================================================
// Verify 子命令
// ============================================================

#[test]
fn test_verify_invalid_cert_file() {
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("bad_cert.bin");
    std::fs::write(&cert_path, b"not a certificate").unwrap();

    let mut cmd = pcm_bin();
    cmd.args([
        "verify",
        "-c",
        cert_path.to_str().unwrap(),
        "-p",
        "../../policies/example.pcm",
    ]);
    let output = cmd.output().expect("failed to run pcm verify");
    // Should fail — invalid certificate
    assert!(!output.status.success());
}

#[test]
fn test_verify_json_format_output() {
    let dir = tempfile::tempdir().unwrap();

    // Create a minimal valid-structure cert JSON (will fail hash verification, but at least parses)
    let zero_hash = vec![0u8; 32];
    let cert_json = serde_json::json!({
        "steps": [],
        "policy_hash": zero_hash,
        "graph_hash": zero_hash,
        "request_hash": zero_hash
    });
    let cert_path = dir.path().join("cert.json");
    std::fs::write(&cert_path, serde_json::to_string(&cert_json).unwrap()).unwrap();

    let mut cmd = pcm_bin();
    cmd.args([
        "verify",
        "-c",
        cert_path.to_str().unwrap(),
        "-p",
        "../../policies/example.pcm",
        "--format",
        "json",
    ]);
    let output = cmd.output().expect("failed to run pcm verify");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let trimmed = stdout.trim();
    assert!(!trimmed.is_empty(), "should produce JSON output");
    let parsed: serde_json::Value =
        serde_json::from_str(trimmed).expect(&format!("output should be valid JSON: {}", trimmed));
    // Should have "valid" field
    assert!(
        parsed.get("valid").is_some(),
        "JSON should have 'valid' field"
    );
}

#[test]
fn test_verify_missing_cert_file() {
    let mut cmd = pcm_bin();
    cmd.args([
        "verify",
        "-c",
        "/nonexistent/cert.bin",
        "-p",
        "../../policies/example.pcm",
    ]);
    let output = cmd.output().expect("failed to run pcm verify");
    assert!(!output.status.success());
}

// ============================================================
// Diff 子命令
// ============================================================

#[test]
fn test_diff_same_policy() {
    let mut cmd = pcm_bin();
    cmd.args([
        "diff",
        "--old",
        "../../policies/example.pcm",
        "--new",
        "../../policies/example.pcm",
    ]);
    let output = cmd.output().expect("failed to run pcm diff");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("No changes detected"),
        "same policy should produce no changes, got: {}",
        stdout
    );
}

#[test]
fn test_diff_different_policies() {
    let mut cmd = pcm_bin();
    cmd.args([
        "diff",
        "--old",
        "../../policies/test_single_deny.pcm",
        "--new",
        "../../policies/test_multi_rule.pcm",
    ]);
    let output = cmd.output().expect("failed to run pcm diff");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // Should detect changes
    assert!(
        stdout.contains("change(s)")
            || stdout.contains("Added")
            || stdout.contains("Removed")
            || stdout.contains("Modified"),
        "should detect differences: {}",
        stdout
    );
}

#[test]
fn test_diff_json_format() {
    let mut cmd = pcm_bin();
    cmd.args([
        "diff",
        "--old",
        "../../policies/test_single_deny.pcm",
        "--new",
        "../../policies/example.pcm",
        "--format",
        "json",
    ]);
    let output = cmd.output().expect("failed to run pcm diff");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Filter out any non-JSON lines (e.g. stderr leaking or report-file messages)
    let json_str = stdout.trim();
    let parsed: serde_json::Value = serde_json::from_str(json_str).expect(&format!(
        "diff JSON output should be valid, got: {}",
        json_str
    ));
    assert!(parsed.get("summary").is_some(), "should have summary field");
    assert!(parsed.get("added").is_some(), "should have added field");
    assert!(parsed.get("removed").is_some(), "should have removed field");
    assert!(
        parsed.get("modified").is_some(),
        "should have modified field"
    );
}

#[test]
fn test_diff_output_file() {
    let dir = tempfile::tempdir().unwrap();
    let out_path = dir.path().join("report.json");

    let mut cmd = pcm_bin();
    cmd.args([
        "diff",
        "--old",
        "../../policies/test_single_deny.pcm",
        "--new",
        "../../policies/example.pcm",
        "-o",
        out_path.to_str().unwrap(),
    ]);
    let output = cmd.output().expect("failed to run pcm diff");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(out_path.exists(), "report file should be created");

    let content = std::fs::read_to_string(&out_path).unwrap();
    let _: serde_json::Value =
        serde_json::from_str(&content).expect("report file should be valid JSON");
}

#[test]
fn test_diff_security_impact_detection() {
    // 创建两个策略：old 有 deny 规则，new 没有 → potential_escalation
    let dir = tempfile::tempdir().unwrap();
    let old_path = dir.path().join("old.pcm");
    let new_path = dir.path().join("new.pcm");

    std::fs::write(
        &old_path,
        r#"deny(Req, "block_http") :-
    action(Req, HttpOut, P, _),
    !has_role(P, "http_allowed").
"#,
    )
    .unwrap();

    // new 策略只有一条不同的 deny 规则
    std::fs::write(
        &new_path,
        r#"deny(Req, "block_writes") :-
    action(Req, DbWrite, P, _),
    !has_role(P, "writer").
"#,
    )
    .unwrap();

    let mut cmd = pcm_bin();
    cmd.args([
        "diff",
        "--old",
        old_path.to_str().unwrap(),
        "--new",
        new_path.to_str().unwrap(),
        "--format",
        "json",
    ]);
    let output = cmd.output().expect("failed to run pcm diff");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    let summary = &parsed["summary"];
    assert!(
        summary["has_security_impact"].as_bool().unwrap_or(false),
        "removing/adding deny rules should be security-relevant: {}",
        stdout
    );
}

// ============================================================
// Audit 子命令
// ============================================================

#[test]
fn test_audit_connection_failure() {
    // 连接到不存在的端点，应该报错
    let mut cmd = pcm_bin();
    cmd.args([
        "audit",
        "--endpoint",
        "http://localhost:19999",
        "--format",
        "text",
    ]);
    let output = cmd.output().expect("failed to run pcm audit");
    assert!(
        !output.status.success(),
        "should fail when service is unavailable"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to connect")
            || stderr.contains("Error")
            || stderr.contains("error"),
        "should provide connection failure info: stderr={}",
        stderr,
    );
}

#[test]
fn test_audit_verify_chain_missing_ids() {
    let mut cmd = pcm_bin();
    cmd.args([
        "audit",
        "--verify-chain",
        "--endpoint",
        "http://localhost:19999",
    ]);
    let output = cmd.output().expect("failed to run pcm audit");
    // May fail due to connection or missing IDs — either is acceptable
    assert!(!output.status.success());
}

// ============================================================
// 全局参数
// ============================================================

#[test]
fn test_help_output() {
    let mut cmd = pcm_bin();
    cmd.args(["--help"]);
    let output = cmd.output().expect("failed to run pcm --help");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(
        stdout.contains("Proof-Carrying Monitor CLI"),
        "stdout: {}",
        stdout
    );
    assert!(stdout.contains("compile"), "should list compile subcommand");
    assert!(stdout.contains("verify"), "should list verify subcommand");
    assert!(stdout.contains("diff"), "should list diff subcommand");
    assert!(stdout.contains("audit"), "should list audit subcommand");
    assert!(
        stdout.contains("validate"),
        "should list validate subcommand"
    );
}

#[test]
fn test_version_output() {
    let mut cmd = pcm_bin();
    cmd.args(["--version"]);
    let output = cmd.output().expect("failed to run pcm --version");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(
        stdout.contains("pcm"),
        "version should mention pcm: {}",
        stdout
    );
}

#[test]
fn test_verbose_flag() {
    let mut cmd = pcm_bin();
    cmd.args(["-v", "validate", "-f", "../../policies/example.pcm"]);
    let output = cmd.output().expect("failed to run pcm with -v");
    assert!(output.status.success());
}
