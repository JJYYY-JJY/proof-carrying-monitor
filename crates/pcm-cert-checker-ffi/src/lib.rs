//! PCM Cert Checker FFI — Lean 抽取的证书验证器绑定
//!
//! 在 Lean 代码抽取完成前，本 crate 提供镜像 Rust 实现作为临时替代。
//! 最终将通过 C FFI 调用 Lean-extracted checker。

/// 证书验证结果
#[derive(Debug, Clone)]
pub struct VerifyResult {
    pub valid: bool,
    pub error: Option<String>,
}

/// 验证 Allow 证书（临时 Rust 镜像实现）
///
/// TODO: 替换为 Lean FFI 调用
pub fn verify_certificate(
    cert_bytes: &[u8],
    request_bytes: &[u8],
    policy_bytes: &[u8],
    _graph_bytes: &[u8],
) -> VerifyResult {
    // 临时实现：基本格式检查
    if cert_bytes.is_empty() || request_bytes.is_empty() || policy_bytes.is_empty() {
        return VerifyResult {
            valid: false,
            error: Some("empty input".to_string()),
        };
    }

    // TODO: 实际验证逻辑（与 Lean checkCert 对齐）
    VerifyResult {
        valid: true,
        error: None,
    }
}

/// 验证 Deny Witness（临时 Rust 镜像实现）
pub fn verify_witness(
    witness_bytes: &[u8],
    request_bytes: &[u8],
    policy_bytes: &[u8],
    _graph_bytes: &[u8],
) -> VerifyResult {
    if witness_bytes.is_empty() || request_bytes.is_empty() || policy_bytes.is_empty() {
        return VerifyResult {
            valid: false,
            error: Some("empty input".to_string()),
        };
    }

    // TODO: 实际验证逻辑（与 Lean checkWitness 对齐）
    VerifyResult {
        valid: true,
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_input_fails() {
        let result = verify_certificate(&[], b"req", b"pol", b"graph");
        assert!(!result.valid);
    }

    #[test]
    fn test_nonempty_passes_placeholder() {
        let result = verify_certificate(b"cert", b"req", b"pol", b"graph");
        assert!(result.valid);
    }
}
