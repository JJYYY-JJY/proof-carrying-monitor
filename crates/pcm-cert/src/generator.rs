//! 证书与反例生成器

use pcm_datalog_engine::engine::EvalResult;

/// 序列化的证书（wire format）
#[derive(Debug, Clone)]
pub struct CertificateData {
    pub steps: Vec<CertStep>,
    pub policy_hash: [u8; 32],
    pub graph_hash: [u8; 32],
    pub request_hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct CertStep {
    pub rule_index: usize,
    pub premise_indices: Vec<usize>,
    pub conclusion_serialized: Vec<u8>,
}

/// 序列化的反例
#[derive(Debug, Clone)]
pub struct WitnessData {
    pub deny_rule_index: usize,
    pub reason: String,
    pub matched_facts_serialized: Vec<Vec<u8>>,
    pub policy_hash: [u8; 32],
    pub request_hash: [u8; 32],
}

/// 从评估结果生成 Allow 证书
pub fn generate_certificate(
    eval: &EvalResult,
    policy_hash: [u8; 32],
    graph_hash: [u8; 32],
    request_hash: [u8; 32],
) -> CertificateData {
    let steps = eval
        .trace
        .iter()
        .map(|t| CertStep {
            rule_index: t.rule_index,
            premise_indices: t.premises.clone(),
            conclusion_serialized: format!("{:?}", t.conclusion).into_bytes(),
        })
        .collect();

    CertificateData {
        steps,
        policy_hash,
        graph_hash,
        request_hash,
    }
}

/// 从评估结果生成 Deny Witness
pub fn generate_witness(
    eval: &EvalResult,
    deny_rule_index: usize,
    reason: &str,
    policy_hash: [u8; 32],
    request_hash: [u8; 32],
) -> WitnessData {
    let matched = eval
        .facts
        .iter()
        .map(|f| format!("{:?}", f).into_bytes())
        .collect();

    WitnessData {
        deny_rule_index,
        reason: reason.to_string(),
        matched_facts_serialized: matched,
        policy_hash,
        request_hash,
    }
}
