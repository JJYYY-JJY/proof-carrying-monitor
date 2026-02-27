//! 策略编译器：AST → CompiledPolicy

use crate::ast::PolicyAst;
use serde::{Deserialize, Serialize};

/// 编译后的策略（内部表示）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledPolicy {
    /// 序列化的规则索引
    pub rules_data: Vec<u8>,
    /// 策略内容哈希 (blake3)
    pub content_hash: [u8; 32],
    /// 语义版本
    pub version: String,
    /// 是否通过可判定性检查
    pub decidable: bool,
}

/// 编译警告
#[derive(Debug, Clone)]
pub struct CompileWarning {
    pub message: String,
    pub rule_index: Option<usize>,
}

/// 编译结果
pub struct CompileResult {
    pub policy: CompiledPolicy,
    pub warnings: Vec<CompileWarning>,
}

/// 编译策略 AST（TODO: 完整实现）
pub fn compile(ast: &PolicyAst, version: &str) -> Result<CompileResult, pcm_common::PcmError> {
    let serialized = serde_json::to_vec(ast)
        .map_err(|e| pcm_common::PcmError::PolicyCompilation(e.to_string()))?;
    let hash = pcm_common::hash::blake3_hash(&serialized);

    Ok(CompileResult {
        policy: CompiledPolicy {
            rules_data: serialized,
            content_hash: hash,
            version: version.to_string(),
            decidable: true, // TODO: 实际分层否定检查
        },
        warnings: vec![],
    })
}
