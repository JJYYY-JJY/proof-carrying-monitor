//! PCM Policy DSL — 策略语言解析器与编译器
//!
//! 实现 Datalog 子集的策略 DSL，包含：
//! - 词法分析与解析（手写递归下降）
//! - 类型/schema 校验
//! - 编译为内部表示 (CompiledPolicy)
//! - 可判定性检查（分层否定验证）

pub mod ast;
pub mod compiler;
pub mod parser;

pub use ast::*;
pub use compiler::{
    compile, decompile, CompileResult, CompileWarning, CompiledPolicy, FactSchema, IndexedRule,
    PredicateInfo, Stratum,
};
pub use parser::parse_policy;
