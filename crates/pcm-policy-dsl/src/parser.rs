//! 策略 DSL 解析器（最小可行实现）

use crate::ast::*;

/// 解析结果
pub type ParseResult<T> = Result<T, ParseError>;

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("unexpected token at line {line}, col {col}: {msg}")]
    UnexpectedToken {
        line: usize,
        col: usize,
        msg: String,
    },
    #[error("unexpected end of input")]
    UnexpectedEof,
}

/// 解析策略 DSL 源码（TODO: 完整实现）
pub fn parse_policy(source: &str) -> ParseResult<PolicyAst> {
    // MVP 占位：返回空策略
    let _ = source;
    Ok(PolicyAst { rules: vec![] })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty() {
        let result = parse_policy("");
        assert!(result.is_ok());
        assert!(result.unwrap().rules.is_empty());
    }
}
