//! 策略 DSL 解析器
//!
//! 使用 nom parser combinator 实现策略 DSL 的完整解析。
//!
//! 支持的语法：
//! - 行注释：`//` 到行尾
//! - 变量：大写字母开头的标识符
//! - 常量：小写字母开头的标识符 或 双引号字符串
//! - 通配符：`_`（匿名变量）
//! - 谓词：action, data_label, has_role, graph_edge, graph_label, precedes, deny
//! - 正文字：atom
//! - 负文字：!atom
//! - 规则：head :- body1, body2, ... .

use crate::ast::*;

/// 解析结果
pub type ParseResult<T> = Result<T, ParseError>;

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("syntax error at line {line}, col {col}: {msg}")]
    UnexpectedToken {
        line: usize,
        col: usize,
        msg: String,
    },
    #[error("unexpected end of input")]
    UnexpectedEof,
}

use nom::{
    IResult,
    branch::alt,
    bytes::complete::{is_not, tag, take_while},
    character::complete::{char, multispace1, satisfy},
    combinator::{all_consuming, cut, map, opt, recognize, value},
    multi::{many0, separated_list1},
    sequence::{delimited, pair, preceded, tuple},
};

// ============================================================
// Whitespace & comment combinators
// ============================================================

/// Parse a line comment: `//` followed by everything until end of line.
fn line_comment(input: &str) -> IResult<&str, ()> {
    value((), pair(tag("//"), opt(is_not("\n\r"))))(input)
}

/// Consume zero or more whitespace characters and/or line comments.
fn ws(input: &str) -> IResult<&str, ()> {
    value((), many0(alt((value((), multispace1), line_comment))))(input)
}

// ============================================================
// Identifiers & terms
// ============================================================

/// An identifier starts with an ASCII letter or `_`, followed by ASCII
/// alphanumerics or `_`.
fn identifier(input: &str) -> IResult<&str, &str> {
    recognize(pair(
        satisfy(|c: char| c.is_ascii_alphabetic() || c == '_'),
        take_while(|c: char| c.is_ascii_alphanumeric() || c == '_'),
    ))(input)
}

/// Parse a double-quoted string literal (supports `\\`, `\"`, `\n`, `\t`
/// escape sequences).
fn string_literal(input: &str) -> IResult<&str, String> {
    let (input, _) = char('"')(input)?;
    let mut result = String::new();
    let mut remaining = input;
    loop {
        match remaining.chars().next() {
            Some('"') => return Ok((&remaining[1..], result)),
            Some('\\') => {
                let mut chars = remaining.chars();
                chars.next(); // skip '\'
                match chars.next() {
                    Some('n') => result.push('\n'),
                    Some('t') => result.push('\t'),
                    Some('\\') => result.push('\\'),
                    Some('"') => result.push('"'),
                    Some(c) => {
                        result.push('\\');
                        result.push(c);
                    }
                    None => {
                        return Err(nom::Err::Error(nom::error::Error::new(
                            remaining,
                            nom::error::ErrorKind::Char,
                        )));
                    }
                }
                remaining = chars.as_str();
            }
            Some(c) => {
                result.push(c);
                remaining = &remaining[c.len_utf8()..];
            }
            None => {
                return Err(nom::Err::Error(nom::error::Error::new(
                    remaining,
                    nom::error::ErrorKind::Char,
                )));
            }
        }
    }
}

/// Parse a [`Term`]: variable (uppercase-start identifier), constant
/// (lowercase-start identifier or quoted string), or wildcard `_`.
fn term(input: &str) -> IResult<&str, Term> {
    alt((
        map(string_literal, Term::Const),
        map(identifier, |s: &str| {
            if s == "_" {
                // Wildcard — anonymous variable
                Term::Var("_".to_string())
            } else if s.starts_with(|c: char| c.is_ascii_uppercase()) {
                Term::Var(s.to_string())
            } else {
                Term::Const(s.to_string())
            }
        }),
    ))(input)
}

// ============================================================
// Atoms (predicates)
// ============================================================

/// Parse a parenthesised, comma-separated list of terms: `(t1, t2, …)`
fn args_list(input: &str) -> IResult<&str, Vec<Term>> {
    delimited(
        pair(char('('), ws),
        separated_list1(tuple((ws, char(','), ws)), term),
        pair(ws, char(')')),
    )(input)
}

/// Parse an [`Atom`] — a known predicate applied to its arguments.
fn atom(input: &str) -> IResult<&str, Atom> {
    let (rest, name) = identifier(input)?;
    let (rest, _) = ws(rest)?;
    let (rest, args) = args_list(rest)?;

    let bad_arity =
        || nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Verify));

    match name {
        "action" if args.len() == 4 => {
            let mut it = args.into_iter();
            Ok((
                rest,
                Atom::Action {
                    id: it.next().unwrap(),
                    action_type: it.next().unwrap(),
                    principal: it.next().unwrap(),
                    target: it.next().unwrap(),
                },
            ))
        }
        "data_label" if args.len() == 2 => {
            let mut it = args.into_iter();
            Ok((
                rest,
                Atom::DataLabel {
                    data: it.next().unwrap(),
                    label: it.next().unwrap(),
                },
            ))
        }
        "has_role" if args.len() == 2 => {
            let mut it = args.into_iter();
            Ok((
                rest,
                Atom::HasRole {
                    principal: it.next().unwrap(),
                    role: it.next().unwrap(),
                },
            ))
        }
        "graph_edge" if args.len() == 3 => {
            let mut it = args.into_iter();
            Ok((
                rest,
                Atom::GraphEdge {
                    src: it.next().unwrap(),
                    dst: it.next().unwrap(),
                    kind: it.next().unwrap(),
                },
            ))
        }
        "graph_label" if args.len() == 2 => {
            let mut it = args.into_iter();
            Ok((
                rest,
                Atom::GraphLabel {
                    node: it.next().unwrap(),
                    label: it.next().unwrap(),
                },
            ))
        }
        "precedes" if args.len() == 2 => {
            let mut it = args.into_iter();
            Ok((
                rest,
                Atom::Precedes {
                    before: it.next().unwrap(),
                    after: it.next().unwrap(),
                },
            ))
        }
        "deny" if args.len() == 2 => {
            let mut it = args.into_iter();
            Ok((
                rest,
                Atom::Deny {
                    request: it.next().unwrap(),
                    reason: it.next().unwrap(),
                },
            ))
        }
        // Known predicate with wrong arity
        "action" | "data_label" | "has_role" | "graph_edge" | "graph_label" | "precedes"
        | "deny" => Err(bad_arity()),
        // Unknown predicate
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        ))),
    }
}

// ============================================================
// Literals
// ============================================================

/// Parse a [`Literal`] — either a positive atom or `!atom` (negated).
fn literal_p(input: &str) -> IResult<&str, Literal> {
    alt((
        map(preceded(pair(char('!'), ws), atom), Literal::Neg),
        map(atom, Literal::Pos),
    ))(input)
}

// ============================================================
// Rules & policy
// ============================================================

/// Parse a [`Rule`]: `head :- body1, body2, … .`
///
/// After the head atom is successfully parsed, errors become
/// non-recoverable (`cut`) so that missing `:-` or `.` are reported
/// directly instead of being swallowed by `many0`.
fn rule_p(input: &str) -> IResult<&str, Rule> {
    let (rest, _) = ws(input)?;
    let (rest, head) = atom(rest)?;
    let (rest, _) = ws(rest)?;
    let (rest, _) = cut(tag(":-"))(rest)?;
    let (rest, _) = ws(rest)?;
    let (rest, body) = cut(separated_list1(tuple((ws, char(','), ws)), literal_p))(rest)?;
    let (rest, _) = ws(rest)?;
    let (rest, _) = cut(char('.'))(rest)?;
    Ok((rest, Rule { head, body }))
}

/// Parse a complete [`PolicyAst`] — zero or more rules, ignoring
/// comments and whitespace.
fn policy_p(input: &str) -> IResult<&str, PolicyAst> {
    let (rest, _) = ws(input)?;
    let (rest, rules) = many0(rule_p)(rest)?;
    let (rest, _) = ws(rest)?;
    Ok((rest, PolicyAst { rules }))
}

// ============================================================
// Error position calculation
// ============================================================

/// Compute 1-based (line, col) from the original source and a remaining
/// slice pointer.
fn compute_position(source: &str, remaining: &str) -> (usize, usize) {
    let offset = source.len() - remaining.len();
    let consumed = &source[..offset];
    let line = consumed.chars().filter(|&c| c == '\n').count() + 1;
    let col = match consumed.rfind('\n') {
        Some(pos) => offset - pos - 1,
        None => offset,
    } + 1;
    (line, col)
}

// ============================================================
// Public API
// ============================================================

/// Parse a PCM policy DSL source string into a [`PolicyAst`].
///
/// Returns `Err(ParseError)` with line/column information on syntax
/// errors.
pub fn parse_policy(source: &str) -> ParseResult<PolicyAst> {
    match all_consuming(policy_p)(source) {
        Ok((_, ast)) => Ok(ast),
        Err(nom::Err::Error(e) | nom::Err::Failure(e)) => {
            let (line, col) = compute_position(source, e.input);
            let msg = if e.input.is_empty() {
                "unexpected end of input".to_string()
            } else {
                let snippet: String = e.input.chars().take(40).collect();
                format!("near '{}'", snippet.trim())
            };
            Err(ParseError::UnexpectedToken { line, col, msg })
        }
        Err(nom::Err::Incomplete(_)) => Err(ParseError::UnexpectedEof),
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Helper: resolve a policy file path relative to the workspace root.
    fn policy_path(name: &str) -> PathBuf {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        manifest.join("../../policies").join(name)
    }

    // ---- basic cases ----

    #[test]
    fn test_parse_empty() {
        let result = parse_policy("");
        assert!(result.is_ok());
        assert!(result.unwrap().rules.is_empty());
    }

    #[test]
    fn test_parse_comments_only() {
        let result = parse_policy("// comment line 1\n// comment line 2\n");
        assert!(result.is_ok());
        assert!(result.unwrap().rules.is_empty());
    }

    // ---- single / multi rules ----

    #[test]
    fn test_parse_single_rule() {
        let input = r#"deny(Req, "test") :- action(Req, HttpOut, P, _)."#;
        let ast = parse_policy(input).unwrap();
        assert_eq!(ast.rules.len(), 1);
        assert!(matches!(&ast.rules[0].head, Atom::Deny { .. }));
        assert_eq!(ast.rules[0].body.len(), 1);
    }

    #[test]
    fn test_parse_multi_rule() {
        let input = r#"
            deny(Req, "a") :- action(Req, HttpOut, P, _).
            deny(Req, "b") :- has_role(P, "admin").
        "#;
        let ast = parse_policy(input).unwrap();
        assert_eq!(ast.rules.len(), 2);
    }

    // ---- term identification ----

    #[test]
    fn test_term_variable() {
        let input = r#"deny(Req, "t") :- action(Req, HttpOut, P, _)."#;
        let ast = parse_policy(input).unwrap();
        if let Atom::Deny { request, .. } = &ast.rules[0].head {
            assert_eq!(*request, Term::Var("Req".to_string()));
        } else {
            panic!("expected Deny atom");
        }
    }

    #[test]
    fn test_term_constant_identifier() {
        let input = r#"deny(Req, "t") :- action(Req, HttpOut, P, _), graph_edge(A, B, data_flow)."#;
        let ast = parse_policy(input).unwrap();
        if let Literal::Pos(Atom::GraphEdge { kind, .. }) = &ast.rules[0].body[1] {
            assert_eq!(*kind, Term::Const("data_flow".to_string()));
        } else {
            panic!("expected GraphEdge literal");
        }
    }

    #[test]
    fn test_term_string_constant() {
        let input = r#"deny(Req, "unauthorized") :- action(Req, HttpOut, P, _)."#;
        let ast = parse_policy(input).unwrap();
        if let Atom::Deny { reason, .. } = &ast.rules[0].head {
            assert_eq!(*reason, Term::Const("unauthorized".to_string()));
        } else {
            panic!("expected Deny atom");
        }
    }

    #[test]
    fn test_wildcard() {
        let input = r#"deny(Req, "t") :- action(Req, HttpOut, _, _)."#;
        let ast = parse_policy(input).unwrap();
        if let Literal::Pos(Atom::Action {
            principal, target, ..
        }) = &ast.rules[0].body[0]
        {
            assert_eq!(*principal, Term::Var("_".to_string()));
            assert_eq!(*target, Term::Var("_".to_string()));
        } else {
            panic!("expected Action literal");
        }
    }

    // ---- negation ----

    #[test]
    fn test_negation() {
        let input = r#"deny(Req, "t") :- action(Req, HttpOut, P, _), !has_role(P, "admin")."#;
        let ast = parse_policy(input).unwrap();
        assert_eq!(ast.rules[0].body.len(), 2);
        assert!(matches!(&ast.rules[0].body[0], Literal::Pos(_)));
        assert!(matches!(
            &ast.rules[0].body[1],
            Literal::Neg(Atom::HasRole { .. })
        ));
    }

    // ---- example.pcm ----

    #[test]
    fn test_parse_example_pcm() {
        let path = policy_path("example.pcm");
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        let ast = parse_policy(&source).unwrap();
        assert_eq!(ast.rules.len(), 4, "example.pcm should contain 4 rules");
        for rule in &ast.rules {
            assert!(matches!(&rule.head, Atom::Deny { .. }));
        }
    }

    // ---- error reporting ----

    #[test]
    fn test_syntax_error_missing_period() {
        let input = r#"deny(Req, "t") :- action(Req, HttpOut, P, _)"#;
        let err = parse_policy(input).unwrap_err();
        let msg = err.to_string();
        // Must mention a position (line/col)
        assert!(
            msg.contains("line") || msg.contains("end of input"),
            "error should mention position: {msg}"
        );
    }

    #[test]
    fn test_syntax_error_missing_horn() {
        let input = r#"deny(Req, "t") action(Req, HttpOut, P, _)."#;
        let err = parse_policy(input);
        assert!(err.is_err(), "missing :- should be a syntax error");
    }

    // ---- integration: all .pcm files ----

    #[test]
    fn test_parse_test_empty_pcm() {
        let source = std::fs::read_to_string(policy_path("test_empty.pcm")).unwrap();
        let ast = parse_policy(&source).unwrap();
        assert!(ast.rules.is_empty());
    }

    #[test]
    fn test_parse_test_single_deny_pcm() {
        let source = std::fs::read_to_string(policy_path("test_single_deny.pcm")).unwrap();
        let ast = parse_policy(&source).unwrap();
        assert_eq!(ast.rules.len(), 1);
    }

    #[test]
    fn test_parse_test_multi_rule_pcm() {
        let source = std::fs::read_to_string(policy_path("test_multi_rule.pcm")).unwrap();
        let ast = parse_policy(&source).unwrap();
        assert!(ast.rules.len() >= 3);
    }

    #[test]
    fn test_parse_test_graph_constraint_pcm() {
        let source = std::fs::read_to_string(policy_path("test_graph_constraint.pcm")).unwrap();
        let ast = parse_policy(&source).unwrap();
        assert!(!ast.rules.is_empty());
        // Should contain graph_edge / graph_label references in body
        let has_graph = ast.rules.iter().any(|r| {
            r.body.iter().any(|lit| {
                matches!(
                    lit,
                    Literal::Pos(Atom::GraphEdge { .. }) | Literal::Pos(Atom::GraphLabel { .. })
                )
            })
        });
        assert!(has_graph, "should contain graph predicates");
    }

    #[test]
    fn test_parse_test_temporal_pcm() {
        let source = std::fs::read_to_string(policy_path("test_temporal.pcm")).unwrap();
        let ast = parse_policy(&source).unwrap();
        assert!(!ast.rules.is_empty());
        // Should contain precedes references
        let has_precedes = ast.rules.iter().any(|r| {
            r.body.iter().any(|lit| {
                matches!(
                    lit,
                    Literal::Pos(Atom::Precedes { .. }) | Literal::Neg(Atom::Precedes { .. })
                )
            })
        });
        assert!(has_precedes, "should contain precedes predicates");
    }
}
