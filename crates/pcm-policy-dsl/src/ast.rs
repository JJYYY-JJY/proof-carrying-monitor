//! 策略 DSL 抽象语法树

use serde::{Deserialize, Serialize};

/// 动作类型
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActionType {
    ToolCall,
    HttpOut,
    DbWrite,
    DbReadSensitive,
    FileWrite,
    FileRead,
    Custom(String),
}

/// 敏感标签
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Label {
    Public,
    Internal,
    Confidential,
    Secret,
}

/// 边类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EdgeKind {
    DataFlow,
    ControlFlow,
    Causal,
    Temporal,
}

/// 原子项（可为变量或常量）
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Term {
    Var(String),
    Const(String),
}

/// 原子谓词
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Atom {
    Action {
        id: Term,
        action_type: Term,
        principal: Term,
        target: Term,
    },
    DataLabel {
        data: Term,
        label: Term,
    },
    HasRole {
        principal: Term,
        role: Term,
    },
    GraphEdge {
        src: Term,
        dst: Term,
        kind: Term,
    },
    GraphLabel {
        node: Term,
        label: Term,
    },
    Precedes {
        before: Term,
        after: Term,
    },
    Deny {
        request: Term,
        reason: Term,
    },
}

/// 文字（正或负）
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Literal {
    Pos(Atom),
    Neg(Atom),
}

/// 规则
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub head: Atom,
    pub body: Vec<Literal>,
}

/// 策略 AST
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyAst {
    pub rules: Vec<Rule>,
}
