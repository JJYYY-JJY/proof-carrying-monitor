//! 事实构建工具

use pcm_policy_dsl::ast::{Atom, Term};

/// 从请求参数构建基础事实
pub fn build_request_fact(
    request_id: &str,
    action_type: &str,
    principal: &str,
    target: &str,
) -> Atom {
    Atom::Action {
        id: Term::Const(request_id.to_string()),
        action_type: Term::Const(action_type.to_string()),
        principal: Term::Const(principal.to_string()),
        target: Term::Const(target.to_string()),
    }
}

/// 从角色列表构建 has_role 事实
pub fn build_role_facts(roles: &[(String, String)]) -> Vec<Atom> {
    roles
        .iter()
        .map(|(p, r)| Atom::HasRole {
            principal: Term::Const(p.clone()),
            role: Term::Const(r.clone()),
        })
        .collect()
}

/// 构建 graph_edge 事实
pub fn build_graph_edge(src: &str, dst: &str, kind: &str) -> Atom {
    Atom::GraphEdge {
        src: Term::Const(src.to_string()),
        dst: Term::Const(dst.to_string()),
        kind: Term::Const(kind.to_string()),
    }
}

/// 构建 graph_label 事实
pub fn build_graph_label(node: &str, label: &str) -> Atom {
    Atom::GraphLabel {
        node: Term::Const(node.to_string()),
        label: Term::Const(label.to_string()),
    }
}

/// 构建 precedes 事实
pub fn build_precedes(before: &str, after: &str) -> Atom {
    Atom::Precedes {
        before: Term::Const(before.to_string()),
        after: Term::Const(after.to_string()),
    }
}

/// 构建 data_label 事实
pub fn build_data_label(data: &str, label: &str) -> Atom {
    Atom::DataLabel {
        data: Term::Const(data.to_string()),
        label: Term::Const(label.to_string()),
    }
}
