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
