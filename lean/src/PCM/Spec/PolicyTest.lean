/-
  PCM.Spec.PolicyTest — Policy 类型的测试与示例

  验证 isAllowed 对不同策略的行为正确。
-/
import PCM.Spec.Policy

namespace PCM.Spec.PolicyTest

open PCM.Spec

-- ============================================================
-- 基础测试：空策略
-- ============================================================

-- 空策略（无规则）
def testPolicy : Policy := { rules := [] }

-- 测试请求
def testReq : Request := Request.mk' "r1" .httpOut "alice" "api.example.com"

-- 空图
def testGraph : Graph := Graph.empty

-- 空策略下，isAllowed 应返回 true
#eval isAllowed testReq testPolicy testGraph []

-- 验证 baseFacts 包含请求的 action 事实
#eval baseFacts testReq testGraph []

-- 验证 minimalModel 对空策略等于 baseFacts
#eval minimalModel testPolicy (baseFacts testReq testGraph [])

-- ============================================================
-- 含 deny 规则的策略
-- ============================================================

-- 一条 deny 规则：当存在 httpOut 动作时 deny
def denyRule : Rule := {
  head := .deny "r1" "test_deny",
  body := [.pos (.action "r1" .httpOut "alice" "api.example.com")]
}

-- 含 deny 规则的策略
def testPolicyDeny : Policy := { rules := [denyRule] }

-- 含 deny 规则时，isAllowed 应返回 false
#eval isAllowed testReq testPolicyDeny testGraph []

-- 验证 deny 规则触发后 minimalModel 包含 deny atom
#eval minimalModel testPolicyDeny (baseFacts testReq testGraph [])

-- ============================================================
-- 不匹配的 deny 规则
-- ============================================================

-- 不匹配的 deny 规则（target 不同）
def denyRuleNoMatch : Rule := {
  head := .deny "r1" "wrong_target",
  body := [.pos (.action "r1" .httpOut "alice" "other.example.com")]
}

-- 不匹配 deny 规则的策略
def testPolicyNoMatch : Policy := { rules := [denyRuleNoMatch] }

-- 不匹配的 deny 规则不应阻止请求
#eval isAllowed testReq testPolicyNoMatch testGraph []

-- ============================================================
-- 带角色的策略
-- ============================================================

-- deny 依赖 has_role 的规则
def denyWithRole : Rule := {
  head := .deny "r1" "role_based_deny",
  body := [
    .pos (.action "r1" .httpOut "alice" "api.example.com"),
    .pos (.hasRole "alice" "admin")
  ]
}

def testPolicyRole : Policy := { rules := [denyWithRole] }

-- 无角色分配时，deny 规则不触发
#eval isAllowed testReq testPolicyRole testGraph []

-- 有匹配角色时，deny 规则触发
#eval isAllowed testReq testPolicyRole testGraph [("alice", "admin")]

-- ============================================================
-- 负文字（negation）测试
-- ============================================================

-- deny 使用负文字：无 http_allowed 角色时 deny
def denyWithNeg : Rule := {
  head := .deny "r1" "unauthorized_http",
  body := [
    .pos (.action "r1" .httpOut "alice" "api.example.com"),
    .neg (.hasRole "alice" "http_allowed")
  ]
}

def testPolicyNeg : Policy := { rules := [denyWithNeg] }

-- 无 http_allowed 角色 → deny（负文字满足）
#eval isAllowed testReq testPolicyNeg testGraph []

-- 有 http_allowed 角色 → allow（负文字不满足，规则不触发）
#eval isAllowed testReq testPolicyNeg testGraph [("alice", "http_allowed")]

-- ============================================================
-- example 验证
-- ============================================================

/-- 空策略允许任何请求 -/
example : isAllowed testReq testPolicy testGraph [] = true := rfl

/-- 匹配的 deny 规则拒绝请求 -/
example : isAllowed testReq testPolicyDeny testGraph [] = false := rfl

/-- 不匹配的 deny 规则不影响允许 -/
example : isAllowed testReq testPolicyNoMatch testGraph [] = true := rfl

/-- 缺少角色前提时 deny 规则不触发 -/
example : isAllowed testReq testPolicyRole testGraph [] = true := rfl

/-- 角色前提满足时 deny 规则触发 -/
example : isAllowed testReq testPolicyRole testGraph [("alice", "admin")] = false := rfl

/-- 负文字满足时 deny 触发 -/
example : isAllowed testReq testPolicyNeg testGraph [] = false := rfl

/-- 负文字不满足时不 deny -/
example : isAllowed testReq testPolicyNeg testGraph [("alice", "http_allowed")] = true := rfl

end PCM.Spec.PolicyTest
