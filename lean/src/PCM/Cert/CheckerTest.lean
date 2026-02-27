/-
  PCM.Cert.CheckerTest — Checker 的 #eval 端到端测试

  测试 checkCert / checkWitness / checkDiffCert 在具体输入上的行为。
-/
import PCM.Cert.Checker

namespace PCM.Cert.CheckerTest

open PCM.Spec PCM.Cert

-- ============================================================
-- 测试用公共定义
-- ============================================================

/-- 空 ByteArray（测试用，不检查哈希） -/
def emptyHash : ByteArray := .empty

-- ============================================================
-- 场景 1: 空策略、空证书 → Allow (checkCert = true)
-- ============================================================

def pol1 : Policy := { rules := [] }
def req1 : Request := Request.mk' "r1" .httpOut "alice" "api.example.com"
def cert1 : Certificate := {
  steps := [], policyHash := emptyHash, graphHash := emptyHash, requestHash := emptyHash
}

-- 空策略、无推导步骤 → baseFacts 中无 deny → true
#eval checkCert cert1 req1 pol1 Graph.empty []
-- 预期: true

example : checkCert cert1 req1 pol1 Graph.empty [] = true := rfl

-- ============================================================
-- 场景 2: 有非 deny 推导规则 → Allow (checkCert = true)
-- ============================================================

-- 规则: precedes("a", "b") :- hasRole("alice", "admin")
-- 规则头不是 deny，推导成功但不产生 deny → allow
def rule2 : Rule := {
  head := .precedes "a" "b",
  body := [.pos (.hasRole "alice" "admin")]
}
def pol2 : Policy := { rules := [rule2] }
def req2 : Request := Request.mk' "r2" .httpOut "alice" "api.example.com"
def cert2 : Certificate := {
  steps := [{
    ruleIdx := 0,
    premises := [],
    conclusion := .precedes "a" "b"
  }],
  policyHash := emptyHash,
  graphHash := emptyHash,
  requestHash := emptyHash
}

-- 角色 admin 在 baseFacts 中，规则体满足，推导出 precedes（非 deny）→ true
#eval checkCert cert2 req2 pol2 Graph.empty [("alice", "admin")]
-- 预期: true

example : checkCert cert2 req2 pol2 Graph.empty [("alice", "admin")] = true := rfl

-- ============================================================
-- 场景 3: deny 规则匹配 → Witness 验证通过 (checkWitness = true)
-- ============================================================

-- 策略: deny("r3", "unauthorized_http") :-
--   action("r3", httpOut, "alice", "api.example.com"),
--   ¬hasRole("alice", "http_allowed")
-- 请求 alice 发起 httpOut，无 http_allowed 角色
-- Witness: matchedFacts 是 baseFacts 子集，规则体在 base ∪ matched 中满足
def denyRule3 : Rule := {
  head := .deny "r3" "unauthorized_http",
  body := [
    .pos (.action "r3" .httpOut "alice" "api.example.com"),
    .neg (.hasRole "alice" "http_allowed")
  ]
}
def pol3 : Policy := { rules := [denyRule3] }
def req3 : Request := Request.mk' "r3" .httpOut "alice" "api.example.com"
def wit3 : Witness := {
  denyRuleIdx := 0,
  matchedFacts := [.action "r3" .httpOut "alice" "api.example.com"],
  violationPaths := [],
  policyHash := emptyHash,
  requestHash := emptyHash
}

-- 与 PolicyTest 中 isAllowed = false 一致：deny 规则触发
#eval checkWitness wit3 req3 pol3 Graph.empty []
-- 预期: true

example : checkWitness wit3 req3 pol3 Graph.empty [] = true := rfl

-- ============================================================
-- 场景 4: 错误 Witness → 验证失败 (checkWitness = false)
-- ============================================================

-- 无效 witness: matchedFacts 包含不在 baseFacts 中的事实
def badWit4 : Witness := {
  denyRuleIdx := 0,
  matchedFacts := [.hasRole "alice" "nonexistent_role"],
  violationPaths := [],
  policyHash := emptyHash,
  requestHash := emptyHash
}

-- matchedFacts ⊄ baseFacts → false
#eval checkWitness badWit4 req3 pol3 Graph.empty []
-- 预期: false

example : checkWitness badWit4 req3 pol3 Graph.empty [] = false := rfl

-- ============================================================
-- 场景 5: 无效证书 → 验证失败 (checkCert = false)
-- ============================================================

-- 证书步骤引用不存在的规则索引（99），空策略无规则
def badCert5 : Certificate := {
  steps := [{
    ruleIdx := 99,
    premises := [],
    conclusion := .deny "r1" "fake"
  }],
  policyHash := emptyHash,
  graphHash := emptyHash,
  requestHash := emptyHash
}

-- pol.rules[99]? = none → checkStep = false → checkCert = false
#eval checkCert badCert5 req1 pol1 Graph.empty []
-- 预期: false

example : checkCert badCert5 req1 pol1 Graph.empty [] = false := rfl

-- ============================================================
-- 场景 6: DiffWitness (escalation) 端到端 (checkDiffCert = true)
-- ============================================================

-- 旧策略: deny httpOut for all（同 pol3）
-- 新策略: 空策略（allow all）
-- DiffKind: escalation（Deny → Allow）
-- 构造: witnessOld（旧策略 deny 有效）+ certNew（新策略 allow 有效）
def polOld6 : Policy := pol3
def polNew6 : Policy := { rules := [] }
def dw6 : DiffWitness := {
  kind := .escalation,
  request := req3,
  graph := Graph.empty,
  roles := [],
  certOld := none,
  certNew := some {
    steps := [],
    policyHash := emptyHash,
    graphHash := emptyHash,
    requestHash := emptyHash
  },
  witnessOld := some wit3,
  witnessNew := none
}

-- checkWitness wit3 req3 polOld6 ... = true ∧ checkCert emptyCert req3 polNew6 ... = true → true
#eval checkDiffCert dw6 polOld6 polNew6
-- 预期: true

example : checkDiffCert dw6 polOld6 polNew6 = true := rfl

end PCM.Cert.CheckerTest
