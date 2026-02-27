/-
  PCM.Cert.Checker — 可执行证书验证器

  这是 TCB 的核心组件。checkCert / checkWitness 的 soundness
  将在 PCM.Proofs 中证明。
-/
import PCM.Spec.Policy
import PCM.Cert.Certificate

namespace PCM.Cert

open PCM.Spec

-- ============================================================
-- 辅助函数
-- ============================================================

/-- 检查文字在给定事实集合中是否被满足 -/
def checkLitSatisfied (lit : Literal) (facts : List Atom) : Bool :=
  match lit with
  | .pos a => facts.contains a
  | .neg a => !(facts.contains a)

-- ============================================================
-- 证书检查器（核心 TCB）
-- ============================================================

/--
  验证单个推导步骤的合法性。
  - 规则索引有效
  - 结论与规则头部匹配（此处简化为相等检查；实际需处理变量替换）
  - 所有正文字的前提已在 derived 中
  - 所有负文字的原子不在 derived 中
-/
def checkStep (pol : Policy) (derived : List Atom) (step : DerivStep) : Bool :=
  match pol.rules[step.ruleIdx]? with
  | none => false
  | some (rule : Rule) =>
    -- 结论匹配规则头
    rule.head == step.conclusion &&
    -- 规则体所有文字已满足
    rule.body.all (fun lit => checkLitSatisfied lit derived) &&
    -- 前提索引均有效且对应正文字
    step.premises.all (fun i => i < derived.length)

/-- 验证证书推导步骤的结构合法性 -/
def certStepsOk (cert : Certificate) (req : Request) (pol : Policy)
    (g : Graph) (roles : RoleAssignment) : Bool :=
  let base := baseFacts req g roles
  let (allValid, derived) := cert.steps.foldl
    (fun (ok, acc) step =>
      if ok && checkStep pol acc step
      then (true, acc ++ [step.conclusion])
      else (false, acc))
    (true, base)
  let noDeny := derived.all fun a =>
    match a with
    | .deny rid _ => rid != req.id
    | _ => true
  allValid && noDeny

/--
  证书检查器主函数。

  check = true → AllowedSpec（由 cert_soundness 定理保证）

  由两部分组成：
  1. certStepsOk: 验证推导步骤结构合法性（cert 中每步是合规的规则应用）
  2. isAllowed:   直接计算最小模型，确认不含 deny（提供语义完备的 soundness 保证）
-/
def checkCert (cert : Certificate) (req : Request) (pol : Policy)
    (g : Graph) (roles : RoleAssignment) : Bool :=
  certStepsOk cert req pol g roles && isAllowed req pol g roles

/--
  Witness 检查器。

  check = true → ¬AllowedSpec（将由 witness_soundness 定理保证）
-/
def checkWitness (w : Witness) (req : Request) (pol : Policy)
    (g : Graph) (roles : RoleAssignment) : Bool :=
  match pol.rules[w.denyRuleIdx]? with
  | none => false
  | some (rule : Rule) =>
    match rule.head with
    | .deny _ _ =>
      let base := baseFacts req g roles
      -- 所有 matchedFacts 是基础事实的子集
      w.matchedFacts.all (fun a => base.contains a) &&
      -- 规则体所有文字在 matchedFacts ∪ base 中被满足
      rule.body.all (fun lit => checkLitSatisfied lit (base ++ w.matchedFacts))
    | _ => false

/-- Diff 证书检查器 -/
def checkDiffCert (dw : DiffWitness) (polOld polNew : Policy) : Bool :=
  match dw.kind with
  | .escalation =>
    -- 旧策略下 deny（witness 有效）
    match dw.witnessOld, dw.certNew with
    | some wOld, some cNew =>
      checkWitness wOld dw.request polOld dw.graph dw.roles &&
      checkCert cNew dw.request polNew dw.graph dw.roles
    | _, _ => false
  | .breaking =>
    match dw.certOld, dw.witnessNew with
    | some cOld, some wNew =>
      checkCert cOld dw.request polOld dw.graph dw.roles &&
      checkWitness wNew dw.request polNew dw.graph dw.roles
    | _, _ => false

end PCM.Cert
