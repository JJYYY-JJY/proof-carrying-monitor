/-
  PCM.Spec.Diff — 策略差分语义定义
-/
import PCM.Spec.Policy

namespace PCM.Spec

/-- 差分类型 -/
inductive DiffKind where
  | escalation  -- Deny → Allow（升权）
  | breaking    -- Allow → Deny（破坏性变更）
  deriving DecidableEq, Repr

/-- DiffSpec：请求 r 在旧策略和新策略下有不同判定 -/
def DiffSpec (polOld polNew : Policy) (g : Graph)
    (roles : RoleAssignment) (r : Request) (k : DiffKind) : Prop :=
  match k with
  | .escalation =>
      ¬AllowedSpec r polOld g roles ∧ AllowedSpec r polNew g roles
  | .breaking =>
      AllowedSpec r polOld g roles ∧ ¬AllowedSpec r polNew g roles

/-- 两个策略是否语义等价 -/
def PolicyEquiv (polA polB : Policy) (g : Graph) (roles : RoleAssignment) : Prop :=
  ∀ r : Request,
    AllowedSpec r polA g roles ↔ AllowedSpec r polB g roles

end PCM.Spec
