/-
  PCM.Proofs — Soundness 定理

  核心定理：
  1. cert_soundness:    checkCert = true  → AllowedSpec
  2. witness_soundness: checkWitness = true → ¬AllowedSpec
  3. diff_witness_soundness: checkDiffCert = true → DiffSpec
-/
import PCM.Spec.Policy
import PCM.Spec.Diff
import PCM.Cert.Certificate
import PCM.Cert.Checker

namespace PCM.Proofs

open PCM.Spec PCM.Cert

-- ============================================================
-- 辅助引理
-- ============================================================

/-- 基础事实是最小模型的子集 -/
theorem baseFacts_subset_model (pol : Policy) (req : Request) (g : Graph)
    (roles : RoleAssignment) :
    ∀ a ∈ baseFacts req g roles, a ∈ minimalModel pol (baseFacts req g roles) := by
  intro a ha
  -- minimalModel 从 baseFacts 开始迭代，基础事实一定保留
  sorry

/-- 单步推导保持已推导集的子集关系 -/
theorem oneRound_monotone (pol : Policy) (known : List Atom) :
    ∀ a ∈ known, a ∈ oneRound pol known := by
  sorry

-- ============================================================
-- 定理 1: 证书 Soundness
-- ============================================================

/--
  **Theorem (Certificate Soundness)**:
  如果 checkCert 返回 true，则请求在语义上被允许。

  证明路线：
  1. checkCert = true → 所有推导步骤合法
  2. 由步骤合法性，归纳证明 derived ⊆ minimalModel
  3. derived 中不含 deny(req.id, _)
  4. 需要证明：checkCert 验证了所有可能的 deny 规则不可触发
  5. 由 Datalog 最小模型的完备性，minimalModel 中也不含 deny
  6. 即 AllowedSpec 成立
-/
theorem cert_soundness
    (req : Request) (pol : Policy) (g : Graph)
    (roles : RoleAssignment)
    (cert : Certificate)
    (h : checkCert cert req pol g roles = true)
    : AllowedSpec req pol g roles := by
  sorry

-- ============================================================
-- 定理 2: Witness Soundness
-- ============================================================

/--
  **Theorem (Witness Soundness)**:
  如果 checkWitness 返回 true，则请求在语义上被拒绝。

  证明路线：
  1. checkWitness = true → ∃ deny 规则 r，matchedFacts 满足其体部
  2. matchedFacts ⊆ baseFacts
  3. 由 Datalog 语义，deny(req.id, reason) ∈ minimalModel
  4. ¬AllowedSpec
-/
theorem witness_soundness
    (req : Request) (pol : Policy) (g : Graph)
    (roles : RoleAssignment)
    (w : Witness)
    (h : checkWitness w req pol g roles = true)
    : ¬AllowedSpec req pol g roles := by
  sorry

-- ============================================================
-- 定理 3: Diff Witness Soundness
-- ============================================================

/--
  **Theorem (Diff Witness Soundness)**:
  如果 checkDiffCert 返回 true，则旧策略和新策略对该请求给出不同判定。

  证明：组合 cert_soundness 和 witness_soundness。
-/
theorem diff_witness_soundness
    (polOld polNew : Policy) (g : Graph)
    (roles : RoleAssignment)
    (dw : DiffWitness)
    (h : checkDiffCert dw polOld polNew = true)
    : DiffSpec polOld polNew g roles dw.request dw.kind := by
  sorry

end PCM.Proofs
