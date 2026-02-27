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

/-- 单步推导保持已推导集的子集关系 -/
theorem oneRound_monotone (pol : Policy) (known : List Atom) :
    ∀ a ∈ known, a ∈ oneRound pol known := by
  intro a ha
  simp only [oneRound]
  apply List.mem_append_left
  exact ha

/-- fixpoint 保留初始集合中的所有元素 -/
private theorem mem_fixpoint_of_mem (pol : Policy) (fuel : Nat) :
    ∀ (known : List Atom) (a : Atom), a ∈ known → a ∈ fixpoint pol known fuel := by
  induction fuel with
  | zero =>
    intro known a ha
    exact ha
  | succ n ih =>
    intro known a ha
    show a ∈ (if (oneRound pol known).length == known.length
              then known
              else fixpoint pol (oneRound pol known) n)
    split
    · exact ha
    · exact ih _ _ (oneRound_monotone pol known a ha)

/-- 基础事实是最小模型的子集 -/
theorem baseFacts_subset_model (pol : Policy) (req : Request) (g : Graph)
    (roles : RoleAssignment) :
    ∀ a ∈ baseFacts req g roles, a ∈ minimalModel pol (baseFacts req g roles) := by
  intro a ha
  exact mem_fixpoint_of_mem pol 1000 _ _ ha

-- ============================================================
-- 定理 1: 证书 Soundness
-- ============================================================

/-- 从布尔合取式中提取右侧为 true -/
private theorem Bool.right_eq_true_of_and_eq_true
    {a b : Bool} (h : (a && b) = true) : b = true := by
  cases a <;> simp_all

/--
  **Theorem (Certificate Soundness)**:
  如果 checkCert 返回 true，则请求在语义上被允许。

  证明路线：
  checkCert = certStepsOk && isAllowed。
  由 isAllowed_iff_AllowedSpec，isAllowed = true ↔ AllowedSpec。
  提取 isAllowed = true 即得 AllowedSpec。
-/
theorem cert_soundness
    (req : Request) (pol : Policy) (g : Graph)
    (roles : RoleAssignment)
    (cert : Certificate)
    (h : checkCert cert req pol g roles = true)
    : AllowedSpec req pol g roles := by
  -- checkCert = certStepsOk && isAllowed
  unfold checkCert at h
  -- 提取 isAllowed = true
  have hIA : isAllowed req pol g roles = true :=
    Bool.right_eq_true_of_and_eq_true h
  -- 通过 isAllowed_iff_AllowedSpec 得出 AllowedSpec
  exact (isAllowed_iff_AllowedSpec req pol g roles).mp hIA

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
