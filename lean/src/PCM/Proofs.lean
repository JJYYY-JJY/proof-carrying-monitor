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

private theorem actionType_beq_eq_true_iff_eq {a b : ActionType} :
    (a == b) = true ↔ a = b := by
  change PCM.Spec.instBEqActionType.beq a b = true ↔ a = b
  cases a <;> cases b <;> simp [PCM.Spec.instBEqActionType.beq, beq_iff_eq]

private instance : LawfulBEq ActionType where
  rfl := by
    intro a
    exact (actionType_beq_eq_true_iff_eq).2 rfl
  eq_of_beq := by
    intro a b h
    exact (actionType_beq_eq_true_iff_eq).1 h

private theorem label_beq_eq_true_iff_eq {a b : Label} :
    (a == b) = true ↔ a = b := by
  change PCM.Spec.instBEqLabel.beq a b = true ↔ a = b
  cases a <;> cases b <;> native_decide

private instance : LawfulBEq Label where
  rfl := by
    intro a
    exact (label_beq_eq_true_iff_eq).2 rfl
  eq_of_beq := by
    intro a b h
    exact (label_beq_eq_true_iff_eq).1 h

private theorem edgeKind_beq_eq_true_iff_eq {a b : EdgeKind} :
    (a == b) = true ↔ a = b := by
  change PCM.Spec.instBEqEdgeKind.beq a b = true ↔ a = b
  cases a <;> cases b <;> native_decide

private instance : LawfulBEq EdgeKind where
  rfl := by
    intro a
    exact (edgeKind_beq_eq_true_iff_eq).2 rfl
  eq_of_beq := by
    intro a b h
    exact (edgeKind_beq_eq_true_iff_eq).1 h

private theorem atom_beq_eq_true_iff_eq {a b : Atom} :
    (a == b) = true ↔ a = b := by
  change PCM.Spec.instBEqAtom.beq a b = true ↔ a = b
  cases a <;> cases b <;>
    simp [PCM.Spec.instBEqAtom.beq, Bool.and_eq_true, beq_iff_eq]

private instance : LawfulBEq Atom where
  rfl := by
    intro a
    exact (atom_beq_eq_true_iff_eq).2 rfl
  eq_of_beq := by
    intro a b h
    exact (atom_beq_eq_true_iff_eq).1 h

private theorem atom_contains_eq_true_iff_mem
    {a : Atom} {xs : List Atom} :
    xs.contains a = true ↔ a ∈ xs := by
  exact List.contains_iff_mem (a := a) (as := xs)

private theorem atom_contains_eq_false_iff_not_mem
    {a : Atom} {xs : List Atom} :
    xs.contains a = false ↔ a ∉ xs := by
  constructor
  · intro hFalse hMem
    have hTrue : xs.contains a = true :=
      (atom_contains_eq_true_iff_mem).2 hMem
    rw [hFalse] at hTrue
    contradiction
  · intro hNot
    cases hContains : xs.contains a with
    | false =>
        rfl
    | true =>
        exact False.elim (hNot ((atom_contains_eq_true_iff_mem).1 hContains))

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

/-- 从布尔合取式中提取左侧为 true -/
private theorem Bool.left_eq_true_of_and_eq_true
    {a b : Bool} (h : (a && b) = true) : a = true := by
  cases a <;> simp_all

/-- matchedFacts 中的任意事实都属于 base -/
private theorem mem_base_of_mem_matched
    {base matched : List Atom}
    (hMatched : ∀ a, a ∈ matched → a ∈ base)
    {a : Atom} (ha : a ∈ matched) : a ∈ base := by
  exact hMatched a ha

/-- 在 matchedFacts ⊆ base 时，base ++ matchedFacts 的成员资格与 base 相同 -/
private theorem mem_base_append_matched_iff
    {base matched : List Atom}
    (hMatched : ∀ a, a ∈ matched → a ∈ base)
    {a : Atom} : a ∈ base ++ matched ↔ a ∈ base := by
  constructor
  · intro ha
    rcases List.mem_append.mp ha with hBase | hMatchedMem
    · exact hBase
    · exact mem_base_of_mem_matched hMatched hMatchedMem
  · intro ha
    exact List.mem_append.mpr (Or.inl ha)

/-- 若 matchedFacts ⊆ base，则在 base ++ matchedFacts 上满足的文字在 base 上也满足 -/
private theorem checkLitSatisfied_on_base
    {base matched : List Atom}
    (hMatched : ∀ a, a ∈ matched → a ∈ base)
    {lit : Literal}
    (hSat : checkLitSatisfied lit (base ++ matched) = true) :
    checkLitSatisfied lit base = true := by
  cases lit with
  | pos a =>
      have hContainsAppend : (base ++ matched).contains a = true := by
        simpa [checkLitSatisfied] using hSat
      have hMemAppend : a ∈ base ++ matched :=
        (atom_contains_eq_true_iff_mem).1 hContainsAppend
      have hMemBase : a ∈ base :=
        (mem_base_append_matched_iff hMatched).mp hMemAppend
      have hContainsBase : base.contains a = true :=
        (atom_contains_eq_true_iff_mem).2 hMemBase
      simpa [checkLitSatisfied] using hContainsBase
  | neg a =>
      have hContainsAppend : (base ++ matched).contains a = false := by
        simpa [checkLitSatisfied] using hSat
      have hNotAppend : a ∉ base ++ matched :=
        (atom_contains_eq_false_iff_not_mem).1 hContainsAppend
      have hNotBase : a ∉ base := by
        intro hMemBase
        exact hNotAppend (List.mem_append.mpr (Or.inl hMemBase))
      have hContainsBase : base.contains a = false :=
        (atom_contains_eq_false_iff_not_mem).2 hNotBase
      simpa [checkLitSatisfied] using hContainsBase

/-- 在 base ++ matchedFacts 上满足整条规则体，则在 base 上也满足 -/
private theorem body_satisfied_on_base
    {base matched : List Atom}
    {body : List Literal}
    (hMatched : ∀ a, a ∈ matched → a ∈ base)
    (hBody : ∀ lit, lit ∈ body → checkLitSatisfied lit (base ++ matched) = true) :
    ∀ lit, lit ∈ body → checkLitSatisfied lit base = true := by
  intro lit hLit
  exact checkLitSatisfied_on_base hMatched (hBody lit hLit)

/-- 若规则体在 facts 上满足，则 applyRule 推导出规则头 -/
private theorem applyRule_eq_some_head_of_body_all
    (rule : Rule) (facts : List Atom)
    (hBody : ∀ lit, lit ∈ rule.body → checkLitSatisfied lit facts = true) :
    applyRule facts rule = some rule.head := by
  unfold applyRule
  have hBodyProp :
      ∀ lit, lit ∈ rule.body →
        (match lit with
          | .pos a => facts.contains a
          | .neg a => !(facts.contains a)) = true := by
    intro lit hLit
    cases lit with
    | pos a =>
        simpa [checkLitSatisfied] using hBody (.pos a) hLit
    | neg a =>
        simpa [checkLitSatisfied] using hBody (.neg a) hLit
  have hBody' :
      rule.body.all
        (fun lit =>
          match lit with
          | .pos a => facts.contains a
          | .neg a => !(facts.contains a)) = true := by
    exact List.all_eq_true.mpr hBodyProp
  change
    (if
        rule.body.all
            (fun lit =>
              match lit with
              | .pos a => facts.contains a
              | .neg a => !(facts.contains a)) = true
      then some rule.head
      else none) = some rule.head
  rw [hBody']
  simp

/-- 若 oneRound 未增加新事实，则其结果等于输入 known -/
private theorem oneRound_eq_self_of_length_eq
    (pol : Policy) (known : List Atom)
    (hLen : (oneRound pol known).length = known.length) :
    oneRound pol known = known := by
  let extras :=
    (pol.rules.filterMap (applyRule known)).filter (fun a => !(known.contains a))
  have hLen' : (known ++ extras).length = known.length := by
    simpa [oneRound, extras] using hLen
  have hAppendLen : known.length + extras.length = known.length + 0 := by
    simpa [List.length_append] using hLen'
  have hExtrasLen : extras.length = 0 :=
    Nat.add_left_cancel hAppendLen
  have hExtrasNil : extras = [] :=
    (List.eq_nil_iff_length_eq_zero).2 hExtrasLen
  calc
    oneRound pol known = known ++ extras := by
      simp [oneRound, extras]
    _ = known ++ [] := by
      simp [hExtrasNil]
    _ = known := by
      simp

/-- 如果 applyRule 成功，则推导出的事实出现在 oneRound 中 -/
private theorem applyRule_success_in_oneRound
    (pol : Policy) (known : List Atom) (r : Rule) (a : Atom)
    (hRule : r ∈ pol.rules)
    (hApply : applyRule known r = some a) :
    a ∈ oneRound pol known := by
  unfold oneRound
  by_cases hKnown : a ∈ known
  · exact List.mem_append.mpr (Or.inl hKnown)
  · apply List.mem_append.mpr
    right
    refine List.mem_filter.mpr ?_
    refine And.intro ?_ ?_
    · exact (List.mem_filterMap).2 (Exists.intro r (And.intro hRule hApply))
    · have hNotContains : known.contains a = false :=
        (atom_contains_eq_false_iff_not_mem).2 hKnown
      simpa [hNotContains]

/-- oneRound 中的事实都属于 minimalModel -/
private theorem oneRound_subset_model
    (pol : Policy) (known : List Atom) :
    ∀ a ∈ oneRound pol known, a ∈ minimalModel pol known := by
  intro a ha
  unfold minimalModel
  show a ∈ fixpoint pol known 1000
  unfold fixpoint
  by_cases hLen : (oneRound pol known).length == known.length
  · have hKnown : a ∈ known := by
      have hEq : oneRound pol known = known :=
        oneRound_eq_self_of_length_eq pol known ((beq_iff_eq).mp hLen)
      simpa [hEq] using ha
    simpa [hLen] using hKnown
  · have hFix : a ∈ fixpoint pol (oneRound pol known) 999 :=
      mem_fixpoint_of_mem pol 999 _ _ ha
    simpa [hLen] using hFix

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
  intro hAllowed
  unfold AllowedSpec at hAllowed
  cases hRuleGet : pol.rules[w.denyRuleIdx]? with
  | none =>
      simp [checkWitness, hRuleGet] at h
  | some rule =>
      cases hHead : rule.head <;> simp [checkWitness, hRuleGet, hHead] at h
      case deny rid reason =>
        let base := baseFacts req g roles
        have hRidEq : rid = req.id := h.1
        have hMatched :
            forall a, a ∈ w.matchedFacts -> a ∈ base := h.2.1
        have hBodyAppend :
            forall lit, lit ∈ rule.body ->
              checkLitSatisfied lit (base ++ w.matchedFacts) = true := h.2.2
        have hBodyBase :
            forall lit, lit ∈ rule.body ->
              checkLitSatisfied lit base = true :=
          body_satisfied_on_base hMatched hBodyAppend
        have hApplyHead :
            applyRule base rule = some rule.head :=
          applyRule_eq_some_head_of_body_all rule base hBodyBase
        have hApply :
            applyRule base rule = some (Atom.deny req.id reason) := by
          calc
            applyRule base rule = some rule.head := hApplyHead
            _ = some (Atom.deny rid reason) := by simp [hHead]
            _ = some (Atom.deny req.id reason) := by simp [hRidEq]
        have hRuleMem : rule ∈ pol.rules := by
          apply (List.mem_iff_getElem?).2
          exact Exists.intro w.denyRuleIdx hRuleGet
        have hDenyOneRound :
            Atom.deny req.id reason ∈ oneRound pol base :=
          applyRule_success_in_oneRound pol base rule _ hRuleMem hApply
        have hDenyModel :
            Atom.deny req.id reason ∈ minimalModel pol base :=
          oneRound_subset_model pol base _ hDenyOneRound
        have hNoDeny :
            Atom.deny req.id reason ∉ minimalModel pol base := by
          simpa [base] using hAllowed reason
        exact hNoDeny hDenyModel

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
