/-
  PCM.Spec.Policy — 策略语义定义

  定义 Datalog 规则、策略、基础事实推导、最小模型语义以及 AllowedSpec。
-/
import PCM.Spec.Basic

namespace PCM.Spec

/-- 原子事实 -/
inductive Atom where
  | action (id : String) (ty : ActionType) (princ : String) (tgt : String)
  | dataLabel (data : String) (l : Label)
  | hasRole (princ : String) (role : String)
  | graphEdge (src dst : String) (kind : EdgeKind)
  | graphLabel (node : String) (l : Label)
  | precedes (a b : String)
  | deny (req : String) (reason : String)
  deriving DecidableEq, BEq, Repr, Hashable

/-- 规则体文字（正或负） -/
inductive Literal where
  | pos (a : Atom)
  | neg (a : Atom)
  deriving DecidableEq, BEq, Repr, Hashable

/-- Datalog 规则（Horn 子句） -/
structure Rule where
  head : Atom
  body : List Literal
  deriving DecidableEq, BEq, Repr, Hashable

/-- 策略 = 有序规则列表 -/
structure Policy where
  rules : List Rule
  deriving DecidableEq, BEq, Repr, Hashable

/-- 从请求和图推导基础事实集合 -/
def baseFacts (req : Request) (g : Graph) (roles : RoleAssignment) : List Atom :=
  -- 请求自身
  [Atom.action req.id req.action req.principal req.target]
  -- 角色分配
  ++ roles.map (fun ⟨p, r⟩ => Atom.hasRole p r)
  -- 图边 → graphEdge 事实
  ++ g.edges.map (fun e => Atom.graphEdge e.src e.dst e.kind)
  -- 图节点标签 → graphLabel 事实
  ++ g.nodes.map (fun n => Atom.graphLabel n.id n.label)

/-- 请求的 action 事实一定在 baseFacts 中 -/
theorem action_in_baseFacts (req : Request) (g : Graph) (roles : RoleAssignment) :
    Atom.action req.id req.action req.principal req.target ∈ baseFacts req g roles := by
  simp [baseFacts]

/-- 角色分配中的事实一定在 baseFacts 中 -/
theorem role_in_baseFacts (req : Request) (g : Graph) (roles : RoleAssignment)
    (p r : String) (h : (p, r) ∈ roles) :
    Atom.hasRole p r ∈ baseFacts req g roles := by
  have hRole :
      Atom.hasRole p r ∈ roles.map (fun pr => Atom.hasRole pr.1 pr.2) := by
    exact List.mem_map_of_mem (f := fun pr => Atom.hasRole pr.1 pr.2) h
  simp [baseFacts, hRole]

/-- 图边事实一定在 baseFacts 中 -/
theorem edge_in_baseFacts (req : Request) (g : Graph) (roles : RoleAssignment)
    (e : GEdge) (h : e ∈ g.edges) :
    Atom.graphEdge e.src e.dst e.kind ∈ baseFacts req g roles := by
  have hEdge :
      Atom.graphEdge e.src e.dst e.kind
        ∈ g.edges.map (fun e' => Atom.graphEdge e'.src e'.dst e'.kind) := by
    exact List.mem_map_of_mem (f := fun e' => Atom.graphEdge e'.src e'.dst e'.kind) h
  simp [baseFacts, hEdge]

/-- 图节点标签事实一定在 baseFacts 中 -/
theorem label_in_baseFacts (req : Request) (g : Graph) (roles : RoleAssignment)
    (n : GNode) (h : n ∈ g.nodes) :
    Atom.graphLabel n.id n.label ∈ baseFacts req g roles := by
  have hLabel :
      Atom.graphLabel n.id n.label
        ∈ g.nodes.map (fun n' => Atom.graphLabel n'.id n'.label) := by
    exact List.mem_map_of_mem (f := fun n' => Atom.graphLabel n'.id n'.label) h
  simp [baseFacts, hLabel]

/-- baseFacts 中的每个事实都来自 action / role / edge / label 之一 -/
theorem baseFacts_classification (req : Request) (g : Graph) (roles : RoleAssignment)
    (a : Atom) (h : a ∈ baseFacts req g roles) :
    (a = Atom.action req.id req.action req.principal req.target) ∨
    (∃ p r, (p, r) ∈ roles ∧ a = Atom.hasRole p r) ∨
    (∃ e ∈ g.edges, a = Atom.graphEdge e.src e.dst e.kind) ∨
    (∃ n ∈ g.nodes, a = Atom.graphLabel n.id n.label) := by
  have hGrouped :
      a ∈ (([Atom.action req.id req.action req.principal req.target]
        ++ roles.map (fun pr => Atom.hasRole pr.1 pr.2))
        ++ (g.edges.map (fun e => Atom.graphEdge e.src e.dst e.kind)
        ++ g.nodes.map (fun n => Atom.graphLabel n.id n.label))) := by
    simpa [baseFacts, List.append_assoc] using h
  rcases List.mem_append.mp hGrouped with hLeft | hRight
  · rcases List.mem_append.mp hLeft with hAct | hRole
    · exact Or.inl (by simpa using hAct)
    · rcases List.mem_map.mp hRole with ⟨pr, hpr, hEq⟩
      exact Or.inr <| Or.inl <| ⟨pr.1, pr.2, hpr, hEq.symm⟩
  · rcases List.mem_append.mp hRight with hEdge | hLabel
    · rcases List.mem_map.mp hEdge with ⟨e, he, hEq⟩
      exact Or.inr <| Or.inr <| Or.inl <| ⟨e, he, hEq.symm⟩
    · rcases List.mem_map.mp hLabel with ⟨n, hn, hEq⟩
      exact Or.inr <| Or.inr <| Or.inr <| ⟨n, hn, hEq.symm⟩

/-- baseFacts 不包含任何 deny 原子 -/
theorem baseFacts_no_deny (req : Request) (g : Graph) (roles : RoleAssignment) :
    ∀ a ∈ baseFacts req g roles, ∀ rid reason, a ≠ Atom.deny rid reason := by
  intro a ha rid reason
  rcases baseFacts_classification req g roles a ha with hAct | hRest
  · subst hAct
    simp
  · rcases hRest with hRole | hRest
    · rcases hRole with ⟨p, r, _, hEq⟩
      subst hEq
      simp
    · rcases hRest with hEdge | hLabel
      · rcases hEdge with ⟨e, _, hEq⟩
        subst hEq
        simp
      · rcases hLabel with ⟨n, _, hEq⟩
        subst hEq
        simp

/-- 单步规则应用：给定已知事实集，尝试推导新事实 -/
def applyRule (known : List Atom) (r : Rule) : Option Atom :=
  let bodyOk := r.body.all fun lit =>
    match lit with
    | .pos a => known.contains a
    | .neg a => !(known.contains a)
  if bodyOk then some r.head else none

/-- 一轮推导：对所有规则做一次前向应用 -/
def oneRound (pol : Policy) (known : List Atom) : List Atom :=
  let newFacts := pol.rules.filterMap (applyRule known)
  -- 去重合并
  known ++ newFacts.filter (fun a => !(known.contains a))

/-- 不动点迭代（带最大步数限制以保证终止性） -/
def fixpoint (pol : Policy) (known : List Atom) (fuel : Nat := 1000) : List Atom :=
  match fuel with
  | 0 => known
  | fuel' + 1 =>
    let next := oneRound pol known
    if next.length == known.length then known
    else fixpoint pol next fuel'

/-- Datalog 最小模型 -/
def minimalModel (pol : Policy) (base : List Atom) : List Atom :=
  fixpoint pol base

/-- AllowedSpec：策略 + 图 + 角色下，请求被允许当且仅当最小模型中不含 deny -/
def AllowedSpec (req : Request) (pol : Policy) (g : Graph)
    (roles : RoleAssignment) : Prop :=
  let model := minimalModel pol (baseFacts req g roles)
  ∀ reason : String, Atom.deny req.id reason ∉ model

/-- 可判定版本的 AllowedSpec（用于可执行检查） -/
def isAllowed (req : Request) (pol : Policy) (g : Graph)
    (roles : RoleAssignment) : Bool :=
  let model := minimalModel pol (baseFacts req g roles)
  model.all fun a =>
    match a with
    | .deny rid _ => rid != req.id
    | _ => true

private theorem all_nonDeny_iff (reqId : String) (model : List Atom) :
    (∀ a ∈ model,
        (match a with
        | .deny rid _ => rid != reqId
        | _ => true) = true) ↔
    ∀ reason : String, Atom.deny reqId reason ∉ model := by
  constructor
  · intro hAll reason hMem
    have hPred := hAll (Atom.deny reqId reason) hMem
    simp at hPred
  · intro hNoDeny a hMem
    cases a with
    | action id ty princ tgt =>
        rfl
    | dataLabel data l =>
        rfl
    | hasRole princ role =>
        rfl
    | graphEdge src dst kind =>
        rfl
    | graphLabel node l =>
        rfl
    | precedes a b =>
        rfl
    | deny rid reason =>
        by_cases hRid : rid = reqId
        · subst hRid
          exact False.elim (hNoDeny reason hMem)
        · exact bne_iff_ne.mpr hRid

/-- isAllowed = true ↔ AllowedSpec -/
theorem isAllowed_iff_AllowedSpec (req : Request) (pol : Policy) (g : Graph)
    (roles : RoleAssignment) :
    isAllowed req pol g roles = true ↔ AllowedSpec req pol g roles := by
  simp only [isAllowed, AllowedSpec, List.all_eq_true]
  exact all_nonDeny_iff req.id (minimalModel pol (baseFacts req g roles))

end PCM.Spec
