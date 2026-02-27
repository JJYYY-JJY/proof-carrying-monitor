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

end PCM.Spec
