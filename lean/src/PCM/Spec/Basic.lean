/-
  PCM.Spec.Basic — 基础类型定义

  定义动作类型、敏感标签、请求、图节点/边等核心数据类型。
  所有类型均推导 BEq, DecidableEq, Repr, Hashable 以支持可判定性与哈希。
-/

namespace PCM.Spec

-- 为 List 提供 Hashable 实例（Lean 4 core 不含此定义）
instance instHashableList {α : Type} [Hashable α] : Hashable (List α) where
  hash xs := xs.foldl (fun h x => mixHash h (hash x)) 7

/-- 动作类型 -/
inductive ActionType where
  | toolCall
  | httpOut
  | dbWrite
  | dbReadSensitive
  | fileWrite
  | fileRead
  | custom (tag : String)
  deriving BEq, DecidableEq, Repr, Hashable

/-- 敏感级别标签（形成全序）-/
inductive Label where
  | low
  | medium
  | high
  | critical
  deriving BEq, DecidableEq, Repr, Hashable

/-- 标签到自然数的映射（用于偏序比较）-/
def Label.toNat : Label → Nat
  | .low      => 0
  | .medium   => 1
  | .high     => 2
  | .critical => 3

instance : LE Label where
  le a b := a.toNat ≤ b.toNat

instance : LT Label where
  lt a b := a.toNat < b.toNat

instance (a b : Label) : Decidable (a ≤ b) :=
  inferInstanceAs (Decidable (a.toNat ≤ b.toNat))

instance (a b : Label) : Decidable (a < b) :=
  inferInstanceAs (Decidable (a.toNat < b.toNat))

/-- Label.toNat 单射性 -/
theorem Label.toNat_injective : ∀ a b : Label, a.toNat = b.toNat → a = b := by
  intro a b
  cases a <;> cases b <;> simp [Label.toNat]

/-- Label 全序 -/
theorem Label.le_total : ∀ a b : Label, a ≤ b ∨ b ≤ a := by
  intro a b
  show a.toNat ≤ b.toNat ∨ b.toNat ≤ a.toNat
  omega

/-- Label 反对称 -/
theorem Label.le_antisymm : ∀ a b : Label, a ≤ b → b ≤ a → a = b := by
  intro a b h1 h2
  apply Label.toNat_injective
  have h1' : a.toNat ≤ b.toNat := h1
  have h2' : b.toNat ≤ a.toNat := h2
  omega

/-- 图边类型 -/
inductive EdgeKind where
  | dataFlow
  | controlFlow
  | causal
  | temporal
  deriving BEq, DecidableEq, Repr, Hashable

/-- 图节点类型 -/
inductive NodeKind where
  | entity
  | action
  | data
  | resource
  deriving BEq, DecidableEq, Repr, Hashable

/-- 请求（动作请求） -/
structure Request where
  id        : String
  action    : ActionType
  principal : String
  target    : String
  attrs     : List (String × String)
  deriving BEq, DecidableEq, Repr, Hashable

/-- 图节点 -/
structure GNode where
  id    : String
  kind  : NodeKind
  label : Label
  deriving BEq, DecidableEq, Repr

/-- 图边 -/
structure GEdge where
  src  : String
  dst  : String
  kind : EdgeKind
  deriving BEq, DecidableEq, Repr

/-- 依赖图 -/
structure Graph where
  nodes : List GNode
  edges : List GEdge
  deriving BEq, DecidableEq, Repr

/-- 角色分配 -/
abbrev RoleAssignment := List (String × String)

/-! ### 智能构造函数 -/

/-- 创建无属性的请求 -/
def Request.mk' (id : String) (action : ActionType) (principal target : String) : Request :=
  { id, action, principal, target, attrs := [] }

/-- 空图 -/
def Graph.empty : Graph := { nodes := [], edges := [] }

/-- 向图中添加节点 -/
def Graph.addNode (g : Graph) (n : GNode) : Graph := { g with nodes := n :: g.nodes }

/-- 向图中添加边 -/
def Graph.addEdge (g : Graph) (e : GEdge) : Graph := { g with edges := e :: g.edges }

/-! ### 基础引理 -/

theorem Graph.empty_has_no_nodes : Graph.empty.nodes = [] := rfl
theorem Graph.empty_has_no_edges : Graph.empty.edges = [] := rfl

end PCM.Spec
