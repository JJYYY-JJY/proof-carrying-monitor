/-
  PCM.Spec.BasicTest — Basic 类型的测试与示例
-/
import PCM.Spec.Basic

namespace PCM.Spec.BasicTest

open PCM.Spec

-- ============================================================
-- #eval 验证类型可实例化
-- ============================================================

#eval ActionType.httpOut
#eval ActionType.custom "myAction"
#eval Label.low
#eval Label.critical
#eval EdgeKind.dataFlow
#eval NodeKind.entity

#eval Request.mk' "r1" .httpOut "alice" "api.example.com"
#eval Graph.empty
#eval Graph.addNode Graph.empty { id := "n1", kind := .entity, label := .high }

-- ============================================================
-- #check 验证关键定理类型正确
-- ============================================================

#check @Label.toNat_injective
#check @Label.le_total
#check @Label.le_antisymm
#check @Graph.empty_has_no_nodes
#check @Graph.empty_has_no_edges

-- ============================================================
-- example 证明简单等式
-- ============================================================

/-- 空图没有节点 -/
example : Graph.empty.nodes = [] := rfl

/-- 空图没有边 -/
example : Graph.empty.edges = [] := rfl

/-- Label.toNat 对 low 返回 0 -/
example : Label.toNat Label.low = 0 := rfl

/-- Label.toNat 对 critical 返回 3 -/
example : Label.toNat Label.critical = 3 := rfl

/-- low ≤ high -/
example : Label.low ≤ Label.high := by decide

/-- Request.mk' 构造函数生成空属性列表 -/
example : (Request.mk' "r1" .httpOut "alice" "target").attrs = [] := rfl

/-- Graph.addNode 将节点添加到列表头部 -/
example :
  let n : GNode := { id := "n1", kind := .entity, label := .low }
  (Graph.addNode Graph.empty n).nodes = [n] := rfl

/-- ActionType.httpOut 的 BEq 自反性 -/
example : (ActionType.httpOut == ActionType.httpOut) = true := rfl

/-- Label 全序：low ≤ medium -/
example : Label.low ≤ Label.medium := by decide

end PCM.Spec.BasicTest
