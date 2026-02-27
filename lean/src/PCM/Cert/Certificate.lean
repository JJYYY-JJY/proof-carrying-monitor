/-
  PCM.Cert.Certificate — 证书与反例数据结构
-/
import PCM.Spec.Basic
import PCM.Spec.Diff

namespace PCM.Cert

open PCM.Spec

-- ByteArray 在 Lean 4 中无内置 Repr，派生之
deriving instance Repr for ByteArray

/-- 推导步骤 -/
structure DerivStep where
  ruleIdx    : Nat
  premises   : List Nat          -- 前提在已推导列表中的索引
  conclusion : Atom
  deriving DecidableEq, Repr

/-- Allow 证书（推导树序列化） -/
structure Certificate where
  steps       : List DerivStep
  policyHash  : ByteArray
  graphHash   : ByteArray
  requestHash : ByteArray
  deriving Repr

/-- Deny 反例 -/
structure Witness where
  denyRuleIdx     : Nat
  matchedFacts    : List Atom
  violationPaths  : List (List (String × String))
  policyHash      : ByteArray
  requestHash     : ByteArray
  deriving Repr

/-- Diff 反例 -/
structure DiffWitness where
  kind        : DiffKind
  request     : Request
  graph       : Graph
  roles       : RoleAssignment
  -- 升权: witnessOld + certNew；破坏性: certOld + witnessNew
  certOld     : Option Certificate
  certNew     : Option Certificate
  witnessOld  : Option Witness
  witnessNew  : Option Witness
  deriving Repr

end PCM.Cert
