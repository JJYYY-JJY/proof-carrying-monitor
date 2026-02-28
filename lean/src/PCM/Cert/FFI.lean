import Lean.Data.Json
import Lean.Data.Json.FromToJson
import PCM.Cert.Checker

namespace PCM.Cert.FFI

open Lean
open PCM.Spec
open PCM.Cert

instance : FromJson ByteArray where
  fromJson? j := do
    let bytes : List Nat ← fromJson? j
    bytes.foldlM (init := ByteArray.empty) fun acc n => do
      if n < 256 then
        pure <| acc.push (UInt8.ofNat n)
      else
        throw s!"byte out of range: {n}"

deriving instance FromJson for ActionType, Label, EdgeKind, NodeKind
deriving instance FromJson for Request, GNode, GEdge, Graph
deriving instance FromJson for Atom, Literal, Rule, Policy
deriving instance FromJson for DerivStep, Certificate, Witness

structure CheckerRequest where
  mode : String
  certificate : Option Certificate
  witness : Option Witness
  request : Request
  policy : Policy
  graph : Graph
  roles : RoleAssignment
  expectedPolicyHash : ByteArray
  expectedGraphHash : Option ByteArray
  expectedRequestHash : ByteArray
  deriving FromJson

structure CheckerResponse where
  valid : Bool
  error : Option String
  deriving ToJson

private def parseRequest (input : String) : Except String CheckerRequest := do
  let payload ← Json.parse input
  fromJson? (α := CheckerRequest) payload

private def renderError (msg : String) : CheckerResponse :=
  { valid := false, error := some msg }

private def ensureHashEq (actual expected : ByteArray) (label : String) : Except String Unit :=
  if actual == expected then
    pure ()
  else
    throw s!"{label} mismatch"

private def runCertCheck (req : CheckerRequest) : Except String Bool := do
  let some cert := req.certificate
    | throw "missing certificate payload"
  let some expectedGraphHash := req.expectedGraphHash
    | throw "missing expectedGraphHash"
  ensureHashEq cert.policyHash req.expectedPolicyHash "policy hash"
  ensureHashEq cert.graphHash expectedGraphHash "graph hash"
  ensureHashEq cert.requestHash req.expectedRequestHash "request hash"
  pure <| checkCert cert req.request req.policy req.graph req.roles

private def runWitnessCheck (req : CheckerRequest) : Except String Bool := do
  let some witness := req.witness
    | throw "missing witness payload"
  ensureHashEq witness.policyHash req.expectedPolicyHash "policy hash"
  ensureHashEq witness.requestHash req.expectedRequestHash "request hash"
  pure <| checkWitness witness req.request req.policy req.graph req.roles

private def execute (req : CheckerRequest) : Except String Bool :=
  match req.mode with
  | "cert" => runCertCheck req
  | "witness" => runWitnessCheck req
  | other => throw s!"unsupported mode: {other}"

def runCheckerJson (input : String) : CheckerResponse :=
  match parseRequest input with
  | .error err => renderError err
  | .ok req =>
    match execute req with
    | .ok valid => { valid, error := none }
    | .error err => renderError err

def renderCheckerResponse (resp : CheckerResponse) : String :=
  toString (toJson resp)

@[export lean_check_cert_ffi]
def checkCertFFI (input : String) : UInt8 :=
  match parseRequest input with
  | .error _ => 0
  | .ok req =>
    match req.mode, runCertCheck req with
    | "cert", .ok true => 1
    | _, _ => 0

@[export lean_check_witness_ffi]
def checkWitnessFFI (input : String) : UInt8 :=
  match parseRequest input with
  | .error _ => 0
  | .ok req =>
    match req.mode, runWitnessCheck req with
    | "witness", .ok true => 1
    | _, _ => 0

end PCM.Cert.FFI
