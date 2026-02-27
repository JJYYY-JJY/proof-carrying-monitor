import Lake
open Lake DSL

package pcm where
  leanOptions := #[
    ⟨`autoImplicit, false⟩
  ]

@[default_target]
lean_lib PCM where
  srcDir := "src"
  roots := #[`PCM]

lean_lib PCMProofs where
  srcDir := "src"
  roots := #[`PCM.Proofs]
