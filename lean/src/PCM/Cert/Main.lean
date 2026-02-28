import PCM.Cert.FFI

open PCM.Cert.FFI

def main (args : List String) : IO UInt32 := do
  match args with
  | ["--json"] =>
      let stdin ← IO.getStdin
      let input ← stdin.readToEnd
      IO.println <| renderCheckerResponse (runCheckerJson input)
      pure 0
  | _ =>
      IO.eprintln "usage: pcm_checker --json"
      pure 1
