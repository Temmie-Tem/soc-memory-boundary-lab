# Experiment 003 — Controller Candidates

State: static inventory complete; live register read `UNKNOWN`.

Only source/firmware-backed ranges and widths are eligible. Blind MMIO scanning
is forbidden because an otherwise read-only access may still cause an external
abort or wedge. Candidate ranking is in
`../../research/sm8150-memory-subsystem.md`.
