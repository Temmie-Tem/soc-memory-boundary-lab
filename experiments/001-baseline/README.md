# Experiment 001 — Baseline Read-Only Snapshot

Result: `PROVED` successful once. See
`../../evidence/manifests/001-baseline-live-20260825-01.manifest.json` and
`../../docs/EXPERIMENT_MATRIX.md`.

The raw snapshot is intentionally Git-ignored. The collector performed only its
compiled `version`, `cat`, and `ls` allowlist through the target-pinned bridge.
