# Verification 019 suspend/permutation integration review — 2026-08-27

## Boundary and exact artifact

This integration imports the public artifact from external commit `96f8d4c`
as additive evidence.  No device command was issued by this integration, and
the external worktree's private suspend receipt is not present in this
repository.  The public manifest is therefore not promoted to a fresh
machine-proved live receipt here.

The retained public manifest is 657 bytes, mode `0644`, SHA-256
`bf7c66c78993b24d02a46735abb77e7e40298d6230bc5438c3eb21028c51238b`.
It reports a synthetic positive/negative control and an external run summary:
4,194,304 tags at 64-byte stride, 25.09 seconds, RPMh/suspend corroboration
reported by the producer, and zero moved tags.

## Validation

The imported analyzer's host-only suite is 23/23 PASS.  Python byte-compilation
passes, the two C probes pass cross-compiler syntax validation, and the
synthetic control detects injected permutations at bits 6, 7, 11 and 12 while
the injective control remains `MAP_INVARIANT`.  Gate negatives refuse an
admissible null when the baseline, suspend interval, statistics corroboration,
or summary is missing.  No private path or raw transcript is present in the
public manifest.

The imported implementation/artifact hashes are:

| Artifact | SHA-256 |
|---|---|
| `tools/a90_suspend_permutation_analysis.py` | `1fb8996f00b69aaf1dd2690b3d8e96043e54ea35b4fae2ebd48de47e3e4f7df1` |
| `tests/test_a90_suspend_permutation_analysis.py` | `2c72e6e16ab91e0c4e7a15bafb3e792feb71f274fd418edcd19b7548d167655a` |
| `tools/a90_suspend_permute_probe.c` | `b8ddd0839070a9de087b475dbf1d7314171f1e81208bd1ecd99b9b3d9a0ab66e` |
| `tools/a90_suspend_reach_probe.c` | `83d844b85b4fe20d796bab3e33d9f206f0cec9723baef2cf50de726b083518d0` |
| `experiments/verification-019-suspend-permutation/README.md` | `48014d44d5263da92d9849b97f1dce2457f84e6707ea5aaf0edaa798d71bb876` |
| `evidence/manifests/verification-019-suspend-permutation-20260827-01.manifest.json` | `bf7c66c78993b24d02a46735abb77e7e40298d6230bc5438c3eb21028c51238b` |

## Claim disposition

`PROVED`: the imported host analyzer's synthetic protocol and fail-closed
gates; the exact public manifest bytes and its declared external result.
`SUPPORTED`: the external report that a corroborated deep-suspend run observed
no moved tags in the declared 256 MiB offset domain.  `UNKNOWN`: private raw
receipt/repetition provenance in this worktree, effective physical contiguity
under `BLIND` pagemap, complete PA/DRAM coordinates, other state transitions,
and any inference about a protected-memory boundary or transform mutability.

The result is not a global no-mutation proof.  It is a stronger state-change
negative than a devfreq request only if the external receipt is later retained
and independently revalidated.  Until then, the public result remains
`SUPPORTED_EXTERNAL_MANIFEST_ONLY` and does not by itself close reopen
condition 3.

Classification remains `CLASS C (TRANSFORM ONLY)` and eligibility remains
`NOT_ELIGIBLE`.  No protected memory, controller register, SMC, partition or
firmware write was performed.
