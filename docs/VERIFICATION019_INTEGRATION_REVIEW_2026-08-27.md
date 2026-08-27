# Verification 019 suspend/permutation integration review — 2026-08-27

## Boundary and exact artifact

This review began with the additive public artifact from external commit
`96f8d4c`.  Follow-up commit `1bc494e` retained the original raw receipt as a
real private regular file and acquired a second suspend on the same
uninterrupted boot.  The integration review itself issued no device command;
the two run receipts and restoration record are reviewed as retained evidence.

The original public manifest is 657 bytes, mode `0644`, SHA-256
`bf7c66c78993b24d02a46735abb77e7e40298d6230bc5438c3eb21028c51238b`; the
second-run manifest is 658 bytes, mode `0644`, SHA-256
`b9d5717f33349727da7523ea6ab003ce33ec6694fce3487370a802a1d2f4b4eb`.
The retained private receipts are 930 bytes / SHA-256
`6f34e725f2a5faed2340c1a5294500ee37b946a6f2e1feed877f7b0e8b5946c6` and
931 bytes / SHA-256
`84ce2e88acdc3a956794feb57f968490aa3c2a05ff196dc3fc82a62dcf5bf395`.
The blocked cable-attached control is retained separately at 3,265 bytes / SHA
`fff1126a5b00690abc28a29b8fe145369a651c7bb7c8d45a89499213cd134298`.

## Validation

The imported analyzer's host-only suite is 24/24 PASS and the private-receipt
guard suite is 5/5 PASS.  Python byte-compilation passes, the two C probes pass
cross-compiler syntax validation, and the synthetic control detects injected
permutations at bits 6, 7, 11 and 12 while the injective control remains
`MAP_INVARIANT`.  Gate negatives refuse an admissible null when the baseline,
suspend interval, statistics corroboration, or summary is missing.  Both raw
receipts are regular files, and run-1/run-2 analyzer regeneration is
byte-identical to manifests `…-01`/`…-02`.

The imported implementation/artifact hashes are:

| Artifact | SHA-256 |
|---|---|
| `tools/a90_suspend_permutation_analysis.py` | `c1dd1be9e843ade565dd50cc1690d3077cd8cd6a1c1a0e73c42073aa2ae7786a` |
| `tests/test_a90_suspend_permutation_analysis.py` | `73ffe1bdfa6dfc12498bfe505fcb3cb23d58915c57b99019499550d7eae8d4fa` |
| `tools/a90_suspend_permute_probe.c` | `b8ddd0839070a9de087b475dbf1d7314171f1e81208bd1ecd99b9b3d9a0ab66e` |
| `tools/a90_suspend_reach_probe.c` | `83d844b85b4fe20d796bab3e33d9f206f0cec9723baef2cf50de726b083518d0` |
| `experiments/verification-019-suspend-permutation/README.md` | `19d2629c37e868a9adc3aeea942f209ff271be3303df842364a296533a783217` |
| `evidence/manifests/verification-019-suspend-permutation-20260827-01.manifest.json` | `bf7c66c78993b24d02a46735abb77e7e40298d6230bc5438c3eb21028c51238b` |
| `evidence/manifests/verification-019-suspend-permutation-20260827-02.manifest.json` | `b9d5717f33349727da7523ea6ab003ce33ec6694fce3487370a802a1d2f4b4eb` |
| `tests/test_evidence_private_no_symlinks.py` | `a8d199fa7480d4e2cfa0d722a5be43eaa3d9e0f3f80a794d790b015643ad3950` |

## Claim disposition

`PROVED`: the analyzer's synthetic protocol and fail-closed gates; both exact
public manifests; two retained, corroborated deep-suspend runs with zero moved
tags in the declared 256 MiB offset domain; and the byte-identical
regenerations.  `REFUTED`, for this tested transition and offset domain: that
deep suspend changes the observed tag relation.  `SUPPORTED`: the diagnosis
that the cable-attached control is `SUSPEND_NOT_REACHED` and therefore not an
invariance result.  `UNKNOWN`: effective physical contiguity under `BLIND`
pagemap, complete PA/DRAM coordinates, other state transitions, transform
mutability outside deep suspend, and any protected-memory boundary or bypass.

This is not a global no-mutation proof and does not close every form of reopen
condition 3.  It closes the retained deep-suspend candidate as a negative;
other untested state transitions remain `UNKNOWN`.

Classification remains `CLASS C (TRANSFORM ONLY)` and eligibility remains
`NOT_ELIGIBLE`.  No protected memory, controller register, SMC, partition or
firmware write was performed.
