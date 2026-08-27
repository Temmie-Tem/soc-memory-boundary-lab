# Verification 020L integration review — 2026-08-27

The 020L change is limited to its tool, focused tests, experiment README,
contract, and public manifest. It binds the exact 020K source/manifest and
XBL by size and SHA-256, re-derives seven unique conditional targets, and
inspects one executable landing word per target. The landing-word reader and
decoder reject a non-instruction-aligned VA before reading or decoding its
word. Expected families are
ADRP×2, LDR_UNSIGNED×1, LOGICAL_OR_BITMASK_IMMEDIATE×2, MOV_REGISTER×1, and
LDP_STP_PAIR×1. The imported 020D and 020F decoder sources are independently
size/hash pinned, with mutation negatives for both pins. Tests cover
target-set mutation, source/manifest/XBL hash drift, unknown/non-executable
words, redaction and no-clobber publication.

The result is deterministic, host-only, `CLASS C (TRANSFORM ONLY)`, and
`NOT_ELIGIBLE`. No ADB/USB, device, reboot, SMC, SCM, MMIO, normal-RAM,
protected-memory, partition, controller, or firmware write occurred. Static
landing shape does not establish execution, function boundaries, runtime
values, pointer/PA meaning, mutability, protected reach, or bypass authority.

## Artifact and validation pins

| Artifact | Size | SHA-256 |
|---|---:|---|
| `tools/sm8150_xbl_caller_context_branch_target_landing_word_inventory_020l.py` | 9,053 | `5da6631817837b56691b94c5b0f641c84de74d4f6e0f6dc0e554d39ca3c720c4` |
| `tests/test_sm8150_xbl_caller_context_branch_target_landing_word_inventory_020l.py` | 3,465 | `2464362b06bd28a4b74c80c92e41ec1c022e77e8fb6173a364acc51721203a63` |
| `experiments/verification-020L-branch-target-landing-word/README.md` | 1,423 | `4875b3914793fc064b6ce56179e8c6dae237b3988ab67c096d961201fa576795` |
| `docs/VERIFICATION020L_CONTRACT_2026-08-27.md` | 1,411 | `61018050109100575ca455a8cc1669d95cd108f4ce411678de1cdec3c7c920aa` |
| `evidence/manifests/020L-branch-target-landing-word-inventory-20260827-01.manifest.json` | 5,109 | `cdb0db05596ad06ae179861a4083e08b116ce283f683dd5fae44efde020f85dc` |

The imported 020D and 020F decoder sources are separately pinned in the tool
and manifest (21,053 bytes / `5a315f8735c38c86147367a1ad7c953d263d58c4bc63251473fa565e15efb332`; 23,772 bytes /
`b1f12fb516b52e3b15168e61930d407f08788dd2379fa330b9f2220fc2cf3a53`).
Python byte-compilation and the focused suite are **7/7 PASS**, including the
unaligned landing-VA negative. Regeneration
is byte-identical to the mode-`0644` manifest; `git diff --check` passes.

The alignment hardening adds a pre-read gate and a focused unaligned-VA
negative; the canonical manifest was regenerated after that contract change.

## Hostile-review disposition

`PASS` is required before commit.  The review scope is limited to the seven
target set, local XBL/dependency pins, imported decoder-source pins, strict
one-word family decoding, executable-segment/alignment gate, redaction,
no-clobber and the no-device boundary.  No live follow-up is authorized by
this artifact.
