# Experiment 029 integration review — 2026-08-26

## Scope

This review integrates committed host-only Experiment 029 from commit
`a495bdc`. It inventories only the 71 Experiment 027 site ranges whose result
was `INDIRECT_OR_UNSUPPORTED`. It does not extend the Experiment 027 decoder,
establish CFG reachability, execute firmware, contact a device, read MMIO, or
perform a write. Class C remains `TRANSFORM ONLY`; Experiments 015/016 remain
`NOT ELIGIBLE`.

The checked public artifact is
`evidence/manifests/029-dcb-unsupported-frontier-20260826-01.manifest.json`,
size 628,525 bytes, mode `0644`, SHA-256
`c6d46c382d7c091fffad137adb9491d107ff823ad6c6221f51eb627cc218f634`.
It contains virtual addresses and raw instruction words already required for
the bounded static audit, but no firmware bytes, private absolute path,
runtime value, device identifier, or secret.

## Artifact and dependency pins

| Artifact | Size | SHA-256 |
|---|---:|---|
| `tools/sm8150_dcb_unsupported_frontier.py` | 43,950 | `e5c491deaddafd4c60de7df3bfe0531f38bbd3740fe668942b912466ee86bca0` |
| `tests/test_sm8150_dcb_unsupported_frontier.py` | 24,461 | `d5eebfcbf1b4332bfeef693802e9b554728480051bc61331e811993c8837a1f2` |
| `experiments/029-dcb-unsupported-frontier/README.md` | 5,853 | `805476c2aad021a781011c66910e819fd9bbf3dc1a05d84aa4435b9704274ef6` |
| Checked public manifest | 628,525 | `c6d46c382d7c091fffad137adb9491d107ff823ad6c6221f51eb627cc218f634` |

The exact XBL input is 4,194,304 bytes with SHA-256
`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.
Experiment 027's frozen tool is 86,782 bytes with SHA-256
`11a4dab37e9a54e74ec93fba7c89524de1e77c7e71b86f105dd167d77780bcb9`;
its checked public manifest is 334,847 bytes with SHA-256
`d11785969f16ba09155a2305eefd091158abfc515bc64cf94cb34d573a302277`.
Experiment 029 validates those identities and the required dependency
semantics before importing the frozen decoder.

## Validation

- Focused Experiment 029 unittest suite: **17 PASS**.
- Full repository unittest discovery: **633 PASS** in **84.985 s**.
- Python byte-compilation of the tool and focused test: **PASS**.
- Public JSON parse: **PASS** for all 68 checked public manifests.
- Two fresh Experiment 029 generations: **byte-identical** to each other and
  the checked manifest.
- Publication uses `O_EXCL` and `O_NOFOLLOW`; no-clobber and mode `0644`:
  **PASS**.
- Independent hostile review after decoder-mask repairs: **PASS**.

The full suite was run serially. No parallel test runner or device process was
started by this integration.

## Exact bounded accounting

`PROVED`: the 71 dependency ranges contain 1,992 scanned word occurrences at
1,180 unique virtual addresses. Experiment 027 recognizes 1,640 occurrences
at 961 unique addresses. The unsupported frontier therefore contains 352
per-range occurrences at 219 unique addresses and 197 unique raw words. Both
identities are exact:

```text
1,640 + 352 = 1,992 occurrences
961 + 219 = 1,180 unique virtual addresses
```

`PROVED`: 191 frontier occurrence rows are members of overlapping ranges and
161 occur in exactly one range. Those rows represent 58 overlapped unique
addresses and 161 non-overlapped unique addresses. Frontier duplicate
multiplicity is 133; all-range overlap multiplicity is 812. Range membership,
including `UNREACHABLE_OR_OVERLAP_UNKNOWN`, is not CFG reachability.

The exact primary-class occurrence counts are:

| Primary class | Occurrences |
|---|---:|
| `DECODER_EXTENSION_CANDIDATE` | 161 |
| `FLAG_ONLY_NO_GPR_DEF` | 99 |
| `TAINT_KILL_REQUIRED` | 27 |
| `CONTROL_OR_MEMORY_UNSUPPORTED` | 54 |
| `UNKNOWN` | 11 |

`PROVED`: the four syntactic extension candidates rank by unique virtual
address count, then unique raw-word count, occurrence count, and family name:

| Rank | Family | Unique VAs | Unique words | Occurrences |
|---:|---|---:|---:|---:|
| 1 | `BITFIELD_IMM` | 56 | 54 | 120 |
| 2 | `AND_SHIFT` | 14 | 14 | 37 |
| 3 | `EOR_SHIFT` | 2 | 2 | 2 |
| 4 | `BIC_SHIFT` | 2 | 1 | 2 |

These are instruction-mask matches only. Every candidate remains
`HYPOTHESIS`, with source provenance
`UNKNOWN_REQUIRES_PRIMARY_SOURCE_REVIEW`, reachability
`UNKNOWN_RANGE_MEMBERSHIP_IS_NOT_CFG_REACHABILITY`, and decoder safety
`NOT_CLAIMED`. One indirect/runtime-alias site, Experiment 027 site 35 at
store `0x1484f9e0`, remains separately identified with reachability and target
both `UNKNOWN`.

## Hostile-review repairs and claim boundary

The final hostile review verifies that W-form extended-register options 3 and
7 remain reserved, logical shifted-register shift type 3 is ROR, shifted
S=0/Rd=31 is a zero-register discard rather than SP, extended S=0/Rd=31 is
SP, and reserved conditional-select encodings are rejected. A broad
three-source classifier was removed: the 11 matching occurrences are
conservatively `THREE_SOURCE_UNVALIDATED` / `UNKNOWN` with
`encoding_mask_match: false` rather than promoted as multiply instructions.

`REFUTED`: treating the 71 fail-closed ranges as 71 independent instruction
streams or treating duplicated range membership as execution evidence.

`UNKNOWN`: source-qualified instruction semantics, actual CFG reachability,
runtime execution, current object/base values, destination physical address,
global DCB consumer or writer identity, register programming semantics,
post-boot writability, alias behavior, and security-boundary effect.
Experiment 027's writer-absence field remains `UNKNOWN`; Experiment 029 makes
no absence claim.

## Final disposition and next discriminator

`PASS`: Experiment 029 is integrated as a deterministic, bounded syntactic
inventory. It narrows the fail-closed frontier but does not itself change any
Experiment 027 site result.

Experiment 031 subsequently completed the source-qualified scalar-plus-dispatch
follow-up from artifact commit `cd9f26e` plus reconciliation repair commit
`12a8ebe`. It transitions 51 of the 71 baseline sites to
bounded `NO_TARGET_WITHIN_MODEL`, with 20 still `INDIRECT_OR_UNSUPPORTED`; the
result is explicitly `V2_MODEL_ONLY` and `NO_ABSENCE_CLAIM`, not scalar-only
closure. Its 031 integration review records the exact artifact pins and
validation: 19 focused and 652 tracked full unittest PASS in 85.226 s,
maximum RSS 220,684 KiB with no swaps, QEMU 280/280, 69 public JSON manifests,
two fresh manifests byte-identical to the checked manifest, and final
reconciliation hostile review `PASS`.

The next non-overlapping DCB discriminator is Experiment 032, scored `82/100`:
qualify an official source and apply bounded semantics to the exact reached
`MADD/UMADDL` plus `EOR/BIC` arithmetic frontier. Pair/sign-extending memory,
system/control, indirect aliases, and any unsafe form remain fail-closed.
Pair-memory remains a later candidate after the arithmetic frontier.

External Claude Experiments 028 and 030 remain outside this integration and
unreviewed here. No result, authority, review, or commit from either is
integrated or claimed.
