# Experiment 032 integration review — 2026-08-26

## Scope and authority boundary

This review integrates the completed host-only Experiment 032 artifact from
commit `d46c44c`, immediately after documentation commit `e063181`. It extends
the exact Experiment 031 scalar-plus-dispatch model with a source-qualified
arithmetic frontier. It performs no device, USB, SMC, MMIO, normal-RAM,
protected-memory, boot, activation, or write action. `current_destination` and
`writer_absence` remain `UNKNOWN`; Class C remains `TRANSFORM ONLY`, and
Experiments 015/016 remain `NOT ELIGIBLE`.

The exact XBL input is `xbl--sdb1.bin`, 4,194,304 bytes, SHA-256
`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.
The 032 model analyzes exactly the 71 Experiment 027 fail-closed site
identities inherited through the pinned 029 manifest and 031 result. Range
membership is not CFG reachability, execution, or a current destination.

## Artifact and dependency pins

| Artifact | Size | Mode | SHA-256 |
|---|---:|---:|---|
| `tools/sm8150_dcb_arithmetic_frontier.py` | 127,151 | — | `d4233d08ebe3c28cf803f5e9e1e564f1d9e40af12eca85498d23e569821219e2` |
| `tests/test_sm8150_dcb_arithmetic_frontier.py` | 22,710 | — | `8bb006cb409235bff0b5a2d2fe2a00cae389eb5253124fcd580bb7713df4d3ad` |
| `experiments/032-dcb-arithmetic-frontier/README.md` | 6,484 | — | `20292544e84c5a30876856043287cf6b712642309a6ccd7cfb3fa21702da7573` |
| Checked public manifest | 1,564,295 | `0644` | `beee3cdaa7d69f240310bed8b574f8dd81b00b48c2383f48dd849ebd36fb4b31` |

The public manifest is
`evidence/manifests/032-dcb-arithmetic-frontier-20260826-01.manifest.json`.
It contains no firmware bytes, private path, device identifier, runtime value,
or secret. The exact dependency chain was checked before import:

| Dependency | Size | SHA-256 |
|---|---:|---|
| Frozen 031 tool | 91,221 | `5263d8975e9d64809aed04763e0c5573458dabcc6ae7432763d2858a36fc267b` |
| Frozen 031 manifest | 1,327,118 | `51a187195c16eb609d337305540fc6d20a09297f5ab76b054497c5c58c3a2e86` |
| Frozen 029 tool | 43,950 | `e5c491deaddafd4c60de7df3bfe0531f38bbd3740fe668942b912466ee86bca0` |
| Frozen 029 manifest | 628,525 | `c6d46c382d7c091fffad137adb9491d107ff823ad6c6221f51eb627cc218f634` |
| Frozen 027 tool | 86,782 | `11a4dab37e9a54e74ec93fba7c89524de1e77c7e71b86f105dd167d77780bcb9` |
| Frozen 027 manifest | 334,847 | `d11785969f16ba09155a2305eefd091158abfc515bc64cf94cb34d573a302277` |

## Source qualification and bounded model

`PROVED`: the arithmetic forms are qualified against Arm's primary
`Arm A64 Instruction Set for A-profile architecture`, DDI0602 (ID092025),
version 2025-09, at
<https://developer.arm.com/documentation/ddi0602/2025-09/>. The downloaded
source is `ISA_A64_xml_A_profile-2025-09_ASL0.pdf`, 25,622,354 bytes, SHA-256
`683025f0460c8af8d6711b764c5c4d51d1b56f38d78b618e6cb27d9abf4c853f`.

| Form | Primary-source page | Bounded rule |
|---|---:|---|
| `MADD` | 539 | W/X modulo-width multiply-add from pre-state operands |
| `UMADDL` | 873 | zero-extend W operands, add X accumulator, modulo 64 bits |
| shifted `EOR` | 354 | modulo-width XOR and exact identity cases |
| shifted `BIC` | 62 | modulo-width AND-with-inverted-shift and exact identity cases |

The three-source mask validates fixed bits 30:21 and `o0` (`0x7FE08000`).
MSUB, SMADDL/SMSUBL, UMSUBL, reserved selectors, malformed encodings, and
unsupported forms fail closed. Register operands are read from pre-state,
including overlaps; `Rd=31` is a ZR discard. An address origin is retained
only for an exact address accumulator plus a known constant product, a proven
zero product, or another explicit identity case. Non-identity pointer
transforms become `UNKNOWN`; unknown arithmetic is destination-local and does
not erase unrelated origins.

The inherited `DIRECT_CONTROL_DISPATCH_REPAIR` remains a separately bounded
direct-CFG model. It supplies no runtime branch-target, execution-order,
device-authority, or absence claim. Pair/sign-extending memory, system/control,
indirect branches and aliases, reserved/unknown forms, and all unsafe forms
remain fail-closed.

## Exact accounting and result

`PROVED`: the 029 frontier contains 352 occurrence rows. The combined selected
membership is **298 occurrences / 175 unique VAs / 162 unique raw words**
across all 71 ranges. It retains the exact 031 scalar domain (283 / 160 / 148)
and adds 15 arithmetic rows across seven sites (15 / 15 / 14). Syntactic
membership is not reachability: 264 selected events are reached and 34
selected occurrences are not reached.

The reached arithmetic identity is exact: 14 events from 15 selected rows,
with `MADD` 3, `UMADDL` 7, `EOR` 2, and `BIC` 2. There are zero family or
label mismatches and zero events outside the selected domain. The inherited
031 equivalence gate compares canonical full records, not only counts, and is
exact for 250 reached scalar-extension events, all 143 direct-control events,
and all 23 reached taint-kill events.

`PROVED`: the combined v3 model transitions **55/71** baseline 027 fail-closed
sites to bounded `NO_TARGET_WITHIN_MODEL`; 16 remain
`INDIRECT_OR_UNSUPPORTED`. Relative to 031, 51 sites remain no-target and four
sites transition to no-target: **1, 36, 37, and 52**. There are zero reverse
transitions and zero regressions. The all-range syntactic selection spans
56/71 sites; this is a membership count, not a closure prediction.

The residual syntactic frontier is **54 occurrences / 44 unique VAs / 35
unique raw words across 15 sites**:

| Preserved family | Occurrences |
|---|---:|
| `PAIR_MEMORY` | 48 |
| `SIGN_EXTENDING_MEMORY` | 2 |
| `SYSTEM_CONTROL` | 4 |

The result is explicitly `V3_MODEL_ONLY` and `NO_ABSENCE_CLAIM`. Zero
`DCB_CONSUMER_PATH` and zero `MC_OR_SHRM_SYMBOLIC_TARGET` paths are promoted.
Runtime execution/order, current object/base values, physical destination,
global consumer/writer identity, post-boot writability, alias behavior,
protected-memory semantics, `current_destination`, and `writer_absence` remain
`UNKNOWN`.

## Validation and final disposition

- Focused Experiment 032 suite: **18 PASS**, maximum RSS **58,388 KiB**, swap
  **0**.
- Full repository unittest discovery: **670 PASS** in **84.937 s**,
  maximum RSS **233,928 KiB**, swaps **0**.
- Python byte-compilation: **PASS**.
- Public JSON parse: **PASS** for **70** public manifests.
- Two fresh host manifest generations: byte-identical to each other and the
  checked manifest.
- Exact-word `qemu-aarch64` oracle: **56/56**.
- Synthetic `qemu-aarch64` oracle: **76/76**.
- Encoding grids: logical shifted-register **1,024/1,024** and three-source
  **128/128** (**1,152/1,152** total).
- Final independent hostile review after fixes: **PASS**.

`PASS`: Experiment 032 is integrated as a deterministic, bounded,
source-qualified v3 arithmetic extension. It narrows the bounded 027 frontier
and preserves all fail-closed and no-absence boundaries; it does not establish
a live consumer, writer, current destination, transform mutation, alias,
protected reach, or bypass. The artifact is `HOST_ONLY_READ_ONLY` and
`NOT_ELIGIBLE`; no device authority exists.

## Next non-overlapping selection

Experiment 033 is selected at **87/100**. It will source-qualify and model the
exact remaining reached residual: 41 `PAIR_MEMORY` events across 13 sites
(38 `LDP`, 3 `STP`; 34 are SP-based `LDP`), two sign-extending loads across
two sites, and one `DAIFClr` system-control event, spanning the 15-site
residual and 16-site fail-closed set. `STP` must be represented as two
explicit store observations, not skipped; unpredictable, overlap, and
writeback forms remain fail-closed, and site 35's indirect/runtime alias
remains fail-closed.

This outranks live capture and withheld 023R because it addresses concrete
reached residual events using existing exact host inputs and deterministic
source/model validation without a new device gate. Experiment 023R remains
withheld because its timing protocol is not comparable to 014, physical-
allocation PA provenance is missing, and its full GF(2) matrix is non-unique.
Experiment 033 is host-only and grants no device, MMIO, write, or live
authority.

External Claude Experiments 028 and 030 remain outside this integration and
unreviewed here. No result, score, authority, review, or commit from either is
integrated or claimed.
