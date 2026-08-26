# Experiment 033 integration review — 2026-08-26

## Scope and authority boundary

This review integrates the completed host-only Experiment 033 artifact from
commit `56b5ffa`. It extends the exact Experiment 032 v3 scalar, arithmetic,
and direct-control model with a bounded residual-memory/system v4 admission.
It performs no device, USB, SMC, MMIO, normal-RAM, protected-memory, boot,
activation, or write action. Class C remains `TRANSFORM ONLY`; Experiments 015
and 016 remain `NOT_ELIGIBLE`. `current_destination`, `writer_absence`, and
protected-memory semantics remain `UNKNOWN`.

The exact XBL input is `xbl--sdb1.bin`, 4,194,304 bytes, SHA-256
`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.
Membership in the inherited 029 ranges is syntactic membership only; the
bounded events are not proof of runtime execution, current destination,
global consumer/writer absence, or a security-boundary result.

## Artifact and dependency pins

| Artifact | Size | Mode | SHA-256 |
|---|---:|---:|---|
| `tools/sm8150_dcb_residual_memory_frontier.py` | 172,708 | `0644` | `aeb346253aab7860554c8a1cb627d04cbd56d9d82abf50a4a5b811da62a20f93` |
| `tests/test_sm8150_dcb_residual_memory_frontier.py` | 20,273 | `0644` | `58632f7a74772e2e86f1ff106c616fd85d0719781394a099cf0d411bb7258dba` |
| `experiments/033-dcb-residual-memory-frontier/README.md` | 7,648 | `0644` | `fb87bee1cbb001054389134afb8ae3c80da694d66355731848bc735a37189002` |
| Checked public manifest | 2,017,356 | `0644` | `606723e5125d661c800b167133f2a9b69a3b8d47361b39176665a49be539e598` |

The public manifest is
`evidence/manifests/033-dcb-residual-memory-frontier-20260826-01.manifest.json`.
It contains no firmware bytes, private path, device identifier, runtime value,
or secret. The tool validates the exact 032 tool and manifest before importing
their already-hashed source bytes; the pinned 032 module validates and imports
its exact 031/029/027 dependency chain. The prior dependency pins are
published in the Experiment 033 README and manifest.

The Arm primary source is `Arm A64 Instruction Set for A-profile architecture`,
DDI0602 (ID092025), version 2025-09, PDF SHA-256
`683025f0460c8af8d6711b764c5c4d51d1b56f38d78b618e6cb27d9abf4c853f`.

## Source-qualified v4 admission

| Form | Primary-source pages | Bounded rule |
|---|---:|---|
| `LDP W/X` signed offset | 437–439 | signed `imm7`, scaled by 4/8; two pre-state destination definitions |
| `LDP X` post-index | 437–439 | load at pre-state base and base+8; modulo-64 base/SP writeback |
| `STP W/X` signed offset | 752–754 | two explicit stores at base+offset and base+element-size |
| `LDRSW X` unsigned immediate | 465–466 | destination-local S32-to-X64 sign extension |
| `LDRSB W` unsigned immediate | 457–458 | destination-local S8-to-W32 sign extension with zeroed W upper bits |
| exact `DAIFClr #IRQ` (`0xd50342ff`) | 553–556 | bounded PSTATE.DAIF IRQ instruction semantics; no GPR or NZCV definition |

`PROVED`: pair lanes read the pre-state base, and each `STP` publishes two
separate lane observations. Pre-index and unseen pair modes, SIMD/FP pairs,
LDPSW, constrained-unpredictable overlaps, post-index base/destination
overlap, other system forms, indirect aliases, malformed words, and unsound
memory provenance remain fail-closed. Unknown sign-extending values are
destination-local. `DAIFClr` records instruction semantics only; its runtime
exception level and `CheckDAIFAccess` result remain `UNKNOWN`.

## Exact accounting and result

`PROVED`: the complete 029 frontier contains 352 occurrences / 219 unique VAs
/ 197 unique raw words across 71 bounded ranges. Experiment 033 reaches 308
selected events and leaves 44 selected occurrences not reached. The inherited
032 full-record equality is exact for 264 reached extension events, 143
direct-control events, and 23 taint-kill events.

The 44 new residual events are:

| Operation | Reached events |
|---|---:|
| `LDP` | 38 |
| `STP` | 3 |
| `LDRSW` | 1 |
| `LDRSB` | 1 |
| `DAIFClr` | 1 |

The three `STP` instructions produce six explicit lane observations, including
both lane indices 0 and 1. The measured bounded site result is 70
`NO_TARGET_WITHIN_MODEL` and one `INDIRECT_OR_UNSUPPORTED`; the latter is site
35's unresolved indirect/runtime alias. No bounded `DCB_CONSUMER_PATH` or
`MC_OR_SHRM_SYMBOLIC_TARGET` path is promoted.

The result is `V4_MODEL_ONLY` and `NO_ABSENCE_CLAIM`. Global writer identity or
absence, current physical destination, protected-memory reach/semantics,
post-boot writability, execution order, aliases, and live authority remain
`UNKNOWN`. The result is therefore `CLASS C (TRANSFORM ONLY)`, not a bypass
finding.

## Validation and final disposition

- Focused Experiment 033 suite: **15/15 PASS**; Python `py_compile`: **PASS**;
  maximum RSS **65,064 KiB**, swap **0**.
- Full repository unittest discovery: **685/685 PASS** in **85.706 s**;
  maximum RSS **253,944 KiB**, swap **0**.
- Two fresh CLI publications and the checked manifest are byte-identical;
  SHA-256 is `606723e5125d661c800b167133f2a9b69a3b8d47361b39176665a49be539e598`.
- Public JSON parsing, private-path/device-identifier safety, exact
  352/308/44 accounting, 264/143/23 inheritance, 70/1 site outcomes, and six
  STP lane records passed.
- GNU AArch64 `objdump` decoding matched all 29 unique reached residual words.
  A QEMU AArch64 oracle confirmed LDP pre-state/post-index behavior, both STP
  lanes, and LDRSB/LDRSW sign extension; `DAIFClr` was not executed in EL0.
- A separate read-only hostile review returned **PASS** with no P0–P2
  findings after checking masks, source semantics, dependency ordering,
  accounting, deterministic publication, authority boundaries, and
  non-overlap with external Claude Experiments 028/030.

`PASS`: Experiment 033 is integrated as a deterministic, source-qualified,
bounded v4 residual extension. It closes the selected instruction-form frontier
inside the stated model, but it does not establish a live consumer, writer,
current destination, transform mutation, physical-to-DRAM alias, protected
reach, or isolation bypass.

## Next selection: Experiment 034

Experiment 034 is the next highest-information, non-overlapping host-only
selection. It will resolve site 35's exact indirect jump-table target using a
pinned static tool and tests. Current reconnaissance is `HYPOTHESIS`, not a
site-closure claim:

- `BR X1` is at `0x1484fa08`.
- The candidate table base is `0x14824cf0`.
- `W9` is guarded by `CMP W9,#4` plus `B.HI` at `0x1484f9f4/0x1484f9f8`.
- `LDR X1,[X5,X9,LSL#3]` is at `0x1484fa04`.
- The five little-endian entries are `0x1484fa3c`, `0x1484fa50`,
  `0x1484fa88`, `0x1484fa0c`, and `0x1484fa0c`; all are local.

Only a pinned decoder, exact accounting, and hostile review may reclassify
site 35. No device/MMIO/write/live authority is selected. External Claude
Experiments 028 and 030 remain outside this integration and unreviewed.
