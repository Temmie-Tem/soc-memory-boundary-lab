# Experiment 033 — bounded DCB residual-memory frontier

## Question and authority boundary

Can the exact residual integer-memory/system frontier left by Experiment 032
be qualified against Arm's primary source and evaluated inside the same bounded
CFG/dataflow model? This is a deterministic, host-only transform over the
exact A90 5G / SM-A908N / SM8150 XBL input (`xbl--sdb1.bin`, 4,194,304 bytes,
SHA-256 `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`).

No device, USB, SMC, MMIO, protected-memory, boot, activation, or write action
occurs. `current_destination` and `writer_absence` remain `UNKNOWN`. Membership
in a 029 range is syntactic membership, not reachability; a bounded model
result is not execution or a runtime absence claim. Experiments 028 and 030
are not inputs or authority for this result.

## Exact dependency and source pins

The 032 tool and public manifest are size- and SHA-256-checked and semantically
validated before the already-hashed 032 source bytes are imported. The pinned
032 module then validates and imports its exact 031/027/029 source/public
chain. The Arm primary source is DDI0602 (ID092025), version 2025-09,
SHA-256 `683025f0460c8af8d6711b764c5c4d51d1b56f38d78b618e6cb27d9abf4c853f`.

| Input | Size | SHA-256 |
|---|---:|---|
| Frozen 032 tool | 127,151 | `d4233d08ebe3c28cf803f5e9e1e564f1d9e40af12eca85498d23e569821219e2` |
| Frozen 032 manifest | 1,564,295 | `beee3cdaa7d69f240310bed8b574f8dd81b00b48c2383f48dd849ebd36fb4b31` |
| Frozen 031 tool | 91,221 | `5263d8975e9d64809aed04763e0c5573458dabcc6ae7432763d2858a36fc267b` |
| Frozen 031 manifest | 1,327,118 | `51a187195c16eb609d337305540fc6d20a09297f5ab76b054497c5c58c3a2e86` |
| Frozen 029 tool | 43,950 | `e5c491deaddafd4c60de7df3bfe0531f38bbd3740fe668942b912466ee86bca0` |
| Frozen 029 manifest | 628,525 | `c6d46c382d7c091fffad137adb9491d107ff823ad6c6221f51eb627cc218f634` |
| Frozen 027 tool | 86,782 | `11a4dab37e9a54e74ec93fba7c89524de1e77c7e71b86f105dd167d77780bcb9` |
| Frozen 027 manifest | 334,847 | `d11785969f16ba09155a2305eefd091158abfc515bc64cf94cb34d573a302277` |

## Exact v4 admission

The local fork preserves all 032 arithmetic/scalar/direct-control semantics
and adds only these source-qualified forms:

| Form | Primary-source pages | Bounded rule |
|---|---:|---|
| `LDP W/X` signed offset | 437–439 | signed `imm7`, scaled by 4/8; two pre-state destination definitions |
| `LDP X` post-index | 437–439 | load at pre-state base and base+8; modulo-64 base/SP writeback |
| `STP W/X` signed offset | 752–754 | two explicit stores at base+offset and +element size; no writeback |
| `LDRSW X` unsigned immediate | 465–466 | destination-local S32→X64 sign extension |
| `LDRSB W` unsigned immediate | 457–458 | destination-local S8→W32 sign extension and zeroed W upper X bits |
| exact `DAIFClr #IRQ` (`0xd50342ff`) | 553–556 | PSTATE.DAIF IRQ instruction semantics; no GPR or NZCV definition |

Pre-index and unseen pair modes, SIMD/FP pairs, LDPSW, reserved or
constrained-unpredictable overlaps, other system forms, indirect aliases,
malformed words, and unsound memory provenance remain fail-closed. Pair loads
read both lanes from pre-state; `ZR` destinations are discarded. Post-index
base/destination overlap is rejected. Unknown sign-extending results are
destination-local; DCB-derived data is retained only when the inherited DCB
load provenance is exact. The runtime exception level and `CheckDAIFAccess`
outcome for `DAIFClr` remain `UNKNOWN`; the record does not prove that its
side effect executed without a trap.

## Measured accounting

The 029 frontier contains **352 occurrences / 219 unique VAs / 197 unique raw
words** across all 71 bounded ranges. The 032 residual syntactic membership is
kept as a separate ledger: **54 occurrences / 44 unique VAs / 35 unique raw
words** across 15 sites, consisting of:

| Residual family | Syntactic occurrences |
|---|---:|
| `PAIR_MEMORY` | 48 |
| `SIGN_EXTENDING_MEMORY` | 2 |
| `SYSTEM_CONTROL` | 4 |

Measured residual admission is pair `48 selected / 41 reached / 7 not
reached`, sign-extending `2 / 2 / 0`, and system `4 / 1 / 3`.

The run measures **308 reached extension events**: 264 inherited 032 records
plus 44 new residual events. Exactly 44 selected occurrences are not reached.
The new-event operation identity is:

| Operation | Reached events |
|---|---:|
| `LDP` | 38 |
| `STP` | 3 |
| `LDRSW` | 1 |
| `LDRSB` | 1 |
| `DAIFClr` | 1 |

The three STP instructions publish six lane observations, with both lane
indices 0 and 1. The measured bounded site result is **70
`NO_TARGET_WITHIN_MODEL` / 1 `INDIRECT_OR_UNSUPPORTED`**. Site 35 retains its
unresolved indirect/runtime alias; no DCB consumer or MC/SHRM symbolic target
path is promoted. This is a bounded transform result, not a global absence
claim.

The inherited 032 equality gates are exact for the complete 264 reached
extension events (including its 14 arithmetic events), all 143 direct-control
events, and all 23 taint-kill events. The 032 source manifest itself is also
validated for its prior 55/16 site split, 51/16/4/0 transition quadrants,
250/143/23 inherited equality counts, 3/7/2/2 arithmetic operation counts,
and `writer_absence=UNKNOWN` with no claim.

## Reproduce and validate

```sh
python3 tools/sm8150_dcb_residual_memory_frontier.py \
  --firmware-dir <exact-firmware-dir> \
  --manifest-dir <public-manifest-dir> \
  --output <public-manifest-path>

python3 -m unittest -v tests.test_sm8150_dcb_residual_memory_frontier
python3 -m py_compile tools/sm8150_dcb_residual_memory_frontier.py
```

Publication uses `O_EXCL`, `O_NOFOLLOW` where available, refuses clobbering,
and sets mode `0644`. The checked JSON is deterministic, contains no private
path or firmware bytes, and two fresh host generations are byte-identical.

## Verification record

- Focused Experiment 033 tests: **15/15 PASS**; `py_compile`: **PASS**;
  maximum RSS 65,064 KiB, swap 0.
- Full host discovery: **685/685 PASS** in 85.706 seconds; maximum RSS
  253,944 KiB, swap 0.
- Two fresh CLI publications and the checked manifest are byte-identical at
  SHA-256 `606723e5125d661c800b167133f2a9b69a3b8d47361b39176665a49be539e598`;
  all are mode `0644`.
- Independent raw-word decoding with GNU AArch64 `objdump` matched all 29
  unique reached residual words. A QEMU AArch64 execution oracle confirmed
  pre-state post-index LDP lanes and writeback, both STP lanes, and LDRSB/LDRSW
  sign extension. `DAIFClr` was deliberately not executed in the EL0 oracle.
- The pinned Arm PDF hash was independently rechecked. Public JSON parsing,
  private-path/identifier leakage checks, exact 264/143/23 inherited equality,
  352/308/44 admission, 70/1 outcome, and six STP lane records all passed.
- A separate read-only hostile reviewer returned **PASS with no P0-P2
  findings** after checking decoder masks, source semantics, dependency
  ordering, accounting, authority boundaries, deterministic publication, and
  non-overlap with Experiments 028/030.

## Final artifacts

| Artifact | Size | SHA-256 |
|---|---:|---|
| Experiment 033 tool | 172,708 | `aeb346253aab7860554c8a1cb627d04cbd56d9d82abf50a4a5b811da62a20f93` |
| Focused tests | 20,273 | `58632f7a74772e2e86f1ff106c616fd85d0719781394a099cf0d411bb7258dba` |
| Checked public manifest | 2,017,356 | `606723e5125d661c800b167133f2a9b69a3b8d47361b39176665a49be539e598` |

The classification is `CLASS C (TRANSFORM ONLY)`, mode
`HOST_ONLY_READ_ONLY`, eligibility `NOT_ELIGIBLE`. This experiment does not
authorize live use, a writer/consumer absence statement, a physical
destination claim, or a boundary bypass.
