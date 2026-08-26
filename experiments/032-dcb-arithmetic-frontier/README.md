# Experiment 032 — bounded DCB arithmetic frontier

## Question and authority boundary

Can the exact residual arithmetic frontier from Experiment 031 be qualified
against Arm's primary source and evaluated inside the same bounded CFG/dataflow
model? This is a deterministic, host-only transform for the exact A90 5G /
SM-A908N / SM8150 XBL input (`xbl--sdb1.bin`, 4,194,304 bytes,
SHA-256 `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`).

No device, USB, SMC, MMIO, protected-memory, boot, activation, or write action
occurs. `current_destination` and `writer_absence` remain `UNKNOWN`.
Membership in a 029 range is not reachability; a bounded model result is not
execution or a runtime absence claim. Experiments 028 and 030 are not inputs
or authority for this result.

## Exact dependencies

The 031 tool and public manifest are size- and SHA-256-checked, semantically
validated, and imported before the local v3 hook is used. The pinned 027 and
029 source/public chain is also checked before the 027 decoder import.

| Input | Size | SHA-256 |
|---|---:|---|
| Frozen 031 tool | 91,221 | `5263d8975e9d64809aed04763e0c5573458dabcc6ae7432763d2858a36fc267b` |
| Frozen 031 manifest | 1,327,118 | `51a187195c16eb609d337305540fc6d20a09297f5ab76b054497c5c58c3a2e86` |
| Frozen 029 tool | 43,950 | `e5c491deaddafd4c60de7df3bfe0531f38bbd3740fe668942b912466ee86bca0` |
| Frozen 029 manifest | 628,525 | `c6d46c382d7c091fffad137adb9491d107ff823ad6c6221f51eb627cc218f634` |
| Frozen 027 tool | 86,782 | `11a4dab37e9a54e74ec93fba7c89524de1e77c7e71b86f105dd167d77780bcb9` |
| Frozen 027 manifest | 334,847 | `d11785969f16ba09155a2305eefd091158abfc515bc64cf94cb34d573a302277` |

## Qualified arithmetic

The local fork retains all qualified 031 scalar semantics and the exact
`DIRECT_CONTROL_DISPATCH_REPAIR`. It adds only the following source-qualified
forms from Arm `DDI0602 (ID092025)`, version 2025-09:

| Form | Primary-source page(s) | Bounded rule |
|---|---:|---|
| `MADD` | 539 | W/X modulo-width multiply-add |
| `UMADDL` | 873 | zero-extend W operands, add X accumulator, modulo 64 bits |
| shifted `EOR` | 354 | modulo-width XOR and exact identity cases |
| shifted `BIC` | 62 | modulo-width AND-with-inverted-shift and exact identity cases |

The three-source mask validates fixed bits 30:21 and `o0` (mask
`0x7FE08000`), and rejects MSUB, SMADDL/SMSUBL, UMSUBL, and reserved
selectors. Register operands are read from pre-state, including overlaps;
`Rd=31` is a ZR discard. Constant results are exact modulo the architectural
width. An address origin is retained only for an exact address accumulator plus
a known constant product, a proven zero product, or another explicit identity
case. Pointer transforms that are not exact identities become `UNKNOWN`.

Unknown arithmetic is destination-local and does not erase unrelated origins.
Pair/sign-extending memory, system/control, indirect branches, malformed or
reserved encodings, and every other unknown form remain fail-closed.

## Exact accounting

The 029 frontier has 352 occurrence rows. The combined selected membership is
**298 occurrences / 175 unique VAs / 162 unique raw words** across all 71
ranges. It consists of the exact 031 domain (**283 / 160 / 148**) plus 15
arithmetic rows (**15 / 15 / 14**) across seven sites. One arithmetic row is
the unreached site-57 MADD/UMADDL occurrence; syntactic membership is not
reachability. The all-range syntactic selection is **56/71** sites.

The preserved residual syntactic frontier is **54 occurrences / 44 unique VAs
/ 35 unique raw words** across 15 sites:

| Preserved family | Occurrences |
|---|---:|
| `PAIR_MEMORY` | 48 |
| `SYSTEM_CONTROL` | 4 |
| `SIGN_EXTENDING_MEMORY` | 2 |

The bounded result transitions **55/71** baseline 027 fail-closed sites to
`NO_TARGET_WITHIN_MODEL`; 16 remain `INDIRECT_OR_UNSUPPORTED`. Relative to
031, four sites transition to no-target: **1, 36, 37, and 52**. The remaining
031 fail-closed sites are **32, 35, 39, 40, 41, 42, 56, 57, 58, 60, 61, 63,
64, 65, 66, and 67**. Site 35 retains its unresolved indirect branch; sites
56 and 57 retain pair-memory blockers.

The reached arithmetic event identity is exact: 10
`THREE_SOURCE_UNVALIDATED` events at sites 35/36/37/56, two `EOR_SHIFT`
events at sites 36/37, and two `BIC_SHIFT` events at sites 1/52. There are 14
reached arithmetic events from 15 selected 029 rows, with zero outside,
family, or label mismatches. Every event is keyed by
`(site_index, va, raw_word, family, effect)` and records
`PASS_EXACT_029_SELECTED` admission. The inherited direct-control repair
remains 143 events across 62 sites (`B.cond` 87, `CBZ_CBNZ` 28, `B` 15,
`TBZ_TBNZ` 13); it is bounded CFG dispatch only.

The inherited 031 equivalence gate compares canonical full records, not only
counts: 250 non-arithmetic reached-extension events, all 143 flattened direct
control events, and 23 reached taint-kill events are byte-for-byte equal to
the pinned 031 records. Any VA, raw-word, effect, or other record mutation is
rejected. Dependency imports execute the already-hashed source bytes, so a
path replacement after hashing cannot alter the executed module.

No `DCB_CONSUMER_PATH` or `MC_OR_SHRM_SYMBOLIC_TARGET` path is promoted.

## Reproduce and validate

```sh
python3 tools/sm8150_dcb_arithmetic_frontier.py \
  --firmware-dir <exact-firmware-dir> \
  --manifest-dir <public-manifest-dir> \
  --output <public-manifest-path>

python3 -m unittest -v tests.test_sm8150_dcb_arithmetic_frontier
python3 -m py_compile tools/sm8150_dcb_arithmetic_frontier.py
```

Publication uses `O_EXCL`, `O_NOFOLLOW` where available, refuses clobbering,
and sets mode `0644`. The checked public manifest is deterministic JSON and
contains no private path, firmware bytes, or secret. Two fresh host manifest
generations were each byte-identical to the checked manifest.

## Final artifacts

| Artifact | Size | SHA-256 |
|---|---:|---|
| Experiment 032 tool | 127,151 | `d4233d08ebe3c28cf803f5e9e1e564f1d9e40af12eca85498d23e569821219e2` |
| Focused tests | 22,710 | `8bb006cb409235bff0b5a2d2fe2a00cae389eb5253124fcd580bb7713df4d3ad` |
| Checked public manifest | 1,564,295 | `beee3cdaa7d69f240310bed8b574f8dd81b00b48c2383f48dd849ebd36fb4b31` |

The classification is `CLASS C (TRANSFORM ONLY)`, mode
`HOST_ONLY_READ_ONLY`, eligibility `NOT_ELIGIBLE`. This experiment does not
authorize live use, a writer/consumer absence statement, a physical
destination claim, or a boundary bypass.
