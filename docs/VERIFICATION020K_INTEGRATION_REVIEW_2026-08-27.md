# Verification 020K integration review — 2026-08-27

## Scope and source pins

This review covers the bounded 020K operand/target inventory only.  It uses
the exact A90 `SM-A908N` / `SM8150` XBL and the retained 020J producer/manifest;
it does not replace 020J or extend its trace.  No device, USB, reboot, SMC,
SCM, MMIO, controller, RAM, protected-memory, partition or firmware action
occurred.

| Artifact | Size | SHA-256 |
|---|---:|---|
| `tools/sm8150_xbl_caller_context_barrier_operand_target_inventory_020k.py` | 19,309 | `efe1a4dd062bd76adfe3f535f441e86fc74a36c105433c884296f648ae5e4ae1` |
| `tests/test_sm8150_xbl_caller_context_barrier_operand_target_inventory_020k.py` | 8,698 | `1e562e4c543d96efc5aaea92ee94a04e61066f04c099f8a95b62c79a5ed5b3d8` |
| `experiments/verification-020K-caller-context-barrier-operand-target/README.md` | 3,051 | `c9be440b93b5739a1bbb4cd26c9ee6684d279928f2f4632970b914f92367f306` |
| `docs/VERIFICATION020K_CONTRACT_2026-08-27.md` | 3,311 | `867f58232d4c89ffff18eedeb4d78ac43886a954800a2619c337d2a5428e7d7c` |
| `evidence/manifests/020K-caller-context-barrier-operand-target-inventory-20260827-01.manifest.json` | 9,961 | `90a0cf4d264c64d0d2836b567a2dc8ac5abff7809be839e5131fc7e91e32975a` |

The dependency pins are the 4,194,304-byte XBL
`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`, the
13,337-byte 020J source
`4ab87464f17bc8887e62c5bb4eba7c693b2ec299575fc38f8bd9f7847c50dc1b`, and
the 7,657-byte 020J manifest
`1fdb1f4ade702fdb2d6ffdc68669a9710c8152e225f89f02fb65c0d10f4c3d55`.

## Independent checks

The implementation re-derived the 020J stop set and required 12 unique
`UNSUPPORTED` rows with family counts `B_COND=5`, `CBZ_CBNZ=2`,
`LDP_STP_PAIR=2`, `LOGICAL_OR_BITMASK_IMMEDIATE=2`, and `BITFIELD=1`.
It decoded one word per stop, recorded only word hashes, and checked every
conditional target for four-byte alignment and same executable file-backed
segment.  Pair decoding covers scalar width, load/store, addressing mode and
scaled signed offset; logical/bitfield decoders reject reserved width/N forms.

Focused validation is **13/13 PASS** after Python byte-compilation.  Mutation
negatives cover dependency/tool hashes, stop cardinality/VA, word hashes,
family masks, reserved encodings, target alignment/segment and no-clobber
publication.  Deterministic regeneration is byte-identical to the retained
9,961-byte mode-`0644` manifest.  No raw words, private paths or secrets are
published.

After the local XBL-pin repair, the full repository discovery suite ran once
serially: **1,288/1,288 PASS**, `skipped=1`, elapsed 180.173 s, maximum RSS
363,772 KiB, swap 0, exit status 0.  `git diff --check` passed.  The
independent hostile review rechecked the repaired local firmware loader,
source pins, decoder masks, target gates, redaction and no-device boundary and
returned `PASS`.

`PROVED`: the bounded operand fields and local branch-target metadata for the
exact 020J stops.  `SUPPORTED`: ordinary control/prologue/bitfield shape in
this finite static model.  `UNKNOWN`: instruction effects, branch execution,
true function boundaries, runtime values/currentness, indirect paths,
physical/MMIO/DRAM identity, mutability/locking, protected reach, aliasing and
bypass.  `CLASS C (TRANSFORM ONLY)` and `NOT_ELIGIBLE` remain unchanged.

## Hostile-review disposition

`PASS`.  The reviewer found and required repair of the initial provenance
defect (the 020K XBL constants were declared but the imported 020D loader was
used); the current local `_read_pinned` path and its XBL-hash mutation negative
close that issue.  The review found no remaining blocker.  No live follow-up
is authorized by this artifact.
