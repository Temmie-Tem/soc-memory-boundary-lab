# Verification 020K contract — caller-context barrier operands and targets

## Objective

Inspect the first unsupported instruction word at each of the twelve exact
020J stop rows.  Decode only bounded operand fields and, for conditional
branches, the signed local target.  This is a metadata follow-up; it must not
continue the 020I/020J trace or promote an instruction shape to a writer,
physical address, DRAM coordinate, or security-boundary primitive.

## Snapshot and exact inputs

- Selection parent: `b8b2e3d` on `codex/config-cdt-integration`.
- Target: A90 5G `SM-A908N`, Qualcomm `SM8150` / Snapdragon 855 only.
- Exact XBL `xbl--sdb1.bin`: 4,194,304 bytes, SHA-256
  `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.
- Exact 020J manifest: 7,657 bytes, SHA-256
  `1fdb1f4ade702fdb2d6ffdc68669a9710c8152e225f89f02fb65c0d10f4c3d55`.
- Exact 020J producer source: 13,337 bytes, SHA-256
  `4ab87464f17bc8887e62c5bb4eba7c693b2ec299575fc38f8bd9f7847c50dc1b`.

The firmware, dependency manifest and producer source are opened through
regular-file, `O_NOFOLLOW`, size/stability and SHA-256 checks.  Raw firmware
words are retained only as per-word hashes in the public manifest.

## Bounded action and expected result

Re-derive the exact 020J stop set from the pinned XBL and manifest, require 12
unique `UNSUPPORTED` rows with the known family split, then inspect one word at
each stop:

- `B.cond`: condition, signed `imm19`, raw immediate and target VA.
- `CBZ`/`CBNZ`: `sf`, operation bit, register, signed `imm19` and target VA.
- scalar GPR `LDP`/`STP`: `opc`, `L`, addressing mode, signed `imm7`, scaled
  byte offset and `Rn/Rt/Rt2`; vector and reserved width forms fail closed.
- logical-immediate: `sf`, `N`, `op`, `S`, `immr`, `imms`, `Rn/Rd`; width/N
  mismatches and reserved 32-bit forms fail closed.
- bitfield (the retained word is `BFXIL`): `sf`, `opc`, `N`, `immr`, `imms`,
  `Rn/Rd`, with width and reserved encodings rejected.

Every branch target must be four-byte aligned and remain in the same
file-backed executable segment as its stop.  The expected split is
`B_COND=5`, `CBZ_CBNZ=2`, `LDP_STP_PAIR=2`,
`LOGICAL_OR_BITMASK_IMMEDIATE=2`, `BITFIELD=1`.

## Negative controls and stop gates

Focused tests must reject changed dependency/tool hashes, stop cardinality or
identity, stop-word hashes, family-mask collisions, vector/reserved-width
forms, unaligned targets and targets outside the executable segment.  A missing
or changed source, ambiguous segment, unsupported family, or private-path
leak stops the run.  Publication is deterministic and no-clobber with mode
`0644`.

No ADB/ACM, reboot, device, SMC, SCM, MMIO, controller, normal-RAM,
protected-memory, partition or firmware write is permitted.  Runtime
execution, true function boundaries, register semantics, currentness,
physical/DRAM identity, mutability, ownership and alias/bypass remain
`UNKNOWN` unless separately proven.

## Classification and recovery

The expected outcome is `CLASS C (TRANSFORM ONLY)` and `NOT_ELIGIBLE`.  This
host-only pass has no device state, so rollback, recovery, repetitions and
target-health receipts are `NOT_APPLICABLE`.  Any security-boundary indicator
would stop the pass and switch to the disclosure gate; no follow-up write is
authorized by this contract.
