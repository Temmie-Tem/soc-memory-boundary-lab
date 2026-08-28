# Verification 020K — caller-context barrier operands and targets

This is a host-only, read-only continuation of 020J.  It inspects exactly one
little-endian instruction word at each of the twelve 020J `UNSUPPORTED` stop
VAs.  It does not continue control flow or data flow past a stop, contact the
A90, or access a device/controller/security interface.

## Exact inputs

- A90/SM8150 XBL `xbl--sdb1.bin`: 4,194,304 bytes,
  SHA-256 `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.
- 020J producer source: 13,337 bytes,
  SHA-256 `4ab87464f17bc8887e62c5bb4eba7c693b2ec299575fc38f8bd9f7847c50dc1b`.
- 020J public manifest: 7,657 bytes,
  SHA-256 `1fdb1f4ade702fdb2d6ffdc68669a9710c8152e225f89f02fb65c0d10f4c3d55`.

All inputs are opened as regular files with no-follow, size/stability and
SHA-256 checks.  Raw instruction words are represented publicly only by
per-word hashes.

## Bounded result

The twelve rows retain the exact 020J family split:

| Family | Count | Bounded metadata |
|---|---:|---|
| `B_COND` | 5 | condition, signed `imm19`, aligned target |
| `CBZ_CBNZ` | 2 | width/op, `Rt`, signed `imm19`, aligned target |
| `LDP_STP_PAIR` | 2 | `L`/`opc`, scalar width, offset/pre-index mode, scaled `imm7`, `Rn/Rt/Rt2` |
| `LOGICAL_OR_BITMASK_IMMEDIATE` | 2 | `sf`/`N`/`op`/`S`, `immr`/`imms`, `Rn/Rd` |
| `BITFIELD` (`BFXIL` alias) | 1 | `sf`/`opc`/`N`, `immr`/`imms`, `Rn/Rd` |

All decoded conditional targets are four-byte aligned and remain in the same
file-backed executable segment as their stop.  The two pair words are scalar
64-bit `STP` forms: one offset `+64` and one pre-index `-16`.  The two logical
words are identical 32-bit immediate forms (`orr w0, wzr, #2` by independent
disassembly), and the bitfield word is the 32-bit `BFXIL` encoding.  Those
descriptions are instruction-shape observations only, not execution claims.

`PROVED`: exact source pins, 12/12 stop identity, family counts, operand-field
decoding and local target-segment checks.  `SUPPORTED`: the finite metadata is
consistent with ordinary control/prologue/bitfield shapes.  `UNKNOWN`:
instruction effects and branch execution, true function boundaries, runtime
values/currentness, indirect paths, MMIO/physical/DRAM identity,
mutability/locking, protected reach, aliasing and bypass.  Classification
remains `CLASS C (TRANSFORM ONLY)` and eligibility `NOT_ELIGIBLE`.

## Validation and boundary

The tool is
`tools/sm8150_xbl_caller_context_barrier_operand_target_inventory_020k.py` and
the focused suite is
`tests/test_sm8150_xbl_caller_context_barrier_operand_target_inventory_020k.py`.
The public manifest is
`evidence/manifests/020K-caller-context-barrier-operand-target-inventory-20260827-01.manifest.json`.
Python compilation, 13 focused tests, deterministic regeneration,
redaction, no-clobber publication and mutation negatives pass.  No ADB/ACM,
reboot, SMC, SCM, MMIO, normal-RAM, protected-memory, partition, firmware or
controller write occurred; rollback, recovery, repetitions and target health
are `NOT_APPLICABLE`.
