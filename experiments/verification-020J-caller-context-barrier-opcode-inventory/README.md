# Verification 020J — caller-context barrier/opcode inventory (2026-08-27)

This host-only, read-only follow-up inspects only the first unsupported
instruction word at each of the twelve exact 020I caller-context barriers.  It
reopens and hashes the public 020I manifest, re-derives the 020I callsite set
from the exact A90 XBL, and does not continue the 020I trace past any stop.

The decoder recognizes only strict ARM64 opcode families whose masks and
operand fields are bounded in the source: `CMP`/`SUBS`, `B.cond`, `CBZ`/`CBNZ`,
`TBZ`/`TBNZ`, `MOVZ`/`MOVK`/`MOVN`, scalar `LDP`/`STP` pairs, bitfield and
logical-immediate forms, `ADRP`, scalar/register-offset memory, flagless
`ADD`/`SUB`, `MADD`, register copies, `RET X30`, direct `B`, and direct `BL`.
Anything outside those masks remains `UNKNOWN_OPCODE`.

## Exact scope and pins

The retained A90 XBL `xbl--sdb1.bin` is bound by size 4,194,304 and SHA-256
`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.
The exact public 020I manifest is opened with `O_NOFOLLOW`, checked as a
regular file, parsed as JSON, and bound to SHA-256
`03c463f667142a21641264ec2e4080d9d5f963c67776037ca9d6194a8a621608`.

## Result

All 12 unsupported 020I stop rows have unique stop VAs and match a strict
family: five `B_COND`, two `CBZ_CBNZ`, two `LDP_STP_PAIR` (offset and
pre-index forms), two `LOGICAL_OR_BITMASK_IMMEDIATE`, and one `BITFIELD`
(the `BFXIL` encoding).  No stop required the `UNKNOWN_OPCODE` fallback.
The inventory records only family metadata and a SHA-256 of each little-endian
word; raw firmware bytes and private paths are not published.

`PROVED`: the exact 020I unsupported-stop set, its 12/12 cardinality and the
bounded family split under the implemented masks.  `SUPPORTED`: the words are
ordinary control/prologue/bitfield encodings within this finite static model.
`HYPOTHESIS`: the barriers may be ABI/prologue/control artifacts rather than
controller programming.  `UNKNOWN`: instruction semantics beyond family
labels, true function boundaries, runtime execution/currentness/values,
indirect paths, object meaning, MMIO/physical/DRAM identity,
mutability/locking, protected reach, aliasing and bypass.

Classification remains `CLASS C (TRANSFORM ONLY)` and eligibility remains
`NOT_ELIGIBLE`.  No device, ADB/ACM, SMC, MMIO, normal-RAM,
protected-memory, partition, firmware-write, or controller-write action was
performed.

## Artifacts and reproduction

The sanitized manifest is
`evidence/manifests/020J-caller-context-barrier-opcode-inventory-20260827-01.manifest.json`.
Focused/full validation, deterministic regeneration, artifact hashes,
redaction and independent hostile-review status are recorded in the
integration review.

```text
python3 tools/sm8150_xbl_caller_context_barrier_opcode_inventory_020j.py \
  --output evidence/manifests/020J-caller-context-barrier-opcode-inventory-20260827-01.manifest.json
python3 -m unittest -v tests.test_sm8150_xbl_caller_context_barrier_opcode_inventory_020j
```
