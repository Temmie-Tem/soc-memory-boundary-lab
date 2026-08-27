# Verification 020C return-helper origin integration review — 2026-08-27

## Boundary and exact inputs

This iteration is host-only and read-only.  No device, ADB, SMC, MMIO,
normal-RAM, protected-memory, partition, or firmware-write operation occurred.
The exact XBL is 4,194,304 bytes with SHA-256
`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.

The helper `[0x9fc160b8,0x9fc160c4)` is 12 bytes, file offset `0x0009d088`,
SHA-256
`aa23cc5c16d3e14a931184f48199c3891359b3074b3433e0b8a82901bc619ff9`.
The returned-object source range `[0x9fc362c0,0x9fc362f0)` is 48 bytes, file
offset `0x000bd290`, SHA-256
`29dfe1d501b1842425aae853943382cf45a0eb6929aab0a78eb5ad745418a649`.
Only its hash is published; raw object bytes/values are not.

## Static checks and result

The exact helper words decode as `ADRP X0,0x9fc36000`, `ADD X0,X0,#0x2c0`,
`RET`, yielding static ELF VADDR `0x9fc362c0`.  An executable PT_LOAD census
finds exactly two direct `BL` callers: `0x9fc22cc0` and `0x9fc26e2c`.  Strict
decoders reject wrong ADRP/BL forms, 32-bit/undefined ADD/SUB encodings, and
changed hashes; a synthetic extra-caller test reaches and rejects the
cardinality gate.

`PROVED`: the bounded static return-address construction, two direct callers,
and hash-pinned source range.  `SUPPORTED`: this identifies the static source
used by 020B and a second consumer path.  `HYPOTHESIS`: the object may be a
shared configuration carrier.  `UNKNOWN`: runtime execution and contents,
object type/currentness, writer/mutability/locking, indirect callers,
physical-to-DRAM mapping, MMIO semantics, protected reach, aliasing and bypass.

Classification remains `CLASS C (TRANSFORM ONLY)` and eligibility remains
`NOT_ELIGIBLE`; no live authority is implied.

## Validation

Focused tests are 6/6 PASS.  Full serial repository validation is 1,173/1,173
PASS (`skipped=1`) in 117.851 seconds, maximum RSS 297,324 KiB, with zero swap.
Python byte-compilation, deterministic regeneration/byte identity, public JSON
parse, private-path scan, mode and no-clobber checks all PASS.  Live
repetitions, rollback, recovery and target-health receipts are
`NOT_APPLICABLE`.

## Independent hostile review

`PASS`.  The independent reviewer confirmed the exact helper/object ranges and
file offsets, ADRP+ADD target `0x9fc362c0`, two direct callers, strict decoder
rejection and synthetic cardinality gate, public redaction, Class C boundary,
and no-device scope.
