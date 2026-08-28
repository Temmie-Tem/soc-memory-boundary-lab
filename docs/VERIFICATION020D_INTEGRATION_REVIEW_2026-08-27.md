# Verification 020D second-caller field-use integration review — 2026-08-27

## Boundary and exact inputs

This iteration is host-only and read-only.  No device, ADB, SMC, MMIO,
normal-RAM, protected-memory, partition, or firmware-write operation occurred.
The exact XBL is 4,194,304 bytes with SHA-256
`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.
The helper range `[0x9fc160b8,0x9fc160c4)` is 12 bytes at file offset
`0x0009d088`, SHA-256
`aa23cc5c16d3e14a931184f48199c3891359b3074b3433e0b8a82901bc619ff9`.
The second caller `[0x9fc26e24,0x9fc26e78)` is 84 bytes at file offset
`0x000addf4`, SHA-256
`4c3100f3dff6b8684aa17fc616f6737b283484bb92199dbe98b747a8ab85721d`.
The object range `[0x9fc362c0,0x9fc36300)` is 64 bytes at file offset
`0x000bd290`, SHA-256
`07f284b58048d944e3d6ef2e19438d9d1e04bde32eafb5541f2eabe294af8277`; raw
object bytes are not published.

## Static checks and result

The exact second caller invokes the helper, loads object fields `+0x28`,
`+0x30`, `+0x38`, `+0x0c`, `+0x18`, and `+0x20`, and stores symbolic origins
to static ELF VAs `0x9fc3e138`, `0x9fc3e140`, `0x9fc3e148`, `0x9fc3e150`,
`0x9fc3e158`, and `0x9fc3e160`.  Strict ADRP, ADD/SUB, scalar LDR/STR, LDP
and BL decoders plus exact frame pins are fail-closed; a synthetic extra
helper caller reaches and rejects the cardinality gate.

`PROVED`: the bounded field-use/static-slot edges and exact hashes.
`SUPPORTED`: a second static consumer of the shared 020C object is present.
`HYPOTHESIS`: the shared object and slots may be configuration state.
`UNKNOWN`: runtime values/type/currentness, slot semantics, writer timing,
mutability/locking, indirect paths, physical-to-DRAM mapping, MMIO meaning,
protected reach, aliasing and bypass.

Classification remains `CLASS C (TRANSFORM ONLY)` and eligibility remains
`NOT_ELIGIBLE`; no live authority is implied.

## Validation

Focused tests are 6/6 PASS.  Full serial repository validation is 1,179/1,179
PASS (`skipped=1`) in 117.908 seconds, maximum RSS 297,080 KiB, with zero swap.
Python byte-compilation, deterministic regeneration/byte identity, public JSON
parse, private-path scan, mode and no-clobber checks all PASS.  Live
repetitions, rollback, recovery and target-health receipts are
`NOT_APPLICABLE`.

## Independent hostile review

`PASS`.  The independent reviewer confirmed the exact helper/caller/object
hashes and file offsets, six field-to-static-slot mappings, strict decoder
masks, two-caller census and synthetic extra-caller gate, public redaction,
Class C boundary, and no-device scope.
