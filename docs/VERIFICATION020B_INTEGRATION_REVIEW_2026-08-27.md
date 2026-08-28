# Verification 020B caller-object origin integration review — 2026-08-27

## Boundary and snapshot

This iteration is host-only and read-only for the exact A90/SM8150 evidence
line.  No device, ADB, SMC, MMIO, normal-RAM, protected-memory, partition, or
firmware-write operation was performed.  Live repetitions, rollback, recovery,
and target-health receipts are `NOT_APPLICABLE` because no device state was
contacted.

The retained input is `xbl--sdb1.bin`, 4,194,304 bytes, SHA-256
`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.
The bounded caller body `[0x9fc22cb4,0x9fc22d30)` is 124 bytes with SHA-256
`60e652142c73aec2bc17bef548e00bbb9edcdab08d75dcb3c4e11d0ca72b2162`; the
construction subrange `[0x9fc22cc0,0x9fc22d28)` is 104 bytes with SHA-256
`b9407c190ddb88b0da62a9e2eefb988fa8fe1829ab3b8232f62019cf65d81c08`.

## Exact static checks

The exact consumer entry `[0x9fc023c8,0x9fc023d4)` is hash-pinned to
`3870d341e69765b3f956c106c02dc49d150d3c34998b313dd3dc5951e51d593c`, and the
query and consumer `BL` words are separately hash-pinned.  A full executable
scan finds exactly one direct caller of `0x9fc023c8`, at `0x9fc22d24`.

The finite interpreter validates the frame setup, the opaque-return query call,
the constant `ORR W8,WZR,#1`, all scalar loads/stores, the `Q0` stack transfer,
the `LDP X11,X10` pair ordering, `ADD X0,SP,#0x20`, the consumer call, epilogue,
and the following `RET`.  Stack reads require prior full-width writes; changed
forms, hashes, ranges, direct-caller cardinality, or stack coverage fail closed.

## Data-flow result

`PROVED` within the bounded model:

```text
BL 0x9fc160b8 return X0  -> opaque symbolic token
  +0x0c (32-bit) -> object+0x10 -> W3
  +0x18 (64-bit) -> object+0x18 -> X0
  +0x20 (64-bit) -> object+0x20 -> X1
  +0x28 (64-bit) -> object+0x28 -> X2
```

The manifest keeps each destination `origin` as `UNKNOWN` and stores the field
offset and `MEMORY_FIELD` provenance separately.  No runtime value, object type,
currentness, physical/DRAM mapping, or MMIO interpretation is asserted.

`SUPPORTED`: the exact caller/object edge is reproducible under the finite
linear model.

`HYPOTHESIS`: the helper return may be a runtime configuration object carrying
controller-base-like fields.

`UNKNOWN`: runtime execution and values, type/currentness, alternate or indirect
callers, writer identity outside this edge, static-slot semantics,
physical-to-DRAM mapping, transform mutability/locking, protected reach,
aliasing, and boundary bypass.

Classification remains `CLASS C (TRANSFORM ONLY)` and eligibility remains
`NOT_ELIGIBLE`.  This result authorizes no live action.

## Artifacts and validation

The sanitized manifest is
`evidence/manifests/020B-caller-object-origin-20260827-01.manifest.json`, 18,518
bytes, mode `0644`, SHA-256
`61e5961620d78e766d3fbc586847f76feb0f07991e41326c4b971110cb2a082a`.

The focused suite is 7/7 PASS.  The full serial repository suite is 1,167/1,167
PASS (`skipped=1`) in 116.419 seconds, maximum RSS 296,676 KiB, with zero swap.
Python byte-compilation, deterministic regeneration/byte-identity, public JSON
parse, private-path scan, publication-mode and no-clobber checks all PASS.  No
device action occurred.

## Independent hostile review

`PASS`.  The independent reviewer confirmed the exact XBL/range/file-offset
pins, singleton direct-caller result, scalar and Q0 decoder masks (including
32-bit `ORR` and fixed ADD/SUB bits), stack write/read ordering, field offsets,
manifest redaction, Class C/eligibility boundaries, and no-device boundary.
