# Verification 020E static-slot census integration review — 2026-08-27

## Boundary and exact inputs

This iteration is host-only and read-only.  No device, ADB, SMC, MMIO,
normal-RAM, protected-memory, partition, or firmware-write operation occurred.
The exact XBL is 4,194,304 bytes with SHA-256
`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.

The analysis is tied to the exact 020C helper
`[0x9fc160b8,0x9fc160c4)` (`aa23cc5c16d3e14a931184f48199c3891359b3074b3433e0b8a82901bc619ff9`),
020D caller `[0x9fc26e24,0x9fc26e78)`
(`4c3100f3dff6b8684aa17fc616f6737b283484bb92199dbe98b747a8ab85721d`), and
020D object `[0x9fc362c0,0x9fc36300)`
(`07f284b58048d944e3d6ef2e19438d9d1e04bde32eafb5541f2eabe294af8277`).

## Static checks and result

The bounded model matches only direct unsigned scalar `LDR`/`STR` accesses
whose base register is defined by an `ADRP` to page `0x9fc3e000` within an
eight-instruction window.  Recognized page-register definitions terminate the
window; unknown forms are retained as barriers rather than treated as
negative evidence.  Direct `BL` is a barrier for caller-saved page registers;
the model continues across X19–X29 only under an explicit AAPCS64
callee-saved assumption.  The exact retained XBL yields 18 unique accesses:
six stores and twelve loads, with 95 recorded barriers (eight caller-saved
`BL` barriers and 87 unknown-instruction barriers).

`PROVED`: exact pins and this bounded recognized access set.  `SUPPORTED`: the
six 020D slots have additional statically visible direct uses, with the
callee-saved-call continuation explicitly conditional on AAPCS64.  `HYPOTHESIS`:
the slots may be shared configuration state.  `UNKNOWN`: global writer or
consumer absence, ABI compliance/callee side effects, runtime
values/currentness/execution, semantics and type, indirect paths,
MMIO/physical/DRAM mapping, mutability/locking, protected reach, aliasing,
and bypass.

Classification remains `CLASS C (TRANSFORM ONLY)` and eligibility remains
`NOT_ELIGIBLE`; no live authority is implied.

## Validation

Focused tests are 7/7 PASS.  The full serial repository suite is 1,186/1,186
PASS (`skipped=1`) in 119.090 seconds, maximum RSS 343,404 KiB, with zero
swap.  Python byte-compilation, deterministic regeneration/byte identity,
public JSON parse, private-path scan, mode `0644`, and no-clobber checks all
PASS.  The sanitized manifest is 29,826 bytes with SHA-256
`4c28b0cc0a113e099fe3b0ce2bd16a77ce0c9d9bfc799ca9494c52eed9c349ad`.
Artifact SHA-256 values are tool
`a026b3af90ce47af590342ff79a34c667464571f3d3a055c50d381c63c26c946`, tests
`ecdf4d10166eafb9d34d808d4390538c798d3225e851f60cb8082fd5b1dd7672`, and
experiment README
`4cd0d278b159bccb22fcd71c29c72ef59325d77a9296bf46ce7ba878c492d985`.
Live repetitions, rollback, recovery, and target-health receipts are
`NOT_APPLICABLE`.

## Independent hostile review

`PASS`.  The independent reviewer confirmed the exact input/dependency pins,
the 18-row 6-store/12-load split, caller-saved `BL` fail-closed behavior,
explicit AAPCS64 callee-saved assumption, barrier accounting, public
redaction, Class C boundary, no-clobber publication, and no-device scope.
