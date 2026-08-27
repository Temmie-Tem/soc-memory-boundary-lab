# Verification 020F static-slot load-use integration review — 2026-08-27

## Boundary and exact inputs

This iteration is host-only and read-only.  No device, ADB, SMC, MMIO,
normal-RAM, protected-memory, partition, or firmware-write operation occurred.
The exact XBL is 4,194,304 bytes with SHA-256
`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.
The 020E sanitized-manifest dependency is pinned by SHA-256
`4c28b0cc0a113e099fe3b0ce2bd16a77ce0c9d9bfc799ca9494c52eed9c349ad`.

## Static checks and result

The tool re-derives and exact-matches the twelve 020E direct scalar load seeds,
then follows each for at most 16 instructions in its same executable segment.
Only strict scalar/register-offset memory, arithmetic, register-copy,
predicate, return, and control-transfer forms are admitted.  Caller-saved
direct `BL` is a barrier; continuation across X19–X29 is conditional on
AAPCS64 callee preservation.  Unknown forms stop the local trace.

The exact XBL yields 16 recognized downstream use events: 10 address-base
uses, 2 arithmetic uses, 2 register-offset address uses, 1 register copy, and
1 return use.  It also yields 11 barriers: 4 caller-saved `BL`, 5 recognized
generic control, and 2 unknown-instruction barriers.  No tainted direct store
is reached in the supported windows.

`PROVED`: exact pins and the bounded per-seed event set.  `SUPPORTED`: several
slot values feed local address formation/arithmetic in the model.  `HYPOTHESIS`:
some values may be object pointers or local configuration fields.  `UNKNOWN`:
global writer/consumer absence, ABI compliance/callee effects, runtime
execution/currentness/values, slot semantics, MMIO/physical/DRAM identity,
mutability/locking, protected reach, aliasing, and bypass.

Classification remains `CLASS C (TRANSFORM ONLY)` and eligibility remains
`NOT_ELIGIBLE`; no live authority is implied.

## Validation

Focused tests are 9/9 PASS.  The full serial repository suite is 1,195/1,195
PASS (`skipped=1`) in 123.910 seconds, maximum RSS 342,272 KiB, with zero
swap.  Python byte-compilation, deterministic regeneration/byte identity,
public JSON parse, private-path scan, mode `0644`, and no-clobber checks all
PASS.  The sanitized manifest is 13,069 bytes with SHA-256
`d19687581d046c7b05841aef6340e9a1e3664c69e19903689d1c583aee5b9764`.
Artifact SHA-256 values are tool
`b1f12fb516b52e3b15168e61930d407f08788dd2379fa330b9f2220fc2cf3a53`, tests
`d26fd34586f8d0ed8f65ad63def95b5c9b140129eeffa6ba483e1fac903ef805`, and
experiment README
`92771447e4af092a55ae58f769f38b789dcd1cb341cf1541e3f6471f15987490`.
Live repetitions, rollback, recovery, and target-health receipts are
`NOT_APPLICABLE`.

## Independent hostile review

`PASS`.  The independent reviewer confirmed the exact 020E seed/dependency
pins, strict decoder masks, caller-saved X0–X18/X30 barriers, conditional
X19–X29 call handling, MOVK fail-closed partial-kill behavior, CBNZ/TBNZ
coverage, bounded event accounting, public redaction, Class C boundary,
no-clobber publication, and no-device scope.
