# Verification 020J contract — caller-context barrier/opcode inventory

## Objective

Classify the first unsupported instruction at each 020I caller-context stop
using a strict opcode-family inventory, without continuing data-flow past that
barrier.  The discriminator separates ordinary prologue/control/compare forms
from genuinely unknown instruction words while preserving the 020I boundary.

## Snapshot and exact inputs

- Repository HEAD at selection: `6915fb7` (`codex/config-cdt-integration`).
- Working tree: clean before this contract; only exact A90/SM8150 is in scope.
- Exact A90 XBL: `xbl--sdb1.bin`, 4,194,304 bytes,
  SHA-256 `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.
- Exact public 020I dependency:
  `020I-static-slot-caller-context-entry-role-20260827-01.manifest.json`,
  12,472 bytes, SHA-256
  `03c463f667142a21641264ec2e4080d9d5f963c67776037ca9d6194a8a621608`.

## Bounded action

Reopen the exact 020I manifest with regular-file and `O_NOFOLLOW` checks,
re-derive the exact XBL callsite set, and inspect only the `stop_va` word for
rows whose stop reason is `UNSUPPORTED`.  Recognize only strict, independent
opcode families: `CMP`/`SUBS`, `B.cond`, `CBZ`/`CBNZ`, `TBZ`/`TBNZ`,
`MOVZ`/`MOVK`/`MOVN`, `LDP`/`STP`, `ADRP`, scalar/register-offset memory,
flagless `ADD`/`SUB`, `MADD`, register copies, `RET X30`, direct `B`, and
direct `BL`.  A word matching none is retained as `UNKNOWN_OPCODE`.

Do not trace beyond the first stop or reinterpret a barrier as a call graph.
Record the stop VA, a family label, decoder width/operands only where proven,
and a SHA-256 of the inspected word.  Do not publish raw firmware bytes or
private paths.  No static word is promoted to a runtime pointer, PA, MMIO,
controller register, DRAM coordinate, ownership state, or bypass primitive.
There is no device, ADB/ACM, SMC, MMIO, normal-RAM, protected-memory,
partition, firmware, or controller write.

## Expected and negative results

Expected evidence is a deterministic inventory of 020I unsupported stops,
with common ARM64 families separated from `UNKNOWN_OPCODE`.  For the retained
XBL the expected family counts are `B_COND=5`, `CBZ_CBNZ=2`,
`LDP_STP_PAIR=2`, `LOGICAL_OR_BITMASK_IMMEDIATE=2`, and `BITFIELD=1`, with
12 unique stop VAs and zero fallback rows.  Negative tests must cover
family-mask collisions, wrong widths/operands, stop-VA mutation, dependency
hash drift, exact unsupported-row cardinality, public redaction, and
no-clobber publication.  This inventory alone cannot change `CLASS C`.

## Stop, rollback, and disclosure

Missing/hash-drifted inputs, changed 020I stop cardinality, ambiguous mapping,
device endpoint, or any security-boundary indicator stops the run.  No device
state exists in this host-only pass, so repetitions, rollback, recovery and
target-health receipts are `NOT_APPLICABLE`.  Any protected-memory or writable
transform implication remains disclosure-gated and is not followed here.

## Selection rationale

020I's main residual is not a missing callsite but 12 fail-closed unsupported
barriers.  Classifying only those exact words is cheaper and non-overlapping
with the caller-context trace, and it can convert some `UNKNOWN` barriers into
ordinary control/prologue evidence without extending the taint model.
