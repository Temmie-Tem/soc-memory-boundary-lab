# Verification 020I contract — bounded caller-context/entry-role trace

## Objective

Test whether the direct `BL` source sites recorded by 020H are reached from a
bounded initialization/helper caller context with statically recognizable
argument preparation, or whether the caller evidence remains unsupported.  The
trace is deliberately caller-context only: it does not claim a true function
boundary, runtime execution, pointer value, physical address, MMIO identity,
DRAM destination, ownership, or bypass.

## Snapshot and exact inputs

- Repository HEAD at selection: `88e497c` (`codex/config-cdt-integration`).
- Working tree: clean before this contract; only the exact A90/SM8150 target is
  in scope.  S20+ and S22+ remain untouched and out of scope.
- Exact A90 XBL: `xbl--sdb1.bin`, 4,194,304 bytes,
  SHA-256 `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.
- Exact public 020H dependency:
  `020H-static-slot-function-role-base-origin-20260827-01.manifest.json`,
  19,314 bytes, SHA-256
  `b306ca67675430314289fd79faa2e53b2d67994807d0b08bd91ced9b625faba2`.

## Bounded action

The implementation must reopen both exact inputs with regular-file and
`O_NOFOLLOW` checks, re-derive the 020H role rows, and analyze only the
file-backed executable words immediately preceding each 020H
`block_entry_direct_bl_sources` call site.  A caller window is at most 16
instructions and stops at a strict `RET`, direct `B`, direct `BL`, unsupported
instruction, segment boundary, or ambiguous mapping.

Only strict forms needed for argument-context labels may be recognized:
`RET X30`, direct `B`, direct `BL`, unsigned scalar and `UXTX` register-offset
`LDR`/`STR`, `ADRP`, flagless `ADD`/`SUB`, `MADD`, and register copies.  The
trace may record definitions of X0–X3 and the 020H static-slot page, but all
other values remain symbolic/unknown.  Each callsite row must retain the
source VA, target block entry, bounded window boundary, recognized definitions,
and one of `STATIC_SLOT_ORIGIN`, `ARGUMENT_COPY_OR_CONSTANT`,
`CALLER_CONTEXT_UNSUPPORTED`, or `ARGUMENT_OR_UNKNOWN`.

No static caller or target may be promoted to a true function, runtime
pointer, PA, MMIO aperture, controller register, DRAM coordinate, or security
primitive.  There is no device contact, ADB/ACM action, SMC, MMIO,
normal-RAM, protected-memory, partition, firmware, or controller write.

## Expected and negative results

Expected positive evidence is a deterministic census of the 020H direct-BL
source sites and any strictly recognized argument/static-slot origins.
Expected negative evidence is an explicit fail-closed row for unsupported
instructions, indirect paths, non-unique boundaries, or mutated opcode/target
data.  A caller-context result does not change `CLASS C (TRANSFORM ONLY)`.

Synthetic tests must cover B-versus-BL discrimination, RET-link-register
validation, unsupported/ambiguous instructions, source/target mutation,
dependency hash drift, exact callsite cardinality, public redaction, and
no-clobber publication.

## Stop, rollback, and disclosure

Any missing exact input, hash drift, unexpected callsite count, ambiguous
executable mapping, device endpoint, or potential security-boundary indicator
stops the run.  This iteration has no device state, so live repetitions,
rollback, recovery, and target-health receipts are `NOT_APPLICABLE`.  If a
caller context appears to reach a protected-memory or writable-transform path,
stop before mutation and move to disclosure-gated handling.

## Selection rationale

020H showed that the 020G accesses sit in a small helper/object-shaped code
cluster and exposed the exact direct-BL source VAs used as block-entry
contexts.  Tracing those source sites is non-overlapping with the 020H block
partition and base-origin pass, is host-only, and tests whether the apparent
local role survives one caller edge.  It preserves unknown function boundaries
and indirect paths rather than treating a direct callsite as a complete call
graph.
