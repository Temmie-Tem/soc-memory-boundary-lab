# Verification 020H contract — bounded static-slot function-role/base-origin trace

## Objective

Determine whether the 020G address-use witnesses are contained in a bounded
family of local, return-delimited code blocks with statically recoverable base
origins, or whether the retained instruction shapes require a controller-like
role.  This is a discriminator for static function/data role only.  It is not
a runtime pointer, physical-address, MMIO, DRAM, ownership, or bypass test.

## Snapshot and exact inputs

- Repository HEAD at selection: `1235ddc` (`codex/config-cdt-integration`).
- Working tree: clean before this contract; no other device experiment is
  active.  S20+ and S22+ remain out of scope.
- Exact A90 XBL: `xbl--sdb1.bin`, 4,194,304 bytes,
  SHA-256 `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.
- Exact public 020G dependency:
  `020G-static-slot-pointer-object-census-20260827-01.manifest.json`, 7,218
  bytes, SHA-256
  `f534efeee1e12f18d3af40c107dbc6fbe938eae16d9013aa088d22d7c880af3e`.

Private firmware bytes remain private; public outputs contain hashes and
redacted reproduction templates only.

## Bounded action

The implementation must reopen both exact inputs with regular-file and
`O_NOFOLLOW` checks, re-decode the 020G access set, and analyze only the
file-backed executable region covering the 020G witnesses and their local
seed/return context.  The model may recognize only strict AArch64 forms
needed for this trace: `RET`, direct `BL`, unsigned scalar and `UXTX`
register-offset `LDR`/`STR`, `ADRP`, flagless `ADD`/`SUB`, `MADD`, and register
copies.  Unsupported or ambiguous forms terminate the local trace
fail-closed.

For every unique 020G access VA, publish a bounded row containing:

1. the access shape and exact seed-slot provenance already pinned by 020G;
2. a return-delimited local block boundary, or `UNKNOWN_BOUNDARY` when the
   strict model cannot establish one;
3. direct `BL` targets inside the block and a complete executable-image
   direct-caller census for the block entry when a unique entry is established;
4. a backward base-register classification over at most 16 instructions:
   `STATIC_SLOT_SEED`, `ARITHMETIC_DERIVED`, `ARGUMENT_OR_UNKNOWN`, or
   `UNSUPPORTED_BOUNDARY`, with defining VAs and source registers where the
   decoder proves them.

No static VA or symbolic base may be promoted to a runtime pointer, PA, MMIO
aperture, controller register, DRAM coordinate, or security primitive.
There is no device contact, ADB/ACM action, SMC, MMIO, normal-RAM, protected
memory, partition, firmware, or controller write in this iteration.

## Expected and negative results

Expected positive evidence is a deterministic local block/role census with
some base definitions traceable to the already pinned static-slot seeds.
Expected negative evidence is an explicit fail-closed row for any unsupported
boundary, indirect call, non-unique entry, or mutated opcode/register.  A
successful role census does not change `CLASS C (TRANSFORM ONLY)`.

The implementation must include synthetic tests for wrong `RET`/`BL` targets,
unsupported instructions, base-register mutations, dependency-hash drift,
public redaction, and no-clobber publication.  Aggregate counts must be
checked against the exact 020G unique-access set; malformed or duplicated
rows must fail closed.

## Stop, rollback, and disclosure

Any missing exact input, hash drift, ambiguous executable mapping, unexpected
device endpoint, or potential security-boundary indicator stops the run.  This
host-only iteration has no device state, so rollback, recovery, live
repetitions, and target-health receipts are `NOT_APPLICABLE`.  If the result
suggests a protected-memory reach or a writable transform, stop before any
follow-up mutation and move to disclosure-gated handling.

## Selection rationale

020G established 12 instruction-shape witnesses but left the enclosing role
and base-definition path unresolved.  This trace is non-overlapping with the
020G re-decode, cheaper and safer than live observation, and directly tests
whether the apparent pointer/object family is a local code/data role.  It does
not claim global writer/consumer absence or controller identity.
