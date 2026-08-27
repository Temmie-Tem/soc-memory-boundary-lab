# Verification 020A — setter/base argument trace (2026-08-27)

This is a host-only, read-only follow-on to the earlier 020A/027 XBL
cross-reference.  It asks whether the pinned candidate setter's non-zero stores
can be resolved to a runtime base argument without inventing a current MMIO or
physical address.

## Exact scope

The analyzer binds the retained A90 XBL `xbl--sdb1.bin` by size 4,194,304 and
SHA-256
`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.  It then
checks the exact setter range `[0x9fc06410,0x9fc0643c)` (44 bytes, hash
`4f90392f2e5c34415ad0bb4709227445f3cad1d2444b57a90fa645f1488e063a`) and its
single direct `BL` caller at `0x9fc023f0`.  Only the 20-byte pre-call block
`[0x9fc023e0,0x9fc023f4)` and its 92-byte context are decoded.

Recognized forms are limited to register-only `MOV`, unsigned `LDR` W/X,
unsigned-offset 64-bit `LDP`, and direct `BL`.  An unresolved base, unsupported
instruction, changed range hash, or changed caller cardinality fails closed.
No indirect `BR/BLR`, runtime execution, type inference, or register value is
promoted.

## Result

`PROVED`:

- the setter contains five static global stores: one `XZR` zero and four
  argument-sourced stores from `X0`, `X1`, `X2`, and `W3`;
- the exact XBL has one direct caller of that setter;
- the caller block sources those arguments from an opaque incoming `X0` object:
  `W3=[X0+0x10]`, `X0=[X0+0x18]`, `X1=[X0+0x20]`, and `X2=[X0+0x28]`;
- the trace is symbolic and assigns no current physical, DRAM, or MMIO value.

`SUPPORTED`: the setter-to-caller edge is reproducible in this exact linear
model, and the static slots remain compatible with the prior candidate DDR
segment inference.  That segment identity is not a symbol proof.

`HYPOTHESIS`: the incoming object may carry controller-base-like fields.

`UNKNOWN`: runtime object origin and values, boot execution/currentness, field
type and register semantics, alternate/indirect callers, post-boot mutability
or locks, physical-to-DRAM mapping, protected-memory reach and alias/bypass.

Classification remains `CLASS C (TRANSFORM ONLY)` and eligibility remains
`NOT_ELIGIBLE`.  This result does not authorize a device, MMIO, SMC, controller,
normal-RAM, protected-memory, or partition action.

The sanitized manifest is
`evidence/manifests/020A-setter-base-trace-20260827-01.manifest.json`, 9,171
bytes, mode `0644`, SHA-256
`edf62eb6c1d97a8113f5ba0894548e9d5fafc83eeefbc7976c808b0f7886c051`.

## Validation

The focused suite is 9/9 PASS; the full serial repository suite is 1,160/1,160
PASS (`skipped=1`) in 116.197 seconds, maximum RSS 290,560 KiB, with zero swap.
Python byte-compilation, exact-image rebuild,
public JSON parse, no-private-path scan, byte-identical regeneration and
no-clobber publication checks pass.  Live repetitions, rollback, recovery and
target-health receipts are `NOT_APPLICABLE` because no device state was
contacted or changed.

Reproduction template:

```text
python3 tools/sm8150_xbl_setter_base_trace_020a.py \
  --output evidence/manifests/020A-setter-base-trace-20260827-01.manifest.json
python3 -m unittest -v tests.test_sm8150_xbl_setter_base_trace_020a
```
