# Verification 020C — return-helper origin trace (2026-08-27)

This host-only, read-only experiment follows the opaque return consumed by
Verification 020B.  It asks only what the exact helper instruction sequence
constructs and how many direct callers are visible in the retained XBL.

## Exact scope and pins

The retained A90 XBL `xbl--sdb1.bin` is bound by size 4,194,304 and SHA-256
`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.
The helper range `[0x9fc160b8,0x9fc160c4)` is 12 bytes with SHA-256
`aa23cc5c16d3e14a931184f48199c3891359b3074b3433e0b8a82901bc619ff9`.
The object-field source range needed by 020B, `[0x9fc362c0,0x9fc362f0)`, is
48 bytes and is hash-pinned without publishing its raw bytes:
`29dfe1d501b1842425aae853943382cf45a0eb6929aab0a78eb5ad745418a649`.

## Result

`PROVED`:

- `0x9fc160b8` is exactly `ADRP X0` to page `0x9fc36000`, `ADD X0,#0x2c0`,
  then `RET`;
- the statically constructed ELF virtual address is `0x9fc362c0`;
- the exact executable scan finds two direct `BL` callers,
  `0x9fc22cc0` (the 020B path) and `0x9fc26e2c`.

The returned address is a `STATIC_ELF_VADDR` fact only.  It is not a runtime
pointer, physical address, MMIO base, DRAM coordinate, or evidence of writable
state.  The 48-byte source range is retained by hash only; no raw object values
are exposed in the public manifest.

`SUPPORTED`: this statically identifies the bounded source of the 020B object
fields and shows that a second XBL path calls the same helper.

`HYPOTHESIS`: the static object may be a shared configuration carrier.

`UNKNOWN`: runtime execution, object contents/type/currentness, writer identity,
mutability/locking, indirect callers, physical-to-DRAM mapping, MMIO semantics,
protected-memory reach, aliasing, and boundary bypass.

Classification remains `CLASS C (TRANSFORM ONLY)` and eligibility remains
`NOT_ELIGIBLE`.  No device, ADB, SMC, MMIO, normal-RAM, protected-memory, or
partition action was performed.

## Artifacts and validation

The sanitized manifest is
`evidence/manifests/020C-return-helper-origin-20260827-01.manifest.json`, 5,498
bytes, mode `0644`, SHA-256
`ef89ae91fd7277454422fe9717aad762259645991b41797f8011b8dc5b43fdb2`.
Focused tests are 6/6 PASS and the full serial repository suite is 1,173/1,173
PASS (`skipped=1`) in 117.851 seconds, maximum RSS 297,324 KiB, with zero swap.
Python byte-compilation, deterministic regeneration/byte identity, public JSON
parse, private-path scan, mode and no-clobber checks, and independent hostile
review PASS.  Live repetitions, rollback, recovery and target-health receipts
are `NOT_APPLICABLE` because no device state was contacted or changed.

Reproduction template:

```text
python3 tools/sm8150_xbl_return_helper_trace_020c.py \
  --output evidence/manifests/020C-return-helper-origin-20260827-01.manifest.json
python3 -m unittest -v tests.test_sm8150_xbl_return_helper_trace_020c
```
