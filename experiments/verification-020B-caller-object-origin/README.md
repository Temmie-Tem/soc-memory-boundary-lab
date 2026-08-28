# Verification 020B — caller-object origin trace (2026-08-27)

This is a host-only, read-only follow-on to Verification 020A.  It traces the
one exact direct caller of the 020A consumer at `0x9fc023c8` far enough to ask
where the opaque object passed to that consumer originates.  The trace is
symbolic only: it does not execute XBL and does not assign a value, type,
current address, MMIO role, or physical/DRAM destination to the callee return.

## Exact scope and pins

The analyzer binds the retained A90 XBL `xbl--sdb1.bin` by size 4,194,304 and
SHA-256
`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.
The bounded caller body is `[0x9fc22cb4,0x9fc22d30)` (124 bytes, hash
`60e652142c73aec2bc17bef548e00bbb9edcdab08d75dcb3c4e11d0ca72b2162`).  Its
construction subrange `[0x9fc22cc0,0x9fc22d28)` is separately pinned (104
bytes, hash
`b9407c190ddb88b0da62a9e2eefb988fa8fe1829ab3b8232f62019cf65d81c08`).  The
query `BL` at `0x9fc22cc0`, consumer `BL` at `0x9fc22d24`, and consumer entry
`[0x9fc023c8,0x9fc023d4)` are each hash-pinned in the manifest.

Only a finite set of AArch64 forms is recognized: frame setup/teardown,
unsigned scalar `LDR`/`STR`, the exact `LDR`/`STR Q` stack copy, unsigned 64-bit
`LDP`, logical-immediate `ORR Wd,WZR,#imm`, and direct `BL`.  Any changed range,
unsupported form, unresolved stack coverage, or changed direct-caller census
fails closed.  The `RET` immediately after the hashed body is separately
pinned to `0xd65f03c0`.

## Result

`PROVED`:

- the exact consumer has one direct `BL` caller in the retained XBL, at
  `0x9fc22d24`;
- that caller obtains an opaque `X0` token from `BL 0x9fc160b8`, initializes one
  constant field (`W8 = 1`), and constructs the consumer object at `SP+0x20`;
- within the exact finite stack model, the four 020A setter arguments have the
  following static origins:

  ```text
  W3 = MEMORY[BL 0x9fc160b8 return X0 + 0x0c]  (32-bit)
  X0 = MEMORY[BL 0x9fc160b8 return X0 + 0x18]  (64-bit)
  X1 = MEMORY[BL 0x9fc160b8 return X0 + 0x20]  (64-bit)
  X2 = MEMORY[BL 0x9fc160b8 return X0 + 0x28]  (64-bit)
  ```

The manifest serializes those field offsets as `MEMORY_FIELD` provenance while
keeping their human-readable `origin` value `UNKNOWN`.  This is intentional:
the trace proves a data-flow edge, not the runtime contents or semantics of the
opaque return object.

`SUPPORTED`: the caller/object edge is reproducible under the exact finite
model, and the returned object remains a candidate configuration carrier only.

`HYPOTHESIS`: the helper at `0x9fc160b8` may return a runtime configuration
object carrying controller-base-like fields.

`UNKNOWN`: runtime execution and values, object type/currentness, alternate or
indirect callers, writer identity outside this direct edge, static-slot meaning,
physical-to-DRAM mapping, transform mutability/locking, protected-memory reach,
aliasing, and any boundary bypass.

Classification remains `CLASS C (TRANSFORM ONLY)` and eligibility remains
`NOT_ELIGIBLE`.  No device, ADB, SMC, MMIO, normal-RAM, protected-memory, or
partition action was performed or authorized by this experiment.

## Artifacts and validation

The sanitized public manifest is
`evidence/manifests/020B-caller-object-origin-20260827-01.manifest.json`.
It is 18,518 bytes, mode `0644`, SHA-256
`61e5961620d78e766d3fbc586847f76feb0f07991e41326c4b971110cb2a082a`.
The focused suite is 7/7 PASS and the full serial repository suite is 1,167/1,167
PASS (`skipped=1`) in 116.419 seconds, maximum RSS 296,676 KiB, with zero swap.
Python byte-compilation, deterministic regeneration/byte identity, public JSON
parse, no-private-path scan, publication mode, and no-clobber checks pass.  Live
repetitions, rollback, recovery, and target-health receipts are
`NOT_APPLICABLE` because no device state was contacted or changed.

Reproduction template:

```text
python3 tools/sm8150_xbl_caller_object_origin_020b.py \
  --output evidence/manifests/020B-caller-object-origin-20260827-01.manifest.json
python3 -m unittest -v tests.test_sm8150_xbl_caller_object_origin_020b
```
