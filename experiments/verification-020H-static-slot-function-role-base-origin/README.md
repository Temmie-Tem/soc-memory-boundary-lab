# Verification 020H — bounded static-slot function-role/base-origin trace (2026-08-27)

This host-only, read-only experiment follows the exact 020G access witnesses
one structural step further.  It reopens and hashes the public 020G manifest,
re-derives its exact XBL access set, then analyzes only the 220-byte executable
region containing those accesses, their seed loads, and their return/branch
boundaries.  The region is partitioned into bounded return/direct-branch blocks;
strict direct `BL` sources and a backward base-register trace of at most 16
instructions are retained for each unique access VA.

The block boundaries are deliberately not promoted to true function boundaries.
Leaf blocks can begin at an unknown entry, and indirect callers/callee effects
remain outside the model.  A base definition is labelled `STATIC_SLOT_SEED`,
`ARITHMETIC_DERIVED`, `REGISTER_COPY`, `MEMORY_LOAD_DEFINITION`,
`ARGUMENT_OR_UNKNOWN`, or `UNSUPPORTED_BOUNDARY` only when the strict decoder
supports that statement.

## Exact scope and pins

The retained A90 XBL `xbl--sdb1.bin` is bound by size 4,194,304 and SHA-256
`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.
The exact public 020G manifest is opened with `O_NOFOLLOW`, checked as a
regular file, parsed as JSON, and bound to SHA-256
`f534efeee1e12f18d3af40c107dbc6fbe938eae16d9013aa088d22d7c880af3e`.
The analyzed role region is `[0x9fc26e84,0x9fc26f60)` (220 bytes), pinned by
SHA-256
`f73b378e946379833124c814ad280086c7666123bd9d70985963ca6e1071eaba`.

## Result

The census retains 12 020G witness rows grouped into 11 unique access VAs and
7 bounded local blocks.  Nine blocks contain unsupported/ambiguous forms and
are explicitly labelled `UNKNOWN_ROLE_UNSUPPORTED_FORM`; two are
`LOCAL_READ_SHAPED_BLOCK`.  Ten unique accesses
have a backward base definition classified as `STATIC_SLOT_SEED`; the indexed
access at `0x9fc26ea0` is `ARITHMETIC_DERIVED` from a bounded `MADD` definition.
These are static code-shape and provenance results only.

`PROVED`: exact XBL, 020G dependency, role-region pin, 12/11 cardinalities,
return/direct-branch partition, and strict bounded role/base-origin records.

`SUPPORTED`: the access family is consistent with a local helper/object cluster
whose bases are static-slot-derived or locally arithmetic-derived.  This is not
a runtime function-identity, controller-register, or DRAM-mapping proof.

`HYPOTHESIS`: the apparent family may be local configuration/helper state
rather than final memory-controller programming.

`UNKNOWN`: true leaf function boundaries, runtime values/currentness/execution,
indirect callers and callee effects, object semantics, global writer/consumer
absence, ABI effects, MMIO/physical/DRAM identity, mutability/locking,
protected reach, aliasing, and bypass.

Classification remains `CLASS C (TRANSFORM ONLY)` and eligibility remains
`NOT_ELIGIBLE`.  No device, ADB, SMC, MMIO, normal-RAM, protected-memory,
partition, firmware-write, or controller-write action was performed.

## Artifacts and validation

The sanitized manifest is
`evidence/manifests/020H-static-slot-function-role-base-origin-20260827-01.manifest.json`.
Focused/full validation, deterministic regeneration, artifact hashes, and
independent hostile-review status are recorded in the integration review.

Reproduction template:

```text
python3 tools/sm8150_xbl_static_slot_function_role_base_origin_020h.py \
  --output evidence/manifests/020H-static-slot-function-role-base-origin-20260827-01.manifest.json
python3 -m unittest -v tests.test_sm8150_xbl_static_slot_function_role_base_origin_020h
```
