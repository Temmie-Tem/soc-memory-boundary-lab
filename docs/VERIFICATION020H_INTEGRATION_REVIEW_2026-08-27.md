# Verification 020H static-slot function-role/base-origin integration review — 2026-08-27

## Boundary and exact inputs

This iteration is host-only and read-only.  No device, ADB, SMC, MMIO,
normal-RAM, protected-memory, partition, firmware-write, or controller-write
operation occurred.  The exact XBL is 4,194,304 bytes with SHA-256
`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.
The public 020G dependency is pinned to SHA-256
`f534efeee1e12f18d3af40c107dbc6fbe938eae16d9013aa088d22d7c880af3e`.
The bounded role region is `[0x9fc26e84,0x9fc26f60)` (220 bytes), SHA-256
`f73b378e946379833124c814ad280086c7666123bd9d70985963ca6e1071eaba`.

## Static result

The tool re-derives the exact 020G witness set and groups 12 witnesses into 11
unique access VAs and 7 return/direct-branch-delimited local blocks.  Nine
blocks contain unsupported/ambiguous forms and remain
`UNKNOWN_ROLE_UNSUPPORTED_FORM`; two are `LOCAL_READ_SHAPED_BLOCK`.  Ten
unique access rows have `STATIC_SLOT_SEED` base origins;
the indexed access at `0x9fc26ea0` is `ARITHMETIC_DERIVED` from a bounded
`MADD`.  These labels are static shape/provenance only and do not establish
true function boundaries, runtime pointers, physical addresses, MMIO, DRAM,
ownership, or a bypass.

`PROVED`: exact input/dependency/region pins and the bounded 12/11/7 census.
`SUPPORTED`: local helper/object role consistency.  `HYPOTHESIS`: the family
may be local configuration/helper state.  `UNKNOWN`: runtime execution and
values, true function boundaries, indirect callers/callee effects, object
semantics, global writer/consumer absence, ABI effects, MMIO/physical/DRAM
identity, mutability/locking, protected reach, aliasing, and bypass.

Classification remains `CLASS C (TRANSFORM ONLY)` and eligibility remains
`NOT_ELIGIBLE`.

## Validation

Python byte-compilation passed for the tool and focused test module.  The
focused suite is 11/11 PASS.  The full repository suite was run serially to
avoid memory pressure: 1,216/1,216 tests PASS (`skipped=1`) in 140.860
seconds, maximum RSS 349,728 KiB, zero swap, exit status 0.  Deterministic
regeneration produced a 19,314-byte mode-`0644` manifest with SHA-256
`b306ca67675430314289fd79faa2e53b2d67994807d0b08bd91ced9b625faba2`, byte
identical to the retained public artifact.  Public JSON parsing, private-path
redaction, no-clobber publication, exact 12/11/7 cardinalities, role-region
hash, and synthetic decoder/base/dependency negatives passed.

The implementation and focused-test hashes at review time are:

| Artifact | SHA-256 |
|---|---|
| `tools/sm8150_xbl_static_slot_function_role_base_origin_020h.py` | `5d54ef00868fcb0fa3e8332bfca60072f5c90f51d0e25041412ee109dd6c2f0f` |
| `tests/test_sm8150_xbl_static_slot_function_role_base_origin_020h.py` | `f7440d1cba96436f702421b4af0680722cec735536463ed5ec3011129455b88e` |
| `experiments/verification-020H-static-slot-function-role-base-origin/README.md` | `516fd5583196e321d4421bf153387cbdc1a3138b257c17ce84e1b90d1035a94c` |
| `docs/VERIFICATION020H_CONTRACT_2026-08-27.md` | `c595714dd932317f67af862aed3c5b368ce491f8031b37863127749359119a39` |
| `evidence/manifests/020H-static-slot-function-role-base-origin-20260827-01.manifest.json` | `b306ca67675430314289fd79faa2e53b2d67994807d0b08bd91ced9b625faba2` |

Live repetitions, rollback, recovery, and target-health receipts are
`NOT_APPLICABLE` because this iteration performed no device action.

## Independent hostile review

`PASS`.  The independent reviewer confirmed exact XBL/020G/role-region pins,
the B-only branch mask (BL is not a block terminator), strict RET X30 handling,
LDR-only base definitions (STR cannot define a base), exact 12/11/7
cardinalities, 10 `STATIC_SLOT_SEED` rows and the indexed `MADD` origin,
fail-closed decoder/base/dependency negatives, public redaction,
Class C/`UNKNOWN` boundaries, non-overlap with 020G, and no-device scope.
No P0/P1/P2 issue remains; no edits or device commands were performed by the
reviewer.
