# Verification 020G — bounded static-slot pointer/object census (2026-08-27)

This host-only, read-only experiment follows the 020F address-use events one
step further.  It reopens and hashes the public 020F manifest, re-derives the
same exact XBL analysis, and re-decodes only the 10 immediate and 2
register-offset memory accesses reported there.  Immediate accesses are
labelled `IMMEDIATE_OBJECT_FIELD`; register-offset accesses are labelled
`REGISTER_OFFSET_ARRAY_ELEMENT`.  One register-offset VA is witnessed by two
different slot loads and is retained as a duplicate witness rather than
silently merged.

These labels describe instruction shape only.  The base registers contain
unknown runtime values; no static VA is promoted to a runtime pointer,
physical address, MMIO aperture, DRAM coordinate, or security-boundary
primitive.

## Exact scope and pins

The retained A90 XBL `xbl--sdb1.bin` is bound by size 4,194,304 and SHA-256
`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.
The exact public 020F manifest is mechanically opened with `O_NOFOLLOW`,
regular-file checked, parsed as JSON, and bound to SHA-256
`d19687581d046c7b05841aef6340e9a1e3664c69e19903689d1c583aee5b9764`.

## Result

The bounded census contains 12 event witnesses: 10 immediate scalar object-
field-shaped accesses (7 loads and 3 stores) and 2 register-offset
array-element-shaped load witnesses.  The register-offset witnesses share
one access VA (`0x9fc26ea0`) but arise from two distinct 020F seed loads, so
the unique access-VA count is 11 and the duplicate-witness count is 1.

`PROVED`: exact XBL/020F pins and this bounded instruction-shape census.

`SUPPORTED`: the observed uses are structurally consistent with local pointer
or object/array state and include three writes to fields of such a runtime
base.  This is not a controller-register or DRAM mapping proof.

`HYPOTHESIS`: the six static slots may carry pointers to local configuration
objects or arrays rather than final memory-controller state.

`UNKNOWN`: runtime base values/currentness/execution, object types and
semantics, global writer/consumer absence, MMIO/physical/DRAM identity,
mutability/locking, protected reach, aliasing and bypass.

Classification remains `CLASS C (TRANSFORM ONLY)` and eligibility remains
`NOT_ELIGIBLE`.  No device, ADB, SMC, MMIO, normal-RAM, protected-memory,
partition, firmware-write, or controller-write action was performed.

## Artifacts and validation

The sanitized manifest is
`evidence/manifests/020G-static-slot-pointer-object-census-20260827-01.manifest.json`.
Focused/full validation, artifact hashes, deterministic regeneration, and
independent hostile-review status are recorded in the integration review.

Reproduction template:

```text
python3 tools/sm8150_xbl_static_slot_pointer_object_census_020g.py \
  --output evidence/manifests/020G-static-slot-pointer-object-census-20260827-01.manifest.json
python3 -m unittest -v tests.test_sm8150_xbl_static_slot_pointer_object_census_020g
```
