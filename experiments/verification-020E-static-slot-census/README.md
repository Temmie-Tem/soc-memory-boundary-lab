# Verification 020E — bounded static-slot consumer census (2026-08-27)

This is a host-only, read-only follow-up to Verification 020D.  It asks which
direct XBL `LDR`/`STR` instructions reference the six static ELF slots found
by 020D.  The scan is deliberately bounded: an `ADRP` defining the slot page
must be followed by a recognized unsigned scalar access within eight
instructions, and unknown instructions or unsupported control/data-flow
forms stop that local window.  A direct `BL` is a barrier when the page
register is caller-saved; it is allowed to continue only for X19–X29 under an
explicit AAPCS64 callee-saved assumption.  A static ELF address is not
promoted to a runtime physical address, MMIO register, DRAM coordinate, or
security-boundary primitive.

## Exact scope and pins

The retained A90 XBL `xbl--sdb1.bin` is bound by size 4,194,304 and SHA-256
`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.
Dependencies are hash-pinned to the exact 020C helper
`[0x9fc160b8,0x9fc160c4)` (`aa23cc5c16d3e14a931184f48199c3891359b3074b3433e0b8a82901bc619ff9`),
the 020D second caller `[0x9fc26e24,0x9fc26e78)`
(`4c3100f3dff6b8684aa17fc616f6737b283484bb92199dbe98b747a8ab85721d`), and
the 020D object range `[0x9fc362c0,0x9fc36300)`
(`07f284b58048d944e3d6ef2e19438d9d1e04bde32eafb5541f2eabe294af8277`).
Raw private object/firmware bytes are not published.

The slot page is `0x9fc3e000`; the six tested offsets are `0x138`, `0x140`,
`0x148`, `0x150`, `0x158`, and `0x160`.

## Result

Within this finite model, the exact XBL contains 18 unique direct scalar
accesses to those slots: six `STR` stores and twelve `LDR` loads.  The scan
also records 95 bounded barriers: eight caller-saved `BL` barriers and 87
unknown-instruction barriers.  The six stores are the 020D caller's
static writes; the twelve loads are additional bounded direct consumers found
by this census.  Access VAs and slot VAs are retained in the sanitized
manifest, while indirect paths and unsupported instruction effects remain
outside the model.

`PROVED`: exact input/dependency hashes and the bounded recognized access set
(18 total, split 6 stores / 12 loads) in the retained XBL.

`SUPPORTED`: the six 020D slots have more than one statically visible use, so
they are a useful cross-reference set for later semantic tracing.  The one
callee-saved-register call window is conditional on the stated ABI assumption;
caller-saved call windows are fail-closed barriers.

`HYPOTHESIS`: the slots may be shared configuration state rather than final
controller registers.

`UNKNOWN`: global writer/consumer absence, ABI compliance and callee side
effects, runtime execution/currentness, values and slot semantics,
MMIO/physical/DRAM meaning, mutability/locking, protected reach, aliases, and
any boundary bypass.

Classification remains `CLASS C (TRANSFORM ONLY)` and eligibility remains
`NOT_ELIGIBLE`.  No device, ADB, SMC, MMIO, normal-RAM, protected-memory,
partition, firmware-write, or controller-write action was performed.

## Artifacts and validation

The sanitized manifest is
`evidence/manifests/020E-static-slot-census-20260827-01.manifest.json`,
29,826 bytes, mode `0644`, SHA-256
`4c28b0cc0a113e099fe3b0ce2bd16a77ce0c9d9bfc799ca9494c52eed9c349ad`.
Focused tests are 7/7 PASS and the full serial repository suite is 1,186/1,186
PASS (`skipped=1`) in 119.090 seconds, maximum RSS 343,404 KiB, with zero
swap.  Python byte-compilation, deterministic regeneration/byte identity,
public JSON parse, private-path scan, mode/no-clobber checks, and independent
hostile review are PASS.  The durable record is
`docs/VERIFICATION020E_INTEGRATION_REVIEW_2026-08-27.md`.

Reproduction template:

```text
python3 tools/sm8150_xbl_static_slot_census_020e.py \
  --output evidence/manifests/020E-static-slot-census-20260827-01.manifest.json
python3 -m unittest -v tests.test_sm8150_xbl_static_slot_census_020e
```
