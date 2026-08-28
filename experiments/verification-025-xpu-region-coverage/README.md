# Verification 025 — complete MPU region coverage

**Result: `0x17c00000` is protected. The prior `UNKNOWN` was an artifact of this
project's own extraction scope, not a property of the target.**

> **Superseded in part by Verification 026 (2026-08-27).** The query answers
> below all stand and were reconfirmed. Two things in this record are wrong:
> the `*_MPU` name heuristic wrongly excluded `CFG_SSC`, `BOOT_ROM` and
> `PMIC_ARB`, which do use address records; and the unused-slot test keyed on
> the magic value `0xffffffff` rather than on zero width, so **60 zero-width
> filler entries were counted as regions**. The corrected figures are 109 real
> address regions (not 164) and 190 unused slots, and the 1,465 records left
> `UNKNOWN` below are now decoded — they carry no address at all. See
> `experiments/verification-026-xpu-record-layouts/README.md`.

Host-only. No device, USB, MMIO, SMC, SCM, controller or protected-memory
access; no firmware bytes emitted. `CLASS C (TRANSFORM ONLY)` / `NOT_ELIGIBLE`
unchanged.

## The question, and why the old answer was weak

`docs/BROAD_SURVEY_2026-08-27.md` recorded, correctly, that no address inside
`0x17c00000..0x17c01000` — the `apcs_glb` mailbox block — appears in the
retained 009/010 XPU inventories, and bounded that as *"not evidence of absent
protection"*. It could not say how weak the evidence was.

It was very weak. The 009 manifest declares **1,726 protected regions** across
44 XPU instances in the `>= 2` selector branch, and retains decoded ranges for
**5**. Every absence-of-address claim made against it was measured against
0.3% of the declared policy. The highest enumerated XPU instance base is
`0x14406000`, so the queried block was above the top of the enumeration
entirely.

## What this does

`tools/sm8150_xpu_region_coverage.py` reuses the exact Verification 009 record
parser and permission decoder, takes the instance descriptors from the pinned
009 manifest rather than re-deriving them, and walks every region table in both
selector branches.

## The MPU/non-MPU split, and why it is not a convenience

Applying the 32-byte `<IIIIQQ` record to all 44 instances produces **717 records
with ends above 2^40** and **710 table pointers outside the image**. Partitioned
by instance class the split is total:

| Class | Instances | Plausible | Unused slots | Implausible | Unreadable |
|---|---:|---:|---:|---:|---:|
| `*_MPU` | 18 | 104 | 157 | **0** | **0** |
| XPU / RPU / APU / BAM / other | 26 | 5 | 33 | **717** | **710** |

Zero anomalies among MPU-class instances and every anomaly outside them. The
32-byte layout Verification 009 validated is the **MPU** region layout; the
other classes use a record shape this project has not established. They are
reported as `not_decoded` with their declared counts rather than decoded into
noise, and the walk raises rather than publishes if an implausible record ever
appears in the MPU set.

## Result

Both selector branches agree on every query. Accounting closes exactly:
164 decoded + 97 unused slots = 261 declared MPU regions (`>= 2` branch);
163 + 96 = 259 (`< 2` branch).

| Query | Covered | Instance | Region | Owner | HLOS read | HLOS write |
|---|---|---|---|---|---|---|
| `apcs_glb` mailbox `0x17c00000..0x17c01000` | yes | `CNOC_AOSS_MPU` | `0x17c00000..0x18200000` | TZ | no | no |
| `apcs` syscon IPC `0x17c0000c` | yes | `CNOC_AOSS_MPU` | same | TZ | no | no |
| APSS watchdog `0x17c10000..0x17c11000` | yes | `CNOC_AOSS_MPU` | same | TZ | no | no |
| remapper instance 0 `0x09248080` | yes | `DC_NOC_BROADCAST_MPU` | `0x09248000..0x09249000` | TZ | no | no |
| **control** — remapper page | yes | `DC_NOC_BROADCAST_MPU` | `0x09248000..0x09249000` | TZ | no | no |

The `CNOC_AOSS_MPU` table is internally coherent: eight used entries, seven
`0xffffffff` unused slots, uniform `flags=0x9`, and ordinal 5 starting at
exactly the device-tree-declared `apcs_glb` base. A 6 MiB region beginning on
that boundary is not a coincidence of misparsing.

`PROVED`: within the exact pinned TrustZone image, the `apcs_glb` block is
covered by a TZ-owned `CNOC_AOSS_MPU` region granting no HLOS read or write, and
the same region covers the APSS watchdog named in the Verification 023 crash
log.

`REFUTED`: the reading that `0x17c00000` sits outside enumerated protection.
It sits inside a decoded region; the earlier absence was extraction scope.

`UNKNOWN`, unchanged: the 26 non-MPU instances' 1,465 declared regions; runtime
register values as opposed to static policy; whether protection is enforced at
runtime as the static table describes; and everything the 1b checkpoint left
open about undiscovered apertures.

## Negative controls

- The remapper page is queried as a **control**: if the walk cannot reproduce
  Verification 009's retained `DC_NOC_BROADCAST_MPU` result the tool raises
  instead of publishing.
- Moving the region in a synthetic set moves the `apcs_glb` answer, so the
  answer is not a constant.
- An HLOS-granting VMID pattern must produce a grant, or the permission columns
  would be vacuous. **This control fired during development**: the first
  implementation read `hlos_read`/`hlos_write` from the decoder, which emits
  `hlos_present_in_read_mask`/`..._write_mask`, so both columns were `False`
  for every region regardless of the data. The test caught it before publication.

## Reproduce

```
python3 tools/sm8150_xpu_region_coverage.py \
  --output evidence/manifests/verification-025-xpu-region-coverage-20260827-01.manifest.json
python3 -m unittest tests.test_sm8150_xpu_region_coverage
```

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| `verification-025-xpu-region-coverage-20260827-01.manifest.json` | 12,003 | `0ca9b32fc5a07088f2d45b11b0ab3274e49a382603484b43e37ef264b505cbed` |
