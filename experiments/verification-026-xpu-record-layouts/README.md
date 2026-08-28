# Verification 026 — the other record layout, and what V025 got wrong

**Result: every one of the 1,726 declared records is now decoded. The 1,465
Verification 025 left `UNKNOWN` are not undecoded address ranges — they carry no
address at all.**

Host-only. No device, USB, MMIO, SMC, SCM, controller or protected-memory
access; no firmware bytes emitted. `CLASS C (TRANSFORM ONLY)` / `NOT_ELIGIBLE`
unchanged.

## Two layouts, and the name does not tell you which

Verification 025 classified instances by the `_MPU` name suffix. That is a
heuristic, and the record size is not a guess — it is measurable. The region
tables are laid out consecutively, so the distance from one table pointer to the
next divides exactly by the first table's record count:

```text
CRYPTO0_BAM   0x1c2ee3a0   6 regions   delta 0x60  = 16 bytes/record
MMSS          0x1c2ee400   8 regions   delta 0x80  = 16
CNOC_AOSS_MPU 0x1c2f2860  15 regions   delta 0x1e0 = 32
AOSS_MPU      0x1c2f2a40  17 regions   delta 0x220 = 32
```

Every adjacent pair inside a contiguous cluster agrees, and the answer is always
16 or 32.

| Layout | Size | Fields | Instances (branch `>= 2`) | Records |
|---|---:|---|---:|---:|
| Address range | 32 | `index, flags, read_vmid, write_vmid, start, end` | 21 | 299 |
| Resource slot | 16 | `index, flags, read_vmid, write_vmid` | 21 | 1,427 |

`299 + 1,427 = 1,726` — the full declared count. Nothing is left undecoded.

## The finding

**Slot records contain no address.** Across all 1,427 of them the first word is
a small resource index — maximum `0xcd`, never anything address-shaped — and the
flags take only three values (`0x9`, `0x11`, `0x21`), the same family the address
records use. The naming matches the structure exactly: an **MPU** protects
address ranges, while an **XPU / APU / RPU / BAM** protects numbered resource
slots belonging to its own instance.

That settles the question Verification 025 had to leave open. The 1,465
undecoded records were never hiding an address policy, because records of that
class cannot express an address. **The address-containment question is answered
completely by the 299 address records**, and no further decoding can change it.

## Two defects in Verification 025, both corrected here

### 1. The name heuristic excluded three instances

`CFG_SSC`, `BOOT_ROM` and `PMIC_ARB` use 32-byte address records despite not
being named `*_MPU`. V025 reported them as undecoded. `PMIC_ARB` in particular
holds **five real regions** that V025 never saw:

| Region | read_vmid | write_vmid |
|---|---|---|
| `0x0c400000..0x0c430000` | `0xf0ffffff` | `0x00000000` |
| `0x0c440000..0x0c450000` | `0xf0ffffff` | `0x00000000` |
| `0x0c460000..0x0c4e1000` | `0xf0ffffff` | `0x00000000` |
| `0x0e600000..0x0e700000` | `0xf0ffffff` | `0xf0ffffff` |
| `0x0e700000..0x0e7a0000` | `0xf0ffffff` | `0x00000000` |

The error direction was safe — V025 under-claimed — but the classifier was not
principled.

### 2. The unused-slot test used a magic value, not the property

V025 treated a record as an unused slot only when start and end both equalled
`0xffffffff`. The filler is **not constant**: `0xffffffff` in `CFG_SSC`,
`0x3ffff` in `BOOT_ROM`, `0xfffffff` in `PMIC_ARB`. The property that matters is
zero width.

Consequence: V025 counted **60 zero-width entries as regions**. Its published
figure of 164 decoded regions was therefore 104 real regions plus 60 filler.
The corrected count is **109 real** (104 + the 5 from `PMIC_ARB`) with **190**
unused slots.

This mattered beyond bookkeeping: a zero-width entry at address *X* satisfies
`start < hi and lo < end` whenever `lo < X < hi`, so it *could* have answered a
containment query with a spurious hit. None of V025's five published answers was
affected — each returned exactly one covering region with a real range — but the
guard was absent, and a regression test now covers it.

## Result, unchanged where it matters

Both selector branches still agree on every query, and every published V025
answer stands:

| Query | Covered | Instance | Region | HLOS read | HLOS write |
|---|---|---|---|---|---|
| `apcs_glb` mailbox | yes | `CNOC_AOSS_MPU` | `0x17c00000..0x18200000` | no | no |
| `apcs` syscon IPC | yes | `CNOC_AOSS_MPU` | same | no | no |
| APSS watchdog | yes | `CNOC_AOSS_MPU` | same | no | no |
| remapper instance 0 | yes | `DC_NOC_BROADCAST_MPU` | `0x09248000..0x09249000` | no | no |
| **control** — remapper page | yes | `DC_NOC_BROADCAST_MPU` | same | no | no |

## HLOS-granting regions, and why they do not reopen route 2

With the corrected set, **21 of 109** real address regions grant HLOS read or
write. This is worth stating because it proves the permission decoder
distinguishes rather than always answering "denied": `IMEM_MPU` (read only),
fifteen `AOSS_MPU` regions in `0x0c21_0000..0x0c2e_1000`, and the five
`PMIC_ARB` regions above. Two owner classes appear, `TZ` and
`HYP_OR_BASE_NONSECURE`.

None of them touches the transform:

| Band | Overlap with an HLOS-granting region |
|---|---|
| `qhs_llcc` remapper ×4 | none |
| BIMC MPU ×4 | none |
| SHRM snapshot page | none |
| MCCC / `qhs_mc` | none |
| `0x09000000..0x09800000` | none |
| `apcs_glb` block | none |
| DRAM `0x80000000..0x200000000` | none |

Identical in both selector branches. AOSS and PMIC-arbiter apertures being
Normal-World writable is ordinary — that is how the AP talks to the always-on
subsystem and the SPMI arbiter. `CLASS C` and the route-2 disposition are
unchanged.

## Negative controls

- The remapper page remains the **control query**; the walk raises instead of
  publishing if it cannot reproduce Verification 009's retained result.
- Accounting must close exactly: address + unused + slot equals declared, per
  branch, or the walk raises.
- A slot record carrying a `start` field raises — the "no address" property is
  asserted, not assumed.
- Four different filler values must all be classified as unused slots.
- A zero-width entry must not answer a containment query.
- An HLOS-granting VMID pattern must produce a grant, or the permission columns
  would be vacuous.

## Reproduce

```
python3 tools/sm8150_xpu_region_coverage.py \
  --output evidence/manifests/verification-026-xpu-record-layouts-20260827-01.manifest.json
python3 -m unittest tests.test_sm8150_xpu_region_coverage
```

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| `verification-026-xpu-record-layouts-20260827-01.manifest.json` | 13,669 | `8db1f3c168448c1c2bb258ab1d879c3d331f80342b73566c836c72a422c934cf` |
