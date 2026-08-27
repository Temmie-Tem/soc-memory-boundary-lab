# PA28 is measurable, and the base was published all along

The physical base of the `camera_preview` ION heap is **`0xC2000000`**, declared
in the device tree. Combined with the measured 320 MiB ceiling, that makes
`f(PA28)` directly measurable on this device — with no `pagemap`, no CVE, no
privilege escalation, and no inference.

This reopens route 1, which `docs/REMAINING_ROUTES_2026-08-27.md` closed.

## The chain

Read from the live target, read-only:

```
/soc/qcom,ion/qcom,ion-heap@30
    reg            = 0x1e            (= heap_id 30, the measured camera_preview)
    memory-region  = phandle 0x67a
                        |
/reserved-memory/camera_mem_region
    phandle        = 0x67a
    reg            = base 0xC2000000, size 0x14000000
    properties     = ion,recyclable | name | phandle | reg
    no-map         = absent
    reusable       = absent
```

`reusable` absent means this is **not** a CMA region — it is a fixed carveout.
`no-map` absent means the kernel keeps its linear mapping. So the region is a
contiguous, statically placed 320 MiB span at a base the device tree publishes.

Three independent numbers agree on the size:

| Source | Value |
|---|---|
| Device tree `reg` size | `0x14000000` = 335,544,320 |
| Measured allocation ceiling (Verification 020) | 320 MiB, bracketed 320 ✓ / 352 ✗ |
| Kernel ION debugfs `peak allocated` | 335,544,320 |

## Why this settles the base

A 320 MiB allocation from a 320 MiB fixed carveout **is** the whole region.
There is nowhere else it can be placed. So for the full-size allocation, offset
`o` corresponds to physical `0xC2000000 + o` **structurally**, not
behaviourally — which is stronger than the contiguity Verification 016
established by measurement, and it removes the assumption V016, V018 and V019
all had to carry.

This is also why the 256 MiB allocations those three experiments used could not
have gotten here: the base was equally knowable then, but 256 MiB is not a wide
enough span to hold a PA28 pair.

## The pair exists across the entire window

Span `[0xC2000000, 0xD6000000)`. A pair differing in only bit 28 is `x` and
`x + 2^28`, both in range, requiring `x ∈ [0xC2000000, 0xC6000000)` — a 64 MiB
window. Across that whole window:

```
x mod 2^29  ∈  [0x02000000, 0x05FFFFFF]   <  0x10000000
```

so bit 28 of `x` is **zero throughout**, and `x + 2^28` carries nowhere:

| `x` | `x + 2^28` | XOR | in range |
|---|---|---|---|
| `0xC2000000` | `0xD2000000` | `0x10000000` | yes |
| `0xC3000000` | `0xD3000000` | `0x10000000` | yes |
| `0xC5FFF000` | `0xD5FFF000` | `0x10000000` | yes |

Every offset in 64 MiB of slack yields a clean single-bit-28 pair. There is no
boundary to locate and no phase to infer — the carry-phase lever proposed in
`docs/BROAD_SURVEY_2026-08-27.md` is **not needed**. It remains valid for heaps
whose base is not published, and is superseded here.

## What this corrects, for the third time

| Claim | Status |
|---|---|
| "largest non-secure heap is 256 MiB" | `REFUTED` — it is 320 MiB (Verification 020) |
| "measuring f(PA28) needs a 512 MiB span" | `REFUTED` — it needs a span exceeding 2^28 (Verification 020) |
| "what still blocks PA28 is the unknown physical base" | `REFUTED` — the base is `0xC2000000`, published in the device tree |

Each correction loosened the constraint, and each was found by checking a claim
this project had asserted without a receipt rather than by new capability. The
pattern is worth naming: **route 1 was never closed by the device, it was closed
by three unverified sentences.**

## What this does *not* change

Reopen condition 2, as written, asks for at least **512 MiB** and remains
`NOT_MET`: 320 < 512. But the condition's *purpose* was to enable a measurement
above PA27, and that purpose is now served by a different route. The threshold
should be re-specified against what it was for.

Nothing here touches access control. This is a measurement capability, not an
aperture: it says where bits land, not who may write the transform. Every
protection finding stands — the eight known remapper/BIMC apertures are
TZ-owned with no HLOS grant, and `CLASS C (TRANSFORM ONLY)` and `NOT_ELIGIBLE`
are unchanged.

## The experiment this enables

Allocate the **full 320 MiB** from `camera_preview` — anything smaller forfeits
the structural base argument — and measure row-buffer conflict between offset
pairs `(o, o + 2^28)` using the existing timing apparatus. The outcome extends
the recovered relation from PA13..PA27 to PA28, and the same allocation admits
no pair for PA29 or above, so this is exactly one new bit.

Preconditions, all now checkable rather than assumed: the allocation must
actually be 320 MiB (else the base argument fails and it must be abandoned, not
weakened); `f` must be re-derived rather than extrapolated; and the existing
positive and negative timing controls must fire before any PA28 result is
admissible.

## Ranking

`PROVED`: the device-tree facts — heap 30's `memory-region`, the region's base,
size and absent `no-map`/`reusable` — read directly from the live target; the
three-way size agreement; and the pair arithmetic above.

`SUPPORTED`: that a full-size allocation from this heap starts at `0xC2000000`,
from the pigeonhole argument plus the observed success of a 320 MiB allocation.

`UNKNOWN`, unchanged: the value of `f(PA28)`; whether the relation changes
character above the rank boundary; complete DRAM coordinates; transform
mutability; and every access-control question.
