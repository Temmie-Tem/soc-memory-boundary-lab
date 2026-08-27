# Verification 021 — does a full-size allocation consume the whole carveout?

`HOLD_CONSUMES_POOL`. With 320 MiB held from `camera_preview`, **not one 4 KiB
page** remains allocatable. Both controls fired.

## Why this was run

`docs/PA28_UNBLOCKED_2026-08-27.md` argued by pigeonhole that a 320 MiB
allocation from a 320 MiB carveout must start at the region base, and ranked
that `SUPPORTED`. The 020M integration review held it `UNKNOWN` instead —
correctly. Nothing had shown the allocation actually spans the pool rather than
the heap over-committing, or the pool being larger than the device tree
declares. An argument from a published size is not a measurement of extent.

So the extent was measured.

## The measurement

Hold the full size, then try to allocate anything at all from the same heap.
A failure under hold proves nothing on its own, so it is bracketed:

| Phase | 16 MiB | 4 MiB | 1 MiB | 64 KiB | 4 KiB |
|---|---|---|---|---|---|
| `control_before` | ✓ | ✓ | ✓ | ✓ | ✓ |
| **`under_hold`** | ✗ | ✗ | ✗ | ✗ | **✗** |
| `control_after` | ✓ | ✓ | ✓ | ✓ | ✓ |

`control_before` 5/5 and `control_after` 5/5 — so the probe sizes are
allocatable in this heap, and releasing the hold restores exactly what was there
before. The `ENOMEM` in the middle row is attributable to the hold and to
nothing else.

Nothing is mapped, read or written. Each successful allocation is released
immediately.

## What it establishes

The pool is **exactly** 320 MiB: 320 MiB allocates, and one further page does
not. The device tree declares `camera_mem_region` as base `0xC2000000`, size
`0x14000000` — the same 320 MiB — and heap 30 names that region through its
`memory-region` phandle, which the 020M review `PROVED` on the live target.

A pool neither larger nor smaller than its declared region, reached through that
region's phandle, is that region. The full-size allocation therefore spans
`[0xC2000000, 0xD6000000)`, and offset `o` is physical `0xC2000000 + o`.

The residual assumption is stated rather than hidden: this receipt does not
itself re-derive the phandle chain, so "the pool is *that* region rather than an
equally sized region elsewhere" leans on 020M. The two are independent
collections and agree.

## Why it mattered

`f(PA28)` needs two addresses differing in only bit 28. Across the whole 64 MiB
window `x ∈ [0xC2000000, 0xC6000000)`, `x mod 2^29` stays below `0x10000000`, so
bit 28 of `x` is zero and `x ^ (x + 2^28)` is exactly `0x10000000`. A test
asserts this over the span this experiment establishes, rather than over a span
that was assumed.

## Provenance

The probe is `tools/a90_heap_exhaustion_probe.c`, built with
`aarch64-linux-gnu-gcc -O2 -static -Wall -Wextra -Werror` **from its retained
repository path**, so the executed binary and the reproducible build are the
same bytes:

| | SHA-256 |
|---|---|
| `tools/a90_heap_exhaustion_probe.c` | `02dc73f8731bcdfb6e82d8fb29df2ca73e57a51003435506a29cdd10798126f8` |
| built binary, local and verified on device | `9361018ea2e9f9169ed8e204c259a243647700448aa31f5515f2e599a4815303` |
| `…-01/carveout-exhaustion.jsonl` (2,368 B) | `cb16a3c1ba64f6050a52edd2e2fefe9a405d96fde86928cfe344b74764d28694` |

Verification 020's review found that its executed binary had not been retained
and that building from a scratch path produced a different hash than building
from the repository. Building from the repository path here removes that gap
rather than documenting it.

## Claims and ranking

`PROVED`: with 320 MiB held, zero of five probe sizes down to one page are
allocatable, while both controls are 5/5 — on this device at this uptime under
this firmware.

`PROVED`: the pool is exactly 320 MiB, since the full size allocates and no
further page does.

`SUPPORTED`: the full-size allocation spans `[0xC2000000, 0xD6000000)`, from the
size equality plus 020M's proved phandle chain.

`UNKNOWN`, unchanged: physical page identity, complete DRAM coordinates, the
value of `f(PA28)`, whether the extent varies with uptime or fragmentation,
transform mutability, and every access-control question.

`CLASS C (TRANSFORM ONLY)` and `NOT_ELIGIBLE` unchanged. No boundary-bypass
indicator appeared.

## Reproduce

```
aarch64-linux-gnu-gcc -O2 -static -Wall -Wextra -Werror \
  -o a90_heap_exhaustion_probe tools/a90_heap_exhaustion_probe.c
./a90_heap_exhaustion_probe <ion-node> camera_preview 320

python3 tools/a90_carveout_exhaustion_analysis.py \
  --raw evidence/private/verification-021-carveout-exhaustion-20260827-01/carveout-exhaustion.jsonl \
  --output evidence/manifests/verification-021-carveout-exhaustion-20260827-01.manifest.json
python3 -m unittest tests.test_a90_carveout_exhaustion_analysis
```
