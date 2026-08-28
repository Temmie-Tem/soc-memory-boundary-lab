# Verification 021 — does a full-size allocation consume the whole carveout?

`HOLD_CONSUMES_POOL` within the retained receipt. With 320 MiB held from
`camera_preview`, **not one 4 KiB page** remains allocatable. Both controls
fired. The receipt has no same-run target, bridge, command-line or timestamp
attestation, so this is not a `PROVED` exact-device claim.

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
allocatable in the selected heap, and releasing the hold restores exactly what
was there before. Within this receipt, the `ENOMEM` in the middle row is
attributable to the hold and to nothing else.

Nothing is mapped, read or written. Each successful allocation is released
immediately.

## What it establishes

The selected heap has a **320 MiB full-hold / no-residual-probe result**: 320
MiB allocates, and one further page does not. The device tree declares
`camera_mem_region` as base `0xC2000000`, size `0x14000000` — the same 320 MiB —
and heap 30 names that region through its `memory-region` phandle, which the
separate 020M review `PROVED` on its live target.

A pool neither larger nor smaller than its declared region, reached through that
region's phandle, would be that region. The conditional span is therefore
`[0xC2000000, 0xD6000000)`, and offset `o` would be physical
`0xC2000000 + o`; the 021 receipt does not independently attest the target or
re-derive the 020M chain.

The residual assumption is stated rather than hidden: this receipt does not
itself re-derive the phandle chain, so "the pool is *that* region rather than an
equally sized region elsewhere" leans on 020M. The two are independent
collections and agree.

## Why it mattered

`f(PA28)` needs two addresses differing in only bit 28. Conditionally, across the whole 64 MiB
window `x ∈ [0xC2000000, 0xC6000000)`, `x mod 2^29` stays below `0x10000000`, so
bit 28 of `x` is zero and `x ^ (x + 2^28)` is exactly `0x10000000`. A test
asserts this over the span this experiment establishes, rather than over a span
that was assumed.

## Provenance

The probe source is `tools/a90_heap_exhaustion_probe.c`; the operator reported
building it with `aarch64-linux-gnu-gcc -O2 -static -Wall -Wextra -Werror`
**from its retained repository path**. Because the executed binary and build
receipt are not retained, byte identity is not independently reverified here:

| | SHA-256 |
|---|---|
| `tools/a90_heap_exhaustion_probe.c` (retained source, 6,491 B) | `02dc73f8731bcdfb6e82d8fb29df2ca73e57a51003435506a29cdd10798126f8` |
| `a90_heap_exhaustion_probe` (binary; size not recorded, **NOT_RETAINED**) | `9361018ea2e9f9169ed8e204c259a243647700448aa31f5515f2e599a4815303` |
| `…-01/carveout-exhaustion.jsonl` (2,368 B) | `cb16a3c1ba64f6050a52edd2e2fefe9a405d96fde86928cfe344b74764d28694` |

The source metadata and receipt hash are mechanically carried into the v2 public
manifest. The executed binary hash is an operator-reported pin only: the binary
itself is not retained and its byte size was not recorded, so the analyzer emits
`size_bytes: null` and `status: NOT_RETAINED`. Verification 020's review found
that its executed binary had not been retained and that building from a scratch
path produced a different hash than building from the repository. The 021 source
path is retained, but no build receipt or same-run binary artifact is available
to upgrade this report to a reproducible executed-build claim.

The production analyzer also hard-pins the canonical receipt basename,
2,368-byte size and SHA-256 above. A same-schema replacement or same-size hash
mutation is rejected before reduction; `analyse()` rejects a supplied input
metadata record that does not match the same pin.

## Same-run provenance boundary

The 021 private receipt is `carveout-exhaustion.jsonl`, 2,368 bytes, SHA-256
`cb16a3c1ba64f6050a52edd2e2fefe9a405d96fde86928cfe344b74764d28694`. It contains
no target version/cmdline, serial or bridge binding, executed argv, start/end
time, or final-health record. The v2 manifest therefore records:

| Item | Status | Why |
|---|---|---|
| target (`SM-A908N` / `SM8150` intended) | `UNKNOWN_UNRETAINED` | no same-run identity/preflight record |
| bridge/device path | `UNKNOWN_UNRETAINED` | no same-run bridge binding record |
| executed command argv | `UNKNOWN_UNRETAINED` | no command receipt or transcript |
| timestamp/final health | `UNKNOWN_UNRETAINED` | no lifecycle record |
| probe source | `RETAINED_SOURCE` | basename, 6,491 B and SHA pinned above |
| probe binary | `NOT_RETAINED` | basename and SHA reported; size unavailable |

The 020M-03 target/bridge manifest is an independent collection. It may support
the DT-region dependency described above, but it is not evidence that the 021
allocation ran on that same target, through that same bridge, at that same time.

The analyzer mechanically pins that dependency as
`verification-020m-pa28-dt-20260827-03.manifest.json`, 8,246 bytes, SHA-256
`69b087bd5a6aa279fff9c943405b46491381f3461c5ea1ac57f4d2f287d8ad9a`, and
rechecks its `a90-pa28-dt-snapshot-v1` schema, exact target/version, strict
`/dev/ttyACM0` bridge fields, heap-30 `0x67a` phandle, and
`camera_mem_region` base/size/end. A dependency size/hash or semantic mutation
fails closed before the conditional span is emitted. This validates the
imported DT semantics; it does not upgrade 021's missing same-run attestation.

## Safety and rollback boundary

The probe's device-side operation is limited to `ION_IOC_HEAP_QUERY` followed by
allocating and closing buffers on the named `camera_preview` heap. It does not
map, read or write the allocated memory and does not access registers, MMIO, SMC,
SCM, EL2/EL3, protected memory, partitions or firmware. The full-size hold is
released by `close()` before the trailing control; if the process exits, the
kernel closes its descriptors. No rollback write is required or authorized.
The receipt does not retain process-exit/final-health evidence, so health after
the historical run remains `UNKNOWN_UNRETAINED`. The analyzer itself is
host-only and performs no device contact.

## 020N candidate assessment

This residual-allocation design is a useful precondition discriminator for the
PA28 timing candidate: it directly tests whether a successful 320 MiB hold leaves
any allocatable remainder, and the before/after controls make an isolated
`ENOMEM` interpretable. It is safer and more informative about allocation extent
than inferring extent from the ceiling alone. It is not a replacement for PA28
timing: it cannot identify physical pages, complete DRAM coordinates or the
value of `f(PA28)`, and the retained 021 receipt cannot prove exact target
identity. A future 020N run must fail closed unless same-run target/bridge
preflight, the named heap/size, the two controls, and cleanup/final-health
receipts are retained.

## Claims and ranking

`SUPPORTED_WITHIN_RETAINED_RECEIPT`: with 320 MiB held, zero of five probe sizes
down to one page are allocatable, while both controls are 5/5. The same-run
device/firmware identity is not attested by this receipt.

`SUPPORTED_WITHIN_RETAINED_RECEIPT`: the selected heap has no residual probe
capacity at the tested 4 KiB floor after the 320 MiB hold.

`SUPPORTED_CONDITIONAL_ON_020M_CHAIN`: the full-size allocation is consistent
with spanning `[0xC2000000, 0xD6000000)`, from the receipt's size result plus
020M's separately proved phandle chain.

`UNKNOWN`, unchanged: physical page identity, complete DRAM coordinates, the
value of `f(PA28)`, whether the extent varies with uptime or fragmentation,
transform mutability, and every access-control question.

The exact target, bridge/device binding, executed argv and timestamp are also
`UNKNOWN_UNRETAINED`: the private JSONL contains only context/probe/hold/summary
records. The separate 020M manifest is not a same-run attestation and cannot be
substituted for one. The public v2 manifest records this boundary explicitly.

`CLASS C (TRANSFORM ONLY)` and `NOT_ELIGIBLE` unchanged. No boundary-bypass
indicator appeared.

## Reproduce

This section is a future operator template, not an instruction executed in this
host-only review. No binary or new raw receipt was created for the v2 parser
repair. A future device run must first record exact A90 target and bridge
preflight in the same receipt, then perform the bounded command below.

```
aarch64-linux-gnu-gcc -O2 -static -Wall -Wextra -Werror \
  -o a90_heap_exhaustion_probe tools/a90_heap_exhaustion_probe.c
./a90_heap_exhaustion_probe <ion-node> camera_preview 320

python3 tools/a90_carveout_exhaustion_analysis.py \
  --raw evidence/private/verification-021-carveout-exhaustion-20260827-01/carveout-exhaustion.jsonl \
  --output evidence/manifests/verification-021-carveout-exhaustion-20260827-01.manifest.json
python3 -m unittest tests.test_a90_carveout_exhaustion_analysis
```
