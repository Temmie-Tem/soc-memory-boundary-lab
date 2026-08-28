# Verification 028 — an independent rank floor for the bank function

**Pre-registered before the run.** This file was committed before the probe was
uploaded; the prediction below is not a description of a result.

## Question

Verification 027 recovered the bank kernel from retained timing in polynomial
time and reached an independent floor of `rank f >= 2`. It could not reach 3,
because a floor of `k` requires `k` differences whose every nonempty XOR
combination was measured as a negative, and no retained run contains such a
triple. This run measures two triples to closure in a single allocation.

## Why one allocation, and not the corpus

V027's own result forbids assembling the triple from existing runs. Physical
provenance is `BLIND` (pagemap reports no PFN for dma-buf), so a declared
difference is `declared_base + offset` and is coherent only inside one
allocation; pooling the corpus produces 44 contradictions and puts the PA13
fast control inside the kernel. Six of seven combinations per triple are
already measured **in other runs**, which is why this experiment is cheap to
justify but must still measure all seven itself.

## The two triples

| | d1 | d2 | d3 | d1^d2 | d1^d3 | d2^d3 | d1^d2^d3 |
|---|---|---|---|---|---|---|---|
| A | `0x2000` | `0x4000` | `0x1000000` | `0x6000` | `0x1002000` | `0x1004000` | `0x1006000` |
| B | `0x2000` | `0x8000` | `0x1000000` | `0xa000` | `0x1002000` | `0x1008000` | `0x100a000` |

They share only `0x2000` and `0x1000000`, so a pass on both is two
confirmations rather than one. `0x6000` and `0xa000` have never been measured
anywhere in the corpus, at any page size, under any probe schema.

## Prediction, and what would refute it

Under the established basis `f(PA13) = 001`, `f(PA14) = 010`, `f(PA15) = 100`:

```
f(0x6000) = 001 ^ 010 = 011   != 0   ->  must measure NEGATIVE (fast)
f(0xa000) = 001 ^ 100 = 101   != 0   ->  must measure NEGATIVE (fast)
```

- **All fourteen combination measurements negative** → `rank f >= 3`
  independently, by a route that does not use the mask-by-mask argument.
- **`0x6000` or `0xa000` measures CONFLICT** → its image is zero, the three
  images are dependent, and **the rank-3 basis is wrong**. This is the outcome
  that makes the run worth doing.
- A control-bracket failure (see below) voids the run; it is repeated, not
  reinterpreted.

## Fixed invocation

Probe `tools/a90_region_probe_r.c`
`2dbc81ef7595d30f627df8d28d24e21603d8c1c174074e85593b9fe8df5569e9`
— the exact source pinned by Verification 016 — built with
`aarch64-linux-gnu-gcc -O2 -static -Wall -Wextra -Werror` (15.2.0) to
`bd41bb9c8a5f7dfe1ddcec8f069382df6e0ad85d8712da31a9823243c124d204`, 776,312
bytes, verified byte-identical on rebuild.

```
qsecom 32 201 16 7 spread \
  0x16000 0x2000 \
  0x4000 0x8000 0x6000 0xa000 \
  0x1000000 0x1002000 \
  0x1004000 0x1006000 \
  0x1008000 0x100a000 \
  0x16000 0x2000
```

`qsecom` is heap type 4; the probe refuses the page-based system heap because
an offset difference there would not be a physical one. The leading and
trailing `0x16000`/`0x2000` are the project's canonical conflict and fast
controls, repeated at both ends so drift across the run is visible.

## Reduction rule, fixed in advance

Threshold is the midpoint of the widest gap between sorted medians, **and** the
controls must bracket it: `0x16000` above, `0x2000` below. That second half is
`check_controls_bracket` in `tools/dram_bank_kernel_recovery.py`, added after
V027 found that the widest gap alone can land above the conflict cluster and
let a run pass vacuously. A run failing the bracket is void.

`rank >= 3` is claimed only if, for at least one triple, all seven nonempty XOR
combinations classify as negatives in this run's own reduction.

## Scope

`CLASS C (TRANSFORM ONLY)`. One ION allocation on a non-secure heap, timing
reads, no write of any kind: no MMIO, no controller, no SMC, no partition, no
`param`, no reboot. This bears on the completeness of the DRAM coordinate
model, not on P1 or P2, and it is not a boundary-bypass probe.

## Result — `rank f >= 3`, and the prediction held

Run 2026-08-28 on the exact target: `A90 Linux init 0.9.285`
(`v2321-usb-clean-identity-rodata`), kernel
`4.14.190-25818860-abA908NKSU5EWA3`, `SM-A908N`, `debug_level=0x4f4c`,
self-test `pass=11 warn=1 fail=0 entries=12` before **and** after.

Separation 345, threshold 342.5. The controls bracket at both ends of the run:

| | leading | trailing |
|---|---:|---:|
| `0x16000` conflict control | 515 | 534 |
| `0x2000` fast control | 136 | 149 |

| difference | median | class | role |
|---|---:|---|---|
| `0x2000` | 136 | negative | d1, both triples |
| `0x4000` | 149 | negative | A d2 |
| `0x8000` | 139 | negative | B d2 |
| **`0x6000`** | **155** | **negative** | **A d1^d2 — never measured before** |
| **`0xa000`** | **167** | **negative** | **B d1^d2 — never measured before** |
| `0x1000000` | 152 | negative | d3, both triples |
| `0x1002000` | 108 | negative | d1^d3 |
| `0x1004000` | 142 | negative | A d2^d3 |
| `0x1006000` | 161 | negative | A d1^d2^d3 |
| `0x1008000` | 164 | negative | B d2^d3 |
| `0x100a000` | 170 | negative | B d1^d2^d3 |

Both triples closed: all seven nonempty XOR combinations of A and of B measured
as negatives **in this single allocation**, so their images are linearly
independent and `rank f >= 3` follows without the mask-by-mask argument.
`image_rank_lower_bound` returns 3 with witness
`0x2000, 0x4000, 0x1000000`. Linearity consistent, zero contradictions.

The registered prediction was `f(0x6000) = 011` and `f(0xa000) = 101`, both
non-zero, both therefore negative. Both held. The refuting outcome — a conflict
at either — did not occur, so the rank-3 basis survives a test it could have
failed.

This does not raise the floor past 3, and it does not bear on P1 or P2. It
closes the gap Verification 027 left open, by the independent polynomial route
rather than by agreement with the earlier result.

## Provenance

- probe `tools/a90_region_probe_r.c`
  `2dbc81ef7595d30f627df8d28d24e21603d8c1c174074e85593b9fe8df5569e9`
  (the Verification 016 pin), built to
  `bd41bb9c8a5f7dfe1ddcec8f069382df6e0ad85d8712da31a9823243c124d204`,
  776,312 bytes, byte-identical on rebuild; remote hash equal before and after
  execution
- manifest
  `evidence/manifests/verification-028-bank-rank-triple-20260828-01.manifest.json`,
  3,529 bytes,
  `e75bd791e7a71d55bb1c1299f4d34354601272791cc47203d34aeb2054adfaad`
- the only device mutation was a temporary `/dev/ion` character node
  (`c 10 94`, after verifying `/sys/class/misc/ion/dev` = `10:94`), removed
  with absence proven; upload envelope and binary removed, `/tmp/a90-native`
  left holding only the runtime's own log
- one bounded `stophud` was needed after boot, cleared on the first attempt —
  the device-side `busy` condition reported in
  `docs/CODEX_HANDOFF_V024_BUSY_CHANNEL_2026-08-27.md`, observed live again
