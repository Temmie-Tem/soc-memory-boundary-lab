# Verification 020 — how much non-secure contiguous memory is actually available?

`NOT_MET`. No non-secure ION heap on this device yields 512 MiB. The largest is
`camera_preview` at **320 MiB**, bracketed 320 ✓ / 352 ✗.

## Why this was worth measuring

Reopen condition 2 in `docs/CODEX_HANDOFF_ROUTE2_TERMINATION_2026-08-27.md`
asks for "a reproducible non-secure, physically proved contiguous allocation of
at least 512 MiB". Every other reopen condition has been tested directly.
Condition 2 had only ever been *asserted*: `docs/REMAINING_ROUTES_2026-08-27.md`
stated that Verification 016 tested each heap by allocation and that the largest
non-secure result was 256 MiB, but no retained manifest contained such a survey.

That is the same defect twice corrected elsewhere in this project — a load-
bearing number with no receipt behind it. So it was measured.

## What was measured

Every ION heap is enumerated read-only through `ION_IOC_HEAP_QUERY`. Allocation
is then attempted **only** on heaps named on the command line, so the decision
of what to touch is made on the host and stays auditable off-device, rather than
being inferred by a program running on the target.

Three heaps were attempted, each with prior art in this project:
`camera_preview` (Verifications 016, 018, 019) and `qsecom` and `user_contig`
(Experiment 023). Each successful allocation is released immediately; nothing is
mapped, written or read.

| Heap | Type | Ceiling | Bracket |
|---|---:|---:|---|
| `camera_preview` | 10 | **320 MiB** | 320 ✓ / 352 ✗ |
| `qsecom` | 4 | 32 MiB | 32 ✓ / 64 ✗ |
| `user_contig` | 4 | 16 MiB | 16 ✓ / 32 ✗ |

The seven heaps that were **not** attempted are not zero, they are `UNKNOWN`:

| Heap | Type | Why it was withheld |
|---|---:|---|
| `system` | 0 | page-based; cannot supply a contiguous span by construction |
| `adsp` | 4 | remote-processor carveout |
| `qsecom_ta`, `secure_carveout`, `spss`, `secure_display`, `secure_heap` | 2, 9, 8, 8, 7 | secure — allocating drives `hyp_assign` and a VMID transition, a mandatory pause gate |

## The instrument gate

A ceiling is only meaningful if the ladder is **monotone**: every size at or
below it succeeds and every size above it fails. A success above a failure is
transient memory pressure, not a capacity boundary, and the analyzer reports
`INSTRUMENT_FAILED` rather than reducing it to a number. Both retained ladders
are monotone. The negative result is not hardcoded — a test drives a synthetic
512 MiB success through the same reduction and requires the condition to flip
to `MET`.

## Two corrections this forced

**The heap ceiling is 320 MiB, not 256 MiB.** 256 MiB is what Verifications 016,
018 and 019 *requested*, never what the heap could give.

**The span needed to measure `f(PA28)` is 256 MiB, not 512 MiB.** A pair
differing in only bit 28 is `x` and `x + 2^28`, so the span must *exceed* `2^28`
— it need not reach `2^29`. The 512 MiB figure was the base-independent
guarantee, the same aligned-versus-arbitrary distinction Verification 017 turned
on.

Together these mean 320 MiB **exceeds** the span PA28 requires. PA28 is no
longer excluded by allocation size. What still blocks it is the physical base: a
usable pair exists only if the base modulo `2^29` falls in the right half, and
`pagemap` is `BLIND` for dma-buf, so the base can be neither chosen nor read.

The conclusion is unchanged. The stated reason for it was wrong.

## Claims and ranking

`PROVED`: the three measured ceilings and their brackets, on this device at this
uptime under this firmware, with monotone ladders in both runs.

`REFUTED`: that the largest non-secure heap is 256 MiB.

`REFUTED`: that measuring `f(PA28)` requires a 512 MiB span.

`NOT_MET`: reopen condition 2, as measured — no attempted heap reaches 512 MiB.

`UNKNOWN`: the capacity of the seven withheld heaps; whether the ceiling varies
with uptime, fragmentation or firmware; the physical base of any allocation;
and therefore whether a usable PA28 XOR pair exists inside 320 MiB.

`CLASS C (TRANSFORM ONLY)` and `NOT_ELIGIBLE` are unchanged. No boundary-bypass
indicator appeared.

## Device actions

`ION_IOC_HEAP_QUERY` (read-only) and a sequence of `ION_IOC_ALLOC` calls on
three non-secure heaps, each released immediately with `close()`. One temporary
ION character node, removed. No mapping, no read or write of allocated memory,
and no register, MMIO, SMC, SCM, EL2/EL3, protected-memory, partition or
firmware operation. Every uploaded binary and intermediate file was removed;
`/tmp/a90-native` was left holding only the pre-existing `native-init.log` and
the Verification 019 run-1 receipt. Uptime advanced continuously with no reset.

## Provenance

The probe is `tools/a90_heap_capacity_probe.c`, built with
`aarch64-linux-gnu-gcc -O2 -static -Wall -Wextra -Werror` and hash-verified on
the device after upload.

The retained source does **not** rebuild to the hash of the binary that ran, and
the reason is worth stating rather than hiding. `gcc` embeds the source
*basename* in the static binary, so the same bytes compiled as `heap_cap.c`
(what ran) and as `a90_heap_capacity_probe.c` (what is retained) differ:

| | SHA-256 | Size |
|---|---|---:|
| built as `heap_cap.c` — the fine ladder that ran | `cf0b3caf834213fd0d8db22f09b85e1a58084c94dc69193b49fe141111390457` | 706,184 |
| built as `tools/a90_heap_capacity_probe.c` — reproducible from the repository | `d913d633ed5edea38025318658f61b2175318ec1c18ad3859b616f746723fedf` | 706,192 |

The two are the same program: the sources are byte-identical (`diff` is empty),
every section size matches, the only differing embedded string is the basename,
and the 8-byte size delta is that basename difference after alignment. Building
from the repository path is deterministic — two successive builds produce
`d913d633…` exactly.

The coarse ladder came from an earlier build differing only in the `LADDER_MIB`
constant (`{1024, 768, 512, 384, 256, 128}`), SHA-256
`e8d91ab9fad54d08585decea48cdf9fd3fffeecfcceaae4083f9c8cfaa60489b`. It is
retained as a receipt and used only to cross-check the fine ladder, never as the
source of a published number.

| Receipt | Bytes | SHA-256 |
|---|---:|---|
| `heap-capacity-coarse.jsonl` | 3,655 | `ea8a9d477195cfec449e76c522c9c87981717cd5ea339b35039c86ef180467ab` |
| `heap-capacity-fine.jsonl` | 5,881 | `2761238820b845987ae55ac13e408ecd9a0566f2e8c95efdd160efb199105625` |

## Reproduce

```
python3 tools/a90_heap_capacity_analysis.py \
  --raw evidence/private/verification-020-heap-capacity-20260827-01/heap-capacity-coarse.jsonl \
  --raw evidence/private/verification-020-heap-capacity-20260827-01/heap-capacity-fine.jsonl \
  --output evidence/manifests/verification-020-heap-capacity-20260827-01.manifest.json
python3 -m unittest tests.test_a90_heap_capacity_analysis
```

Passing both ladders makes them cross-check each other: neither may succeed at a
size the other proved impossible.
