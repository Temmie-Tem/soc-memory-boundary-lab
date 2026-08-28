# Verification 030 — A90 RBIN physical-allocation oracle

Status: `PRE_REGISTERED / HOST IMPLEMENTATION COMPLETE / 10 FOCUSED TESTS PASS / NO LIVE EFFECT YET`

## Question

Does one exact 320 MiB `camera_preview` allocation on the bound
`SM-A908N/SM8150` produce a complete, allocation-local scatter/gather layout
that can be joined to physical addresses rather than inferred from a DT base?

This directly tests the principal provenance `UNKNOWN` left by Verifications
018, 019 and 022R.  It does not test a protected carveout, change a memory
controller, or claim a physical-to-DRAM alias.

## Pre-registered source evidence

The external source corpus is the retained A90 stock-source tree
`a90-stock-mpgen27-20260822/source`.  Its enclosing
`android-native-init-lab` workspace was at commit
`510d909eff0fe10e48f3bfff573bc17f59f0656a`, but that commit is workflow
provenance rather than content attestation for the ignored private source
corpus.  The individual SHA-256 values below bind the source bytes used here.

| Claim | Evidence | Status |
|---|---|---|
| `camera_mem_region` advertises `[0xc2000000,0xd6000000)` | `arch/arm64/boot/dts/samsung/renovation/sm8150-sec-r3q-kor-overlay-r00.dts:6425`, SHA-256 `7a6ca7d57fe336eb60137a16f0b9eb121b5b150761ebf0923a87f2dd0857fc0e` | `PROVED` for the pinned source |
| heap ID 30 names that memory-region and type `RBIN` | same DTS, lines 6470–6476 | `PROVED` for the pinned source |
| the DT base and size become `heap->base` and `heap->size` | `drivers/staging/android/ion/msm/msm_ion_of.c:162`, SHA-256 `468579683a2d17ed0ca6c1e76ae9ca8992024d664555848cb801ac4c444be0c4` | `PROVED` for the pinned source |
| each successful allocation chunk becomes one SG entry | `drivers/staging/android/ion/ion_rbin_heap.c:189–215`, SHA-256 `3f9596aac0e93b5a0289cdc2f5acf4182c8d2173af7e438f73e1d65dd3598650` | `PROVED` for the pinned source |
| pool and partial allocation-end tracepoints carry `size` and raw `struct page *` | `include/trace/events/ion.h:285–305,350,380`, SHA-256 `79cf72d2afe0ee1083250b8debd2c50b09e886d8f5d1c18c388ea3f6ecabcf5d` | `PROVED` for the pinned source |
| a fresh RBIN-region chunk originates in the fixed `gen_pool` | `mm/rbinregion.c:333–365`, SHA-256 `3e4f4eaf2bc635132b6542f3f95eed58d96bb76cba1c7c51796b6ce83a03f0ce` | `PROVED` for the pinned source |
| sparse-vmemmap uses `page - vmemmap` for PFN | `include/asm-generic/memory_model.h:51–55`, SHA-256 `a789dc8435d98e7dfabe4c11ba30d266ede5f0e0e388ed13a984690c333568ae` | `PROVED` for the pinned source |
| `cma:cma_alloc` stores raw `pfn`, `page`, `count`, and `align` in one record | `include/trace/events/cma.h`, SHA-256 `f10d61cd5c22bf29d2ab91517dcf3444b4ad004cecb6b4d8544a2d20dd661836` | `PROVED` for the pinned source |
| `PERF_SAMPLE_RAW` emits `header + u32 raw_size + raw_size`; `raw_size` includes the kernel's alignment padding | `kernel/events/core.c:6145–6221,6353–6402`, SHA-256 `8ddef9d707447d55d8ac28a89cdee553f37efd928a9e5824d7952ff3a3919484` | `PROVED` for the pinned source |
| raw tracepoint sampling is privilege-checked by `perf_allow_tracepoint()` | `kernel/trace/trace_event_perf.c:45–89`, SHA-256 `3d24060a5ae9b928a12f85ab66b81a03691d5465245d422efe10c5e8c143543b` | `PROVED` for the pinned source; live availability remains `UNKNOWN` until preflight |

`PROVED`: retained V020M binds the live heap-30 DT chain to the same advertised
base and size.  Retained V022R proves that a full-size allocation and its
timing workload completed on the exact target.

`UNKNOWN`: no retained artifact contains the allocation's actual SG page
list, PFNs or physical base.  V022R's `declared_base` is calculated input, not
an observed PA.

## Hypothesis and prediction

`HYPOTHESIS`: the live kernel permits a root, self-scoped perf tracepoint
consumer to observe every allocation-end chunk emitted by exactly one heap-30
allocation.

Predictions:

1. Exactly one `ion_rbin_alloc_start`/`ion_rbin_alloc_end` pair brackets the
   current process's chunk events.
2. Successful `ion_rbin_pool_alloc_end` and
   `ion_rbin_partial_alloc_end` lengths sum to exactly `0x14000000`.
3. Each non-null page and length can be converted into a relative PFN interval
   after a same-run affine calibration.
4. Three held, distinct `user_contig` CMA allocations expose raw `(pfn,page)`
   pairs.  Two determine `page = slope*pfn + intercept`; the third must validate
   that relation.  The observed slope is compared with, but not assumed from,
   the source's 64-byte `struct page` layout.
5. Absolute PA is emitted only after that current-boot calibration succeeds.
   The expected DT region must not be used as a circular anchor.

`SUPPORTED`: because the source constructs the SG table from the same ordered
chunk list, a complete ordered trace is an allocation-local SG-layout oracle.

## KASLR qualification

`PROVED`: the exact config enables `CONFIG_RANDOMIZE_BASE`; the retained
cmdline does not contain `nokaslr`.  `arm64_memblock_init()` may subtract a
random one-GiB multiple from `memstart_addr`.

Therefore:

- uncalibrated page-pointer differences prove only a relative layout;
- `VMEMMAP_START` plus the advertised DRAM start alone cannot prove absolute
  PFNs for the current boot;
- the fixed same-run `cma:cma_alloc` records are the primary PFN anchor;
- if fewer than three valid, distinct calibration pairs are observed, absolute
  `first_pa`, `end_pa`, and `exact_region_match` remain `UNKNOWN`.

Retained crash records contain two independently observed direct-map pairs
whose arithmetic is consistent with `memstart_addr=0x80000000` on those prior
boots.  They are a `SUPPORTED` cross-check only; they are not transferred as
the current boot's affine anchor.

This restriction prevents the experiment from proving its desired answer by
assuming the answer.

## Fixed live action

The production CLI has no target, heap, size, flag, tracepoint or command
selectors.  With an explicit `--execute`, it performs once:

1. claim the fixed experiment ID with an exclusive fsynced no-replay journal;
2. bind the existing loopback bridge and exact `SM-A908N/SM8150` V2321 runtime,
   attest the current V2321 boot-prefix SHA-256, and capture the current boot ID;
3. verify the fixed helper bytes after transfer and revalidate the bridge
   immediately before durable `EFFECT_DISPATCHED`;
4. pin the helper to CPU 7;
5. open only the four fixed ION RBIN tracepoints and `cma:cma_alloc`,
   self-scoped through `perf_event_open`, and parse their live `format`
   descriptions;
6. allocate and hold three small fixed `user_contig` buffers, require their
   CMA counts in the exact `1,2,3` page order, derive the
   `(pfn,page)` affine mapping from two records, and validate it with the third;
7. issue one `ION_IOC_ALLOC` for heap 30, size `0x14000000`, flags 0, disable
   tracing, drain the perf rings, and reconstruct source-loop order by replacing
   each pool miss with exactly one next partial-allocation success;
8. close all four dma-bufs exactly once, remove and prove absence of every
   temporary node/file, and require unchanged boot ID, target identity and a
   passing final native selftest;
9. retain complete raw records privately and publish only hashes and the
   bounded SG/PA summary.

No automatic operation retry is permitted.  A pre-effect refusal may use a
new experiment ID; an ambiguous or post-allocation failure is reconciled and
not replayed.

## Effects and recovery

Expected bounded effects are one 320 MiB normal-RAM/RBIN allocation, three
held one-to-three-page CMA calibration allocations, perf file descriptors and
ring mappings, the existing read-only boot-prefix attestation capture, one
temporary regular helper, and one temporary ION character node matching the
already-proved V022R pattern.  All descriptors are closed and all temporary
objects are removed with absence checks before final health.

The experiment performs no reboot, boot/param/partition write, MMIO access,
controller write, SCM/SMC, XPU/SMMU ownership change, protected-memory read,
firmware mutation or persistent change.  Panic/sysctl restore and boot
rollback are explicitly `NOT_APPLICABLE` because neither state changes and no
reboot occurs.  Allocation failure, perf-policy
refusal or missing tracepoints can establish that no allocation was attempted,
but once the host has durably recorded `EFFECT_DISPATCHED`, the fixed
experiment ID remains consumed even if the remote helper refuses before
allocation.  Such a returned refusal is retained as incomplete evidence; it
is not a reason to widen privileges, mutate the kernel, or replay the ID.

The durable journal is created before device contact and records the
pre-effect binding, dispatch intent, returned frame, cleanup and terminal
state.  An ambiguous or post-dispatch failure is retained as an incident and
never makes the fixed experiment ID replayable.

## Result classification

| Observation | Result |
|---|---|
| returned fixed trace/perf refusal proves no allocation was attempted | `TRACE_ORACLE_UNAVAILABLE`; fixed ID remains consumed after dispatch and physical provenance remains `UNKNOWN` |
| calibration unavailable before the camera allocation | no camera allocation is dispatched; absolute PA remains `UNKNOWN` |
| complete anchored, contiguous RBIN chunks exactly cover `[0xc2000000,0xd6000000)` | emitted `EXACT_CAMERA_PREVIEW_RBIN_REGION`; interpret as exact RBIN physical placement proved |
| complete anchored, contiguous CMA record exactly covers `[0xc2000000,0xd6000000)` | emitted `EXACT_CAMERA_PREVIEW_CMA_REGION`; placement is proved but the backend disagrees with the expected fresh-RBIN path |
| complete anchored, contiguous union occupies a different range | emitted `NONEXACT_CAMERA_PREVIEW_RBIN_REGION` or `NONEXACT_CAMERA_PREVIEW_CMA_REGION`; pause on source/runtime disagreement, with no boundary-bypass claim |
| non-contiguous, missing, lost, duplicate, malformed or non-attributable records | `INCOMPLETE_EVIDENCE`; private returned evidence is retained and no physical claim is published |

Every outcome leaves `CLASS C (TRANSFORM ONLY)` unchanged unless a separate
experiment demonstrates a physical-to-DRAM alias or protected-boundary
effect.

## Non-overlap

The concurrently integrated TZ SMC/IO allowlist audit uses host-side firmware
bytes only.  V030 touches only the current A90's normal-RAM RBIN allocator and
ION tracepoint observation.  It does not share code outputs, firmware ranges,
address apertures or semantic questions with that audit.

The deferred GICD control remains a separate instrument-validation candidate
and requires a boot-image transition.  `GICD_PIDR2` at `0x17a0ffe8` is a valid
register inside the 64 KiB distributor aperture, but it would require widening
the existing inline probe's fixed `0x5c` mapping.  V031 instead uses
`GICD_TYPER`/`GICD_IIDR` at offsets `0x004`/`0x008`, which fit the unchanged
minimal window.  Neither control is part of V030.

## Host implementation verification

The production host coordinator, fixed native probe, and focused regression
suite are complete.  Ten focused tests pass, the Python coordinator compiles,
its host-only `--preflight` passes, and the native probe builds with
`aarch64-linux-gnu-gcc -O2 -static -Wall -Wextra -Werror`.  The native source
SHA-256 used by preflight is
`6434c33c0ced5031c3492b2853f35171ccdfdbceb5c39affbc715a1450726768`.

No `--execute`, bridge, USB, ADB, ACM, MMIO, allocation, or other device
command was invoked during this host implementation pass.  Repository-wide
validation is deferred until integration with the main worktree because this
isolated worktree lacks ignored private fixtures required by older tests; no
full-suite PASS is claimed here.
