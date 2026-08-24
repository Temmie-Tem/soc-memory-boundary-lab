# Normal-RAM Physical-to-DRAM Alias Design

State: `DESIGNED / NOT RUN`. A transform-register candidate and write gate are
missing, so the mutation phase is ineligible.

## Required proposition

For pinned, ordinary RAM pages with independently proved PFNs `PA_A != PA_B`, a
candidate state `S1` must repeatedly show:

```text
DRAM_S1(PA_A) == DRAM_S1(PA_B)
```

or another precisely predicted cross-state equality. A single equal read is not
sufficient.

## Baseline and controls

1. Allocate physically distinct, pinned pages from an experiment-owned pool.
   Record PFNs from inside the kernel, PTEs, `struct page` identity and allocation
   lifetime. `PROVED` distinct PFNs are a precondition.
2. Under unchanged state `S0`, alternate nonsecret 256-bit markers and their
   inverses in A/B for many trials. Clean to the point of coherency, fence,
   invalidate, and independently reread. A and B must remain distinct.
3. Positive control: map two VAs to the same PA and show the harness detects a
   known virtual/page-table alias. Label it explicitly as such.
4. Negative control: map two VAs to the two distinct PAs and show identical VA
   layout/cache operations do not cause cross-observation.
5. Use one CPU, pin execution, suppress preemption/interrupt noise only inside a
   bounded critical section, and use ARM64 `dsb/isb` plus source-reviewed cache
   maintenance. Do not mix conflicting memory attributes for live aliases.
6. Record cacheable and carefully constructed Normal-NonCacheable trials
   separately. An effect that disappears after correct maintenance is a cache
   artifact, not a DRAM alias.
7. Keep DMA out of the primary proof. If an independent DMA read is later used,
   first prove its IOVA-to-PA mapping and SMMU domain; an IOMMU/DMA alias is a
   separate result.

## Candidate-state trial after approval

1. Read and hash exact pre-state register values.
2. Enter the one-core bounded section; quiesce other experiment traffic.
3. Apply only the approved bit transition and verify readback.
4. Perform one bounded marker operation through A/B.
5. Restore the exact pre-state before leaving the section and verify readback.
6. Reestablish normal cache state, then validate marker relationships through a
   separately constructed mapping/read path.
7. Randomize markers and A/B order. Require deterministic reproduction plus
   unchanged-state negative trials. A reboot must return the baseline unless
   separately proved otherwise.

## Classification defenses

| Alternative | Required exclusion evidence |
|---|---|
| Virtual-address alias | Different VAs plus kernel-proved different PFNs; same-PA positive control kept separate. |
| Page-table alias | Captured PTE/PFN and stable pinned pages before/after each trial. |
| Cache-coherency artifact | Correct clean/invalidate/fences; cacheable and noncacheable agreement; alternating markers. |
| DMA alias | CPU-only primary result; any DMA path has independently proved IOVA/PA/SMMU mapping. |
| IOMMU alias | No IOVA is treated as a CPU PA; SMMU domain and mappings captured if used. |
| Memory corruption/race | One-core bounded section, guard pages, canaries, repetition and immediate state restoration. |
| Actual physical-to-DRAM alias | Survives all above controls and follows the transform model's predicted address relation. |

Protected carveouts are never inputs to this experiment. Only after this result
is `PROVED` and protection ordering is independently supported may a minimal
boundary validation be designed.
