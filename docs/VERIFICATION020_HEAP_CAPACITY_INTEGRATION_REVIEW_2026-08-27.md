# Verification 020 heap-capacity integration review - 2026-08-27

## Boundary and retained evidence

Verification 020 measures the allocation-size gate for reopen condition 2.
The retained coarse and fine ladders are private regular files; this review
performed no device, USB, ION, MMIO, SMC, SCM, controller, protected-memory or
partition action.  The public reduction is
`evidence/manifests/verification-020-heap-capacity-20260827-01.manifest.json`.

Only three non-secure heaps were attempted: `camera_preview`, `qsecom` and
`user_contig`.  `system` is page-based and cannot provide a contiguous span;
secure and remote-processor heaps were enumerated but withheld because an
allocation would cross the `hyp_assign`/VMID pause gate.  Their capacities are
`UNKNOWN`, not zero.

## Claim disposition

`PROVED` within the retained ladders and the device/firmware uptime recorded by
the producer: monotone ceilings are 320 MiB (`camera_preview`, 320 success /
352 failure), 32 MiB (`qsecom`, 32/64), and 16 MiB (`user_contig`, 16/32).
`NOT_MET`: no attempted non-secure heap reaches the 512-MiB reopen threshold.
`REFUTED`: the prior unbacked 256-MiB ceiling and the prior 512-MiB PA28 span
wording.  A 320-MiB span is arithmetically sufficient to contain a PA28 pair,
but the physical base is `UNKNOWN` because dma-buf `pagemap` is `BLIND`.
`UNKNOWN`: withheld-heap capacity, uptime/fragmentation dependence, physical
base selection, effective contiguity and any alias or protected-boundary
implication.  `CLASS C (TRANSFORM ONLY)` and `NOT_ELIGIBLE` remain unchanged.

The analyzer has an explicit monotonicity gate: a success above a failure is
reported as `INSTRUMENT_FAILED`, not a capacity.  A synthetic 512-MiB success
test flips the same reduction to `MET`, so the negative is not hardcoded.

## Artifact and validation pins

| Artifact | Size | SHA-256 |
|---|---:|---|
| `tools/a90_heap_capacity_analysis.py` | 12,964 | `0d50aba0f7a700dc7db3eaf0349c4562a07beadfc1bb6058cc1b63850ac4f2f9` |
| `tests/test_a90_heap_capacity_analysis.py` | 9,003 | `25c8bea60eb20fd64c007dc6eb8bd228b17f79904de72e516765884afae8613c` |
| `tools/a90_heap_capacity_probe.c` | 4,176 | `26b320115e0a23884e633709a13afa40276c66c0d95c54882bd2399fd31c8876` |
| `experiments/verification-020-heap-capacity/README.md` | 7,404 | `8022615a5e7a1f6ef79dab1f5590016ade9ecbbe8397a265f4236848d4ff6d9b` |
| `evidence/manifests/verification-020-heap-capacity-20260827-01.manifest.json` | 4,575 | `567ed802dc434965ea7a10d73fd3bea41018826dab6d13f8ea518afce657e043` |

The 21-test focused suite passes.  Re-running the analyzer over both retained
ladders regenerates the public manifest byte-for-byte.  The manifest now
contains exact filename/size/SHA pins for both raw ladders and a mechanically
checked pin for the retained probe source.  It also carries the producer's
explicit executed-binary and reproducible-build attestations, each marked
`retained: false`; the experiment README explains the basename-only build
difference.  This limitation is visible and does not change the reduction or
the bounded claims.

## Review boundary

This review does not promote `camera_preview` allocation offsets to physical
addresses, infer a DRAM coordinate, or authorize a protected-memory test.  The
next normal-RAM discriminator is a separate, explicitly gated PA28 marker test
using the measured 320-MiB heap; it must retain V018's two-VA and cache/control
negatives and remain outside the security boundary.
