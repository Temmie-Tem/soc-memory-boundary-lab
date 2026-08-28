# Verification 017 integration review — 2026-08-27

## Review boundary

This is a host-only, read-only algebra/range audit.  It consumes only the
tracked 023R/V016 public manifests and the tracked memory-map record.  It does
not access the A90, SMC, MMIO, controller registers, protected memory or any
private transcript, and it does not authorize a write.

The result is intentionally narrower than the attack question.  It tests
whether a protection mechanism that observes only the recovered three-bit bank
class could separate the listed protected carveouts from ordinary System RAM.
It does not test a complete DRAM coordinate, the placement of the check, or a
state transition.

## Independent review and repairs

The imported bounded implementation was independently checked against the
retained manifests and then repaired before publication:

1. The three public input files are size/SHA-256 pinned and semantically
   checked for a resolved unique 023R rank-3 result and the exact V016
   high-bit equalities.
2. Broad `System RAM` was not treated as wholly unprotected: the nested
   `rkp_region`/`uh_heap_region` span is subtracted, and a 4-KiB fragment below
   the 64-KiB covering span is retained as an explicit exclusion.
3. Ranges must be page-aligned; large ranges are evaluated without silent
   truncation.  The output is canonical JSON, created once with
   `O_EXCL`/`O_NOFOLLOW`, mode `0644`, and no-clobber semantics.
4. Tests include changed-input sensitivity for both relation and memory-map
   inputs, a deliberate V016 disagreement, alignment/base controls,
   low-rank/high-bit countermodels, explicit injective/non-injective GF(2)
   completions, range-size controls, overlap rejection and publication safety.

## Exact result

The relation has rank 3.  The lowest contributing model bit is 13, giving an
8-KiB minimum class-change span.  The first three independent vectors appear by bit
15, giving a 64-KiB-aligned span that covers all eight bank classes; for an
arbitrary base the conservative guarantee is 128 KiB.  The five listed
protected carveouts and nine explicitly unprotected System RAM fragments meet
that aligned-or-128-KiB bound under the allocation-offset/model-coordinate
projection.  The 4-KiB `0x80000000-0x80000fff` fragment is not used as a
representative unprotected interval because it does not meet that bound.  The
pinned 023R kernel basis and MEMORY_MAP ranges are parsed and matched before
calculation.  Three finite GF(2) completions preserve the exact bank projection
while exhibiting injective, non-injective and bank-only behavior, so complete
coordinate injectivity is underdetermined by the observed relation.

The public manifest is
`evidence/manifests/verification-017-protection-bank-granularity-20260827-05.manifest.json`
(18,108 bytes, SHA-256
`97ff68a2f8ebfb6313f228f2626f12f88260764a993f916ba1f97677d7b99f02`, mode
`0644`).  The 42 focused tests pass, and regenerated output is byte-identical
to the retained manifest.  The full serial repository suite is 1,132/1,132
PASS (`skipped=1`) in 113.958 seconds, maximum RSS 278,532 KiB, with zero swap.

A separate bounded host-process recheck independently recomputed the nine-row
023R kernel rank (9), checked all ten MEMORY_MAP System RAM rows and five fixed
carveouts, asserted the `MODEL_PROJECTED_ONLY` scope, and compared the manifest
to fresh `encode_public(analyse())` output.  It passed without device access or
large sweeps.

## Claim disposition

`PROVED`: rank/granularity arithmetic, source-manifest agreement including the
source kernel basis and parsed MEMORY_MAP ranges, the alignment-sensitive
64/128-KiB bounds, explicit range subtraction, all listed model-projected range
histograms, and the finite injective/non-injective countermodels sharing the
same bank projection.

`REFUTED` only in the declared model-projection/range scope: a bank-only
post-decode check cannot separate those protected carveouts from the explicitly
unprotected comparison ranges under the retained allocation-offset model.

`SUPPORTED`: the bank-only shape is insufficient to explain protection
separation; a check retaining additional address information remains possible.

`UNKNOWN`: actual protection ordering, complete physical-to-DRAM coordinates,
physical PA identity, PA28+, transform-state mutability, global writer/register
absence, and protected-memory reach or bypass.  The class remains
`CLASS C (TRANSFORM ONLY)` and Experiments 015/016 remain `NOT_ELIGIBLE`.

The route-2 handoff remains a falsification challenge, not a consensus gate:
`docs/CODEX_HANDOFF_ROUTE2_TERMINATION_2026-08-27.md`.
