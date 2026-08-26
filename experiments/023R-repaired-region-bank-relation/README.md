# Experiment 023R — repaired second-region bank relation and its uniqueness

## Why this experiment exists

Experiment 023 measured the DRAM bank relation in a second physical region and
was withheld `NO-GO` on three grounds: its timing protocol was not comparable
to Experiment 014, it had no physical-address provenance, and the GF(2)
relation it reported was not unique. All three objections were checked against
Experiment 014's source and all three hold. 023R repairs them.

The clearest single consequence: Experiment 023 reported "gap 328 milli-ticks
against 014's 314" as evidence that its apparatus reproduced 014. Experiment
014 divides its summed reopen pair by `kept * 2`; Experiment 023 did not
divide at all. Its numbers were on a 2x scale, so that comparison was between
two different units and should never have been made.

## Scope and eligibility

Device-side and read-only: allocate, map, read, free. No register, partition,
boot-image, governor, or device-memory write outside the probe's own
allocation. The device stayed in TWRP recovery throughout. The operating point
was already the one Experiment 014 recorded and was not changed.

Conceptual Experiment 015 (a controlled normal-RAM alias) and Experiment 016
(protected-boundary reach) remain `NOT ELIGIBLE`. 023R proves no alias, no
transform mutation, no protected reach, and no bypass.

## The four protocol repairs

Each was confirmed by reading `tools/a90_dram_timing_probe.c` before being
repaired, not inferred from the objection.

| Aspect | Experiment 014 | Experiment 023 | 023R |
|---|---|---|---|
| Order | alternates relation/baseline first on `repetition & 1` | relation always first | alternates, as 014 |
| Warmup | all four reopen forms | two of four | all four |
| Barrier | `load_barrier` is `dsb ld` | `dsb ld; isb` | `dsb ld`, as 014 |
| Scale | divides by `kept * 2` | no divisor | divides by `kept * 2` |

The extra `ISB` is why 023's non-conflicting differences sat near zero while
014's sat near 210: serialising every measurement masks the small cost a
row miss in a *different* bank still carries. The timed quantity was not the
same quantity. `measure_reopen_once`, `read_cntvct` and `load_barrier` are now
copied from 014 verbatim, including the exact inline asm.

## Inputs

- Device `SM-A908N`, TWRP recovery, kernel `4.14.190-Grass,SD855-Perf+`.
- CPU7 `performance` at 2,841,600 kHz; `soc:qcom,cpu-llcc-ddr-bw`
  `performance` at 7,980; `CNTFRQ_EL0` 19.2 MHz. Unchanged from Experiment 014.
- Region: `qseecom_region`, device-tree `reg = <0x0 0xa6000000 0x0 0x2400000>`,
  `compatible = "shared-dma-pool"`, `no-map`. 36 MiB, distinct from Experiment
  014's 16 MiB `user_contig` CMA window.
- ION heap `qsecom`, heap id 27, type 4. 32 MiB allocation, write-combine
  (no `ION_FLAG_CACHED`).
- 1001 repetitions and 64 pairs per difference, 17 warmups per form.
- Five phases, 66 differences: 34 measured conflicting, 32 measured
  non-conflicting.

## Classification comes from the measurements, not from Experiment 014

Importing 014's numeric floor as this run's classifier would make agreement
with 014 partly an artefact of the threshold. Deltas are split instead at the
widest gap in their own sorted distribution, which uses no model and no prior
run.

- Widest gap: 182 to 537 milli-ticks, an empty band 355 wide; threshold 359.
- Kernel-class minimum p10 512; non-conflicting maximum p90 224; class gap 288.
- Experiment 014 reported 536 and 222. **Both fall strictly inside this run's
  empty band**, which is the comparability check, made without using either
  number to classify anything.

Two differences in phase A, `0x230000` and `0x288000`, were typed into the run
script by hand with an arithmetic slip; their vectors are `111` and `011`, so
they were never kernel elements. The model predicts non-conflicting and the
measurement agrees. They are reported as negative controls, not as
predictions.

## Physical-address provenance is measured, not assumed

`/proc/self/pagemap` is blind here: over all 8,192 pages of the mapping, zero
are present and every PFN reads back zero. The dma-buf is `VM_PFNMAP`. This is
reported as `BLIND` rather than worked around silently.

Experiment 023 assumed the allocation began at the carveout base and offered,
as verification, that nine differences classified as 014 classified them. That
is not a test of the assumption: a shifted base reproduces exactly those labels
whenever the shift does not carry into the bits those differences name.

023R solves for the offset instead. For base `B = 0xa6000000 + delta` and
page-aligned offsets `a` and `a ^ d`, the realised physical difference is
`(B + a) ^ (B + (a ^ d))`, which equals `d` only when adding `B` carries
identically for both. Every candidate `delta` that disagrees with even one
measured pair is eliminated.

- 2,624 constraining pairs across 64 low-bit-varying offsets.
- Surviving offsets: exactly one, `0x0`.
- Control: without the phase E/F differences the surviving set is
  `{0x0, 0x200000, 0x400000}`. Only differences that set bit 21 or bit 22 make
  a 2 MiB or 4 MiB offset carry differently, so those differences are what
  resolve it. Every difference in phases B, C and D is blind to this by
  construction, exactly as Experiment 023's were.

The solve uses only Experiment 014's bits 13..23 and never PA24, so it is not
circular with the PA24 claim it supports. The allocation therefore begins at
physical `0xa6000000`, and the region is genuinely distinct from Experiment
014's `0xf0400000`.

## PA24 is resolved by exhaustive discrimination

Eight differences were chosen so that each of the eight possible 3-bit
contributions for PA24 is the unique contribution making exactly one of them
conflict. All eight were measured.

| Contribution | Difference | Measured |
|---|---|---|
| `000` | `0x1000000` | non-conflicting, p90 193 |
| `001` | `0x1002000` | non-conflicting, p90 197 |
| `010` | `0x1004000` | non-conflicting, p90 201 |
| `011` | `0x1010000` | non-conflicting, p90 199 |
| `100` | `0x1008000` | non-conflicting, p90 189 |
| `101` | `0x1080000` | non-conflicting, p90 193 |
| `110` | `0x1020000` | **conflicting, p10 539** |
| `111` | `0x1040000` | non-conflicting, p90 186 |

Exactly one survives: `0b110`. A single conflicting witness would in fact have
identified the same value, since `0x1020000` is `PA24 ^ PA17` and a conflict
forces PA24 to match PA17. What one witness cannot do is notice being wrong.
The exhaustive set supplies seven independent refutations, and a mislabelled
measurement inside it leaves no survivor at all rather than a confident wrong
answer. That error-detection property, not identifiability, is what Experiment
023 lacked.

Eighteen held-out differences that were not used to fit anything agree: ten
predicted conflicting measured p10 516 to 528, eight predicted non-conflicting
measured p90 at most 208.

## The relation is now unique, and the model order is measured

A conflict measurement observes only whether `f(d) == 0`, so the object the
data can determine is `ker f`, not `f`: 168 relabellings in `GL(3,2)` predict
identical conflicts. Reporting a single matrix as though the measurement chose
it overstates the evidence, which is what Experiment 023 did.

With Experiment 023's difference set the conflicting differences spanned only
7 of the 9 dimensions a rank-three kernel over PA13..PA24 requires, leaving
**98 consistent kernels**. Codex's uniqueness objection was correct. Phase F
added `0x408000` and `0x810000`, which raise the span to 9.

- Span dimension 9, required 9, no non-conflicting difference inside the span.
- Consistent kernels: **exactly 1**.

The rank is measured rather than assumed. Ranks 4 and 5 are refuted because the
conflicting differences span more dimensions than their kernels allow; ranks 1
and 2 are refuted because no kernel of their dimension avoids every measured
non-conflicting difference. Rank 3 alone survives.

One representative of the unique kernel, in Experiment 014's basis:

```text
b0 = PA13 xor PA16 xor PA18 xor PA19 xor PA20 xor PA23
b1 = PA14 xor PA16 xor PA17 xor PA18 xor PA21 xor PA23 xor PA24
b2 = PA15 xor PA17 xor PA18 xor PA19 xor PA22 xor PA24
```

The kernel is unique; this particular `b0/b1/b2` labelling is one of 168 that
describe it.

## Claims and ranking

`PROVED`: the four protocol repairs; a class separation whose empty band
contains both of Experiment 014's reported bounds; the allocation's physical
base `0xa6000000`, solved from 2,624 pairs with a control showing which
differences resolve it; PA24's contribution `0b110` by exhaustive
discrimination over all eight candidates with 18 held-out agreements; a
9-dimensional kernel span with exactly one consistent kernel; model rank 3
with ranks 1, 2, 4 and 5 refuted; and the bank relation holding in a second,
independently located physical region.

`REFUTED`: Experiment 023's claim that its apparatus reproduced 014's
magnitude, which compared a 2x-scaled figure with 014's; Experiment 023's
replay as verification of its own base assumption; and, for this difference
set, model ranks 1, 2, 4 and 5.

`UNKNOWN`: PA25 and above, which a 32 MiB allocation cannot vary; behaviour in
any region beyond the two measured; the mapping from this relation to named
controller registers; whether any transform is mutable or reachable. The
`/proc/self/pagemap` route to physical addresses is `BLIND`, not merely
unused.

Current classification is unchanged: `CLASS C (TRANSFORM ONLY)` /
`NO_BOUNDARY_BYPASS_OBSERVED`. 023R strengthens the transform's description
and its provenance; it demonstrates no alias, no mutation, and no bypass.
Experiments 015 and 016 remain `NOT ELIGIBLE`.

## Reproduction and provenance

```sh
aarch64-linux-gnu-gcc -O2 -static -Wall -Wextra \
  -o a90_region_probe_r tools/a90_region_probe_r.c
# on device, read-only:
#   ./a90_region_probe_r qsecom 32 1001 64 7 stride  <phase A differences>
#   ./a90_region_probe_r qsecom 32 1001 64 7 spread  <phase B/C/D/EF differences>
python3 tools/a90_region_relation_solver.py \
  --raw <private raw directory> --probe tools/a90_region_probe_r.c \
  --output evidence/manifests/023R-repaired-region-bank-relation-20260826-01.manifest.json
python3 -m unittest -v tests.test_a90_region_relation_solver
```

- Probe SHA-256:
  `31fa568ef1bf9257cbc3ba555dbda66458e6318f113dd4a4dca4c5ac739b4377`.
- Solver SHA-256:
  `5f8d1f346a6d46f6b990cf069062b5fd79cad15a67227bffa061a70059cfadea`.
- Focused result: 32 tests pass. Full repository discovery: 513 tests pass.
- Raw phase output is retained privately under
  `evidence/private/023R-repaired-region-20260826-01/`; the public manifest
  carries its SHA-256 digests only.
- Date: 2026-08-26 KST. Mode: `DEVICE_READ_ONLY`; no MMIO, SMC, register,
  partition or boot-image access.

The public manifest contains thresholds, counts, classifications, difference
values and hashes only. It contains no raw firmware bytes and no private
absolute paths.
