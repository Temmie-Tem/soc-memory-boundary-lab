# Experiment 023 — The bank relation in a second region, and PA24

## Question

Experiment 014 recovered a GF(2) bank-selection relation inside one 16 MiB ION
`user_contig` allocation and left PA bits 24 and above `UNKNOWN`. Two things
about that were unexamined. Only one region was ever measured, and Experiment
006 had found a six-slot region remapper at `qhs_llcc + 0x8080`, so a
region-dependent transform was a live possibility. And the unreached bits were
assumed to be a matter of effort.

They were not. `user_contig` is a 16 MiB CMA window, so a difference of
`0x1000000` does not fit in it. Bit 24 was structurally out of reach of the
allocation path, not merely unmeasured.

## Scope and eligibility

Device measurements are read-only: the probe allocates from an ION heap, maps
it, reads, and frees. It writes no register, no partition, no protected memory
and nothing outside its own allocation. No governor or operating point was
changed; CPU7 was already `performance` at 2,841,600 kHz and the
`cpu-llcc-ddr-bw` governor already `performance` at 7,980, the same operating
point Experiment 014 recorded. No boot image was flashed and the device stayed
in recovery throughout.

Conceptual Experiments 015 and 016 remain reserved and `NOT ELIGIBLE`. This
proves no alias, no mutation and no protected reach.

## Result

`PROVED`: the Experiment 014 relation holds unchanged in a second carveout.
Nine differences replayed at the `qseecom` region classify exactly as
Experiment 014 classified them, with a 306 milli-tick non-overlap gap.

`PROVED`: PA24 contributes `b1 ^ b2`. Of eight discrimination differences,
exactly one is in the kernel class, with a 168 milli-tick gap; seven held-out
controls not used to fit it all agree with the extended relation, with a 195
milli-tick gap.

`REFUTED`: Experiment 014's silence about PA24 reflects a limit of effort.
It reflects a 16 MiB allocation window.

The extended relation, with the new term in bold:

```text
b0 = PA13 xor PA16 xor PA18 xor PA19 xor PA20 xor PA23
b1 = PA14 xor PA16 xor PA17 xor PA18 xor PA21 xor PA23 xor **PA24**
b2 = PA15 xor PA17 xor PA18 xor PA19 xor PA22 xor **PA24**
```

| Row bit | Bank-basis contribution |
|---:|---|
| 16 | `b0^b1` |
| 17 | `b1^b2` |
| 18 | `b0^b1^b2` |
| 19 | `b0^b2` |
| 20 | `b0` |
| 21 | `b1` |
| 22 | `b2` |
| 23 | `b0^b1` |
| **24** | **`b1^b2`** |

`UNKNOWN`: PA25 and above, which a 32 MiB allocation still cannot vary; whether
the relation holds in regions other than these two; the responsible register;
any alias or protected-boundary effect.

Current classification is unchanged:

```text
CLASS C (TRANSFORM ONLY)
NO_BOUNDARY_BYPASS_OBSERVED
```

## Measuring without a physical address

Experiment 014 bound its allocation to a physical interval through a
`/proc/kpageflags` buddy transition, which needs the allocation to be
contiguous. The `qseecom` carveout is `no-map`, so its pages are not in the
buddy allocator and that method cannot see it.

It is not needed. For a linear `f` a conflict is `f(a ^ b) == 0`, a function of
the difference alone, so replaying a difference in another contiguous region
tests whether `f` is the same there without knowing where the region starts.

That shortcut has one requirement, and the measurements show what happens when
it is not met. An offset difference equals a physical difference only when the
allocation base is aligned to the allocation size; otherwise `base + offset`
carries into bits the difference does not name.

Experiment 014's window began at `0xf0400000`, which is 4 MiB aligned but not
16 MiB aligned. So in the validation run, differences reaching bit 22 —
`0xc84000`, `0x95c000`, `0xc86000`, `0x95e000` — are outside what this method
can read, and the analysis excludes them rather than reporting them as
disagreement. The five remaining differences reproduce Experiment 014 exactly.

The `qseecom` region is `reg = <0xa6000000 0x2400000>` in the device tree, and
`0xa6000000` is 32 MiB aligned, so a 32 MiB allocation there admits every
difference. That the four excluded differences then classify correctly at
`qseecom`, agreeing with Experiment 014's ground truth, is itself the check
that the allocation really did start at the carveout base.

## The apparatus reproduces Experiment 014 from a different kernel

The device is in TWRP recovery on kernel `4.14.190-Grass,SD855-Perf+`, not the
V2321 runtime on `4.14.190-25818860-abA908NKSU5EWA3` that Experiment 014 used,
and the probe here is a separate program from
`tools/a90_dram_timing_probe.c`. Its timing core — the reopen sequence, the
barriers, the counter reads, the trimmed mean — is reproduced from that probe so
the numbers are comparable.

In the validation run the kernel-class minimum p10 is 343 and the negative
maximum p90 is 15, a 328 milli-tick gap. Experiment 014 reported a 314
milli-tick gap. Absolute deltas differ, as two kernels and two probes should,
but the separation and every classification match.

Write-combine is not source-backed here as it was in Experiment 014, since the
recovery kernel's source is not retained. It follows from the same `flags = 0`
ION path, and it is checked behaviourally: Experiment 014 `REFUTED` a cached
mapping as a DRAM classifier on this target because LLCC confounded it, so a
cached mapping would have collapsed the separation rather than reproducing it.

## Why the region result matters, and how far it goes

Two distinct carveouts, `0xa6000000` and the `user_contig` CMA window, decode
identically. Within the range these measurements reach, the transform is not
region-programmed, and the Experiment 006 remapper is either inactive or does
not affect bank selection between them.

That is a bounded statement about two regions. It is not a claim about the
whole address space, and it is the kind of claim Experiment 022 exists to keep
honest: 32 MiB of roughly 6 GiB is about half a percent, twice Experiment 014's
reach and still a sliver.

## Evidence

- `evidence/manifests/023-second-region-bank-relation-20260826-01.manifest.json`
- Raw probe output and device context: `evidence/private/` (Git-ignored)

The manifest contains classifications, gaps, counts and the recovered relation
only. It contains no raw firmware bytes and no private paths.

## Reproduce

```sh
aarch64-linux-gnu-gcc -O2 -static -o a90_region_probe tools/a90_region_probe.c
adb push a90_region_probe /tmp/a90_region_probe && adb shell chmod 755 /tmp/a90_region_probe
adb shell '/tmp/a90_region_probe user_contig 16 1001 64 7 0x16000 0x3a000 0x24a000 0x38000 0x248000'
adb shell '/tmp/a90_region_probe qsecom 32 1001 64 7 0x1000000 0x1100000 0x1200000 0x1400000 0x1010000 0x1020000 0x1080000 0x1040000'

python3 tools/a90_region_timing_analysis.py \
  --validation   evidence/private/023-second-region-20260826-01/phase1-user_contig.jsonl \
  --replay       evidence/private/023-second-region-20260826-01/phase2-qsecom-replay.jsonl \
  --discriminate evidence/private/023-second-region-20260826-01/phase3-pa24-discriminate.jsonl \
  --heldout      evidence/private/023-second-region-20260826-01/phase4-heldout.jsonl \
  --output evidence/manifests/023-second-region-bank-relation-20260826-01.manifest.json
python3 -m unittest -v tests.test_a90_region_timing_analysis
```

## Provenance

- Probe source SHA-256:
  `dc6c44645bfabaecd59b2cf8f370fa5f28329862e0991c050cc53df6a665d15d`.
- Static probe binary SHA-256:
  `67cc4d1cb2ffeb937e2620bb0bd5b0e503376b3981bd0ffd533434184f5f43ef`.
- Analysis tool SHA-256:
  `6c2f2017a293198c730bc7073e3b3af9b716483d289bd3b97d9b90dbdae900db`.
- Focused-test SHA-256:
  `4471bae4c7b7d1f5ea15a3035e2ca5e9114c19a492a5219e91a2378571f9b0ef`.
- Public manifest SHA-256:
  `297ecfcbfd8a47a61b18ba4f6e957d393ea4bdaeccb9954cac6705fc4637e953`.
- Focused result: 28 tests pass.
- Device: `SM-A908N`, TWRP 3.7.0, kernel `4.14.190-Grass,SD855-Perf+`,
  CPU7 `performance` at 2,841,600 kHz, `cpu-llcc-ddr-bw` `performance` at 7,980,
  `CNTFRQ_EL0` 19.2 MHz. No partition, register or boot-image write.
- Date: 2026-08-26 KST.
- Produced on branch `research/xbl-config-cdt` in a separate worktree.
  `STATUS.md`, `docs/EXPERIMENT_MATRIX.md` and `docs/RESEARCH_LOG.md` are
  deliberately untouched here and are reconciled at integration.
