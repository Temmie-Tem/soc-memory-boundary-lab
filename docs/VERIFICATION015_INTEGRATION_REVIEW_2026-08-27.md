# Verification 015 runtime-invariance integration review — 2026-08-27

## Integration boundary

This iteration starts from clean repository commit `5a803fa`, after Experiment
034 and exact-parent external reconciliation. Historical commits `05a4c5c`,
`a297fde`, and `b2b5068` identify the original measurement, coldboot addition,
and bandwidth-axis retraction. They were evidence to revalidate, not code to
cherry-pick. Commit `4b78b61` is review prose and is not imported. Later
Verification 016/017 commits `6b3abc7` and `c91f473` remain outside this
iteration.

The V015 artifact set consists of four public files: the repaired analyzer, its
focused tests, the experiment README, and the generated manifest. This review
and the root-document updates only summarize and link that artifact set.
Private transcripts are parsed and hashed from one stable snapshot, then
independently re-read and required to match before publication; they remain
ignored and private. No device, USB, reboot, bus vote, SMC, MMIO, memory,
partition, protected-memory or controller action occurred in this integration.

## Repaired evidence contract

The original result was not promoted unchanged. The repair closes the observed
empty-glob/six-versus-eleven-level/provenance defects and the later independent
review findings:

- exact basename/size/SHA-256 pins for 15 condition transcripts, one repeat
  transcript, one six-level sweep transcript and two journals;
- stable-snapshot parse/hash followed by an independent matching re-read,
  strict JSON/context/heap/pagemap validation, exact pair counts and recomputed
  qsort-index p10/median/p90 values;
- equal 51-key condition sets, per-key observation values and dispersion, and
  scale-invariant within-condition separation;
- exact binding of the two primary L762 disagreements to independently split
  repeat groups; any repeated flip survives rather than being majority-voted
  away;
- auxiliary heap/pagemap/context binding, while keeping reported contiguity
  separate from effective contiguity under `BLIND` pagemap;
- a fail-closed canonical public build; noncanonical input requires the explicit
  distinct analysis-only schema. Claim vocabulary is closed, public keys and
  values are sanitized, and atomic no-clobber publication has inode/byte and
  hostile input/output-substitution controls.

## Bounded result

`PROVED` from exact retained bytes, strictly in
`ALLOCATION_OFFSET_MODEL_COORDINATES`:

| Condition label | Files | Threshold | Empty band | Gap | Runner-up | CONFLICT |
|---|---:|---:|---:|---:|---:|---:|
| `twrp-pre-L7980` | 4 | 371 | 199..543 | 344 | 7 | 25 |
| `twrp-pre-L6881` | 4 | 573 | 375..771 | 396 | 3 | 25 |
| `twrp-post-L7980` | 2 | 365 | 192..538 | 346 | 13 | 25 |
| `v2321-L7980` | 2 | 351 | 182..521 | 339 | 8 | 25 |
| `v2321-L762` | 1 | 274 | 192..357 | 165 | 140 | 27 |
| `v2321-coldboot-L7980` | 2 | 350 | 181..519 | 338 | 8 | 25 |

Four comparisons to `v2321-L7980` have 51 shared labels and zero
disagreements. `v2321-L762` has exactly two excursions, `0x100e000` and
`0x1012000`, and remains `REPEAT_REQUIRED`; global `all_invariant` remains
false. Six independently thresholded repeat groups cover both excursions and
have zero low/high label flips. This repeat result does not promote the primary
L762 comparison.

The retained sweep is exactly six requested bus-vote levels times two
repetitions, not eleven levels. It is `RETRACTED_AND_EXCLUDED` from DDR-frequency
or transform-transition inference: the reported higher-voter observation has
no retained transcript. The sweep is measurement-stability evidence only.

`SUPPORTED`, not proved by the raw condition files: their TWRP/V2321, reboot,
kernel/userspace and coldboot identities. These come from unretained operator
report and retained project context. Exact acquisition timestamps, probe build
and two-environment transfer receipts, power-cycle/reboot receipts, and complete
rollback/recovery/final-state receipts remain `UNKNOWN` or incomplete. Pagemap
is `BLIND`; effective physical contiguity and physical-page provenance remain
`UNKNOWN`.

## Artifacts and validation

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| Analyzer | 97,572 | `6fae489d27d03f94e9dcd89086027a4209988a67020620e54f1df7e22ca99e03` |
| Focused tests | 28,904 | `ccd6604febeb3c16e40c253a51f5a3fe35c3c61dcd77f6757daa2a9b8ca23ceb` |
| Experiment README | 11,820 | `0c2166e25707ea1381850a64c3089afefccf4ec6f7102f7d1253addbc2461c2d` |
| Public manifest | 112,840 | `fab880dc50f8e66e74828a0276f8e5ab5ef9b1f2b2f2f9f032dcef03b6b98592` |

- Focused suite: **44/44 PASS**, maximum RSS **31,576 KiB**, swap **0**.
- Full serial discovery: **1,039/1,039 PASS** in **109.389 s**, maximum RSS
  **275,168 KiB**, swap **0**.
- Python byte-compilation, public JSON parsing, manifest/build byte equality,
  local-link checks and `git diff --check` pass.
- Two fresh manifest generations are byte-identical. The publisher requested
  and observed mode `0644` for fresh outputs; exact checkout permissions are not
  part of Git artifact identity.
- Independent hostile review recomputed 19/19 pins, 43 sections, 633 summaries,
  10,704 pairs and zero qsort mismatches, then returned **PASS** with no
  remaining P0–P2 for the stable four-file tree.

## Disposition

`PASS`: the numerical condition-labelled result is integrated as bounded
host-side evidence. It supports stability across the operator-reported
transitions but does not prove immutable transform state, actual DDR-frequency
variation, a physical-to-DRAM alias, transform mutation, protected-memory
reach, protection ordering or bypass.

Class remains `CLASS C (TRANSFORM ONLY)`. Numbered conceptual Experiments 015
and 016 remain `NOT_ELIGIBLE`. The next highest-information non-overlapping
iteration is a separate repair of retained Verification-016 high-bit evidence:
preserve phases, remove filename-order merging, pin provenance, and keep
PA25–PA27 physical attribution model-scoped until base/alignment/contiguity is
proved. Verification 017 cannot consume that relation before this gate passes.
