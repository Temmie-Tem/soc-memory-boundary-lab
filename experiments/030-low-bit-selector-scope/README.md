# Experiment 030 — Does the bank relation extend below the page?

## Question

Experiment 023R proved a rank-3 relation over allocation-offset/model bits
PA13..PA24. Experiment 014
reported PA9 and PA10 as "two further independent selection components
consistent with channel selection", ranked `SUPPORTED`, which would make the
full selector rank 5. Since 014's window was PA0..PA23 and 023R's is
PA13..PA24, the two numbers are not in conflict on their face — but whether
they describe one selector or two windows depends on what PA9 and PA10 do.

## Result

They do something, and it is not what the evidence for them assumed.

014's test was that adding PA9 or PA10 to the kernel witness `0x16000` made the
result leave the conflict class. That observation reproduces exactly. The
inference from it does not, because a difference can leave the conflict class
in two opposite directions and only one of them means the bit selects
anything:

- **downward**, to the non-conflict level, is what a selection component does:
  the two addresses stop sharing a bank, so nothing interferes;
- **upward**, past the conflict level, is a different event entirely.

PA9 and PA10 leave upward. The control that separates the two cases is to add
the bit to a difference that is already *non*-conflicting.

## Measurement

Same apparatus as Experiment 023R: the model/device-tree-declared `qsecom`
carveout base `0xa6000000` (not an observed physical base), 32 MiB
write-combine ION allocation, CPU7 at 2,841,600 kHz,
`cpu-llcc-ddr-bw` `performance` at 7,980, 1001 repetitions, 64 pairs,
alternating order, `dsb ld`, per-reopen milli-ticks. The probe's sub-page
restriction was lifted: offsets are page aligned and the allocation base is
page aligned, so a pair's low bits differ by exactly the difference's low bits
with no carry.  Pagemap is `BLIND` for all phases, so the absolute base remains
`SUPPORTED_WITHIN_MODEL_NOT_OBSERVED`; the measurements establish relative
offset behavior only.

The analysis keeps each probe phase separate.  Phase C is the complete
low-bit sweep in `spread` mode (64 pairs); phase D is an independent retest in
`stride` mode (32 pairs).  Their reference levels are therefore not merged:

| Phase / mode | Same row `0x800` | Non-conflict `0x2000` | Conflict `0x16000` |
|---|---:|---:|---:|
| C / `spread`, 64 pairs | **21** | **172** | **544** |
| D / `stride`, 32 pairs | **19** | **168** | **538** |

Each low bit in phase C was measured three ways: alone, added to the
conflicting witness, and added to the non-conflicting witness.

| Bit | Alone | With `0x16000` | With `0x2000` | Phase C verdict |
|---:|---:|---:|---:|---|
| PA0–PA3 | 16–22 | 534–542 | 164–170 | INERT |
| PA4 | 22 | 367 | −4 | MODULATING |
| PA5 | −19 | 271 | −68 | MODULATING |
| PA6–PA8 | 20–23 | 538–543 | 158–162 | INERT |
| **PA9** | **717** | **702** | **702** | **SATURATING** |
| **PA10** | **453** | **461** | **463** | **SATURATING** |
| PA11, PA12 | 21, 11 | 537, 538 | 154, 160 | INERT |

Phase D's overlapping measurements are retained independently:

| Bit | Alone | With `0x16000` | With `0x2000` | Phase D verdict |
|---:|---:|---:|---:|---|
| **PA9** | **762** | **753** | **760** | **SATURATING** |
| PA10 | **503** | — | — | INCOMPLETE |

The retained phase-D JSONL contains PA10 alone (`0x400`, median 503), but it
does not contain the `0x16400` or `0x2400` differences needed for the other
two cells.  A pre-repair mixed manifest listed 461 and 463 there, matching
phase C, but its phase-D attribution cannot be reproduced from the retained
raw file.  This repair leaves those values out of the phase-D classification
rather than inventing raw evidence; the phase-C result remains SATURATING and
the phase-D PA9 retest is independently SATURATING.

The public manifest's `phase_measurements`, `phase_contexts` and
`phase_results` fields preserve the complete per-phase medians, offset mode,
pair count and verdicts. A consensus verdict is emitted only when all phases
with a complete three-cell/non-`INCOMPLETE` verdict agree; incomplete partial
measurements remain visible and do not create consensus. A disagreement is
reported explicitly and is never resolved by input-file order.

**No low bit behaves as a selection component.** Nine are inert, confirming
014's list of bits that preserved the class. PA4 and PA5 move the levels
unevenly, which is why 014 excluded them as intermediate. PA9 and PA10 drive
the conflicting and non-conflicting witnesses to *the same* value — once either
is set, the bank relation is no longer visible through the metric at all.

The PA9 reading is robust across both offset modes (phase C: 64 pairs; phase
D: 32 pairs) and for three separate kernel witnesses (`0x16000`, `0x2c000`,
`0x102000`) in the spread-mode control data.  Those witnesses give `+PA9`
medians of 759, 758 and 760 against their own conflict levels of 541, 543 and
532.  Phase B also contains a complete spread-mode PA10 triplet: **506**
alone, **500** with `0x16000`, and **464** with `0x2000`, classified
**SATURATING**.  Phase C's complete PA10 triplet is **453**, **461**, **463**,
also **SATURATING**.  Only the phase-D cross-mode PA10 retest is incomplete:
its raw file retains **503** alone but lacks the `0x16400` and `0x2400`
witness combinations.

## What the result falsifies about the channel-selection interpretation

If PA9 were an independent channel selector whose only effect was to separate
the two addresses, a conflicting pair with PA9 added would land in different
channels, nothing would interfere, and the delta would fall to the non-conflict
level near 168. It rises to about 760 — well above the conflict level of 538.
That simple independent-selector inference is contradicted by the measurement;
it does not rule out a joint channel contribution or another coordinate.

That is not a claim that the bits are inert. The retained measurements do not
isolate whether saturation is caused by channel, rank, bank group, or another
coordinate. This experiment does not assign a DRAM coordinate to either bit;
it establishes that the reopen delta saturates on them and therefore cannot
identify their physical role.

## Claims and ranking

`PROVED` within the retained allocation-offset observation: the phase-specific
reference levels above; that phase C measures
PA0–PA3, PA6–PA8, PA11 and PA12 as inert against both a conflicting and a
non-conflicting witness; that PA9 and PA10 drive both witnesses to the same
value in phase C; that phase D independently reproduces the PA9 saturation;
and that no bit measured in the complete phase-C sweep below PA13 lowers a
conflicting difference to the non-conflict level.  The phase-D file is a
partial retest, so unmeasured phase-D bits remain unclassified there.

`REFUTED`: only the Experiment 014 inference that an upward class departure
proves an independent channel selector. PA9 and PA10 could still contribute
jointly to channel or another coordinate; the data do not identify their
physical role.

`UNKNOWN`: what PA9 and PA10 do select, if anything — rank and bank group are
consistent with a penalty above a bank conflict but are not established here;
PA4 and PA5, whose uneven movement this experiment does not resolve either;
and the contents of the SMEM DDR structure, which this kernel offers no way to
read.

Consequence for Experiment 023R within its validated model dependency: its
rank-3 result stands and is not extended downward. The selector's rank over
PA13..PA24 is 3; a rank-5 selector over a wider window is not established by
PA9 and PA10, so the two remaining dimensions, if they exist, are not located.

Classification is unchanged: `CLASS C (TRANSFORM ONLY)` /
`NO_BOUNDARY_BYPASS_OBSERVED`. Experiments 015 and 016 remain `NOT ELIGIBLE`.

## Reproduction and provenance

```sh
# on device, read-only:
#   ./a90_region_probe_r qsecom 32 1001 64 7 spread <differences>
#   ./a90_region_probe_r qsecom 32 1001 32 7 stride <differences>
python3 tools/a90_low_bit_selector_analysis.py \
  --raw <private raw directory> \
  --relation-manifest <023R public manifest> \
  --output evidence/manifests/030-low-bit-selector-20260826-01.manifest.json
python3 -m unittest -v tests.test_a90_low_bit_selector_analysis
```

The reproduction commands are `REDACTED_REPRODUCTION_TEMPLATE`s: private raw
and output paths are redacted, while the 023R relation manifest is pinned by
hash; they are not executed-command receipts.

- Focused result: 21 tests pass. Full repository discovery was not rerun for
  this repair.
- Current verifier tool SHA-256:
  `ec144a7d76864bb765505e57877eb046bf2490e7b25cbfd0ef1d3a84364b9f93`.
- Current verifier focused-test SHA-256:
  `93d2ea8720b714846c2afa84281ea8aec6ad01a723ec6b21318c36a0447f84a9`.
- Repaired public manifest SHA-256:
  `28f167a67a8d32c56a227e01f93ea243ff9bb2eb1ba4bb1007524b9c71b0a73f`.
- Validated 023R relation-manifest SHA-256:
  `5c3e14ff898c109de740d98260d974bca10751000f85977775cd467ac74aac2e`.
- Raw phase output is retained privately under
  `evidence/private/030-low-bit-selector-20260826-01/`; the public manifest
  carries its SHA-256 digests and phase summaries only.  Device-observation
  context and host-analysis provenance are separate manifest sections.
- The manifest records a retained-device-context target and an `UNKNOWN` build
  because no exact live bind/build receipt is present in the raw phase files;
  it records the date, commands and 1001 repetitions with explicit read-only
  and no-op rollback boundaries.
- Date: 2026-08-26 KST. Mode: `DEVICE_READ_ONLY`; allocate, map, read, free.
  No governor, register, partition or boot-image write is claimed; recovery
  state is not independently asserted by this retained analysis.
