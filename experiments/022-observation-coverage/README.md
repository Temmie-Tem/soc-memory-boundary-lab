# Experiment 022 — How much controller state is observable at all

## Question

Experiments 014, 017, 018, 019 and 021 all return negatives about the same
twelve ranked MC targets. Those targets come from Verification 012's Top-5
ranking, which ranked among the registers the SHRM snapshot happens to sample.

Nothing in this repository had measured how large that sample is relative to
the space it is drawn from. Without that number the strength of every
downstream negative is unquantified — a negative over a near-complete sample
and a negative over a sliver read the same in a summary.

## Scope and eligibility

Host-only, read-only, over the exact Experiment-004 `xbl--sdb1.bin` and the
retained live `SHRM_MEM.BIN`. No device, SMC, MMIO, normal-RAM,
protected-memory or runtime-register access. Conceptual Experiments 015 and 016
remain reserved and `NOT ELIGIBLE`.

## Result

Two static channels name controller addresses, and their union is the complete
set this project can name without a device read:

| Channel | Addresses |
|---|---:|
| SHRM snapshot, set 0 | 430 |
| SHRM snapshot, union of both sets | 470 |
| Experiment 017 XBL MC table | 122 |
| XBL table addresses new to the snapshot | 22 |
| **Union** | **492** |

The two channels agree almost completely: of the table's 122 entries only 22
are addresses the snapshot does not already name.

Within each ranked MC instance:

| Instance | Observed | Observed span (word slots) | Coverage of span |
|---|---:|---:|---:|
| `0x09260000` | 42 | 9,305 | **0.451 %** |
| `0x092e0000` | 42 | 9,305 | **0.451 %** |
| `0x09360000` | 42 | 9,305 | **0.451 %** |
| `0x093e0000` | 42 | 9,305 | **0.451 %** |

Across the four instances, 168 addresses out of 65,536 addressable word slots:
**0.256 %**.

`PROVED`: the union of every static observation channel names 42 of the 9,305
word slots each ranked MC instance spans.

`REFUTED`: the ranked-candidate negatives from Experiments 014, 017, 018, 019
and 021 bound where the Experiment 014 bank relation can live. The candidate
set was drawn from this sample, and this sample is a small fraction of the
space it is drawn from.

`UNKNOWN`: how many registers each block actually implements, and so the true
denominator; whether the bank relation is implemented by a register at all;
everything the channels do not name, which is the majority of each block under
either denominator.

Current classification is unchanged:

```text
CLASS C (TRANSFORM ONLY)
NO_BOUNDARY_BYPASS_OBSERVED
```

## Reading the denominators

Both are reported because neither is right on its own.

A 64-KiB block holds 16,384 addressable word slots, but how many are
implemented is `UNKNOWN` and is certainly fewer. Coverage measured against the
block is therefore a **lower** bound on true coverage — if the instance
implements 500 registers rather than 16,384, the sample sees a far larger share
than 0.256 % suggests. That figure should not be quoted alone.

Coverage against the observed span is the defensible number. Both ends of the
span are addresses a channel really names, so the span is a set of slots the
hardware plausibly uses, and 0.451 % is a statement about a range known to be
in play rather than about an assumed one.

## What this does and does not weaken

It weakens exactly one class of result: negatives whose search space is the
ranked candidate set. Experiment 017's read-only snapshot copier, Experiment
019's absence of the ranked addresses from the DCB, and Experiment 021's SHRM
literal audit all speak about twelve addresses chosen from 0.451 % of each
instance. All three ranked offsets lie inside the sample, which is not a
coincidence and not evidence: they were selected from it.

It does not weaken the searches that scan firmware for a value. Experiment 014's
literal audit of the bank relation, the field-encoded and AMD `ROWXOR` forms
tested since, and Experiment 019's materialisation audit all search whole
images and are independent of what the snapshot samples. Their limit is the set
of encodings tried, not the observation channel.

It also does not touch Experiment 020's finding, which is about the shape of a
search rather than its space.

## Consequence

Static work on the ranked candidates has reached the point of diminishing
return. Extending it means either enlarging the observation channel, which
needs a device read that Experiments 007 and 013 showed is blocked, or
searching a space 200 times larger with no candidate ranking to guide it.

The remaining discriminator that does not depend on naming a register is
behavioural: re-run the Experiment 014 timing recovery at a different DDR
operating point. Experiment 014 measured at one point only, with CPU7 pinned
and the `cpu-llcc-ddr-bw` governor at `performance`. If the recovered GF(2)
matrix differs at another point, the relation is programmed and switched by an
existing runtime mechanism; if it is identical, it is invariant across that
transition. Neither outcome requires naming, reading or writing a register.

## Evidence

- `evidence/manifests/022-observation-coverage-20260826-01.manifest.json`

The manifest contains counts, addresses and classifications only. It contains
no raw firmware bytes and no private paths.

## Reproduce

```sh
python3 tools/sm8150_observation_coverage.py \
  --output evidence/manifests/022-observation-coverage-20260826-01.manifest.json
python3 -m unittest -v tests.test_sm8150_observation_coverage
```

## Provenance

- Tool SHA-256:
  `2f4da8239792ad78bdfb14540f5bfd7191a924c58d1ea89ba9fa0239decda68e`.
- Focused-test SHA-256:
  `9334e7dd1b9b52148478f9de4ef6ff5b42e9e9f8e5a6b7a2dacccb4203d2d74d`.
- Public manifest SHA-256:
  `8bc21c38d42f69448d9a499a6417a75526d79eb0b8487376d3b348028a1d769d`.
- Focused result: 18 tests pass.
- Regeneration is byte-identical; manifest mode is `0644`.
- Date: 2026-08-26 KST.
- Mode: `HOST_ONLY_READ_ONLY`; device, SMC and MMIO access: none.
- Produced on branch `research/xbl-config-cdt` in a separate worktree.
  `STATUS.md`, `docs/EXPERIMENT_MATRIX.md` and `docs/RESEARCH_LOG.md` are
  deliberately untouched here and are reconciled at integration.
