# Experiment 022A — How much controller state is observable at all

Numbered `022A`, not `022`. This experiment and the concurrent `022-observation-coverage`
were created independently on 2026-08-26 and given the same number: at the
common ancestor `b78879a` neither existed. They are different investigations,
not two revisions of one. That one is on `main`, integrated across the shared
documents, with Experiments 024-034 built on top of it, so it keeps the bare
number and this one takes the suffix, following the `023R` precedent. Nothing
about this result changed.

## Question

Experiments 014, 017, 018, 019A and 021A all return negatives about the same
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

Two enumerated static channels name controller addresses. Their union is the
exact count for those two channels only, not the complete set this project can
name without a device read:

| Channel | Addresses |
|---|---:|
| SHRM snapshot, set 0 | 430 |
| SHRM snapshot, union of both sets | 470 |
| Experiment 017 XBL MC table | 122 |
| XBL table addresses new to the snapshot | 22 |
| **Union** | **492** |

The two channels agree almost completely: of the table's 122 entries only 22
are addresses the snapshot does not already name.

The known controller address `0x09248080` is absent from both channels. Thus
their union is not a complete project-nameable set; completeness is `REFUTED`
under this two-channel scope.

Within each ranked MC instance:

| Instance | Observed | Observed span (word slots) | Coverage of span |
|---|---:|---:|---:|
| `0x09260000` | 42 | 9,305 | **0.451 %** |
| `0x092e0000` | 42 | 9,305 | **0.451 %** |
| `0x09360000` | 42 | 9,305 | **0.451 %** |
| `0x093e0000` | 42 | 9,305 | **0.451 %** |

Across the four instances, 168 addresses out of 65,536 addressable word slots:
**0.256 %**.

`PROVED`: the exact counts for the two enumerated channels and their density
arithmetic: 42 of the 9,305-word observed span per ranked instance, or 0.4514%
observed-span address density; 42/16,384 = 0.2563% full-64-KiB word-slot
density per instance and 168/65,536 = 0.2563% across four instances. All three
ranked offsets lie inside the selected sample because the candidates were
selected from it.

`SUPPORTED`: these channels provide a sparse observed sample around the ranked
instances; the density figures are descriptive, not implemented-register
coverage.

`REFUTED`: the claim that the two channels are complete: known address
`0x09248080` is outside both. This counterexample is pinned to
`006-xbl-memory-pipeline-inventory.json`, field
`ddr_remapper/icb_property/records/0/register_bases/0/address`, SHA-256
`39469ac59ef0e3a2b9858b7435a4433def58d57407a4066da3854cfdd24409a5`.

`UNKNOWN`: the true implemented-register denominator and coverage; whether the
bank relation is implemented by a register at all; and whether ranked-candidate
negatives generalize beyond these selected channels. These counts cannot
establish global absence.

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
019A's absence of the ranked addresses from the DCB, and Experiment 021A's SHRM
literal audit all speak about twelve addresses chosen from 0.451 % of each
instance. All three ranked offsets lie inside the sample, which is not a
coincidence and not evidence: they were selected from it.

It does not weaken the searches that scan firmware for a value. Experiment 014's
literal audit of the bank relation, the field-encoded and AMD `ROWXOR` forms
tested since, and Experiment 019A's materialisation audit all search whole
images and are independent of what the snapshot samples. Their limit is the set
of encodings tried, not the observation channel.

It also does not touch Experiment 020A's finding, which is about the shape of a
search rather than its space.

## Consequence

Static work on the ranked candidates has reached the point of diminishing
return. Extending it means either enlarging the observation channel, which
needs a device read that Experiments 007 and 013 showed is blocked, or
searching a space 200 times larger with no candidate ranking to guide it.

The remaining discriminator that does not depend on naming a register is
behavioural: re-run the Experiment 014 timing recovery at a different DDR
operating point. This remains a `HYPOTHESIS`, not a result of the refuted
completeness claim. Neither outcome requires naming, reading or writing a
register.

## Evidence

- `evidence/manifests/022A-observation-coverage-20260826-01.manifest.json`

The manifest contains counts, addresses and classifications only. It contains
no raw firmware bytes and no private paths.

## Reproduce

```sh
python3 tools/sm8150_observation_coverage_022a.py \
  --output evidence/manifests/022A-observation-coverage-20260826-01.manifest.json
python3 -m unittest -v tests.test_sm8150_observation_coverage_022a
```

The reproduction command is a `REDACTED_REPRODUCTION_TEMPLATE`: the default
private firmware/SHRM inputs and output path are redacted while the exact
inputs are pinned by their published hashes; it is not an executed-command
receipt.

## Provenance

- Historical producer tool SHA-256:
  `2f4da8239792ad78bdfb14540f5bfd7191a924c58d1ea89ba9fa0239decda68e`.
- Historical producer focused-test SHA-256 (suffix test):
  `0d0354e37acbc07b5314b0ff082908cc2ad1096929a7a1c2fdfdf81cbf5a5053`.
- Historical producer manifest SHA-256 before repair:
  `8bc21c38d42f69448d9a499a6417a75526d79eb0b8487376d3b348028a1d769d`.
- Current verifier tool SHA-256:
  `a9f35b778655eb9c284d4c868779add086e8513714864cb9069b1faaef99239f`.
- Current verifier focused-test SHA-256:
  `03ffa945d4117bad136c83e42d2da005a578d6726967c3e8d1204f6f09feb3fd`.
- Repaired public manifest SHA-256: `7e365211af1b92fc5b26788fad1cfca47c436e10d1a2bea8dce7ad75d513ca9e`.
- Focused result: 28 tests pass. Full repository discovery is not rerun here.
- The publisher requests mode `0644` for fresh output; no tracked-file mode is
  asserted. Its historical producer hash remains recorded separately rather
  than silently repinned.
- Date: 2026-08-26 KST.
- Mode: `HOST_ONLY_READ_ONLY`; device, SMC and MMIO access: none.
- Produced on branch `research/xbl-config-cdt` in a separate worktree.
  `STATUS.md`, `docs/EXPERIMENT_MATRIX.md` and `docs/RESEARCH_LOG.md` are
  deliberately untouched here and are reconciled at integration.
