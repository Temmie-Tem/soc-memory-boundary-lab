# Experiment 022 — Observed-span address density

## Question

How dense are the addresses named by the two enumerated retained-evidence
channels around the four ranked MC instances?

## Scope and eligibility

This is host-only, read-only evidence over the exact Experiment-004 XBL and
the retained `SHRM_MEM.BIN`. The counts below are exact for two enumerated
channels only:

1. the SHRM snapshot decoder’s set 0 and union, and
2. the Experiment-017 XBL MC address table.

Their union is not the complete project-nameable controller-address set. The
known address `0x09248080` is outside both channels and is retained as a
completeness counterexample. No device, SMC, MMIO, normal-RAM,
protected-memory or runtime-register access was used.

## Exact channel counts

| Enumerated observation | Exact count |
|---|---:|
| SHRM snapshot, set 0 | 430 |
| SHRM snapshot, union of both sets | 470 |
| Experiment-017 XBL MC table | 122 |
| XBL-table addresses new to the SHRM union | 22 |
| **Union of these two channels** | **492** |

`0x09248080` is absent from the SHRM set and XBL table, so the claim that
these two channels form a complete project-nameable set is `REFUTED`.
Its provenance is pinned to
`006-xbl-memory-pipeline-inventory.json`, field
`ddr_remapper/icb_property/records/0/register_bases/0/address`, whose SHA-256
is `39469ac59ef0e3a2b9858b7435a4433def58d57407a4066da3854cfdd24409a5`.

The retained raw input is pinned as `SHRM_MEM.BIN`, size **65,536** bytes,
SHA-256
`409550ad226443271a39b6bc060f0e8fb3224111cc03f07a6ee563eaa7098bb7`.
Size/hash mismatches are rejected before decoding.

## Density, not implemented-register coverage

The four ranked instances each contain 42 addresses in the enumerated union,
spanning 9,305 word slots:

| Instance | Observed addresses | Observed span | Observed-span address density | Full-64-KiB word-slot density |
|---|---:|---:|---:|---:|
| `0x09260000` | 42 | 9,305 | 42/9305 = **0.4514%** | 42/16384 = **0.2563%** |
| `0x092e0000` | 42 | 9,305 | 42/9305 = **0.4514%** | 42/16384 = **0.2563%** |
| `0x09360000` | 42 | 9,305 | 42/9305 = **0.4514%** | 42/16384 = **0.2563%** |
| `0x093e0000` | 42 | 9,305 | 42/9305 = **0.4514%** | 42/16384 = **0.2563%** |
| **Four-instance union** | **168** | — | — | 168/65536 = **0.2563%** |

These are observed-span address density and full-64-KiB word-slot density.
The true implemented-register denominator and implemented-register coverage
are both `UNKNOWN`; the output does not infer either from a 64-KiB block.
The public manifest records per-block rows under `address_density_by_block`.

## What the result does and does not say

`PROVED`: the four counts above and the density arithmetic for the two
enumerated channels. The three ranked offsets lie in the selected sample
because the candidates were selected from it.

`UNKNOWN`: whether ranked-candidate negatives from Experiments 014, 017, 018,
019 and 021 generalize outside these selected channels. Those counts cannot
establish global absence and do not quantify search coverage elsewhere.

`HYPOTHESIS`: repeating Experiment-014 timing recovery at another DDR
operating point remains one candidate follow-up. This experiment does not
elevate DDR-OPP timing or any other candidate using the refuted completeness
claim.

```text
CLASS C (TRANSFORM ONLY)
NO_BOUNDARY_BYPASS_OBSERVED
```

## Evidence and reproducibility

- Public manifest: `evidence/manifests/022-observation-coverage-20260826-01.manifest.json`
- Dependencies are hash-pinned in the manifest:
  - `004-live-firmware-readonly-20260825-01.manifest.json`:
    `1ed4b8b14b2e0ccf2d4ae084ea413e0395d9dc488dd5d2bb1dd872fbe20d9247`
  - `017-xbl-mc-snapshot-xref-20260825-01.manifest.json`:
    `b1db21235374c64de797c1a123c64ddb23c43fca9100bbd51cf7b4897ea5c61b`
  - `006-xbl-memory-pipeline-inventory.json`:
    `39469ac59ef0e3a2b9858b7435a4433def58d57407a4066da3854cfdd24409a5`
  - `verification-012-a90-samsung-upload-shrm-20260825-01.manifest.json`:
    `ab1ce8168fe52f358f9c670e1b734125ff078628fa0667568d7cdea115d6021b`
- Imported decoder `tools/shrm_dump_decode.py` is hash-pinned as
  `1cf33c9292890c2479c20c8f9470c05058348046a49dc2280d061a64e224b5a7`.

```sh
repro_dir=$(mktemp -d /tmp/022-observation-coverage.XXXXXX)
python3 tools/sm8150_observation_coverage.py \
  --output "$repro_dir/manifest.json"
python3 -m unittest -v tests.test_sm8150_observation_coverage
```

Output creation is `O_EXCL`/`O_NOFOLLOW` by default. Use `--force` only for an
intentional replacement of an existing regular output file.

The manifest contains counts, hashes, addresses and classifications only; it
contains no raw firmware bytes or private paths.

## Provenance

- Tool SHA-256: `4e44f2a1801f85d20bce762b4278e394f7bfc958f6eb13a30afc564773580feb`
- Focused-test SHA-256: `8218b3084a89c39d2b64841f72e425a51bfdf951be346c149f2be63ab9a50390`
- Public manifest SHA-256: `c3b783ba8009f2ec9d64f314166b52892003d621dcd1198f393d8681c701be2f`
- Mode: `HOST_ONLY_READ_ONLY`; device, SMC and MMIO access: none.
