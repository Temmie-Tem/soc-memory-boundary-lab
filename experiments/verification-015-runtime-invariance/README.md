# Verification 015 — runtime invariance of the bank relation

This record is in the `verification-` lane. It is not the numbered conceptual
Experiment 015 alias gate. The numbered conceptual Experiments 015/016
promotion path is `NOT_ELIGIBLE`; this record is a host-side, read-only analysis of retained
probe transcripts.

The repaired integration was rebuilt on current clean HEAD `5a803fa`. The
historical commits below are evidence for the record's scope only; they were
not cherry-picked or imported as implementation:

| Evidence commit | Narrow use in this record |
|---|---|
| `05a4c5c` | original runtime-condition comparison and per-condition separation |
| `a297fde` | retained coldboot condition |
| `b2b5068` | retraction of the DDR-bandwidth interpretation |

## Scope and method

Experiment 023R supplies the repaired region/bank relation in
allocation-offset/model coordinates. Verification 015 asks whether the
observed conflict/negative classification remains stable across separately
retained runtime-labelled transcript sets. Absolute delta magnitudes are not
compared across conditions. Every condition derives its own threshold from its
own widest median gap; labels are then compared against the V2321-L7980
baseline.

Every nonblank JSONL line is validated. Each probe context section contains
exactly one identical `ion_heap` and `pa_provenance` record, and all condition
contexts agree. Pair offsets and offset-XOR-differences are bounded by the
32-MiB context allocation. Pair offsets are unique per difference, pair records
precede their summary, and the summary's p10/median/p90 are recomputed from
the retained deltas using the probe's exact qsort indexes. A difference is
never silently overwritten or averaged within a transcript.

The common acquisition record reports `contiguous=true` only as
`reported_contiguous`. Pagemap status is `BLIND`, so effective physical
contiguity remains `UNKNOWN`.

## Six condition-labelled transcript sets

The following are exact condition labels on retained transcript files. They
are not six machine-proved runtime identities. Runtime identity, reboot
identity, and coldboot identity are `SUPPORTED_BY_UNRETAINED_OPERATOR_REPORT`
and retained project context only.

| Condition | Retained files | Differences | Threshold | Empty band | Widest gap | Runner-up gap | CONFLICT |
|---|---:|---:|---:|---:|---:|---:|---:|
| `twrp-pre-L7980` | 4 | 51 | 371 | 199..543 | 344 | 7 | 25 |
| `twrp-pre-L6881` | 4 | 51 | 573 | 375..771 | 396 | 3 | 25 |
| `twrp-post-L7980` | 2 | 51 | 365 | 192..538 | 346 | 13 | 25 |
| `v2321-L7980` | 2 | 51 | 351 | 182..521 | 339 | 8 | 25 |
| `v2321-L762` | 1 | 51 | 274 | 192..357 | 165 | 140 | 27 |
| `v2321-coldboot-L7980` | 2 | 51 | 350 | 181..519 | 338 | 8 | 25 |

The TWRP pre files are `sweep[0246]` for L7980 and `sweep[1357]` for L6881;
the post files are `postboot8/9`; V2321 L7980 and coldboot have pass0/pass1;
V2321 L762 has pass0. Each condition retains its own medians, labels,
observation values, count, spread, minimum, maximum, mean, and population
standard deviation. The final key set is exactly the same 51-key set in all
six conditions.

Against `v2321-L7980`, the four clean comparisons are:

```text
twrp-post-L7980       : 51 shared, 0 disagreements -> INVARIANT
twrp-pre-L6881        : 51 shared, 0 disagreements -> INVARIANT
twrp-pre-L7980        : 51 shared, 0 disagreements -> INVARIANT
v2321-coldboot-L7980  : 51 shared, 0 disagreements -> INVARIANT
```

`v2321-L762` has two label excursions, `0x100e000` (baseline NEGATIVE 147,
condition CONFLICT 357) and `0x1012000` (baseline NEGATIVE 153, condition
CONFLICT 369). Its weak separation (165 widest gap versus 140 runner-up, so
the within-condition runner-up/widest ratio is above the 0.6 threshold) keeps the comparison
`REPEAT_REQUIRED`. The public comparison therefore remains
`all_invariant=false`.

## Independently bound repeat

`v2321-level-repeat.jsonl` is bound to the L762/L7980 excursion set and does
not reuse the V2321-L7980 absolute threshold. Each of its six groups derives
an independent widest-gap split:

| Repetition | Level | Threshold | Empty band | Widest gap | Runner-up gap |
|---:|---:|---:|---:|---:|---:|
| 0 | 762 | 342 | 170..515 | 345 | 12 |
| 0 | 7980 | 345 | 164..527 | 363 | 10 |
| 1 | 762 | 367 | 195..540 | 345 | 208 |
| 1 | 7980 | 358 | 180..537 | 357 | 22 |
| 2 | 762 | 353 | 173..534 | 361 | 34 |
| 2 | 7980 | 350 | 170..531 | 361 | 19 |

Low/high labels are compared within each repetition. A surviving flip means
any observed repeated flip; no majority vote can erase one. The six bound
differences have zero surviving flips. This repeat result does not promote
the primary L762 condition: its condition comparison stays
`REPEAT_REQUIRED`, and `all_invariant` stays false.

The repeat acquisition context is the common heap/PA context with only the
declared `pairs=32` difference from the main `pairs=16` context. The level
sweep binds exactly to the main `pairs=16` context. Heap and PA records are
identical across every auxiliary group and condition; physical contiguity is
still not promoted beyond the reported allocation flag.

## Bus-vote sweep and retraction

`v2321-level-sweep.jsonl` contains exactly six requested bus-vote levels,
each retained twice: `762`, `2597`, `5161`, `5931`, `6881`, and `7980`.
There are 12 level groups, not eleven levels. The rows retain three probe
differences each and report the requested and observed vote values.

The bandwidth axis is `RETRACTED` and `EXCLUDED` from DDR-frequency or
transform-transition inference. An unmodified higher voter was reported, but
the corresponding msm-bus transcript is not retained, so these requests do
not prove a DDR operating-point transition. The sweep is retained only as a
bus-vote stability transcript; no level-to-level transform comparison is made.

## Evidence and provenance boundaries

The canonical private input set has 15 condition probe files, one repeat file,
one sweep file, and two devfreq journals: 19 exact artifacts. For each private
input, the public manifest carries a sanitized basename, byte size, and
SHA-256 digest; it also publishes derived summaries and acquisition context,
never raw transcript bytes. It carries no private absolute path, raw firmware,
or secret.

The probe source is pinned to
`2dbc81ef7595d30f627df8d28d24e21603d8c1c174074e85593b9fe8df5569e9`; the
023R dependency manifest is pinned to
`5c3e14ff898c109de740d98260d974bca10751000f85977775cd467ac74aac2e`.
The historical probe binary digest
`bd41bb9c8a5f7dfe1ddcec8f069382df6e0ad85d8712da31a9823243c124d204` is
recorded, but no retained two-environment build or transfer receipt exists;
verified transfer/build is therefore `UNKNOWN`.

The intended target identity is `SM-A908N` / `SM8150` (A90 5G), with TWRP
kernel `4.14.190-Grass,SD855-Perf+` and V2321 runtime `0.9.285` on vendor
kernel `4.14.190-25818860-abA908NKSU5EWA3`. These identities are
`SUPPORTED_BY_UNRETAINED_OPERATOR_REPORT`/retained project context only; the
raw probe transcripts do not attest them. Acquisition timestamp is
`UNKNOWN_UNRETAINED`, the command record is a
`REDACTED_REPRODUCTION_TEMPLATE`, and rollback/recovery/final-state status is
`UNKNOWN_INCOMPLETE_RECEIPT` despite exact journal inputs.

The exact numeric transcript analysis and input hashes are `PROVED`. Runtime,
reboot, coldboot, and final-cleanup identity are only
`SUPPORTED_BY_UNRETAINED_OPERATOR_REPORT`/retained project context. Device action,
reboot/power-cycle, and final-state receipts are incomplete in these files;
this host integration performed no new device action. Physical-page
provenance and unreachable-path mutability remain `UNKNOWN`.

Class C is unchanged: `TRANSFORM ONLY`. There is no alias, mutation,
protected reach, or boundary-bypass authority here. The scoped host-integration
disposition is `NO_ALIAS_OR_MUTATION_OBSERVED_OR_TESTED`: it is read-only and
rejects duplicate condition names, paths, content hashes, difference records,
and per-difference pair offsets; it rejects mismatched contexts. This does not
turn historical acquisition actions into a machine-proved no-mutation receipt.

## Reproduction

Run from the repository root. The globs below bind the exact canonical
basenames; the auxiliary files and source/dependency pins are explicit.

```sh
v015_repro_dir="$(mktemp -d -t verification015-repro.XXXXXX)"

python3 tools/a90_runtime_invariance_analysis.py \
  --condition 'twrp-pre-L7980=evidence/private/verification-015-runtime-invariance-20260826-01/twrp-pre-sweep[0246]-L7980.jsonl' \
  --condition 'twrp-pre-L6881=evidence/private/verification-015-runtime-invariance-20260826-01/twrp-pre-sweep[1357]-L6881.jsonl' \
  --condition 'twrp-post-L7980=evidence/private/verification-015-runtime-invariance-20260826-01/twrp-post-*.jsonl' \
  --condition 'v2321-L7980=evidence/private/verification-015-runtime-invariance-20260826-01/v2321-L7980-*.jsonl' \
  --condition 'v2321-L762=evidence/private/verification-015-runtime-invariance-20260826-01/v2321-L762-*.jsonl' \
  --condition 'v2321-coldboot-L7980=evidence/private/verification-015-runtime-invariance-20260826-01/v2321-coldboot-L7980-*.jsonl' \
  --baseline v2321-L7980 \
  --repeat evidence/private/verification-015-runtime-invariance-20260826-01/v2321-level-repeat.jsonl \
  --sweep evidence/private/verification-015-runtime-invariance-20260826-01/v2321-level-sweep.jsonl \
  --journal evidence/private/verification-015-runtime-invariance-20260826-01/twrp-devfreq-journal.txt \
  --journal evidence/private/verification-015-runtime-invariance-20260826-01/v2321-devfreq-journal.txt \
  --dependency evidence/manifests/023R-repaired-region-bank-relation-20260826-01.manifest.json \
  --probe-source tools/a90_region_probe_r.c \
  --output "$v015_repro_dir/manifest.json"

cmp -- "$v015_repro_dir/manifest.json" evidence/manifests/verification-015-runtime-invariance-20260826-01.manifest.json

python3 -m unittest -v tests.test_a90_runtime_invariance_analysis
python3 -m py_compile tools/a90_runtime_invariance_analysis.py tests/test_a90_runtime_invariance_analysis.py
```

Publication is atomic and no-clobber. A fresh output inode is forced to mode
0644 and `lstat` records the actual write result; this is not a claim about
the mode of a checked-out Git file. Reproduction twice in fresh temporary
outputs must produce byte-identical JSON. The final handoff records the
tool, test, README, and manifest sizes and SHA-256 values; a README's own
digest is reported externally to avoid a self-referential embedded hash.

## Validation snapshot

The repaired focused suite has 44 tests covering canonical reproduction,
strict contexts, unequal keys, duplicate inputs/records, empty globs,
independent repeat binding, six-level scope, deterministic encoding, public
safety, no-clobber publication, and fresh mode. Two fresh canonical
generations were byte-identical at 112840 bytes before this README was
published.

Final generated artifact pins for this handoff are:

| Artifact | Size | SHA-256 |
|---|---:|---|
| `tools/a90_runtime_invariance_analysis.py` | 97572 | `6fae489d27d03f94e9dcd89086027a4209988a67020620e54f1df7e22ca99e03` |
| `tests/test_a90_runtime_invariance_analysis.py` | 28904 | `ccd6604febeb3c16e40c253a51f5a3fe35c3c61dcd77f6757daa2a9b8ca23ceb` |
| `evidence/manifests/verification-015-runtime-invariance-20260826-01.manifest.json` | 112840 | `fab880dc50f8e66e74828a0276f8e5ab5ef9b1f2b2f2f9f032dcef03b6b98592` |
| this README | reported in the final handoff | a self-digest is not embedded to avoid changing the bytes being hashed |

The output manifest was published once at the canonical path through the
atomic no-clobber writer; its fresh mode was observed as `0644`. A second
fresh temporary generation matched the first byte-for-byte. No private input
was modified.
