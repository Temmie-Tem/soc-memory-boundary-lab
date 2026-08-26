# Verification 016: model bits 25–27 (historical PA labels)

This is a host-only, read-only repair of the retained Verification-016
transcripts.  It is a transcript analysis, not a live-device authorization or
a new device action.  The raw JSONL remains private; the public manifest
contains sanitized input metadata and derived summaries only.

## Retained inputs and parser boundary

The canonical raw directory contains exactly three pinned JSONL artifacts:

| Artifact | Sections | Keys per section | Size | SHA-256 |
|---|---:|---:|---:|---|
| `pa25-27-discriminate.jsonl` | 3 | 14 | 142987 | `0b269229a1607c6894fea15c21008ed3651b29faf02b9bc6cd851878c6030754` |
| `pa25-27-heldout.jsonl` | 1 | 9 | 30770 | `38649c2d2f73be05ef238c20cdc69880b391547f84fe48cd656fff9343be91b0` |
| `pa25-27-three-column.jsonl` | 2 | 14 | 94966 | `4cea5779ebdace6cc9817de591c8cff81dbd7f029ad78f46d8711708758c950f` |

The three discrimination sections are retained independently and map, in
order, to model bits PA25, PA26 and PA27.  The two three-column sections are
same-context passes and are the only sections combined; their keys are checked
for equality before a floor mean is calculated.  Overlapping references are
therefore never selected by filename order or merged across acquisition
phases.

Each section is parsed strictly.  The parser requires valid probe JSON,
identical contexts, one ion heap, one pagemap `BLIND` provenance record, nonzero
differences, page-aligned pair offsets, 32 pair records per difference, unique
offsets within each difference, both page-sized XOR endpoints inside the
allocation, pair records before their summary, and exact C-probe `qsort`
p10/median/p90 values.

The retained context is `camera_preview`, heap type 10/id 30, 256 MiB,
201 repetitions, 32 pairs, 17 warmups, CPU 7, `spread` offsets,
`alternating` order, `dsb_ld` barrier, and `kept_times_two` divisor.  The
probe source and repaired V015 helper are also pinned:

| Dependency | Size | SHA-256 |
|---|---:|---|
| `tools/a90_region_probe_r.c` | 19337 | `2dbc81ef7595d30f627df8d28d24e21603d8c1c174074e85593b9fe8df5569e9` |
| `evidence/manifests/023R-repaired-region-bank-relation-20260826-01.manifest.json` | 18040 | `5c3e14ff898c109de740d98260d974bca10751000f85977775cd467ac74aac2e` |
| `tools/a90_runtime_invariance_analysis.py` | 97572 | `6fae489d27d03f94e9dcd89086027a4209988a67020620e54f1df7e22ca99e03` |

## Reproduced results

Every split is computed independently by the widest observed gap in that
phase.  `CONFLICT` means median greater than the phase threshold.

| Phase | Threshold | Gap | Runner-up gap | Band | CONFLICT |
|---|---:|---:|---:|---|---:|
| Model bit PA25 discrimination | 339 | 295 | 22 | 192..487 | 3 |
| Model bit PA26 discrimination | 325 | 273 | 75 | 189..462 | 2 |
| Model bit PA27 discrimination | 355 | 302 | 25 | 204..506 | 3 |
| Held-out section | 299 | 276 | 38 | 161..437 | 5 |
| Two-pass three-column floor mean | 358 | 304 | 136 | 206..510 | 2 |

In every discrimination section, the held-out section, each three-column pass,
and the combined three-column result, the parser explicitly asserts
`0x16000` = `CONFLICT` and `0x2000` = `NEGATIVE`; aggregate conflict counts do
not substitute for those same-phase control checks.

Discrimination against PA13–PA24 finds the equal-contribution matches:

| Model bit | Matching lower bits |
|---:|---|
| PA25 | PA14, PA21 |
| PA26 | PA19 |
| PA27 | PA13, PA20 |

Before averaging, the two same-phase three-column passes produce these
per-pass triplets and retain the same verdicts as the combined result:

| Model bit | Pass 0 triplet | Pass 1 triplet | Combined floor mean | Verdict in both passes and combined |
|---:|---|---|---|---|
| PA25 | 186, 161, 226 | 118, 105, 186 | 152, 133, 206 | `SELECTOR` |
| PA26 | 161, 161, 149 | 139, 121, 124 | 150, 141, 136 | `SELECTOR` |
| PA27 | 145, 158, 527 | 118, 139, 493 | 131, 148, 510 | `SELECTOR_CANCELS_NEGATIVE_WITNESS` |

The parser computes and checks each pass-level verdict before averaging, then
rejects any pass/combined disagreement rather than allowing a mean to hide it.

The table's triplets are ordered as (alone, `+0x16000`, `+0x2000`).

The PA27 result is kept as a direction-specific cancellation verdict.  Its
raised negative-witness column is not collapsed into the saturation verdict.

The separate held-out file yields a 7/7 out-of-sample/model-derived
agreement:

| Difference | Expected/observed |
|---|---|
| `0x6084000` | `CONFLICT` |
| `0xa202000` | `CONFLICT` |
| `0xc180000` | `CONFLICT` |
| `0xa104000` | `CONFLICT` |
| `0x6000000` | `NEGATIVE` |
| `0xc000000` | `NEGATIVE` |
| `0xa004000` | `NEGATIVE` |

Only the two reference/control differences `0x16000` and `0x2000` are reused in
each phase.  The historical README's 17/17 referred to eight kernel and nine
negative historical PA-label controls, not to 17 reference differences.  The
retained V016 bytes contain only the two controls per phase, so the claim that
the retained evidence establishes 17/17 is
`REFUTED_AS_RETAINED_EVIDENCE`.  Whether a separate unretained 17-difference
run occurred, and what result it produced, is `UNKNOWN`; this does not refute
that historical event.  The external `192/170/506` tuple is not coherent with
either retained three-column pass or their two-pass combine; its historical
producer or cause is `UNKNOWN` in the canonical inputs.  The retained two-pass
means are the triplets above.

The held-out predictions are not asserted to have been preregistered before
acquisition.  Prediction preregistration and acquisition order/timestamp are
`UNKNOWN` because the retained bytes do not attest them.

## Scope and disposition

The model-bit PA25–PA27 result is `SUPPORTED_WITHIN_MODEL` in
`ALLOCATION_OFFSET_MODEL_COORDINATES`.  The pinned 023R dependency reports a
resolved rank-3 model; the two lower-bit equalities implied by the matches
(`0x204000` and `0x102000`) are present in its retained kernel evidence.  Thus
the result supports duplicate contributions for model bits PA25, PA26 and
PA27 while preserving rank 3.  It does not establish physical controller
semantics.

All retained pagemap records are `BLIND`.  Physical-address mapping for these
model bits, allocation base, allocation alignment, and effective physical
contiguity are `UNKNOWN`.  The producer's contiguous flag is retained only as
`reported_contiguous`; it is not physical-page proof.

Target and build identity are `SUPPORTED_BY_UNRETAINED_OPERATOR_REPORT` only;
the transcripts do not attest target identity.  Timestamp, commands executed,
historical device action, cleanup, and final state are unretained or incomplete
receipts.  This repair performed no device action and supplies no device
authority.  No alias, mutation, protected-memory reach, or boundary bypass is
observed or proved by this host analysis.

Raw-input identity is scoped to pinned exact bytes and content stability;
filesystem inode provenance is `UNKNOWN` and is not claimed.  Replacing an
input inode with identical content would not change this analysis.

The disposition remains Class C: `TRANSFORM ONLY`.  Numbered Experiments 015
and 016 remain `NOT_ELIGIBLE`.  This result satisfies Verification 017's input
dependency gate, but does not promote its external implementation or claims:
Verification 017 is `UNBLOCKED_FOR_SEPARATE_AUDIT_NOT_PROMOTED`.

## Reproduction

The CLI is canonical-only: it accepts the exact three filenames and their
pinned bytes, then publishes through the repaired V015 stable-read,
public-safety, atomic no-clobber publisher.

```sh
tmp_dir="$(mktemp -d)"
tmp_manifest="$tmp_dir/manifest.json"
trap 'rm -f -- "$tmp_manifest"; rmdir -- "$tmp_dir" 2>/dev/null || true' EXIT
python3 tools/a90_high_bit_relation_analysis.py \
  --raw evidence/private/verification-016-high-bit-relation-20260827-01 \
  --output "$tmp_manifest"
cmp -- "$tmp_manifest" \
  evidence/manifests/verification-016-high-bit-relation-20260827-01.manifest.json
rm -- "$tmp_manifest"
rmdir -- "$tmp_dir"
trap - EXIT

python3 -m unittest -v tests/test_a90_high_bit_relation_analysis.py
python3 -m py_compile tools/a90_high_bit_relation_analysis.py \
  tests/test_a90_high_bit_relation_analysis.py
```

Publication is no-clobber.  An existing manifest path is never overwritten.
