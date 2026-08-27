# Verification 022 integration review — 2026-08-27

Disposition: host-only repair accepted for retained-receipt reduction;
device promotion remains blocked.

## Reviewer blocker disposition

| blocker | repair |
|---|---|
| tautological `pa_xor` check | Recompute `pa_a`, `pa_b`, and `pa_a XOR pa_b` from the base, offsets, and named difference; compare the emitted field only as an independent consistency check. |
| missing phase/cardinality gates | Canonical existence and identification phases have exact difference sets/repeat counts, one context/heap/pagemap record, summary accounting, pair-group counts, and per-phase controls before resolution. |
| C range/overflow/heap-mask safety | Range and base-carry checks precede pointer formation; numeric arguments, allocation arithmetic, base, pair count, and heap id are bounded; the fixed id 30 is used for the mask. |
| unstable or unpinned loader | Inputs are bounded regular files opened with `O_NOFOLLOW`; symlinked parents, duplicate/non-finite JSON, descriptor mutation, canonical raw names, exact size, and SHA-256 are rejected. |
| absent 020M/021 disposition | Both exact manifest pins and semantic attestations are required. Target/bridge/command provenance remains explicit `UNKNOWN_UNRETAINED`; no same-run claim is fabricated. |

## Artifacts

- `tools/a90_pa28_relation_analysis.py` — strict reducer and redacted manifest
  publisher.
- `tools/a90_pa28_probe.c` — repaired bounded probe source; not executed in this
  pass.
- `tests/test_a90_pa28_relation_analysis.py` — focused positive and hostile
  negatives.
- `experiments/verification-022-pa28-relation/README.md` — conservative claim
  and provenance contract.
- `evidence/manifests/verification-022-pa28-relation-20260827-01.manifest.json`
  — regenerated from the two pinned private receipts.

## Verification evidence

The focused checks pass:

```text
gcc -std=c11 -Wall -Wextra -Werror -fsyntax-only tools/a90_pa28_probe.c
python3 -m unittest -v tests.test_a90_pa28_relation_analysis
Ran 28 tests ... OK
```

The generated manifest has schema `a90_pa28_relation_v2`, disposition
`SUPPORTED_MODEL_EXTENSION`, and target provenance `UNKNOWN_UNRETAINED`. It
contains 3,029 rechecked pairs with zero arithmetic mismatches, but this is a
retained-receipt fact only. No adb/fastboot/bridge/device command was run by
this repair.

Final public artifact pins:

| artifact | size | SHA-256 |
|---|---:|---|
| `tools/a90_pa28_probe.c` | 25,030 B | `b324c1c3332c61b00f6d6e5c75891721be4a5fb2a998c7f0222900d4eba5e199` |
| `evidence/manifests/verification-022-pa28-relation-20260827-01.manifest.json` | 6,698 B | `f583bd4f4fe30ad4822832e708edd87e2e049333f2a6c0cf014467b5a33bc2d2` |

The final serial repository suite after the 021/022 pin updates and root-doc
integration is **1,398/1,398 PASS** (`skipped=1`) in 181.278 seconds, with
maximum RSS 379,680 KiB and zero swap.  This suite is host-only; it performed
no device action.

## Remaining boundary

The repaired source is not the historical binary's retained source artifact,
and the historical binary itself is not retained. Therefore the repaired C
surface cannot be promoted to a live result without a separately authorized,
exact-target, same-run preflight and durable receipt. The relation result stays
a model extension and does not authorize alias, physical mapping, transform
mutation, protected writes, or bypass work.
