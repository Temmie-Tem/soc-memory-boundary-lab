# Verification 029 — the published model, tested out of sample, and one anomaly

**Pre-registered before the run.** Committed before the probe was dispatched.

## What is being tested

Verification 028 closed the rank floor at 3. This tests the thing the rank
floor does not: whether the **complete published bit-to-image map** predicts
differences nobody has measured.

Assembled from the project's own results — 023R's explicit relation, V016's
PA25–PA27 equalities, and V022R's `f(PA28) = 010`:

| bit | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 20 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| image | 001 | 010 | 100 | 011 | 110 | 111 | 101 | 001 | 010 | 100 | 011 | 110 | 010 | 101 | 001 | 010 |

`f(d)` is the XOR of the images of `d`'s set bits, and `f(d) = 0` means the two
addresses share a bank, which is a row-buffer conflict. Applied to every
in-domain difference in the usable corpus the map scores **760 of 763**, and
the three residuals are:

| residual | run | separation | status |
|---|---|---:|---|
| `0x100e000` | `v2321-L762-pass0` | 165 | in the one run V027's quality check independently flagged |
| `0x1012000` | `v2321-L762-pass0` | 165 | same run |
| **`0xc84000`** | `023 phase1-user_contig` | 375 | **clean run, unexplained** |

## The list

```
0x16000 0x2000                                        leading controls
0x784000 0x8b6000 0xaea000 0xb74000                   predicted CONFLICT (f = 000)
0xc84000                                              the standing anomaly
0x40a000 0x518000 0x6ce000 0x91a000                   predicted negative
0x16000 0x2000                                        trailing controls
```

Every candidate is a genuine multi-bit combination (three to seven set bits),
none has been measured anywhere in the corpus at any page size under any probe
schema, and each leaves at least 19.5 MiB of offset room in the 32 MiB
allocation. The four predicted negatives were chosen to cover four distinct
non-zero images (`001`, `010`, `011`, `100`) so a failure cannot be confined to
one direction.

## Predictions, and what refutes them

| difference | bits | `f` | predicted |
|---|---|---|---|
| `0x784000` | 14,19,20,21,22 | `000` | CONFLICT |
| `0x8b6000` | 13,14,16,17,19,23 | `000` | CONFLICT |
| `0xaea000` | 13,15,17,18,19,21,23 | `000` | CONFLICT |
| `0xb74000` | 14,16,17,18,20,21,23 | `000` | CONFLICT |
| `0x40a000` | 13,15,22 | `001` | negative |
| `0x518000` | 15,16,20,22 | `010` | negative |
| `0x6ce000` | 13,14,15,18,19,21,22 | `011` | negative |
| `0x91a000` | 13,15,16,20,23 | `100` | negative |
| `0xc84000` | 14,19,22,23 | `000` | CONFLICT — **contradicts the one prior measurement** |

- **8 of 8 correct** → the map holds out of sample across the whole modelled
  range, on combinations it was never fitted to.
- **Any miss** → the map is wrong for at least one bit, and the failing
  difference names the bits to re-derive. This is a real possibility: the map
  is assembled from three separate experiments and has never been tested as one
  object.
- `0xc84000` is a deliberate re-measurement. CONFLICT resolves the residual in
  the model's favour and implicates the earlier run; negative confirms a genuine
  model failure at bits 14/19/22/23 and is the more interesting outcome.

A control-bracket failure voids the run; it is repeated, not reinterpreted.

## Fixed invocation

Same probe and binary as Verification 028 — `tools/a90_region_probe_r.c`
`2dbc81ef7595d30f627df8d28d24e21603d8c1c174074e85593b9fe8df5569e9`, built to
`bd41bb9c8a5f7dfe1ddcec8f069382df6e0ad85d8712da31a9823243c124d204`.

```
qsecom 32 201 16 7 spread \
  0x16000 0x2000 \
  0x784000 0x8b6000 0xaea000 0xb74000 \
  0xc84000 \
  0x40a000 0x518000 0x6ce000 0x91a000 \
  0x16000 0x2000
```

## Scope

`CLASS C (TRANSFORM ONLY)`. One ION allocation on the non-secure `qsecom` heap
and timing reads. No MMIO, controller, SMC, partition, `param` or reboot. The
only device mutation is a temporary `/dev/ion` node, created after verifying
the misc identity `10:94` and removed with absence proven.

## Result

Not run yet at the time of this commit.
