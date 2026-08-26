# Experiment 034 — bounded site-35 jump-table resolution

Status: `PROVED` for the bounded static resolver; `CLASS C (TRANSFORM ONLY)`;
`NOT_ELIGIBLE`; host-only and read-only.

This experiment resolves only the last Experiment 033 fail-closed site. It
does not widen the firmware scan and it does not treat a resolved static
branch as proof of runtime execution, runtime table contents, or a current
DRAM/security destination.

## Exact inputs

The experiment pins and semantically validates the committed Experiment 033
tool (`172708` bytes, SHA-256
`aeb346253aab7860554c8a1cb627d04cbd56d9d82abf50a4a5b811da62a20f93`) and
manifest (`2017356` bytes, SHA-256
`606723e5125d661c800b167133f2a9b69a3b8d47361b39176665a49be539e598`) before
importing the source from the already-hashed bytes. The 033 dependency chain
performs its own exact 032/031/029/027 hash and semantic gates. The exact
SM8150 XBL input is pinned as `4194304` bytes with SHA-256
`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.

No device, MMIO, SMC, boot image, or persistent state was touched. The
firmware is copied only in host memory for the four synthetic analyses.

## Static gate

At site 35 (`0x1484f954..0x1484fa3c`, store `0x1484f9e0`), the exact local
sequence is source-qualified and field-checked:

```text
0x1484f9f0  LDR W9,[SP,#36]       (zero-extended into X9)
0x1484f9f4  CMP W9,#4             (SUBS WZR,W9,#4)
0x1484f9f8  B.HI 0x1484fb9c       (unsigned out-of-range exit)
0x1484f9fc  ADRP X5,0x14824000
0x1484fa00  ADD X5,X5,#0xcf0       (X5 = 0x14824cf0)
0x1484fa04  LDR X1,[X5,X9,LSL#3]
0x1484fa08  BR X1                  (the original blocker)
```

The validator checks the guard condition and bound, ADRP/ADD table base,
load index/scale/destination, BR register, contiguous adjacency, and the
absence of any W9/X9 redefinition between the result load and table load.
The primary Arm source is the hash-pinned DDI0602 (ID092025, 2025-09): CMP
pp.135–136; B.cond pp.54–55; ADRP pp.30–31; ADD immediate pp.20–21; LDR
immediate pp.441–443 and register-offset pp.444–446; BR pp.67–68.
The unsigned guard interpretation also pins shared `AddWithCarry` p.4913 and
`ConditionHolds` p.4954.

Guard coverage is proved only for the exact Experiment 033 bounded CFG entered
at site head `0x1484f954`: that traversal is complete, retains the single exact
BR blocker, and has no modeled direct edge into the chain after the W9 load.
External or otherwise unmodeled entries remain `UNKNOWN`.

## Table and bounded synthetic resolver

The 40-byte table at `0x14824cf0` (XBL file offset `0xbcf0`) has SHA-256
`6c58a7dff5de7e6bc512bd83a5ce4f84499b2c89c0ff0a71b58b972c7f3dce61` and
entries:

```text
[0x1484fa3c, 0x1484fa50, 0x1484fa88, 0x1484fa0c, 0x1484fa0c]
```

The duplicate `0x1484fa0c` is retained as table multiplicity. Each of the
four unique entries was analyzed in a separate in-memory copy of the exact
XBL. Only the word at `0x1484fa08` was replaced, with the measured direct-B
encodings:

| target | replacement word | CFG states | observations | handled forms |
|---|---:|---:|---:|---:|
| `0x1484fa0c` | `0x14000001` | 186 | 7 | 19 |
| `0x1484fa3c` | `0x1400000d` | 181 | 5 | 19 |
| `0x1484fa50` | `0x14000012` | 190 | 6 | 20 |
| `0x1484fa88` | `0x14000020` | 212 | 10 | 23 |

All four runs were `cfg_complete=true`, had `unsupported_forms=[]`, and had
exactly `NO_TARGET_WITHIN_MODEL`. None produced `DCB_CONSUMER_PATH` or
`MC_OR_SHRM_SYMBOLIC_TARGET`. The replacement width is four bytes, while the
actual byte differences are three bytes for the first three listed target
words and two bytes for `0x14000020`; exact synthetic-image hashes and changed
byte indices are published in the manifest.

## Outcome and boundaries

`PROVED`: the combined bounded accounting is 71
`NO_TARGET_WITHIN_MODEL` and 0 fail-closed sites after the site-35 synthetic
resolver gate. All 71 baseline 033 site records remain in the public
manifest unchanged; the 70 non-site-35 records pass exact full-record
identity and the baseline site-35 record is retained verbatim for comparison.
The top-level `sites` array is explicitly baseline-only; the composed 034
71/0 result is published separately under `analysis.combined_outcome`.

`SUPPORTED`: resolving this one bounded indirect CFG edge removes the final
model blocker without creating a symbolic consumer or controller target.

`UNKNOWN`: runtime execution and ordering, actual table index and contents at
runtime, X1 runtime authority, aliases, current destination, global consumer
or writer absence, protected-memory semantics, and any Qualcomm security
boundary effect. This is not evidence of an address-transform primitive,
isolation bypass, or exploitability. Direct `B` and indirect `BR` also differ
in architectural branch-type/PSTATE.BTYPE behavior; that state is not modeled
and runtime equivalence is not claimed.

Experiments 028 and 030 are explicitly non-input and non-overlapping. Their
work and conclusions are not imported, inferred, or claimed by this
experiment.

## Validation record

- Focused Experiment 034 suite: **14/14 PASS**; Python `py_compile`: **PASS**;
  maximum RSS 125,552 KiB, swap 0.
- Full repository unittest discovery: **699/699 PASS** in 89.234 seconds;
  maximum RSS 274,656 KiB, swap 0.
- Two fresh CLI publications and the checked manifest are byte-identical at
  SHA-256 `75728982e1622f3e807c367baff5cc87d18cff94fa2a9135699f3f836b804b92`;
  all are mode `0644`.
- An independent raw-byte oracle recomputed all dispatch fields, five table
  entries, direct-B words, actual byte differences, four synthetic-image
  hashes, and exact baseline-site identity. GNU AArch64 disassembly agrees.
- Negative controls include 224 one-bit dispatch mutations plus dependency,
  guard, width, table identity/alignment/truncation/locality/multiplicity,
  substitution-boundary, source-availability, and no-clobber failures.
- Independent hostile review found one P2 (`CMP W` decoder omitted `sf`), which
  was fixed with an explicit width gate and exhaustive one-bit control. The
  same reviewer then returned **PASS** with no remaining P0–P2 findings.

## Final artifacts

| Artifact | Size | SHA-256 |
|---|---:|---|
| Experiment 034 tool | 56,864 | `7589b9f61d92fc835a2378f11106963c074619d59675209082ad919f823690a8` |
| Focused tests | 21,596 | `081b7334a4e88a04647d39e5657c13bcb537b374db192e0597b561ce02cae51b` |
| Checked public manifest | 2,241,492 | `75728982e1622f3e807c367baff5cc87d18cff94fa2a9135699f3f836b804b92` |

Reproduce with:

```text
python3 tools/sm8150_dcb_site35_jump_table.py \
  --firmware-dir <exact-firmware-dir> \
  --manifest-dir <public-manifest-dir> \
  --output <new-public-manifest-path>
```
