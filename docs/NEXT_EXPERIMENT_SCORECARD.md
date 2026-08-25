# Next-experiment scorecard — 2026-08-26

This scorecard ranks host-only follow-up work after the integrated
Experiments 019–022 and 024. It does not grant live, device, SMC, MMIO, write,
or Experiments 015/016 authority. Experiment 024 is complete as a bounded
static result; its conditional and semantic boundaries remain explicit below.

| Rank | Experiment | Information target | Scope and gate | Status |
|---:|---|---|---|---|
| 1 | 025 | Determine whether the runtime BSS object/registry path can keep the initialized base current through the unresolved success-path callback. | Host-only: bound registry/attach/factory/vtable/callback reach, write cross-references, and boot-order evidence for BSS slot `0x14890590` and registry `[0x14890e50,0x14890f50)`. Require a qualified, independently reviewed committed manifest before any promotion. | `NEXT HOST-ONLY`; highest information value |
| 2 | 023R | Re-test the timing claim only after the protocol and provenance defects are repaired. | Require a protocol comparable to Experiment 014 (including ordering, warmup, barriers, and reopen accounting), physical-allocation PA provenance, and a unique full GF(2) matrix. `PA24=b1^b2` can remain `SUPPORTED` until those gates pass. | `LATER`; 023 is withheld/`NO-GO` and not public |

## Experiment 024 integrated result

Experiment 024 is `COMPLETED` and integrated from commit `c62c33e`. It is a
host-only, read-only static analysis with no device, SMC, MMIO, protected-memory,
normal-RAM, or activation action. The exact XBL input is pinned by SHA-256
`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.

`PROVED`: the exact walker `[0x148689a0,0x14868a64)` has the six-byte record
stride, `UMADDL` arithmetic, flags/offset/value loads at `+0/+2/+4`, exact
`0x8000` terminator comparison, `B.EQ` to the return, and conditional
`STR W14,[X15,X13]`. `LDRB` zero-extends the byte, so a taken store writes a
32-bit word; other nonterminator flag combinations may skip the store and flag
semantics remain `UNKNOWN`.

`PROVED`: exactly three direct callers exist at `0x14868640`, `0x1486867c`,
and `0x14868698`. The five nonzero provider alternatives select XBL-resident
tables; selector `== 0xf` has 53 unique aligned offsets, selector `!= 0xf`
has 127, and their cross-alternative syntactic union has 170 spanning
`0x7000..0x7de0`. Provider3 on selector `== 0xf` returns count zero without a
pointer, and the pinned zero-count path reaches `RET` before dereference.

The five table alternatives are `(0x14880bee, 43,
f7b7ca7dae26320d69c87c9b4c59472eb0933aa7216936ed7564f78b770f643c)`,
`(0x14880e70, 90,
8c26948bb9e7e24ae9c2d950412e851dd1e60e412aa4f82d7936c247103ac240)`,
`(0x14880ba0, 13,
eac051599765de4842c6ecf7a6076813eac93a07cd052d829787b1095fa353b1)`,
`(0x14880cf0, 64,
7c0fb81701455fb380cf4a2d1af4120a444a6be66235c2a87dad5ca2c932711f)`, and
`(0x14880b40, 16,
1c596a44cbec1cdbcc5b23e81eccde1c20556b17ab3c434ef393c29ab63aa015)`;
counts include each exact terminator. The alternatives contain 221
nonterminator records in total; each table is six-byte-record data ending in
the exact `0x8000/0/0/0` terminator.

`PROVED`: the two pinned design-source snapshots contain byte-identical UFS
blocks (4,464 bytes, SHA-256
`cea31db3785be5916a1ff08d1c99b92155a7914b07d09ecb6c3638d8c16ff10a`). Under
initialized-base retention, all 170 symbolic `BASE+offset` destinations lie
inside broader `ufshc` `ufs_phy` `[0x01d87000,0x01d87e00)`; three offsets
(`0x7dc4`, `0x7dd8`, `0x7de0`) lie beyond standalone `ufsphy_mem` while still
inside the broader resource. The Experiment 019 dependency pins the separate
8-byte representation, and the two forms are structurally distinct.

`SUPPORTED`: the direct-call positive control supports a table-driven UFS
interpretation only under initialized-base retention and store reach; it does
not prove or refute a DDR/MC/DCB path. `UNKNOWN`: current base because of the
runtime-BSS `BLR X9` at `0x1486ac1c`, selector/runtime execution, reached-store
subset, flag semantics, live-DTB equality, DCB semantic alias/global
consumer/writer, DDR/MC relation, GF(2), and alias/bypass. All 170 mappings are
conditional symbolic `BASE+offset` supersets, not one execution/current
destination set. Class C remains unchanged; 015/016 remain `NOT ELIGIBLE`.

The integrated tool/test/manifest SHA-256 values are respectively
`f0ccb5648b2cce4ab2b835e23c4658c976df9779b0ae6273767b59cc7b6a58bf`,
`97c58a22c5c3e7e6cd5b7bc4f8d181c74050b2b530afac03eba3fbb946577f6d`, and
`f9ac896d396650075ca9e66d8d805a2deaf40b0207e819cd94f8d638c8121b01`.
Validation is 30 focused and 534 full tests, 64 public JSON manifests, a
byte-identical regeneration, and two independent review `PASS` results
recorded in
[EXP024_INTEGRATION_REVIEW_2026-08-26.md](EXP024_INTEGRATION_REVIEW_2026-08-26.md).
The public manifest is 30,400 bytes and mode `0644`.

## Experiment 025 design boundary

The highest-information next step is bounded registry/attach/factory/vtable/
callback and write-xref/boot-order proof for runtime BSS slot `0x14890590` and
registry `[0x14890e50,0x14890f50)`. Pre-integration design inputs are the seed
`[0x1482ee38,0x1482ee4c)`, registry/attach `[0x1482d7ec,0x1482d948)`, wrappers
`[0x1482e7bc,0x1482e834)`, record `0x14875590` with ID `0x02000139`,
descriptor/vtable `0x14824ab8..0x14824b40`, factory `[0x1484a880,0x1484a8fc)`,
and callback `[0x1484a9d4,0x1484aa0c)`. These are design inputs, not final
claims. Do not promote before a qualified, independently reviewed committed
025 manifest. No device action or MMIO write is part of this scorecard.

## Experiment 023R prerequisites

Experiment 023 is explicitly withheld as `NO-GO`: its timing order is not
comparable to Experiment 014 (fixed order, half warmup, `ISB`, and summed
reopen without `/2`), physical allocation PA provenance is missing so a
`+0x1000` countermodel still fits the labels, and the full GF(2) matrix is
non-unique. Its raw evidence is private and is not integrated or published.
Only a repaired rerun satisfying all three prerequisites may enter the
scorecard as evidence; until then `PA24=b1^b2` is `SUPPORTED`, not `PROVED`.
