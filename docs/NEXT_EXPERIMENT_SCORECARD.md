# Next-experiment scorecard — 2026-08-26

This scorecard ranks host-only follow-up work after the integrated
Experiments 019–022, 024, and 025. It does not grant live, device, SMC, MMIO,
write, or Experiments 015/016 authority. Experiments 024 and 025 are complete
as bounded static results; their conditional and semantic boundaries remain
explicit below.

| Rank | Experiment | Information target | Scope and gate | Status |
|---:|---|---|---|---|
| 1 | 026 | Reconstruct exact-XBL dispatch/order linking registration/bootstrap to main-init, with a complementary slot-escape census. | Host-only: bind the new function/table/caller ranges below; census unsupported-form slot/page/global aliases and argument escapes. Treat every Experiment 025 range as dependency-only. Require independent re-derivation and pinned hashes before any promotion; no device action. | `PRIMARY HYPOTHESIS`; 95/100 |
| 2 | DCB writer follow-up | Resolve the remaining bounded DCB/register-writer complement after the 018–022 coverage. | Host-only, exact-byte and conservative decoder scope; no broad MMIO scan or device action. Preserve all current unknown writer/semantic boundaries. | `LATER`; 69/100 |
| 3 | 023R | Re-test the timing claim only after the protocol and provenance defects are repaired. | Require a protocol comparable to Experiment 014 (including ordering, warmup, barriers, and reopen accounting), physical-allocation PA provenance, and a unique full GF(2) matrix. `PA24=b1^b2` can remain `SUPPORTED` until those gates pass. | `LATER`; 64/100; 023 is withheld/`NO-GO` and not public |

The scores are decision aids, not vulnerability probabilities or evidence
labels. They compare critical-`UNKNOWN` closure, discriminatory power, success
probability, cost/recoverability, dependency/non-overlap, and reuse value.

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

## Experiment 025 integrated result

Experiment 025 is `COMPLETED` and integrated from commit `d743150` (parent
`a68d2f1`). It is host-only, read-only static analysis of the exact XBL with no
device, SMC, MMIO, protected-memory, normal-RAM, or activation action.

`PROVED`: helper `[0x1486abec,0x1486acac)` has one direct caller at
`0x1486847c`, which passes `X0=SP+0x10`, not main context `X19`; the helper's
exact slot path loads, addresses, and reloads `0x14890590`. The attach path
pins semantic `MOVZ/MOVK` service ID `0x02000139`.

`PROVED`: the static seed derives `X0=0x14875668` and outer record
`X1=0x14875590` with count five; it selects descriptor `0x14824ab8` -> factory
`0x1484a880` -> constructed object candidate `0x1488f418` -> inline vtable
`0x14824ad0 + 0x48` -> callback `0x1484a9d4`. The bounded callback path
`a9d4->a730->a824->aa30->a854` has one recognized output write at
`0x1484a9f4` to helper `SP+0xc`; nested recursion/status writes are only at
`0x1488f3f9`, `0x14890ba0`, and `0x14890b90`, with one decoded MMIO read at
`0x01fc8004` and zero recognized MMIO writes.

The all-file-backed executable census and pinned loop blocks are conservative
recognized coverage, not arbitrary-write absence. `SUPPORTED`: conditional
intended binding can populate the slot and the recognized callback flow does
not write caller context `+8`. `UNKNOWN`: runtime registration/order, slot
value/object identity, actual `BLR X9` target, alternate BSS mutation/global
aliases/unsupported writes, full `0x01d80000` base currentness, and live
mapping/authority. Experiment 024's UFS mapping remains conditional; Class C
remains unchanged and 015/016 remain `NOT ELIGIBLE`.

The integrated tool/test/README/manifest SHA-256 values are respectively
`16e9584a3043d76670c66b6a517e56c87267645506c1f76a040737d731b168b9`,
`219227a927acb8a98d8e7294150c154b916795e709ab02bb076b946d8d7bb687`,
`eb97735c91b79fb13f8feb40e9b98ffd7f2aa71a9dcc2fbe479fcdcf2e4014a3`, and
`d3c405d7c8d23dc1cd65b1c578b4b4ce931d9bdfeb303c892e9c0c145c4c81cc`.
The public manifest is 28,132 bytes and mode `0644`.
Validation is 22 focused and 556 full tests, 65 public JSON manifests, Python
byte-compilation, byte-identical regeneration, and two artifact-review PASS
results; the durable integration-doc review is recorded separately in
[EXP025_INTEGRATION_REVIEW_2026-08-26.md](EXP025_INTEGRATION_REVIEW_2026-08-26.md).

## Experiment 026 primary design boundary

Experiment 026 is the primary host-only selection, scored `95/100`, for exact-
XBL dispatch/order and a complementary unsupported-form slot/page/global-alias/
argument-escape census linking registration/bootstrap to main-init. Its new
design-input ranges are:

- registration-list helpers `[0x1482ecb4,0x1482edac)` and initializer loop
  `[0x1482edac,0x1482f0b4)`;
- table header `[0x14875534,0x14875568)`;
- bootstrap caller `[0x14852ce0,0x14852d70)`, veneer `[0x14843d20,0x14843d50)`,
  and alternate paths `[0x14828338,0x14828360)` and
  `[0x14828b44,0x14828c80)`;
- main dispatcher `[0x14864834,0x148648c0)`, callers
  `[0x148641a4,0x1486420c)`, `[0x1486420c,0x1486424c)`,
  `[0x148642dc,0x148644cc)`, and top `[0x1485a2ec,0x1485a30c)`;
- memory-only runtime initializer pool `[0x146b30c0,0x146b38b0)`.

These are design inputs/`HYPOTHESIS` only; no preliminary 026 range hashes are
claims until Experiment 026 independently re-derives and pins them. All 025
ranges are dependency-only. Even on static closure, runtime order, slot value,
actual `BLR` target, base currentness and live mapping remain `UNKNOWN`; no
device, SMC, MMIO, write, or activation action is part of this selection.

## Experiment 023R prerequisites

Experiment 023 is explicitly withheld as `NO-GO`: its timing order is not
comparable to Experiment 014 (fixed order, half warmup, `ISB`, and summed
reopen without `/2`), physical allocation PA provenance is missing so a
`+0x1000` countermodel still fits the labels, and the full GF(2) matrix is
non-unique. Its raw evidence is private and is not integrated or published.
Only a repaired rerun satisfying all three prerequisites may enter the
scorecard as evidence; until then `PA24=b1^b2` is `SUPPORTED`, not `PROVED`.
