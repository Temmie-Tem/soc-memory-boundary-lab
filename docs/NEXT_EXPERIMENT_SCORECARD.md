# Next-experiment scorecard — 2026-08-26

This scorecard ranks host-only follow-up work after the integrated
Experiments 019–022 and 024–026. It does not grant live, device, SMC, MMIO,
write, or Experiments 015/016 authority. Experiments 024–026 are complete as
bounded static results; their conditional and semantic boundaries remain
explicit below.

| Rank | Experiment | Information target | Scope and gate | Status |
|---:|---|---|---|---|
| 1 | 027 | Resolve the remaining bounded DCB consumer/writer complement after the integrated 024–026 coverage. | Host-only, exact XBL plus pinned `xbl_config--sdb2.bin`; use exact DCB blocks and explicit loader/section-directory/computed-address discriminators. Keep checksum/bounds readers distinct from controller writers, exclude 024–026 dependency ranges, and preserve all runtime-base/writer/semantic `UNKNOWN`s. No broad MMIO scan or device action. | `PRIMARY SELECTED`; 79/100 |
| 2 | E — capture-feasibility | Assess whether a future host-only evidence capture has a safe, bounded path without promoting a device action. | Read-only feasibility review only; no capture, device, SMC, MMIO or write action. | `LATER`; 52/100 |
| 3 | D — 023R | Re-test the timing claim only after the protocol and provenance defects are repaired. | Require a protocol comparable to Experiment 014 (including ordering, warmup, barriers, and reopen accounting), physical-allocation PA provenance, and a unique full GF(2) matrix. `PA24=b1^b2` can remain `SUPPORTED` until those gates pass. | `LATER`; 41/100; 023 is withheld/`NO-GO` and not public |
| 4 | B — base currentness | Resolve initialized-base currentness as a bounded static/runtime-boundary question. | Preserve the unresolved runtime base and indirect `BLR` boundaries; no device action or live promotion. | `LATER`; 24/100 |
| 5 | A — runtime slot/object observation | Reassess the runtime slot/object question only if a safe evidence path exists. | The existing 26-record catalog does not cover the target slot; no safe capture path is currently available. This is not selected; no device action is proposed by this scorecard; future action needs a separate exact-bound contract/gates. | `LATER`; 14/100 |

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

## Experiment 026 integrated result

Experiment 026 is `COMPLETED` and integrated from commit `0305a03` as
host-only, read-only static analysis of the exact XBL. `PROVED`: registration
helpers `[0x1482ecb4,0x1482edac)` pin a 24-byte node and list head
`0x14890f60`; initializer loop `[0x1482edac,0x1482f0b4)`; table header
`[0x14875534,0x14875568)` has count two, row start `0x14875538`, cursor
`0x1487554c`, and stride `0x18`. `PROVED`: bounded bootstrap, veneer,
alternates, dispatcher, and caller local/control/data edges include the
dispatcher base/stride/index guard and symbolic pointer escape
`0x146b30c0 + runtime_index*0x3f8` for modeled index `0..1`, not an exact
runtime base. `SUPPORTED`: memory-only initializer-pool shape
`[0x146b30c0,0x146b38b0)`, two-row `0x3f8` geometry. Pool contents and runtime
values remain `UNKNOWN`.

The complementary census scans 847,465 executable words, excludes 622 words
covered by 025, recognizes 9 accesses (3 writes, 6 reads) and 2 pointer
escapes, and finds zero recognized interval-overlap writes to slot
`[0x14890590,0x14890598)`. Its taxonomy is `ORDER_OPEN` and
`PROVED_BOUNDED_NO_RECOGNIZED_SLOT_MUTATION`; this is not global writer
absence. Runtime execution/order, slot value, object identity, `BLR` target,
base currentness, writer absence and live authority remain `UNKNOWN`. Its
artifact hashes and 25 focused/581 full validation are recorded in
[EXP026_INTEGRATION_REVIEW_2026-08-26.md](EXP026_INTEGRATION_REVIEW_2026-08-26.md).

## Experiment 027 selected bounded DCB consumer/writer complement

Experiment 027 is the selected next host-only follow-up, scored `79/100`; this
scorecard records selection only, not an implementation or preliminary hash.
The exact XBL remains bound by size 4,194,304 and SHA-256
`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`. The
second exact input is `xbl_config--sdb2.bin`, size 4,149,248, SHA-256
`0e9dfac1ddd0f9acc2cc899213e621490308f0cadf329814048edb7712e2484c`.

The 020 target set is the 67 register-offset loop sites minus the one 024
walker (66 new loop candidates), plus all 8 computed-address sites. Representative
computed-address loop stores are `0x1484b9a0`, `0x146aea20`, and `0x9fc05ef4`;
the exact candidate-segment setter is `[0x9fc06410,0x9fc0643c)` with direct
caller `0x9fc023f0`. The DCB candidate sections are 6, 7, 8, 10, 11, and 12;
section 5's absolute-address table is a negative control only, not a promoted
DCB writer target.

The four DCB blocks are `0x3404` bytes at file offsets `0x1079c`, `0x13ba0`,
`0x16fa4`, and `0x1a3a8`. Other exact discriminators are the XBL DCB-loader
window `[0x1489f9e8,0x1489fbe8)` and section-directory reader starts
`0x1485f0f8`, `0x1485f13c`, `0x1485f17c`, `0x1485f1c0`, `0x1485f200`, and
`0x1485f23c`. The full 024 walker `[0x148689a0,0x14868a64)` is an excluded
positive control; the overlapping 020 subrange `[0x148689c8,0x14868a60)`
(SHA-256 `02248b786ffb501a5fa9242aa3952e1e4d783f47464952e96ca2704a9f94341`)
is not a new claim. The three 024 direct-caller context ranges are also
excluded/control: `[0x14868630,0x14868644)`, `[0x14868668,0x14868680)`, and
`[0x14868684,0x1486869c)`.

Required outcome labels are `DCB_CONSUMER_PATH`,
`MC_OR_SHRM_SYMBOLIC_TARGET`, `NO_TARGET_WITHIN_MODEL`, and
`INDIRECT_OR_UNSUPPORTED`. Stop and preserve `UNKNOWN` on unsupported forms,
aliases, unresolved computed pointers, overlap with an excluded/control range,
or any device/MMIO/write action. The implementation must distinguish
checksum/bounds readers from controller writers and preserve `UNKNOWN` for
runtime base, writer identity/absence, register semantics and execution. No
device, SMC, MMIO, normal-RAM, protected-memory or write action is selected.

## Alternative A boundary — runtime slot/object observation

The exact 26-record rawdump catalog does not cover slot `0x14890590`. Record 19
maps SHRM `SHRM_MEM.BIN` at `[0x09060000,0x09070000)`; the retained `ocimem`
window is `[0x14680000,0x146c0000)`. Neither interval covers the runtime slot.
Samsung Upload supplies only `SHRM_MEM.BIN`; Sahara status is
`NO_SHRM_DUMP_CAPTURED`. There is no safe arbitrary XBL-BSS path in the
current evidence, and survival is `UNKNOWN`, not absent. This alternative is
not selected; no device action is proposed by this scorecard; future action
needs a separate exact-bound contract/gates.

## Experiment 023R prerequisites

Experiment 023 is explicitly withheld as `NO-GO`: its timing order is not
comparable to Experiment 014 (fixed order, half warmup, `ISB`, and summed
reopen without `/2`), physical allocation PA provenance is missing so a
`+0x1000` countermodel still fits the labels, and the full GF(2) matrix is
non-unique. Its raw evidence is private and is not integrated or published.
Only a repaired rerun satisfying all three prerequisites may enter the
scorecard as evidence; until then `PA24=b1^b2` is `SUPPORTED`, not `PROVED`.
