# Next-experiment scorecard — 2026-08-26

This scorecard ranks host-only follow-up work after the integrated
Experiments 019–022, 024–027, 029, and 031. It does not grant live, device,
SMC, MMIO, write, or Experiments 015/016 authority. The integrated Experiments
024–027, 029, and 031 are complete as bounded static results; their conditional
and semantic boundaries remain explicit below. External 028/030 are excluded.

| Rank | Experiment | Information target | Scope and gate | Status |
|---:|---|---|---|---|
| 1 | 032 | Qualify official semantics for the exact reached arithmetic frontier left by Experiment 031. | Host-only; bind an official source and inspect only reached `MADD/UMADDL`, `EOR`, and `BIC` blockers. Preserve site 35's indirect branch, site 56's pair, and all unsafe/unknown forms as fail-closed; no device/MMIO/write action. | `PRIMARY SELECTED`; 82/100 |
| 2 | E — capture-feasibility | Assess whether a future host-only evidence capture has a safe, bounded path without promoting a device action. | Read-only feasibility review only; no capture, device, SMC, MMIO or write action. | `LATER`; 52/100 |
| 3 | D — 023R | Re-test the timing claim only after the protocol and provenance defects are repaired. | Require a protocol comparable to Experiment 014 (including ordering, warmup, barriers, and reopen accounting), physical-allocation PA provenance, and a unique full GF(2) matrix. `PA24=b1^b2` can remain `SUPPORTED` until those gates pass. | `LATER`; 41/100; 023 is withheld/`NO-GO` and not public |
| 4 | B — base currentness | Resolve initialized-base currentness as a bounded static/runtime-boundary question. | Preserve the unresolved runtime base and indirect `BLR` boundaries; no device action or live promotion. | `LATER`; 24/100 |
| 5 | A — runtime slot/object observation | Reassess the runtime slot/object question only if a safe evidence path exists. | The existing 26-record catalog does not cover the target slot; no safe capture path is currently available. This is not selected; no device action is proposed by this scorecard; future action needs a separate exact-bound contract/gates. | `LATER`; 14/100 |
| — | 028/030 (external Claude) | Bank-relation/SHRM encoding and low-bit selection work. | External work outside this integration and unreviewed here; no result, score, authority, or review is claimed here. | `OUTSIDE THIS INTEGRATION`; not scored |

The scores are decision aids, not vulnerability probabilities, success
probabilities, or evidence labels. They compare critical-`UNKNOWN` closure,
discriminatory power, execution feasibility, cost/recoverability,
dependency/non-overlap, and reuse value.

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

## Experiment 027 integrated bounded DCB consumer/writer complement

Experiment 027 is `COMPLETED` and integrated from commit `7aa1df7`; its score
was `79/100` at selection. The exact XBL is bound by size 4,194,304 and
SHA-256 `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.
The exact `xbl_config--sdb2.bin` input is 4,149,248 bytes with SHA-256
`0e9dfac1ddd0f9acc2cc899213e621490308f0cadf329814048edb7712e2484c`.

The bounded result analyzes 65 of the 67 Experiment 020 register-offset sites
after two dependency-owned exclusions, plus all 8 computed-address idioms
(three complete loop contexts and five local forms), for 73 sites total. The
census returns 71 `INDIRECT_OR_UNSUPPORTED`, 2 `NO_TARGET_WITHIN_MODEL`, zero
`DCB_CONSUMER_PATH`, and zero `MC_OR_SHRM_SYMBOLIC_TARGET`. Two nonexclusive
`SECTION_READER_PROXIMITY_ONLY` hypotheses remain: `0x148aa758` to reader
`0x148ab138` at signed `-2528`/absolute `2528`, and `0x148ab4f8` to the same
reader at signed `960`/absolute `960`; threshold `0x1000`,
`link_proof: NONE`. All runtime base/current destination, execution, aliases,
writer/global consumer identity, register semantics, and unsupported paths
remain `UNKNOWN`; zero labels are bounded-model results, not global absence
claims.

The DCB sections are 6/7/8/10/11/12, with section-7 keys `0x400` and `0x404`
both carrying `0x10000000` in all four `0x3404`-byte blocks at offsets
`0x1079c/0x13ba0/0x16fa4/0x1a3a8`. The exact candidate setter is
`[0x9fc06410,0x9fc0643c)` with caller `0x9fc023f0`; the 024 walker and
overlapping 020 false-negative range remain excluded controls. The public
manifest is 334,847 bytes, mode `0644`, SHA-256
`d11785969f16ba09155a2305eefd091158abfc515bc64cf94cb34d573a302277`.
Validation is 35 focused and 616 full unittest PASS in 86.100 s, Python
byte-compilation, 67 public JSON manifests, two fresh byte-identical
generations, public safety/no-clobber, and independent hostile review `PASS`
after fixes, recorded in [EXP027_INTEGRATION_REVIEW_2026-08-26.md](EXP027_INTEGRATION_REVIEW_2026-08-26.md).

## Experiment 029 integrated unsupported-frontier inventory

Experiment 029 is `COMPLETED` and integrated from commit `a495bdc`, with
selection score `76/100`. It uses the exact XBL (4,194,304 bytes,
`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`) and the
committed Experiment 027 tool pin
`11a4dab37e9a54e74ec93fba7c89524de1e77c7e71b86f105dd167d77780bcb9` plus
manifest pin
`d11785969f16ba09155a2305eefd091158abfc515bc64cf94cb34d573a302277`.
It inspects only the 71 fail-closed site ranges. It independently
deduplicates unique VAs versus per-site multiplicity, classifies exact
unrecognized instruction forms without treating syntactic range membership as
reachability, and ranks only source-backed decoder-extension candidates for
later semantic review. Required labels are `DECODER_EXTENSION_CANDIDATE`,
`FLAG_ONLY_NO_GPR_DEF`, `TAINT_KILL_REQUIRED`,
`CONTROL_OR_MEMORY_UNSUPPORTED`, and `UNREACHABLE_OR_OVERLAP_UNKNOWN`.
`PROVED`: the 71 ranges contain 1,992 occurrences / 1,180 unique VAs; the
unsupported frontier is 352 occurrences / 219 unique VAs / 197 unique words.
The primary classes are `DECODER_EXTENSION_CANDIDATE` 161,
`FLAG_ONLY_NO_GPR_DEF` 99, `TAINT_KILL_REQUIRED` 27,
`CONTROL_OR_MEMORY_UNSUPPORTED` 54, and `UNKNOWN` 11. These are bounded
syntactic labels only: source provenance, CFG reachability, decoder safety,
runtime destination, consumer/writer identity, and writer absence remain
`UNKNOWN`/`NOT_CLAIMED`. Validation is 17 focused and 633 full unittest PASS
in 84.985 s, 68 public JSON manifests, byte-identical repetition, and final
hostile review `PASS`, recorded in
[EXP029_INTEGRATION_REVIEW_2026-08-26.md](EXP029_INTEGRATION_REVIEW_2026-08-26.md).

## Experiment 031 integrated scalar-frontier extension

Experiment 031 is `COMPLETED` and integrated from artifact commit `cd9f26e`
plus reconciliation repair `12a8ebe`. The source-qualified scalar-plus-
dispatch v2 model selects 283 occurrences / 160 unique VAs / 148 unique
words, reaches 250 selected events, and retains 69 occurrences / 59 unique
VAs / 49 unique words across 20 sites. It transitions 51 of the 71 baseline
sites to bounded `NO_TARGET_WITHIN_MODEL`; 20 remain
`INDIRECT_OR_UNSUPPORTED`. The result is explicitly `V2_MODEL_ONLY` and
`NO_ABSENCE_CLAIM`, and the 51-site transition depends on the combined scalar
and `DIRECT_CONTROL_DISPATCH_REPAIR` model rather than scalar-only closure.

The repair contributes 143 events across 62 sites: `B.cond` 87,
`CBZ/CBNZ` 28, `B` 15, and `TBZ/TBNZ` 13. Pair/sign-extending memory,
system/control, three-source, `BIC`/`EOR`, indirect aliases, and unsafe forms
remain fail-closed; zero `DCB_CONSUMER_PATH` and zero
`MC_OR_SHRM_SYMBOLIC_TARGET` are bounded-model labels, not absence claims.
Validation is 19 focused and 652 tracked full unittest PASS in 85.226 s,
maximum RSS 220,684 KiB with no swaps, Python byte-compilation, 69 public JSON
manifests, two fresh manifests byte-identical to the checked manifest, QEMU
280/280, and final reconciliation hostile review `PASS`, recorded in
[EXP031_INTEGRATION_REVIEW_2026-08-26.md](EXP031_INTEGRATION_REVIEW_2026-08-26.md).
The reconciled artifact pins are tool 91,221 bytes / SHA-256
`5263d8975e9d64809aed04763e0c5573458dabcc6ae7432763d2858a36fc267b`, tests
18,751 bytes / SHA-256
`3a81fb4b4fc3023e70918a1648b6f04bb50e0967d27a8f09dbf939f9b55eff6d`,
Experiment README 7,580 bytes / SHA-256
`12924ad1fcfeba580f57447e67f74d14743a5962046941ff3088e1b130d173de`, and
manifest 1,327,118 bytes / mode `0644` / SHA-256
`51a187195c16eb609d337305540fc6d20a09297f5ab76b054497c5c58c3a2e86`.

## Experiment 032 selection rationale

Experiment 032 is the next non-overlapping host-only selection at `82/100`.
It qualifies an official source and applies bounded semantics to the exact
reached `MADD/UMADDL` plus `EOR/BIC` arithmetic frontier. The target blockers
are 10 reached `THREE_SOURCE` events at sites 35/36/37/56, two `EOR` events at
sites 36/37, and two `BIC` events at sites 1/52. Site 35's indirect branch and
site 56's pair remain fail-closed.

This selection outranks pair-memory because pair-memory has 41 events across
13 sites, 38 of them `LDP`, with most of the remainder being SP epilogues;
the arithmetic forms directly construct indexes/addresses in the high-value
runtime-alias/hash-like contexts. Pair-memory remains a later candidate. No
device, MMIO, write, or live authority is selected.

External Claude Experiments 028 and 030 remain outside this integration and
unreviewed here. No result, score, authority, review, or commit from either is
claimed or integrated.

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
