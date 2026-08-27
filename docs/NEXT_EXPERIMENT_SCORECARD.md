# Next-experiment scorecard — 2026-08-27

This scorecard ranks follow-up work after Experiment 034, the exact-parent
`247b0e1` external-line reconciliation, and the independently rebuilt
Verifications 015/016. It does not grant SMC, MMIO,
controller-write, protected-memory, or numbered Experiments 015/016 authority.
Later moving-branch commits are evidence to repair, never moving-tip authority.

| Rank | Experiment | Information target | Scope and gate | Status |
|---:|---|---|---|---|
| 1 | 020D second-caller field-use trace | Trace the second direct caller `0x9fc26e2c` of `0x9fc160b8` to its bounded object-field loads and static stores, without treating values as runtime MMIO. | Host-only exact-XBL control/data flow; preserve indirect paths, runtime execution/currentness/type and destination semantics as `UNKNOWN`; no device/MMIO/controller write. | `PRIMARY NEXT; BOUNDED ONLY` |
| 2 | 020C return-helper origin trace | Trace the exact `BL 0x9fc160b8` helper that supplies the 020B object, including its static return-address construction and bounded direct callers. | Host-only exact-XBL control/data flow; preserve runtime data/type/currentness, indirect paths, and static-object semantics as `UNKNOWN`; no device/MMIO/controller write. See `docs/VERIFICATION020C_INTEGRATION_REVIEW_2026-08-27.md`. | `COMPLETED; STATIC VADDR ONLY / CLASS C UNCHANGED` |
| 3 | 020B caller-object origin trace | Trace the opaque incoming object at `0x9fc023f0` to its bounded direct callers and construction/origin fields. | Host-only exact-XBL control/data flow; preserve indirect `BLR`, runtime execution, currentness and type as `UNKNOWN`; no device/MMIO/controller write. See `docs/VERIFICATION020B_INTEGRATION_REVIEW_2026-08-27.md`. | `COMPLETED; SYMBOLIC FIELDS / CLASS C UNCHANGED` |
| 4 | 020A setter/base trace | Trace candidate setter `0x9fc06410` through caller `0x9fc023f0` to the runtime base-argument source. | Host-only exact-firmware control/data flow; bounded model only; no device/MMIO/controller write. See `docs/VERIFICATION020A_INTEGRATION_REVIEW_2026-08-27.md`. | `COMPLETED; SYMBOLIC FIELDS / CLASS C UNCHANGED` |
| 5 | Route-2 manifest audit | Revalidate the exact 029–034 bounded writer-path summaries and rank-relation fields without converting unknown raw rows into concurrence. | Host-only exact-byte/hash and semantic audit; Q1 bounded closure, Q4 remains UNKNOWN; no device/MMIO/write. See `docs/ROUTE2_RANK_AUDIT_INTEGRATION_REVIEW_2026-08-27.md`. | `COMPLETED; Q1 SUPPORTED / Q4 UNKNOWN; CLASS C UNCHANGED` |
| 6 | Verification 017 post-decode-granularity audit | Check the external bank-granularity argument now that V016's dependency gate is satisfied. | Host-only algebra/carveout audit; require exact distinction between bank-only refutation and full post-transform-coordinate enforcement. | `COMPLETED; BANK-ONLY SHAPE REFUTED; CLASS C UNCHANGED` |
| 7 | Verification 018 allocation-local baseline | Establish the storage-identity baseline with exact raw provenance and positive/negative controls. | Completed one reversible `camera_preview` run; no MMIO, SMC, secure heap, protected memory or partition action. Result is one-state allocation-offset evidence only. | `COMPLETED; DEVICE_ACQUISITION_VALIDATED; CLASS C UNCHANGED` |
| 8 | E — capture-feasibility | Assess whether a future bounded evidence capture has a safe path without promoting a controller action. | Feasibility review only; no SMC/MMIO/protected-memory action. | `LATER` |
| 9 | B — base currentness | Resolve initialized-base currentness as a bounded static/runtime-boundary question. | Preserve the unresolved runtime base and indirect `BLR` boundaries; no live promotion. | `LATER` |
| — | Verification 015 | Test relation stability across retained condition-labelled runtime/reboot/coldboot sets. | Rebuilt from 19 pinned inputs: four clean invariant comparisons; L762 remains `REPEAT_REQUIRED`/`all_invariant=false`; six independent repeat groups have zero flips; bus-vote axis excluded. | `COMPLETED`; 44 focused / 1,039 full PASS, hostile `PASS` |
| — | Verification 016 | Determine what the retained camera-preview measurements establish above model bit 24. | Rebuilt from three pinned raw files: phase-specific splits, per-pass consistency, exact matches and 7/7 separate held-out agreement; physical mapping remains `UNKNOWN` under `BLIND` pagemap. | `COMPLETED`; 23 focused / 1,062 full PASS, hostile `PASS` |
| — | 034 | Resolve the exact site-35 indirect jump table left by Experiment 033. | Completed bounded host-only reconstruction: five entries/four unique targets and 71/71 `NO_TARGET_WITHIN_MODEL`; no global absence claim. | `COMPLETED`; artifact commit `d5d8046` |
| — | 023R/028/029A/030 | Repaired relation, encoding, ABL and low-bit evidence. | Reconciled at exact parent `247b0e1` after scope/provenance/phase repairs; model/physical and runtime boundaries remain explicit. | `RECONCILED`; later commits excluded |
| — | 033 | Source-qualify and model the exact reached pair-memory, sign-extending-memory, and system-control residual left by Experiment 032. | Completed host-only extension: 352 selected occurrences, 308 reached events, 44 selected-not-reached; 44 new events (`LDP` 38, `STP` 3, `LDRSW` 1, `LDRSB` 1, `DAIFClr` 1), six explicit STP lane observations, and a single site-35 indirect blocker preserved fail-closed; no device/MMIO/write action. | `COMPLETED AND INTEGRATED`; 033 artifact commit `56b5ffa` |
| — | 032 | Source-qualify and model the exact reached arithmetic frontier left by Experiment 031. | Completed host-only extension: 15 arithmetic rows across 7 sites, with all unsafe/unknown forms and site 35/site 56 blockers preserved fail-closed; no device/MMIO/write action. | `COMPLETED AND INTEGRATED`; 82/100 |

The scores are decision aids, not vulnerability probabilities, success
probabilities, or evidence labels. They compare critical-`UNKNOWN` closure,
discriminatory power, execution feasibility, cost/recoverability,
dependency/non-overlap, and reuse value.

## Verification 020B and 020C completed results

020B is complete as a host-only, read-only exact-XBL trace.  The sole direct
caller of consumer `0x9fc023c8` obtains an opaque token from `BL 0x9fc160b8`,
constructs a stack object at `SP+0x20`, and supplies the 020A setter arguments
from return-object offsets `0x0c`, `0x18`, `0x20`, and `0x28`.  The finite model,
focused tests (7/7), full serial suite (1,167/1,167, `skipped=1`), and hostile
review all pass.  Runtime values/type/currentness, indirect callers, static
object semantics, physical-to-DRAM mapping, mutability, protected reach and
alias/bypass remain `UNKNOWN`; Class C is unchanged.

020C then proved that the exact `0x9fc160b8` helper is `ADRP X0` to
`0x9fc36000`, `ADD #0x2c0`, `RET`, yielding static ELF VADDR `0x9fc362c0`,
with exactly two direct callers (`0x9fc22cc0` and `0x9fc26e2c`).  The returned
object range is hash-pinned only.  Runtime contents/type/currentness, writer or
mutability state, physical-to-DRAM mapping, protected reach and alias/bypass
remain `UNKNOWN`; Class C is unchanged.

The next candidate, 020D, is deliberately non-overlapping: trace the second
direct caller `0x9fc26e2c` to its bounded field loads/stores and preserve all
runtime and destination semantics as `UNKNOWN`.

Experiment 034's historical `94/100` selection score was explicit: information gain
20/20 (the sole remaining 033 fail-closed site), discriminating power 20/20
(every guarded table target is separately testable), success feasibility
13/15 (the exact sequence/table is reconstructed but not yet pinned by the
034 artifact), cost 10/10 (existing retained inputs), safety/recoverability
15/15 (pure host-memory copies, no device state), dependency/non-overlap 8/10
(depends on exact 033 but not external 028/030), and reuse value 8/10 (a
fail-closed guarded jump-table resolver is reusable). That selection is now
completed; it is not the current scorecard choice.

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

## Experiment 032 integrated result

Experiment 032 is `COMPLETED` and integrated from artifact commit `d46c44c`
after docs commit `e063181`. It is a host-only, read-only, source-qualified
arithmetic extension of the exact 031 scalar-plus-dispatch model. The exact
XBL input remains `xbl--sdb1.bin`, 4,194,304 bytes, SHA-256
`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.

`PROVED`: the combined selected membership is **298 occurrences / 175 unique
VAs / 162 unique raw words** across the 71 exact 029 ranges. It consists of
the inherited 031 domain (283 / 160 / 148) plus 15 arithmetic rows across
seven sites (15 / 15 / 14). The bounded model reaches 264 selected events;
34 selected occurrences are not reached. The reached arithmetic identity is
14 events: `MADD` 3, `UMADDL` 7, `EOR` 2, and `BIC` 2. The 031 full-record
equivalence gate is exact for 250 reached extension events, 143 direct-control
events, and 23 reached taint-kill events.

`PROVED`: the combined v3 model transitions **55/71** baseline sites to
bounded `NO_TARGET_WITHIN_MODEL`; 16 remain `INDIRECT_OR_UNSUPPORTED`.
Relative to 031, four sites transition (1, 36, 37, and 52), 51 remain
no-target, and there are zero regressions. The residual syntactic frontier is
**54 occurrences / 44 unique VAs / 35 unique raw words across 15 sites**:
`PAIR_MEMORY` 48, `SIGN_EXTENDING_MEMORY` 2, and `SYSTEM_CONTROL` 4.
Range membership is not CFG reachability; all results are `V3_MODEL_ONLY` and
`NO_ABSENCE_CLAIM`. Zero `DCB_CONSUMER_PATH` and zero
`MC_OR_SHRM_SYMBOLIC_TARGET` paths are promoted, and `current_destination` and
`writer_absence` remain `UNKNOWN`.

The added forms are qualified against Arm's primary A64 source, DDI0602
(ID092025), version 2025-09: `MADD` page 539, `UMADDL` page 873, shifted `EOR`
page 354, and shifted `BIC` page 62. The source PDF is
`ISA_A64_xml_A_profile-2025-09_ASL0.pdf`, 25,622,354 bytes, SHA-256
`683025f0460c8af8d6711b764c5c4d51d1b56f38d78b618e6cb27d9abf4c853f`.
Only modulo-width arithmetic and explicit exact identity cases preserve an
address origin; overlaps read pre-state, `Rd=31` is a ZR discard, and
reserved, unsafe, pointer-transform, pair-memory, sign-extending-memory,
system/control, and indirect forms remain fail-closed.

The final artifact pins are tool 127,151 bytes / SHA-256
`d4233d08ebe3c28cf803f5e9e1e564f1d9e40af12eca85498d23e569821219e2`, focused
tests 22,710 bytes / SHA-256
`8bb006cb409235bff0b5a2d2fe2a00cae389eb5253124fcd580bb7713df4d3ad`,
Experiment README 6,484 bytes / SHA-256
`20292544e84c5a30876856043287cf6b712642309a6ccd7cfb3fa21702da7573`, and
checked public manifest 1,564,295 bytes / mode `0644` / SHA-256
`beee3cdaa7d69f240310bed8b574f8dd81b00b48c2383f48dd849ebd36fb4b31`.
Validation is 18 focused PASS (maximum RSS 58,388 KiB, swap 0), 670
full-discovery unittest PASS in 84.937 s (maximum RSS 233,928 KiB, swaps 0), Python
byte-compilation, 70 public JSON manifests, two fresh byte-identical
generations, exact-word QEMU 56/56, synthetic QEMU 76/76, logical and
three-source encoding grids totaling 1,152/1,152, and final independent hostile
review `PASS`; the durable review is
[EXP032_INTEGRATION_REVIEW_2026-08-26.md](EXP032_INTEGRATION_REVIEW_2026-08-26.md).

## Experiment 033 integrated result

Experiment 033 is `COMPLETED` and integrated from artifact commit `56b5ffa`.
It is a host-only, read-only v4 extension of the exact 032 bounded model over
the exact A90/SM8150 XBL input. The complete 029 frontier is selected as 352
occurrences / 219 unique VAs / 197 unique words; 308 selected events are
reached and 44 selected occurrences are not reached. The 44 new residual
events are `LDP` 38, `STP` 3, `LDRSW` 1, `LDRSB` 1, and `DAIFClr` 1. The three
`STP` instructions publish six explicit lane observations.

`PROVED`: source-qualified `LDP W/X` signed-offset, `LDP X` post-index,
`STP W/X` signed-offset, `LDRSW X`, `LDRSB W`, and exact `DAIFClr #IRQ` forms
are bounded with fail-closed handling for pre-index/unseen modes, SIMD/FP
pairs, LDPSW, overlap/unpredictable forms, other system forms, indirect
aliases, and malformed words. The measured site result is 70
`NO_TARGET_WITHIN_MODEL` and one `INDIRECT_OR_UNSUPPORTED`, with site 35
remaining unresolved. No bounded `DCB_CONSUMER_PATH` or
`MC_OR_SHRM_SYMBOLIC_TARGET` path is promoted.

The inherited 032 canonical full-record equality is exact for 264 reached
extension events, 143 direct-control events, and 23 taint-kill events. This is
`V4_MODEL_ONLY` / `NO_ABSENCE_CLAIM`: global writer identity/absence, current
physical destination, protected-memory semantics, and the runtime exception
level or `CheckDAIFAccess` outcome for `DAIFClr` remain `UNKNOWN`. Class C and
Experiments 015/016 eligibility are unchanged.

The artifact pins are tool 172,708 bytes / SHA-256
`aeb346253aab7860554c8a1cb627d04cbd56d9d82abf50a4a5b811da62a20f93`, focused
tests 20,273 bytes / SHA-256
`58632f7a74772e2e86f1ff106c616fd85d0719781394a099cf0d411bb7258dba`, and
checked public manifest 2,017,356 bytes / mode `0644` / SHA-256
`606723e5125d661c800b167133f2a9b69a3b8d47361b39176665a49be539e598`.
Validation is 15 focused PASS, 685 full-discovery unittest PASS in 85.706 s
(maximum RSS 253,944 KiB, swap 0), Python byte-compilation, byte-identical
fresh publications, independent AArch64/QEMU and JSON safety checks, and
hostile review `PASS` with no P0-P2 findings. The durable review is
[EXP033_INTEGRATION_REVIEW_2026-08-26.md](EXP033_INTEGRATION_REVIEW_2026-08-26.md).

## Experiment 034 completed rationale

Experiment 034 was the highest-information target after 033 and is now
`COMPLETED` at artifact commit `d5d8046`. Its pinned tool proves the guarded
index, table base, five entries/four unique local targets and four CFG-complete
direct-edge substitutions. The composed bounded result is 71/71
`NO_TARGET_WITHIN_MODEL`; runtime equivalence, execution, current destination
and global writer/consumer absence remain `UNKNOWN`.

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

Historical Experiment 023 remains `WITHHELD/NO-GO` and unpromoted: its timing
order is not comparable to Experiment 014, physical-allocation PA provenance
is missing, and the full GF(2) matrix is non-unique. Its audit artifact is now
retained as merge-history evidence; raw evidence remains private. Repaired
Experiment 023R proves allocation-offset/model algebra while physical
PA24/rank/base attribution is only `SUPPORTED_WITHIN_MODEL` under its stated
contiguity and Experiment-014-relation assumptions.
