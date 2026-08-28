# SM8150 Architecture and Protection Map

This is a confidence map, not a completed block diagram.

```text
CPU virtual address
  -> ARMv8 MMU / stage-1 translation
  -> system physical address
  -> SM8150 interconnect path
  -> LLCC-facing / memory-controller-facing path
  -> observed XOR bank-selection relation (exact owner unknown)
  -> DDRSS memory controller + PHY
  -> LPDDR4X channel/rank/bank/row/column
```

`PROVED`: The exact downstream DT represents a path from `MASTER_LLCC` to
`SLAVE_EBI_CH0` and a distinct `SLAVE_CNOC_DDRSS` configuration endpoint.
Evidence: exact source `sm8150-bus.dtsi:1091-1098` and `:1573-1581`, SHA-256
`2f72785b42496ff21ade9bc2ee5bfc06253daaf6352e1caf2683d0d8a06f4c4d`.

`PROVED` as selected OSRC source evidence, not live-DTB identity: its
`sm8150.dtsi` supplies LLCC at `0x09200000 + 0x450000`, four bank offsets, and
broadcast offset `0x400000`. Evidence: `sm8150.dtsi:1971-1999`, SHA-256
`c0d42e66ddd5640e2dd7b65527c25fb617008d94a6a04062b9e1077f0eb63849`. The
live-DTB hash remains `UNKNOWN`.

`PROVED`: The Linux LLCC driver fields at offsets `0x21000 + 8*n`,
`0x21004 + 8*n`, `0x21f00`, and `0x21f04` configure cache slice allocation,
ways/capacity and activation. They are not source evidence for PA-to-DRAM
channel/bank selection. Evidence: `drivers/soc/qcom/llcc-slice.c:30-57` and
`:318-350`.

`PROVED`: DT exposes LLCC/DDR performance observation landmarks:
`0x090cc000` LLCC PMU, CPU-to-LLCC BWMON at `0x090b6400/0x090b6300`, and
LLCC-to-DDR BWMON at `0x090cd000`; the last path is labeled LLCC to EBI_CH0.
Evidence: `sm8150.dtsi:992-1059`.

`PROVED`: The AOP drivers visible to Linux only send DDR performance/frequency
messages (`{class: ddr, perfmode: on}` and 300 MHz on halt/poweroff). They do not
expose address-map programming. Evidence:
`drivers/soc/qcom/aop_ddrss_cmds.c:24-61` and
`drivers/soc/qcom/aop_ddr_msgs.c:24-60`.

`PROVED`: Exact live XBL owns DDR initialization/training and loads board-specific
DCB data, while exact live AOP contains the runtime DDR manager. Evidence:
Experiment 004 hashes and `research/live-firmware-static-recon.md`.

`PROVED`: XBL maps `MCCC_MCCC_MSTR` at `0x090b0000–0x090b0fff` as an
uncacheable `NS_DEVICE` during boot. This is a firmware-backed register landmark,
not yet a final-decode register identification or proof of post-boot EL1 access.

`PROVED`: Exact XBL's DDR remapper selects a row by channel/rank mask and total
MiB, constructs two physical-region records, and sends them to
`/dev/icbcfg/boot`. DAL property `icbcfg_info` resolves to four register bases:
`0x09248080`, `0x092c8080`, `0x09348080`, and `0x093c8080`. Exact topology
labels each containing window `qhs_llcc`; the layout-1 writer touches 32-bit
offsets `0x00..0x58` in each instance. Evidence:
`evidence/manifests/006-xbl-memory-pipeline-inventory.json` and
`research/xbl-shrm-icbcfg-recon.md`.

`PROVED` by Experiment 008: retained XBL records select exact DCB
`/6003_0200_1_dcb.bin` and report two 3072-MiB ranks. Mask `0x3` and total
6144 MiB uniquely choose remapper row 7, with destination bases `0x80000000`
and `0x140000000`. The writer encodes six 36-bit ranges, split into low32/high4
fields, brackets programming with disable/enable writes, and makes no distinct
lock-register write inside its exact bounded function.

`PROVED` by Experiment 011: the exact XBL Quest DDR failure reporter computes
its rank boundary as `0x80000000 + (ddr_size_gib << 29)`. Its preceding size
accumulator obtains 6 GiB for the retained topology, so the diagnostic boundary
is `0x140000000`, exactly row 7's rank-1 destination. Within a rank it labels:

```text
row=PAoff[31:16], bank=PAoff[15:13], channel=PAoff[10:9],
column=PAoff[12:11]||PAoff[8:1], byte=PAoff[0]
```

The bit partition is complete, non-overlapping, and invertible. `REFUTED`: this
bounded diagnostic formula itself contains an XOR/hash or admits two PAs for
one coordinate. It is a `PROVED` diagnostic model used by the real failure
path, but Experiment 014 `REFUTES` it as the complete silicon bank-selection
model.

`PROVED` live by Experiment 014, for rank-relative PA bits `0..23`: a
write-combine non-secure ION allocation at stable PA
`0xf0400000..0xf13fffff` exposes a three-dimensional XOR bank-selection row
space. One equivalent basis is:

```text
b0 = PA13 xor PA16 xor PA18 xor PA19 xor PA20 xor PA23
b1 = PA14 xor PA16 xor PA17 xor PA18 xor PA21 xor PA23
b2 = PA15 xor PA17 xor PA18 xor PA19 xor PA22
```

Four held-out kernel vectors and four one-bank-bit negatives have a 314
milli-tick p10/p90 non-overlap gap; same-row controls centre near zero. The
basis is defined only up to an invertible output-basis change and therefore
does not label physical BA pins. Experiment 030 later `REFUTED` the inference
that PA9/PA10 leaving the conflict class upward proves two independent channel
selectors: both saturate in complete spread phases, PA9 also saturates in
stride mode, and stride-mode PA10 is `INCOMPLETE`; their physical roles remain
`UNKNOWN`. Experiment 023R `PROVED` allocation-offset/model bit-24
contribution `0b110`; mapping it to physical PA24/rank/base is only
`SUPPORTED_WITHIN_MODEL` because pagemap is `BLIND`. Physical contributions
from PA25..31, exact block/register ownership, and complete-coordinate alias
behaviour remain `UNKNOWN`.

`PROVED`: selected DCB section 16 parses exactly into two base-token/offset-token
sets. The exact Xtensa SHRM helper at `0x2d8dc` computes
`(base_page << 12) + (offset_token << 2)` and stages one 32-bit word per
computed register. Both exact direct consumers pass direction zero, which is
the helper's read-to-snapshot path; selected lists contain 430 and 64 reads.
`SUPPORTED`: this is an SHRM controller-register snapshot inventory.
Verification 012 subsequently acquired the real file: set 0 has coherent
four-instance MC/MCCC structure, while set 1 is refuted as a coherent current
snapshot. Exact set-0 bitfield semantics and any indirect reverse-direction
invocation remain `UNKNOWN`.

`PROVED` by host-only Experiment 017: exact XBL contains a 122-entry u64 table
at `0x146b1218` / file `0x630b8`, with 30 four-instance MC groups and two
globals. All 12 `qhs_mc +0x400/+0x404/+0x4d0` candidates are covered; MCCC
`+0x118` and master `+0x294` are excluded from this table only. The exact
`0x54`-byte helper statically constructs zero-sentinel table-driven 32-bit
loads and conditional stores to distinct read-copy VA `0x146bf300`; its only
identified store bases are X12/X8, so this helper is not a candidate-register
programming path. The helper has no hard 122-entry cap. Runtime completion,
coherence/currentness, MMIO side effects/faults, mutable table contents,
indirect reachability and current-boot execution remain `UNKNOWN`. This is
independent static observation confidence, not semantic likelihood.

`PROVED` by host-only Experiment 018 Stage 1A: the exact XBL literal inventory
finds, for each of the 12 MC targets, one single 8-byte table encoding viewed
as both the one aligned u64 match and the overlapping one aligned u32 match at
the same file offset; these are two views of one entry, not independent stored
literals, and there is no separate target literal elsewhere. Only base `0x09260000`
has an aligned outside-table u32 literal (file `0x80154`, VA `0x148bc254`) and
that occurrence is in RWE; all base aligned-u64 counts are zero. The strict
STR W/X unsigned-immediate census finds 14 matching offsets (RX11/RWE3), with
seven RX candidates based on SP. Stage 1A performs no base/effective-address
resolution and makes no writer claim; its classification is
`STAGE1A_LITERAL_AND_STORE_OFFSET_CENSUS_WRITER_UNKNOWN`. Stage 2A is the
completed next host-only discriminator for only the four non-SP RX candidates;
its bounded result is recorded below.

`PROVED` by host-only Experiment 018 Stage 2A: exactly the four pinned non-SP
RX candidates were analyzed with a maximum 128-instruction same-block slice.
The only supported definitions are 64-bit MOVZ/MOVK and same-register
`ADRP Xn; ADD Xn,Xn,#imm`. The two long X8 sequences stop at the window limit;
the X8 sequence at `0x146a70c0` fails closed on LDR `0x146a70b4`; and the X19
sequence stops at a BL control boundary. No base or exact target resolves.
`REFUTED` only: the supported Stage 2A direct-definition path does not resolve
an exact target for these four stores. This does not prove writer absence;
seven SP candidates, three RWE candidates and all unsupported/dynamic paths
remain `UNKNOWN`.

`PROVED` by host-only Experiment 018 Stage 2B: the two Stage 2A window-limit
X8 candidates resolve through the pinned same-register W-wide-move chain within
512 predecessors. Both compute XBL virtual-address values `0x1489f400` and
`0x1489f4d0`, outside file-backed PT_LOADs and numerically outside the 12
targets. `REFUTED` only: numeric target equality in this W-wide-move model.
VA-to-PA translation/identity, physical destination/ownership, runtime
execution, writer identity and unsupported/dynamic paths remain `UNKNOWN`; no
writer absence is claimed.

`PROVED` by host-only Experiment 018 Stage 2C: the remaining non-SP RX X8
store at `0x146a70c0` has exactly one direct BL caller in file-backed executable
PT_LOADs. Its pinned wrapper and lookup success path derives X19 from X1,
selects a 16-byte retained-table row by ID, copies the matched `+8` pointer to
`[X19]`, and the writer loads X8 from `[X0]` before `STR W9,[X8,#0x400]`.
All 48 table-derived possible `+0x400` values miss the 12 targets. Because
descriptor `+0x20` eligibility is runtime-dependent, these are a possible-value
superset, not proof that every store executes. `REFUTED` only: numeric target
equality in this model; physical destination, runtime execution, indirect
callers, other X8 writers and writer identity outside this path remain
`UNKNOWN`.

`PROVED` by host-only Experiment 018 Stage 2D: the remaining X19 store has one
direct-BL caller and the caller supplies W0=0 on its pinned success edge. Exact
dispatch and `CBNZ W0,0x14935ce8` pins make the pre-MADD success result an
explicit runtime precondition. The callee constructs X23/X24 and MADD X19; the
initializer statically assigns import-slot value `0x1483c904`, and the
resolved target range has zero BL/BLR/BR transfers, one RET, and zero X19-X29
definitions under an exact instruction-class/write-set audit. Under explicit
normal-return and initialized-slot conditions, the computed effective value is
`0x85e9e970`, outside the file-backed portion of the RW PT_LOAD and numerically
outside the 12 targets. Runtime initialization, slot currentness, import
conformance, physical destination and indirect paths remain `UNKNOWN`; no
writer absence is claimed.

`PROVED` by host-only Experiment 018 Stage 2E: all seven RX SP-base STR W/X
candidates map to the exact F1/F2 functions, whose local `SUB SP` allocations,
frame updates and unique direct-BL callers are pinned. Each access lies within
its local allocation. The same-function immediate-control CFG (BL modeled as
fallthrough) has no recognized SP-write-class instruction after allocation on a
path to each candidate; unsupported instruction effects remain `UNKNOWN`.
The explicit memory-writeback audit accounts for four recognized sites per
function (two SP frame updates and two non-SP writebacks); recognized BR/BLR
counts are zero, and the all-file-backed-executable-PT_LOAD-words direct-entry
census finds one external BL to each function start and none to interiors.
Absolute runtime stack address, stack integrity, physical destination,
execution and writer identity remain `UNKNOWN`; the three RWE candidates are
outside this RX-only stage.

## Host-only DCB follow-up — Experiments 019–022

`PROVED` by Experiment 019, narrowly: the exact bounded DCB blocks contain
strict syntactic candidate address/offset-value pair arrays in absolute and
base-relative key domains. These are not proved register tables or consumers;
absolute keys do not reach ranked MC bases, and section/base semantics,
consumer identity, register meaning and writer identity remain `UNKNOWN`.
The bounded stored-word/exact-wide/ORR audit finds `0x00003333` and
`0x00300014` absent and two adjacent sequences for `0x00300033`; it does not
prove writer absence.

`PROVED` by Experiment 020, within its decoder model: the XBL contains 719
register-offset stores, but the narrow classifier has a pinned false negative
at `0x14868a50`. `SUPPORTED`: the largest RWE segment is only a candidate
segment selected by bounded size/content criteria. General six-byte walkers,
DCB consumers, runtime bases and writers remain `UNKNOWN`; a general
zero-walker conclusion is `REFUTED` by the pinned false negative.

`PROVED` by Experiment 021 for one pinned bounded-copy target: direct census is
seven `BL` and zero direct `B` edges; five calls have local labels for sections
`{0,1,2,15,16}`, and two are unlabelled. Other-section, indirect, other-copy
and global delivery remain `UNKNOWN`, not refuted. Only local label
completeness is `REFUTED`.

`PROVED` by Experiment 022: `430/470/122/492` are counts for two enumerated
retained-evidence channels, and their observed density is sparse. Completeness
of those channels is `REFUTED` by known `0x09248080`; implemented-register
coverage and the unenumerated address set remain `UNKNOWN`. These results do
not identify the final decode owner or advance Experiments 015/016, which
remain `NOT ELIGIBLE`.

The historical Experiment 023 artifact is retained as merge-history evidence
but remains `WITHHELD/NO-GO` and unpromoted. Its protocol is not comparable to
Experiment 014, physical-allocation PA provenance is missing, its full GF(2)
matrix is non-unique, and `PA24=b1^b2` is `SUPPORTED` only. Experiment 023R is
the separately repaired, model-scoped result. Experiment 024 is `COMPLETED` and
integrated as host-only, read-only static evidence. `PROVED`: its exact
`[0x148689a0,0x14868a64)` walker has six-byte records, the exact `0x8000`
terminator and `B.EQ` return-before-store, and a conditional 32-bit store of
the zero-extended byte; exactly three direct callers select five XBL-resident
table alternatives plus the selector-`0xf` zero-count/no-pointer path. The
selector unions contain 53 and 127 unique offsets, a 170-offset
cross-alternative syntactic superset, and 221 nonterminator records. The two
pinned design-source UFS blocks are byte-identical, and under initialized-base
retention all 170 symbolic destinations lie in the broader `ufshc` `ufs_phy`
resource. `SUPPORTED`: this is a table-driven positive control only under base
retention and store reach. Current base, selector/runtime execution,
reached-store subset, flag semantics, live-DTB equality, DCB semantic
alias/global consumer/writer, DDR/MC relation, GF(2), and alias/bypass remain
`UNKNOWN`; the mappings are conditional symbolic supersets, not current
destinations. Class C remains unchanged and Experiments 015/016 remain
`NOT ELIGIBLE`.

Experiment 025 is now `COMPLETED` and integrated from commit `d743150` (parent
`a68d2f1`). `PROVED`: the exact platform-query helper
`[0x1486abec,0x1486acac)` has caller `0x1486847c` with `X0=SP+0x10`, not main
context `X19`; it loads, addresses, and reloads slot `0x14890590`, and pins
semantic ID `0x02000139` via `MOVZ/MOVK`. The static seed
`X0=0x14875668`, outer record `X1=0x14875590` count five, descriptor
`0x14824ab8`, factory `0x1484a880`, constructed candidate `0x1488f418`, inline
vtable `0x14824ad0 + 0x48`, and callback `0x1484a9d4` form the pinned chain.
The bounded callback graph `a9d4->a730->a824->aa30->a854` has one recognized
output write at `0x1484a9f4` to helper `SP+0xc`; nested writes are only to
`0x1488f3f9`, `0x14890ba0`, and `0x14890b90`, with one decoded MMIO read at
`0x01fc8004` and zero recognized MMIO writes. The all-executable census and
pinned loop blocks are conservative recognized coverage, not arbitrary-write
absence. `SUPPORTED`: conditional intended binding can populate the slot and
the recognized callback flow does not write caller context `+8`. `UNKNOWN`:
runtime registration/order, slot/object identity, actual `BLR X9` target,
alternate BSS mutation/global aliases/unsupported writes, full `0x01d80000`
base currentness, and live mapping or authority. Experiment 024's UFS mapping
remains conditional; Class C and 015/016 eligibility are unchanged.

Experiment 026 is now `COMPLETED` and integrated from commit `0305a03` as
host-only, read-only static evidence. `PROVED`: registration helpers
`[0x1482ecb4,0x1482edac)`, initializer loop `[0x1482edac,0x1482f0b4)`, and
table header `[0x14875534,0x14875568)` pin the 24-byte node shape, list head
`0x14890f60`, count two, row start `0x14875538`, cursor `0x1487554c`, and
stride `0x18`. `PROVED`: bounded bootstrap, veneer, alternates, dispatcher,
and caller local/control/data edges include the dispatcher base/stride/index
guard and symbolic pointer escape `0x146b30c0 + runtime_index*0x3f8` for
modeled index `0..1`, not an exact runtime base. `SUPPORTED`: memory-only
initializer-pool shape `[0x146b30c0,0x146b38b0)`, two-row `0x3f8` geometry.
Pool contents and runtime values remain `UNKNOWN`.

The complementary census scans 847,465 executable words, excludes 622 words
covered by the Experiment 025 dependency, and recognizes 9 accesses (3
writes, 6 reads) plus 2 pointer escapes. It finds zero recognized access
intervals overlapping slot `[0x14890590,0x14890598)`. Its taxonomy is
`ORDER_OPEN` and `PROVED_BOUNDED_NO_RECOGNIZED_SLOT_MUTATION`; this is not
global writer absence. Runtime execution/order, slot value, object identity,
`BLR` target, base currentness, writer absence, and live authority remain
`UNKNOWN`. Validation is 25 focused and 581 full unittest PASS, Python
byte-compilation, JSON safety, byte-identical regeneration, mode `0644`, and
exact-XBL/final decoder hostile-review `PASS`, recorded in
[EXP026_INTEGRATION_REVIEW_2026-08-26.md](EXP026_INTEGRATION_REVIEW_2026-08-26.md).
Experiment 027 is now `COMPLETED` and integrated from commit `7aa1df7` as a
host-only, read-only bounded CFG/dataflow result. It analyzes 73 sites: 65 of
67 register-offset sites after two dependency-owned exclusions plus all 8
computed-address idioms (three complete loop contexts and five local forms).
The implemented census returns 71 `INDIRECT_OR_UNSUPPORTED`, 2
`NO_TARGET_WITHIN_MODEL`, zero `DCB_CONSUMER_PATH`, and zero
`MC_OR_SHRM_SYMBOLIC_TARGET`; the zero labels are bounded-model results, not
global absence claims. Two nonexclusive `SECTION_READER_PROXIMITY_ONLY`
hypotheses remain: `0x148aa758` is signed `-2528`/absolute `2528` from reader
`0x148ab138`, and `0x148ab4f8` is signed `960`/absolute `960` from the same
reader; threshold is `0x1000`, with `link_proof: NONE`. Runtime base/current
destination, execution, writer/global consumer identity, aliases, register
semantics, and unsupported paths remain `UNKNOWN`.

The public manifest is 334,847 bytes, mode `0644`, SHA-256
`d11785969f16ba09155a2305eefd091158abfc515bc64cf94cb34d573a302277`.
Validation is 35 focused and 616 full unittest PASS in 86.100 s, Python
byte-compilation, 67 public JSON manifests parsed, two fresh byte-identical
generations, public safety/no-clobber checks, and independent hostile review
`PASS` after fixes, recorded in
[EXP027_INTEGRATION_REVIEW_2026-08-26.md](EXP027_INTEGRATION_REVIEW_2026-08-26.md).
The candidate setter remains `[0x9fc06410,0x9fc0643c)` with caller
`0x9fc023f0`; DCB sections 6/7/8/10/11/12, loader/readers, and the 024
positive-control exclusions remain exact boundaries as recorded in the review.

Experiment 029 is `COMPLETED` and integrated from commit `a495bdc` as a
host-only, read-only unsupported-frontier inventory. It covers the exact 71
Experiment 027 fail-closed ranges and proves 1,992 range occurrences / 1,180
unique VAs, including a 352-occurrence / 219-unique-VA / 197-unique-word
frontier. Source provenance, reachability, and decoder safety remain
`UNKNOWN`/`NOT_CLAIMED`; its 17 focused / 633 full validation and final hostile
review `PASS` are recorded in the integration review.

Experiment 031 is `COMPLETED` and integrated from artifact commit `cd9f26e`
plus reconciliation repair `12a8ebe`. Its source-qualified scalar-plus-
dispatch v2 model selects 283 occurrences / 160 unique VAs / 148 unique
words, reaches 250 selected events, and retains 69 occurrences / 59 unique
VAs / 49 unique words across 20 sites. The combined model transitions 51 of
71 baseline sites to bounded `NO_TARGET_WITHIN_MODEL`; 20 remain
`INDIRECT_OR_UNSUPPORTED`. This is `V2_MODEL_ONLY` and `NO_ABSENCE_CLAIM`, not
scalar-only closure; no DCB consumer/MC/SHRM path is promoted. Class C and
015/016 eligibility remain unchanged.

The selected membership is 283 occurrences / 160 unique VAs / 148 unique
words, with 250 reached selected events and 33 selected-not-reached; family or
label mismatches and events outside the selected domain are zero. The separate
`DIRECT_CONTROL_DISPATCH_REPAIR` contributes 143 events across 62 sites, with
outcomes 48 no-target/14 fail-closed when present and 3/6 without it. The
residual 69 occurrences / 59 unique VAs / 49 unique words remains fail-closed.
The reconciled 031 public manifest is 1,327,118 bytes, mode `0644`, SHA-256
`51a187195c16eb609d337305540fc6d20a09297f5ab76b054497c5c58c3a2e86`; the
tool/test/README pins and validation are recorded in the integration review.

Experiment 032 is `COMPLETED` and integrated from artifact commit `d46c44c`
after docs commit `e063181`. It is a host-only, read-only, source-qualified
arithmetic extension of the exact 031 scalar-plus-dispatch model. The combined
selection is 298 occurrences / 175 unique VAs / 162 unique raw words, with
264 reached selected events and 34 selected-not-reached occurrences. The
arithmetic addition is 15 selected rows across seven sites and 14 reached
events (`MADD` 3, `UMADDL` 7, `EOR` 2, `BIC` 2). The model transitions 55 of
71 baseline sites to bounded `NO_TARGET_WITHIN_MODEL`; 16 remain
`INDIRECT_OR_UNSUPPORTED`. Relative to 031, sites 1, 36, 37, and 52
transition, with zero regressions. The residual is 54 occurrences / 44 unique
VAs / 35 unique raw words across 15 sites: `PAIR_MEMORY` 48,
`SIGN_EXTENDING_MEMORY` 2, and `SYSTEM_CONTROL` 4.

The inherited 031 canonical full-record equivalence is exact for 250 scalar
events, 143 direct-control events, and 23 taint-kill events. Qualified forms
are limited to modulo-width `MADD/UMADDL` plus shifted `EOR/BIC` and explicit
identity cases; pair/sign-extending memory, system/control, indirect aliases,
reserved encodings, and unknown forms remain fail-closed. Zero
`DCB_CONSUMER_PATH` and zero `MC_OR_SHRM_SYMBOLIC_TARGET` paths are promoted;
`current_destination` and `writer_absence` remain `UNKNOWN`. The source,
artifact pins, and validation are recorded in
[EXP032_INTEGRATION_REVIEW_2026-08-26.md](EXP032_INTEGRATION_REVIEW_2026-08-26.md).

Experiment 033 is now `COMPLETED` and integrated from artifact commit
`56b5ffa`. It is a host-only, read-only v4 extension of the exact 032 bounded
model. The complete 029 frontier is selected as 352 occurrences / 219 unique
VAs / 197 unique words; 308 events are reached and 44 selected occurrences
are not reached. The inherited 032 full-record equality is exact for 264
extension events, 143 direct-control events, and 23 taint-kill events. The 44
new residual events are `LDP` 38, `STP` 3, `LDRSW` 1, `LDRSB` 1, and
`DAIFClr` 1. The three `STP` instructions are represented by six explicit
lane observations.

`PROVED`: source-qualified `LDP W/X`, `LDP X` post-index, `STP W/X`,
`LDRSW X`, `LDRSB W`, and exact `DAIFClr #IRQ` forms are modeled with
fail-closed handling for pre-index/unseen pair modes, SIMD/FP pairs, LDPSW,
overlap/unpredictable forms, other system forms, indirect aliases, and
malformed words. The bounded site result is 70
`NO_TARGET_WITHIN_MODEL` and one `INDIRECT_OR_UNSUPPORTED` at site 35; no
bounded `DCB_CONSUMER_PATH` or `MC_OR_SHRM_SYMBOLIC_TARGET` path is promoted.
`UNKNOWN`: global writer identity/absence, current physical destination,
protected-memory semantics, and the runtime exception level or
`CheckDAIFAccess` result for `DAIFClr`. Class C remains unchanged and
Experiments 015/016 remain `NOT_ELIGIBLE`.

The checked public manifest is 2,017,356 bytes, mode `0644`, SHA-256
`606723e5125d661c800b167133f2a9b69a3b8d47361b39176665a49be539e598`.
Validation is 15 focused / 685 full unittest PASS, full maximum RSS
253,944 KiB with zero swap, byte-identical fresh publications, and an
independent hostile review `PASS` with no P0-P2 findings. The tool and focused
test pins are recorded in the integration review.

Experiment 034 is `COMPLETED`: its guarded five-entry table and four unique
local targets close site 35 to 71/71 `NO_TARGET_WITHIN_MODEL` inside the
bounded static model. Exact external parent `247b0e1` is also reconciled for
019A–023R/028/029A/030 after claim/provenance/phase repairs. Later
implementations through observed `c91f473` are not promoted wholesale; review
response `4b78b61` is preserved and V015/V016 are independently rebuilt. These
results do not identify the runtime transform owner or writer.

Verification 015 subsequently proves six exact condition-labelled numerical
classifications in allocation-offset/model coordinates. Four clean comparisons
share all 51 labels; the weak L762 condition retains two excursions and remains
`REPEAT_REQUIRED`/`all_invariant=false`, while six independently split repeat
groups have zero flips. This `SUPPORTED` stability across operator-reported
runtime/reboot/coldboot contexts does not prove transform immutability or a
data-path location.

Verification 016 extends the same bounded model to allocation-offset/model bits
25–27. The retained equal-contribution classes are bit25=`{14,21}`,
bit26=`{19}`, and bit27=`{13,20}`; both three-column passes independently retain
the same selector/cancellation verdicts, and a separate seven-row set agrees
with model-derived labels 7/7. This supports a rank-three folded selection model
but does not locate named controller coordinates. Pagemap remains `BLIND`;
physical PA identity, base/alignment and effective contiguity remain `UNKNOWN`.
Verification 017 applies the pinned relation to the exact protected carveouts
and explicitly unprotected System RAM fragments as an
allocation-offset/model-coordinate projection.  It proves an 8-KiB minimum
class-change span; a 64-KiB-aligned 64-KiB span covers all eight bank classes,
while 128 KiB is the arbitrary-base guarantee.  Finite GF(2) countermodels show
that the observed bank projection admits both injective and non-injective
complete-coordinate completions.  The narrow bank-only post-decode enforcement
shape is therefore `REFUTED` as a separator for those projected ranges.  The
result is a granularity exclusion only: actual protection ordering, complete
DRAM coordinates, transform mutability and protected reach remain `UNKNOWN`.

Verification 018 supplies a separate, allocation-local live baseline.  The exact
A90 V2321 runner pins the checked-in probe source, a byte-identical static
AArch64 binary and a build receipt before bridge contact, then allocates only
the non-secure `camera_preview` ION heap (type 10/id 30).  Two write-combine
virtual mappings of that one 256-MiB dma-buf pass the same-storage and
distinct-offset controls.  Across four fixed anchors, bits 6..27 and two
trials, all 176 candidate observations are `DISTINCT` with zero disturbance,
anchor clobbering or trial disagreement.  This is `PROVED` only as
`NO_ALIAS` over the retained one-state allocation-offset pairs.  Pagemap is
`BLIND`, so physical PA identity, effective contiguity, final DRAM coordinates,
cross-state permutation and any protected-boundary implication remain
`UNKNOWN`; it does not promote numbered Experiments 015 or 016.

Verification 019 adds a retained cross-state marker result.  Its host
analyzer's synthetic control detects injected address-line permutations and its
gate refuses a null without a pre-suspend baseline and corroborated suspend.
The original and an independent second retained receipt report 4,194,304 tags
unchanged across 25.090-second and 25.151-second deep suspends.  The bounded
result is `PROVED` for those exact receipts and `REFUTED` for a map change in
that tested transition and offset domain.  Physical contiguity, complete DRAM
coordinates, other state changes and global transform mutability remain
`UNKNOWN`; this does not close every form of reopen condition 3 or alter
`CLASS C`.

Verification 020 separately measures the non-secure contiguous-allocation
boundary relevant to PA28.  The attempted `camera_preview`, `qsecom` and
`user_contig` heaps are monotone at 320, 32 and 16 MiB respectively; no
attempted heap reaches the 512-MiB reopen threshold.  The old 256-MiB ceiling
and 512-MiB PA28 span wording are `REFUTED`.  Secure and remote-processor heaps
were enumerated but not allocated from, so their capacity is `UNKNOWN`.  A
later 020M live read-only receipt proves that heap 30 points to
`camera_mem_region` (`phandle=0x67a`) with advertised
`reg=<0,c2000000,0,14000000>` and explicit `ENOENT` for `no-map`/`reusable`;
actual allocation placement remains `UNKNOWN`.  This changes the cheapest
next normal-RAM test from a span-feasibility question to a PA28 alias question;
it does not change Class C or authorize protected-memory access.

The 1b known-aperture checkpoint then reconciles the retained access-control
evidence without changing device state.  Both selector branches enumerate the
same eight known qhs_llcc-remapper/BIMC addresses, and the exact 010 policy
hits for every candidate are TZ-owned with no HLOS read/write grant under both
`MEMNOC_MS_MPU` and `CNOC_SNOC_MS_MPU`.  The exact 009 narrow region covering
`0x09248080` is also branch-invariant.  The retained fixed EL1 load produced
no value and a `Non Secure Watchdog Bark`, while the control-node route failed
before a read; these observations do not prove the watchdog's precise cause.
This is `PROVED` only for the eight known static-policy candidates and
`SUPPORTED` as a constraint on their tested Normal-World route.  Global
reachability, alternate apertures, final runtime policy, ordering, mutability,
and bypass remain `UNKNOWN`; Class C and `NOT_ELIGIBLE` are unchanged.  See
`docs/VERIFICATION1B_REACHABILITY_REVIEW_2026-08-27.md` and the public
manifest with SHA-256
`b4135f22bff47df22cda674eeabfff909ef4d3bc2a1843b358be7556b6d5ff02`.

The Route-2 audit then revalidated the exact 027/029/030/031/032/033/034 public
manifests.  `SUPPORTED` bounded closure: no promoted DCB-consumer or MC/SHRM
symbolic target appears in the declared models, the 71-site identities and
transition counts are stable, and 030 inherits the validated rank-three
relation.  Q4 remains `UNKNOWN` because those manifests do not contain a
complete relation-row set; this audit does not establish global writer absence,
runtime execution, physical mapping or a security-boundary result.

Verification 020A then pinned the candidate setter
`[0x9fc06410,0x9fc0643c)` and its sole direct caller `0x9fc023f0`.  The setter
stores one zero and four incoming argument registers; the caller's bounded
linear block resolves those registers to fields of an opaque incoming `X0`
object at offsets `0x10`, `0x18`, `0x20` and `0x28`.  This is symbolic static
data flow only: object type/value/currentness, physical-to-DRAM mapping,
post-boot mutability and protected reach remain `UNKNOWN`.  It does not identify
the final controller writer or authorize a live mutation.

Verification 020B extends that edge by tracing the sole direct caller of the
consumer at `0x9fc023c8`.  The caller obtains an opaque token from
`BL 0x9fc160b8`, copies its fields into a stack object at `SP+0x20` (including
an exact `Q0` two-lane transfer), and passes that object to the consumer.  The
020A setter arguments are therefore symbolically `[return+0x0c]` (W3),
`[return+0x18]` (X0), `[return+0x20]` (X1), and `[return+0x28]` (X2).  The
return helper's runtime value/type/currentness, static-object semantics,
physical-to-DRAM destination, mutability/locking and protected reach remain
`UNKNOWN`; this is not a controller-writer or alias proof.  The result remains
`CLASS C (TRANSFORM ONLY)` and `NOT_ELIGIBLE`.

Verification 020C resolves the bounded source of that opaque token.  The exact
helper at `0x9fc160b8` is `ADRP X0,0x9fc36000; ADD X0,#0x2c0; RET`, so its
static ELF return address is `0x9fc362c0`; the executable census finds direct
callers at `0x9fc22cc0` and `0x9fc26e2c`.  The object-field bytes needed by
020B are retained by hash only.  This does not promote the static address to a
runtime pointer/physical or DRAM destination, and object semantics, writer or
mutability state, protected reach and alias/bypass remain `UNKNOWN`.  The
second caller is the next bounded discriminator.

Verification 020D then traced that second caller at `0x9fc26e2c`.  It loads
object fields `+0x28`, `+0x30`, `+0x38`, `+0x0c`, `+0x18` and `+0x20`, and
stores their symbolic origins to static ELF slots `0x9fc3e138`,
`0x9fc3e140`, `0x9fc3e148`, `0x9fc3e150`, `0x9fc3e158` and `0x9fc3e160`.
These are static code/data edges only; slot values, runtime currentness,
mutability, physical-to-DRAM destination, protected reach and alias/bypass
remain `UNKNOWN`.  The next discriminator is a bounded census of those slots'
other consumers and writers.

Verification 020E completed that bounded census without promoting static VAs to
runtime state.  In the exact XBL it recognizes 18 unique direct scalar
accesses to the six slots (6 stores and 12 loads).  Caller-saved direct `BL`
windows are barriers; continuation across X19–X29 is conditional on an
explicit AAPCS64 callee-saved assumption.  Ninety-five barriers are retained
(8 caller-saved calls and 87 unknown instructions).  Global writer/consumer
absence, ABI compliance, runtime execution/currentness/values, slot semantics,
physical-to-DRAM identity, mutability, protected reach and alias/bypass remain
`UNKNOWN`; Class C is unchanged.  The next discriminator is a bounded load-use
trace over the twelve recognized loads.

Verification 020F then followed each of the twelve 020E load destinations for
16 instructions in the same executable segment.  It found 16 recognized use
events (10 address-base, 2 arithmetic, 2 register-offset, 1 register-copy,
and 1 return) and 11 barriers (4 caller-saved `BL`, 5 recognized control, 2
unknown), with no tainted direct store reached in the bounded windows.  This
is static value-flow evidence only; global consumers/writers, runtime values
and currentness, ABI compliance, slot semantics, physical-to-DRAM identity,
mutability, protected reach and alias/bypass remain `UNKNOWN`.  The next
discriminator is bounded pointer/object resolution for the address-use events.

Verification 020G then re-decoded exactly those 020F address-use events.  The
bounded result has 12 witnesses: 10 immediate object-field-shaped accesses
(7 `LDR`, 3 `STR`) and 2 `UXTX` register-offset array-element-shaped loads,
occupying 11 unique access VAs with one duplicate witness.  This is
instruction-shape evidence only; runtime base values/currentness, object
semantics, global writer/consumer absence, MMIO/physical/DRAM identity,
mutability, protected reach and alias/bypass remain `UNKNOWN`.  Class C and
`NOT_ELIGIBLE` remain unchanged, and no device action occurred.  The next
discriminator is a bounded static-slot function-role/base-origin trace (020H).
The sanitized manifest is 7,218 bytes, mode `0644`, SHA-256
`f534efeee1e12f18d3af40c107dbc6fbe938eae16d9013aa088d22d7c880af3e`; focused
tests are 10/10 and the full serial suite is 1,205/1,205 PASS (`skipped=1`) in
134.596 seconds, maximum RSS 347,740 KiB, zero swap.

Verification 020H then grouped the exact 020G address-use witnesses into 11
unique access VAs and 7 bounded return/direct-branch-delimited local blocks.
Nine blocks contain unsupported forms and remain
`UNKNOWN_ROLE_UNSUPPORTED_FORM`; two are `LOCAL_READ_SHAPED_BLOCK`.  Ten unique
bases trace to `STATIC_SLOT_SEED` definitions;
the indexed access at `0x9fc26ea0` is `ARITHMETIC_DERIVED` from a bounded
`MADD`.  These are static role/provenance labels only; true function
boundaries, runtime values/currentness/execution, indirect effects,
MMIO/physical/DRAM identity, mutability, protected reach and alias/bypass
remain `UNKNOWN`.  Class C and `NOT_ELIGIBLE` remain unchanged, and no device
action occurred.  The manifest is 19,314 bytes, mode `0644`, SHA-256
`b306ca67675430314289fd79faa2e53b2d67994807d0b08bd91ced9b625faba2`; focused
tests are 11/11 and the full serial suite is 1,216/1,216 PASS (`skipped=1`) in
140.860 seconds, maximum RSS 349,728 KiB, zero swap.  The next discriminator
is a bounded caller-context/entry-role trace (020I).

Verification 020I then checked 20 exact direct-BL source/target edges from the
020H block-entry census and traced at most 16 preceding instructions per source.
Twelve windows stop on unsupported forms, six remain `ARGUMENT_OR_UNKNOWN`,
and two are `ARGUMENT_COPY_OR_CONSTANT`; static-slot-origin evidence is not
reached in the bounded caller windows.  This is not a true-function or global
writer/consumer proof.  Runtime execution/currentness/values, indirect
effects, MMIO/physical/DRAM identity, mutability, protected reach and
alias/bypass remain `UNKNOWN`.  Class C and `NOT_ELIGIBLE` remain unchanged,
and no device action occurred.  The manifest is 12,472 bytes, mode `0644`,
SHA-256 `03c463f667142a21641264ec2e4080d9d5f963c67776037ca9d6194a8a621608`;
focused tests are 11/11 and the full serial suite is 1,227/1,227 PASS
(`skipped=1`) in 151.571 seconds, maximum RSS 356,228 KiB, zero swap.  The
next discriminator is a bounded caller-context barrier/opcode inventory (020J).

Verification 020J then re-derived the exact 12 unsupported 020I stops and
inspected only each first stop word.  All 12 stop VAs are unique and classify
as `B_COND` 5, `CBZ_CBNZ` 2, `LDP_STP_PAIR` 2, logical-immediate 2 and
`BITFIELD` 1 (`BFXIL`); no stop requires the `UNKNOWN_OPCODE` fallback.  This
does not extend the caller trace or identify true functions, runtime values,
MMIO/physical/DRAM identity, ownership or a bypass.  Class C and
`NOT_ELIGIBLE` remain unchanged.  The public manifest is 7,657 bytes, mode
`0644`, SHA-256
`1fdb1f4ade702fdb2d6ffdc68669a9710c8152e225f89f02fb65c0d10f4c3d55`;
focused tests are 7/7 and the full serial suite is 1,234/1,234 PASS
(`skipped=1`) in 164.114 seconds, maximum RSS 355,764 KiB, zero swap.  The
next bounded result is recorded below.

Verification 020K decodes only the first word at each of those 12 stops.  The
exact family split is preserved; the five conditional branches and two compare
branches have aligned targets inside their source executable segment, the two
pair words are scalar 64-bit `STP` with `+64` offset and `-16` pre-index
offset, the two logical-immediate words are identical 32-bit forms, and the
bitfield word is the 32-bit `BFXIL` alias.  The local 020K loader independently
pins the XBL rather than inheriting another experiment's constants.  This is
bounded operand/target metadata only: instruction effects, true-function and
runtime semantics, physical/DRAM identity, mutability, protected reach and
alias/bypass remain `UNKNOWN`; Class C and `NOT_ELIGIBLE` are unchanged.  The
public manifest is 9,961 bytes, mode `0644`, SHA-256
`90a0cf4d264c64d0d2836b567a2dc8ac5abff7809be839e5131fc7e91e32975a`;
focused tests are 13/13 and the full serial suite is 1,288/1,288 PASS
(`skipped=1`) in 180.173 seconds, maximum RSS 363,772 KiB, zero swap.  An
independent hostile review is `PASS` after the local-pin repair; no device
action occurred.  The next discriminator is 020L, a one-word census of the
unique conditional branch landing VAs, still host-only/read-only and without
path continuation.

Verification 020L then inspected exactly one word at each of the seven unique
conditional landing VAs emitted by 020K.  The strict family split is ADRP x2,
LDR_UNSIGNED x1, logical-immediate x2, MOV_REGISTER x1 and scalar LDP x1;
the landing-word reader rejects unaligned VAs before reading and requires the
same executable file-backed segment.  Raw words are hash-only and no target
block is followed.  This is finite instruction metadata only: execution,
function boundaries, runtime values, pointer/PA meaning, MMIO/DRAM identity,
mutability, protected reach and bypass remain `UNKNOWN`; Class C and
`NOT_ELIGIBLE` are unchanged.  The manifest is 5,109 bytes, SHA-256
`cdb0db05596ad06ae179861a4083e08b116ce283f683dd5fae44efde020f85dc`;
focused tests are 7/7 PASS and the hostile review is `PASS`.

Verification 020M supplies the live precondition for a PA28 normal-RAM test.
The exact runtime receipt binds heap 30 (`reg=0x1e`) to `memory-region=0x67a`
and to `camera_mem_region` with matching phandle and advertised
`reg=<0,c2000000,0,14000000>`.  `no-map` and `reusable` return expected
`ENOENT`, while `ion,recyclable` is present.  This proves the advertised DT
chain only; actual allocation placement, complete DRAM coordinates, `f(PA28)`
and mutability remain `UNKNOWN`.  The public manifest is 8,246 bytes,
SHA-256 `69b087bd5a6aa279fff9c943405b46491381f3461c5ea1ac57f4d2f287d8ad9a`,
and no controller or protected-memory action occurred.

Verification 021 adds a retained receipt-level extent observation: a 320 MiB
`camera_preview` hold made all five residual probes, including 4 KiB, fail, and
the same controls recovered after release.  Same-run target/bridge/argv/health
are `UNKNOWN_UNRETAINED`; the conditional span is only
`SUPPORTED_CONDITIONAL_ON_020M_CHAIN`.  Verification 020N is a host-only fixed
normal-RAM PA28 timing design bound to the 020M/021 manifests.  Both leave
physical page identity, complete DRAM coordinates, transform mutability,
protection ordering and bypass `UNKNOWN`; Class C is unchanged.

Verification 022 reduces the retained PA28 existence/identification receipts
with strict phase and arithmetic gates.  All 3,029 pair rows recheck, both
same-phase controls fire, and exactly one rank-3 candidate conflicts, yielding
`f(PA28) = 010 = f(PA14)` as a `SUPPORTED_WITHIN_RETAINED_RECEIPT` model
extension.  The historical same-run target/bridge/argv/timestamp/final-health
and binary provenance are `UNKNOWN_UNRETAINED`; the repaired fixed-gate source
was not rerun.  This is not a physical alias or controller-writability result:
complete coordinates, transform mutability, protection ordering and bypass
remain `UNKNOWN`, and Class C/`NOT_ELIGIBLE` are unchanged.  The public
manifest is 6,698 bytes, SHA-256
`f583bd4f4fe30ad4822832e708edd87e2e049333f2a6c0cf014467b5a33bc2d2`.

Verification 022R repeats that model question with a provenance-complete exact
A90 acquisition. Both leading and trailing control brackets produce threshold
`369` and uniquely classify `0x10004000` as conflict; 1,787 accepted pair rows
and their address/XOR arithmetic independently recheck. This `SUPPORTED`
same-run result extends the recovered relation to
`f(PA28)=010=f(PA14)`. It identifies a bank-selection relation, not a storage
alias or full physical-to-DRAM map: physical-page identity, row/channel/rank/
column coordinates, transform mutability, post-transform enforcement,
protected reach and bypass remain `UNKNOWN`. Exact cleanup and final V2321
health are `PROVED`; no controller or protected-memory action occurred.

`PROVED` by Experiment 013: both exact TZ policy branches place the complete
snapshot workspace `0x09065100..0x09065fff` inside
`DC_NOC_NON_BROADCAST_MPU`, `MEMNOC_MS_MPU`, and `CNOC_SNOC_MS_MPU` regions.
All six matches are enabled/TZ-owned and exclude the comparative HLOS VMID for
both read and write. Runtime activation is `SUPPORTED`; final policy-register
readback remains `UNKNOWN`.

`PROVED` live: a purpose-built fixed control mapped/unmapped SHRM snapshot word
`0x0906566c` and returned `0xc071`. Its paired body differed by one instruction
and issued one `LDR W`; it returned no value and retained log records
`Non Secure Watchdog Bark` plus `TZBSP_ERR_FATAL_NON_SECURE_WDT`. V2321 was
restored and passed final health. `SUPPORTED`: the load caused a protected
fabric stall and XPU policy explains it. A decoded XPU syndrome is absent, so
the causal root remains below `PROVED`.

`PROVED` by Verification 024: DMID does not make the separate exact remapper
aperture at `0x09248080` usable through the tested Normal-World EL1 path. The
same-state map/unmap-only control returned `0xc071`; the paired read boot was
re-attested as `6fe92825…`, dispatched one fixed 32-bit load, emitted no END or
`A90R`, and disconnected USB. The one-shot retained log contains one ordered
set of watchdog bark `97.880454`, last pet `86.880167`, MID debug,
`Non Secure Watchdog Bark`, and `TZBSP_ERR_FATAL_NON_SECURE_WDT`, a
`11.000287`-second bark interval. The first host `INCIDENT` label was a parser
false negative for the real `msm_watchdog:78` printk prefix and is reclassified
from the immutable raw log. `SUPPORTED`: the load, not mapping alone, caused a
protected-fabric stall. Exact enforcement block/order and other possible
apertures remain `UNKNOWN`; this is not global writer or reachability closure.
V2321, stable LOW, `panic_on_oops=1`, temporary-path absence, and self-test
`11/1/0/12` are subsequently restored and `PROVED`.

`PROVED` by Verification 002: exact XBL independently contains and consumes a
26-record crash/download raw-dump catalog. Record 19 covers
`0x09060000..0x0906ffff` as `SHRM_MEM.BIN`, including the entire section-16
workspace and both snapshot destinations. The AArch64 loop at `0x14917ca8`
loads each `{base,size,description,filename}` record and calls registrar
`0x14917670`; its pinned call chain begins in the dload path. `SUPPORTED`: this
is a post-reset bootloader diagnostic path, not a normal HLOS runtime mapping.
Verification 005 later proved the exact outer/inner gates, and Verification 012
proved successful retail extraction through Samsung Upload. This remains a
post-reset diagnostic path, not a normal HLOS runtime mapping.

`PROVED` live by Verifications 003/004: exact V2321 exposes
`debug_level=0x4f4c` (`LOW`), `force_upload=0`, A90 source-backed
`msm_poweroff.download_mode=1`, `panic=-1`, and `panic_on_warn=0`. The newer
S22+ `qcom_dload_mode` and ramoops `max_reason` paths are absent. Exact A90
source and live config explain both differences: `msm-poweroff.c` owns the
dload module parameter, `CONFIG_QCOM_DLOAD_MODE=y`, and
`CONFIG_QCOM_MINIDUMP=n`. `REFUTED`: all initial observable dump-entry signals
were positive; debug and force-upload were negative. No reset was attempted in
those two eligibility passes.
Later bounded verification captured FMM as unlocked, changed only debug
LOW→MID, and used one panic trigger.

`PROVED` live by Verification 012: host journal records
`04e8:685d / MSM_UPLOAD`; the qdl 05c6 collector captured nothing. One exact
64-KiB `SHRM_MEM.BIN` passed the workspace header and 494-word plan. The staged
inventory still excludes all four remapper controls at `+0x8080`. The final
partition was restored and a new LOW boot passed health.

`PROVED`: bounded set-0 MC/MCCC/DDRSS numeric words are now available from the
post-reset snapshot. `UNKNOWN`: their exact bitfield meanings, the remapper
control words, runtime per-channel source bases, and the rank-interleave mask.

`PROVED` by the Experiment-014 exact-firmware audit: none of the seven non-zero
linear combinations of the recovered bank rows appears anywhere in the real
SHRM snapshot or as an aligned u32 in the nine captured firmware images. Four
apparent TZ byte matches are misaligned pieces of monotonic u64 address tables.
`REFUTED`: those substring hits directly attribute the bank hash to TZ data.
Encoded/computed forms remain `UNKNOWN`.

`SUPPORTED`: This four-instance block owns system-PA region placement/remapping
during DDR bring-up. A finer bank hash now exists as a `PROVED` behavioral
relation; whether the remapper also owns it or it occurs later in MCCC/MC logic
is `UNKNOWN`.

`PROVED`: Experiment 007's verified generic-REPL call to `__ioremap` returned a
mapping for the first fixed range, then the device produced a non-secure
watchdog before the intended `msm_readl`. This retires that callback-context
adapter and establishes no register value. Experiment 009 separately makes an
XPU denial `SUPPORTED`, not causally `PROVED`.

`PROVED`: The exact live TrustZone ELF contains the same `/dev/icbcfg/boot`
device hash and the same four-base/six-slot layout record. `SUPPORTED`: secure
firmware has configuration knowledge for this remapper. Runtime invocation,
lock ownership and enforcement ordering remain `UNKNOWN`.

`PROVED` by Experiment 008: primary TZ registry records bind `BIMC_MPU0..3` to
`0x0924e000`, `0x092ce000`, `0x0934e000`, and `0x093ce000`. Thus each
remapper at `qhs_llcc + 0x8080` has a named BIMC MPU configuration block in the
same 64-KiB instance at `+0xe000`. `UNKNOWN`: whether it mediates the remapper
configuration aperture, downstream traffic, or both.

`PROVED` by Experiment 009: the primary TZ resource table has 48 records and is
consumed by the pinned HAL lookup at `0x1c0fc890..0x1c0fca1c`. Both possible
embedded policy lists contain a `DC_NOC_BROADCAST_MPU` descriptor at
`0x090e0000` and the identical enabled/TZ-owned region 11:

```text
0x09248000 <= system PA < 0x09249000
read_vmid  = 0x80000000
write_vmid = 0x00000000
```

This includes the failed EL1 load at `0x09248080`. The exact MPU conversion
routine produces zero standard VMID permission words and client-permission
bytes `0x11/0x08`: TZ-owner read/write plus MSA-class read-only, with no HLOS
VMID grant. Exact devcfg sets `/ac/xpu:disable_xpu_ac = 0`.

`SUPPORTED`: the load was blocked by `DC_NOC_BROADCAST_MPU` or its downstream
fabric response. `UNKNOWN`: final runtime XPU register readback and a decoded
syndrome. The retained collector's encrypted/unparsed TZ payload prevents a
causal `PROVED` label.

`PROVED`: TZ's global XPU error map routes `DC_NOC_BROADCAST_MPU` to bank 0 bit
29 and routes `BIMC_MPU0..3` to bits 25..28. `PROVED`: neither embedded static
policy list directly contains BIMC_MPU0..3.

`PROVED` by Experiment 010: a separate TZ memory-assignment fallback supplies
the missing dynamic initializer chain:

```text
SMC 0x02000c16 -> assignment core -> memory lock
  -> BIMC topology fanout -> MPU reconfigure
  -> BIMC_MPU0..3 (+ LLCC_BROADCAST_MPU on some topology branches)
```

This dynamic chain is distinct from exact QHEE's same-ID HLOS intercept.
QHEE validates ownership and calls its local stage-2/SMMU access-control
wrapper; that bounded handler neither directly calls the generic TZ SMC wrapper
nor the TZ BIMC routines. `SUPPORTED`: the QHEE intercept is the production
HLOS path; exact runtime dispatcher precedence remains below `PROVED`.

`PROVED`: TZ SMC `0x02000c23` exposes an XPU toggle, but its disable allowlist
count is exactly zero. The enable branch accepts only a base resolved through
the registered-XPU table and invokes HAL restore. This is not an arbitrary EL1
XPU writer or usable disable primitive.

`PROVED`: both exact policy branches cover all four remapper addresses and all
four BIMC configuration bases with TZ-owned `MEMNOC_MS_MPU` region 0
(`0x00000000–0x10000000`) and `CNOC_SNOC_MS_MPU` region 5
(`0x09000000–0x09800000`). Neither grants the ordinary HLOS VMID. Effective
runtime denial is `SUPPORTED`; final hardware readback remains `UNKNOWN`.

`SUPPORTED`: four successful retained boots register LLCC PMU and LLCC-to-DDR
monitoring paths, disfavoring a broad whole-fabric-off explanation. Separate
clock/power/security treatment of `+0x8080` remains `UNKNOWN`. The retained
XPU diagnostic was encrypted or unparsed, so no decoded violation can be used
either for or against an XPU-denial hypothesis.

`REFUTED`: Downstream `mc_virt-base = 0x09680000` is by itself an exact DDR
controller-register identification. In this tree the `fab_mc_virt` fabric uses
`bypass-qos-prg`, and upstream review describes `*_virt` register ranges as
arbitrary/unused by the interconnect driver. Evidence: `sm8150-bus.dtsi:15-35`,
`:452-461`; upstream discussion:
<https://lkml.iu.edu/hypermail/linux/kernel/2007.3/04458.html>.

## Protection pipeline

`PROVED`: Exact kernel `hyp_assign_phys()` turns the caller's physical base and
size into a scatter-gather entry and sends source VMIDs, destination VMIDs and
permissions through `hyp_assign_table()` to SCM service `MP`, command `0x16`.
Evidence: exact `drivers/soc/qcom/secure_buffer.c:227-269,279-385`, SHA-256
`c8cf938407ef3f54b688eb451742ccec7458259704a68b2b3e87ad699df8ed5f`.

`PROVED`: The kernel-side ownership API therefore names system physical ranges,
not DRAM row/bank coordinates.

`PROVED`: exact QHEE's HLOS `hyp_assign` intercept enforces ownership through
its local access-control/stage-2/SMMU mapping path. `PROVED`: exact TZ has a
separate same-ID fallback whose memory-lock path programs dynamic BIMC MPU
policy. Separately, `PROVED`: `DC_NOC_BROADCAST_MPU` statically protects the
tested remapper configuration PA. `UNKNOWN`: whether memory data-path checks
see an address before or after final DDR address decoding, and whether a second
XPU/MPU check exists after a mutable transform. These ordering claims do not
follow from the SCM call signature or from configuration-aperture coverage.

`PROVED`: Exact source initializes RKP with physical/virtual kernel metadata and
invokes `uh_call(UH_APP_RKP, RKP_START, ...)`; `uh_call` reaches `smc #0`.
Evidence: `init/main.c:701-728,849-854`, `include/linux/rkp.h`,
`include/linux/uh.h`, and `arch/arm64/kernel/uh_entry.S`; exact `init/main.c`
SHA-256 `814d9dafdc49b73ae4fe5d5625a1a1c205b75a915889118761cd0a2aa6650409`.

`PROVED`: Exact defconfig retains `CONFIG_UH_RKP`, `CONFIG_RKP_KDP`,
`CONFIG_RKP_NS_PROT`, `CONFIG_RKP_DMAP_PROT`, `CONFIG_RKP_CFP_JOPP`, and
`CONFIG_RKP_CFP_ROPP`. Evidence:
`arch/arm64/configs/r3q_kor_single_defconfig:656-671`, SHA-256
`3d90a83d61a7a1873249642f7657c572e06f91a61bc3e5b737758f08ec765216`.

`PROVED`: Independently extracted stock kallsyms and exact rebuild System.map
both contain `uh_call`, `rkp_init_ns`, `hyp_assign_table`, `hyp_assign_phys`,
`qcom_scm_assign_mem`, `rkp_init_data`, and 31 CFP/JOPP/ROPP symbol matches.
Hashes: stock map
`9e6a1d6f322344e3d6fced7e6d29a254e1516cc5163bad8595388a9d0d02ec3a`;
rebuild map
`573d61f1d6fcefbe3f9b0b1ccb88dad92eeddbb449ad45baa26c22233c25bf74`.

`REFUTED`: The self-built kernel disabled all RKP/QHEE paths. The exact config,
source callsite and two symbol maps contradict that claim.

`PROVED`: The live `hyp` partition is the QHEE/hypervisor image: its ELF load
address and entry fall inside live `hyp_mem`, and its code/data identify the
hypervisor, ownership and kernel-protection paths.

`PROVED`: The live TrustZone image consumes a registry binding BIMC, MEMNOC,
LLCC-broadcast, DC_NOC and SHRM MPUs to exact configuration bases. Its static
DC_NOC policy covers the tested PA and grants no HLOS access; its dynamic
memory-lock path reconfigures BIMC_MPU0..3. BIMC-MPU final runtime values and
all protection ordering relative to DRAM decode remain `UNKNOWN`.

## Answers required for a bypass determination

| Question | Current answer |
|---|---|
| Which block owns the final mapping? | `PROVED`: qhs_llcc ICB windows own boot region remapping; live timing proves a distinct low-24 XOR bank-selection relation. MCCC/MC/DDRSS token families are exact candidates; final hardware decode owner remains `UNKNOWN`. |
| Who programs it? | `PROVED`: XBL programs the region remapper through `icbcfg` and copies section 16 to SHRM. `PROVED`: the exact SHRM section-16 consumers read listed controller words into a read-copy buffer; the observed section-16 paths do not write those addresses. Experiment 017 independently proves the exact XBL helper's store-base dataflow does not program candidate registers. Experiment 018 Stage 1A adds only literal/offset census evidence, Stage 2A refutes only its supported direct-definition path for four RX candidates, Stage 2B refutes only numeric target equality for two W-wide-move-resolved values, Stage 2C refutes only numeric target equality for a 48-row possible-value superset, and Stage 2D refutes only numeric target equality under explicit preservation/slot conditions; none proves writer absence or physical destination. Experiments 019–022 add only syntactic pair arrays, a bounded register-offset census with a false-negative control, one bounded-copy direct-edge census, and two-channel sparse density. Their consumer/base/writer boundaries remain `UNKNOWN`; 021 other-section/global delivery is not refuted and 022 channel completeness is `REFUTED`. AOP runtime DDR management is `PROVED`; final-decode writer remains `UNKNOWN`. |
| At what stage? | Region-remap programming during XBL DDR initialization before HLOS is `PROVED`; later mutability remains `UNKNOWN`. |
| Can EL1 observe it? | `PROVED` behaviorally: non-secure ION/CNTVCT timing exposes the low-24 bank-equivalence relation. Direct register routes remain `REFUTED`: `/dev/mem` is absent and the fixed protected load returned no value. After reset, Samsung Upload exports coherent set-0 words, but is not an EL1 runtime interface and omits remapper controls. Experiment 017 adds host-only static XBL read-copy evidence, not current-boot EL1 observability. |
| Can EL1 modify it? | No mutation is proved. The exact HLOS-visible XPU-disable allowlist has zero entries, and all known configuration apertures have branch-invariant TZ-owned coverage. Final runtime policy/lock readback is `UNKNOWN`. |
| Does EL2/EL3 lock it? | `PROVED`: QHEE applies ownership/stage-2/SMMU enforcement and TZ dynamically programs BIMC policies. `UNKNOWN`: final hardware write-disable bit and exact dispatcher/lock ordering. |
| Is there a post-transform security check? | `UNKNOWN`; the diagnostic coordinate formula and configuration-aperture coverage do not locate the data-path check. Dynamic BIMC MPU policy makes a later check plausible but does not place it relative to hidden/final decode. |
