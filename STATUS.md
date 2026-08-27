# Initial Reconnaissance Status — 2026-08-25

Current research state: `NO_BOUNDARY_BYPASS_OBSERVED`

Current class: `CLASS C (TRANSFORM ONLY) — live normal-RAM timing proves a
hidden low-24-bit physical-region XOR bank-selection relation, and retained
allocation-offset/model evidence extends the same rank-three shape through
model bit 27; direct EL1 controller/SHRM reads remain blocked; no transform
write, complete-coordinate alias, protection-order mismatch, or boundary bypass
has been observed`

Platform provenance: the A90 runtime, ACM bridge, REPL primitive, TWRP
code-boot and boot-prefix rollback used throughout are supplied by the upstream
`android-native-init-lab` project; see the Upstream section of `README.md`.
This derived project runs under a single binding constraint — anything that
cannot permanently brick the device may proceed quickly — so bootloader-class
partitions, fuses, RPMB and the partition table stay forbidden while volatile
controller writes do not.

Device mutation: Experiment 007 temporarily wrote the exact boot-only REPL,
fixed no-load control, and fixed one-load read candidates. Each transition was
bounded to the boot partition and verified by a 60,882,944-byte readback.
V2321 is restored and healthy. The experiment made no memory-controller,
MMIO, SCM, EL2, EL3, or protected-memory write; it attempted one fixed 32-bit
MMIO load.
Experiment 004 created and removed fixed temporary block-device nodes under
`/dev`; Experiment 005 created and removed one fixed temporary character node.
Experiments 008, 009, 010, 011, 012, Experiment 013 preparation, and
Verifications 001–002 were
entirely host-only. Experiment 013 then wrote exact control/read boot candidates
and V2321 rollbacks with full-prefix readback. It performed no controller,
memory, SCM, EL2, EL3, or protected-memory write and attempted one fixed
32-bit SHRM load. V2321 is restored and healthy.
Verifications 006–014 additionally captured the complete `param` partition,
changed only its four-byte debug field LOW→MID, dispatched one SysRq panic,
collected only `SHRM_MEM.BIN`, restored the original full partition hash, and
proved a subsequent LOW boot with selftest `fail=0`. Force-upload, FMM, and dump
sink remained zero. No controller, XPU, SMMU, SCM, EL2, EL3, firmware, GPT,
RPMB, QFPROM, or protected-memory write occurred.
Experiment 014 used only non-secure ION `user_contig` RAM and temporary files
below `/tmp/a90-native`. The temporary character node and probe were removed;
the final exact-target receipt reports V2321 `0.9.285`, selftest `fail=0`, and
battery 100%. No partition or hardware-control register was written.

Host-only Experiment 017 then cross-referenced the exact XBL MC address table
and helper read-copy path. It made no device, SMC or MMIO access and does not
satisfy reserved/`NOT ELIGIBLE` Experiments 015 (normal-RAM alias) or 016
(protected-boundary reach).

Host-only Experiment 018 Stage 1A now inventories exact XBL literals and a
strict STR W/X store-offset census for the 12 ranked MC targets. The exact
file-backed PT_LOAD census is RX4/RWE2/RW3, with 6945/5169 recognized forms
and 14 matching offsets (RX11, RWE3; seven RX candidates are SP-based). Each
target's single 8-byte table encoding yields both the one aligned u64 match
and the overlapping one aligned u32 match at the same file offset; these are
two views of one table entry, not independent stored literals, and there is no
separate target literal elsewhere. Only base `0x09260000` has an aligned u32
outside it, at file `0x80154` / VA `0x148bc254` in RWE. Stage 1A performs no
base/effective-address resolution, so its hit count is `null`, not zero, and
makes no writer claim. Experiments 015 and 016 remain reserved and `NOT
ELIGIBLE`.

Stage 2A now analyzes only the four non-SP RX candidates with a maximum 128-
instruction same-block direct-definition slice. It supports only 64-bit
`MOVZ/MOVK` and same-register `ADRP Xn; ADD Xn,Xn,#imm`, and fails closed at
branches, calls, returns, inbound block entries, boundaries and unsupported
definitions. Exact outcomes are two `WINDOW_LIMIT` no-definitions, one
unsupported LDR definition at `0x146a70b4`, and one BL `CONTROL_TRANSFER`
boundary. `resolved_base_count=0` and `resolved_target_hit_count=0`; the
classification is
`NO_RESOLVED_TARGET_STORE_WITHIN_STAGE2A_DIRECT_DEFINITION_RX_MODEL`. This
refutes only the supported Stage 2A direct-definition path, not writer
existence; SP/RWE and all other paths remain `UNKNOWN`.

Stage 2B now extends only the two Stage 2A window-limit X8 candidates with a
maximum-512 same-block W-wide-move model. The pinned `MOVZ W8,#0xf000` and
`MOVK W8,#0x1489,LSL#16` chain resolves XBL virtual-address value
`0x1489f000`, computing `0x1489f400` and `0x1489f4d0`; both are outside
file-backed PT_LOADs and neither numerically matches a target. The result is
`resolved_base_count=2`, `resolved_numeric_target_hit_count=0`, with
classification
`NO_NUMERIC_TARGET_ADDRESS_MATCH_WITHIN_STAGE2B_W_WIDE_MOVE_RX_MODEL`.
This refutes only numeric target equality in that model; physical destination,
VA-to-PA translation, writer identity and all unsupported/dynamic paths remain
`UNKNOWN`. Experiments 015 and 016 remain reserved and `NOT ELIGIBLE`.

Stage 2C covers the remaining non-SP RX X8 store at `0x146a70c0` through its
unique direct BL caller at `0x146a67a4` and retained 48-entry table. The exact
lookup/writer pins produce 48 conservative table-derived possible `+0x400`
values; none numerically matches the 12 targets. Descriptor `+0x20`
eligibility, per-entry execution, VA-to-PA translation, physical destination,
indirect callers and other X8 writer paths remain `UNKNOWN`. One non-SP RX
static candidate remains (`X19`). Classification is
`NO_NUMERIC_TARGET_ADDRESS_MATCH_WITHIN_STAGE2C_UNIQUE_DIRECT_CALLER_TABLE_MODEL`;
this is not a no-writer claim. Experiments 015 and 016 remain reserved and
`NOT ELIGIBLE`.

Stage 2D examines the remaining non-SP RX X19 store at `0x14935bf4`. One
direct-BL caller at `0x14949eec` statically supplies W0=0; exact dispatch and
`CBNZ W0,0x14935ce8` pins make the pre-MADD success result an explicit runtime
precondition. The exact initializer statically assigns `0x1483c904` to the
import slot, and an exact instruction-class/write-set audit proves the
resolved target has no X19-X29 definitions. Under explicit normal-return and
slot-preservation conditions, the direct effective value is `0x85e9e970`, with
zero target matches. Runtime initializer execution, slot currentness, import
conformance, VA-to-PA identity and physical ownership remain `UNKNOWN`; no
writer absence is claimed. Classification is
`NO_NUMERIC_TARGET_ADDRESS_MATCH_WITHIN_STAGE2D_UNIQUE_DIRECT_CALLER_CONDITIONAL_CALLEE_SAVED_PRESERVATION_MODEL`.

Stage 2E examines only the seven RX SP-base candidates in exact F1/F2
functions. Their STR W/X forms, frame allocations, prologues/epilogues, unique
direct-BL callers and range-hash-bound audits within the recognized SP-write
classes are pinned; each
function's explicit memory-writeback audit accounts for exactly four recognized
sites (two SP frame updates and two non-SP writebacks). Recognized BR/BLR counts
are zero, and the all-file-backed-executable-PT_LOAD-words direct-entry census
finds one external BL to each function start and zero external entries to
interiors. All seven accesses are inside the local allocations. The
same-function immediate-control CFG (BL modeled as fallthrough) has no
recognized SP-write-class instruction after allocation on a path to each
candidate; unsupported instruction effects remain `UNKNOWN`.
An independent GNU objdump 2.46 disassembly census, pinned by each exact range
hash and not recomputed by this tool, reports F1 as 492 instructions/134
writeback-free SP-base accesses and F2 as 1,102/168.
Absolute runtime stack address, stack integrity/rebasing, physical destination
and execution remain `UNKNOWN`. Classification is
`SEVEN_RX_SP_CANDIDATES_ARE_PINNED_STACK_FRAME_STORES_RUNTIME_STACK_ADDRESS_UNKNOWN`.

Host-only Experiments 019–022 are now integrated. Experiment 019 proves only
strict syntactic candidate pair arrays in two key domains, not register tables
or consumers; absolute keys do not hit ranked MC bases, sections and implicit
bases are `UNKNOWN`, and bounded stored/exact-wide/ORR materialisation finds
`0x00003333` and `0x00300014` absent while `0x00300033` has two adjacent
sequences. It makes no writer-absence claim. Experiment 020's bounded
register-offset census has a pinned false negative at `0x14868a50`;
`SUPPORTED` only is treating its largest RWE segment as a candidate by
size/content. Controller identity, general walkers, DCB consumers and writers
remain `UNKNOWN`. Experiment 021 proves seven direct
`BL` and zero direct `B` edges to one bounded-copy target; only five are
locally labelled `{0,1,2,15,16}`, two are unlabelled, and other-section/global
delivery is `UNKNOWN`, not refuted. Experiment 022 proves `430/470/122/492`
counts for two enumerated retained-evidence channels and sparse density;
completeness is `REFUTED` by known `0x09248080`, while implemented-register
coverage remains `UNKNOWN`. Class C is unchanged; Experiments 015/016 remain
`NOT ELIGIBLE`.

Integration validation for the current host-only Experiment 025 record is
independently recorded as 22 focused and 556 full unittest PASS, 65 public JSON
manifests, Python byte-compilation, byte-identical regeneration, and two
independent artifact-review PASS results in the
[Experiment 025 integration review](docs/EXP025_INTEGRATION_REVIEW_2026-08-26.md).
The historical Experiment 023 artifact is retained as merge-history evidence
but remains `WITHHELD/NO-GO` and unpromoted: its timing protocol is not
comparable to Experiment 014 (fixed order, half warmup, `ISB`, summed reopen
without `/2`), physical-allocation PA provenance is missing so a `+0x1000`
countermodel fits the labels, and the full GF(2) matrix is non-unique.
`PA24=b1^b2` is `SUPPORTED` only; raw evidence remains private. Experiment
023R is the separately repaired result described below.

Experiment 024 is `COMPLETED` and integrated. `PROVED`: the exact
`[0x148689a0,0x14868a64)` walker uses six-byte records, compares flags with
`0x8000`, branches `B.EQ` to return before the store, and conditionally stores
the zero-extended byte as a 32-bit word. Exactly three direct callers select
five XBL-resident table alternatives; selector unions are 53 and 127 unique
offsets with a 170-offset cross-alternative syntactic superset and 221
nonterminator records. The two pinned UFS design blocks are byte-identical;
under initialized-base retention all 170 symbolic destinations lie in the
broader `ufshc` `ufs_phy` resource. `SUPPORTED`: the table-driven positive
control is conditional on base retention and store reach. `UNKNOWN`: current
base because helper `0x1486abec` reaches unresolved `BLR X9` at `0x1486ac1c`,
selector/runtime execution, reached-store subset, flag semantics, live-DTB
equality, DCB semantic alias/global consumer/writer, DDR/MC relation, GF(2),
and alias/bypass. All mappings are conditional symbolic supersets, not current
destinations. Class C remains unchanged and Experiments 015/016 remain
`NOT ELIGIBLE`.

Experiment 025 is `COMPLETED` and integrated from commit `d743150` (parent
`a68d2f1`). `PROVED`: the exact platform-query range
`[0x1486abec,0x1486acac)` has caller `0x1486847c` with `X0=SP+0x10`, not main
context `X19`; it loads, forms the attach-output address for, and reloads slot
`0x14890590`, and pins semantic `MOVZ/MOVK` ID `0x02000139`. The static seed
derives `X0=0x14875668`, outer record `X1=0x14875590` with count five, then
descriptor `0x14824ab8` -> factory `0x1484a880` -> constructed candidate
`0x1488f418` -> inline vtable `0x14824ad0` + `0x48` -> callback
`0x1484a9d4`. The bounded callback path is
`0x1484a9d4 -> 0x1484a730 -> 0x1484a824 -> 0x1484aa30 -> 0x1484a854`;
its recognized output write at `0x1484a9f4` targets helper `SP+0xc`. Nested
recursion/status writes are only at `0x1488f3f9`, `0x14890ba0`, and
`0x14890b90`; one decoded MMIO read is at `0x01fc8004`, with zero recognized
MMIO writes in the bounded helper. The all-executable census is conservative
coverage, not arbitrary-write absence. `SUPPORTED`: conditional intended
binding can populate the slot and the recognized callback flow does not write
caller context `+8`. `UNKNOWN`: runtime registration/order, slot value/object
identity, actual `BLR X9` target, alternate BSS mutation/global aliases/
unsupported writes, full `0x01d80000` base currentness, and live mapping or
authority. Experiment 024's UFS mapping remains conditional; Class C is
unchanged and Experiments 015/016 remain `NOT ELIGIBLE`. See [the integration
review](docs/EXP025_INTEGRATION_REVIEW_2026-08-26.md).

Experiment 026 is `COMPLETED` and integrated from commit `0305a03` as
host-only, read-only static analysis. `PROVED`: registration helpers
`[0x1482ecb4,0x1482edac)`, the initializer loop `[0x1482edac,0x1482f0b4)`,
and table header `[0x14875534,0x14875568)` independently pin a 24-byte
registration node, list head `0x14890f60`, count two, row start
`0x14875538`, cursor `0x1487554c`, and stride `0x18`; `PROVED`: bounded
bootstrap, veneer, alternates, dispatcher, and caller local/control/data edges
include the dispatcher base/stride/index guard and symbolic pointer escape
`0x146b30c0 + runtime_index*0x3f8`, with modeled index `0..1`, not an exact
runtime base. `SUPPORTED`: memory-only initializer-pool shape
`[0x146b30c0,0x146b38b0)`, two-row `0x3f8` geometry. Pool contents and runtime
values remain `UNKNOWN`.

The complementary census scans 847,465 executable words, excludes 622 words
covered by the Experiment 025 dependency, and recognizes 9 direct accesses
(3 writes, 6 reads) plus 2 pointer escapes. Zero recognized access intervals
overlap slot `[0x14890590,0x14890598)`. The taxonomy is `ORDER_OPEN` and
`PROVED_BOUNDED_NO_RECOGNIZED_SLOT_MUTATION`; this is not global writer
absence. Runtime execution/order, slot value, object identity, `BLR` target,
base currentness, and writer absence remain `UNKNOWN`. Validation is 25
focused and 581 full unittest PASS, Python byte-compilation, JSON safety,
byte-identical regeneration, mode `0644`, and exact-XBL/final decoder hostile
review `PASS`; see [the Experiment 026 integration review](docs/EXP026_INTEGRATION_REVIEW_2026-08-26.md).
Class C remains `TRANSFORM ONLY`; 015/016 remain `NOT ELIGIBLE`. Experiment
027 is `COMPLETED` and integrated from commit `7aa1df7` as a host-only,
read-only bounded CFG/dataflow result. It analyzes 73 sites: 65 of the 67
register-offset sites after two dependency-owned exclusions, plus all 8
computed-address idioms (three complete loop contexts and five local forms).
The implemented census returns 71 `INDIRECT_OR_UNSUPPORTED`, 2
`NO_TARGET_WITHIN_MODEL`, zero `DCB_CONSUMER_PATH`, and zero
`MC_OR_SHRM_SYMBOLIC_TARGET`; these are bounded-model labels, not global
absence claims. Two nonexclusive `SECTION_READER_PROXIMITY_ONLY` hypotheses
remain: `0x148aa758` to reader `0x148ab138` at signed `-2528`/absolute `2528`,
and `0x148ab4f8` to the same reader at signed `960`/absolute `960`; threshold
`0x1000`, `link_proof: NONE`. Runtime base/current destination, execution,
writer/global consumer identity, aliases, register semantics, and unsupported
paths remain `UNKNOWN`.

The public manifest is 334,847 bytes, mode `0644`, SHA-256
`d11785969f16ba09155a2305eefd091158abfc515bc64cf94cb34d573a302277`; tool,
focused-test, and experiment-README hashes plus validation are recorded in
[the Experiment 027 integration review](docs/EXP027_INTEGRATION_REVIEW_2026-08-26.md).
Validation is 35 focused and 616 full unittest PASS in 86.100 s, Python
byte-compilation, 67 public JSON manifests parsed, two fresh byte-identical
generations, public safety/no-clobber checks, and independent hostile review
`PASS` after fixes.

Experiment 029 is `COMPLETED` and integrated from commit `a495bdc` as a
host-only, read-only inventory of the 71 exact Experiment 027 fail-closed site
ranges. It proves 1,992 range occurrences / 1,180 unique VAs and a
352-occurrence / 219-unique-VA / 197-unique-word unsupported frontier. Its
integration review records 17 focused and 633 full unittest PASS in 84.985 s,
68 public JSON manifests, deterministic repetition, and final hostile review
`PASS`; source provenance, reachability, and decoder safety remain
`UNKNOWN`/`NOT_CLAIMED`.

Experiment 031 is `COMPLETED` and integrated from artifact commit `cd9f26e`
plus reconciliation repair `12a8ebe`. The source-qualified scalar-plus-
dispatch v2 model selects 283 occurrences / 160 unique VAs / 148 unique
words, reaches 250 selected events (33 selected-not-reached; family/label
mismatches and events outside the selected domain are zero), and retains 69
occurrences / 59 unique VAs / 49 unique words across 20 sites. It transitions
51 of 71 baseline sites to bounded `NO_TARGET_WITHIN_MODEL`; 20 remain
`INDIRECT_OR_UNSUPPORTED`. This is `V2_MODEL_ONLY` and `NO_ABSENCE_CLAIM`,
not scalar-only closure. `DIRECT_CONTROL_DISPATCH_REPAIR` contributes 143
events across 62 sites (B 15, B.cond 87, CBZ/CBNZ 28, TBZ/TBNZ 13), with
repair outcomes 48 no-target/14 fail-closed and no-repair outcomes 3/6.
Validation is 19 focused and 652 tracked full
unittest PASS in 85.226 s (maximum RSS 220,684 KiB, no swaps), 69 public JSON
manifests, QEMU 280/280, byte-identical fresh generations, and final
reconciliation hostile review `PASS`; the checked manifest is 1,327,118 bytes,
mode `0644`, SHA-256
`51a187195c16eb609d337305540fc6d20a09297f5ab76b054497c5c58c3a2e86`.
The reconciled tool/test/Experiment-README pins are respectively
`5263d8975e9d64809aed04763e0c5573458dabcc6ae7432763d2858a36fc267b`,
`3a81fb4b4fc3023e70918a1648b6f04bb50e0967d27a8f09dbf939f9b55eff6d`, and
`12924ad1fcfeba580f57447e67f74d14743a5962046941ff3088e1b130d173de`.

Experiment 032 is `COMPLETED` and integrated from artifact commit `d46c44c`
after docs commit `e063181`. This host-only, read-only v3 model retains the
exact 031 scalar-plus-dispatch semantics and adds only Arm-qualified
`MADD/UMADDL`, shifted `EOR`, and shifted `BIC`. It selects 298 occurrences /
175 unique VAs / 162 unique words, reaches 264 selected events, and leaves 34
selected-not-reached. The arithmetic extension is 15 selected rows across
seven sites, with 14 reached (`MADD` 3, `UMADDL` 7, `EOR` 2, `BIC` 2).
The combined result transitions 55 of 71 baseline sites to
`NO_TARGET_WITHIN_MODEL`; 16 remain `INDIRECT_OR_UNSUPPORTED`. Relative to
031, sites 1, 36, 37, and 52 transition, with zero regressions. The residual
is 54 occurrences / 44 unique VAs / 35 unique words across 15 sites:
`PAIR_MEMORY` 48, `SIGN_EXTENDING_MEMORY` 2, and `SYSTEM_CONTROL` 4.
The inherited 031 full-record equivalence is exact for 250 scalar events,
143 direct-control events, and 23 taint-kill events. No DCB consumer or
MC/SHRM symbolic-target path is promoted; `current_destination` and
`writer_absence` remain `UNKNOWN`. Validation, source, and final artifact pins
are recorded in [the Experiment 032 integration review](docs/EXP032_INTEGRATION_REVIEW_2026-08-26.md).

Experiment 033 is `COMPLETED` and integrated from artifact commit `56b5ffa` as
a host-only, read-only v4 extension. It selects the complete 029 frontier:
352 occurrences / 219 unique VAs / 197 unique words, with 308 reached events
and 44 selected-not-reached occurrences. The inherited 032 full-record
equivalence is exact for 264 reached extension events, 143 direct-control
events, and 23 taint-kill events. The 44 new residual events are `LDP` 38,
`STP` 3, `LDRSW` 1, `LDRSB` 1, and `DAIFClr` 1; three `STP` instructions
produce six explicit lane observations.

`PROVED`: the bounded site result is 70 `NO_TARGET_WITHIN_MODEL` and one
`INDIRECT_OR_UNSUPPORTED`, with site 35 retaining the unresolved
indirect/runtime alias. No bounded DCB consumer or MC/SHRM symbolic target is
promoted. `UNKNOWN`: global writer identity/absence, current physical
destination, protected-memory semantics, and the runtime exception level or
`CheckDAIFAccess` result for `DAIFClr`. The checked public manifest is
2,017,356 bytes, mode `0644`, SHA-256
`606723e5125d661c800b167133f2a9b69a3b8d47361b39176665a49be539e598`.
Validation is 15 focused and 685 full unittest PASS, full maximum RSS
253,944 KiB with zero swap, byte-identical fresh publications, and an
independent hostile review PASS with no P0-P2 findings. See
[the Experiment 033 integration review](docs/EXP033_INTEGRATION_REVIEW_2026-08-26.md).

Experiment 034 is completed in artifact commit `d5d8046`. It proves the exact
guarded table at `0x14824cf0`, five entries/four unique local targets, and four
CFG-complete bounded direct-edge resolutions. The composed result is 71
`NO_TARGET_WITHIN_MODEL` / zero fail-closed sites, without promoting a bounded
consumer or controller target. Runtime `BR`/direct-`B` equivalence, execution,
current table contents/destination, global absence and security effect remain
`UNKNOWN`. Validation is 14 focused and 699 full unittest PASS; hostile review
is `PASS` after a `CMP W` width-mask repair. See
[the Experiment 034 integration review](docs/EXP034_INTEGRATION_REVIEW_2026-08-26.md).

The external line is reconciled at exact parent `247b0e1`. Later implementation
commits through observed `c91f473` are not promoted wholesale: `4b78b61` is
preserved as a review response, while Verifications 015/016 are rebuilt from
retained inputs. 023R proves rank-three/bit-24
algebra only in allocation-offset/model coordinates; physical PA attribution
is `SUPPORTED_WITHIN_MODEL` because pagemap is `BLIND`. 028 is a bounded
494-register encoding negative, 029A supplies reproducible ABL extraction and
stored-form negatives, and 030 preserves phases while refuting only the
independent-channel-selector inference. Physical roles, runtime writers,
computed ABL paths and live DT remain `UNKNOWN`; phase-D PA10 remains
`INCOMPLETE`.

Validation is 296 focused and 995 full unittest PASS, deterministic fresh
manifests are mode `0644`, and final hostile review is `PASS`; see
[the external-line reconciliation](docs/EXTERNAL_LINE_RECONCILIATION_2026-08-26.md).
Class C and Experiments 015/016 eligibility are unchanged.

Verification 015 runtime invariance is repaired from exact retained inputs.
`PROVED` in allocation-offset/model coordinates: six 51-key condition-labelled
sets; four clean comparisons with zero disagreements; and one weak L762
comparison with two excursions that remains `REPEAT_REQUIRED` and keeps
`all_invariant=false`. Six independently thresholded repeat groups cover both
excursions and have zero flips without promoting that primary result. The
retained bus-vote sweep is six levels × two and is excluded from DDR-frequency
or transform-transition inference. Runtime/reboot/coldboot identities are only
`SUPPORTED_BY_UNRETAINED_OPERATOR_REPORT`; pagemap is `BLIND`, and complete
action/final-state receipts are absent. Validation is 44 focused / 1,039 full
serial PASS with independent hostile-review `PASS`; see the
[Verification 015 integration review](docs/VERIFICATION015_INTEGRATION_REVIEW_2026-08-27.md).

Verification 016 is repaired from three exact retained raw files. `PROVED` in
allocation-offset/model coordinates: separate bit-25/26/27 thresholds and
matches `[14,21]`, `[19]`, `[13,20]`; two three-column passes with identical
per-bit verdicts before/after combination; and seven of seven model-derived
labels in the separate held-out file. The raw files do not retain the historical
17-control run. Pagemap is `BLIND`, so physical PA/base/alignment/effective
contiguity remain `UNKNOWN`. Validation is 23 focused and 1,062 full serial
PASS with hostile-review `PASS`; see the
[Verification 016 integration review](docs/VERIFICATION016_INTEGRATION_REVIEW_2026-08-27.md).

Class C and numbered Experiments 015/016 eligibility remain unchanged.

Verification 017 has completed the separate host-only post-decode-granularity
audit.  From the exact pinned 023R/V016 manifests and the live memory-map
record, the rank-3 model has a minimum class-change span of 8 KiB and reaches all
eight bank classes in a 64-KiB-aligned 64-KiB span (128 KiB for an arbitrary
base) under the retained allocation-offset/model projection.  Every listed
protected carveout and every explicitly unprotected System RAM fragment meets
that model-projection bound.  Thus a bank-only post-decode check is `REFUTED` as
a separator for those projected ranges.  Finite GF(2) countermodels prove that
the bank projection alone does not determine complete-coordinate injectivity.
The actual protection ordering, complete DRAM coordinate, transform mutability,
and any bypass remain `UNKNOWN`; this is not a physical alias or Class-D/E
result.  The canonical public manifest is
`evidence/manifests/verification-017-protection-bank-granularity-20260827-05.manifest.json`,
18,108 bytes, SHA-256
`97ff68a2f8ebfb6313f228f2626f12f88260764a993f916ba1f97677d7b99f02`, mode
`0644`, with 42 focused / 1,132 full serial tests passing (`skipped=1`, no
swaps) and no device action.

Verification 018's first parser-only attempt stopped before any target-dependent
mutation: it retained only `version`/`cmdline` frames because the live version
format included an explicit parenthesized build string. That incident is kept
private and was not replayed as an effect. The corrected second run is
`PROVED` as a bounded allocation-local result: exact A90 `SM-A908N` / SM8150
V2321, `camera_preview` ION type 10/id 30, one 256-MiB write-combine
allocation, two distinct virtual mappings, 4 page-aligned anchors, bits 6..27,
2 trials and 176 candidate observations. Both controls fired (`ALIAS` for the
same dma-buf through two VAs and `DISTINCT` for the distinct-offset negative);
all 176 candidates were `DISTINCT`, with zero disturbance, anchor clobbering or
trial disagreement. The analyzer result is `NO_ALIAS` only for the exact tested
offset pairs in one state. Pagemap was `BLIND` (0 present / 0 nonzero PFNs), so
physical PA identity, contiguity and final DRAM coordinates remain `UNKNOWN`.
This does not satisfy or promote numbered Experiments 015/016 and is not
physical-alias or protected-boundary evidence.

The live receipt and raw artifacts are private under the ignored evidence
directory. The canonical public manifest is
`evidence/manifests/verification-018-a90-20260827-03.manifest.json`, 47,715
bytes, SHA-256
`4747a45c20b038b511c3310ebbdd4ac67f9885f29dfe2e3155882a3cf7eb0371`, mode
`0644`. The probe source is 22,191 bytes / SHA-256
`cdc6f985fb8e2f37a3964a25f8d575ec1b3fe48eab71d084a30537c6fbe6f3bb`; the
byte-identical static AArch64 binary is 710,408 bytes / SHA-256
`33ef21a13ef79f6888b5a466644660ace3c6950664b1e2b497aad474f1487d56`, built
twice with `aarch64-linux-gnu-gcc` 15.2.0. Host validation is 28 focused
tests at this iteration; the independent hostile review's P1s were repaired
by exact source/binary/build pins, bridge serial binding, strict framing and
receipt/sidecar checks. Class C remains unchanged. V017's audit is complete and
does not authorize a controller or protection write. The bounded Route-2 audit
recorded below and in
`docs/ROUTE2_RANK_AUDIT_INTEGRATION_REVIEW_2026-08-27.md` is complete; its Q4
unknown is retained as a constraint on the next discriminator.
The detailed integration review is
`docs/VERIFICATION018_INTEGRATION_REVIEW_2026-08-27.md`.

The Route-2 falsification audit is complete as a separate host-only semantic
cross-check.  Q1 is `SUPPORTED_BOUNDED_CLOSURE_UNKNOWN_GLOBAL`: the exact
027/029/031–034 manifests retain zero promoted DCB-consumer or MC/SHRM symbolic
paths, stable 71-site identities and explicit global writer `UNKNOWN` fields.
Q4 is deliberately `UNKNOWN`: 030 inherits the validated rank-3 relation, but
the 029–034 public manifests do not contain a complete relation-row set.  The
public manifest is
`evidence/manifests/route2-rank-audit-20260827-01.manifest.json`, 9,607 bytes,
SHA-256
`ec3ec693768bf1294366c5650ab9c5e76b27f9bdce049c7a6f2b205a00a72fb8`, mode
`0644`.  Validation is 19 focused and 1,151 full serial PASS (`skipped=1`, no
swaps); no device action occurred.  The follow-on host-only 020A setter/base
trace is now complete and remains bounded by the same no-writer/no-live-
authority rule.

Verification 020A is now complete as a separate host-only static trace.  The
exact setter `[0x9fc06410,0x9fc0643c)` has five static stores: one `XZR` zero
and four argument-sourced values.  Its sole direct caller at `0x9fc023f0`
supplies `W3=[X0+0x10]`, `X0=[X0+0x18]`, `X1=[X0+0x20]`, and
`X2=[X0+0x28]` from an opaque incoming object in the bounded linear model.
Runtime values/currentness, field type, physical-to-DRAM mapping, mutability,
protected reach and aliases remain `UNKNOWN`; Class C and numbered 015/016
eligibility are unchanged.  The sanitized manifest is
`evidence/manifests/020A-setter-base-trace-20260827-01.manifest.json`, 9,171
bytes, SHA-256
`edf62eb6c1d97a8113f5ba0894548e9d5fafc83eeefbc7976c808b0f7886c051`, mode
`0644`.  Validation is 9 focused and 1,160 full serial tests PASS (`skipped=1`,
no swaps); the final hostile review is `PASS` as recorded in the integration
review (`docs/VERIFICATION020A_INTEGRATION_REVIEW_2026-08-27.md`).  The next
scored candidate is
the host-only caller-object origin trace (020B), not a device write.

## A. 현재까지 PROVED

- Exact A90 source, defconfig, System.map, independently extracted stock
  kallsyms, DTS/overlay and secure-buffer/RKP callsites were rechecked by path,
  line and SHA-256; existing prose was not treated as authority.
- `CONFIG_UH_RKP`, `CONFIG_RKP_KDP`, `CONFIG_RKP_NS_PROT`,
  `CONFIG_RKP_DMAP_PROT`, JOPP and ROPP remain enabled. `rkp_init()` calls
  `uh_call(... RKP_START ...)`, and `uh_call` reaches `smc #0`.
- `hyp_assign_phys/table` and `qcom_scm_assign_mem` name physical ranges plus
  VMID/permission data for SCM MP service calls.
- The exact SM8150 DT/source contains LLCC, LLCC-to-EBI_CH0, a CNOC DDRSS
  configuration endpoint, LLCC/DDR bandwidth monitors and AOP DDR perf/frequency
  messages.
- Live A90 capture `001-baseline-live-20260825-01` produced 12 successful,
  binary-safe read-only frames. It proved live `hyp_mem`, TIMA, RKP, UH heap and
  QSEECom advertised ranges and fixed current runtime/kernel identity.
- AMD's demonstrated primitive is a temporary Family 16h DRAM bank-map/
  swizzle/swap state change plus a controlled uncacheable access and GF(2)/Z3
  alias recovery; those details are AMD facts only.
- Experiment 004 captured nine exact live boot-firmware artifacts with matching
  device-before/host/device-after SHA-256. Exact XBL owns DDR DSF/DCB training;
  exact AOP manages DDR runtime state; exact `hyp` supplies QHEE; exact `tz`
  names BIMC/MEMNOC/LLCC memory-protection units.
- Experiment 006 binds all four DCBs to exact selector filenames, proves the
  section-16 path into SHRM, recovers XBL's 13-row DDR remapper table, and
  follows `icbcfg_info` to four `qhs_llcc + 0x8080` register windows:
  `0x09248080`, `0x092c8080`, `0x09348080`, `0x093c8080`. Layout 1 touches
  32-bit offsets `0x00..0x58` in each window.
- Experiment 008 resolves the exact live selection from retained boot-firmware
  evidence: `/6003_0200_1_dcb.bin`, two 3072-MiB ranks, mask `0x3`, and unique
  remapper row 7 with destinations `0x80000000` and `0x140000000`.
- Experiment 011 pins the real XBL Quest DDR failure recorder and its coordinate
  reporter. For the retained 6-GiB topology it derives rank boundary
  `0x140000000`, exactly row 7's rank-1 destination, then maps rank-relative PA
  bits to row `[31:16]`, bank `[15:13]`, channel `[10:9]`, column
  `[12:11]||[8:1]`, and byte `[0]`.
- That diagnostic bit partition is complete, non-overlapping, and invertible.
  Its exact bounded formula has no XOR and no PA-to-coordinate collision.
- Selected DCB section 16 parses exactly into two compact base-token/offset-
  token sets with 22 and 8 records. Base tokens numerically equal
  `physical_base >> 12` for exact `qhm_shrm` MCCC, MC, MCCC-master, DDRSS, and
  SHRM-CSR topology bindings.
- Experiment 012 recovers the exact Xtensa SHRM helper at `0x2d8dc`. It
  computes `(base_page << 12) + (offset_token << 2)` and direction zero reads
  each 32-bit word into a SHRM snapshot buffer. The two exact section-16
  callsites pass direction zero and produce 430/64 reads; the observed path is
  not a transform-write command stream.
- Experiment 013 proves both exact TZ selector branches place the complete
  `0x09065100–0x09065fff` snapshot workspace inside three enabled, TZ-owned
  regions. The exact narrow region is `DC_NOC_NON_BROADCAST_MPU` region 5 at
  `0x09060000–0x0906ffff`; all six branch/region matches exclude ordinary HLOS
  read and write.
- Experiment 013's fixed no-load control mapped/unmapped snapshot word
  `0x0906566c` and returned `0xc071`. The paired body differs by exactly one
  32-bit instruction (`MOVZ` versus `LDR W`); the one-load path returned no
  value, disconnected USB, and retained `Non Secure Watchdog Bark` with
  `TZBSP_ERR_FATAL_NON_SECURE_WDT`. It was not retried. V2321 full-prefix
  rollback and final `selftest fail=0` are proved.
- Exact layout-1 code encodes six 36-bit ranges as low32/high4 fields, disables
  the four instances before programming and enables them afterward. There is no
  distinct lock-register write inside that exact bounded XBL function; later
  firmware/hardware locking remains `UNKNOWN`.
- The separate exact TrustZone ELF contains the same `/dev/icbcfg/boot` DAL
  identity and four-base, six-slot layout record. Runtime invocation/locking is
  still `UNKNOWN`.
- Experiment 009 proves the primary TZ registry is a consumed 48-record table,
  not string-only metadata. Both embedded policy-selector branches contain a
  40-region `DC_NOC_BROADCAST_MPU` policy at `0x090e0000`.
- In both branches, region 11 is enabled, TZ-owned, covers
  `0x09248000–0x09248fff`, and therefore contains the tested PA
  `0x09248080`. Its raw access words are `0x80000000/0x00000000`, not
  `0x80/0x80`.
- The pinned exact TZ conversion path produces zero standard VMID permission
  words and client-permission bytes `0x11/0x08`: TZ-owner read/write plus
  MSA-class read-only, with no ordinary HLOS VMID grant. Exact devcfg sets
  `/ac/xpu:disable_xpu_ac = 0`.
- The exact TZ error router assigns `DC_NOC_BROADCAST_MPU` to global status
  bank 0 bit 29 and also assigns all four BIMC MPUs. `BIMC_MPU0..3` are absent
  from both embedded static policy lists.
- Experiment 010 proves that absence does not mean inactivity. The separate
  exact TZ memory-assignment fallback reaches memory-lock, topology fanout and
  dynamic `BIMC_MPU0..3` reconfiguration; some topologies also program
  `LLCC_BROADCAST_MPU`.
- Exact QHEE independently registers HLOS SMC `0x02000c16`. Its bounded
  `hyp_assign` handler validates ownership and calls a local stage-2/SMMU
  access-control wrapper; it does not directly call QHEE's generic TZ SMC
  wrapper or the TZ BIMC functions.
- Exact TZ registers XPU toggle SMC `0x02000c23`, but its disable path's
  allowed-base count is zero. Its enable path restores only a registered XPU,
  so this is not an arbitrary HLOS XPU-write or disable primitive.
- Both exact TZ selector branches cover every known remapper and BIMC
  configuration aperture with TZ-owned `MEMNOC_MS_MPU` region 0 and
  `CNOC_SNOC_MS_MPU` region 5; neither record grants ordinary HLOS VMID access.
- The boot master-MPU loop initializes `ANOC2_MPU`, `MSS_NAV_MPU`, and
  `CNOC_AOSS_MPU`, not `BIMC_MPU0..3`. XBL's BIMC literals are in a TZ-branded
  XPU diagnostic table and do not prove a main-XBL policy writer.
- Four successful retained boots register LLCC PMU and LLCC-to-DDR monitors.
  The reset XPU diagnostic is encrypted or unparsed, so it supplies no decoded
  violation and cannot exclude one.
- Live host sysfs proves the A90 remained connected as `04e8:6861`/`A90-LNX`;
  only the Codex sandbox omitted its `/dev/ttyACM0` node. A pinned host bridge
  completed live identity/config and Experiment 005 observations.
- Live `/proc/config.gz` proves `# CONFIG_DEVMEM is not set`. A fixed `1:1`
  character node therefore opens with `ENXIO`; cleanup and final runtime health
  (`pass=11 warn=1 fail=0`) were proved.
- Experiment 007 reproduced the exact historical REPL candidate
  (`b846ae9f…`), proved its named peek/call selftest, and then ran one fixed
  `__ioremap(0x09248080, 0x5c, PROT_DEVICE_nGnRE)` attempt after a fresh warm
  boot. Retained `/proc/last_kmsg` contains the slide result, the `__ioremap`
  return, and a `Non Secure Watchdog Bark` 3.027327 seconds later.
- `msm_readl` was never invoked in the generic attempt and no remapper value
  was read. The exact V2321 rollback prefix SHA-256 is `ca978551…`; native
  version and selftest `pass=11 warn=1 fail=0` are `PROVED` after rollback.
- The fixed inline no-load control (`dbbf81f2…`) returned sentinel `0xc071` and
  preserved runtime health. Its paired one-load candidate (`6fe92825…`) then
  ran once: no value returned, USB/ACM disconnected, and retained last-kmsg
  records a bark at 69.080426 s, last pet at 58.080136 s, bootloader cause
  `Non Secure Watchdog Bark`, and warm reset. `SUPPORTED`: the one fixed load,
  rather than mapping alone, triggered the stall. The result does not identify
  a firewall, XPU, clock/power, or ownership cause by itself. Combined with
  Experiment 009, an active `DC_NOC_BROADCAST_MPU` denial is now `SUPPORTED`,
  not yet causally `PROVED` because no decoded syndrome or runtime register
  readback exists.
- Verification 001 independently re-derived seven load-bearing static claims
  from the raw bytes without reusing any repository tool, and all seven were
  `CONFIRMED`. The full Experiment 009 chain resolves end to end: registry
  `{id=0x3c, base=0x090e0000, name → "DC_NOC_BROADCAST_MPU"}` → both policy
  entries (`region_count=40`) → byte-identical region 11
  (`read=0x80000000`, `write=0x00000000`, `0x09248000..0x09249000` exclusive).
  The XPU disable allowlist is a compile-time `0` at fixed `0x1c122a90`; SMC
  `0x0200030f` is a single `RET` (`0xd65f03c0`); the SHRM helper's decisive
  instructions decode byte-exactly as `slli a9, a9, 12` and
  `addx4 a12, a12, a9`.
- `PROVED` by that audit and previously underweighted: region 11's write access
  word is `0x00000000`, so **no** client class holds write permission, not
  merely no ordinary HLOS VMID. `DC_NOC_NON_BROADCAST_MPU` region 5 matches.
  Sibling regions 12 and 13 carry `0x40000000/0x40000000` and
  `0xf0000000/0xf0000000`, so the write denial is deliberate, not a default.
- The audit checks static facts only. It does not verify their security
  interpretation, and every `UNKNOWN` in section D stands unchanged.
- Verification 002 proves exact XBL has a consumed 26-record raw-dump table at
  `0x14961730`. Index 19 is a 32-byte descriptor for physical
  `0x09060000..0x0906ffff`, description `SHRM MEM region`, filename
  `SHRM_MEM.BIN`; that range contains the complete section-16 workspace and
  both snapshot destinations.
- Its exact primary loop at `0x14917ca8` loads each record as base/size and
  description/filename, advances by `0x20`, and calls registrar `0x14917670`.
  The pinned dload call chain is `0x14902cc4 -> 0x14917740 -> 0x14917c60`.
- The embedded Xtensa blob has one direct `0x25100` literal, referenced by the
  two direction-zero producers. It has no direct u32 literal for `0x25330`,
  `0x259e8`, or their physical addresses. This is a bounded direct/literal
  negative, not proof against dynamically derived consumers.
- A read-only check of mounted `ANDROIDLABSD` found no `SHRM_MEM.BIN`,
  `rawdump.bin`, or exact Experiment-004 A90 firmware filename. Its only A908
  item is the Samsung open-source kernel archive/directory; the exact firmware
  input remains the private live capture in this repository.
- Verifications 003/004 bound exact V2321 before every read and used no
  property service. Live `/proc/cmdline` reports
  `androidboot.debug_level=0x4f4c` (`LOW`),
  `androidboot.force_upload=0x0`, and normal boot-recovery value `0`.
- The S22+ precedent path
  `/sys/module/qcom_dload_mode/parameters/download_mode` is absent on A90.
  Exact A90 4.14 source instead binds `module_param_call(download_mode, ...)`
  to `msm-poweroff.o`; its source-backed live path
  `/sys/module/msm_poweroff/parameters/download_mode` returns `1`.
- Live `panic=-1` and `panic_on_warn=0`. Exact A90 `kernel/panic.c` proves a
  negative nonzero timeout skips delay then calls `emergency_restart()`.
  The newer ramoops `max_reason` parameter is absent, while the retained live
  config independently has `CONFIG_PSTORE=y` and `CONFIG_PSTORE_RAM=y`.
- No reset/dump attempt followed Verifications 003/004 themselves. A separate
  Samsung `04e8:6860` endpoint received no command; only the pinned A90P1
  `04e8:6861` bridge was used.
- Host-only decoder commit `9fdd5d6` loads the committed Experiment-012 plan
  and labels all 494 staged words in a structurally valid `SHRM_MEM.BIN`.
  Twenty focused tests prove the `430/64` shape, ordering, bounds, value
  placement, header/size rejection and zero-dump rejection. `PROVED`: the
  staged inventory does not reach the remapper window at `+0x8080`.
- Verification 005 pins the exact main-XBL outer trigger and XBLRamDump inner
  gate. MID is sufficient for inner vendor admission with FMM unlocked; a
  dload cookie or `0x776655ee` restart reason is independently required outside.
- Verification 006 captured all 10 MiB of live `param` with equal
  device-before/host/device-after SHA-256. It proved `DLOW`, force-upload `0`,
  FMM lock `0`, and dump sink `0` before any mutation.
- The bounded transition changed only the four-byte debug field. A normal MID
  boot proved XBL consumption without rawdump entry; one later SysRq panic
  supplied the outer trigger and was not replayed.
- Host journal proves the crash transport is Samsung `04e8:685d / MSM_UPLOAD`,
  followed by disconnect and return of native `04e8:6861`. The 05c6 Sahara/qdl
  collector captured no file.
- Verification 012 acquired exactly one 65,536-byte `SHRM_MEM.BIN`, SHA-256
  `409550ad226443271a39b6bc060f0e8fb3224111cc03f07a6ee563eaa7098bb7`.
  Its exact header validates at dump offset `0x5100`, and all 494 staged words
  map to the Experiment-012 register plan.
- Set 0 is `SUPPORTED` as populated controller state: 17/18 common four-instance
  MC offset groups are identical and the last is a stable two-by-two split.
  Set 1 is `REFUTED` as a coherent current snapshot: 64/64 values are distinct,
  its four MC `+0x80` values all differ, and 0/24 shared addresses match set 0.
- The original full `param` SHA-256 was restored. A subsequent new boot proved
  LOW, force-upload 0, dump-sink 0, dload master 1, and selftest `fail=0`.
- Experiment 014 bound a single-SG, write-combine, non-secure ION allocation to
  stable PA `0xf0400000..0xf13fffff`. A unique `/proc/kpageflags` transition
  window and a pinned dma-buf showed all 4096 pages with zero changed/lost
  pages; secure heaps were never selected.
- Live row-conflict timing proves that rank-relative PA bits `16..23` contribute
  XOR terms to a three-dimensional bank-selection row space generated from
  PA13..PA15. Four held-out kernel vectors and four one-bank-bit negatives have
  a 314 milli-tick p10/p90 separation gap; same-row `D=0x800` controls remain
  centred near zero.
- One equivalent observed bank basis is
  `0x9d2000, 0xa74000, 0x4e8000`. This basis is not a claim about named hardware
  BA-bit order; it identifies the invariant GF(2) row space.
- Literal audit searched all seven non-zero combinations across the nine pinned
  Experiment-004 images and the real 64-KiB SHRM snapshot. SHRM has no hit at
  any alignment; firmware has zero aligned u32 hits. All four raw TZ substring
  hits are one-byte-shifted pieces of monotonic 64-bit address tables, not
  direct hash-mask constants.
- Experiment 017 proves the exact XBL table at VA `0x146b1218` / file
  `0x630b8`: 122 nonzero u64 addresses plus a zero terminator, inclusive hash
  `d5042980…`, structurally 30 four-instance MC groups plus two globals. It
  covers all 12 `qhs_mc +0x400/+0x404/+0x4d0` candidates and excludes
  `qhs_mccc +0x118` plus `qhs_mccc_master +0x294` from this table only. The
  independent SHRM-plan intersections are set0 `100/430`, set1 `4/64`, union
  `100`, table-only `22`, SHRM-only `370`.
- Experiment 017's exact helper range is `0x146ae138..0x146ae18c`
  (end-exclusive), file `0x62318`, 0x54 bytes, hash `f325a8bf…`. Static
  control flow constructs sentinel prefill and conditional 32-bit read/copy to
  distinct VA `0x146bf300`; store bases inside the range are only X12/X8, so
  this helper is not a candidate-register writer. The table is an exact
  on-disk zero-sentinel table; helper traversal has no hard 122-entry cap.
  Exactly two direct BL callsites occur in file-backed executable PT_LOADs;
  current-boot execution and indirect/tail reachability remain `UNKNOWN`.
- Experiment 017 command was
  `python3 tools/sm8150_xbl_mc_snapshot_xref.py --output evidence/manifests/017-xbl-mc-snapshot-xref-20260825-01.manifest.json`.
  Public manifest/tool/focused-test SHA-256 are respectively
  `b1db2123…` / `2baa9e3d…` / `5b0f6f3e…`; 20 focused and all 279 repository
  unittest-discovery tests pass. An
  independent read-only raw-byte review accepted the result and emitted no
  artifact or artifact hash. Date: 2026-08-25 KST; device/SMC/MMIO access: none.
- Experiment 018 Stage 1A proves the exact XBL literal and strict store-offset
  census only: each target's single 8-byte table encoding yields the one
  aligned u32/u64 matches at the same file offset (two views of one entry, not
  independent literals), with no separate target literal elsewhere; the one
  aligned outside-table base literal is the RWE `0x80154`/`0x148bc254` fact,
  and matching offsets total 14. The public resolved hit count is `null` and
  classification is `STAGE1A_LITERAL_AND_STORE_OFFSET_CENSUS_WRITER_UNKNOWN`;
  literal or offset equality is not a writer proof. Stage 2A then analyzed only
  four non-SP RX candidates; seven SP candidates remain runtime-derived and
  three RWE candidates remain ambiguous.
- Experiment 018 Stage 2A proves the bounded model outcome for exactly four
  pinned non-SP RX candidates: two window-limit no-definitions, one unsupported
  LDR-to-X8 definition at `0x146a70b4`, and one BL control boundary before the
  older X19 definition. It resolves zero bases and zero exact target hits. The
  result refutes only this supported direct-definition path and makes no claim
  that no writer exists.
- Experiment 018 command was
  `python3 tools/sm8150_xbl_mc_writer_xref.py --output evidence/manifests/018-xbl-mc-writer-xref-stage1a-20260825-01.manifest.json`.
  Public manifest/tool/focused-test SHA-256 are respectively
  `8861a5626576fac32a83c295c34be63f91fd5e3f4b434490d567fb2984bb192d`,
  `9806b64c01f9965161966c88bbf5b943d953e790664c3136b2a116da63f8dc57`, and
  `b5fbf50e545b9df86d45ac012106d8905af231d9e94b0b2dd1927ec365da13d8`;
  8 focused and all 287 repository unittest-discovery tests pass. All 54
  public manifests parse as JSON and the generated manifest is mode 0644.
  Date: 2026-08-25 KST; device/SMC/MMIO access: none.
- Experiment 018 Stage 2A command was
  `python3 tools/sm8150_xbl_mc_writer_stage2a.py --output evidence/manifests/018-xbl-mc-writer-xref-stage2a-20260825-01.manifest.json`.
  Tool/test/manifest SHA-256 values are
  `eb0a8ce21154d97d052de9f7e4e0de40f85087a8cb517179f7c44332e9d85eb0`,
  `1272fadb0bcc6b883f74577284312ee34678975fa7ba60377d05d86927960b3b`, and
  `eeed732e4a6cecd60453e9088d8c3d4c7ed207a1e7c723bae91e27033d134a4b`;
  14 focused and 301 full repository unittest-discovery tests pass; all 55
  public manifests parse as JSON and regeneration is byte-identical; mode
  `0644`; device/SMC/MMIO access: none.
- Experiment 018 Stage 2B command was
  `python3 tools/sm8150_xbl_mc_writer_stage2b.py --output evidence/manifests/018-xbl-mc-writer-xref-stage2b-20260825-01.manifest.json`.
  Tool/test/manifest SHA-256 values are
  `aa35d8b303a7ea32a086d601b1f08390b1cad0932f105209ac337f394813dbcb`,
  `af7ca7b46550dda13e85e517c0c1c1df19b6414549d06415316b6d428e020fc9`, and
  `a4715112e27c74e5548ecb49f09106c236146c8a0216c87446ddbd3c355ccca6`;
  10 focused and 311 full repository unittest-discovery tests pass; all 56
  public manifests parse as JSON and regeneration is byte-identical; mode
  `0644`; device/SMC/MMIO access: none.
- Experiment 018 Stage 2C command was
  `python3 tools/sm8150_xbl_mc_writer_stage2c.py --output evidence/manifests/018-xbl-mc-writer-xref-stage2c-20260825-01.manifest.json`.
  Tool/test/manifest SHA-256 values are
  `d53d820eb8d10e8417247fabbc0e3196f73c73584a6b7d79d583a96834c34d53`,
  `92c95472940937a7001fe48dd055b4c598fd290c28a1e15757d1c297ebf5f526`, and
  `e096562a35da93a1dac10a1651fc7eff08eecf05dafca4a789bae2fd50540c01`;
  9 focused and 320 full unittest-discovery tests pass; all 57 public manifests
  parse as JSON; regeneration is byte-identical; mode `0644`; device/SMC/MMIO
  access: none.
- Experiment 018 Stage 2D command was
  `python3 tools/sm8150_xbl_mc_writer_stage2d.py --output evidence/manifests/018-xbl-mc-writer-xref-stage2d-20260826-01.manifest.json`.
  Tool/test/manifest SHA-256 values are
  `95e53e25f288ba1ef09996ff73919c2ad1dd4186c4fec41dc84216d715ee8b26`,
  `23c91a14c16706b920b4c3556e85844543dc99545a2b7b6d864a8c09d35f6136`, and
  `48c7aa83d30844f1d42094fcb0f8d7dd13cf44265f9961167912792d014661c4`;
  14 focused and 334 full unittest-discovery tests pass; all 58 public manifests
  parse as JSON; regeneration is byte-identical; mode `0644`; device/SMC/MMIO
  access: none.
- Experiment 018 Stage 2E command is
  `python3 tools/sm8150_xbl_mc_writer_stage2e.py --output evidence/manifests/018-xbl-mc-writer-xref-stage2e-20260826-01.manifest.json`.
  Tool/test/manifest SHA-256 values are
  `16519db59009efc1d55bee8ef37046679261ba486703dcffd371bb639331cc74`,
  `174af64d6f536f2b44a8fe3301e53ea9d4ea5acfb50323fe783a2db714764563`, and
  `c52babccfcfe825df7477dffc9533754fe1afd656d3afd839a398b078477ee36`;
  13 focused and 347 full unittest-discovery tests pass; all 59 public
  manifests parse as JSON; regeneration is byte-identical; mode `0644`;
  device/SMC/MMIO access: none.
- Stage 2E's exact SP-frame model proves seven RX SP-base stores, F1/F2 local
  allocation bounds, four recognized explicit writeback sites per function
  (two SP and two non-SP), zero recognized BR/BLR transfers, the external
  direct-entry census, and the same-function immediate-control CFG result for
  recognized SP-write classes; unsupported instruction effects remain UNKNOWN
  and it does not prove an absolute stack address or runtime destination.
- Experiment 019 proves strict syntactic candidate pair arrays in two key
  domains across the bounded DCB blocks. This is a shape result only: the
  arrays are not proved register tables or consumers, no absolute key reaches
  a ranked MC base, and bounded materialisation proves only the stated
  stored/exact-wide/ORR absences (`0x00003333`, `0x00300014`) plus two adjacent
  `0x00300033` sequences. No writer absence is proved.
- Experiment 020 proves its bounded register-offset/store census and supports
  treating the largest RWE segment as a candidate segment only. The pinned
  false negative at `0x14868a50` refutes any general zero-walker conclusion;
  general walkers, DCB consumers and writer identity remain `UNKNOWN`.
- Experiment 021 proves the direct census for one bounded-copy target: seven
  direct `BL`, zero direct `B`, five locally labelled sites for sections
  `{0,1,2,15,16}`, and two unlabelled sites. This does not refute delivery of
  other sections through unlabelled, indirect, other-copy or global paths.
- Experiment 022 proves the `430/470/122/492` counts and their sparse observed
  density for two enumerated retained-evidence channels only. The known
  `0x09248080` counterexample refutes completeness of those channels;
  implemented-register coverage remains `UNKNOWN`.
- Experiment 033 proves a bounded v4 admission of the complete 029 frontier:
  352 selected occurrences / 219 unique VAs / 197 unique words, 308 reached
  events and 44 selected-not-reached. The inherited 032 full-record equality
  is exact for 264 extension, 143 direct-control, and 23 taint-kill events;
  44 new events are `LDP` 38, `STP` 3, `LDRSW` 1, `LDRSB` 1, and `DAIFClr` 1,
  with six explicit `STP` lane observations. Its bounded site split is 70
  `NO_TARGET_WITHIN_MODEL` / one `INDIRECT_OR_UNSUPPORTED` at site 35, with
  zero bounded DCB-consumer or MC/SHRM-target paths. Global writer/current
  destination/protected semantics and the `DAIFClr` current-EL/
  `CheckDAIFAccess` result remain `UNKNOWN`; Class C and 015/016 eligibility
  are unchanged. Validation is 15 focused / 685 full PASS (full RSS
  253,944 KiB, swap 0), with hostile review PASS and no P0-P2 findings.
- Experiment 034 proves the exact site-35 guarded dispatch and five-entry table
  at `0x14824cf0`. Four unique local targets each produce a CFG-complete
  bounded in-memory direct-edge run, transitioning the composed model to 71
  `NO_TARGET_WITHIN_MODEL` / zero fail-closed sites with no regression and no
  promoted consumer/controller target. The baseline 033 site records remain
  verbatim. Runtime branch-type equivalence, execution/index/table contents,
  current destination, global absence and security effect remain `UNKNOWN`.
- Reconciled 023R proves 66 summaries/58 unique differences and, strictly in
  allocation-offset/model coordinates, a unique rank-three kernel plus
  bit-24 contribution `0b110`. Mapping these to physical PA24/rank/base or a
  second physical region is only `SUPPORTED_WITHIN_MODEL`; all five pagemap
  records are `BLIND` and effective contiguity is `UNKNOWN`.
- Experiment 028 proves seven numeric model covectors and zero tested
  register-mask/index/triple matches among 494 decoded registers/274 nonzero.
  Its 0.4514% observed-span density is not implemented-register coverage, and
  physical-bank attribution of the masks is only `SUPPORTED_WITHIN_MODEL`.
- Experiment 029A reproducibly extracts ABL's 4,763,976-byte canonical payload
  and proves zero exact controller-base/model-mask literals and zero tested
  spanning triples. PE32 runtime/computed paths, controller participation and
  the unretained live-DT property set remain `UNKNOWN`.
- Experiment 030 proves phase-preserving low-bit verdicts. PA9 is saturating in
  spread and stride modes; PA10 is saturating in complete spread phases B/C,
  while phase D has only PA10-alone `503` and is `INCOMPLETE`. `REFUTED` is
  only the inference that upward departure proves an independent channel
  selector; the physical roles of PA9/PA10 remain `UNKNOWN`.
- External reconciliation validation is 296 focused / 995 full PASS, with
  byte-identical mode-`0644` publications and independent hostile-review
  `PASS`. Exact parent is `247b0e1`; later implementation work is not promoted
  wholesale, and the separately rebuilt V015/V016 records supersede it only in
  their named scopes.
- Verification 015 proves the exact six-condition numerical classifications,
  per-difference dispersion, two primary L762 excursions, zero flips across six
  independently split repeat groups, and the exact six-level × two bus-vote
  transcript scope. The comparison remains `REPEAT_REQUIRED`/
  `all_invariant=false`; runtime-transition identity is only `SUPPORTED`, and
  the bandwidth axis is excluded from DDR-frequency inference.
- Experiment 024's integrated host-only validation record is 30 focused and 534 full
  unittest PASS, 64 public JSON manifests, byte-identical regeneration, and
  two independent review PASS results recorded in the
  [Experiment 024 integration review](docs/EXP024_INTEGRATION_REVIEW_2026-08-26.md).

## B. 현재 HYPOTHESIS

- One or more section-16 readback registers may expose or derive the now-proved
  XOR bank-selection state not represented by the XBL diagnostic formula.
- The final bank-selection owner is MCCC/MC or closely coupled DDRSS logic
  initialized before HLOS. Prediction: exact init stores or register semantics
  will encode a row space equivalent to `0x9d2000/0xa74000/0x4e8000`, although
  not necessarily as those literal masks.
- The retained watchdog may be the XPU denial's downstream fabric response.
  Static policy coverage and lack of an HLOS grant support this; the encrypted
  or unparsed TZ log prevents a causal syndrome match.
- One or more coherent set-0 MC/MCCC words may encode geometry, channel
  selection, or a hidden transform term. Their repeated/two-by-two structure
  makes this testable, but no semantic assignment is presently proved.
- Retained Verification-016 measurements may extend the allocation-offset/model
  relation through bits 25–27. Prediction: a phase-preserving repair will keep
  the reported labels while rejecting filename-order merging. Physical PA
  attribution remains a separate hypothesis until allocation base/alignment
  and effective contiguity are proved.

## C. REFUTED

- “The A90 self-built kernel disabled all RKP/QHEE paths.”
- “Mapping an EL2 interface/range proves arbitrary EL2 private-memory R/W.”
- “A similar hash exists, therefore the AMD vulnerability exists on Qualcomm.”
- “`mc_virt-base = 0x09680000` alone identifies final memory-controller decode
  registers.”
- “RKP appearing in a broad `/proc/iomem` System RAM resource proves it is
  accessible/unprotected.”
- “Linux `raw_id/raw_version` directly supply XBL's DCB filename fields.” Live
  values `165/3` do not match exact CFGL `0x6003/{0x0100,0x0200}`.
- “The exact live DCB revision remains unknown.” Retained XBL/CDT records select
  `/6003_0200_1_dcb.bin` without using Linux SMEM fields.
- “XBL's special 12-GiB remap case applies to this boot.” Exact topology is
  3072+3072 MiB and selects the ordinary 6-GiB row 7.
- “The current kernel can read the remapper through `/dev/mem`.” Live config has
  `CONFIG_DEVMEM=n`; the fixed `1:1` node fails at open before MMIO.
- “The generic REPL `__ioremap -> msm_readl -> __iounmap` sequence is a safe
  narrow kernel adapter.” The first verified `__ioremap` return was followed by
  a non-secure watchdog before `msm_readl`; all three targets are also `DENY`
  under the existing host call-safety classifier.
- “The tested `0x09248080` address lies outside the exact TrustZone XPU policy.”
  Both selector branches cover it with the same `DC_NOC_BROADCAST_MPU` region.
- “The critical policy word is `0x80`.” The exact little-endian uint32 field is
  `0x80000000`.
- “The critical static record grants ordinary HLOS access.” Its exact
  conversion has no HLOS VMID bit and no standard VMID permission word.
- “`BIMC_MPU0..3` are unconfigured because they are absent from both static
  policy lists.” Exact TZ memory-lock code configures them dynamically.
- “Kernel `hyp_assign` directly programs TZ's BIMC XPU.” Exact QHEE intercept
  instead uses its local ownership/stage-2/SMMU mapping path; TZ has a separate
  same-ID fallback implementation.
- “The HLOS-visible XPU toggle can disable a selected controller XPU.” Its
  exact allowed-disable count is zero.
- “The named RPM-region SMC unlocks an XPU in this exact TZ build.” The exact
  TZ handler for `0x0200030f` is a single `RET`.
- “The exact XBL diagnostic coordinate formula itself contains an XOR/hash or
  admits two physical addresses for one DRAM coordinate.” Its 32 input bits are
  partitioned exactly once and the inverse reconstructs the PA.
- “The `invert_row` string alone proves final PA-to-row transform state.” Its
  two pinned users report and forward a local DDR-code flag outside the Quest
  coordinate reporter.
- “Section 16's raw offset tokens imply 4-KiB register offsets or an observed
  write primitive.” The exact SHRM helper proves four-byte scaling and read
  direction for both direct consumers.
- “The SHRM snapshot workspace is statically unprotected or granted to HLOS.”
  Both exact policy branches cover it with the same three TZ-owned regions and
  no comparative HLOS VMID bit.
- “The purpose-built direct EL1 path can observe staged MCCC snapshot word
  `0x0906566c` on this boot.” The only eligible one-load attempt returned no
  value and ended in a non-secure watchdog reset.
- “No exact firmware export path covers the protected SHRM workspace.” XBL's
  consumed raw-dump descriptor covers the full enclosing 64-KiB region.
- “The exact SHRM blob directly exports either derived snapshot through a
  literal HLOS mailbox path.” Neither destination/local physical literal exists
  in the complete blob; the proved export consumer is external XBL code.
- “The S22+ `qcom_dload_mode` sysfs path transfers unchanged to A90.” The exact
  path is absent; the source-backed A90 owner is `msm_poweroff`.
- “Current V2321 has positive observable raw-dump entry signals.” Debug level
  and force-upload are both negative despite the positive dload master switch.
- “Both MID and force-upload are required for A90 rawdump.” Exact XBL and the
  successful live run used MID with force-upload zero.
- “The exact A90 crash transport is Qualcomm 05c6 Sahara/qdl.” The live target
  enumerated as Samsung `04e8:685d / MSM_UPLOAD`; qdl captured no file.
- “No real `SHRM_MEM.BIN` can be collected on this retail target.” Verification
  012 collected and structurally decoded the exact 64-KiB file.
- “Set 1 is a coherent current controller snapshot.” Its captured statistical
  and cross-set consistency checks fail.
- “The dump contains the remapper control window at `+0x8080`.” All staged
  same-page words are below that window.
- “The XBL diagnostic `bank=PA[15:13]` formula is the complete silicon
  bank-selection function.” Experiment 014's held-out live timing requires row
  bits `16..23` in the bank-selection row space.
- “Anonymous cached RAM plus EL0 `DC CIVAC` alone is a valid DRAM classifier on
  this target.” Its result remained LLCC-confounded; the retained proof uses a
  write-combine ION mapping instead.
- “Raw `0x009d2000`, `0x00a74000`, or `0x003a6000` byte matches in the exact TZ
  image directly attribute the hash to TrustZone.” All are unaligned windows
  inside 64-bit address tables advancing by `0x200000`.
- “The exact 0x54-byte helper programs/writes the candidate controller
  addresses.” Its table-derived registers are load bases only; the identified
  STR store bases are X12/X8, the fixed read-copy-buffer aliases.
- “The helper independently enforces a maximum of 122 iterations.” Its
  traversal is zero-sentinel-only; the exact on-disk table's terminator is at
  index 122.

- “Experiment 019's syntactic pair arrays are proved register tables or
  consumers.” Their shape does not establish section/base semantics or a
  writer, and no writer absence follows.
- “Experiment 020's narrow zero-walker result is a general absence claim.”
  The pinned false negative at `0x14868a50` refutes that generalization.
- “Experiment 021's five local section labels account for every direct
  bounded-copy call.” Two direct `BL` sites are unlabelled; other-section and
  global delivery are not refuted.
- “Experiment 022's two enumerated channels are complete.” Known
  `0x09248080` is outside them, so completeness is `REFUTED`; this does not
  refute implemented registers outside the channels.

## D. UNKNOWN

- Physical attribution of the 023R model bit-24 contribution, contributions
  from physical PA25..31, the actual roles of saturating PA9/PA10, and the
  reason PA4/PA5 produce intermediate timing.
- Exact semantic names, bitfields, and lock/writability state of coherent set-0
  section-16 registers; any indirect helper invocation with reverse direction;
  and final-decode meaning.
- Final runtime XPU register state and a decoded XPU syndrome for the fixed
  staged-MCCC read. The observed reset is exact; XPU as its root cause remains
  `SUPPORTED`, not `PROVED`.
- Numeric boot remapper values, runtime MMIO writability, and lock state.
  Destination regions and rank sizes are known, but runtime per-channel source
  bases and the interleave mask are missing. Static TZ policy ownership is now
  proved; its final hardware register state and the precise watchdog response
  remain unresolved.
- Final boot/runtime `BIMC_MPU0..3` policy and control-register values. The TZ
  dynamic initializer is proved, but its runtime inputs, topology selector and
  post-programming readback are not.
- Which exact MCCC/MC/DDRSS register represents or derives the proved bank hash,
  who writes it, and whether it is writable or locked after boot.
- Protection ordering and existence of a post-transform security check.
- Any deterministic normal-RAM DRAM alias or protected-boundary consequence.
- Live boot-image and live-DTB byte hashes.
- Why set 1 is stale/unpopulated/uninitialized; only its use as a coherent
  current snapshot is refuted.
- Any normal-boot HLOS-readable export of the set-0 words. The proved Samsung
  Upload path is post-reset bootloader diagnostics, not an EL1 runtime mapping.
- Experiment 017's successful runtime completion, partial/sentinel output,
  coherent/atomic/current status, MMIO read side effects or faults, mutable
  runtime table contents/lock, indirect BLR/tail-call reachability, and any
  other writer/programmer for these candidates.
- Experiment 018 Stage 1A's base/effective-address resolution, writer identity,
  all unsupported store forms, dynamic/cross-block/cross-call paths, AOP/TZ
  paths, runtime execution/semantics/mutability, alias/bypass, and the meaning
  of the literal/offset matches remain `UNKNOWN`. The RWE three are ambiguous;
  the seven SP-based RX candidates are runtime-derived. No REFUTED writer claim
  is made.
- Experiment 018 Stage 2A leaves the seven SP candidates, three RWE candidates,
  unsupported/cross-block/cross-call/dynamic paths, runtime execution and all
  writer/semantic/mutability/GF(2)/alias/bypass questions `UNKNOWN`.
- Experiment 018 Stage 2B leaves VA-to-PA translation/identity, physical
  destination, execution, writer identity, mixed-width/unsupported/dynamic
  paths, semantics, mutability/lock, GF(2), alias and bypass `UNKNOWN`. Its
  two computed values are XBL virtual-address values only; neighboring ELF
  headers do not establish physical RAM ownership.
- Experiment 018 Stage 2C leaves descriptor `+0x20` per-entry eligibility,
  successful execution, runtime table mutation/currentness, VA-to-PA identity,
  physical destination/ownership, indirect callers, other X8 writer paths,
  writer identity outside the unique direct path, semantics, mutability/lock,
  GF(2), alias and bypass `UNKNOWN`. Its 48 rows are a possible-value superset,
  not proof that every store executes.
- Experiment 018 Stage 2D leaves initializer execution, later slot mutation,
  current runtime import-slot target/currentness, the two pre-MADD import-wrapper
  preservation conditions, pre-MADD success result, post-call values without
  explicit conditions, VA-to-PA identity, physical
  destination/ownership, indirect callers, runtime semantics, mutability/lock,
  alias, bypass and writer identity outside the scoped path `UNKNOWN`.
- Experiment 018 Stage 2E leaves absolute runtime stack address, stack
  corruption/rebasing, callee behavior, execution, VA-to-PA identity, physical
  destination/ownership, indirect callers, semantics, mutability/lock, alias,
  bypass and writer identity `UNKNOWN`; the three RWE candidates remain outside
  this RX-only stage.
- Experiment 019 leaves section/base semantics, consumers, register identity,
  computed values, writer identity and any relation to the GF(2) observation
  `UNKNOWN`; its materialisation audit is bounded to stored words, exact wide
  moves and ORR immediates.
- Experiment 020 leaves the exact six-byte walker interpretation, its DCB
  identity, runtime base, general walker coverage, DCB consumer and writer
  `UNKNOWN`; the largest RWE segment is not an identity proof.
- Experiment 021 leaves the two unlabelled direct calls, delivery of sections
  outside `{0,1,2,15,16}`, indirect/global callers and other copy routines
  `UNKNOWN`.
- Experiment 022 leaves implemented-register denominator/coverage and all
  unenumerated controller-address channels `UNKNOWN`; sparse observed density
  is not global search coverage.
- Experiment 023 remains withheld/`NO-GO`; its protocol comparability, PA
  provenance, and unique full GF(2) matrix are unresolved, and its raw
  evidence is private. Experiment 024 does not refute a DDR/MC/DCB path,
  current base, runtime execution, reached-store subset, flag semantics,
  live-DTB equality, DCB semantic alias/global consumer/writer, DDR/MC
  relation, GF(2), or alias/bypass; those boundaries remain `UNKNOWN`.

## E. SDM855 physical→DRAM pipeline 후보

```text
CPU VA -> ARM stage-1 -> system PA -> NoC/interconnect
       -> four qhs_llcc ICB region-remap windows
       -> XBL intended rank/row/bank/channel/column model
       -> observed low-24 XOR bank selection (PROVED relation; owner UNKNOWN)
       -> PHY -> LPDDR4X coordinate
```

The CPU/MMU, source-visible interconnect endpoints, LLCC/EBI direction, XBL's
four-window region-remap programming, diagnostic formula, and a distinct live
bank-selection relation are `PROVED`. The exact block/register implementing
that relation and precise protection ordering remain `UNKNOWN`.

## F. protection pipeline 후보

```text
EL1 physical range + VMIDs/perms -> QHEE hyp_assign -> stage-2/SMMU ownership
same SMC ID, separate TZ fallback -> memory lock -> dynamic BIMC MPU policy
RKP metadata -> UH call -> SMC -> QHEE/RKP enforcement
EL1 access to qhs_llcc remapper -> DC_NOC_BROADCAST_MPU policy decision
```

Kernel inputs/call boundaries and the static DC_NOC policy covering the tested
configuration PA are `PROVED`; final runtime XPU registers and the protection
position relative to DRAM decode remain `UNKNOWN`.

## G. 가장 가능성 높은 controller/register 후보 Top 5

1. `PROVED value / UNKNOWN semantics`: four `qhs_mc +0x400`, all
   `0xc003ffff`; Experiment 017 adds exact table/read-copy coverage and
   independent observation confidence only.
2. `PROVED value / UNKNOWN semantics`: four `qhs_mc +0x404`, all
   `0x00003333`; Experiment 017 adds exact table/read-copy coverage and
   independent observation confidence only.
3. `PROVED value / UNKNOWN semantics`: four `qhs_mccc +0x118`, all
   `0x00111111`; Experiment 017 excludes these from its table only and does
   not downgrade their transform-state likelihood.
4. `PROVED value pattern / UNKNOWN semantics`: four `qhs_mc +0x4d0`, first
   pair `0x00300014`, second pair `0x00300033`; Experiment 017 adds exact
   table/read-copy coverage and independent observation confidence only.
5. `PROVED value / UNKNOWN semantics`: `qhs_mccc_master +0x294 = 0x00001111`;
   Experiment 017 excludes it from its table only and does not downgrade its
   transform-state likelihood.

Full addresses, values, and qualification fields are in the Verification-012
public manifest and experiment README.

## H. EL1에서 현재 관측 가능한 부분

`PROVED`: `/proc/iomem`, `/proc/meminfo`, live DT reserved-memory, runtime/kernel
identity, LLCC/BWMON resource landmarks, kernel SCM/UH interfaces and their
source-visible PA inputs. `REFUTED`: current-kernel userland `/dev/mem` access.
`REFUTED`: the generic REPL call chain as a safe read adapter. `PROVED`: a
fixed inline map/unmap control can return safely; a paired one-load execution
returned no value and ended in watchdog reset. `PROVED`: its PA is in a
TZ-owned static XPU region with no HLOS grant. `SUPPORTED`: XPU/fabric denial;
final runtime policy remains `UNKNOWN`. Exact XBL's post-reset raw-dump catalog
and one real export are `PROVED`, but they are not an EL1/HLOS runtime API.
`PROVED`: EL1-visible `/proc/kpageflags`, non-secure ION CMA, CNTVCT and normal
RAM timing expose the low-24 bank equivalence relation without controller MMIO.
After final restoration, EL1 observes LOW, force-upload `0`, dump-sink `0`,
dload master `1`, and selftest `fail=0`.

## I. EL2/QHEE가 담당하는 것으로 보이는 부분

`PROVED`: UH/RKP has an EL1-to-SMC call path; exact `hyp` firmware loads into
live `hyp_mem` and contains kernel/ownership protection. Exact QHEE intercepts
SMC `0x02000c16` and enforces ownership with its local stage-2/SMMU access-
control path, separate from TZ's BIMC implementation. `UNKNOWN`: arbitrary EL2
runtime R/W, DDR decode ownership and final protection ordering.

## J. EL3/TrustZone이 담당하는 것으로 보이는 부분

`PROVED`: SCM MP is the kernel-facing boundary. Exact TrustZone consumes its
48-entry XPU registry; both static-policy branches configure
`DC_NOC_BROADCAST_MPU` region 11 over the tested remapper PA as TZ-owned with no
HLOS grant, and exact devcfg does not disable XPU access control. Its separate
assignment fallback dynamically configures `BIMC_MPU0..3`; the XPU-disable SMC
has a zero-entry allowlist. `UNKNOWN`: final register readback and whether any
check is after final DRAM decode.

## K. AMD Skitter 공격과 구조적으로 같은 부분

`PROVED`: both platforms have an XOR-expressible bank-selection relation that
can be reasoned about over GF(2). `SUPPORTED`: both attack questions contain a
system PA, a protection/ownership decision, later DRAM-coordinate selection,
controller state, and the need to distinguish cache/virtual effects from an
actual physical-to-DRAM alias.

## L. AMD와 구조적으로 다른 부분

`PROVED`: AMD's exact Family 16h registers and PCI/MSR access method have no
identified SM8150 equivalent. AMD demonstrates Normal-World transform-state
mutation and a resulting alias; SM8150 currently demonstrates only passive
normal-RAM observation of a bank row space. `SUPPORTED`: Qualcomm's
LLCC/NoC/AOP/QHEE/SCM partitioning creates different owners and potential later
enforcement layers. SM8150 register identity, mutability, lock state and
ordering remain `UNKNOWN`, so this is not yet a structural impossibility proof.

## M. 가장 값싼 다음 실험

Verification 016 is complete, Verification 017 has excluded the narrow
bank-only enforcement shape, Verification 018 has supplied the fresh
allocation-local baseline, the Route-2 audit has closed its bounded Q1
question while retaining Q4 as `UNKNOWN`, and Verification 020A has traced the
setter's incoming object fields.  Verification 020B is now complete: its exact
caller trace resolves the object construction to the opaque return of
`BL 0x9fc160b8` while preserving runtime values/type/currentness as `UNKNOWN`.
The Route-2 handoff, 020A symbolic boundary, and 020B opaque-return boundary
remain the constraints for interpreting it.

The ordered next step is a separate bounded host-only trace of the
`0x9fc160b8` return helper, with no device/MMIO/controller write and no
promotion of its static return address to a runtime physical destination.

The completed V018 action wrote only inside its own non-secure allocation and
did not touch MMIO, SMC, secure heap, protected memory or a partition.
Verification 020B is now complete.  It traced the exact sole direct caller of
the 020A consumer at `0x9fc023c8`: `BL 0x9fc160b8` returns an opaque token,
which is copied into a stack object at `SP+0x20`; the four setter arguments are
symbolically `[return+0x0c]`, `[return+0x18]`, `[return+0x20]`, and
`[return+0x28]` with widths 32/64/64/64.  The result remains `CLASS C
(TRANSFORM ONLY)` and `NOT_ELIGIBLE`; runtime values, type/currentness,
physical-to-DRAM mapping, mutability and protected reach remain `UNKNOWN`.
The 020B focused suite is 7/7 and the full serial suite is 1,167/1,167 PASS
(`skipped=1`, no swaps); no device action occurred.  The integration review,
manifest and hostile-review result are recorded in
`docs/VERIFICATION020B_INTEGRATION_REVIEW_2026-08-27.md`.

Verification 020C is now complete.  The helper `[0x9fc160b8,0x9fc160c4)` is
`ADRP X0,0x9fc36000; ADD X0,#0x2c0; RET`, yielding static ELF VADDR
`0x9fc362c0`, with exactly two direct callers.  Its 48-byte object-field source
range is hash-pinned only; runtime contents/type/currentness, mutability,
physical-to-DRAM mapping, protected reach and alias/bypass remain `UNKNOWN`.
The 020C focused suite is 6/6 and the full serial suite is 1,173/1,173 PASS
(`skipped=1`, no swaps); no device action occurred.  The next scored candidate
is a bounded trace of the second helper caller at `0x9fc26e2c`. Numbered
Experiments 015/016 remain `NOT_ELIGIBLE`.

Verification 020D is now complete.  The second helper caller loads six fields
from the static object and stores symbolic origins to static slots
`0x9fc3e138`, `0x9fc3e140`, `0x9fc3e148`, `0x9fc3e150`, `0x9fc3e158`, and
`0x9fc3e160`.  Field values, slot semantics, runtime currentness, mutability,
physical-to-DRAM mapping and protected reach remain `UNKNOWN`.  Its focused
suite is 6/6 and the full serial suite is 1,179/1,179 PASS (`skipped=1`, no
swaps); no device action occurred.  The next scored candidate is a bounded
static-slot consumer census (020E).

Verification 020E is now complete.  The bounded exact-XBL census found 18
unique direct scalar accesses to the six 020D static slots: 6 `STR` stores and
12 `LDR` loads.  It retained 95 barriers (8 caller-saved direct `BL` barriers
and 87 unknown-instruction barriers); continuation across X19–X29 is only an
explicit AAPCS64 callee-saved assumption.  This does not establish global
writer/consumer absence, ABI compliance, runtime execution/currentness or
values, slot semantics, physical-to-DRAM identity, mutability, protected reach
or alias/bypass.  The focused suite is 7/7 and the full serial suite is
1,186/1,186 PASS (`skipped=1`) in 119.090 seconds, maximum RSS 343,404 KiB,
zero swap; no device action occurred.  The manifest and hostile review are
recorded in `docs/VERIFICATION020E_INTEGRATION_REVIEW_2026-08-27.md`.  The
next scored candidate is a bounded load-use trace (020F).

Verification 020F is now complete.  The twelve 020E load seeds were traced for
16 instructions within their same executable segments.  The exact model
records 16 downstream use events (10 address-base, 2 arithmetic, 2
register-offset, 1 register-copy, and 1 return) plus 11 barriers (4
caller-saved `BL`, 5 recognized control, 2 unknown); no tainted direct store
was reached.  X30 is caller-saved, MOVK stops fail-closed without a bit-level
lattice, and CBNZ/TBNZ are explicitly decoded.  The 020E manifest dependency
is mechanically opened with `O_NOFOLLOW` and SHA-256 checked.  Focused tests
are 9/9 and the full serial suite is 1,195/1,195 PASS (`skipped=1`) in
123.910 seconds, maximum RSS 342,272 KiB, zero swap; no device action
occurred.  The manifest and hostile review are recorded in
`docs/VERIFICATION020F_INTEGRATION_REVIEW_2026-08-27.md`.  The next scored
candidate is a bounded pointer/object resolution trace (020G).

Verification 020G is now complete.  It re-decoded the exact 020F address-use
events into 12 witnesses: 10 immediate object-field-shaped accesses (7
`LDR`, 3 `STR`) and 2 `UXTX` register-offset array-element-shaped loads.  The
set contains 11 unique access VAs and one duplicate witness.  Runtime base
values/currentness, object semantics, global writer/consumer absence,
MMIO/physical/DRAM identity, mutability, protected reach and alias/bypass
remain `UNKNOWN`; Class C and `NOT_ELIGIBLE` remain unchanged.  No device
action occurred.  The manifest is 7,218 bytes, mode `0644`, SHA-256
`f534efeee1e12f18d3af40c107dbc6fbe938eae16d9013aa088d22d7c880af3e`, and
focused tests are 10/10 with the full serial suite 1,205/1,205 PASS
(`skipped=1`) in 134.596 seconds, maximum RSS 347,740 KiB, zero swap.  The
next scored candidate is a bounded static-slot function-role/base-origin
trace (020H).

Verification 020H is now complete.  The exact 020G witness set groups into 11
unique access VAs and 7 bounded return/direct-branch-delimited local blocks.
Nine blocks contain unsupported forms and remain
`UNKNOWN_ROLE_UNSUPPORTED_FORM`; two are `LOCAL_READ_SHAPED_BLOCK`.  Ten unique
accesses have `STATIC_SLOT_SEED` base definitions;
indexed access `0x9fc26ea0` is `ARITHMETIC_DERIVED` from a bounded `MADD`.
True function boundaries, runtime values/currentness/execution, indirect
callers/callee effects, object semantics, MMIO/physical/DRAM identity,
mutability, protected reach and alias/bypass remain `UNKNOWN`.  Class C and
`NOT_ELIGIBLE` remain unchanged; no device action occurred.  The manifest is
19,314 bytes, mode `0644`, SHA-256
`b306ca67675430314289fd79faa2e53b2d67994807d0b08bd91ced9b625faba2`.
Focused tests are 11/11 and the full serial suite is 1,216/1,216 PASS
(`skipped=1`) in 140.860 seconds, maximum RSS 349,728 KiB, zero swap.  The
next scored candidate is a bounded caller-context/entry-role trace (020I).

## N. 가장 위험한 아직 금지된 실험

Treating a section-16 offset token as a byte offset and writing the resulting
MCCC/MC address. The exact helper proves four-byte scaling for its read path,
but no safe write semantics, restore state, or runtime values are known. Writing
the proved `qhs_llcc + 0x8080` map words while memory traffic is active is also
high risk because it can redirect system PA. Neither is justified without exact
semantics, boot values, a one-core/cache-safe critical section, restore path,
and watchdog/recovery behavior.

Reconciled with the operating policy: neither write is brick-capable, so
neither is forbidden by the binding constraint, and the "watchdog/recovery
behavior" prerequisite is now met by three retained resets. What still
withholds them is information, not safety — set-0 values are available only in
a post-reset snapshot, exact semantics are unknown, and no live readback path
can verify or restore a mutation. They remain low-yield blind writes.

Experiments 015 (normal-RAM alias) and 016 (protected-boundary reach) remain
reserved and `NOT ELIGIBLE`; Experiments 017 and 018 do not satisfy either
gate.

## O. 현재 취약점 가능성 평가

No numeric probability is justified.

Evidence for the attack class being relevant:

- SM8150 has distinct LLCC-to-EBI and DDRSS configuration paths.
- Exact XBL programs a topology-dependent system-PA remapper in four qhs_llcc
  instances before HLOS; exact retained topology selects row 7.
- Qualcomm primary filings describe channel/bank XOR hashing as a design class.
- Protection APIs name system physical ranges; they do not themselves reveal
  final decoded DRAM coordinates.
- A real post-reset snapshot now exposes coherent MC/MCCC value patterns that
  can be cross-checked independently against normal-RAM timing.
- Live write-combine normal-RAM timing now proves a hidden low-24 XOR
  bank-selection relation with held-out positive and one-bank-bit negative
  controls. The transform side of the question is therefore real, rather than
  inferred from patents or diagnostic strings.
- Verification 015 independently retains the same 51-key classification across
  four clean operator-labelled runtime/reboot/coldboot comparisons. This
  `SUPPORTED` stability makes the observed relation less likely to be a single-
  boot artifact, but it is not an immutability or transition proof.
- Verification 016 independently retains the folded rank-three shape through
  allocation-offset/model bits 25–27, with per-phase controls, two-pass verdict
  consistency and 7/7 separate-file model-derived agreement. This widens the
  model but does not establish physical PA identity, contiguity, a complete
  coordinate map, mutation or alias.
- Experiment 017 adds exact-XBL table/read-copy observation confidence for the
  three qhs_mc candidate groups, but does not prove any writer, mutation,
  alias, protected reach or bypass. Experiments 015 and 016 remain `NOT
  ELIGIBLE`.
- Experiment 018 Stage 1A adds exact-XBL literal and syntactic store-offset
  census confidence only: 14 matching offsets (RX11/RWE3), seven SP-based RX
  candidates, and no base/effective-address resolution. It does not prove any
  writer, mutation, alias, protected reach or bypass; 015 and 016 remain `NOT
  ELIGIBLE`.
- Experiment 018 Stage 2A does not prove any writer, mutation, alias, protected
  reach or bypass. It only refutes the supported direct-definition model for
  the four analyzed RX candidates; 015 and 016 remain `NOT ELIGIBLE`.
- Experiment 018 Stage 2B adds numeric-address confidence only for its two
  W-wide-move-resolved X8 candidates. It refutes only exact numeric target
  equality within that model; it does not prove any physical destination,
  writer, mutation, alias, protected reach or bypass. Experiments 015 and 016
  remain `NOT ELIGIBLE`.
- Experiment 018 Stage 2C adds static exact-XBL path/table confidence only:
  one direct caller, the 56/108/272-byte range hashes, and 48 possible
  table-derived `+0x400` values with zero numeric target matches. It refutes
  only numeric equality in that model; it does not prove per-entry eligibility,
  execution, physical destination, writer identity outside this path, mutation,
  alias, protected reach or bypass. Experiments 015 and 016 remain `NOT
  ELIGIBLE`.
- Experiment 018 Stage 2D adds static function/caller/initializer/import-target
  confidence only. It refutes numeric equality only under explicit
  callee-preservation or static-initialized-slot conditions; it does not prove
  initializer execution, slot currentness, runtime conformance, physical
  destination, writer identity, mutation, alias, protected reach or bypass.
  Experiments 015 and 016 remain `NOT ELIGIBLE`.
- Experiment 018 Stage 2E adds only RX SP-frame-store confidence for the seven
  SP-base candidates. It does not prove runtime stack placement, physical
  destination, execution, mutation, alias, protected reach, bypass or writer
  absence; Experiments 015 and 016 remain `NOT ELIGIBLE`.
- Experiment 019 adds syntactic candidate pair-array evidence only. It does
  not prove register-table meaning, a consumer, a base, writer identity or
  writer absence; bounded materialisation remains limited to the named models.
- Experiment 020 adds a bounded register-offset census and candidate-segment
  observation, but the pinned false negative at `0x14868a50` prevents a general
  zero-walker inference. General walker, consumer and writer remain `UNKNOWN`.
- Experiment 021 adds direct-edge evidence for one bounded-copy target only:
  seven `BL`, zero `B`, five local labels and two unlabelled calls. Other
  section/global delivery remains `UNKNOWN`, not refuted.
- Experiment 022 adds sparse density for two enumerated evidence channels only;
  known `0x09248080` refutes channel completeness and implemented-register
  coverage remains `UNKNOWN`. These host-only results do not advance 015/016.
- Reconciled 023R independently recovers a unique rank-three relation in
  allocation-offset/model coordinates, but physical PA24/rank/base mapping is
  `SUPPORTED_WITHIN_MODEL`, not direct pagemap evidence.
- Experiment 030 shows the low-bit metric saturates on PA9 and PA10 rather than
  supporting the prior independent-channel-selector inference. Their actual
  physical roles remain `UNKNOWN`.
- Experiment 033 qualifies the remaining integer-memory/system forms in the
  same bounded model and reduces the 032 result to 70 bounded
  `NO_TARGET_WITHIN_MODEL` sites plus one unresolved indirect site (35). Its
  352/308/44 accounting, exact 264/143/23 inheritance, and six STP lane
  observations are static evidence only; it does not promote a DCB consumer,
  MC/SHRM target, current destination, writer, or protected reach.
- Experiment 034 resolves site 35 inside the bounded static model, producing
  71/71 `NO_TARGET_WITHIN_MODEL` without promoting a consumer/controller path;
  it is model closure, not runtime writer absence.

Evidence against a presently usable bypass:

- No remapper value has been obtained and no post-boot write has been
  demonstrated. The only fixed read attempt ended in a watchdog reset.
- The first generic-REPL `__ioremap` attempt returned but then caused a
  non-secure watchdog before any `msm_readl`, so that adapter path is retired.
- The purpose-built no-load control passed, but its paired single-load candidate
  produced no value and a second retained non-secure watchdog. This is evidence
  against a presently usable EL1 observation primitive, not proof of a lock or
  firewall.
- The live kernel has `CONFIG_DEVMEM=n`; both default and temporary-node
  userland read paths stop before reaching MMIO.
- No SM8150 Linux code programming such a transform was found, and no exact
  firmware register write has yet been attributed to the recovered row space.
- Experiment 028 finds no tested numeric model-mask encoding among 494 observed
  decoded registers/274 nonzero; this is evidence against those encodings only,
  not controller-wide absence. Experiment 029A likewise finds no exact stored
  controller-base/model-mask literal or tested triple in extracted ABL, while
  computed/runtime paths remain `UNKNOWN`.
- Verification 018's fresh allocation-local marker baseline found no collision
  in 176 exact one-state offset pairs across two trials, with both controls
  valid; pagemap was BLIND, so this is not a physical-to-DRAM alias exclusion.
- No normal-RAM physical-to-DRAM alias is proved in the retained evidence.
- Verification 015's only requested bus-vote axis is excluded: retained data do
  not prove a DDR-frequency transition, and the L762 primary comparison remains
  `REPEAT_REQUIRED` even though its two excursions do not recur in the bounded
  repeat transcript.
- The recovered bank hash alone does not create a complete-coordinate alias;
  its conflict witnesses intentionally share a bank while selecting different
  rows. The exact XBL diagnostic coordinate formula is also bijective and
  cannot itself create an alias.
- Exact QHEE ownership/stage-2/SMMU enforcement is separate from TZ's dynamic
  BIMC policy, adding a second boundary rather than exposing generic control.
- Every known remapper/BIMC configuration aperture is covered in both static
  TZ policy branches, and the only identified HLOS-visible XPU toggle has a
  zero-entry disable allowlist.
- The complete SHRM snapshot workspace is independently covered by three
  enabled TZ-owned regions in both policy branches, with no ordinary HLOS read
  or write grant.
- The purpose-built paired test separated mapping from access: map/unmap passed,
  while the sole extra load produced no value and a retained non-secure watchdog
  reset. This is strong evidence against usable direct EL1 visibility.
- Exact XBL's alternative is a gated crash/download raw-dump catalog, not a
  normal-world register or shared-memory primitive. Its existence improves
  observability but does not supply transform mutation or an alias.
- The successful export required a persistent debug-level change plus a crash;
  after restoration the current boot is again LOW/force-upload 0. This is a
  diagnostic route, not an always-available runtime primitive.
- Secure ownership, boot-time locking, or a post-transform check could each
  independently make the AMD attack class fail.
- Exact TrustZone firmware names multiple BIMC/MEMNOC/LLCC MPUs, increasing the
  concrete evidence for additional enforcement layers. Experiment 009 proves
  narrow DC_NOC coverage of the tested remapper PA; Experiment 010 proves
  broad branch-invariant no-HLOS coverage for all known remapper/BIMC apertures
  and a separate dynamic BIMC policy path.
- Exact devcfg leaves XPU access control enabled (`disable_xpu_ac=0`), and the
  boot path consumes the selected static policy table.

Critical unknowns are exact set-0 register semantics, any normal-HLOS runtime
export, hash-register identity and encoding, lock/writability state, indirect
reverse-direction use, physical attribution of the model bit-24 contribution,
PA25..31 contributions, final XPU/remapper/MCCC/MC readback, dynamic BIMC
policy inputs, protection ordering, and deterministic complete-coordinate
alias behavior. Site 35 is closed only inside the bounded static model;
runtime execution/current destination remain unknown.
The `DAIFClr` current exception level and `CheckDAIFAccess` result also remain
unknown. The defensible current conclusion is
`NORMAL-RAM LOW-24 XOR BANK HASH PROVED / SECURE CONTROLLER APERTURES PROVED /
TRANSFORM MUTATION AND COMPLETE-COORDINATE ALIAS UNPROVED / NO BOUNDARY BYPASS
OBSERVED`.
