# SDM855 Memory Boundary Lab

Private, evidence-led research into the final system-physical-address to DRAM
mapping on Samsung SM-A908N / Qualcomm SM8150.

The central question is whether a Normal World physical address can be checked
by one protection layer but later transformed to a different protected DRAM
destination. This repository does **not** assume the AMD Skitter Creek result
applies to Qualcomm.

This is a derived project. See [Upstream](#upstream) for the platform it
observes from and the safety method it inherits.

Current phase: source reconstruction plus bounded, source-backed live
normal-RAM observation and host-only frontier qualification. Experiment 007
first retired a generic REPL mapping path after a watchdog before its intended
MMIO read. A fixed inline no-load control later passed; the paired candidate's
single fixed 32-bit load produced no value and was followed by a retained
`Non Secure Watchdog Bark`. `SUPPORTED`, not `PROVED`: the load caused the
stall. V2321 was restored by verified boot-prefix readback and passed final
native health. No DDR/controller, XPU, SMMU, SCM, EL2, EL3, or
protected-memory write has been performed.

Live Verifications 005–014 have now completed the gated diagnostic track. Exact
XBL static analysis proved that MID alone admits the inner vendor path while a
panic-supplied dload cookie/restart reason supplies the outer trigger. A
byte-exact 10-MiB `param` capture proved FMM, force-upload, and dump sink were
zero; only the four-byte debug field was changed, verified, and finally
restored. One source-backed SysRq panic was dispatched without replay.

Host-only Experiment 008 then resolved the exact live DCB and remapper row from
the retained boot records, pinned the six-slot 36-bit XBL writer, and bound
TrustZone `BIMC_MPU0..3` records to `qhs_llcc + 0xe000` beside each remapper at
`+0x8080`. This narrows the ownership question but does not prove policy
coverage, post-boot mutability, an alias, or a bypass.

Host-only Experiment 009 now proves static policy coverage for the tested
instance-0 page. Both exact TrustZone selector branches place `0x09248080` in
enabled, TZ-owned `DC_NOC_BROADCAST_MPU` region 11; exact permission conversion
grants no ordinary HLOS access, and exact devcfg has `disable_xpu_ac=0`.
`SUPPORTED`, not causally `PROVED`: XPU/fabric denial explains the fixed-load
watchdog. A decoded syndrome and final runtime policy readback are still absent.

Host-only Experiment 010 now resolves the missing initializer boundary.
QHEE's exact `hyp_assign` intercept enforces ownership through its local
stage-2/SMMU access-control path, while a separate same-ID TrustZone fallback
reaches dynamic `BIMC_MPU0..3` reconfiguration. The HLOS-visible XPU toggle
cannot disable any XPU because its exact allowed-disable count is zero. Both TZ
policy branches also cover all four remapper and BIMC configuration apertures
with broad TZ-owned records containing no HLOS grant. This is strong Class A/B
candidate evidence for the known controller apertures, not a proof that the
overall AMD attack class is structurally impossible: the final DRAM transform
and post-transform protection ordering remain `UNKNOWN`.

Host-only Experiment 011 recovers an exact XBL Quest DDR diagnostic formula.
For the retained 6-GiB topology its rank boundary is `0x140000000`, exactly
the selected remapper row's rank-1 destination. Rank-relative PA bits map
linearly and bijectively to row/bank/channel/column, with no XOR and no alias in
that bounded formula. Selected DCB section 16 also parses into two exact token
sets whose base tokens match SHRM-visible MCCC/MC/DDRSS pages. Hidden hardware
transform state, token semantics, mutability, and protection ordering remain
`UNKNOWN`; no alias or bypass has been observed.

Host-only Experiment 012 then recovers the exact Xtensa SHRM section-16
consumer. Its helper computes `(base_page << 12) + (offset_token << 2)` and
reads each 32-bit register into a SHRM snapshot buffer. Both exact callsites
pass the read direction; the selected lists produce 430 and 64 register-word
reads and no transform-write stream. Runtime register values and any indirect
reverse-direction path remain `UNKNOWN`.

Host-only Experiment 013 proves that the complete SHRM snapshot workspace is
inside three enabled, TZ-owned regions in both exact policy branches. The
narrow `DC_NOC_NON_BROADCAST_MPU` region is exactly
`0x09060000..0x0906ffff`; none of the six branch/region matches grants ordinary
HLOS read or write. The fixed no-load control at snapshot word `0x0906566c`
returned `0xc071`; its paired candidate differed by one instruction and made
one 32-bit load, returned no value, disconnected USB, and ended in a retained
`Non Secure Watchdog Bark` / `TZBSP_ERR_FATAL_NON_SECURE_WDT`. The operation
was not retried. V2321 was restored by full-prefix SHA-256 and passed final
selftest with zero failures. This blocks the tested direct EL1 snapshot path;
it does not prove that XPU is the causal root or that no hidden transform
exists.

Host-only Verification 001 then audited the evidence chain itself. Every
`PROVED` statement here is one agent's interpretation of the exact bytes, and
Experiments 008–013 consume 004/006 conclusions as pinned inputs, so an early
misinterpretation would be inherited downstream. Seven load-bearing static
claims were re-derived from raw bytes without reusing any repository tool, and
all seven were `CONFIRMED`, with no substantive error and two notation issues.
The audit also records a fact the experiments underweighted: the remapper and
SHRM policy regions deny write to **every** client class, not merely to ordinary
HLOS. It verifies static facts only, not their security interpretation.

Host-only Verification 002 traced consumers beyond the blocked EL1 path.
Exact XBL contains and actively enumerates a 26-record crash/download raw-dump
table whose index 19 exports the full `0x09060000..0x0906ffff` SHRM range as
`SHRM_MEM.BIN`, covering both snapshot buffers. This refutes “no firmware
export path exists,” but does **not** prove a normal Android/HLOS interface. A
read-only mounted-SD check found neither `SHRM_MEM.BIN` nor `rawdump.bin`; the
exact A90 firmware used here remains the private Experiment-004 live capture,
not an SD-card artifact.

Live Verifications 003/004 implemented the property-free A90 eligibility
counterpart. Exact V2321 reported `debug_level=LOW`, `force_upload=0`, and the
A90 source-backed `msm_poweroff` dload master switch `1`; the newer S22+
`qcom_dload_mode` path is absent on this 4.14 kernel. Verification 005 then
recovered the exact outer/inner XBL gates, and Verification 006 captured the
live fields before any write.

The host-only `SHRM_MEM.BIN` decoder is complete. It derives, rather than
duplicates, Experiment 012's ordered plan and labels all `430 + 64 = 494`
staged words in the real 64-KiB dump. Verification 012 acquired it through
Samsung `04e8:685d / MSM_UPLOAD`, SHA-256 `409550ad…`; Qualcomm 05c6 Sahara/qdl
was the wrong transport. Set 0 is a coherent populated-state candidate (17/18
four-instance MC groups identical, one stable two-by-two split). Set 1 is
refuted as a coherent current snapshot. The staged list does not reach the
separate remapper window at `qhs_llcc + 0x8080`, and no alias or bypass was
observed. The device is restored to LOW and passed a new-boot selftest.

Live Experiment 014 now proves the first silicon-side transform result. A
single-SG non-secure ION CMA allocation was bound to stable PA
`0xf0400000..0xf13fffff` and mapped write-combine. Symmetric row-reopen timing
over 64 PA pairs recovers a three-dimensional GF(2) bank row space in which
rank-relative PA bits `16..23` are XORed with PA13..PA15. Four held-out kernel
vectors and four one-bank-bit negatives remain separated by a 314 milli-tick
p10/p90 gap. This refutes the XBL no-XOR diagnostic formula as the complete
silicon bank mapping, but does not demonstrate a complete-coordinate alias,
transform writability, protected-memory reach or isolation bypass. A literal
audit of the real SHRM snapshot and all nine exact firmware images finds no
direct mask in SHRM and refutes the apparent TrustZone matches as unaligned
bytes inside 64-bit address tables.

Host-only Experiment 017 now cross-references the exact XBL MC address table
with the SHRM plan and the exact `0x54`-byte helper's static data flow. The pinned table
has 122 nonzero u64 addresses plus a zero terminator, structurally 30 four-
instance MC groups plus two globals. All 12 `qhs_mc +0x400/+0x404/+0x4d0`
candidate addresses are covered; `qhs_mccc +0x118` and
`qhs_mccc_master +0x294` are excluded from this table only. The helper's exact
`0x54`-byte range constructs table-derived reads and conditional copies to a
distinct read-copy buffer; its store-base data flow refutes that helper as a
candidate-register writer. The loops are zero-sentinel-only with no hard
122-entry cap, and static direct-BL reachability is not current-boot execution.
Experiments 015 (normal-RAM alias) and 016 (protected-boundary reach) remain
reserved and `NOT ELIGIBLE`; 017 satisfies neither gate. The overall result
remains Class C transform observation only.

Host-only Experiment 018 Stage 1A inventories the exact XBL literals and
strict STR W/X store-offset candidates for the 12 ranked MC targets. Each
target's single 8-byte table encoding yields both the one aligned u64 match
and the overlapping one aligned u32 match at the same file offset; these are
two views of one table entry, not independent stored literals, and there is no
separate target literal elsewhere. Only base `0x09260000` has an aligned u32
outside that table, at file `0x80154` / VA `0x148bc254` in an RWE segment. The
file-backed PT_LOAD census is RX4/RWE2/RW3, with 6945/5169 recognized STR W/X
forms and 14 matching offsets (RX11, RWE3; seven RX candidates are SP-based).
Stage 1A performs no base/effective-address resolution, so its resolved hit
count is `null`, not zero; its classification remains
`STAGE1A_LITERAL_AND_STORE_OFFSET_CENSUS_WRITER_UNKNOWN`.

Stage 2A then analyzes only the four non-SP RX candidates using a bounded
same-block direct-definition model. It resolves no base and no exact target:
the two long X8 sequences hit the 128-instruction window, the X8 load fails
closed as unsupported, and the X19 path stops at a BL boundary. Its exact
classification is
`NO_RESOLVED_TARGET_STORE_WITHIN_STAGE2A_DIRECT_DEFINITION_RX_MODEL`.
This refutes only that supported direct-definition path, not writer existence;
the seven SP and three RWE candidates plus all other paths remain `UNKNOWN`.
Stage 2B extends only the two Stage 2A window-limit X8 candidates with a
maximum-512 same-block W-wide-move model. It resolves XBL virtual-address value
`0x1489f000` and computes `0x1489f400`/`0x1489f4d0`, neither numerically equal
to a target and both outside file-backed PT_LOADs. VA-to-PA translation and
physical destination remain `UNKNOWN`; this refutes only numeric target
equality within that model, not writer existence. Its classification is
`NO_NUMERIC_TARGET_ADDRESS_MATCH_WITHIN_STAGE2B_W_WIDE_MOVE_RX_MODEL`.
Stage 2C then analyzes the remaining X8 store at `0x146a70c0` through its
unique direct BL caller and retained 48-entry table. The decoded lookup/writer
path yields 48 conservative `table_derived_possible_effective_values`; none
matches the 12 targets. Descriptor `+0x20` eligibility, per-entry execution,
VA-to-PA translation and physical ownership remain `UNKNOWN`; this does not
eliminate other X8 writer paths. Its classification is
`NO_NUMERIC_TARGET_ADDRESS_MATCH_WITHIN_STAGE2C_UNIQUE_DIRECT_CALLER_TABLE_MODEL`.
Stage 2D examines the remaining X19 store at `0x14935bf4` through one direct-BL
caller. The caller statically supplies W0=0; the callee pins the W20 dispatch
and the `CBNZ W0,0x14935ce8` success precondition before constructing
conditional X19 bases. The exact initializer statically assigns `0x1483c904`
to the import slot, and an exact instruction-class audit proves the resolved
target has no X19–X29 definitions. Under explicit normal-return/slot
preservation models, effective value `0x85e9e970` has no numeric match to the
12 targets. Runtime initializer execution, slot currentness, import target
conformance, VA-to-PA identity and physical ownership remain `UNKNOWN`.
Its classification is
`NO_NUMERIC_TARGET_ADDRESS_MATCH_WITHIN_STAGE2D_UNIQUE_DIRECT_CALLER_CONDITIONAL_CALLEE_SAVED_PRESERVATION_MODEL`.
Stage 2E now covers the seven RX candidates whose encoded base is SP. Exact
F1/F2 frame ranges, prologues/epilogues and direct-BL callers are pinned; all
seven STR W/X accesses lie within their local `SUB SP` allocations. The
same-function immediate-control CFG (BL modeled as fallthrough) has no
recognized SP-write-class instruction after allocation on a path to each
candidate; unsupported instruction effects remain `UNKNOWN`. Each range's
explicit memory-writeback audit accounts for exactly four recognized sites (two SP frame
updates and two non-SP writebacks); recognized BR/BLR counts are zero, and the
all-file-backed-executable-PT_LOAD-words direct-entry census finds one external
BL to each function start and zero external entries to interiors. Runtime stack address,
stack integrity, physical destination and execution remain `UNKNOWN`. Its
classification is
`SEVEN_RX_SP_CANDIDATES_ARE_PINNED_STACK_FRAME_STORES_RUNTIME_STACK_ADDRESS_UNKNOWN`.
Experiment 018 broadens no AOP/TZ scope and does not satisfy reserved/`NOT
ELIGIBLE` Experiments 015 or 016. See [Experiment 018](experiments/018-xbl-mc-writer-xref/README.md).

Host-only Experiments 019–022 now extend the static boundary with four
strictly bounded results. Experiment 019 proves only strict syntactic
candidate address/offset-value pair arrays in two key domains, not register
tables or consumers; absolute keys do not hit ranked MC bases, sections and
implicit bases remain `UNKNOWN`, and bounded stored/exact-wide/ORR
materialisation finds `0x00003333` and `0x00300014` absent while
`0x00300033` has two adjacent sequences. No writer absence is claimed.
Experiment 020 proves a bounded register-offset census and exact stores into a
candidate segment, but only `SUPPORTED` treating the largest RWE segment as a
candidate by size/content. Its narrow classifier has a pinned false negative
at `0x14868a50`; controller identity, general walkers, DCB consumers and
writers remain `UNKNOWN`.
Experiment 021 proves seven direct `BL` and zero direct `B` edges to one pinned
bounded-copy target; only five calls are locally labelled `{0,1,2,15,16}` and
two are unlabelled, so other-section/global delivery is `UNKNOWN`, not
refuted. Experiment 022 proves `430/470/122/492` counts for two enumerated
retained-evidence channels and sparse observed density; completeness is
`REFUTED` by known `0x09248080`, while implemented-register coverage remains
`UNKNOWN`. Class C is unchanged and Experiments 015/016 remain `NOT ELIGIBLE`.

Integration validation for the current host-only Experiment 025 record is 22
focused and 556 full unittest PASS, 65 public JSON manifests, Python
byte-compilation, byte-identical regeneration, and two independent
artifact-review PASS results recorded in the
[Experiment 025 integration review](docs/EXP025_INTEGRATION_REVIEW_2026-08-26.md).
The historical Experiment 023 artifact is retained as merge-history evidence
but remains `WITHHELD/NO-GO` and unpromoted: its timing protocol is not
comparable to Experiment 014, PA provenance is missing, and its full GF(2)
matrix is non-unique. `PA24=b1^b2` is `SUPPORTED` only; raw evidence remains
private. Experiment 023R is the separately repaired result described below.

Experiment 024 is `COMPLETED` and integrated. `PROVED`: the exact
`[0x148689a0,0x14868a64)` six-byte XBL walker has the `0x8000` terminator,
`B.EQ` return-before-store, and a conditional 32-bit store of the
zero-extended `LDRB` value; exactly three direct callers select five
XBL-resident table alternatives plus a selector-`0xf` zero-count/no-pointer
path. The selector unions contain 53 and 127 unique offsets, 170 in their
cross-alternative syntactic superset, and 221 nonterminator records. The two
pinned design-source UFS blocks are byte-identical, and under initialized-base
retention the 170 symbolic destinations lie in the broader `ufshc` `ufs_phy`
resource. `SUPPORTED`: this is a table-driven positive control conditional on
base retention and store reach. `UNKNOWN`: current base due to the unresolved
runtime-BSS `BLR X9` at `0x1486ac1c`, selector/runtime execution, reached-store
subset, flag semantics, live-DTB equality, DCB semantic alias/global
consumer/writer, DDR/MC relation, GF(2), and alias/bypass. All mappings are
conditional symbolic supersets, not current destinations. Class C is
unchanged; Experiments 015/016 remain `NOT ELIGIBLE`.

Experiment 025 is `COMPLETED` and integrated from commit `d743150` (parent
`a68d2f1`). `PROVED`: the exact platform-query helper
`[0x1486abec,0x1486acac)` has caller `0x1486847c` with `X0=SP+0x10`, not main
context `X19`; it loads, addresses, and reloads slot `0x14890590`, and pins
semantic `MOVZ/MOVK` service ID `0x02000139`. The static seed derives
`X0=0x14875668`, outer record `X1=0x14875590` with count five, then
descriptor `0x14824ab8` -> factory `0x1484a880` -> constructed candidate
`0x1488f418` -> inline vtable `0x14824ad0` + `0x48` -> callback `0x1484a9d4`.
The bounded callback path `0x1484a9d4 -> 0x1484a730 -> 0x1484a824 ->
0x1484aa30 -> 0x1484a854` has its recognized output write at `0x1484a9f4`
to helper `SP+0xc`; nested recursion/status writes are only at
`0x1488f3f9`, `0x14890ba0`, and `0x14890b90`, with one decoded MMIO read at
`0x01fc8004` and zero recognized MMIO writes in the bounded helper. The
all-executable census is conservative coverage, not arbitrary-write absence.
`SUPPORTED`: intended conditional binding can populate the slot and the
recognized callback flow does not write caller context `+8`. `UNKNOWN`: runtime
registration/order, slot value/object identity, actual `BLR X9` target, alternate
BSS mutation/global aliases/unsupported writes, full `0x01d80000` base
currentness, and live mapping/authority. Experiment 024's UFS mapping remains
conditional; Class C is unchanged and Experiments 015/016 remain
`NOT ELIGIBLE`. See the
[Experiment 025 integration review](docs/EXP025_INTEGRATION_REVIEW_2026-08-26.md).

Experiment 026 is `COMPLETED` and integrated from commit `0305a03` as
host-only, read-only static analysis. `PROVED`: independently pinned
registration helpers `[0x1482ecb4,0x1482edac)`, the initializer loop
`[0x1482edac,0x1482f0b4)`, table header `[0x14875534,0x14875568)` with count
two, row start `0x14875538`, cursor `0x1487554c`, and derived stride `0x18`.
The registration node is 24 bytes (object, identifier, next at `+0x0/+0x8/
+0x10`) with list head `0x14890f60`. `PROVED`: bounded bootstrap, veneer,
alternate, dispatcher, and caller local/control/data edges include the
dispatcher base/stride/index guard and symbolic pointer escape
`0x146b30c0 + runtime_index*0x3f8`, modeled index `0..1`, not an exact runtime
base. `SUPPORTED`: the memory-only initializer pool has shape
`[0x146b30c0,0x146b38b0)`, two-row `0x3f8` geometry. Pool contents and runtime
values remain `UNKNOWN`.

The complementary census scans 847,465 executable words, excludes 622 words
covered by the Experiment 025 dependency, and recognizes 9 direct accesses
(3 writes, 6 reads) plus 2 pointer escapes. It finds zero recognized writes
whose actual access intervals overlap slot `[0x14890590,0x14890598)`. The
bounded result is `ORDER_OPEN` and
`PROVED_BOUNDED_NO_RECOGNIZED_SLOT_MUTATION`; this is not global writer
absence. Runtime execution/order, slot value, object identity, `BLR` target,
base currentness, and writer absence remain `UNKNOWN`. Validation is 25
focused and 581 full unittest PASS, Python byte-compilation, JSON safety,
byte-identical regeneration, mode `0644`, and exact-XBL plus final decoder
hostile-review `PASS`, recorded in the
[Experiment 026 integration review](docs/EXP026_INTEGRATION_REVIEW_2026-08-26.md).
Class C is unchanged; Experiments 015/016 remain `NOT ELIGIBLE`. Experiment
027 is now `COMPLETED` and integrated from commit `7aa1df7` as a host-only,
read-only bounded CFG/dataflow result. Across 73 analyzed sites (65 of 67
register-offset sites after two dependency-owned exclusions, plus all 8
computed-address idioms), the implemented model returns 71
`INDIRECT_OR_UNSUPPORTED`, 2 `NO_TARGET_WITHIN_MODEL`, zero
`DCB_CONSUMER_PATH`, and zero `MC_OR_SHRM_SYMBOLIC_TARGET`. The latter zeros
are bounded-model results, not global absence claims. Two nonexclusive
`SECTION_READER_PROXIMITY_ONLY` hypotheses remain non-destination leads:
`0x148aa758` is signed `-2528`/absolute `2528` from reader `0x148ab138`, and
`0x148ab4f8` is signed `960`/absolute `960` from the same reader; threshold is
`0x1000`, with no link proof. Runtime base/current destination, execution,
writer/global consumer identity, aliases, register semantics, and unsupported
paths remain `UNKNOWN`.

The integrated artifact is
`evidence/manifests/027-dcb-consumer-writer-complement-20260826-01.manifest.json`
(334,847 bytes, mode `0644`, SHA-256
`d11785969f16ba09155a2305eefd091158abfc515bc64cf94cb34d573a302277`).
Validation is 35 focused and 616 full unittest PASS in 86.100 s, Python
byte-compilation, 67 public JSON manifests parsed, two fresh byte-identical
generations, public safety/no-clobber checks, and independent hostile review
`PASS` after fixes; see the [Experiment 027 integration review](docs/EXP027_INTEGRATION_REVIEW_2026-08-26.md).

Experiment 029 is `COMPLETED` and integrated from commit `a495bdc` as a
host-only, read-only inventory of the 71 exact Experiment 027 fail-closed site
ranges. It proves 1,992 range occurrences / 1,180 unique VAs in the scanned
domain, with a 352-occurrence / 219-unique-VA / 197-unique-word unsupported
frontier. The four syntactic extension families rank as
`BITFIELD_IMM` (120 occurrences), `AND_SHIFT` (37), `EOR_SHIFT` (2), and
`BIC_SHIFT` (2); source provenance, reachability and decoder safety remain
explicitly `UNKNOWN`/`NOT_CLAIMED`. Its integration review records 17 focused
and 633 full unittest PASS in 84.985 s, 68 public JSON manifests, deterministic
repetition, and final hostile review `PASS`.

Experiment 031 is `COMPLETED` and integrated from artifact commits `cd9f26e`
plus reconciliation repair `12a8ebe` as the source-qualified
scalar-plus-dispatch follow-up. It selects 283 occurrences /
160 unique VAs / 148 unique words, reaches 250 selected events (33 selected-
not-reached; family/label mismatches and events outside the selected domain
are zero), and retains a 69-occurrence / 59-unique-VA / 49-unique-word
residual across 20 sites. The combined v2 model transitions 51 of 71 sites to bounded
`NO_TARGET_WITHIN_MODEL`; 20 remain `INDIRECT_OR_UNSUPPORTED`. This is
explicitly `V2_MODEL_ONLY` and `NO_ABSENCE_CLAIM`, and the 51 result depends on
the 143-event/62-site `DIRECT_CONTROL_DISPATCH_REPAIR` (with repair: 48
no-target/14 fail-closed; without: 3/6), not scalar-only closure. Its
integration validation is 19 focused and 652 tracked full unittest PASS in
85.226 s (maximum RSS 220,684 KiB, no swaps), 69 public JSON manifests,
byte-identical fresh generations, QEMU 280/280, and final reconciliation
hostile review `PASS`; the checked manifest is 1,327,118 bytes, mode `0644`,
SHA-256 `51a187195c16eb609d337305540fc6d20a09297f5ab76b054497c5c58c3a2e86`.
See the
[Experiment 031 integration review](docs/EXP031_INTEGRATION_REVIEW_2026-08-26.md).

Experiment 032 is `COMPLETED` and integrated from artifact commit `d46c44c`
after docs commit `e063181` as a host-only, read-only source-qualified
arithmetic extension. It retains the exact 031 scalar-plus-dispatch semantics
and adds only Arm-qualified `MADD/UMADDL`, shifted `EOR`, and shifted `BIC`.
The combined selection is 298 occurrences / 175 unique VAs / 162 unique words,
reaches 264 selected events (34 selected-not-reached), and adds 15 arithmetic
rows across seven sites (14 reached: `MADD` 3, `UMADDL` 7, `EOR` 2, `BIC` 2).
The bounded result transitions 55 of 71 baseline sites to
`NO_TARGET_WITHIN_MODEL`; 16 remain `INDIRECT_OR_UNSUPPORTED`. Relative to
031, sites 1, 36, 37, and 52 transition with zero regressions. The residual
is 54 occurrences / 44 unique VAs / 35 unique words across 15 sites:
`PAIR_MEMORY` 48, `SIGN_EXTENDING_MEMORY` 2, and `SYSTEM_CONTROL` 4.
The inherited 031 full-record equivalence is exact for 250 scalar events,
143 direct-control events, and 23 taint-kill events. Zero DCB-consumer and
MC/SHRM symbolic-target paths are promoted; writer absence and current
destination remain `UNKNOWN`. Validation and artifact pins are recorded in the
[Experiment 032 integration review](docs/EXP032_INTEGRATION_REVIEW_2026-08-26.md).

Experiment 033 is `COMPLETED` and integrated from artifact commit `56b5ffa` as
a host-only, read-only v4 extension of the exact 032 model. The complete 029
frontier is selected as 352 occurrences / 219 unique VAs / 197 unique words;
308 events are reached and 44 selected occurrences are not reached. The
inherited 032 record is exact for 264 reached extension events, 143 direct
control events, and 23 taint-kill events. The 44 new residual events are
`LDP` 38, `STP` 3, `LDRSW` 1, `LDRSB` 1, and `DAIFClr` 1; the three `STP`
instructions publish six lane observations.

`PROVED`: the bounded site result is 70 `NO_TARGET_WITHIN_MODEL` and one
`INDIRECT_OR_UNSUPPORTED`, with the latter remaining at site 35. No bounded
`DCB_CONSUMER_PATH` or `MC_OR_SHRM_SYMBOLIC_TARGET` path is promoted.
`UNKNOWN`: global writer identity/absence, current physical destination,
protected-memory semantics, and the runtime exception level or
`CheckDAIFAccess` outcome for `DAIFClr`. Class C remains unchanged and
Experiments 015/016 remain `NOT_ELIGIBLE`.

The checked public manifest is 2,017,356 bytes, mode `0644`, SHA-256
`606723e5125d661c800b167133f2a9b69a3b8d47361b39176665a49be539e598`.
Validation is 15 focused and 685 full unittest PASS, with full-discovery
maximum RSS 253,944 KiB and zero swap, byte-identical fresh publications,
and independent hostile review `PASS` with no P0–P2 findings. Details and
artifact pins are in
[EXP033_INTEGRATION_REVIEW_2026-08-26.md](docs/EXP033_INTEGRATION_REVIEW_2026-08-26.md).

Experiment 034 is `COMPLETED` in artifact commit `d5d8046`. It proves the
guarded five-entry table at `0x14824cf0`, four unique local targets, and four
CFG-complete in-memory direct-edge resolutions. The composed bounded result is
71 `NO_TARGET_WITHIN_MODEL` / zero fail-closed sites, with no bounded DCB
consumer or MC/SHRM symbolic target. The original 71 Experiment 033 site
records remain verbatim and the composed result is published separately.
Runtime `BR`/direct-`B` equivalence, execution, table contents, current
destination, global writer/consumer absence, protected-memory semantics and
security effect remain `UNKNOWN`. Validation is 14 focused and 699 full
unittest PASS; final hostile review is `PASS` after repairing a `CMP W` width
mask. See the
[Experiment 034 integration review](docs/EXP034_INTEGRATION_REVIEW_2026-08-26.md).

The external line is now reconciled at exact parent `247b0e1`; later moving-
branch commits are excluded. `PROVED` in allocation-offset/model coordinates:
023R records 66 summaries/58 unique differences, a unique rank-three kernel
and model bit-24 contribution `0b110`. Physical PA24/rank/base attribution is
only `SUPPORTED_WITHIN_MODEL` because all pagemap records are `BLIND`. 028's
zero matches are limited to 494 observed registers/274 nonzero and tested
numeric encodings. 029A deterministically extracts ABL and proves bounded
stored-literal/triple negatives while runtime participation and live DT remain
`UNKNOWN`. 030 preserves each phase and refutes only the inference that upward
class departure proves an independent channel selector; PA9/PA10 physical roles
remain `UNKNOWN` and phase-D PA10 is `INCOMPLETE`.

Reconciliation validation is 296 focused and 995 full unittest PASS; fresh
manifests are byte-identical/mode `0644`, and independent hostile review is
`PASS`. See
[the external-line reconciliation](docs/EXTERNAL_LINE_RECONCILIATION_2026-08-26.md).
Class C and Experiments 015/016 eligibility remain unchanged.

Verification 015 runtime invariance is now repaired and integrated from exact
retained inputs rather than by merging the later branch. `PROVED` in
allocation-offset/model coordinates: six condition-labelled 51-key sets, four
clean zero-disagreement comparisons, and one weak L762 comparison with exactly
two excursions that remains `REPEAT_REQUIRED` and keeps
`all_invariant=false`. Six independently split repeat groups cover both
excursions and contain zero repeated flips without promoting that primary
status. The retained bus-vote sweep is six levels × two, not eleven, and is
excluded from DDR-frequency/transform-transition inference. Runtime/reboot/
coldboot identities are only `SUPPORTED_BY_UNRETAINED_OPERATOR_REPORT`;
pagemap is `BLIND`, and action/final-state receipts are incomplete. Validation
is 44 focused and 1,039 full serial tests with hostile-review `PASS`; see the
[Verification 015 integration review](docs/VERIFICATION015_INTEGRATION_REVIEW_2026-08-27.md).

Verification 016 is now independently repaired from three exact retained raw
files. `PROVED` in allocation-offset/model coordinates: independent model-bit
25/26/27 splits, equal-contribution matches `[14,21]`, `[19]`, `[13,20]`, two
three-column passes whose verdicts agree before and after combination, and 7/7
model-derived labels in the separate held-out file. The historical `17/17`
run is not retained, and the external `192/170/506` tuple is not coherent with
either retained pass or their combine. Pagemap remains `BLIND`; physical PA,
base/alignment and effective contiguity remain `UNKNOWN`. Validation is 23
focused and 1,062 full serial tests with hostile-review `PASS`; see the
[Verification 016 integration review](docs/VERIFICATION016_INTEGRATION_REVIEW_2026-08-27.md).

Class C and numbered Experiments 015/016 eligibility remain unchanged.
Verification 017 is unblocked only for a separate audit and is not promoted.
The next highest-information iteration is a repaired, fully retained normal-RAM
storage-identity baseline: harden the external Verification-018 oracle, then
reacquire its reversible camera-preview allocation run because the historical
public manifest has no retained raw transcript or sufficient provenance.

Claim vocabulary is deliberately closed:

- `PROVED`: directly demonstrated by named source, artifact, or repeated result.
- `SUPPORTED`: multiple observations support the claim, but a decisive link is missing.
- `HYPOTHESIS`: falsifiable explanation with a stated prediction.
- `UNKNOWN`: evidence is presently insufficient.
- `REFUTED`: named evidence contradicts the claim.

Start with [STATUS.md](STATUS.md), then [docs/ARCHITECTURE_MAP.md](docs/ARCHITECTURE_MAP.md)
and [docs/EXPERIMENT_MATRIX.md](docs/EXPERIMENT_MATRIX.md). The cache/VA/PTE/
DMA/IOMMU controls for a future normal-RAM proof are specified in
[docs/NORMAL_RAM_ALIAS_DESIGN.md](docs/NORMAL_RAM_ALIAS_DESIGN.md).

Exact live `xbl/xbl_config/aop/devcfg/tz/hyp/abl` artifacts were acquired in
Experiment 004. Raw bytes remain private; the first static reconstruction is in
[research/live-firmware-static-recon.md](research/live-firmware-static-recon.md).
Experiment 006 follows the exact DCB/SHRM path into the concrete four-instance
ICB/LLCC remapper; see
[research/xbl-shrm-icbcfg-recon.md](research/xbl-shrm-icbcfg-recon.md).
Experiment 007 records both the retired generic path and the completed fixed
inline control/read comparison; see
[experiments/007-kernel-remapper-adapter/README.md](experiments/007-kernel-remapper-adapter/README.md).
Experiment 008's exact evidence recombination is in
[experiments/008-remapper-boundary/README.md](experiments/008-remapper-boundary/README.md).
Experiment 009's consumed XPU policy and permission reconstruction is in
[experiments/009-xpu-policy/README.md](experiments/009-xpu-policy/README.md).
Experiment 010's QHEE/TZ authority split and dynamic BIMC initializer are in
[experiments/010-xpu-initializer/README.md](experiments/010-xpu-initializer/README.md).
Experiment 011's exact diagnostic coordinate formula and DCB/SHRM register-token
inventory are in
[experiments/011-dram-coordinate-map/README.md](experiments/011-dram-coordinate-map/README.md).
Experiment 012's exact SHRM interpreter and read-only section-16 conclusion are
in
[experiments/012-shrm-section16-interpreter/README.md](experiments/012-shrm-section16-interpreter/README.md).
Experiment 013's exact SHRM workspace policy and fixed live-probe preparation
are in
[experiments/013-shrm-snapshot-boundary/README.md](experiments/013-shrm-snapshot-boundary/README.md).
Experiment 014's live ION timing, recovered GF(2) bank row space, controls and
literal-attribution audit are in
[experiments/014-dram-conflict-timing/README.md](experiments/014-dram-conflict-timing/README.md).
Experiment 017's exact XBL table/read-copy cross-reference is in
[experiments/017-xbl-mc-snapshot-xref/README.md](experiments/017-xbl-mc-snapshot-xref/README.md).
Experiment 018's Stage 1A/Stage 2A/Stage 2B/Stage 2C/Stage 2D/Stage 2E XBL writer cross-reference is in
[experiments/018-xbl-mc-writer-xref/README.md](experiments/018-xbl-mc-writer-xref/README.md).
Experiment 019's strict DCB pair-array inventory is in
[experiments/019-dcb-register-programming/README.md](experiments/019-dcb-register-programming/README.md).
Experiment 020's bounded XBL consumer and register-offset cross-reference is in
[experiments/020-xbl-dcb-consumer-xref/README.md](experiments/020-xbl-dcb-consumer-xref/README.md).
Experiment 021's bounded-copy delivery audit is in
[experiments/021-dcb-delivery-paths/README.md](experiments/021-dcb-delivery-paths/README.md).
Experiment 022's two-channel observation-coverage audit is in
[experiments/022-observation-coverage/README.md](experiments/022-observation-coverage/README.md).
Experiment 024's exact XBL six-byte walker is in
[experiments/024-xbl-six-byte-walker/README.md](experiments/024-xbl-six-byte-walker/README.md),
and Experiment 025's platform-query binding is in
[experiments/025-xbl-platform-query-binding/README.md](experiments/025-xbl-platform-query-binding/README.md).
Verification 001's independent re-derivation of the load-bearing static claims
is in
[experiments/verification-001-independent-claim-audit/README.md](experiments/verification-001-independent-claim-audit/README.md).
Verification 002's exact XBL `SHRM_MEM.BIN` descriptor and raw-dump consumer
chain are in
[experiments/verification-002-shrm-dump-export/README.md](experiments/verification-002-shrm-dump-export/README.md).
Verifications 003/004's live A90 property-free dump-gate inventory is in
[experiments/verification-003-a90-rawdump-eligibility/README.md](experiments/verification-003-a90-rawdump-eligibility/README.md).
Verification 005's exact XBL outer/inner gate reconstruction is in
[experiments/verification-005-xbl-rawdump-gate-static/README.md](experiments/verification-005-xbl-rawdump-gate-static/README.md).
Verifications 006–014's bounded `param`, reboot, trigger, and recovery sequence
is in
[experiments/verification-006-a90-param-debug-live/README.md](experiments/verification-006-a90-param-debug-live/README.md).
The real Samsung Upload dump and set qualification are in
[experiments/verification-012-a90-samsung-upload-shrm/README.md](experiments/verification-012-a90-samsung-upload-shrm/README.md).
The exact A90 TWRP code-only System transition is documented in
[docs/A90_TWRP_CODE_BOOT.md](docs/A90_TWRP_CODE_BOOT.md).

Raw dumps, device identifiers, boot/firmware images, and full transcripts are
kept below `evidence/private/` and ignored by Git. Redacted hash manifests are
kept in `evidence/manifests/`.

## Upstream

This research is derived from the local **`android-native-init-lab`** project
(`Temmie-Tem/android-native-init-lab`), which builds a minimal native
Linux-style userspace on Android vendor kernels. That project supplies the
entire platform this repository observes from; none of it originates here.

| Used here | Supplied by upstream |
|---|---|
| V2321 runtime, `pass=11 warn=1 fail=0` selftest | A90 native init baseline |
| `A90-LNX` / `04e8:6861` ACM bridge | USB ACM/NCM stack |
| REPL slide recovery, peek/call, and its call-safety classifier | `workspace/public/src/scripts/revalidation/a90_repl.py` |
| TWRP code-only boot, 60,882,944-byte boot-prefix readback | F1 boot-only transfer process |
| Verified rollback, no-replay, target isolation, health closure | `AGENTS.md` safety contract and `DEVICE_ACTION_PROCESS_V2.md` |

Upstream device-action risk tiers (`H0` host-only, `D0` connected read-only,
`D1` attended non-partition, `F1` boot-only transfer, `R1` privileged
root-data) are the vocabulary behind this repository's experiment design. In
upstream terms, Experiments 008–012 and Verifications 001–002 are `H0`;
Verifications 003–004 are `D0`;
Experiments 001/005/006 live capture is `D0`; and the boot-candidate
transitions in Experiments 007 and 013 are `F1`.

### Operating policy for this derived project

Upstream governance is deliberately **not** inherited wholesale. This project
runs under a single binding constraint set by the maintainer:

> Anything that cannot permanently brick the device may be implemented and
> executed quickly, without the upstream per-action approval ladder.

Practically, that draws the line at persistence rather than at hazard:

| Permitted — volatile, recovered by power cycle | Forbidden — irreversible |
|---|---|
| Controller/remapper/MCCC/MC MMIO writes | `xbl`, `xbl_config`, `tz`, `hyp`, `devcfg`, `aop`, `abl` partition writes |
| Any non-persistent register mutation | QFPROM/eFuse writes (one-time programmable) |
| Watchdog reset and warm reboot | RPMB, secure storage, anti-rollback counters |
| Boot-partition candidates with verified rollback | GPT/partition-table edits; interrupting a partition write |

The bootloader-class partitions are the real boundary: corrupting them leaves
no recovery path on this device without an authorized firehose programmer, and
upstream `AGENTS.md` permanently forbids the `qdl`/Sahara path for the same
reason.

The recoverable side of that line is empirically demonstrated, not assumed:
Experiments 007 (twice) and 013 (once) each ended in `Non Secure Watchdog
Bark`, warm reset, intact V2321 by full-prefix SHA-256, and a passing native
selftest.

Two consequences are recorded deliberately:

- Some gates in this repository are stricter than the policy above. In
  particular `STATUS.md` section N withholds a remapper write partly for
  unknown "watchdog/recovery behavior", which the three retained resets now
  establish. Where a gate and this policy disagree, the gate is the
  conservative historical position, not a safety requirement.
- Device-state history is split. Upstream's `CAMPAIGN_LEDGER_A90.md` does not
  record this project's device actions, so upstream alone is not a complete
  account of the A90's physical state.
