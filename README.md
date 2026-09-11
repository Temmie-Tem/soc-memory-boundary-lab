# SDM855 Memory Boundary Lab

**English** · [한국어](README.ko.md)

Evidence-led research into the final system-physical-address to DRAM mapping on
Samsung SM-A908N / Qualcomm SM8150.

The central question is whether a Normal World physical address can be checked
by one protection layer but later transformed to a different protected DRAM
destination. This repository does **not** assume the AMD Skitter Creek result
applies to Qualcomm.

**This repository contains no exploit.** At publication the work is classified
`CLASS C (TRANSFORM ONLY)` / `NOT_ELIGIBLE`: no alias or protection bypass has
been observed, and no DDR/controller, XPU, SMMU, SCM, EL2, EL3, or
protected-memory write has been performed. Every finding carries one of
`PROVED`, `SUPPORTED`, `HYPOTHESIS`, `UNKNOWN`, or `REFUTED` — read a label as
exactly what it says and no further. [`SECURITY.md`](SECURITY.md) states the
disclosure posture, including what happens if this research ever does reach a
bypass.

The work is done on hardware the author owns. No firmware is redistributed
here: the published records are derived analysis bound to inputs by hash, not
the inputs themselves. See [`NOTICE`](NOTICE).

This is a derived project of
[**android-native-init-lab**](https://github.com/Temmie-Tem/android-native-init-lab),
which supplies the entire platform it observes from — the A90 native runtime,
its ACM bridge and REPL — and the device-safety contract it inherits. See
[Upstream](#upstream) for the exact division of what comes from where.

Current phase: source reconstruction plus bounded, source-backed live
normal-RAM observation and host-only frontier qualification. Experiment 007
first retired a generic REPL mapping path after a watchdog before its intended
MMIO read. A fixed inline no-load control later passed; the paired candidate's
single fixed 32-bit load produced no value and was followed by a retained
`Non Secure Watchdog Bark`. `SUPPORTED`, not `PROVED`: the load caused the
stall. V2321 was restored by verified boot-prefix readback and passed final
native health. No DDR/controller, XPU, SMMU, SCM, EL2, EL3, or
protected-memory write has been performed.

## Findings by experiment

### Live Verifications 005–014 — the gated diagnostic track

Live Verifications 005–014 have now completed the gated diagnostic track. Exact
XBL static analysis proved that MID alone admits the inner vendor path while a
panic-supplied dload cookie/restart reason supplies the outer trigger. A
byte-exact 10-MiB `param` capture proved FMM, force-upload, and dump sink were
zero; only the four-byte debug field was changed, verified, and finally
restored. One source-backed SysRq panic was dispatched without replay.

### Experiment 008 — the live DCB and remapper row, and the six-slot XBL writer

Host-only Experiment 008 then resolved the exact live DCB and remapper row from
the retained boot records, pinned the six-slot 36-bit XBL writer, and bound
TrustZone `BIMC_MPU0..3` records to `qhs_llcc + 0xe000` beside each remapper at
`+0x8080`. This narrows the ownership question but does not prove policy
coverage, post-boot mutability, an alias, or a bypass.

### Experiment 009 — static policy coverage for the tested instance-0 page

Host-only Experiment 009 now proves static policy coverage for the tested
instance-0 page. Both exact TrustZone selector branches place `0x09248080` in
enabled, TZ-owned `DC_NOC_BROADCAST_MPU` region 11 with exact raw permission
words and decoder-derived client values; exact devcfg has `disable_xpu_ac=0`. The
legacy bit-3 HLOS predicate is non-discriminating. The fixed-load non-return is
confirmed, but XPU, QHEE/stage-2, fabric/power, and instrumentation remain live
causal alternatives. Decoded syndrome values and final runtime policy readback
are absent.

### Experiment 010 — the missing initializer boundary

Host-only Experiment 010 now resolves the missing initializer boundary.
QHEE's exact `hyp_assign` intercept enforces ownership through its local
stage-2/SMMU access-control path, while a separate same-ID TrustZone fallback
reaches dynamic `BIMC_MPU0..3` reconfiguration. The HLOS-visible XPU toggle
cannot disable any XPU because its exact allowed-disable count is zero. Both TZ
policy branches also cover all four remapper and BIMC configuration apertures
with broad TZ-owned raw records. Effective initiator/client access, overlap
precedence, live instance selection, the final DRAM transform, and
post-transform protection ordering remain `UNKNOWN`; this is not Class A/B
closure of the overall AMD attack class.

### Experiment 011 — the XBL Quest DDR diagnostic formula

Host-only Experiment 011 recovers an exact XBL Quest DDR diagnostic formula.
For the retained 6-GiB topology its rank boundary is `0x140000000`, exactly
the selected remapper row's rank-1 destination. Rank-relative PA bits map
linearly and bijectively to row/bank/channel/column, with no XOR and no alias in
that bounded formula. Selected DCB section 16 also parses into two exact token
sets whose base tokens match SHRM-visible MCCC/MC/DDRSS pages. Hidden hardware
transform state, token semantics, mutability, and protection ordering remain
`UNKNOWN`; no alias or bypass has been observed.

### Experiment 012 — the Xtensa SHRM section-16 consumer

Host-only Experiment 012 then recovers the exact Xtensa SHRM section-16
consumer. Its helper computes `(base_page << 12) + (offset_token << 2)` and
reads each 32-bit register into a SHRM snapshot buffer. Both exact callsites
pass the read direction; the selected lists produce 430 and 64 register-word
reads and no transform-write stream. Runtime register values and any indirect
reverse-direction path remain `UNKNOWN`.

### Experiment 013 — the SHRM snapshot workspace inside TZ-owned regions

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

### Verification 001 — auditing the evidence chain itself

Host-only Verification 001 then audited the evidence chain itself. Every
`PROVED` statement here is one agent's interpretation of the exact bytes, and
Experiments 008–013 consume 004/006 conclusions as pinned inputs, so an early
misinterpretation would be inherited downstream. Seven load-bearing static
claims were re-derived from raw bytes without reusing any repository tool, and
all seven were `CONFIRMED`, with no substantive error and two notation issues.
The audit also records a fact the experiments underweighted: the remapper and
SHRM policy regions deny write to **every** client class, not merely to ordinary
HLOS. It verifies static facts only, not their security interpretation.

### Verification 002 — consumers beyond the blocked EL1 path

Host-only Verification 002 traced consumers beyond the blocked EL1 path.
Exact XBL contains and actively enumerates a 26-record crash/download raw-dump
table whose index 19 exports the full `0x09060000..0x0906ffff` SHRM range as
`SHRM_MEM.BIN`, covering both snapshot buffers. This refutes “no firmware
export path exists,” but does **not** prove a normal Android/HLOS interface. A
read-only mounted-SD check found neither `SHRM_MEM.BIN` nor `rawdump.bin`; the
exact A90 firmware used here remains the private Experiment-004 live capture,
not an SD-card artifact.

### Live Verifications 003/004 — the property-free A90 eligibility counterpart

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

### Experiment 017 — the XBL MC address table against the SHRM plan

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

### Experiment 018 Stage 1A — XBL literals and strict store-offset candidates

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

### Experiments 019–022 — four bounded extensions of the static boundary

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

### Experiment 024 — the exact XBL six-byte walker

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

### Experiment 025 — the platform-query helper and its caller context

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

### Experiment 026 — registration helpers, initializer loop and table header

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

### Experiment 029 — inventory of the 71 fail-closed site ranges

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

### Experiment 031 — the source-qualified scalar-plus-dispatch follow-up

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

### Experiment 032 — the source-qualified arithmetic extension

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

### Experiment 033 — the v4 extension over the complete 029 frontier

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

### Experiment 034 — the guarded five-entry table and its direct edges

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

### Verification 015 — runtime invariance repaired from retained inputs

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

A separate host-only bus-vote amendment now pins the retained `msm-bus-dbg`
excerpts: `disp_rsc_ebi` is present among the declared 66 clients, with one
initial 12.8 GB/s vote, a transient 400 MB/s IB vote, and restoration.  It does
not establish a DDR clock transition.  The sanitized amendment is
[published](evidence/manifests/verification-015-bus-vote-amendment-20260827-01.manifest.json)
and [reviewed](docs/VERIFICATION015_BUS_VOTE_AMENDMENT_2026-08-27.md); its
manifest is 5,686 bytes, SHA-256
`066d8fc708c5652cb53abfc78e4286b06ea9ec100cffeef5a10240420fb8582b`.

### Verification 016 — independent repair from three retained raw files

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
Verification 017 has now completed its separate host-only post-decode
granularity audit.  The exact rank-3 relation has a minimum class-change span
of 8 KiB and covers all eight recovered bank
classes in a 64-KiB-aligned 64-KiB span (128 KiB is the arbitrary-base
guarantee) when projected into the retained allocation-offset/model domain;
every listed protected carveout and every explicitly unprotected System RAM
fragment meets that model-projection bound.  Therefore a **bank-only post-decode
check** is `REFUTED` as a separator for those projected ranges.  The finite GF(2)
countermodels also prove that the bank projection alone does not determine
complete-coordinate injectivity.  This does not locate the actual protection
check, establish a complete DRAM coordinate, or prove a downstream mutable
transform. The audit-pin refresh manifest is
[verification-017-protection-bank-granularity-20260829-06.manifest.json](evidence/manifests/verification-017-protection-bank-granularity-20260829-06.manifest.json);
it changes only the pinned `MEMORY_MAP.md` revision and retains the bounded
V017 result.
Validation is 42 focused and 1,132 full serial tests (`skipped=1`, no swaps),
with byte-identical regeneration and no device action.
Verification 018 has now completed one exact, reversible A90 allocation-local
baseline with a retained PASS receipt: both controls fired and all 176 tested
candidate pairs were `DISTINCT` across two trials (`NO_ALIAS` in the exact
one-state offset scope). Pagemap remained `BLIND`, so this is not physical alias
or protected-boundary evidence. The first parser-only target-format incident is
retained separately and had no allocation or write effect. The canonical public
manifest is
[verification-018-a90-20260827-03.manifest.json](evidence/manifests/verification-018-a90-20260827-03.manifest.json).
The Route-2 falsification audit is now complete as a host-only semantic
cross-check.  It finds `SUPPORTED` bounded closure for Q1 (no promoted writer
path in the declared 027/031–034 models) while preserving global writer absence
as `UNKNOWN`.  Q4 remains `UNKNOWN`: 030 inherits the validated rank-3 relation,
but the 029–034 public manifests contain no complete relation-row set to audit.
The sanitized result is
[route2-rank-audit-20260827-01.manifest.json](evidence/manifests/route2-rank-audit-20260827-01.manifest.json).
The audit is 19 focused / 1,151 full serial tests PASS (`skipped=1`, no swaps),
with manifest SHA-256
`ec3ec693768bf1294366c5650ab9c5e76b27f9bdce049c7a6f2b205a00a72fb8`.
The handoff and independent response remain in
[docs/CODEX_HANDOFF_ROUTE2_TERMINATION_2026-08-27.md](docs/CODEX_HANDOFF_ROUTE2_TERMINATION_2026-08-27.md)
and
[docs/ROUTE2_TERMINATION_RESPONSE_2026-08-27.md](docs/ROUTE2_TERMINATION_RESPONSE_2026-08-27.md).

### Verification 019 — integration with retained raw receipts

Verification 019 is now integrated with retained raw receipts.  The original
and an independent second deep-suspend run each passed the baseline and
suspend-corroboration gates, and each reports 0 of 4,194,304 tags moved after
25.090 s and 25.151 s respectively.  The public manifests are byte-identical
to their retained private receipts' analyzer regenerations.  This is
`PROVED`/`REFUTED` only for the tested deep-suspend transition and offset
domain; effective contiguity, complete coordinates, other transitions and
global transform mutability remain `UNKNOWN`.  The cable-attached third run is
retained as `SUSPEND_NOT_REACHED`, not an invariance result.  See the
[V019 integration review](docs/VERIFICATION019_INTEGRATION_REVIEW_2026-08-27.md),
[retention review](docs/VERIFICATION019_RAW_RETENTION_2026-08-27.md), and
[public manifest](evidence/manifests/verification-019-suspend-permutation-20260827-01.manifest.json).

### Verification 020 — the allocation-size gate, actually surveyed

Verification 020 measured the allocation-size gate that had previously been
asserted without a retained survey.  The attempted non-secure heaps are
monotone: `camera_preview` reaches 320 MiB (320 success / 352 failure),
`qsecom` 32 MiB, and `user_contig` 16 MiB.  No attempted heap reaches the
512-MiB reopen threshold, so condition 2 is `NOT_MET` as measured.  This
`REFUTES` the old 256-MiB ceiling and the old 512-MiB span requirement for
PA28.  A later 020M read-only DT receipt proves the advertised heap-30 chain to
`camera_mem_region` at base `0xc2000000`, size 320 MiB; actual allocation
placement and physical-page identity remain `UNKNOWN` until the normal-RAM
test.  Secure/remote heaps were enumerated but withheld, so their capacity
remains `UNKNOWN`.  See
[the retained heap-capacity experiment](experiments/verification-020-heap-capacity/README.md)
and [its integration review](docs/VERIFICATION020_HEAP_CAPACITY_INTEGRATION_REVIEW_2026-08-27.md),
plus [its public manifest](evidence/manifests/verification-020-heap-capacity-20260827-01.manifest.json).

### Verification 020M — live read-only precondition snapshot for the PA28 test

Verification 020M is the live read-only precondition snapshot for that PA28
test.  On the exact A90/SM8150 runtime, heap 30 reported `reg=0x1e` and
`memory-region=0x67a`; `camera_mem_region` reported the same phandle and
`reg=<0,c2000000,0,14000000>`, while `no-map` and `reusable` returned expected
`ENOENT` and `ion,recyclable` was present.  This proves the advertised DT
chain, not that an allocation consumes the entire carveout or that any DRAM
mapping changed.  Class C and `NOT_ELIGIBLE` are unchanged.  See the
[020M review](docs/VERIFICATION020M_INTEGRATION_REVIEW_2026-08-27.md) and
[manifest](evidence/manifests/verification-020m-pa28-dt-20260827-03.manifest.json).

### Verification 021 — residual heap capacity, without mapping its contents

Verification 021 measured the residual capacity of the selected heap without
mapping or touching its contents.  The retained receipt holds 320 MiB from
`camera_preview`, then gets `ENOMEM` for every probe down to 4 KiB; all five
probes succeed before and after release.  This is
`SUPPORTED_WITHIN_RETAINED_RECEIPT`, not an exact-device `PROVED` result,
because the historical receipt lacks same-run target, bridge, command and
health attestation.  Its conditional span interpretation is
`SUPPORTED_CONDITIONAL_ON_020M_CHAIN`; physical page identity, `f(PA28)`,
DRAM coordinates and protection remain `UNKNOWN`.  See the
[021 review](docs/VERIFICATION021_INTEGRATION_REVIEW_2026-08-27.md),
[experiment record](experiments/verification-021-carveout-exhaustion/README.md)
and [redacted manifest](evidence/manifests/verification-021-carveout-exhaustion-20260827-01.manifest.json).

### Verification 020N — the separate host-only timing design

Verification 020N remains a separate host-only timing design; the retained
PA28 acquisition is reduced under Verification 022 below.
Its fixed no-argument probe allocates 320 MiB from heap 30 and measures the
`0x10000000` timing candidate with same-offset, two bank-bit negatives and a
cache-maintenance control.  The host reducer binds the 020M and 021 hashes but
does not claim a live timing result or physical alias; classification remains
`CLASS C (TRANSFORM ONLY)` / `NOT_ELIGIBLE`.  See the
[020N contract](docs/VERIFICATION020N_CONTRACT_2026-08-27.md) and
[experiment design](experiments/verification-020N-pa28-timing/README.md).

### Verification 022 — reducing the retained PA28 timing receipts

Verification 022 has now reduced the retained PA28 timing receipts with a
strict host-only path.  The canonical existence and identification phases
recheck all 3,029 pairs, both same-phase controls, exact phase/cardinality
gates, and `pa_a`/`pa_b`/XOR arithmetic; one of seven rank-3 candidates
conflicts, selecting `f(PA28) = 010 = f(PA14)`.  This is
`SUPPORTED_WITHIN_RETAINED_RECEIPT` / `SUPPORTED_MODEL_EXTENSION`, not a new
device run: same-run target, bridge, argv, timestamp, final health and the
historical binary are `UNKNOWN_UNRETAINED`/not retained.  The repaired C probe
is fixed to the reviewed normal-RAM surface and was not executed in the
hardening pass.  No protected-memory, controller, MMIO, SMC, partition or
firmware write occurred; `CLASS C (TRANSFORM ONLY)` and `NOT_ELIGIBLE` remain
unchanged.  See the [022 experiment record](experiments/verification-022-pa28-relation/README.md),
[contract](docs/VERIFICATION022_CONTRACT_2026-08-27.md),
[integration review](docs/VERIFICATION022_INTEGRATION_REVIEW_2026-08-27.md) and
[redacted manifest](evidence/manifests/verification-022-pa28-relation-20260827-01.manifest.json)
(`6,698` bytes, SHA-256 `f583bd4f4fe30ad4822832e708edd87e2e049333f2a6c0cf014467b5a33bc2d2`).

### Verification 022R — repeating identification on the exact V2321 runtime

Verification 022R then repeated the identification measurement on the exact
`SM-A908N`/`SM8150` V2321 runtime with complete same-run provenance. One fixed
normal-RAM probe dispatch produced 1,802 records and independently rechecked
1,787 pair rows; both bracketing reductions selected only `0x10004000`, with
threshold `369`, yielding `f(PA28)=010=f(PA14)`. The acquisition, cleanup and
final `11/1/0/12` self-test are `PROVED`; the model extension is `SUPPORTED`.
Physical-page identity, aliasing, complete coordinates, mutability, protected
reach and bypass remain `UNKNOWN`. No MMIO/controller/SMC/protected-memory or
partition action occurred, so `CLASS C (TRANSFORM ONLY)` / `NOT_ELIGIBLE`
remain unchanged. See the [022R record](experiments/verification-022R-pa28-live/README.md),
[final review](docs/VERIFICATION022R_INTEGRATION_REVIEW_2026-08-27.md), and
[11,989-byte manifest](evidence/manifests/verification-022r-pa28-live-20260827-01.manifest.json)
(SHA-256 `f88a81bd3aabbd76cf2bcb8575f45d1cca7c29433a0279403d76d3affbfa2ca2`).

The 1b known-aperture reachability checkpoint is a bounded host-only
reconciliation. Both exact selector branches enumerate the same eight known
qhs_llcc-remapper/BIMC candidates, and every candidate has retained broad
TZ-owned raw policy coverage. The legacy bit-3 HLOS marker is false for all of
them, but that predicate is non-discriminating and is not an effective-access
verdict. The tested `0x09248080` narrow row is branch-invariant; the retained
fixed EL1 load produced no value and was followed by a `Non Secure Watchdog
Bark`, while the separate control-node route had one failed read and zero
writes. Direct non-return is confirmed; the refusing agent and effective HLOS
access are `UNDECIDABLE`/`UNKNOWN`. Global reachability, alternate apertures,
final runtime state, ordering, mutability, aliases and bypass remain `UNKNOWN`.
The result is operationally `CLASS C (TRANSFORM ONLY)` / `NOT_ELIGIBLE`. The
audit-corrected 24,739-byte v2 manifest is
[verification-1b-known-aperture-reachability-20260829-02.manifest.json](evidence/manifests/verification-1b-known-aperture-reachability-20260829-02.manifest.json),
SHA-256
`123d44a4f044656b7e9b95dbb832b60cb4ee47aa483500d03fd6eeb6cb90a1ac`;
focused validation is 9/9 PASS and no device action occurred. The
[2026-08-27 review](docs/VERIFICATION1B_REACHABILITY_REVIEW_2026-08-27.md)
is retained as historical provenance; its HLOS interpretation is superseded by
the [current report](docs/FINAL_REPORT_2026-08-29.md).

### Verification 020A — the candidate setter's argument origin

Verification 020A then traced the exact candidate setter's argument origin in
the retained XBL.  The five static stores contain one `XZR` zero and four
incoming-object fields; the sole direct caller at `0x9fc023f0` supplies
`W3=[X0+0x10]`, `X0=[X0+0x18]`, `X1=[X0+0x20]`, and `X2=[X0+0x28]` in the
bounded linear model.  This is symbolic setter/base evidence only: runtime
object values, currentness, physical/DRAM mapping, mutability and protected
reach remain `UNKNOWN`.  The result remains `CLASS C (TRANSFORM ONLY)` and
`NOT_ELIGIBLE`; see
[the 020A integration review](docs/VERIFICATION020A_INTEGRATION_REVIEW_2026-08-27.md)
and the sanitized
[020A manifest](evidence/manifests/020A-setter-base-trace-20260827-01.manifest.json).
The 020A focused suite is 9/9 and the full serial suite is 1,160/1,160 PASS
(`skipped=1`, no swaps); hostile review is `PASS`.

### Verification 020B — the sole direct caller at `0x9fc023c8`

Verification 020B then traced the sole direct caller of the 020A consumer at
`0x9fc023c8`.  The exact caller obtains an opaque `X0` token from
`BL 0x9fc160b8`, constructs a stack object at `SP+0x20`, and passes it to the
consumer.  Within the bounded finite model the four setter arguments resolve
to return-object fields `W3=[return+0x0c]`, `X0=[return+0x18]`,
`X1=[return+0x20]`, and `X2=[return+0x28]`.  The manifest retains these as
symbolic `MEMORY_FIELD` provenance with value `UNKNOWN`; it makes no runtime,
type, currentness, physical/DRAM or MMIO claim.  Classification remains
`CLASS C (TRANSFORM ONLY)` and eligibility remains `NOT_ELIGIBLE`.

The 020B experiment, integration review and sanitized manifest are
[documented here](experiments/verification-020B-caller-object-origin/README.md),
[reviewed here](docs/VERIFICATION020B_INTEGRATION_REVIEW_2026-08-27.md), and
[published here](evidence/manifests/020B-caller-object-origin-20260827-01.manifest.json).
The focused suite is 7/7 and the full serial suite is 1,167/1,167 PASS
(`skipped=1`, no swaps); no device action occurred.  The next non-overlapping
candidate is a bounded static trace of the `0x9fc160b8` return helper, with
runtime execution and all indirect paths still `UNKNOWN`.

### Verification 020C — the return helper itself

Verification 020C traced that return helper itself.  Its exact 12-byte body is
`ADRP X0,0x9fc36000; ADD X0,#0x2c0; RET`, producing static ELF VADDR
`0x9fc362c0`; an executable census finds exactly two direct callers,
`0x9fc22cc0` and `0x9fc26e2c`.  The 48-byte object-field source range is
hash-pinned without publishing raw values.  This is static code/data-flow
evidence only: runtime object contents/type/currentness, writer/mutability,
physical-to-DRAM mapping, protected reach and alias/bypass remain `UNKNOWN`.
Class C and `NOT_ELIGIBLE` remain unchanged.

The 020C experiment, integration review and sanitized manifest are
[documented here](experiments/verification-020C-return-helper-origin/README.md),
[reviewed here](docs/VERIFICATION020C_INTEGRATION_REVIEW_2026-08-27.md), and
[published here](evidence/manifests/020C-return-helper-origin-20260827-01.manifest.json).
The focused suite is 6/6 and the full serial suite is 1,173/1,173 PASS
(`skipped=1`, no swaps); no device action occurred.  The next candidate is a
bounded trace of the second helper caller at `0x9fc26e2c`.

### Verification 020D — the second caller

Verification 020D traced that second caller.  It loads object fields
`+0x28,+0x30,+0x38,+0x0c,+0x18,+0x20` and stores symbolic origins to static
ELF slots `0x9fc3e138`, `0x9fc3e140`, `0x9fc3e148`, `0x9fc3e150`,
`0x9fc3e158`, and `0x9fc3e160`.  Field values, slot semantics, runtime
currentness, mutability, physical-to-DRAM mapping, protected reach and
alias/bypass remain `UNKNOWN`; Class C and `NOT_ELIGIBLE` remain unchanged.
The 020D experiment, review and manifest are
[documented](experiments/verification-020D-second-caller-field-use/README.md),
[reviewed](docs/VERIFICATION020D_INTEGRATION_REVIEW_2026-08-27.md), and
[published](evidence/manifests/020D-second-caller-field-use-20260827-01.manifest.json).
The focused suite is 6/6 and the full serial suite is 1,179/1,179 PASS
(`skipped=1`, no swaps); no device action occurred.  The next candidate is a
bounded consumer/writer census for those six static slots.

### Verification 020E — completing the census

Verification 020E completed that census.  The exact XBL contains 18 unique
direct scalar accesses to the six slots (6 `STR` stores and 12 `LDR` loads).
Caller-saved direct `BL` windows fail closed; X19–X29 continuation is
conditional on an explicit AAPCS64 callee-saved assumption.  The scan retains
95 barriers (8 caller-saved calls and 87 unknown-instruction barriers).  This
is static cross-reference evidence only: global writer/consumer absence, ABI
compliance, runtime values/currentness/execution, slot semantics,
physical-to-DRAM meaning, mutability, protected reach and alias/bypass remain
`UNKNOWN`; Class C and `NOT_ELIGIBLE` remain unchanged.  The experiment,
review and manifest are [documented](experiments/verification-020E-static-slot-census/README.md),
[reviewed](docs/VERIFICATION020E_INTEGRATION_REVIEW_2026-08-27.md), and
[published](evidence/manifests/020E-static-slot-census-20260827-01.manifest.json).
The focused suite is 7/7 and the full serial suite is 1,186/1,186 PASS
(`skipped=1`, no swaps); no device action occurred.  The next candidate is a
bounded load-use trace (020F).

### Verification 020F — the bounded load-use trace

Verification 020F completed the bounded load-use trace.  Each of the twelve
020E loads was followed for 16 instructions in its same executable segment.
The model records 16 downstream use events (10 address-base, 2 arithmetic, 2
register-offset, 1 register-copy, and 1 return) and 11 barriers (4
caller-saved `BL`, 5 recognized control, 2 unknown), with no tainted direct
store reached.  X30 is caller-saved, MOVK stops fail-closed, and CBNZ/TBNZ are
decoded explicitly; the 020E manifest is mechanically hash-pinned.  Runtime
execution/currentness, values, slot semantics, physical-to-DRAM identity,
mutability, protected reach and alias/bypass remain `UNKNOWN`; Class C and
`NOT_ELIGIBLE` remain unchanged.  The experiment, review and manifest are
[documented](experiments/verification-020F-static-slot-load-use/README.md),
[reviewed](docs/VERIFICATION020F_INTEGRATION_REVIEW_2026-08-27.md), and
[published](evidence/manifests/020F-static-slot-load-use-20260827-01.manifest.json).
The focused suite is 9/9 and the full serial suite is 1,195/1,195 PASS
(`skipped=1`, no swaps); no device action occurred.  The next candidate is a
bounded pointer/object resolution trace (020G).

### Verification 020G — pointer/object census over the 020F address-use events

Verification 020G completed the bounded pointer/object census over the exact
020F address-use events.  It retains 12 witnesses: 10 immediate object-field
shaped accesses (7 `LDR`, 3 `STR`) and 2 `UXTX` register-offset
array-element-shaped loads.  Those witnesses occupy 11 unique access VAs,
with one duplicate witness at the shared register-offset VA.  This is
instruction-shape evidence only: runtime base values/currentness, object
semantics, global writer/consumer absence, MMIO/physical/DRAM identity,
mutability, protected reach and alias/bypass remain `UNKNOWN`; Class C and
`NOT_ELIGIBLE` remain unchanged, with no device action.  The experiment,
review and manifest are
[documented](experiments/verification-020G-static-slot-pointer-object-census/README.md),
[reviewed](docs/VERIFICATION020G_INTEGRATION_REVIEW_2026-08-27.md), and
[published](evidence/manifests/020G-static-slot-pointer-object-census-20260827-01.manifest.json).
The manifest is 7,218 bytes, mode `0644`, SHA-256
`f534efeee1e12f18d3af40c107dbc6fbe938eae16d9013aa088d22d7c880af3e`.
Focused tests are 10/10 and the full serial suite is 1,205/1,205 PASS
(`skipped=1`) in 134.596 seconds, maximum RSS 347,740 KiB, zero swap.  The
next candidate is a bounded static-slot function-role/base-origin trace
(020H).

### Verification 020H — function-role/base-origin census over the 020G witnesses

Verification 020H completed the bounded function-role/base-origin census over
the exact 020G witnesses.  Twelve witness rows group into 11 unique access
VAs and 7 return/direct-branch-delimited local blocks.  Nine blocks contain
unsupported forms and remain `UNKNOWN_ROLE_UNSUPPORTED_FORM`; two are
`LOCAL_READ_SHAPED_BLOCK`.  Ten unique accesses
have `STATIC_SLOT_SEED` base definitions, while indexed access
`0x9fc26ea0` is `ARITHMETIC_DERIVED` from a bounded `MADD`.  These are static
role/provenance labels only: true function boundaries, runtime values,
MMIO/physical/DRAM identity, mutability, protected reach and alias/bypass
remain `UNKNOWN`; Class C and `NOT_ELIGIBLE` remain unchanged, with no device
action.  The experiment, contract, review and manifest are
[documented](experiments/verification-020H-static-slot-function-role-base-origin/README.md),
[contracted](docs/VERIFICATION020H_CONTRACT_2026-08-27.md),
[reviewed](docs/VERIFICATION020H_INTEGRATION_REVIEW_2026-08-27.md), and
[published](evidence/manifests/020H-static-slot-function-role-base-origin-20260827-01.manifest.json).
The manifest is 19,314 bytes, mode `0644`, SHA-256
`b306ca67675430314289fd79faa2e53b2d67994807d0b08bd91ced9b625faba2`.
Focused tests are 11/11 and the full serial suite is 1,216/1,216 PASS
(`skipped=1`) in 140.860 seconds, maximum RSS 349,728 KiB, zero swap.  The
next candidate is a bounded caller-context/entry-role trace (020I).

### Verification 020I — caller-context census over the 20 direct-BL sources

Verification 020I completed a bounded caller-context census over the exact 20
direct-BL sources reported by 020H.  Each source/target edge was checked in
the exact XBL and traced backward for at most 16 instructions, stopping at
strict RET X30, direct B/BL, segment boundaries, window limits, or unsupported
forms.  Twelve rows stopped unsupported, six remained `ARGUMENT_OR_UNKNOWN`,
and two were `ARGUMENT_COPY_OR_CONSTANT`; no static-slot-origin caller was
reached in these windows.  This is a bounded negative/unknown result, not a
global absence proof.  True function boundaries, runtime values,
MMIO/physical/DRAM identity, mutability, protected reach and alias/bypass
remain `UNKNOWN`; Class C and `NOT_ELIGIBLE` remain unchanged, with no device
action.  The experiment, contract, review and manifest are
[documented](experiments/verification-020I-static-slot-caller-context-entry-role/README.md),
[contracted](docs/VERIFICATION020I_CONTRACT_2026-08-27.md),
[reviewed](docs/VERIFICATION020I_INTEGRATION_REVIEW_2026-08-27.md), and
[published](evidence/manifests/020I-static-slot-caller-context-entry-role-20260827-01.manifest.json).
The manifest is 12,472 bytes, mode `0644`, SHA-256
`03c463f667142a21641264ec2e4080d9d5f963c67776037ca9d6194a8a621608`.
Focused tests are 11/11 and the full serial suite is 1,227/1,227 PASS
(`skipped=1`) in 151.571 seconds, maximum RSS 356,228 KiB, zero swap.  The
next candidate is a bounded caller-context barrier/opcode inventory (020J).

### Verification 020J — the non-overlapping follow-up

Verification 020J completed that non-overlapping follow-up.  It re-derived the
exact 12 unsupported 020I stops and inspected only each first stop word.  All
12 stop VAs are unique and classify as ordinary strict ARM64 families:
`B_COND` 5, `CBZ_CBNZ` 2, `LDP_STP_PAIR` 2, logical-immediate 2, and
`BITFIELD` 1 (`BFXIL`); the `UNKNOWN_OPCODE` fallback is unused for this exact
set.  This is a bounded opcode inventory, not a function-boundary, runtime,
MMIO, physical/DRAM, ownership or bypass proof.  Class C and `NOT_ELIGIBLE`
remain unchanged, with no device action.  The experiment, contract, review and
manifest are [documented](experiments/verification-020J-caller-context-barrier-opcode-inventory/README.md),
[contracted](docs/VERIFICATION020J_CONTRACT_2026-08-27.md),
[reviewed](docs/VERIFICATION020J_INTEGRATION_REVIEW_2026-08-27.md), and
[published](evidence/manifests/020J-caller-context-barrier-opcode-inventory-20260827-01.manifest.json).
The manifest is 7,657 bytes, mode `0644`, SHA-256
`1fdb1f4ade702fdb2d6ffdc68669a9710c8152e225f89f02fb65c0d10f4c3d55`.
Focused tests are 7/7 and the full serial suite is 1,234/1,234 PASS
(`skipped=1`) in 164.114 seconds, maximum RSS 355,764 KiB, zero swap.  The
next bounded result is recorded below.

### Verification 020K — the operand/target follow-up

Verification 020K completed the non-overlapping operand/target follow-up.  It
re-derived the exact 12 020J unsupported stops and decoded one word per stop:
five `B_COND`, two `CBZ_CBNZ`, two scalar 64-bit `STP` pairs (one offset `+64`,
one pre-index `-16`), two identical 32-bit logical-immediate forms, and one
32-bit `BFXIL` alias.  Conditional targets are four-byte aligned and remain in
the same file-backed executable segment.  The local firmware loader pins the
020K XBL size/hash independently; raw words are retained only as hashes and no
trace continues past a stop.  This is bounded instruction metadata, not a
writer, runtime, physical/DRAM, mutability or bypass proof.  Those properties
remain `UNKNOWN`; Class C and `NOT_ELIGIBLE` are unchanged.  The experiment,
contract, review and manifest are [documented](experiments/verification-020K-caller-context-barrier-operand-target/README.md),
[contracted](docs/VERIFICATION020K_CONTRACT_2026-08-27.md),
[reviewed](docs/VERIFICATION020K_INTEGRATION_REVIEW_2026-08-27.md), and
[published](evidence/manifests/020K-caller-context-barrier-operand-target-inventory-20260827-01.manifest.json).
The manifest is 9,961 bytes, mode `0644`, SHA-256
`90a0cf4d264c64d0d2836b567a2dc8ac5abff7809be839e5131fc7e91e32975a`.
Focused tests are 13/13 and the full serial suite is 1,288/1,288 PASS
(`skipped=1`) in 180.173 seconds, maximum RSS 363,772 KiB, zero swap; the
independent hostile review is `PASS`.  The next discriminator is 020L, a
one-word census of the unique conditional branch landing VAs, still
host-only/read-only and without path continuation.

### Verification 020L — the bounded landing-word census

Verification 020L completed that bounded landing-word census.  It re-derived
the exact seven unique conditional target VAs from 020K and inspected one word
at each: ADRP x2, LDR_UNSIGNED x1, logical-immediate x2, MOV_REGISTER x1 and
scalar LDP x1.  Both the landing-word reader and decoder reject unaligned VAs
before reading; executable file-backed segment checks and source/dependency
hash pins remain in force.  Raw words are hash-only, no target block is
followed, and execution, pointer/PA meaning, MMIO/DRAM identity, mutability,
protected reach and bypass remain `UNKNOWN`.  Class C and `NOT_ELIGIBLE` are
unchanged.  The manifest is 5,109 bytes, SHA-256
`cdb0db05596ad06ae179861a4083e08b116ce283f683dd5fae44efde020f85dc`; focused
tests are 7/7 PASS and no device action occurred.  See
[the 020L review](docs/VERIFICATION020L_INTEGRATION_REVIEW_2026-08-27.md) and
[manifest](evidence/manifests/020L-branch-target-landing-word-inventory-20260827-01.manifest.json).

## Claim vocabulary

Claim vocabulary is deliberately closed:

- `PROVED`: directly demonstrated by named source, artifact, or repeated result.
- `SUPPORTED`: multiple observations support the claim, but a decisive link is missing.
- `HYPOTHESIS`: falsifiable explanation with a stated prediction.
- `UNKNOWN`: evidence is presently insufficient.
- `REFUTED`: named evidence contradicts the claim.

## Where to start

Start with [STATUS.md](STATUS.md), then [docs/ARCHITECTURE_MAP.md](docs/ARCHITECTURE_MAP.md)
and [docs/EXPERIMENT_MATRIX.md](docs/EXPERIMENT_MATRIX.md). The cache/VA/PTE/
DMA/IOMMU controls for a future normal-RAM proof are specified in
[docs/NORMAL_RAM_ALIAS_DESIGN.md](docs/NORMAL_RAM_ALIAS_DESIGN.md).

## Evidence index

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
Verification 017's bank-granularity audit is in
[experiments/verification-017-protection-bank-granularity/README.md](experiments/verification-017-protection-bank-granularity/README.md),
with its sanitized result in
[evidence/manifests/verification-017-protection-bank-granularity-20260829-06.manifest.json](evidence/manifests/verification-017-protection-bank-granularity-20260829-06.manifest.json).
The Route-2 writer/rank audit is in
[experiments/verification-route2-rank-audit/README.md](experiments/verification-route2-rank-audit/README.md),
with its sanitized result in
[evidence/manifests/route2-rank-audit-20260827-01.manifest.json](evidence/manifests/route2-rank-audit-20260827-01.manifest.json).
Verification 020A's setter/base trace is in
[experiments/verification-020A-setter-base-trace/README.md](experiments/verification-020A-setter-base-trace/README.md),
with its sanitized result in
[evidence/manifests/020A-setter-base-trace-20260827-01.manifest.json](evidence/manifests/020A-setter-base-trace-20260827-01.manifest.json).
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
Verification 018's bounded non-secure allocation-local storage-identity oracle and its retained
live disposition are documented in
[experiments/verification-018-alias-marker/README.md](experiments/verification-018-alias-marker/README.md)
and
[evidence/manifests/verification-018-a90-20260827-03.manifest.json](evidence/manifests/verification-018-a90-20260827-03.manifest.json).
The integration and hostile-review record is
[docs/VERIFICATION018_INTEGRATION_REVIEW_2026-08-27.md](docs/VERIFICATION018_INTEGRATION_REVIEW_2026-08-27.md).

## Retained private material

Raw dumps, device identifiers, boot/firmware images, and full transcripts are
kept below `evidence/private/` and ignored by Git. Redacted hash manifests are
kept in `evidence/manifests/`.

## Upstream

This research is derived from the **`android-native-init-lab`** project
(<https://github.com/Temmie-Tem/android-native-init-lab>), which builds a minimal native
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
