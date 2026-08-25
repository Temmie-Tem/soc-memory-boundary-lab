# SM8150 Memory Subsystem Reconstruction

## Source-visible blocks

`PROVED`: Exact target source exposes CPU/interconnect traffic toward LLCC, an
LLCC-to-EBI_CH0 path, a DDRSS configuration slave on CNOC, LLCC cache-slice
registers, LLCC/DDR bandwidth monitors and AOP DDR performance messages.

`PROVED`: Exact XBL has a four-instance qhs_llcc region-remapper register space.
`UNKNOWN`: The exact later IP/fields that map system PA bits to channel/rank/
bank-group/bank/row/column. The Linux source contains no identified SM8150
implementation of that finer mapping.

`PROVED` by Experiment 008: exact retained XBL records resolve the live DCB to
`/6003_0200_1_dcb.bin` and the topology to rank 0 = 3072 MiB, rank 1 =
3072 MiB. Those inputs uniquely select remapper table row 7, with destination
bases `0x80000000` and `0x140000000`.

`PROVED` by Experiment 011: the exact XBL Quest DDR failure reporter uses the
same rank boundary and maps every rank-relative PA bit once into
row/bank/channel/column/byte. The formula is linear and bijective, contains no
XOR, and cannot itself create a PA alias. `REFUTED` by live Experiment 014: it
is the complete silicon bank-selection model.

`PROVED` live by Experiment 014, within rank-relative PA bits `0..23`: the
silicon bank-equivalence relation has rank three and XORs PA16..PA23 with the
PA13..PA15 basis. One equivalent row basis is
`0x9d2000/0xa74000/0x4e8000`. PA9 and PA10 are `SUPPORTED` as two further
independent channel-like selection components. Register ownership, PA24..31
terms, mutability and complete-coordinate aliasing remain `UNKNOWN`.

`SUPPORTED`: The decisive state is in memory-controller/PHY-coupled DDRSS logic
initialized by XBL/DDR DSF/DCB before general RAM becomes usable. Exact live XBL
proves DDR initialization, DCB loading and channel/rank training; the specific
decode writes remain unidentified. Exact-firmware literal search finds no
aligned recovered row mask, so the state may be encoded, split or computed.

## Candidate block/register inventory

The ranking reflects value for the attack-class question, not confidence that a
candidate is EL1-accessible.

| Rank | Candidate | Who/when | Base and offset | Width | EL1 read/write | Reset/boot/lock/owner | Confidence |
|---:|---|---|---|---|---|---|---|
| 1 | Per-channel MCCC token set | `PROVED`: selected section 16 plus exact `qhm_shrm` topology and SHRM read consumer | bases `0x09250000`, `0x092d0000`, `0x09350000`, `0x093d0000`; address formula `(page<<12)+(token<<2)` | 32-bit snapshot reads | `UNKNOWN/UNKNOWN` from EL1; section-16 SHRM path reads into snapshot only | values/reset/boot/lock `UNKNOWN`; no observed write callsite | Highest compact four-channel final-decode observation candidate; mutation `REFUTED` for observed path |
| 2 | Per-channel MC page-token sets | `PROVED`: selected section 16 plus exact `qhm_shrm` topology and SHRM read consumer | roots `0x09260000`, `0x092e0000`, `0x09360000`, `0x093e0000`; ten records through matching subpages | 32-bit snapshot reads | `UNKNOWN/UNKNOWN` | operation values/reset/boot/lock `UNKNOWN`; observed direction is read | Broadest exact finer-decode observation set |
| 3 | MCCC master token set | `PROVED`: exact topology plus section-16 numeric match and read consumer | base `0x090b0000`; set-0 `0xa5`, set-1 `0x0,0xa0,0xa2..0xa8` | 32-bit snapshot reads | XBL boot map class is `NS_DEVICE`; post-boot EL1 read/write `UNKNOWN` | values and lock `UNKNOWN`; observed SHRM direction is read | High global interleave/decode observation value |
| 4 | DDRSS register token set | `PROVED`: exact topology plus section-16 numeric match and read consumer | base `0x090c0000`; set-0 tokens `0x16,0x17,0x2c` | 32-bit snapshot reads | `UNKNOWN/UNKNOWN` | observed SHRM direction is read; values/lock `UNKNOWN` | Small exact global observation set |
| 5 | XBL ICB/qhs_llcc region remapper | `PROVED`: XBL programs it during DDR bring-up; exact row 7 selected | bases `0x09248080`, `0x092c8080`, `0x09348080`, `0x093c8080`; offsets `0x00..0x58` | exact writer uses 32-bit MMIO and 36-bit split address fields | `/dev/mem` and generic REPL routes `REFUTED`; fixed load returned no value and watchdog; write `UNKNOWN` | destination bases known; numeric words/source bases/interleave mask/lock `UNKNOWN`; no-HLOS policy coverage `PROVED` | Exact system-PA remap; final hash role `UNKNOWN` |

Experiment 017 preserves the existing Verification-012 Top-5 order. Exact XBL
table/read-copy coverage raises independent observation confidence for the
three qhs_mc groups at `+0x400`, `+0x404` and `+0x4d0`, but does not increase
their semantic likelihood. The absent MCCC candidates are excluded from this
table only and are not downgraded as transform candidates.

`DC_NOC_BROADCAST_MPU` and dynamic `BIMC_MPU0..3` remain the strongest
protection-ordering candidates. They are omitted from this top-five table
because the ranking here now targets address-transform state rather than
access-control state.

### Negative candidate

`REFUTED`: `mc_virt-base/gem_noc-base 0x09680000` is an exact final MC decode
register block merely because the name contains `mc`. The exact downstream node
uses bypass QoS, shares the same range with GEM_NOC, and the corresponding
upstream virtual-provider register space is described as unused/arbitrary.

## Search result

`PROVED`: Searching the exact SM8150 DTS and Qualcomm kernel drivers for
interleave/swizzle/bank-swap/address-map terms found no SM8150-specific CPU
PA-to-DRAM mapping program. Generic legacy BIMC interleave structures and WLAN
descriptor swizzling are not evidence for this target.

`PROVED`: XBL initializes DDR before Linux and programs a topology-dependent
system-PA region remapper through exact qhs_llcc MMIO windows. `UNKNOWN`: whether
this is the final PA-to-DRAM channel/bank/row transform or an earlier aperture
map followed by finer MCCC/MC decode.

`PROVED`: the exact layout-1 function first disables each instance, writes six
36-bit slots, installs the active-slot mask, then enables each instance. No
distinct lock write exists inside that bounded function. Exact numeric register
words cannot be reconstructed without runtime per-channel source bases and the
rank-interleave mask.

`PROVED` by Experiment 009: the failed instance-0 read address is not an
unclassified hole. Both exact TZ policy branches place it in enabled,
TZ-owned `DC_NOC_BROADCAST_MPU` region 11. Exact conversion grants no standard
VMID/HLOS access, while exact devcfg leaves XPU access control enabled.
`SUPPORTED`: XPU/fabric denial caused the watchdog. `UNKNOWN`: decoded syndrome,
runtime policy-register readback, and a possible sub-aperture clock contribution.

`PROVED` by Experiment 010: BIMC_MPU0..3 have exact registry/error-route entries
and are dynamically programmed by TZ's memory-lock topology fanout, explaining
their absence from both embedded static policy lists. QHEE's same-ID HLOS
`hyp_assign` intercept is separate: it validates ownership and reaches a local
stage-2/SMMU access-control mapper without directly invoking TZ's generic SMC
wrapper.

`PROVED`: both static-policy branches independently protect all four remapper
addresses and all four BIMC configuration bases through `MEMNOC_MS_MPU` region
0 and `CNOC_SNOC_MS_MPU` region 5. Both records are TZ-owned and grant no
ordinary HLOS VMID. The exact HLOS-visible XPU toggle cannot disable any XPU
because its allowed-disable list count is zero.

`PROVED` by Experiment 011/012: section 16 binds exact SHRM-visible
MCCC/MC/DDRSS pages, and the exact SHRM helper scales offsets by four bytes and
reads the computed words into a snapshot buffer at both direct consumers.
`PROVED` by Experiment 013: the complete snapshot workspace has no ordinary
HLOS read/write grant in either exact TZ branch and is covered by three
TZ-owned policy regions. The fixed no-load control passed; the paired one-word
MCCC snapshot load returned no value and ended in a retained non-secure
watchdog reset. This refutes direct EL1 visibility through the tested path.
`UNKNOWN`: exact set-0 semantics, lock state, whether any read register controls
final address decode, any indirect reverse-direction invocation, and where the
data-path check sits relative to hidden/final decode. Repeating the denied
configuration-aperture load cannot answer these questions.

`PROVED` by Verification 002: exact XBL's consumed crash/download raw-dump
catalog covers the entire enclosing SHRM 64-KiB region as `SHRM_MEM.BIN`.
This supplies a concrete post-reset observation candidate without changing
controller state. It does not change the direct-EL1 result: the catalog is not
a normal-HLOS runtime API. Verification 012 later proved retail extraction and
coherent set-0 population.

`PROVED` host-only by decoder commit `9fdd5d6`: the two staged ranges resolve
deterministically to 430 and 64 ordered source-register labels, and neither
range reaches the remapper control window at `+0x8080`. Verification 012 later
acquired one real dump and qualified set 0; no remapper control value was
recovered.

`PROVED` by Experiment 014: normal-world behavior can expose the low-24 bank
row space without reading any configuration aperture. This upgrades the
existence of a finer XOR transform from hypothesis to measured fact while
leaving its register-level attribution and writability `UNKNOWN`. The real SHRM
snapshot has no instance of the seven non-zero recovered row-space masks; the
exact firmware audit found zero aligned u32 instances, and four raw TZ hits
were refuted as misaligned bytes inside 64-bit address tables.

## Experiment 017 — exact XBL MC table/read-copy path

Host-only Experiment 017 independently cross-references the exact XBL table
and the Experiment-012 SHRM address plan. The pinned XBL is 4,194,304 bytes,
SHA-256 `e73a07a0…`. Its u64 table at VA `0x146b1218` / file `0x630b8` has
122 nonzero entries followed by a zero terminator at index 122, inclusive hash
`d5042980…`, with 30 four-instance MC groups and two globals. All 12 exact
`qhs_mc +0x400/+0x404/+0x4d0` candidates are covered; qhs_mccc `+0x118` and
qhs_mccc_master `+0x294` are excluded from this table only. Existing Top-5
order is unchanged; this is independent observation confidence, not semantic
likelihood.

The independent address-list intersections are set0 `100/430`, set1 `4/64`,
union `100`, table-only `22`, and SHRM-only `370`. This proves convergence of
address lists only, not semantic identity or writer attribution.

The exact helper range `0x146ae138..0x146ae18c` (end-exclusive, file
`0x62318`, length `0x54`, SHA-256 `f325a8bf…`) statically constructs a
zero-sentinel table-driven 32-bit read/copy path to distinct VA `0x146bf300`.
Its identified store bases are X12 and X8, refuting this exact range as a
candidate-register programming/mutation path. The code range is bounded, but
runtime traversal has no hard 122-entry cap. Successful completion, partial or
sentinel output, coherence/currentness, MMIO side effects/faults, mutable table
contents/lock, post-boot writability, indirect BLR/tail reachability and
current-boot execution remain `UNKNOWN`. Direct-BL evidence is limited to two
callsites in file-backed executable PT_LOADs.

This remains Class C transform observation only: the low-24 GF(2) bank relation
is proved, but no PA alias, transform mutation, protected reach or bypass is
proved. Experiments 015 (normal-RAM alias) and 016 (protected-boundary reach)
remain reserved and `NOT ELIGIBLE`; 017 satisfies neither gate.

The cheapest next discriminator at that stage was a host-only symbolic AArch64 store
cross-reference/backward slice for the 12 exact qhs_mc targets (four bases ×
`+0x400`, `+0x404`, `+0x4d0`), resolving MOVZ/MOVK, ADRP+ADD, literal/table
loads, arithmetic and argument provenance. Unresolved dynamic bases remain
`UNKNOWN`; no broad MMIO scan or device action is authorized by this result.

## Experiment 018 — exact XBL MC writer cross-reference Stage 1A

Host-only Experiment 018 Stage 1A inventories the exact XBL literals and the
strict scalar STR W/X unsigned-immediate offsets for the 12 ranked MC targets.
Each target's single 8-byte table encoding yields both the one aligned u64 match
and overlapping one aligned u32 match at the same file offset; these are two
views of one table entry, not independent literals, with no separate target
literal elsewhere. Only base `0x09260000` has an aligned outside-table u32
literal, at file `0x80154` / VA
`0x148bc254` in RWE; the other bases have zero aligned u32 and all bases have
zero aligned u64 occurrences. Unaligned incidental byte matches are not
treated as aligned literals.

The exact file-backed PT_LOAD census is RX4/RWE2/RW3/OTHER0. Strict STR W/X
recognition is RX6945/RWE5169. Matching offsets are RX
`{0x400:7,0x404:2,0x4d0:2}` and RWE
`{0x400:1,0x404:1,0x4d0:1}`, 14 total; seven RX candidates use SP and the
three RWE decodes remain ambiguous code/data. Stage 1A performs no
base/effective-address resolution, so its public resolved hit count is JSON
`null`, not zero. Literal/offset equality is not writer attribution, and no
writer hypothesis is refuted by this stage.

This remains Class C transform observation only. The actual writer, unsupported
store forms, dynamic/cross-block/cross-call paths, AOP/TZ paths, runtime
semantics/mutability, alias and bypass remain `UNKNOWN`; Experiments 015 and
016 remain reserved and `NOT ELIGIBLE`. At Stage 1A, the next exact
discriminator was Stage 2A over only the four non-SP RX candidates; it is now
completed below. The seven SP candidates are runtime-derived and the three RWE
candidates remain ambiguous. An independent
Luna raw-byte feasibility scan agreed on the 14 candidates and found no
resolved target in its broader model but emitted no artifact; it is supportive
review, not manifest `PROVED` evidence.

## Experiment 018 Stage 2A — exact RX direct-definition discriminator

Host-only Stage 2A examines only the four non-SP RX candidates from the Stage
1A census:

| Store VA / file offset | Base | Offset |
|---|---|---|
| `0x14844b20` / `0x2bb20` | X8 | `+0x400` |
| `0x14844c78` / `0x2bc78` | X8 | `+0x4d0` |
| `0x146a70c0` / `0x2d6090` | X8 | `+0x400` |
| `0x14935bf4` / `0x312bc4` | X19 | `+0x400` |

The bounded backward slice examines at most 128 aligned instructions and stops
at control transfers, recognized inbound direct-branch entries and mapping or
window boundaries. It supports only 64-bit MOVZ/MOVK and same-register
`ADRP Xn; ADD Xn,Xn,#imm`; 32-bit wide-move chains, MOVN, MOV aliases,
wrong-source ADD, loads, MADD and other definitions fail closed.

The two long X8 sequences reach the window limit without a supported
definition. The `0x146a70c0` sequence encounters an unsupported LDR X8 at
`0x146a70b4`. The X19 sequence stops at a BL control boundary before the older
dynamic definition. Thus `resolved_base_count=0` and
`resolved_target_hit_count=0`, with classification
`NO_RESOLVED_TARGET_STORE_WITHIN_STAGE2A_DIRECT_DEFINITION_RX_MODEL`.
This refutes only the supported direct-definition path and does not prove
writer absence. SP/RWE, unsupported/dynamic/cross-block/cross-call paths,
runtime execution/semantics/mutability, GF(2), alias, bypass and other firmware
remain `UNKNOWN`.

## Experiment 018 Stage 2B — W-wide-move numeric discriminator

Host-only Stage 2B extends only the two Stage 2A `WINDOW_LIMIT` X8 candidates,
at `0x14844b20/0x2bb20/+0x400` and
`0x14844c78/0x2bc78/+0x4d0`. Its same-block backward window is at most 512
aligned instructions and retains the earlier control, segment and inbound
direct-branch cutoffs. The only added provenance is same-register 32-bit
`MOVZ W8,#0xf000` followed by `MOVK W8,#0x1489,LSL#16`, whose W semantics
zero-extend into X8.

Both exact chains pin those instructions at VA/file
`0x14844580`/`0x2b580` and `0x1484458c`/`0x2b58c`. They resolve X8 value
`0x1489f000`; the two computed XBL virtual-address values are `0x1489f400`
and `0x1489f4d0` (distances 360/357 and 446/443). Both lie outside file-backed
PT_LOADs and neither numerically equals a target. Thus
`resolved_base_count=2`, `resolved_numeric_target_hit_count=0`, remaining Stage
2A unresolved count 2, classification
`NO_NUMERIC_TARGET_ADDRESS_MATCH_WITHIN_STAGE2B_W_WIDE_MOVE_RX_MODEL`.
This proves only the bounded static numeric computation and refutes only numeric
target equality under that model. The values are not physical destinations:
VA-to-PA translation/identity, physical ownership, runtime execution, writer
identity, semantics, mutability/lock, GF(2), alias, bypass and unsupported or
dynamic paths remain `UNKNOWN`; no writer absence is claimed.
