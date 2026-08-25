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

The earlier cheapest discriminator was a host-only symbolic AArch64 store
cross-reference/backward slice for the 12 exact qhs_mc targets. That line is
now covered by Experiments 018–024; unresolved dynamic bases, consumers and
writers remain `UNKNOWN`. The next highest-information step is Experiment 025,
which stays host-only and performs no broad MMIO scan or device action.

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

## Experiment 018 Stage 2C — unique direct-caller retained-table path

Host-only Stage 2C covers the remaining non-SP RX X8 store at
`0x146a70c0/0x2d6090`, inside the exact writer range
`[0x146a70a4,0x146a70dc)` (56 bytes, file `0x2d6074`). The wrapper and lookup
ranges are respectively 108 and 272 bytes with exact pinned hashes; the scan
of file-backed executable PT_LOADs finds exactly one direct BL caller at
`0x146a67a4/0x2d5774`. Decoded pins show `X1=SP` to lookup, an ID-bounded
16-byte table loop, matched row pointer `+8` copied through `[X19]`, then
`X0=SP` to the writer, which loads X8 from `[X0]` and stores W9 at X8+0x400.

The retained table at `0x146aa4d0/0x2d94a0` contains 48×16-byte rows with
SHA-256
`47a7f6195703f2f4d27cbe1e8bd0cc976600453a3ba4aebba98736ef8e03906e`; its
following count word is 48. IDs and nonzero pointers are unique and all +4
reserved words are zero. All 48 rows are emitted as
`table_derived_possible_effective_values`; no pointer equals a target base and
no `pointer+0x400` equals a target. These are a descriptor-`+0x20`-dependent
possible-value superset, not proof of per-entry success or execution. The
computed values are XBL effective-address values; VA-to-PA/identity, physical
destination/ownership, runtime mutation/currentness, indirect callers, other
X8 writers, execution and writer identity outside this path remain `UNKNOWN`.
Classification:
`NO_NUMERIC_TARGET_ADDRESS_MATCH_WITHIN_STAGE2C_UNIQUE_DIRECT_CALLER_TABLE_MODEL`.

## Experiment 018 Stage 2D — conditional X19 direct-BL path

Host-only Stage 2D covers the remaining non-SP RX X19 store at
`0x14935bf4/0x312bc4`, inside function
`[0x14935960,0x14935edc)` / file `0x312930` (1,404 bytes,
SHA-256 `68739df6f843f790376eb0af47da22f0af5ebeb2421f05d29c3b5a8673983fd9`).
Exactly one direct BL caller exists at `0x14949eec/0x326ebc`; direct B callers
are zero and indirect callers remain `UNKNOWN`. Its success path zeroes W0,
takes CBZ to `0x14949ee4`, supplies X1=SP+0xe0 and W2=0, then calls the
function.

The callee pins W20=W0, W0≤7/X1-nonzero guards, the exact
`SUB W12,W20,#2; CMP W12,#3; B.CS 0x14935aac` dispatch, W20≤1 path, X23
selection, X24=`0x85e9e570`, and `MADD X19,X23,0x600,X24`. The `CBNZ
W0,0x14935ce8` after the pre-MADD direct call makes W0=0 a runtime success
precondition. The intrinsic W0 domain is `{0,1}`, with pre-call bases
`{0x85e9e570,0x85e9eb70}` and possible effective values
`{0x85e9e970,0x85e9ef70}`. The initializer
`[0x14844580,0x14844dac)` stores `0x1483c904` into slot `0x1489f3b0`; its
runtime execution and later slot mutation are `UNKNOWN`. The exact resolved
target range `[0x1483c904,0x1483c9e8)` has zero BL/BLR/BR transfers, one RET,
in-range direct branches, and zero X19-X29 definitions under an exact
instruction-class/write-set audit. The pre-MADD direct callee range
`[0x1493641c,0x1493697c)` has SHA-256
`43fa9c70453b7ad1d8ff88d4ca07b375d2dc6b3b06e805339b2ad1927e4487e0`, a unique
direct caller at `0x14935abc`, and pinned X24/X23 save/restore on its one
normal RET.

Under explicit normal-return and `STATIC_INITIALIZED_SLOT_UNCHANGED` conditions,
the direct effective value is `0x85e9e970`, with zero numeric matches to the 12
targets. It lies in the memory-only tail of RW PT_LOAD
`0x85e44000` (`filesz=0x43620`, `memsz=0x66038`, `p_vaddr=p_paddr`). This is
conditional static evidence only: import conformance, runtime execution,
slot currentness, VA-to-PA identity and physical destination/ownership remain
`UNKNOWN`; no writer absence is claimed.

## Experiment 018 Stage 2E — RX SP-frame stores

Host-only Stage 2E covers only the seven RX candidates whose encoded base is
SP. F1 `[0x1492df68,0x1492e718)` and F2 `[0x14936ae0,0x14937c18)` are pinned
by exact range hashes, unique direct-BL callers and frame prologue/epilogue
instructions. The seven STR W/X forms map to offsets `0x400`, `0x404` and
`0x4d0`; all are within F1's `SUB SP,#0x5a0` or F2's `SUB SP,#0x490` local
allocation. Exact range-hash-bound audits within the recognized SP-write classes
find only four frame updates per function; the explicit memory-writeback audit accounts for exactly four
recognized sites per function (two SP and two non-SP). Recognized BR/BLR counts
are zero, and the all-file-backed-executable-PT_LOAD-words direct-entry census
finds one external BL to each function start and zero external entries to
interiors. An independent GNU objdump 2.46 disassembly census, pinned by each
exact range hash and not recomputed by this tool, reports F1 as 492 instructions
with 134 writeback-free SP-base accesses and F2 as 1,102 instructions with 168
such accesses. The same-function immediate-control CFG (BL modeled as
fallthrough) has no recognized SP-write-class instruction after allocation on a
path to each candidate; unsupported instruction effects remain `UNKNOWN`.

This proves architectural SP-relative stores and frame-relative bounds only.
Under a normal well-formed stack-frame premise they are not static absolute
controller-base stores. Normal-return/callee SP restoration is a separate
`SUPPORTED` premise; absolute runtime stack address, stack integrity or
rebasing, VA-to-PA identity, physical destination/ownership, execution,
indirect callers and writer identity remain `UNKNOWN`. The three RWE candidates
remain outside this RX-only stage. Classification:
`SEVEN_RX_SP_CANDIDATES_ARE_PINNED_STACK_FRAME_STORES_RUNTIME_STACK_ADDRESS_UNKNOWN`.

## Experiment 019 — DCB candidate pair arrays

`PROVED`, narrowly: strict acceptance finds candidate address/offset-value pair
arrays in two syntactic key domains across the bounded DCB blocks. These are
not proved register tables or consumers. Absolute keys do not reach ranked MC
bases; implicit section bases, section semantics, consumers, register identity
and writer identity remain `UNKNOWN`.

The bounded materialisation audit proves only its named models: stored-word,
exact one-instruction/adjacent-wide-move and ORR-immediate paths contain no
`0x00003333` or `0x00300014`, while `0x00300033` has two adjacent sequences.
Computed/loaded/other ordering remains `UNKNOWN`, and no writer absence is
claimed. Class C and the `NOT ELIGIBLE` status of Experiments 015/016 are
unchanged.

## Experiment 020 — DCB consumer and register-offset complement

`PROVED`, within the independent bounded census: 719 register-offset stores
are present (488 unscaled; 67 loop-shaped). A pinned false negative at
`0x14868a50` means the narrow classifier's zero is not a general zero-walker
result. `SUPPORTED`: the largest RWE segment is a candidate segment only.

General walker coverage outside the exact Experiment 024 range, DCB identity,
runtime base, table-provider identity, consumer and writer remain `UNKNOWN`.

## Experiment 021 — bounded-copy delivery paths

`PROVED` for the pinned target and direct encoding census: seven direct `BL`
edges and zero direct `B` edges exist. Five calls have local labels for
sections `{0,1,2,15,16}` and two are unlabelled. Other-section, indirect,
other-copy and global delivery are `UNKNOWN`, not refuted; only the claim that
the local labels account for every direct call is `REFUTED`.

## Experiment 022 — sparse density of two retained channels

`PROVED`: the two enumerated retained-evidence channels have exact counts
`430/470/122/492` and sparse observed density around each ranked instance.
Completeness of those channels is `REFUTED` by known `0x09248080`; the true
implemented-register denominator and coverage remain `UNKNOWN`. The counts do
not generalize the negative results of 014, 017, 018, 019 or 021 beyond these
channels.

## Experiment 024 — exact XBL six-byte walker

Experiment 024 is `COMPLETED` and integrated from commit `c62c33e`. It is
host-only, read-only static analysis of the exact XBL, two pinned design-source
snapshots, and the pinned Experiment 019 dependency; no device, SMC, MMIO,
protected-memory, normal-RAM, or activation action occurred.

`PROVED`: the exact walker `[0x148689a0,0x14868a64)` is a 196-byte range with
SHA-256 `08265307d79c5f82b85266613f241ae160151dcfe51b19da108f9ad6c4e15021`.
`UMADDL` uses a six-byte record stride; flags, offset, and value are loaded at
`+0`, `+2`, and `+4`; the exact terminator is `0x8000`; `B.EQ` returns before
the conditional `STR W14,[X15,X13]`; and `LDRB` zero-extends the byte so the
taken store writes a 32-bit word. Other nonterminator flag combinations may
skip the store; flag semantics remain `UNKNOWN`.

`PROVED`: exactly three direct callers exist at `0x14868640`, `0x1486867c`,
and `0x14868698`. Five nonzero provider alternatives select XBL-resident
tables; selector `== 0xf` has 53 unique offsets, selector `!= 0xf` has 127,
and the cross-alternative syntactic union has 170 aligned offsets spanning
`0x7000..0x7de0`. The alternatives contain 221 nonterminator records, each
table ending in an exact `0x8000/0/0/0` record. Provider3 on selector `== 0xf`
returns count zero without a pointer, and the pinned zero-count path reaches
`RET` before table dereference.

The five table starts/counts/hashes are
`0x14880bee/43/f7b7ca7dae26320d69c87c9b4c59472eb0933aa7216936ed7564f78b770f643c`,
`0x14880e70/90/8c26948bb9e7e24ae9c2d950412e851dd1e60e412aa4f82d7936c247103ac240`,
`0x14880ba0/13/eac051599765de4842c6ecf7a6076813eac93a07cd052d829787b1095fa353b1`,
`0x14880cf0/64/7c0fb81701455fb380cf4a2d1af4120a444a6be66235c2a87dad5ca2c932711f`,
and `0x14880b40/16/1c596a44cbec1cdbcc5b23e81eccde1c20556b17ab3c434ef393c29ab63aa015`.

`PROVED`: the two pinned design-source UFS blocks are byte-identical (4,464
bytes, SHA-256
`cea31db3785be5916a1ff08d1c99b92155a7914b07d09ecb6c3638d8c16ff10a`). Under
initialized-base retention, all 170 symbolic `BASE+offset` destinations lie
in broader `ufshc` `ufs_phy` `[0x01d87000,0x01d87e00)`; 167 lie in standalone
`ufsphy_mem` `[0x01d87000,0x01d87da8)`, while offsets `0x7dc4`, `0x7dd8`, and
`0x7de0` lie beyond the narrower resource. The Experiment 019 eight-byte
representation is structurally distinct; semantic DCB identity is `UNKNOWN`.

`SUPPORTED`: the direct-call positive control supports a table-driven UFS
interpretation only under initialized-base retention and store reach. Current
base is `UNKNOWN` because helper `0x1486abec` reaches runtime-BSS `BLR X9` at
`0x1486ac1c`; selector/runtime execution, reached-store subset, flag semantics,
live-DTB equality, DCB semantic alias/global consumer/writer, DDR/MC relation,
GF(2), alias/bypass, and actual current destinations are also `UNKNOWN`. All
170 mappings are conditional symbolic supersets, not one execution/current
destination set. No unconditional UFS or DDR refutation is made.

Tool/test/manifest SHA-256 values are
`f0ccb5648b2cce4ab2b835e23c4658c976df9779b0ae6273767b59cc7b6a58bf`,
`97c58a22c5c3e7e6cd5b7bc4f8d181c74050b2b530afac03eba3fbb946577f6d`, and
`f9ac896d396650075ca9e66d8d805a2deaf40b0207e819cd94f8d638c8121b01`.
Validation is 30 focused and 534 full unittest-discovery tests, 64 public JSON
manifests, byte-identical regeneration, manifest mode `0644`, and two
independent review `PASS` results recorded in
[the Experiment 024 integration review](../docs/EXP024_INTEGRATION_REVIEW_2026-08-26.md).
Class C remains `TRANSFORM ONLY`; 015/016
remain `NOT ELIGIBLE`.

## Integration gate and next stage

Independent validation records 30 focused and 534 full unittest PASS, 64
public JSON manifests, byte-identical regeneration, and two independent review
PASS results recorded in
[the Experiment 024 integration review](../docs/EXP024_INTEGRATION_REVIEW_2026-08-26.md).
Experiment 023 is explicitly `WITHHELD/NO-GO`, not integrated or
public: its timing protocol is not comparable to Experiment 014 (fixed order,
half warmup, `ISB`, summed reopen without `/2`), physical-allocation PA
provenance is missing so a `+0x1000` countermodel fits the labels, and the full
GF(2) matrix is non-unique. `PA24=b1^b2` is `SUPPORTED` only; raw evidence is
private.

Experiment 025 is the next highest-information host-only step: bound
registry/attach/factory/vtable/callback reach, write cross-references, and
boot-order evidence for runtime BSS slot `0x14890590` and registry
`[0x14890e50,0x14890f50)`. Do not promote before a qualified, independently
reviewed committed 025 manifest. No device action or MMIO write is part of
this step.
