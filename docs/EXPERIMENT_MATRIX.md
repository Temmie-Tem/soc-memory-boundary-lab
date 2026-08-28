# Experiment Matrix

> Current interpretation is governed by
> [FINAL_REPORT_2026-08-29.md](FINAL_REPORT_2026-08-29.md) and the
> [two-audit ledger](AUDIT_RECONCILIATION_LEDGER_2026-08-29.md). Historical
> PASS results retain their bounded observations but do not restore superseded
> high-bit provenance, XPU-causality, HLOS-actor, or cross-transition claims.

| ID | Hypothesis / question | Observable prediction | Controls | State/result |
|---|---|---|---|---|
| 001 | Live target exposes stable topology and reserved ranges read-only. | A90P1 `cat/ls` returns framed, hashable data and binary DT cells. | Fixed allowlist, no retry, target-pinned bridge, host parser tests. | `PROVED`, one live capture; repeat count 1. |
| 002 | Cold boots retain identical fixed carveouts. | DT `reg` values and structural `/proc/iomem` holes match across cold boot A/B. | Same kernel/runtime, hashes, compare dynamic counters separately. | `UNKNOWN`, not yet run. |
| 003 | Stock-like and research boots advertise the same protected ranges. | Fixed ranges equal; differences are attributable to overlays/runtime. | Bind exact boot artifact; do not equate version string with image hash. | `UNKNOWN`. |
| 004 | Exact live boot-firmware bytes can be acquired without partition writes. | Device pre-hash, host raw hash and device post-hash match for every allowlisted partition. | Live GPT/sysfs identity, `ro=1`, exact byte count, bounded size, fixed node names, cleanup inventory. | `PROVED`: nine artifacts, 26,779,648 bytes; all triple hashes match. |
| 005 | The exact XBL-programmed qhs_llcc remapper windows are readable post-boot from EL1. | Four control words, then 92 layout words, return stable 32-bit values without abort. | Fixed addresses only; temporary fixed `1:1` node; default four-word smoke; explicit `--full`; unconditional cleanup; no MMIO write/retry/arbitrary address. | `REFUTED` for current-kernel `/dev/mem`: absent node then `ENXIO`; live config has `CONFIG_DEVMEM=n`. Hardware/kernel-adapter readability remains `UNKNOWN`. |
| 006 | Address-region mapping is programmed by XBL/DDR DSF/DCB/ICB. | XBL config consumption leads to topology-dependent MMIO writes. | Exact live firmware hashes and call-graph provenance; distinguish region remap from final channel/bank hash. | `PROVED`: four qhs_llcc remapper bases and `+0x00..+0x58` writer recovered; final DRAM hash role `UNKNOWN`. |
| 007 | A narrow kernel path can read the exact remapper windows post-boot. | Fixed map/read/unmap returns a stable 32-bit control word without reset. | Exact candidate/map hashes; one fixed base first; no MMIO write/retry/arbitrary address; retained reset log; verified rollback. | `REFUTED` for the generic REPL adapter: `__ioremap` returned, then a non-secure watchdog occurred before `msm_readl`. Purpose-built adapter readability remains `UNKNOWN`. |
| 008 | Exact retained boot evidence resolves the live DCB/remapper row and TZ protection adjacency. | One DCB and table row match; exact TZ registry binds same-instance MPU configuration bases. | Four SHA-256-pinned private inputs; consistent repeated boot values; structural ELF/registry validation; no device access. | `PROVED`: `/6003_0200_1_dcb.bin`, row 7, six 36-bit slots, and `BIMC_MPU0..3` at matching `qhs_llcc+0xe000`; runtime register words/coverage `UNKNOWN`. |
| 009 | Static TZ/XBL/AOP consumers distinguish remapper security ownership from sub-aperture clock/fault gating. | Registry consumers, access policy, clock vote, or fault-response path names `+0x8080`/same window. | Host-only exact bytes; code/data xrefs; no MMIO retry or inferred register semantics. | `PROVED` static raw-row fact: both TZ policy branches place `0x09248080` in TZ-owned `DC_NOC_BROADCAST_MPU` region 11 with read word `0x80000000` and write word zero. Bit actor, client/path/overlap, final live policy, and non-return cause are `UNKNOWN`; XPU/fabric denial is not promoted. |
| 010 | Identify BIMC_MPU0..3 initialization and separate QHEE ownership enforcement from TZ XPU control. | Exact secure paths supply BIMC policies; any HLOS XPU-control SMC has a bounded allowlist; all known controller apertures can be checked against both policy branches. | Host-only exact XBL/TZ/hyp/devcfg bytes; function/data/SMC-record pins; comparative names separated from exact claims; no device/SMC/MMIO access. | `PROVED`: QHEE `hyp_assign` uses local stage-2/SMMU AC; separate TZ fallback dynamically reconfigures BIMC_MPU0..3; XPU-disable allowlist count 0; all eight apertures have broad branch-invariant address coverage. Effective HLOS/all-master denial, final policy/path and ordering are `UNKNOWN`; no bypass observed. |
| 011 | Exact XBL exposes a PA-to-DRAM-coordinate model and selected DCB section 16 identifies candidate controller state. | A real DDR failure path computes rank/row/bank/channel/column; section tokens match SHRM-visible MCCC/MC pages. | Three exact SHA-256 pins, bounded function/word hashes, inverse-coordinate control, structural two-set parser, no device/SMC/MMIO. | `PROVED`: the diagnostic formula is linear, complete and bijective with no XOR/alias; section tokens match five controller families. Experiment 014 later `REFUTED` it as the complete silicon bank map; token semantics remain `UNKNOWN`. |
| 012 | Exact SHRM section-16 consumer establishes token scaling and direction. | Xtensa helper computes controller addresses and stages reads/writes according to a direction argument; exact callsites reveal the observed mode. | Exact XBL/SHRM blob hashes, parser/callsite fingerprints, offset formula, capacity/count checks, no device/SMC/MMIO. | `PROVED`: `(base_page<<12)+(offset<<2)`; both direct consumers pass read direction and produce 430/64 snapshot reads. Section-16 write primitive `REFUTED` for observed paths; runtime values/locks/indirect paths `UNKNOWN`. |
| 013 | What raw static policy rows cover the SHRM snapshot workspace, and does one fixed EL1 load return? | Resolve every covering row without pre-naming client bits; compare one fixed load with the map/unmap-only control. | Exact TZ hash, complete `0xf00` range, both selector branches, candidates differing by one instruction, no retry/address/write input, verified V2321 rollback. | `PROVED`: three TZ-owned raw policy rows per branch cover the workspace; no-load control returned `0xc071`; one-load read returned no value and retained `Non Secure Watchdog Bark`/`TZBSP_ERR_FATAL_NON_SECURE_WDT`. Direct non-return is confirmed. The control has zero MMIO loads, and the bit-3 predicate is non-discriminating, so HLOS denial and XPU versus stage-2/fabric cause remain `UNKNOWN`; no bypass observed. |
| 014 | Normal-RAM bank/channel relationships fit a stable GF(2) model not already explained by the exact diagnostic formula. | XOR-difference row-reopen timing recovers the selector kernel; row-bit relations and held-out combinations must agree while one-bank-bit perturbations leave the class. | Exact non-secure single-SG ION CMA PA binding; write-combine mapping; symmetric reopen/baseline directions; 64 PA pairs; 1001 repetitions; same-row, held-out and one-bit controls; CPU/DDR pinning. | `PROVED`, direct observed low-24 scope: row bits 16..23 contribute the rank-three bank/model relation and held-out controls agree; the diagnostic no-XOR bank formula is `REFUTED` as the complete silicon map. Experiment 030 later `REFUTED` the historical inference that PA9/PA10 class departure proves independent channel selectors; their physical roles remain `UNKNOWN`. No complete-coordinate alias, mutation or bypass. |
| 015 | A controlled transform state creates physical-to-DRAM alias. | `PA_A != PA_B` but writes through one are observed through the other after cache-neutral independent reads. | Prove distinct PTE/PAs; CPU and DMA controls; cache maintenance; reboot/state restoration; unchanged-state negative control. | `NOT ELIGIBLE`: candidate tokens exist, but operation semantics, readback/lock state, safe restore, and an alias-producing state are not proved. |
| 016 | A normal-RAM alias reaches a protected boundary. | Only after 015, a minimal non-secret marker/boundary test differs between normal and alias path. | No dump, exact ordering proof, secondary enforcement control. | `NOT ELIGIBLE`. |
| V017 | Can a bank-only post-decode enforcement check separate the listed protected carveouts from ordinary System RAM? | Apply the exact rank-3 allocation-offset/model relation to the pinned live memory-map ranges; a bank-only check would need a class-set difference. | Host-only source-pinned algebra and range histograms; subtract reserved carveouts nested inside broad System RAM; retain complete-coordinate, protection-ordering and physical-mapping unknowns. No device/SMC/MMIO/write. | `REFUTED` only for the narrow bank-only shape in the model projection: minimum class-change span 8 KiB; a 64-KiB-aligned span covers all eight classes and 128 KiB guarantees coverage at an arbitrary base; every listed protected/unprotected comparison range meets that bound. Finite GF(2) countermodels show complete-coordinate injectivity remains underdetermined. Complete post-decode check, actual ordering, transform mutability and bypass remain `UNKNOWN`; Class C unchanged. |
| V018 | Does one exact A90 non-secure ION allocation expose a single-state storage-identity collision at any tested one-bit offset pair? | A marker written at an anchor is observed through a candidate offset that received only a sentinel; the exact 190-record transcript recomputes every verdict. | Exact source/binary/build pins before bridge contact; type-10/id-30 `camera_preview` allocation; same-storage two-VA positive control; distinct-offset negative; two trials; strict target/bridge/cleanup/final-health receipt; no MMIO/SMC/secure/protected/partition access. | `PROVED` bounded live baseline: both controls passed, 176/176 candidates `DISTINCT`, zero disturbance/clobber/disagreement, `NO_ALIAS` only over the retained one-state allocation-offset pairs. Pagemap `BLIND`; physical PA/contiguity/final DRAM coordinates `UNKNOWN`; cross-state Skitter permutation, transform mutation and protected reach are not tested. Numbered 015/016 remain `NOT ELIGIBLE`. |
| V019 | Does the address-to-DRAM map survive a Normal-World-triggerable deep-suspend transition while the allocation remains in place? | Two retained, independently acquired deep-suspend receipts report 25.090 s and 25.151 s with 0/4,194,304 moved tags; the cable-attached control is explicitly `SUSPEND_NOT_REACHED`. | Exact analyzer/probe/source pins; baseline-before-suspend gate, suspend_stats/RPMh/time corroboration fields, splitmix permutation positive control, retained regular-file receipts with no-follow guard, no protected/controller/partition write. | `PROVED`/`REFUTED` only for the two retained deep-suspend runs and declared offset domain: a map change in that transition is refuted; effective physical contiguity, complete coordinates, other transitions and global mutability remain `UNKNOWN`; Class C unchanged. |
| V024-DMID | Does DMID make the exact protected remapper aperture at `0x09248080` readable through the fixed Normal-World EL1 path? | The same-state no-load control returns `0xc071`; the one-load read emits BEGIN but no END/value, disconnects USB, and one-shot `last_kmsg` reports an exact non-secure-watchdog/TZ reset. | Exact control/read/V2321 prefixes and full readbacks; fixed one-load body; `panic_on_oops` journal; no retry; immutable raw reparse; exact rollback, stable LOW capture, temporary-path absence and final health. | `PROVED` bounded refusal: one ordered watchdog signature, `11.000287`-second bark/last-pet delta, zero `A90R`; `REFUTED` that DMID alone unlocks this aperture. Enforcement block/order and alternate apertures remain `UNKNOWN`. No alias or boundary bypass; `CLASS C` / `NOT_ELIGIBLE`. |
| 020M | Does the live DT bind measured ION heap 30 to a fixed `camera_mem_region` large enough for a PA28 test? | Heap 30 reports `reg=0x1e`, `memory-region=0x67a`; the matching region reports `reg=<0,c2000000,0,14000000>`, `no-map`/`reusable` return ENOENT and `ion,recyclable` is present. | Exact A90/SM8150 target validation; fixed DT allowlist; private raw receipt and redacted manifest; explicit bridge identity; no ION allocation, MMIO, SMC, controller or protected-memory action. | `PROVED` advertised DT chain; `SUPPORTED` fixed-carveout consistency; allocation placement, `f(PA28)`, complete coordinates and mutability remain `UNKNOWN`; Class C unchanged. |
| 021-CE | Does a full-size `camera_preview` hold consume the selected heap's residual capacity? | 320 MiB hold succeeds; 16 MiB, 4 MiB, 1 MiB, 64 KiB and 4 KiB probes fail under hold; all five controls succeed before and after release. | Retained private receipt with v2 reducer; exact heap/type/id and canonical 020M dependency; stable no-follow reads; no mapping/read/write/MMIO/SMC/protected action. Same-run target/bridge/argv/health are explicitly unavailable. | `SUPPORTED_WITHIN_RETAINED_RECEIPT`; conditional physical span `SUPPORTED_CONDITIONAL_ON_020M_CHAIN`; exact target, physical page identity, DRAM coordinates and security effect `UNKNOWN`; Class C unchanged. |
| 020N | Does a full 320 MiB normal-RAM allocation expose a single-bit-28 timing discriminator? | Fixed no-argument probe measures `0x10000000` against same-offset, two bank-bit negatives and a cache-maintenance control; host reduction emits `PA28_TIMING_CANDIDATE` only if all strict gates pass. | Host-only implementation currently; 020M/021 hash+semantic dependencies, exact heap/type/id and allocation size, no pagemap/physical claim, no MMIO/SMC/protected action. No live receipt yet. | `HOST_ONLY_DESIGN`; any timing candidate remains below `PROVED`, does not establish `f(PA28)` or alias, and keeps `CLASS C` / `NOT_ELIGIBLE`. |
| 022-PA28 | What does the retained full-320 MiB timing receipt say about `f(PA28)` within the recovered rank-3 model? | Strict existence/identification reductions recheck 3,029 pair rows, both same-phase controls and exact phase/cardinality sets; one of seven candidates conflicts, selecting `f(PA28)=010=f(PA14)`. | Canonical raw/dependency/source pins; per-phase controls; recomputed base/offset/XOR arithmetic; fixed-gated normal-RAM probe source; no protected/controller/MMIO/SMC/partition write. Same-run target/bridge/argv/timestamp/final-health and historical binary are not retained. | `SUPPORTED_WITHIN_RETAINED_RECEIPT` / `SUPPORTED_MODEL_EXTENSION`; physical coordinates, alias, mutability, protection ordering and bypass `UNKNOWN`; `CLASS C` / `NOT_ELIGIBLE` unchanged. Manifest 6,698 B, SHA-256 `f583bd4f4fe30ad4822832e708edd87e2e049333f2a6c0cf014467b5a33bc2d2`. |
| 022R-PA28 | Does a fresh exact-target acquisition reproduce the retained `f(PA28)` result with complete same-run provenance? | One fixed V2321 probe dispatch yields 1,802 records; both control brackets select only `0x10004000` at threshold 369, yielding `f(PA28)=010=f(PA14)`. | Exact A90/bridge/source/build/binary/argv pins; 1,787 pair arithmetic checks; terminal/remote cleanup and final `11/1/0/12` health; no MMIO/controller/SMC/protected/partition action. | `ACQUISITION_PASS` / `SUPPORTED_MODEL_EXTENSION`; physical identity, alias, complete coordinates, mutability, protected reach and bypass `UNKNOWN_NOT_TESTED`; `CLASS C` / `NOT_ELIGIBLE`. Manifest 11,989 B, SHA-256 `f88a81bd3aabbd76cf2bcb8575f45d1cca7c29433a0279403d76d3affbfa2ca2`. |
| 1b | What do the eight known remapper/BIMC apertures establish about bounded direct reach? | Both selector branches enumerate the same eight candidates inside TZ-owned broad raw policy rows. The tested `0x09248080` narrow row is branch-invariant; its fixed EL1 load produced no value before a recorded watchdog, while the control-node route failed before a read and the map/unmap control executes no MMIO load. | Host-only exact-hash reconciliation of `MEMORY_MAP.md` plus 009/010/007/005 manifests; known candidates only; no device, controller, SMC, SCM, ownership or protected-memory mutation. | `PROVED` bounded static address coverage and instance-0 non-return. The bit-3 HLOS predicate is non-discriminating; refusing agent, global reachability, alternate apertures/initiators, final runtime policy, ordering, mutability and bypass remain `UNKNOWN`; `CLASS C`, `NOT_ELIGIBLE`. |
| R2 | Do the exact 029–034 bounded static manifests leave a promoted writer path or a contradiction with the repaired rank-3 relation? | Pinned JSON semantics preserve zero DCB-consumer/MC-symbolic paths, stable 71-site identities, transition-count invariants, and 030's inherited rank-3 dependency; a complete relation-row contradiction would be separately visible. | Host-only exact-byte/hash and duplicate-key checks; 027/029/030/031/032/033/034 plus 023R/V016 pins; no device/SMC/MMIO/write. | `SUPPORTED_BOUNDED_CLOSURE_UNKNOWN_GLOBAL` for Q1; Q4 `UNKNOWN_NO_COMPLETE_029_034_RELATION_ROW_SET`. No global writer absence, runtime execution, physical mapping or bypass claim; Class C unchanged. |
| 020A-ST | Does the exact candidate setter's incoming argument block resolve to a runtime base source? | `PROVED`: setter `[0x9fc06410,0x9fc0643c)` has one `XZR` zero and four argument-sourced stores; its sole direct caller `0x9fc023f0` supplies `W3=[X0+0x10]`, `X0=[X0+0x18]`, `X1=[X0+0x20]`, and `X2=[X0+0x28]` in a bounded linear model. | Exact XBL/range hashes and singleton direct-caller check; 20-byte trace plus 92-byte context; synthetic decoder/data-flow negatives; no device/SMC/MMIO/write. | `SUPPORTED` symbolic setter/base edge; runtime object values/type/currentness, physical mapping, mutability and protected reach `UNKNOWN`; `CLASS C`, `NOT_ELIGIBLE`. |
| 020B-CO | Does the sole direct caller of the 020A consumer resolve the incoming object to a bounded construction/origin? | `PROVED` within the finite model: `BL 0x9fc160b8` returns an opaque token, the caller builds an object at `SP+0x20`, and the four setter arguments are copied from return offsets `0x0c`, `0x18`, `0x20`, and `0x28` (widths 32/64/64/64). | Exact XBL/caller/consumer-entry/call-word hashes; strict scalar/Q0/pair/stack decoders; direct-caller singleton and stack-coverage negatives; no device/SMC/MMIO/write. | `SUPPORTED` symbolic caller-object edge; helper return value/type/currentness, static-object meaning, physical/DRAM mapping, mutability, protected reach and alias/bypass `UNKNOWN`; `CLASS C`, `NOT_ELIGIBLE`. |
| 020C-RH | Does the exact helper returning the 020B object construct a static address, and how many direct callers are visible? | `PROVED`: `[0x9fc160b8,0x9fc160c4)` is `ADRP X0,0x9fc36000; ADD X0,#0x2c0; RET`, yielding static ELF VADDR `0x9fc362c0`; exactly two direct callers are found. | Exact helper/object-range hashes; strict ADRP/ADD/BL decoders; synthetic extra-caller and hash negatives; object bytes published by hash only; no device/SMC/MMIO/write. | `SUPPORTED` static source bridge to 020B; runtime object contents/type/currentness, writer/mutability, physical/DRAM mapping, protected reach and alias/bypass `UNKNOWN`; `CLASS C`, `NOT_ELIGIBLE`. |
| 020D-SC | Does the second direct caller of `0x9fc160b8` use the shared object to populate static slots? | `PROVED` within the finite model: fields `+0x28,+0x30,+0x38,+0x0c,+0x18,+0x20` flow to static ELF VAs `0x9fc3e138`, `0x9fc3e140`, `0x9fc3e148`, `0x9fc3e150`, `0x9fc3e158`, and `0x9fc3e160`. | Exact helper/caller/object hashes; strict ADRP, scalar/pair LDR, STR and BL decoders; synthetic extra-caller/hash/decoder negatives; no raw object values or device/SMC/MMIO/write. | `SUPPORTED` second static field-use edge; slot semantics, runtime values/currentness, mutability, physical/DRAM mapping, protected reach and alias/bypass `UNKNOWN`; `CLASS C`, `NOT_ELIGIBLE`. |
| 017 | Does exact XBL expose a table-driven MC read-copy path that independently covers the ranked MC candidates? | The pinned u64 table parses to 122 entries plus a zero terminator; the exact helper's static flow conditionally loads each table-derived address and stores results to a distinct buffer. | Exact XBL size/hash, PT_LOAD mapping, inclusive table/helper hashes, AArch64 word pins, direct-BL scan limited to file-backed executable PT_LOADs, SHRM-plan address-list cross-check; host-only, no device/SMC/MMIO. | `PROVED`: 30×4 MC groups + 2 globals, all 12 qhs_mc candidates covered, helper read-copy store-base dataflow, exactly two direct BL callsites. `REFUTED`: helper as candidate-register writer and independent hard 122-entry cap. Runtime completion/coherence/currentness, mutable table state, indirect reachability and writer semantics `UNKNOWN`; 015/016 remain `NOT ELIGIBLE`. |
| 018 | Does exact XBL contain literal and syntactic store-offset evidence for the 12 ranked MC targets, and do the non-SP RX candidates resolve through narrow direct-definition models? | Each target's single 8-byte table encoding yields one aligned u64 match and the overlapping aligned u32 match at the same file offset; strict STR W/X unsigned-immediate offsets enumerate candidates. Stage 2A resolves only 64-bit MOVZ/MOVK or same-register `ADRP Xn; ADD Xn,Xn,#imm` within 128 instructions; Stage 2B extends only its two X8 window-limit candidates with same-register W MOVZ/MOVK within 512 instructions; Stage 2C analyzes one X8 writer through its unique direct caller and 48-row retained table; Stage 2D analyzes the remaining X19 store under explicit dispatch, normal-return, and initialized-slot conditions; Stage 2E analyzes only the seven RX SP-base stores against exact F1/F2 local frame allocations. | Exact XBL size/SHA-256, PT_LOAD RX/RWE/RW/OTHER census, scalar STR decoder negatives, literal mapping/table membership, exact candidate/code/table/initializer pins, exact target instruction-class/write-set audit, exact SP-write/site manifest bound to both function hashes, explicit memory-writeback, BR/BLR, all-file-backed executable PT_LOAD-word direct-entry, direct BL/B and success-path cutoffs, unsupported/mixed-width definition negatives; host-only, no device/SMC/MMIO. | `PROVED`: the two aligned matches per target are views of one table entry, not independent literals, with no separate target literal elsewhere; outside-table aligned u32 only for base `0x09260000` at file `0x80154` / VA `0x148bc254` in RWE; 14 matching offsets (RX11/RWE3), seven RX SP-based; Stage 2A has two window-limit no-definitions, one unsupported LDR, one BL control boundary, zero resolved bases/hits. Stage 2B resolves two W-wide-move bases to XBL virtual-address values `0x1489f000`, computing `0x1489f400`/`0x1489f4d0`, with zero numeric target hits. Stage 2C proves one direct BL, the 56/108/272-byte code-range hashes, and 48 unique ID/pointer rows with zero numeric target matches; these are a descriptor-eligibility-dependent possible-value superset. Stage 2D proves the remaining caller/function/initializer/target static pins, exact target no-call/no-saved-register audit, dispatch and normal-return pins, and computes `0x85e9e970` only within explicit runtime/slot conditions; its conditional value has zero numeric target matches. Stage 2E proves all seven SP forms, both frame ranges/hashes and callers, four recognized explicit writeback sites per function (two SP frame updates and two non-SP writebacks), zero recognized BR/BLR transfers, one external direct BL to each function start with zero external entries to interiors, and in-allocation bounds. The same-function immediate-control CFG (BL modeled as fallthrough) has no recognized SP-write-class instruction after allocation on a path to each candidate; unsupported instruction effects remain `UNKNOWN`; absolute stack address and runtime destination remain `UNKNOWN`. `REFUTED` only: the supported Stage 2A direct-definition path, Stage 2B/2C/2D numeric target equality in their stated models, and static absolute/controller-base interpretation of these seven stores within the normal frame model. Physical destination, runtime execution, writer identity outside scoped paths and all SP/RWE/unsupported/dynamic paths remain `UNKNOWN`; 015/016 remain `NOT ELIGIBLE`. |

| 020E-SS | Do the six 020D static slots have additional bounded direct consumers or writers? | `PROVED` within the finite model: 18 unique direct unsigned scalar accesses (6 `STR`, 12 `LDR`) to the six slots; 95 bounded barriers are retained (8 caller-saved `BL`, 87 unknown-instruction). | Exact XBL/helper/caller/object hashes; ADRP-to-slot-page window of 8 instructions; strict scalar decoders, page-register kill rules, caller-saved `BL` barriers and explicit AAPCS64 X19–X29 continuation assumption; synthetic call-flow negatives; no device/SMC/MMIO/write. | `SUPPORTED` bounded cross-reference only; global writer/consumer absence, ABI compliance, runtime values/currentness, slot semantics, physical/DRAM mapping, mutability, protected reach and alias/bypass `UNKNOWN`; `CLASS C`, `NOT_ELIGIBLE`. |
| 020F-LU | Do the twelve 020E slot loads feed pointer/address formation, stores, predicates, or returns? | `PROVED` within the finite model: 16 recognized downstream use events and 11 barriers across 16-instruction same-block windows; no tainted direct store reached. | Exact XBL plus mechanically hash-pinned 020E manifest; strict LDR/STR, register-offset, ADD/SUB, MADD, MOV, predicate, control and call-preservation model; X30 caller-saved, MOVK fail-closed, CBNZ/TBNZ covered; no device/SMC/MMIO/write. | `SUPPORTED` local address/arithmetic uses only; global writer/consumer absence, ABI/runtime values/currentness, slot semantics, physical/DRAM mapping, mutability, protected reach and alias/bypass `UNKNOWN`; `CLASS C`, `NOT_ELIGIBLE`. |
| 020G-PO | Do the exact 020F address-use events resolve to bounded pointer/object shapes? | `PROVED` within the finite model: 12 witnesses, consisting of 10 immediate object-field-shaped accesses (7 `LDR`, 3 `STR`) and 2 `UXTX` register-offset array-element-shaped loads; 11 unique access VAs and 1 duplicate witness. | Exact XBL plus mechanically hash-pinned 020F manifest; strict unsigned scalar and `UXTX` register-offset decoders at the exact event VAs; no runtime pointer/physical/MMIO/DRAM promotion or device/SMC/write. | `SUPPORTED` local pointer/object/array shape only; runtime base/currentness, object semantics, global writer/consumer absence, mutability, protected reach and alias/bypass remain `UNKNOWN`; `CLASS C`, `NOT_ELIGIBLE`. |
| 020H-FR | Do the exact 020G witnesses belong to bounded local function/role blocks with statically recoverable base origins? | `PROVED` within the finite model: 12 witnesses group into 11 unique access VAs and 7 return/direct-branch-delimited blocks; 9 blocks contain unsupported forms and 2 are local-read-shaped. Ten unique bases are `STATIC_SLOT_SEED`; indexed `0x9fc26ea0` is `ARITHMETIC_DERIVED` from `MADD`. | Exact XBL plus mechanically hash-pinned 020G manifest and 220-byte role region; strict RET X30/direct-B/direct-BL and bounded base decoders; no true-function/PA/DRAM/MMIO promotion or device/SMC/write. | `SUPPORTED` local helper/object role consistency only; true function boundaries, runtime/global/physical semantics, mutability, protected reach and alias/bypass remain `UNKNOWN`; `CLASS C`, `NOT_ELIGIBLE`. |
| 020I-CE | Do the exact 020H block-entry direct-BL sources reveal a bounded caller-context or argument-origin role? | `PROVED` within the finite model: 20 unique source/target BL edges traced for at most 16 preceding instructions; 12 windows stop on unsupported forms, 6 remain `ARGUMENT_OR_UNKNOWN`, and 2 are `ARGUMENT_COPY_OR_CONSTANT`. No static-slot-origin caller was reached. | Exact XBL plus mechanically hash-pinned 020H manifest; strict RET X30/direct-B/BL, scalar/register-offset memory, ADRP, ADD/SUB, MADD and MOV decoders; no true-function/PA/DRAM/MMIO promotion or device/SMC/write. | `SUPPORTED` caller-context shape only; runtime/true-function/global/physical semantics, mutability, protected reach and alias/bypass remain `UNKNOWN`; `CLASS C`, `NOT_ELIGIBLE`. |
| 020J-BO | Do the exact 020I unsupported caller-context barriers resolve to ordinary ARM64 opcode families without extending the trace? | `PROVED` within the finite model: 12 unique stop VAs classify as `B_COND` 5, `CBZ_CBNZ` 2, `LDP_STP_PAIR` 2, logical-immediate 2 and `BITFIELD` 1 (`BFXIL`); `UNKNOWN_OPCODE` count 0. | Exact XBL plus mechanically hash-pinned 020I manifest; inspect only the first unsupported stop word; strict family masks, exact 12/12 and family-count gates, raw-word hash only, no path continuation or device/SMC/MMIO/write. | `SUPPORTED` ordinary finite opcode shape only; full semantics, true functions, runtime/physical/DRAM identity, mutability, protected reach and alias/bypass remain `UNKNOWN`; `CLASS C`, `NOT_ELIGIBLE`. |

| 020K-OT | Do the exact 020J stop words resolve to bounded operands and local branch targets without extending the trace? | `PROVED` within the finite model: 12 unique stops preserve the 5/2/2/2/1 family split; conditional targets are aligned and remain in the same executable file-backed segment; pair offsets are `+64` and `-16`, both scalar 64-bit `STP`; the bitfield word is `BFXIL`. | Exact XBL, 020J producer and 020J manifest pins; local XBL loader; strict signed immediates, pair modes/scales, logical/bitfield width/N checks, target alignment/segment gates, word hashes only; no path continuation or device/SMC/MMIO/write. | `SUPPORTED` bounded operand/target shape only; instruction effects, true functions, runtime/physical/DRAM identity, mutability, protected reach and alias/bypass remain `UNKNOWN`; `CLASS C`, `NOT_ELIGIBLE`. |

## Integrated host-only rows 019–022, 024–027, 029, 031–033, 020E, 020F, 020G, 020H, 020I, 020J, 020K, V019 and 1b

| ID | Question | Bounded result | Classification and boundary |
|---:|---|---|---|
| 019 | Do exact DCB blocks contain candidate address/offset-value data that could feed controller programming? | `PROVED`: 28 strict syntactic pair arrays across four DCB blocks in absolute and base-relative key domains. Absolute keys do not reach ranked MC bases. Bounded stored/exact-wide/ORR materialisation finds `0x00003333` and `0x00300014` absent; `0x00300033` has two adjacent sequences. | Arrays are not proved register tables or consumers. Section/base semantics, consumer, register identity and writer remain `UNKNOWN`; no writer absence. |
| 020 | Which register-offset/computed-address shapes are outside the 018 immediate-offset models? | `PROVED`: bounded census of 719 register-offset stores (488 unscaled; 67 loop-shaped) and bounded computed-address audit. `SUPPORTED`: largest RWE segment is a candidate segment only. The narrow classifier has a pinned false negative at `0x14868a50`. | General walker, DCB consumer, runtime base, writer and semantic identity remain `UNKNOWN`; the false negative refutes a general zero-walker claim. |
| 021 | Does one pinned bounded-copy target receive DCB section data through direct edges? | `PROVED`: 7 direct `BL`, 0 direct `B`; five local labels `{0,1,2,15,16}`, two direct `BL` sites unlabelled. | Other-section/global/indirect delivery is `UNKNOWN`, not refuted. Only the local label-completeness claim is `REFUTED`. |
| 022 | How dense are two retained-evidence address channels around ranked MC instances? | `PROVED`: set-0/union/XBL-table/union counts `430/470/122/492`, with sparse observed-span density. | Completeness of the two enumerated channels is `REFUTED` by known `0x09248080`; implemented-register denominator/coverage is `UNKNOWN`. |
| 024 | Does the exact false-negative loop from 020 resolve as an XBL-resident six-byte table walker and a conditional UFS-PHY path? | `PROVED`: walker `[0x148689a0,0x14868a64)` uses six-byte records, exact `0x8000`/`B.EQ` return-before-store, and conditional 32-bit storage of the zero-extended byte; exactly three direct callers select five XBL-resident alternatives plus provider3's selector-`0xf` zero-count/no-pointer path. The selector unions contain 53 and 127 unique offsets, a 170-offset syntactic superset, and 221 nonterminator records. The two pinned design-source UFS blocks are byte-identical; under initialized-base retention all 170 symbolic destinations lie in broader `ufshc` `ufs_phy`. | `SUPPORTED`: table-driven UFS interpretation only under base retention and store reach. `UNKNOWN`: current base, selector/runtime execution, reached-store subset, flag semantics, live-DTB equality, DCB semantic alias/global consumer/writer, DDR/MC relation, GF(2), alias/bypass, and actual current destinations. All mappings are conditional symbolic supersets. |
| 025 | Can the intended XBL platform-query binding be statically tied from its caller and runtime slot through registry/attach, factory, vtable and callback, and does its recognized callback flow write caller context `+8`? | `PROVED`: helper `[0x1486abec,0x1486acac)` has caller `0x1486847c` with `X0=SP+0x10`, slot `0x14890590` load/address/reload, semantic `MOVZ/MOVK` ID `0x02000139`, seed `X0=0x14875668`/outer record `X1=0x14875590` count 5, descriptor `0x14824ab8` -> factory `0x1484a880` -> object candidate `0x1488f418` -> vtable `0x14824ad0 + 0x48` -> callback `0x1484a9d4`; bounded callback `a9d4->a730->a824->aa30->a854` has output write `0x1484a9f4` to helper `SP+0xc`, nested writes only at `0x1488f3f9/0x14890ba0/0x14890b90`, one decoded MMIO read `0x01fc8004`, and zero recognized MMIO writes. | `SUPPORTED`: conditional intended binding can populate the slot and the recognized callback flow does not write caller context `+8`. `UNKNOWN`: runtime registration/order, slot/object identity, actual `BLR X9` target, alternate BSS mutation/global aliases/unsupported writes, all-exec census coverage outside recognized forms, full `0x01d80000` base currentness, live mapping/authority. Class C remains unchanged; 015/016 remain `NOT ELIGIBLE`. |
| 026 | Does exact XBL statically close the bounded registration/bootstrap/dispatcher local edges, and does a complementary executable census recognize any interval-overlapping mutation of slot `0x14890590`? | `PROVED`: registration helpers `[0x1482ecb4,0x1482edac)` pin a 24-byte node (object/ID/next at `+0x0/+0x8/+0x10`) and head `0x14890f60`; initializer loop `[0x1482edac,0x1482f0b4)`; table header `[0x14875534,0x14875568)` has count 2, row start `0x14875538`, cursor `0x1487554c`, stride `0x18`; bounded bootstrap, veneer, alternates, dispatcher and callers have exact local/control/data edges, including dispatcher base/stride/index guard and symbolic pointer escape. `SUPPORTED`: memory-only initializer-pool shape `[0x146b30c0,0x146b38b0)`, two-row `0x3f8` geometry; pool contents/runtime values are `UNKNOWN`. Census: 847,465 words, 622 excluded 025 words, 9 accesses (3 writes/6 reads), 2 pointer escapes, zero recognized writes overlapping `[0x14890590,0x14890598)`. | Taxonomy `ORDER_OPEN`; slot result `PROVED_BOUNDED_NO_RECOGNIZED_SLOT_MUTATION`. Runtime order/execution, slot value, object identity, `BLR` target, base currentness and writer absence remain `UNKNOWN`; this is not global writer absence. Class C remains unchanged; 015/016 remain `NOT ELIGIBLE`. |
| 027 | Does a bounded fail-closed CFG/dataflow pass over the exact 020 site sets recover a DCB consumer or controller/SHRM symbolic target missed by earlier target-first passes? | `PROVED`: exact XBL/`xbl_config` and dependency pins, DCB sections `{6,7,8,10,11,12}`, section-7 keys `0x400/0x404` with `0x10000000` across four `0x3404`-byte blocks, and 020's 67 register-offset sites plus 8 computed idioms. Two dependency-owned register sites are excluded; 65 register sites plus 8 computed sites are analyzed. Result: 71 `INDIRECT_OR_UNSUPPORTED`, 2 `NO_TARGET_WITHIN_MODEL`, zero `DCB_CONSUMER_PATH`, zero `MC_OR_SHRM_SYMBOLIC_TARGET`; two nonexclusive `SECTION_READER_PROXIMITY_ONLY` hypotheses have no link proof. | Classification `BOUNDED_CONSUMER_WRITER_COMPLEMENT_UNKNOWN_GLOBAL`; zero target labels are bounded-model results, not global absence. Runtime base/current destination, execution/order, writer/global consumer identity, aliases, register semantics, unsupported paths and post-boot mutation remain `UNKNOWN`; Class C remains unchanged and 015/016 remain `NOT ELIGIBLE`. |
| 029 | What exact instruction forms remain outside the 027 decoder in its fail-closed ranges? | `PROVED`: the 71 ranges contain 1,992 occurrences / 1,180 unique VAs; the unsupported frontier is 352 occurrences / 219 unique VAs / 197 unique words. Primary counts are `DECODER_EXTENSION_CANDIDATE` 161, `FLAG_ONLY_NO_GPR_DEF` 99, `TAINT_KILL_REQUIRED` 27, `CONTROL_OR_MEMORY_UNSUPPORTED` 54, and `UNKNOWN` 11. | `BOUNDED_UNSUPPORTED_FRONTIER_INVENTORY_UNKNOWN`: syntactic range membership is not CFG reachability; source provenance, decoder safety, runtime destination, consumer/writer identity, and writer absence remain `UNKNOWN`/`NOT_CLAIMED`. Host-only, no device/MMIO/write action. |
| 031 | Can a source-qualified scalar-plus-dispatch v2 pass reduce the exact 029 frontier without promoting a consumer or writer? | `PROVED`: selected membership is 283 occurrences / 160 unique VAs / 148 unique words, with 250 reached selected events, 33 selected-not-reached occurrences, zero family/label mismatches, and zero events outside the selected domain. The residual is 69 occurrences / 59 unique VAs / 49 unique words across 20 sites. The combined model transitions 51 of 71 sites to bounded `NO_TARGET_WITHIN_MODEL`; 20 remain `INDIRECT_OR_UNSUPPORTED`. `DIRECT_CONTROL_DISPATCH_REPAIR` contributes 143 events across 62 sites (`B.cond` 87, `CBZ/CBNZ` 28, `B` 15, `TBZ/TBNZ` 13); with repair sites split 48 no-target/14 fail-closed, without it 3/6. | `V2_MODEL_ONLY` / `NO_ABSENCE_CLAIM`: the 51 result depends on combined scalar and dispatch repair, not scalar-only closure. Pair/sign-extending memory, system/control, three-source, `BIC`/`EOR`, indirect aliases and unsafe forms remain fail-closed; zero `DCB_CONSUMER_PATH` and zero `MC_OR_SHRM_SYMBOLIC_TARGET`. Runtime destination, writer/consumer identity, execution/order, alias, writability and live authority remain `UNKNOWN`. |
| 032 | Can source-qualified arithmetic semantics reduce the exact reached 031/029 frontier without promoting a consumer or writer? | `PROVED`: the combined selection is 298 occurrences / 175 unique VAs / 162 unique words across 71 ranges, with 264 reached selected events and 34 selected-not-reached occurrences. The arithmetic extension contributes 15 selected rows across 7 sites and 14 reached events (`MADD` 3, `UMADDL` 7, `EOR` 2, `BIC` 2). The result transitions 55/71 sites to `NO_TARGET_WITHIN_MODEL`; 16 remain `INDIRECT_OR_UNSUPPORTED`; relative to 031, sites 1/36/37/52 transition with zero regressions. The residual is 54 occurrences / 44 unique VAs / 35 unique words across 15 sites (`PAIR_MEMORY` 48, `SIGN_EXTENDING_MEMORY` 2, `SYSTEM_CONTROL` 4). | `V3_MODEL_ONLY` / `NO_ABSENCE_CLAIM`: exact full-record equivalence preserves 250 scalar, 143 direct-control, and 23 taint-kill 031 events. Qualified arithmetic is modulo-width and identity-limited; pair/sign-extending memory, system/control, indirect aliases, reserved/unknown forms remain fail-closed. Zero `DCB_CONSUMER_PATH` and zero `MC_OR_SHRM_SYMBOLIC_TARGET`; current destination, writer absence, execution and live authority remain `UNKNOWN`. Host-only, no device/MMIO/write action. |
| 033 | Can source-qualified pair-memory, sign-extending-memory, and system-control semantics reduce the exact residual left by Experiment 032 without promoting a consumer or writer? | `PROVED`: the complete 029 frontier is selected as 352 occurrences / 219 unique VAs / 197 unique words; 308 selected events are reached and 44 selected occurrences are not reached. The new residual admission is 44 events: `LDP` 38, `STP` 3, `LDRSW` 1, `LDRSB` 1, and `DAIFClr` 1. Three `STP` instructions publish six explicit lane observations. The bounded site outcome is 70 `NO_TARGET_WITHIN_MODEL` / 1 `INDIRECT_OR_UNSUPPORTED`, with site 35 remaining unresolved. | `V4_MODEL_ONLY` / `NO_ABSENCE_CLAIM`: inherited 032 full-record equality is exact for 264 extension, 143 direct-control, and 23 taint-kill events. Zero bounded `DCB_CONSUMER_PATH` and `MC_OR_SHRM_SYMBOLIC_TARGET`; global writer/current destination/protected-memory semantics and `DAIFClr` current-EL/`CheckDAIFAccess` remain `UNKNOWN`. Host-only, no device/MMIO/write action; Class C and 015/016 eligibility unchanged. |
| 034 | Does site 35's exact guarded jump table resolve the final Experiment 033 fail-closed edge without promoting a consumer or controller target? | `PROVED`: contiguous `LDR W9`/`CMP W9,#4`/`B.HI`/`ADRP+ADD`/indexed `LDR X1`/`BR X1` dispatch, table `0x14824cf0`, five entries and four unique mapped local targets. Four independent in-memory direct-edge runs are CFG-complete with no unsupported form. The composed result is 71 `NO_TARGET_WITHIN_MODEL` / zero fail-closed sites, with exactly one transition from 033 and no regression. | `BOUNDED_STATIC_RESOLUTION_ONLY` / `NO_ABSENCE_CLAIM`: baseline 033 site records remain verbatim; zero bounded consumer/controller targets are promoted. External/unmodeled entries, runtime `BR`/direct-`B` equivalence, execution/index/table contents, current destination, writer/consumer absence and security effect remain `UNKNOWN`. Host-only; Class C and 015/016 eligibility unchanged. |
| 020J | Do the exact 020I unsupported caller-context barriers resolve to ordinary ARM64 families without extending the trace? | `PROVED` within the finite model: 12 unique first-stop VAs classify as `B_COND` 5, `CBZ_CBNZ` 2, `LDP_STP_PAIR` 2, logical-immediate 2 and `BITFIELD` 1 (`BFXIL`); `UNKNOWN_OPCODE` count 0. | Exact XBL plus hash-pinned 020I manifest; inspect only first stop words; strict family masks, exact 12/12 and family-count gates, raw-word hashes only, no path continuation or device/SMC/MMIO/write. | `SUPPORTED` finite opcode shape only; full semantics, true functions, runtime/physical/DRAM identity, mutability, protected reach and alias/bypass remain `UNKNOWN`; `CLASS C`, `NOT_ELIGIBLE`. |

## Reconciled external A-line and repaired runtime evidence

| ID | Question | Bounded result | Classification and boundary |
|---:|---|---|---|
| 019A | Do selected DCB regions contain pair-array shapes compatible with later register programming? | `PROVED`: exact syntactic pair arrays and their bounded materialization forms are inventoried. | Candidate shapes are not register-table semantics. Implicit bases, consumers, runtime destinations and writers remain `UNKNOWN`. |
| 020A | Do selected XBL literal and local consumer models identify a controller setter? | `PROVED`: bounded literal/cross-reference and conditional setter-idiom results for the named sites. | The largest RWE segment is only a candidate DDR segment. Alternative pointer forms, encodings, runtime base arguments and writer identity remain `UNKNOWN`; Experiment 018 is not generally invalidated. |
| 021A | Do direct bounded-copy calls establish DCB-section delivery? | `PROVED`: seven direct `BL` and zero direct `B`; two calls have no local DCB-section label. | Local labelled delivery is bounded evidence only. Other-section, global and indirect delivery remain `UNKNOWN`; global absence is not claimed. |
| 022A | Are the two retained address-observation channels complete? | `REFUTED`: known address `0x09248080` is outside both enumerated channels. | Channel density is descriptive only. Implemented-register coverage and unobserved addresses remain `UNKNOWN`. |
| 023R | Does a repaired second-region timing protocol recover the same relation beyond Experiment 014's allocation window? | `PROVED` in allocation-offset/model coordinates: 66 summaries/58 unique differences, threshold 359 with empty gap 182..537, a unique rank-three kernel, and bit-24 contribution `0b110`. | Physical PA24/rank/model-base attribution is `SUPPORTED_WITHIN_MODEL` under contiguous-qsecom plus Experiment-014-relation assumptions. All pagemap records are `BLIND`; effective contiguity, alias, mutation and protected reach remain `UNKNOWN`/not observed. |
| 028 | Do the 023R numeric covectors appear in the decoded SHRM register snapshot under tested encodings? | `PROVED`: seven numeric model covectors; zero register-mask/index/triple matches among 494 decoded registers/274 nonzero. Two tested firmware literal hits are unaligned chance matches; the 200-decoy baseline averages 0.66 hits per mask. | Negative scope is only the observed register set and tested encodings; physical-bank attribution is `SUPPORTED_WITHIN_MODEL`. Derived state, writer and runtime mutation remain `UNKNOWN`. |
| 029A | Can exact ABL be reproducibly extracted and searched for the bounded controller/model encodings? | `PROVED`: deterministic flat extraction of the exact ABL payload and zero exact stored controller-base, model-mask and tested adjacent-triple hits; exact diagnostic-string counts are retained. | PE32 execution/disassembly, computed values, controller participation/writes, SMEM value and live DT are `UNKNOWN`/`UNRETAINED_UNKNOWN`. |
| 030 | Do retained low-bit timing phases prove PA9/PA10 are independent channel selectors? | `REFUTED` within the measured reopen model: upward departure from conflict does not prove an independent channel selector. Complete spread-mode triplets for PA9/PA10 and stride-mode PA9 are `SATURATING`; stride-mode PA10 is `INCOMPLETE`. | Whether PA9/PA10 jointly contribute channel, rank, bank group or another coordinate remains `UNKNOWN`; no phase is merged by filename/order. |
| V015 | Is the repaired 023R relation stable across the exact retained condition-labelled runtime/reboot/coldboot transcript sets? | `PROVED` in allocation-offset/model coordinates: six equal 51-key condition sets; four clean zero-disagreement comparisons; L762 has two excursions and remains `REPEAT_REQUIRED`/`all_invariant=false`. Six independently split repeat groups cover both and have zero flips. The retained sweep is exactly six requested bus-vote levels × two. | Runtime/reboot/coldboot identities are only `SUPPORTED_BY_UNRETAINED_OPERATOR_REPORT`. Bus-vote data are excluded from DDR-frequency/transform-transition inference; pagemap is `BLIND`, effective contiguity and physical attribution are `UNKNOWN`. No alias, mutation, protected reach or bypass is observed or proved by V015; numbered Experiments 015/016 remain `NOT_ELIGIBLE`. |
| V016-AUDIT | Does the retained high-bit conclusion survive an independently selected statistic and provenance check? | Recompute all 288 per-pair deltas, lower/upper medians, threshold, labels, and Git history rather than accepting analyzer expectations. | Exact retained raw; compare lower and upper even-N statistic; inspect preregistration history; no device action. | `CONFIRMED` audit defect: decisive rows are 16/32 mixtures with lower/upper `226/475` and `223/437`; lower median moves threshold `299 -> 356` and agreement `7/7 -> 5/7`. No preregistration is retained. High-bit physical conclusion reopened; low-bit results unaffected. |
| V030 | Can one exact heap-30 allocation expose its allocation-local SG/PFN placement without assuming the DT base? | Five self-scoped perf tracepoints plus three same-run CMA `(pfn,page)` calibration records yield a strictly validated private trace and bounded public PA summary. | Fixed A90/V2321 contract; no selectable address/heap/size; durable no-replay; cleanup/final health; no controller/MMIO/SMC/protected access. | `PRE_REGISTERED / HOST IMPLEMENTATION COMPLETE / 10 FOCUSED PASS / NO LIVE EFFECT`. Python compile, host-only preflight, and `aarch64-linux-gnu-gcc -static -Werror` build pass. Physical provenance remains `UNKNOWN` until a separately authorised execution. |
| V031 | Can a same-harness ladder distinguish generic load failure, DC_NOC path failure, and address-correlated raw-policy behavior? | Two GICD values gate LLCC-PMU/MCCC and raw-bit-30-set LLCC reads before the raw-bit-30-clear remapper load. | Six fixed read-only addresses; same candidate/boot/code path; bit30 actor explicitly `UNKNOWN`; stop before remapper if controls fail. | `DESIGNED / DEFERRED UNTIL V030 CLOSES / NO LIVE EFFECT`. It is a discriminator, not evidence that bit30 names HLOS or that XPU caused V024. |

The integrated results retain `CLASS C (TRANSFORM ONLY)` as the operational
gate, with the precise reading `C-MAP only; alias/mutation/reach/policy-path/
order unresolved; no Class D/E effect observed`. Experiments 015 and 016 remain
`NOT ELIGIBLE`. Experiment 027 validation is 35 focused and 616 full
unittest PASS in 86.100 s, Python byte-compilation, 67 public JSON manifests,
two fresh byte-identical generations, public safety/no-clobber, and independent
hostile review `PASS` after fixes, recorded in
[EXP027_INTEGRATION_REVIEW_2026-08-26.md](EXP027_INTEGRATION_REVIEW_2026-08-26.md).
Experiment 029 is `COMPLETED` and integrated from commit `a495bdc`; its
validation is 17 focused and 633 full unittest PASS in 84.985 s, 68 public
JSON manifests, byte-identical repetition, and final hostile review `PASS`, as
recorded in [EXP029_INTEGRATION_REVIEW_2026-08-26.md](EXP029_INTEGRATION_REVIEW_2026-08-26.md).
Experiment 031 is `COMPLETED` and integrated from artifact commit `cd9f26e`
plus reconciliation repair `12a8ebe`; its validation is 19 focused and 652
tracked full unittest PASS in 85.226 s, maximum RSS 220,684 KiB with no swaps,
69 public JSON manifests, Python byte-compilation, QEMU 280/280, two fresh
byte-identical manifests, and final reconciliation hostile review `PASS`, as
recorded in [EXP031_INTEGRATION_REVIEW_2026-08-26.md](EXP031_INTEGRATION_REVIEW_2026-08-26.md).
The reconciled 031 public manifest is 1,327,118 bytes, mode `0644`, SHA-256
`51a187195c16eb609d337305540fc6d20a09297f5ab76b054497c5c58c3a2e86`.
Experiment 032 is `COMPLETED` and integrated from artifact commit `d46c44c`
after docs commit `e063181`; its validation is 18 focused PASS (maximum RSS
58,388 KiB, no swaps), 670 full-discovery unittest PASS in 84.937 s (maximum RSS
233,928 KiB, no swaps), Python byte-compilation, 70 public JSON manifests,
two fresh byte-identical manifests, exact-word QEMU 56/56, synthetic QEMU
76/76, logical/three-source encoding grids totaling 1,152/1,152, and final
independent hostile review
`PASS`, as recorded in
[EXP032_INTEGRATION_REVIEW_2026-08-26.md](EXP032_INTEGRATION_REVIEW_2026-08-26.md).
The checked 032 public manifest is 1,564,295 bytes, mode `0644`, SHA-256
`beee3cdaa7d69f240310bed8b574f8dd81b00b48c2383f48dd849ebd36fb4b31`.
The historical Experiment 023 result remains `WITHHELD/NO-GO`; its public
manifest is retained for audit but it is not promoted. Experiment 023R is the
separate repaired model result and carries the coordinate/provenance limits in
the table above. Experiment 033 is `COMPLETED` and integrated from artifact commit `56b5ffa`; its
public manifest is 2,017,356 bytes, mode `0644`, SHA-256
`606723e5125d661c800b167133f2a9b69a3b8d47361b39176665a49be539e598`.
Validation is 15 focused / 685 full unittest PASS, full maximum RSS
253,944 KiB with zero swap, byte-identical fresh publications, and independent
hostile review `PASS` with no P0-P2 findings. Experiment 034 is completed in
artifact commit `d5d8046`: its guarded table has five entries/four unique local
targets, all four bounded direct-edge runs are CFG-complete, and the composed
outcome is 71 `NO_TARGET_WITHIN_MODEL` / zero fail-closed sites. Validation is
14 focused and 699 full unittest PASS; the final hostile review is `PASS` after
a `CMP W` width-mask repair. Runtime equivalence, execution, current table
contents/destination, global absence and security effect remain `UNKNOWN`.

External parent `247b0e1` is reconciled after phase-preserving 030 repair,
bounded 019A–023R claims, reproducible 029A extraction, corrected
IDs/commands/hashes, primary verification and independent hostile review.
Later implementations through observed `c91f473` remain unpromoted wholesale;
the review response is preserved and V015/V016 are independently rebuilt.
Verification 015 uses exact retained inputs:
44 focused / 1,039 full serial tests and hostile review `PASS`. Verification
016 is also independently repaired from three exact retained inputs: 23 focused
/ 1,062 full serial tests, phase-preserving high-bit analysis, model-only
physical scope, and final hostile-review `PASS`. Verification 017 is complete as
a model-projection bank-only exclusion. Verification 018 now supplies the
repaired/reacquired non-secure allocation-local storage-identity baseline. The
Route-2 manifest audit is complete with Q1 bounded `SUPPORTED` closure and Q4
`UNKNOWN`; Verification 020A is complete as a symbolic setter/base trace, and
the next selected work was host-only 020B caller-object origin tracing, now
complete; 020C then traced its `0x9fc160b8` return helper, and 020D traced the
second helper caller at `0x9fc26e2c`.  The next candidate is a static-slot
consumer census (020E), now complete; 020F then traced the twelve resulting
loads through bounded same-block use chains; 020G then resolved its address-use
events to 12 bounded pointer/object witnesses (10 immediate and 2 `UXTX`
register-offset, with 11 unique VAs and 1 duplicate witness); 020H then
grouped them into 7 bounded local blocks and classified their base origins;
020I then checked 20 direct-BL caller contexts with 12 unsupported stops, 6
unknown and 2 argument-shaped rows; 020J then classified those 12 first stop
words as `B_COND` 5, `CBZ_CBNZ` 2, `LDP_STP_PAIR` 2, logical-immediate 2 and
`BITFIELD` 1, with no `UNKNOWN_OPCODE` fallback.  The next candidate is a
bounded barrier operand/target metadata inventory (020K).
Experiment 035 remains deferred.

The Stage 2E row's writeback result is an exact audit of all recognized
single/pair memory-writeback forms: four sites per function (two SP frame
updates and two non-SP writebacks), zero recognized BR/BLR transfers, and one
external direct BL to each function start with no external entry to an interior.

## Experiment 001 metadata

- Target model: `SM-A908N`
- SoC: `SM8150`
- Firmware/build: runtime `v2321-usb-clean-identity-rodata`; Android kernel build
  `A908NKSU5EWA3`
- Kernel: `4.14.190-25818860`, exact live build string in private record
- Kernel build/hash: live bytes `UNKNOWN`; host-extracted v2321 kernel candidate
  SHA-256 `d97eb6c7291477000299fae1c4272105e95fe77df09631ae13099303510b5263`;
  exact rebuild System.map SHA-256
  `573d61f1d6fcefbe3f9b0b1ccb88dad92eeddbb449ad45baa26c22233c25bf74`
- Boot image hash: live bytes `UNKNOWN`; host candidate SHA-256
  `ca978551aabe4b39563abaf529ccf2522054952d8b2ad852e632d26da88168cb`
- DTB hash: live bytes `UNKNOWN`
- Timestamp: `2026-08-25 03:31:00 KST`
- Preconditions: owner-pinned A90 ACM bridge; research runtime at prompt; no
  protected-memory or MMIO access
- Exact action: fixed `version`, `/proc` `cat`, reserved-memory `ls`, and five
  DT `reg` `cat` commands emitted by `tools/a90_acm_snapshot.py`
- Result: all 12 A90P1 frames `rc=0 status=ok`
- Raw artifact: private JSON, 28,353 bytes, SHA-256
  `977320c895c0098d6de5ff6bead3baf1cf654b203687a60f804078a4b1305a18`
- Public manifest SHA-256:
  `b616639b3afe8e43b74c4417fef02e54e2f8f549f0cdd85f466af20fa8cd8705`
- Collector SHA-256 at capture time:
  `e05fd1667c23888be743123f6b3791fbec8cbac24adcb4e296bc6b495f672084`
- Committed collector after EOF-only normalization:
  `aa6eaf9f2595dddb7e79ee4b6627dacdf95768a51ea3b2ca7b94475881f632b5`
- Repetition count: 1

## Experiment 004 metadata

- Target: live pinned `SM-A908N`, `SM8150`
- Runtime/kernel: `v2321-usb-clean-identity-rodata`,
  `4.14.190-25818860-abA908NKSU5EWA3`
- Timestamp: `2026-08-25 03:59:30–03:59:36 KST`
- Exact action: live sysfs GPT identity/size/`ro`; temporary block node;
  device SHA-256; exact-size A90P1 `cat`; device SHA-256; node removal
- Result: nine artifacts, 26,779,648 bytes; every before/host/after hash equal
- Historical comparison: all five previously measured hashes equal
- Device write: none; filesystem-only temporary `/dev` nodes removed
- Postcondition: no `sdm855_mblab_*` node, selftest `fail=0`, bridge stopped
- Public manifest SHA-256:
  `1ed4b8b14b2e0ccf2d4ae084ea413e0395d9dc488dd5d2bb1dd872fbe20d9247`
- Capture tool SHA-256:
  `b6dd2c928447d1ca3fba34be7adbabc0aaf2152b0211b44c06e2de8c81e3c652`
- Frame helper SHA-256:
  `288291dc8025d1a7bbad4541cee417953cd820b0836056c62012a530b790adbd`
- DCB inventory manifest SHA-256:
  `aa6467904f88fd3370c87c7847f2dcb11b28b3f07e5e4b6a489de879bdcf7157`
- DCB inventory tool SHA-256:
  `7ef54d9a6c7c82a7282b5beb6cafda4f9351afbdca8530097f66367ea33804a7`
- Repetition count: 1 full capture, preceded by one 128 KiB `devcfg` transport smoke

## Experiment 006 metadata

- Inputs: exact Experiment 004 `xbl--sdb1`, `xbl_config--sdb2`, and `tz--sdd5`
  artifacts, respectively SHA-256 `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`,
  `0e9dfac1ddd0f9acc2cc899213e621490308f0cadf329814048edb7712e2484c`,
  and `a5e6c574e18e2e576a25df6274b20bdb142386811dfda6383f86d7b1b3c102ab`
- Exact action: host-only ELF/CFGL/DCB parsing, SHRM blob hashing, remapper-table
  parsing and DAL structure-pointer traversal
- Result: four exact qhs_llcc remapper bases, layout-1 offsets through `+0x58`,
  plus a matching TrustZone record
- Static phase device command/write: none; subsequent live selector/config
  capture is recorded below
- Public manifest SHA-256:
  `39469ac59ef0e3a2b9858b7435a4433def58d57407a4066da3854cfdd24409a5`
- Static inventory tool SHA-256:
  `be9aa3cbb477f47539ef7da1ba75b1785bdaefd5ebdb4fb56ea49fbe9440e6b7`
- Read-only identity collector SHA-256:
  `0b4f99ee1d79ebc586807d88a9bea00f6edcd8409e29c6fdbbe7c34c00ae4f99`
- Fixed ICB remapper collector SHA-256:
  `4020d7e550589d50e466c009fd356f5f2ab16898e731d1fa07d69a2038bd0f1d`
- A90 frame helper SHA-256:
  `86a6c2f82cd7ac3b9f5885b1eafa727cc463ea8be2915b259a83f2036fab3402`
- Host verification: 38 unit tests pass; regenerated static manifest is byte-identical

## Experiment 006 live selector/config metadata

- Live values: SoC ID `339`, revision `2.2`, Linux SMEM `raw_id=165`,
  `raw_version=3`, platform `MTP`, subtype `charm`
- `REFUTED`: treating Linux `raw_id/raw_version` as XBL's direct
  `0x6003/{0x0100,0x0200}` filename fields; the attempted derivation is absent
  from exact CFGL
- At Experiment 006 time, physical-platform `_1` was only `SUPPORTED` by live
  `MTP` and the revision was `UNKNOWN`; Experiment 008 supersedes both with
  retained XBL/CDT proof of `/6003_0200_1_dcb.bin`
- Superseding live identity/config manifest SHA-256:
  `d4bea281c1533a162d7fa077a12cf0c780b8dcc175fc62b36631a1e29ff7f5d1`
- Superseding private raw snapshot SHA-256:
  `1c4ebf17ec35ba33e36b988effe153a24e7fd9dd2498745b8597f3593dee86c1`

## Experiment 005 live metadata

- Exact target: host sysfs `04e8:6861`, product `A90-LNX`, interface
  `A90 Linux ARM64`; target-pinned by-id bridge; other Samsung ACM untouched
- First attempt: one 32-bit read at `0x09248080`; failed before MMIO because
  `/dev/mem` was absent
- Second attempt: temporary `/dev/sdm855_mblab_mem` character node `1:1` created;
  the same read failed at open with `ENXIO`; node cleanup and absence proved
- Memory/MMIO writes: none; temporary devfs-node mutation only
- First public manifest SHA-256:
  `2010907bb1d7e652352a526cda59069b08e7e40ad7a290bd0b6a48379ce069f6`
- Node-backed public manifest SHA-256:
  `35e96ea34bb2d2fea643edcd408710e44c6a936d7ef395859db119d0fa5d31e3`
- Live config: gzip payload SHA-256
  `ff2543fee33573e8efe34110598e963d7ddc9c44fbbf5dc1256cd6edec0f8fde`,
  selected line `# CONFIG_DEVMEM is not set`
- Exact board defconfig SHA-256:
  `3d90a83d61a7a1873249642f7657c572e06f91a61bc3e5b737758f08ec765216`,
  same `CONFIG_DEVMEM=n` result
- Final health: runtime version payload unchanged; selftest
  `pass=11 warn=1 fail=0`; bridge stopped

## Experiment 007 kernel-adapter metadata

- Target: exact `SM-A908N` / `SM8150`; the separate attached `SM-S906N`
  endpoint received no command
- Candidate: historical live-proven REPL boot SHA-256
  `b846ae9f74d8ceb922bbcd854d78b6795ef833d61e38465d3cc474cb6f0dfb65`
- System.map SHA-256:
  `9e6a1d6f322344e3d6fced7e6d29a254e1516cc5163bad8595388a9d0d02ec3a`
- Preconditions: candidate boot prefix verified in TWRP; native health
  `pass=11 warn=1 fail=0`; named REPL peek/call selftest passed; one fresh warm
  boot before the effective attempt
- Attempts 01 and 02: stopped at replay-safe slide-result capture noise; no map
  or MMIO operation
- Attempt 03: stopped at preflight `EBUSY`; no REPL or MMIO operation
- Attempt 04 exact action: recover slide, invoke only
  `__ioremap(0x09248080, 0x5c, 0x0068000000000707)`; intended next actions were
  `msm_readl` and `__iounmap`
- Result: retained log records the slide and `__ioremap` return, followed
  3.027327 seconds later by `Non Secure Watchdog Bark`; `msm_readl` was never
  invoked and zero register values were obtained
- Call-safety audit: existing classifier returns `DENY` for `__ioremap`,
  `__iounmap`, and `msm_readl`; the experiment wrapper incorrectly bypassed
  that policy by calling the low-level session API directly
- MMIO/memory writes: none; boot-partition writes were the exact candidate and
  verified V2321 rollback only
- Effective-attempt collector SHA-256:
  `63130ace433f76acf79470219faf9023624d2e3a9d66fc24f9eebef3b81648b6`
- Public watchdog manifest:
  `evidence/manifests/007-kernel-remapper-watchdog-20260825-01.manifest.json`
- Raw retained watchdog evidence SHA-256:
  `d89347a270e52519559a9ff12b44d46dabd8d5d8e87af28e9efe601370d22c54`
- Rollback: TWRP boot-prefix size `60,882,944`, SHA-256
  `ca978551aabe4b39563abaf529ccf2522054952d8b2ad852e632d26da88168cb`;
  final native runtime health `pass=11 warn=1 fail=0`
- Repetition count: one effective `__ioremap` call; it is not eligible for
  repetition through the generic REPL path
- Host-only successor control: boot SHA-256 `dbbf81f26cd3d9d2d52d2a2dbe84575b759b45cea8946d02646bd4503ad08247`,
  body SHA-256 `0a094ef803e78c773bb548f12c4eb364da27b4b3681dc0d4b37edbf883cf30a7`;
  map → immediate unmap → `0xc071`, zero MMIO loads
- Host-only successor read: boot SHA-256 `6fe92825702f304a067fc716c3814a63b2f4e76198a054de4c666cad55a462ed`,
  body SHA-256 `730f420b219f9ad3ab7da5488f5b8dac3638099cc0007aad7dd31ddfb53982d6`;
  exactly one fixed 32-bit load and unmap before result
- Both successors reproduced byte-identically three times
- Control live result: one invocation returned `0x0000c071`, post-health OK;
  public manifest `007-inline-remapper-control-live-20260825-01`
- Read live result: one invocation, no automatic retry, no returned value,
  USB/ACM disconnect and retained `Non Secure Watchdog Bark` at 69.080426 s;
  public derived manifest `007-inline-remapper-read-watchdog-20260825-01`
- Final rollback: V2321 full-prefix readback match and native selftest
  `pass=11 warn=1 fail=0`; the fixed read is not eligible for repetition

## Experiment 008 exact remapper-boundary metadata

- Experiment ID: `008-remapper-boundary-inventory-20260825-01`
- Target model / SoC: exact retained `SM-A908N` / `SM8150`
- Firmware/build: XBL `BOOT.XF.3.0-00468-SM8150LZB-1`, exact Experiment 004
  XBL/XBL-config/TZ partition hashes pinned by the tool
- Kernel build/hash: no kernel executed in this host-only phase; retained log
  input is exact Experiment 007 artifact SHA-256 `8701d073…`
- Boot image / DTB / research-kernel hash: no new boot artifact; V2321 was
  already restored and health-proved after Experiment 007; live DTB remains
  `UNKNOWN`
- Timestamp: `2026-08-25 07:10 KST`
- Preconditions: exact four inputs present and matching pinned sizes/hashes;
  no connected-device or MMIO precondition
- Exact action: `python3 tools/sm8150_remapper_boundary_inventory.py --replace`
- Result: exact DCB `/6003_0200_1_dcb.bin`; rank topology 3072+3072 MiB;
  unique row 7; 36-bit layout-1 writer; four same-window BIMC MPU registry
  records; numeric boot words and protection coverage remain `UNKNOWN`
- Log reference: private retained last-kmsg SHA-256 `8701d073…`; seven
  consistent chip/CDT observations and six consistent rank observations
- Public manifest SHA-256:
  `b4bb1082df278b57055f164d3da9c3a2f420ac9cc3d904ccb1ea24e78b9f3f9a`
- Private derived record SHA-256:
  `2154ee2af18d0e98b92f6658120cde89434433be8db8f592d026ad278b6660ff`
- Tool SHA-256:
  `f7369436326de88421e4c4e98c518bb5f59e9c5aa94a6f9b9311340da1a87bca`
- Host verification: 66 unit tests pass; all public manifests parse; final
  private/public outputs reproduce byte-identically
- Repetition count: one final exact parser run; repeated boot values are counted
  independently in the manifest
- Device/MMIO/controller writes: none; device access: none

## Experiment 009 exact XPU-policy metadata

- Experiment ID: `009-xpu-policy-inventory-20260825-01`
- Target model / SoC: exact retained `SM-A908N` / `SM8150`
- Firmware/build: exact Experiment 004 TrustZone and devcfg partition hashes,
  pinned by the tool
- Kernel build/hash: no kernel executed in this host-only phase; retained log
  input is exact Experiment 007 artifact SHA-256 `8701d073…`
- Boot image / DTB / research-kernel hash: no new boot artifact or device
  action; V2321 remains the last health-proved runtime; live DTB remains
  `UNKNOWN`
- Timestamp: `2026-08-25 07:43 KST`
- Preconditions: exact TZ, devcfg, and last-kmsg inputs present and matching
  pinned sizes/hashes; no connected-device or MMIO precondition
- Exact action: `python3 tools/sm8150_xpu_policy_inventory.py --replace`
- Result: consumed 48-entry registry; two policy branches with identical
  `DC_NOC_BROADCAST_MPU` raw-row coverage of `0x09248080`; owner/raw words and
  `disable_xpu_ac=0` are exact. The prior MSA/HLOS actor names and XPU-denial
  inference are superseded; effective client/path and cause remain `UNKNOWN`.
- Log reference: retained last-kmsg SHA-256 `8701d073…`; decoded XPU syndrome
  absent because the collector reports encrypted/unparsed TZ log
- Public manifest SHA-256:
  `f5c661af73cd6b4a0d423ef44a59b11cba0e208ad178670ff2dabf097bf2e4e6`
- Private derived record SHA-256:
  `d90d48f776907d23e29b593e3f9eb36c841c84a3ed663703fad018c4c69cff2c`
- Tool SHA-256:
  `88b6cd2ee74ce3e3b50efd59ce64886f5bd66098b50636b766a6213d6361ae3e`
- Focused-test SHA-256:
  `dd17da25f1a99a6ba123e9cd252650bc8219dc1208e3c9d9732c78b6ab81896d`
- Host verification: seven focused tests and all 73 repository tests pass; all
  public manifests parse; final private/public outputs reproduce byte-identically
- Repetition count: one final parser generation; the same live MMIO load was
  not repeated
- Device/MMIO/controller writes: none; device access: none

## Experiment 010 exact XPU-initializer metadata

- Experiment ID: `010-xpu-initializer-inventory-20260825-01`
- Target model / SoC: exact retained `SM-A908N` / `SM8150`
- Firmware/build: exact Experiment 004 XBL, TrustZone, QHEE/hyp, and devcfg
  partition hashes pinned by the tool; no substituted generation or target
- Kernel build/hash: no kernel executed in this host-only phase
- Boot image / DTB / research-kernel hash: no new boot artifact and no device
  action; V2321 remains the last health-proved runtime; live DTB remains
  `UNKNOWN`
- Timestamp: `2026-08-25 08:18 KST`
- Preconditions: all four exact inputs present and matching pinned sizes and
  SHA-256; no connected-device, SMC, or MMIO precondition
- Exact action:
  `python3 tools/sm8150_xpu_initializer_inventory.py --replace`
- Result: exact QHEE `hyp_assign` uses local stage-2/SMMU access control;
  separate TZ same-ID fallback reaches dynamic `BIMC_MPU0..3` policy; XPU
  disable allowlist count is zero; all eight known controller apertures have
  branch-invariant broad TZ-owned raw address coverage. Effective HLOS/all-
  master access, overlap precedence and final live policy remain `UNKNOWN`.
- Log reference: none; this phase consumed only exact firmware images and did
  not infer runtime values from a device log
- Public manifest SHA-256:
  `baeef82f8f0fad7c7e897e3c373dacd129b7f2ed22d78c075a94141ee36c1ce2`
- Private derived record SHA-256:
  `dc4a664b2d9a01982b37684a4e63dd8e5183f41f6fbec191a1169d8ee418133a`
- Tool SHA-256:
  `10b134568213973ef6a69a57a0c384442f27fb8011f008cb23a60ecfd7939005`
- Focused-test SHA-256:
  `c7d1fd557f0499673cbcdf0d7824f54ce002b28ac04a9946f2cb3551bb81ed33`
- Host verification: eight focused tests and all 81 repository tests pass;
  every public manifest parses; three consecutive private/public generations
  are byte-identical; private mode `0600`, public mode `0644`
- Repetition count: one final analysis result, regenerated three times only for
  deterministic host verification
- Device/SMC/MMIO/controller/partition writes: none; device access: none

## Verifications 003/004 A90 raw-dump eligibility metadata

- Verification IDs:
  `verification-003-a90-rawdump-eligibility-20260825-01` and
  `verification-004-a90-rawdump-eligibility-sourcebacked-20260825-01`
- Question: do current exact V2321 property-free proc/sys surfaces positively
  qualify a later XBL `SHRM_MEM.BIN` collection attempt?
- Target: exact `SM-A908N` / `SM8150`, V2321 `0.9.285`, kernel
  `4.14.190-25818860-abA908NKSU5EWA3`
- Transport: existing operator-pinned A90P1 loopback bridge to A90
  `04e8:6861`; the separate Samsung `04e8:6860` endpoint received no command
- Verification 003 result: `debug_level=0x4f4c` (`LOW`), `force_upload=0`,
  S22+ `qcom_dload_mode` path absent, ramoops `max_reason` path absent,
  `panic=-1`, `panic_on_warn=0`
- Source correction: exact A90 `msm-poweroff.c` SHA-256 `0a2b20ec…` owns
  `module_param_call(download_mode, ...)`; retained live config has
  `CONFIG_QCOM_DLOAD_MODE=y` and `CONFIG_QCOM_MINIDUMP=n`
- Verification 004 result: A90 source-backed
  `/sys/module/msm_poweroff/parameters/download_mode=1`
- Final signal vector: debug `NEGATIVE`, force-upload `NEGATIVE`, dload master
  `POSITIVE`; classification `DUMP_ENTRY_SIGNALS_INCOMPLETE`; actual XBL
  FMM/token eligibility `UNKNOWN`
- Public manifest SHA-256 values: V003
  `bbd1da19fa8b7d2b56c6a8f8683ba49fac34aa9fc96d9f05727cb8e58672f856`,
  V004 `a0e5b047ea95169b009c962bf8b445b6f757edebebf4401746d5f0751367bd37`
- Private record SHA-256 values: V003
  `1a5b4b981c2eeb9f6a0fd9683062c8405db55dbe4db7f7ebe23d8c8e0f1365d5`,
  V004 `02cf1474b74d8befca9ea1be192fbd8667e4fc94870d42be0c19bc322a5de8b2`
- Final tool SHA-256:
  `9386c03e444ceb3196ea300371cc6ff0cdfb67ffa38dca570c834bd34c1d5fec`
- Final focused-test SHA-256:
  `9239e68e1351ee1d92e192bf2182717348a9697a2e422832d8df9f91860772a7`
- Host verification: ten focused tests and all 195 repository tests pass; all
  36 public manifests parse; private records mode `0600`, public manifests
  mode `0644`
- Device commands: two exact target binds plus 11 fixed `cat` reads across both
  passes; no getprop, ADB, write, reboot, MMIO, SMC, service action, payload,
  partition action or automatic retry
- Complementary decoder: commit `9fdd5d6`, tool SHA-256
  `1cf33c9292890c2479c20c8f9470c05058348046a49dc2280d061a64e224b5a7`,
  test SHA-256
  `e20cea3fc518b6ee56c4f74e4b1cfbffb72e78e782e8ce3d55680e6d24ad40e8`;
  20 focused tests pass and plan-only output reports `430/64` words with no
  remapper-window coverage

## Experiment 013 SHRM snapshot boundary/live metadata

- Experiment IDs: `013-shrm-snapshot-boundary-20260825-01`,
  `013-shrm-control-live-20260825-01`, `013-shrm-read-live-20260825-01`, and
  `013-shrm-live-result-20260825-01`
- Target model / SoC: exact bound `SM-A908N` / `SM8150`; the separate S22+
  endpoint was inventoried and received no command
- Firmware/build: exact TZ SHA-256 `a5e6c574…`; final native build
  `v2321-usb-clean-identity-rodata`, init `0.9.285`
- Boot images: V2321 `ca978551…`; fixed no-load control `d1d4956b…`; fixed
  one-load read `7ee6a41f…`; each live write had full 60,882,944-byte readback
- Snapshot target: section-16 set-0 word 207 at `0x0906566c`, sourced from
  MCCC register `0x09250118`
- Timestamp: `2026-08-25 09:24–09:33 KST`
- Preconditions: both exact TZ branches prove three enabled/TZ-owned covering
  raw rows; control/read bodies differ by exactly one instruction; exact V2321
  rollback available. Client actor/effective permission is not a precondition.
- Exact live sequence: control write/boot/op once -> V2321 rollback -> read
  write/boot/op once -> retained-log capture -> V2321 rollback
- Result: control `0xc071`; read returned no value and disconnected USB;
  retained log proves `Non Secure Watchdog Bark`,
  `TZBSP_ERR_FATAL_NON_SECURE_WDT`, bark `40.280410`, last pet `29.280131`,
  CPU alive mask `0x07`, and no `A90R` result
- Retained log: 2,097,136 bytes, SHA-256 `92af2a21…`
- Final state: V2321 full-prefix SHA-256 restored; selftest
  `pass=11 warn=1 fail=0`; battery 100%
- Repetition count: control once; read once; read automatic retries zero
- Device effects: four exact boot-only writes including two rollbacks; no
  memory/controller/XPU/SCM/EL2/EL3/protected-memory write; one fixed 32-bit
  SHRM load
- Classification: `CLASS A/B CANDIDATE — FIXED DIRECT EL1 SHRM READ BLOCKED`;
  XPU/fabric root cause `SUPPORTED`; alias/boundary bypass `REFUTED` for this
  path

## Experiment 011 exact DRAM-coordinate metadata

- Experiment ID: `011-dram-coordinate-inventory-20260825-01`
- Target model / SoC: exact retained `SM-A908N` / `SM8150`
- Firmware/build: exact Experiment 004 XBL and XBL-config partition hashes;
  selected `/6003_0200_1_dcb.bin`, DSF `0x00650000`
- Kernel build/hash: no kernel executed in this host-only phase; retained log
  input is exact Experiment 007 artifact SHA-256 `8701d073…`
- Boot image / DTB / research-kernel hash: no new boot artifact and no device
  action; V2321 remains the last health-proved runtime; live DTB remains
  `UNKNOWN`
- Timestamp: `2026-08-25 08:41 KST`
- Preconditions: all three exact inputs present and matching pinned sizes and
  SHA-256; no connected-device, SMC, or MMIO precondition
- Exact action:
  `python3 tools/sm8150_dram_coordinate_inventory.py --replace`
- Result: exact Quest reporter's rank boundary equals remapper row 7;
  rank-relative coordinate formula is complete, bijective and contains no XOR;
  section 16 supplies exact MCCC/MC/MCCC-master/DDRSS/SHRM-CSR token matches;
  hidden hardware transform was `UNKNOWN` at this phase and was later proved
  by Experiment 014; token semantics remain `UNKNOWN`
- Log reference: retained last-kmsg SHA-256 `8701d073…`; six consistent
  3072+3072 MiB topology observations
- Public manifest SHA-256:
  `93fbc8702f90980b9c85cab983a7b8e23260394a9cb4ed7881188bc0435a0c5c`
- Private derived record SHA-256:
  `90a50e319050266c3a11128f917c90cc386f0eaaacfae32d253e2ed4fe923f21`
- Tool SHA-256:
  `15b2ffb9a74e8b8821148ea3f458a305fe05b99cfe81636bf1a515f9732cc495`
- Focused-test SHA-256:
  `29d2358f8982a86437c0ca791ca5e5d57452e67385a36f148caaa0ca1daf724f`
- Host verification: seven focused tests and all 88 repository tests pass;
  every public manifest parses; three consecutive private/public generations
  are byte-identical; private mode `0600`, public mode `0644`
- Repetition count: one final analysis result, regenerated three times only for
  deterministic host verification
- Device/SMC/MMIO/controller/partition writes: none; device access: none

## Verification 001 independent claim-audit metadata

This is an audit of the evidence chain, not a forward experiment. It takes no
Experiment number because 014–016 are already allocated above.

- Verification ID: `verification-001-independent-claim-audit-20260825-01`
- Question: do the load-bearing static claims of Experiments 006–013 survive
  independent re-derivation from the raw bytes?
- Motivation: every `PROVED` statement is one agent's interpretation, and
  Experiments 008–013 consume 004/006 conclusions as pinned inputs, so an early
  misinterpretation would be inherited downstream
- Why prior signals were insufficient: unit tests prove parser determinism,
  hash pins prove input stability, and byte-identical regeneration proves tool
  reproducibility; none proves the interpretation is correct
- Controls: no module in `tools/` is imported, called, or reused; structures are
  located by name and value search and then walked, so a claim can fail even
  when the original tool reproduces byte-identically; subset AArch64 and Xtensa
  decoders were written for the audit because no disassembler was available
- Inputs: exact Experiment 004 XBL `e73a07a0…` and TrustZone `a5e6c574…`, both
  measured equal to their pins
- Timestamp: `2026-08-25 KST`
- Exact action: `python3 tools/independent_claim_audit.py --replace`
- Result: `7/7 CONFIRMED`; no substantive error; two notation issues recorded
  (helper range is end-exclusive at 125 bytes; `0x09248fff` is not a stored
  value, the raw field being end-exclusive `0x09249000`)
- New finding: region 11 and `DC_NOC_NON_BROADCAST_MPU` region 5 both carry
  write access word `0x00000000`, denying write to every client class rather
  than only to ordinary HLOS
- Not audited: QHEE `hyp_assign` stage-2/SMMU path, TZ dynamic `BIMC_MPU0..3`
  initializer, Experiment 011 Quest coordinate formula, section-16 callsites and
  their 430/64 counts, permission-conversion routine
- Public manifest SHA-256:
  `a722f0f66367de300b9a4402002e510a0d457c0250ca1b09f44e964f4914f2e5`
- Tool SHA-256:
  `b6617c19b9fc12d4d5c6dd83badc15da0a0e4df854ee8dc788b417ea3b0431fc`
- Focused-test SHA-256:
  `2c42b6bd7f513c055177c2754666cc902a338117cd7ea053bd602e0a2e62547b`
- Host verification: 34 focused tests and all 125 repository tests pass; all 33
  public manifests parse; three consecutive manifest generations are
  byte-identical; public mode `0644`
- Private record: none; the audit emits no firmware bytes
- Device/SMC/MMIO/controller/partition writes: none; device access: none

## Verification 002 SHRM dump-export metadata

This is a forward static discriminator but takes a Verification number to
preserve the already allocated Experiment 014–016 sequence.

- Verification ID: `verification-002-shrm-dump-export-20260825-01`
- Question: does exact firmware have a downstream consumer/export covering the
  two protected SHRM snapshot buffers after direct EL1 access was blocked?
- Input: exact Experiment-004 XBL, 4,194,304 bytes, SHA-256
  `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`
- Timestamp: `2026-08-25 KST`
- Exact action:
  `python3 tools/sm8150_shrm_dump_export_inventory.py --replace`
- Result: exact XBL consumes a 26-record crash/download raw-dump table whose
  index 19 maps `0x09060000..0x0906ffff` to `SHRM_MEM.BIN`, covering the full
  section-16 workspace and both snapshot destinations
- Consumer proof: loop `0x14917ca8..0x14917cf4`, record stride `0x20`, count
  `0x1a`, registrar `0x14917670`; pinned call chain
  `0x14902cc4 -> 0x14917740 -> 0x14917c60`
- Bounded SHRM negative: one direct `0x25100` literal feeds both direction-zero
  producers; no direct u32 literal for either derived destination or physical
  address; dynamically derived consumers remain possible
- Mounted-SD result: exact filenames `SHRM_MEM.BIN`, `rawdump.bin` and the
  Experiment-004 A90 partition dumps were absent; the only A908 item was the
  Samsung open-source kernel archive/directory
- Classification:
  `BOOTLOADER_RAWDUMP_EXPORT_PRESENT_HLOS_RUNTIME_EXPORT_UNPROVED`
- Public manifest SHA-256:
  `7f35e4e6dd3ede0c1bc2f398d3148656ac95b948a257ad19e8ab6d030c20e635`
- Private derived record SHA-256:
  `205960e837a0a2d58dd416ee4bf89e6f4e182a5dcfcbd358f2722dbbf78d739a`
- Tool SHA-256:
  `a9e0b9e27cb12c8ec3e12d2324b7c32d7eabb7450741767528d54a18a65565ed`
- Focused-test SHA-256:
  `cb7c947520a7aa3a6ea6a400c68f08db050a1c586ab12e58bfd30d581ba9e97d`
- Host verification: ten focused tests and all 135 repository tests pass; all
  34 public manifests parse; consecutive private/public generations are
  byte-identical; private mode `0600`, public mode `0644`
- Device/SMC/MMIO/controller/partition writes: none; device access: none

## Verification 005 exact XBL rawdump-gate metadata

- Verification ID:
  `verification-005-xbl-rawdump-gate-static-20260825-01`
- Target model / SoC / build: retained exact `SM-A908N` / `SM8150` /
  `A908NKSU5EWA3`
- Exact input: XBL 4,194,304 bytes, SHA-256 `e73a07a0…`; exact Samsung
  `sec_param`, panic-handler, SysRq, and `msm-poweroff` sources
- Exact action: host-only ELF/code/data reconstruction and exhaustive boolean
  truth-table evaluation
- Result: main-XBL outer trigger is saved-cookie bits 4/5 or restart reason
  `0x776655ee`; XBLRamDump inner gate admits MID alone when FMM is unlocked;
  force-upload enable is exact integer 5 and is not jointly required
- Classification: `DEBUG_ONLY_SUFFICIENT_WHEN_OUTER_DUMP_TRIGGER_PRESENT`
- Public manifest SHA-256: `5024b24e…`
- Tool SHA-256: `75581e19…`
- Device/reboot/partition/MMIO/SMC access: none

## Verifications 006–014 bounded live-gate metadata

- Target model / SoC / build: exact live `SM-A908N` / `SM8150` /
  `A908NKSU5EWA3`; native `v2321-usb-clean-identity-rodata`
- Timestamp: `2026-08-25 12:14–12:41 KST`
- Initial `param`: live `sda10`, 10 MiB; device-before/host/device-after
  SHA-256 all `1faafee9…`; DLOW, force-upload 0, FMM 0, dump-sink 0
- Exact effects: four-byte LOW→MID; one normal reboot; one SysRq `c`; one
  four-byte MID→LOW restoration; one final normal reboot. Two intermediate
  apply/restore qualification transitions were separately hash-verified.
- Exact MID full-image SHA-256: `50e5c715…`; exact LOW full-image SHA-256:
  `1faafee9…`
- Trigger preconditions: MID, force-upload 0, FMM 0, dump-sink 0, dload master
  1, SysRq enabled; one dispatch and no replay
- Transport result: Qualcomm 05c6 Sahara/qdl captured no file; host journal
  proved Samsung `04e8:685d / MSM_UPLOAD`
- Final result: original full `param` hash restored; new boot reports LOW,
  force-upload 0, dump-sink 0, dload master 1; selftest `fail=0`
- Public manifest SHA-256 sequence: capture `c9bc1838…`, first apply
  `7bf70d53…`, first restore `f10a6888…`, reapply `705fac7c…`, MID reboot
  `d466bf94…`, trigger `aa3ef26b…`, qdl result `bed07a93…`, final restore
  `81b734c2…`, health `c27f307b…`, LOW reboot `c3d7983e…`
- Raw rollback image and journals: mode `0600`, Git-ignored
- Forbidden-target result: no controller, XPU, SMMU, SCM, EL2, EL3, firmware,
  bootloader, GPT, RPMB, QFPROM, or protected-memory write
- Repetition count: one panic only; no trigger replay

## Verification 012 Samsung Upload SHRM metadata

- Verification ID:
  `verification-012-a90-samsung-upload-shrm-20260825-01`
- Exact collection: Samsung Upload client commit `8c9f6eb7…`, source SHA-256
  `7580a6c1…`; selected only exact static catalog record 19
- Raw result: `SHRM_MEM.BIN`, 65,536 bytes, SHA-256 `409550ad…`, mode `0600`,
  Git-ignored
- Structural result: exact section-16 header at file offset `0x5100`; 430 + 64
  staged entries cover 470 distinct source-register addresses
- Set 0: 430 words, 220 zero, 71 distinct; 17/18 four-instance MC groups
  identical and one two-value pair split; `SUPPORTED_POPULATED_COHERENT_SNAPSHOT`
- Set 1: 64/64 distinct nonzero values; four different MC `+0x80` values;
  0/24 overlaps agree with set 0; `REFUTED_AS_COHERENT_CURRENT_SNAPSHOT`
- Remapper coverage: `REFUTED`; all four `qhs_llcc +0x8080` controls remain
  outside the staged list
- Public manifest SHA-256: `ab1ce816…`
- Private analysis SHA-256: `ed5c39e9…`, 168,042 bytes, mode `0600`
- Analysis tool/test SHA-256: `a93e1478…` / `138c504b…`
- Security result: `NO_ALIAS_OR_BOUNDARY_BYPASS_OBSERVED`
- Repetition count: one exact file acquisition; one host decode/qualification

## Experiment 014 live DRAM-timing metadata

- Target model/SoC: `SM-A908N` / `SM8150`
- Firmware/kernel/runtime: `A908NKSU5EWA3` / Linux `4.14.190-25818860` /
  V2321 `0.9.285` build `v2321-usb-clean-identity-rodata`
- Boot state: LOW, force-upload 0, dump-sink 0
- Probe source SHA-256: `f5788486…`
- Probe binary SHA-256: `552432c1…`
- Backing: non-secure ION `user_contig`, flags 0, one SG entry,
  write-combine mapping
- Physical interval: rank-0 PA `0xf0400000..0xf13fffff`, 4096 pages; unique
  `/proc/kpageflags` transition window and zero changed/lost pages while pinned
- Timing controls: CPU7 at 2,841,600 kHz; DDR BW governor `performance` at
  reported `7980`; CNTFRQ 19.2 MHz; 64 PA pairs; normally 1001 repetitions per
  pair; symmetric reopen and same-address baselines
- Recovered bank row basis: `0x9d2000`, `0xa74000`, `0x4e8000` over observed
  rank-relative bits `0..23`; basis order is arbitrary
- Holdout: four unfit kernel vectors have minimum p10 536 milli-ticks; four
  one-bank-bit negatives have maximum p90 222; non-overlap gap 314
  milli-ticks
- Same-row control: ten `D=0x800` median deltas remain within +/-6
  milli-ticks
- Static attribution: zero aligned u32 mask hits in nine exact firmware images;
  all four raw TZ matches are misaligned monotonic u64 address-table bytes
- Timing manifest SHA-256: `7dc5050c…`
- Literal-audit manifest SHA-256: `50cdec42…`
- Final-health manifest SHA-256: `e8219a53…`; selftest `fail=0`, battery 100%
- Device mutation: temporary `/tmp/a90-native` probe and ION node only; both
  removed. No MMIO/SMC/partition/firmware/protected-memory write.
- Security result:
  `NORMAL_RAM_HIDDEN_BANK_HASH_PROVED_NO_ALIAS_OR_BYPASS`

## Experiment 017 XBL MC table/read-copy metadata

- Experiment ID: `017-xbl-mc-snapshot-xref-20260825-01`
- Date: `2026-08-25 KST`
- Target/input: exact retained `SM-A908N` / `SM8150` XBL
  `xbl--sdb1.bin`, 4,194,304 bytes, SHA-256
  `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`
- Exact action:
  `python3 tools/sm8150_xbl_mc_snapshot_xref.py --output evidence/manifests/017-xbl-mc-snapshot-xref-20260825-01.manifest.json`
- Device/SMC/MMIO access: none; mode `HOST_ONLY_READ_ONLY`; public mode `0644`.
- Table: VA `0x146b1218`, file `0x630b8`, 122 nonzero u64 entries plus a
  u64 zero terminator at index 122; inclusive SHA-256
  `d5042980f035d3d52974536115074940b4b1858cb30a47699e7553f1b200da07`;
  structural shape 30 four-instance MC groups plus two globals.
- Candidate coverage: all 12 qhs_mc `+0x400/+0x404/+0x4d0` addresses are in
  the table; qhs_mccc `+0x118` and qhs_mccc_master `+0x294` are excluded from
  this table only. Existing Top-5 order is unchanged; coverage raises
  observation confidence, not semantic likelihood.
- SHRM plan convergence: set0 `100/430`, set1 `4/64`, union intersection
  `100`, table-only `22`, SHRM-only `370`; address-list convergence only, with
  no semantic identity or writer attribution.
- Helper: exact range `0x146ae138..0x146ae18c` end-exclusive, file `0x62318`,
  length `0x54`, SHA-256
  `f325a8bf4c8e9ff7c21a0d20752e742cd8e047422e9eff5c301bf3042a95e138`.
  Static sentinel prefill and conditional table-derived 32-bit read/copy to
  distinct VA `0x146bf300`; only X12/X8 are identified store bases. Traversal
  is zero-sentinel-only with no hard 122-entry cap; successful execution,
  partial output, coherence/currentness, MMIO side effects/faults, mutable
  table state, lock/writability and indirect reachability remain `UNKNOWN`.
- Direct reachability: exactly two direct BL callsites in file-backed executable
  PT_LOADs, at VA/file `0x146ae26c/0x6244c` and
  `0x14839f44/0x20f44`; no current-boot execution claim.
- Classification: `TABLE_DRIVEN_REGISTER_READ_COPY_PATH_WRITER_AND_TRANSFORM_RELATION_UNKNOWN`;
  current overall status remains Class C transform observation only. Experiments
  015 (normal-RAM alias) and 016 (protected-boundary reach) remain reserved and
  `NOT ELIGIBLE`; 017 satisfies neither gate.
- Tool SHA-256:
  `2baa9e3def46bb1c22bfd23c3dc7c4b800cf3fbc16ada1254e73023842633d99`.
- Focused-test SHA-256:
  `5b0f6f3e4d0b9a4a0e80f17555f4c8e12baf1f8d83f5bc6ee1fb97252d21f392`.
- Public manifest SHA-256:
  `b1db21235374c64de797c1a123c64ddb23c43fca9100bbd51cf7b4897ea5c61b`.
- Host verification: 20 focused tests and all 279 repository unittest-discovery
  tests pass. Independent raw-byte review
  accepted the result as a read-only re-derivation and emitted no artifact or
  artifact hash.
- Next discriminator: host-only symbolic AArch64 store xref/backward slice for
  the 12 exact qhs_mc targets, resolving MOVZ/MOVK, ADRP+ADD, literal/table
  loads, arithmetic and argument provenance; unresolved dynamic bases remain
  `UNKNOWN`; no broad MMIO scan/device action.

## Experiment 018 XBL MC writer Stage 1A metadata

- Experiment ID: `018-xbl-mc-writer-xref-stage1a-20260825-01`
- Date: `2026-08-25 KST`
- Target/input: exact retained `SM-A908N` / `SM8150` XBL
  `xbl--sdb1.bin`, 4,194,304 bytes, SHA-256
  `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`
- Exact action:
  `python3 tools/sm8150_xbl_mc_writer_xref.py --output evidence/manifests/018-xbl-mc-writer-xref-stage1a-20260825-01.manifest.json`
- Device/SMC/MMIO access: none; mode `HOST_ONLY_READ_ONLY`; public mode `0644`.
- Literal inventory: each target's single 8-byte table encoding yields both the
  one aligned u64 match and overlapping one aligned u32 match at the same file
  offset; these are two views of one table entry, not independent literals,
  with no separate target literal elsewhere. Only base `0x09260000` has an
  aligned outside-table u32, file `0x80154`, VA
  `0x148bc254`, segment class RWE; other bases have zero aligned u32 and all
  bases have zero aligned u64.
- PT_LOAD/store census: RX4/RWE2/RW3/OTHER0; recognized STR W/X counts
  RX6945/RWE5169; matching offsets RX `{0x400:7,0x404:2,0x4d0:2}` and RWE
  `{0x400:1,0x404:1,0x4d0:1}` for 14 total, with seven RX SP candidates.
- Resolution/classification: no base/effective-address resolution; public
  resolved hit count is JSON `null`, not zero. Classification is
  `STAGE1A_LITERAL_AND_STORE_OFFSET_CENSUS_WRITER_UNKNOWN`; no writer claim.
  Class C remains unchanged and 015/016 are reserved `NOT ELIGIBLE`.
- Tool SHA-256:
  `9806b64c01f9965161966c88bbf5b943d953e790664c3136b2a116da63f8dc57`.
- Focused-test SHA-256:
  `b5fbf50e545b9df86d45ac012106d8905af231d9e94b0b2dd1927ec365da13d8`.
- Public manifest SHA-256:
  `8861a5626576fac32a83c295c34be63f91fd5e3f4b434490d567fb2984bb192d`.
- Host verification: 8 focused tests and all 287 repository unittest-discovery
  tests pass; all 54 public manifests parse as JSON; regeneration is
  byte-identical. Independent Luna raw-byte feasibility review agreed on the
  14 candidates and no resolved target in its broader model but emitted no
  artifact; no review-artifact hash exists.
- Next discriminator: Stage 2A same-block direct-definition slice of only the
  four non-SP RX candidates is complete; see the Stage 2A metadata below.

## Experiment 018 XBL MC writer Stage 2A metadata

- Experiment ID: `018-xbl-mc-writer-xref-stage2a-20260825-01`
- Date: `2026-08-25 KST`
- Target/input: exact retained `SM-A908N` / `SM8150` XBL
  `xbl--sdb1.bin`, 4,194,304 bytes, SHA-256
  `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`
- Exact action:
  `python3 tools/sm8150_xbl_mc_writer_stage2a.py --output evidence/manifests/018-xbl-mc-writer-xref-stage2a-20260825-01.manifest.json`
- Device/SMC/MMIO access: none; mode `HOST_ONLY_READ_ONLY`; public mode `0644`.
- Scope: exactly four non-SP RX candidates:
  `0x14844b20/0x2bb20/X8/+0x400`,
  `0x14844c78/0x2bc78/X8/+0x4d0`,
  `0x146a70c0/0x2d6090/X8/+0x400`, and
  `0x14935bf4/0x312bc4/X19/+0x400`. Seven SP candidates remain runtime-
  derived and three RWE candidates remain ambiguous.
- Model: maximum 128 aligned instructions; only 64-bit MOVZ/MOVK or same-
  register `ADRP Xn; ADD Xn,Xn,#imm`; branches, calls, returns, inbound
  direct-branch entries, boundaries and unsupported definitions fail closed.
- Exact outcome: `resolved_base_count=0`,
  `resolved_target_hit_count=0`; reason counts are three
  `NO_DIRECT_CONSTANT_DEFINITION` (two `WINDOW_LIMIT`, one BL
  `CONTROL_TRANSFER`) and one `UNSUPPORTED_REGISTER_DEFINITION` (LDR at
  `0x146a70b4`). Classification is
  `NO_RESOLVED_TARGET_STORE_WITHIN_STAGE2A_DIRECT_DEFINITION_RX_MODEL`.
  This refutes only the supported direct-definition path, not writer absence.
- Tool SHA-256:
  `eb0a8ce21154d97d052de9f7e4e0de40f85087a8cb517179f7c44332e9d85eb0`.
- Focused-test SHA-256:
  `1272fadb0bcc6b883f74577284312ee34678975fa7ba60377d05d86927960b3b`.
- Public manifest SHA-256:
  `eeed732e4a6cecd60453e9088d8c3d4c7ed207a1e7c723bae91e27033d134a4b`.
- Host verification: 14 focused tests and 301 full repository unittest-
  discovery tests pass; all 55 public manifests parse as JSON; regeneration is
  byte-identical. No runtime execution, writer identity, semantics,
  mutability/lock, GF(2), alias, bypass or other-firmware claim is made.

## Experiment 018 XBL MC writer Stage 2B metadata

- Experiment ID: `018-xbl-mc-writer-xref-stage2b-20260825-01`
- Date: `2026-08-25 KST`
- Target/input: exact retained `SM-A908N` / `SM8150` XBL
  `xbl--sdb1.bin`, 4,194,304 bytes, SHA-256
  `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`
- Exact action:
  `python3 tools/sm8150_xbl_mc_writer_stage2b.py --output evidence/manifests/018-xbl-mc-writer-xref-stage2b-20260825-01.manifest.json`
- Device/SMC/MMIO access: none; mode `HOST_ONLY_READ_ONLY`; public mode `0644`.
- Scope: only `0x14844b20/0x2bb20/X8/+0x400` and
  `0x14844c78/0x2bc78/X8/+0x4d0`, with a maximum 512 aligned predecessors.
  Same-register `MOVZ W8,#0xf000` plus `MOVK W8,#0x1489,LSL#16` zero-extends
  to X8 value `0x1489f000`; computed values are `0x1489f400` and
  `0x1489f4d0`, both outside file-backed PT_LOADs.
- Exact outcome: `resolved_base_count=2`,
  `resolved_numeric_target_hit_count=0`, and remaining Stage 2A unresolved
  count 2. Classification:
  `NO_NUMERIC_TARGET_ADDRESS_MATCH_WITHIN_STAGE2B_W_WIDE_MOVE_RX_MODEL`.
  This refutes only numeric equality under this model; physical destination,
  VA-to-PA translation, writer identity and unsupported/dynamic paths remain
  `UNKNOWN`.
- Tool SHA-256:
  `aa35d8b303a7ea32a086d601b1f08390b1cad0932f105209ac337f394813dbcb`.
- Focused-test SHA-256:
  `af7ca7b46550dda13e85e517c0c1c1df19b6414549d06415316b6d428e020fc9`.
- Public manifest SHA-256:
  `a4715112e27c74e5548ecb49f09106c236146c8a0216c87446ddbd3c355ccca6`.
- Host verification: 10 focused tests and 311 full repository unittest-
  discovery tests pass; all 56 public manifests parse as JSON; regeneration is
  byte-identical. Stage 1A/Stage 2A artifacts remain hash-pinned and unchanged.

## Experiment 018 XBL MC writer Stage 2C metadata

- Experiment ID: `018-xbl-mc-writer-xref-stage2c-20260825-01`
- Date: `2026-08-25 KST`
- Target/input: exact retained `SM-A908N` / `SM8150` XBL
  `xbl--sdb1.bin`, 4,194,304 bytes, SHA-256
  `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`
- Exact action:
  `python3 tools/sm8150_xbl_mc_writer_stage2c.py --output evidence/manifests/018-xbl-mc-writer-xref-stage2c-20260825-01.manifest.json`
- Device/SMC/MMIO access: none; mode `HOST_ONLY_READ_ONLY`; public mode `0644`.
- Scope/pins: writer `[0x146a70a4,0x146a70dc)` / file `0x2d6074`, 56
  bytes, SHA-256 `a50aaeb45c498a63e91704fc0ec4550b120ca0c1b691c238736b0532136dad6c`;
  wrapper 108-byte SHA-256
  `24008bb23f54ed515774f020ac62cb3973b74dc57a41acd2bd358567863ad436`;
  lookup 272-byte SHA-256
  `9e54cfe4e5e2fad580b92c0853513f1be25046abeb00ff76db83d87ad3036046`;
  retained table 48×16 bytes at `0x146aa4d0` / `0x2d94a0`, SHA-256
  `47a7f6195703f2f4d27cbe1e8bd0cc976600453a3ba4aebba98736ef8e03906e`.
- Exact outcome: one direct BL caller at `0x146a67a4` / `0x2d5774`; count
  u32 48; 48 unique IDs and nonzero pointers; reserved +4 zeros 48; zero
  target-base pointer matches and zero possible `base+0x400` target matches.
  The 48 rows are descriptor-eligibility-dependent possible values, not proof
  of per-entry execution. One non-SP RX static candidate remains (`X19`).
  Classification:
  `NO_NUMERIC_TARGET_ADDRESS_MATCH_WITHIN_STAGE2C_UNIQUE_DIRECT_CALLER_TABLE_MODEL`.
- Tool SHA-256:
  `d53d820eb8d10e8417247fabbc0e3196f73c73584a6b7d79d583a96834c34d53`.
- Focused-test SHA-256:
  `92c95472940937a7001fe48dd055b4c598fd290c28a1e15757d1c297ebf5f526`.
- Public manifest SHA-256:
  `e096562a35da93a1dac10a1651fc7eff08eecf05dafca4a789bae2fd50540c01`.
- Host verification: 9 focused tests and 320 full unittest-discovery tests pass;
  all 57 public manifests parse as JSON; regeneration is byte-identical and
  mode is `0644`.

## Experiment 018 XBL MC writer Stage 2D metadata

- Experiment ID: `018-xbl-mc-writer-xref-stage2d-20260826-01`
- Date: `2026-08-26 KST`
- Target/input: exact retained `SM-A908N` / `SM8150` XBL
  `xbl--sdb1.bin`, 4,194,304 bytes, SHA-256
  `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`
- Exact action:
  `python3 tools/sm8150_xbl_mc_writer_stage2d.py --output evidence/manifests/018-xbl-mc-writer-xref-stage2d-20260826-01.manifest.json`
- Device/SMC/MMIO access: none; mode `HOST_ONLY_READ_ONLY`; public mode `0644`.
- Scope/pins: candidate `0x14935bf4/0x312bc4`, function 1,404-byte SHA-256
  `68739df6f843f790376eb0af47da22f0af5ebeb2421f05d29c3b5a8673983fd9`;
  initializer 2,092-byte SHA-256
  `65e117b99fd109cbb01531bd70fc2befe70c0b672a01afe6dd523bbebf1486cb`;
  target 228-byte SHA-256
  `5c979955c6d1cdfd541766ca3ea6964460803d61aa3d07bed0c74f60d3eec34e`.
- Exact outcome: one direct BL caller and zero direct B callers; W0=0 at the
  scoped call; intrinsic effective values `0x85e9e970`/`0x85e9ef70`; direct
  caller conditional value `0x85e9e970`; zero numeric target matches. The
  initializer-derived import slot and target range remain runtime-conditional.
  Classification:
  `NO_NUMERIC_TARGET_ADDRESS_MATCH_WITHIN_STAGE2D_UNIQUE_DIRECT_CALLER_CONDITIONAL_CALLEE_SAVED_PRESERVATION_MODEL`.
- Tool SHA-256:
  `95e53e25f288ba1ef09996ff73919c2ad1dd4186c4fec41dc84216d715ee8b26`.
- Focused-test SHA-256:
  `23c91a14c16706b920b4c3556e85844543dc99545a2b7b6d864a8c09d35f6136`.
- Public manifest SHA-256:
  `48c7aa83d30844f1d42094fcb0f8d7dd13cf44265f9961167912792d014661c4`.
- Host verification: 14 focused tests and 334 full unittest-discovery tests
  pass; all 58 public manifests parse as JSON; regeneration is byte-identical
  and mode is `0644`.

## Experiment 018 XBL MC writer Stage 2E metadata

- Experiment ID: `018-xbl-mc-writer-xref-stage2e-20260826-01`
- Date: `2026-08-26 KST`
- Target/input: exact retained `SM-A908N` / `SM8150` XBL
  `xbl--sdb1.bin`, 4,194,304 bytes, SHA-256
  `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`
- Exact action:
  `python3 tools/sm8150_xbl_mc_writer_stage2e.py --output evidence/manifests/018-xbl-mc-writer-xref-stage2e-20260826-01.manifest.json`
- Device/SMC/MMIO access: none; mode `HOST_ONLY_READ_ONLY`; public mode `0644`.
- Exact outcome: seven RX SP-base STR W/X candidates, F1/F2 hashes and unique
  direct-BL callers, local allocations `0x5a0`/`0x490`, four recognized explicit
  writeback sites per function (two SP frame updates and two non-SP writebacks),
  zero recognized BR/BLR transfers, one external direct BL to each function
  start with zero external entries to interiors. An independent GNU objdump
  2.46 disassembly census, pinned by each exact range hash and not recomputed by
  this tool, reports F1 as 492 instructions/134 writeback-free SP-base accesses
  and F2 as 1,102/168. The same-function immediate-control CFG (BL modeled as
  fallthrough) has no recognized SP-write-class instruction after allocation on
  a path to each candidate; unsupported instruction effects remain `UNKNOWN`.
  All seven accesses
  lie within their local allocations. Three RWE candidates remain outside this
  stage. Classification:
  `SEVEN_RX_SP_CANDIDATES_ARE_PINNED_STACK_FRAME_STORES_RUNTIME_STACK_ADDRESS_UNKNOWN`.
- Tool SHA-256:
  `16519db59009efc1d55bee8ef37046679261ba486703dcffd371bb639331cc74`.
- Focused-test SHA-256:
  `174af64d6f536f2b44a8fe3301e53ea9d4ea5acfb50323fe783a2db714764563`.
- Public manifest SHA-256:
  `c52babccfcfe825df7477dffc9533754fe1afd656d3afd839a398b078477ee36`.
- Host verification: 13 focused tests and 347 full unittest-discovery tests
  pass; all 59 public JSON files parse as JSON; regeneration is byte-identical
  and mode is `0644`.

## Experiment 019 DCB candidate pair-array metadata

- Experiment ID: `019-dcb-register-programming-20260826-01`
- Scope: host-only, read-only static analysis of the exact bounded DCB inputs;
  no device, SMC or MMIO access.
- `PROVED`: strict acceptance finds 28 syntactic candidate pair arrays across
  four DCB blocks, in absolute and base-relative key domains. This does not
  prove register-table meaning or a consumer. Absolute keys do not hit ranked
  MC bases; section/base semantics and writer identity remain `UNKNOWN`.
- Bounded materialisation: `0x00003333` and `0x00300014` are absent from the
  explicitly modelled stored-word, exact-wide-move and ORR-immediate paths;
  `0x00300033` has two adjacent sequences. This is not writer absence.
- Public manifest: `evidence/manifests/019-dcb-register-programming-20260826-01.manifest.json`
  (SHA-256 `232eb037fadf96db1fd303d83d707cf47cb668a24129d7e4791b193fb3fc70c`).
- Tool/focused-test SHA-256:
  `d7a81362548f639bdf7e468dbe24e551a8d280998e1d230e8cd6e7b4e7d7ac2f` /
  `70204b5ae5225f254e0b90e81beaad022584d8b334d129cfa8581548e6a9544a`.

## Experiment 020 XBL DCB consumer/candidate-segment metadata

- Experiment ID: `020-xbl-dcb-consumer-xref-20260826-01`
- Scope: host-only, read-only static analysis; no device, SMC or MMIO access.
- `PROVED`: 719 register-offset stores (488 unscaled; 67 loop-shaped) are in
  executable segments. The narrow classifier has a pinned false negative at
  `0x14868a50`; general walker/consumer/writer conclusions remain `UNKNOWN`.
- `SUPPORTED`: the largest RWE segment is a candidate segment only; no identity
  or writer claim follows from its size/content selection.
- Public manifest: `evidence/manifests/020-xbl-dcb-consumer-xref-20260826-01.manifest.json`
  (SHA-256 `31e8dd6791f07d007447600969326a86466f20a0cb263a58885c1489bd284c9a`).
- Tool/focused-test SHA-256:
  `49fa50dd45d768b01b865ad4dcd1dcc97132ac2e6245eb951b1950e5d9788df3` /
  `5fe1c94ae7009d4965a1f96989b68970cdaa79c590b5d8d4f98b6b44b3725d94`.

## Experiment 021 bounded-copy delivery metadata

- Experiment ID: `021-dcb-delivery-paths-20260826-01`
- Scope: host-only, read-only static analysis of the pinned bounded-copy target;
  no device, SMC or MMIO access.
- `PROVED`: direct census is 7 `BL`, 0 `B`; five sites are locally labelled
  sections `{0,1,2,15,16}` and two are unlabelled. Other-section/global
  delivery is `UNKNOWN`, not refuted; only local label completeness is
  `REFUTED`.
- Public manifest: `evidence/manifests/021-dcb-delivery-paths-20260826-01.manifest.json`
  (SHA-256 `d85999e644bae1f5bafe683b44b253450d04d1b666c73659d9284c010d32b44a`).
- Tool/focused-test SHA-256:
  `180fd7b3eb6f281fa612a31b126dbf474bf99fd775cf6b77ff1d6535d23f133b` /
  `bd7b07fd1be4c60a74080191a090b3d8fbc0649508bb8ab2767bd36ccbbb526e`.

## Experiment 022 observation-coverage metadata

- Experiment ID: `022-observation-coverage-20260826-01`
- Scope: host-only, read-only static analysis of the two enumerated retained
  evidence channels; no device, SMC or MMIO access.
- `PROVED`: channel counts are set-0 `430`, SHRM union `470`, XBL MC table
  `122`, and their union `492`; density is sparse. Completeness is `REFUTED`
  by known `0x09248080`, while implemented-register coverage is `UNKNOWN`.
- Public manifest: `evidence/manifests/022-observation-coverage-20260826-01.manifest.json`
  (SHA-256 `c3b783ba8009f2ec9d64f314166b52892003d621dcd1198f393d8681c701be2f`).
- Tool/focused-test SHA-256:
  `4e44f2a1801f85d20bce762b4278e394f7bfc958f6eb13a30afc564773580feb` /
  `8218b3084a89c39d2b64841f72e425a51bfdf951be346c149f2be63ab9a50390`.

## Experiment 024 exact XBL six-byte walker metadata

- Experiment ID: `024-xbl-six-byte-walker-20260826-01`; commit: `c62c33e`.
- Scope: host-only, read-only static analysis of exact XBL and two pinned design
  sources; no device, SMC, MMIO, protected-memory, normal-RAM, or activation
  action.
- `PROVED`: walker range `[0x148689a0,0x14868a64)` is 196 bytes with SHA-256
  `08265307d79c5f82b85266613f241ae160151dcfe51b19da108f9ad6c4e15021`; it
  uses six-byte records, exact `0x8000` terminator and `B.EQ` return-before-
  store, and conditionally writes the zero-extended byte as a 32-bit word.
- `PROVED`: direct callers are exactly `0x14868640`, `0x1486867c`, and
  `0x14868698`; five nonzero provider alternatives select XBL-resident tables,
  while provider3 on selector `== 0xf` returns count zero without a pointer.
  The alternatives contain 221 nonterminator records and 170 unique aligned
  offsets in the cross-alternative syntactic superset (selector unions 53 and
  127). The five table starts/counts/hashes are:
  `0x14880bee/43/f7b7ca7dae26320d69c87c9b4c59472eb0933aa7216936ed7564f78b770f643c`,
  `0x14880e70/90/8c26948bb9e7e24ae9c2d950412e851dd1e60e412aa4f82d7936c247103ac240`,
  `0x14880ba0/13/eac051599765de4842c6ecf7a6076813eac93a07cd052d829787b1095fa353b1`,
  `0x14880cf0/64/7c0fb81701455fb380cf4a2d1af4120a444a6be66235c2a87dad5ca2c932711f`,
  `0x14880b40/16/1c596a44cbec1cdbcc5b23e81eccde1c20556b17ab3c434ef393c29ab63aa015`.
- `PROVED`: under initialized-base retention, the two pinned design-source UFS
  blocks are byte-identical (4,464 bytes, SHA-256
  `cea31db3785be5916a1ff08d1c99b92155a7914b07d09ecb6c3638d8c16ff10a`).
  Under initialized-base retention, all 170 symbolic destinations are within
  `ufshc` `ufs_phy` `[0x01d87000,0x01d87e00)`; 167 are within standalone
  `ufsphy_mem` `[0x01d87000,0x01d87da8)`, with `0x7dc4`, `0x7dd8`, and `0x7de0`
  beyond that narrower resource. The Experiment 019 dependency pins the
  separate 8-byte representation; semantic DCB identity is `UNKNOWN`.
- `SUPPORTED`: the table-driven positive control is conditional on initialized
  base retention and flag-gated store reach. `UNKNOWN`: current base,
  selector/runtime execution, reached-store subset, flag semantics, live-DTB
  equality, DCB semantic alias/global consumer/writer, DDR/MC relation, GF(2),
  aliases, bypass, and actual current destinations. Class C remains unchanged;
  Experiments 015/016 remain `NOT ELIGIBLE`.
- Tool/test/manifest SHA-256:
  `f0ccb5648b2cce4ab2b835e23c4658c976df9779b0ae6273767b59cc7b6a58bf` /
  `97c58a22c5c3e7e6cd5b7bc4f8d181c74050b2b530afac03eba3fbb946577f6d` /
  `f9ac896d396650075ca9e66d8d805a2deaf40b0207e819cd94f8d638c8121b01`.
- Public manifest: `evidence/manifests/024-xbl-six-byte-walker-20260826-01.manifest.json`
  (30,400 bytes, mode `0644`).
- Host verification: 30 focused and 534 full unittest-discovery tests pass;
  all 64 public JSON manifests parse, regeneration is byte-identical, and two
  independent reviews pass as recorded in
  [EXP024_INTEGRATION_REVIEW_2026-08-26.md](EXP024_INTEGRATION_REVIEW_2026-08-26.md).

## Experiment 025 exact XBL platform-query binding metadata

- Experiment ID: `025-xbl-platform-query-binding`; commit: `d743150` (parent
  `a68d2f1`).
- Scope: host-only, read-only static analysis of exact XBL; no device, SMC,
  MMIO, protected-memory, normal-RAM, or activation action.
- Exact input: `xbl--sdb1.bin`, size 4,194,304, SHA-256
  `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.
- `PROVED`: helper `[0x1486abec,0x1486acac)` and caller `0x1486847c` pass
  `X0=SP+0x10`, not main `X19`; slot `0x14890590` has exact load/address/
  reload xrefs; semantic `MOVZ/MOVK` pins ID `0x02000139`.
- `PROVED`: seed `X0=0x14875668`, outer record `X1=0x14875590` count five,
  descriptor `0x14824ab8`, factory `0x1484a880`, object candidate
  `0x1488f418`, inline vtable `0x14824ad0 + 0x48`, and callback `0x1484a9d4`
  form the intended static chain.
- `PROVED`: bounded callback `a9d4->a730->a824->aa30->a854` has output write
  `0x1484a9f4` to helper `SP+0xc`; recognized nested BSS writes are only
  `0x1488f3f9`, `0x14890ba0`, and `0x14890b90`; one decoded MMIO read is
  `0x01fc8004` and recognized MMIO writes count is zero.
- `SUPPORTED`: conditional intended binding can populate the slot and the
  recognized callback flow does not write caller context `+8`. `UNKNOWN`:
  runtime registration/order, slot/object identity, actual `BLR X9` target,
  alternate BSS mutation/global aliases/unsupported writes, complete
  arbitrary-write absence, full `0x01d80000` base currentness, and live
  mapping/authority. The all-executable census is conservative recognized
  coverage only. Class C remains unchanged; 015/016 remain `NOT ELIGIBLE`.
- Tool/test/README/manifest SHA-256:
  `16e9584a3043d76670c66b6a517e56c87267645506c1f76a040737d731b168b9` /
  `219227a927acb8a98d8e7294150c154b916795e709ab02bb076b946d8d7bb687` /
  `eb97735c91b79fb13f8feb40e9b98ffd7f2aa71a9dcc2fbe479fcdcf2e4014a3` /
  `d3c405d7c8d23dc1cd65b1c578b4b4ce931d9bdfeb303c892e9c0c145c4c81cc`.
- Public manifest: `evidence/manifests/025-xbl-platform-query-binding-20260826-01.manifest.json`
  (28,132 bytes, mode `0644`).
- Host verification: 22 focused and 556 full unittest-discovery tests pass;
  Python byte-compilation passes, all 65 public JSON manifests parse,
  regeneration is byte-identical, and two artifact reviews pass. The durable
  integration-doc review is `PASS` in
  [EXP025_INTEGRATION_REVIEW_2026-08-26.md](EXP025_INTEGRATION_REVIEW_2026-08-26.md).

## Experiment 026 exact XBL dispatch/order and slot-escape metadata

- Experiment ID: `026-xbl-dispatch-order-slot-escape`; commit: `0305a03`.
- Scope: host-only, read-only static analysis of exact XBL; no device, SMC,
  MMIO, protected-memory, normal-RAM, write, or activation action. Experiment
  025 is a semantically validated dependency and its ranges are excluded from
  the complementary census.
- Exact input: `xbl--sdb1.bin`, size 4,194,304, SHA-256
  `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.
  Experiment 025 dependency: size 28,132, SHA-256
  `d3c405d7c8d23dc1cd65b1c578b4b4ce931d9bdfeb303c892e9c0c145c4c81cc`.
- `PROVED`: registration helpers `[0x1482ecb4,0x1482edac)` pin a 24-byte
  node (object/ID/next at `+0x0/+0x8/+0x10`) and head `0x14890f60`; the
  initializer loop is `[0x1482edac,0x1482f0b4)`. Table header
  `[0x14875534,0x14875568)` has count 2, row start `0x14875538`, cursor
  `0x1487554c`, and derived stride `0x18`.
- `PROVED`: bootstrap caller `[0x14852ce0,0x14852d70)`, veneer
  `[0x14843d20,0x14843d50)`, alternates `[0x14828338,0x14828360)` and
  `[0x14828b44,0x14828c80)`, dispatcher `[0x14864834,0x148648c0)`, callers
  `[0x148641a4,0x1486420c)`, `[0x1486420c,0x1486424c)`,
  `[0x148642dc,0x148644cc)`, and `[0x1485a2ec,0x1485a30c)` have exact
  local/control/data edges, including dispatcher base/stride/index guard and
  symbolic pointer escape `0x146b30c0 + runtime_index*0x3f8`, modeled index
  `0..1`. `SUPPORTED`: memory-only initializer-pool shape
  `[0x146b30c0,0x146b38b0)`, two-row `0x3f8` geometry; pool contents/runtime
  values are `UNKNOWN`.
- Complementary census: 847,465 executable words scanned; 622 Experiment 025
  words excluded; 9 recognized accesses (3 writes, 6 reads) and 2 pointer
  escapes; zero recognized interval-overlap writes to slot
  `[0x14890590,0x14890598)`.
- Taxonomy: `ORDER_OPEN` and
  `PROVED_BOUNDED_NO_RECOGNIZED_SLOT_MUTATION`. Runtime execution/order, slot
  value, object identity, `BLR` target, base currentness, writer absence and
  live authority remain `UNKNOWN`; no global writer-absence claim is made.
  Class C remains `TRANSFORM ONLY`; 015/016 remain `NOT ELIGIBLE`.
- Tool/test/README/manifest SHA-256:
  `61b4f993678527b7cb1b024b0e8f5cdf4b965a9bf3aedc8a2a12214c8d26a5f8` /
  `3f8aad6ed90b8c16d4bece5dc272e402ddd4f91af35ae1a294c53beb6d5d9b41` /
  `392631c3ef6298b23ef52bdfe085d723b7bd5451dd10483e5296e4ab4c6e3d24` /
  `2139b5d230be78d822eda656f2856a229894167938227d34a614dcabf16c7885`.
- Public manifest:
  `evidence/manifests/026-xbl-dispatch-order-slot-escape-20260826-01.manifest.json`
  (64,027 bytes, mode `0644`).
- Host verification: 25 focused and 581 full unittest-discovery tests pass;
  Python byte-compilation, public JSON safety, two byte-identical fresh
  generations, and exact-XBL/final decoder hostile-review `PASS`. The durable
  integration-doc review is `PASS` in
  [EXP026_INTEGRATION_REVIEW_2026-08-26.md](EXP026_INTEGRATION_REVIEW_2026-08-26.md).

## Experiment 020E static-slot census metadata

Verification 020E is a host-only, read-only bounded cross-reference of the
six static ELF slots populated by 020D.  The exact XBL is pinned by size
4,194,304 and SHA-256
`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`; the
020C helper, 020D caller, and 020D object ranges are independently hash-pinned
as dependencies.  An `ADRP` to page `0x9fc3e000` followed within eight
instructions by an unsigned scalar `LDR`/`STR` to one of offsets
`0x138,0x140,0x148,0x150,0x158,0x160` is recognized.  Unknown forms terminate
the local window.  Caller-saved direct `BL` is a barrier; continuation across
X19–X29 is explicitly conditional on AAPCS64 callee preservation.

`PROVED`: 18 unique direct accesses in the exact XBL (6 stores and 12 loads),
with 95 retained barriers (8 caller-saved calls and 87 unknown instructions).
`SUPPORTED`: the slots have additional static uses.  `HYPOTHESIS`: they may
be shared configuration state.  `UNKNOWN`: global writer/consumer absence,
ABI compliance, runtime values/currentness/execution, slot semantics,
MMIO/physical/DRAM identity, mutability/locking, protected reach, aliasing and
bypass.  Class C remains unchanged and 015/016 remain `NOT_ELIGIBLE`.

The tool/test/manifest SHA-256 values are recorded by the integration review;
the public manifest is 29,826 bytes, mode `0644`, SHA-256
`4c28b0cc0a113e099fe3b0ce2bd16a77ce0c9d9bfc799ca9494c52eed9c349ad`.
Validation is 7 focused and 1,186 full serial unittest PASS (`skipped=1`) in
119.090 seconds, maximum RSS 343,404 KiB, zero swap, with deterministic
regeneration and independent hostile-review `PASS`.

## Experiment 020F static-slot load-use metadata

Verification 020F follows the twelve direct scalar loads retained by 020E.  It
is host-only and read-only: each load is traced for at most 16 instructions in
the same executable PT_LOAD.  The model recognizes only strict scalar and
register-offset memory, ADD/SUB, MADD, register-copy, predicate and control
forms.  Caller-saved X0–X18/X30 direct calls are barriers; X19–X29 continuation
is conditional on AAPCS64.  MOVK on tainted registers stops fail-closed, and
CBNZ/TBNZ are included explicitly.

`PROVED`: 16 downstream use events (10 address-base, 2 arithmetic, 2
register-offset, 1 register-copy, 1 return) and 11 barriers (4 caller-saved
`BL`, 5 recognized control, 2 unknown), with no tainted direct store reached
within the windows.  `SUPPORTED`: local address/arithmetic use leads only.
`HYPOTHESIS`: some values may be object pointers or local configuration
fields.  `UNKNOWN`: global writer/consumer absence, ABI compliance/callee
effects, runtime execution/currentness/values, slot semantics,
MMIO/physical/DRAM identity, mutability/locking, protected reach, aliasing and
bypass.  Class C remains unchanged and 015/016 remain `NOT_ELIGIBLE`.

The public manifest is 13,069 bytes, mode `0644`, SHA-256
`d19687581d046c7b05841aef6340e9a1e3664c69e19903689d1c583aee5b9764`.
Validation is 9 focused and 1,195 full serial unittest PASS (`skipped=1`) in
123.910 seconds, maximum RSS 342,272 KiB, zero swap, with deterministic
regeneration, redaction and independent hostile-review `PASS`.

## Experiment 020G static-slot pointer/object metadata

Verification 020G re-decodes exactly the 020F address-use events under a
bounded instruction-shape model.  It yields 12 witnesses: 10 immediate
object-field-shaped accesses (7 `LDR`, 3 `STR`) and 2 `UXTX` register-offset
array-element-shaped loads.  There are 11 unique access VAs and one duplicate
witness.  `PROVED` is limited to the exact bounded census; `SUPPORTED` is
local pointer/object/array shape only.  Runtime base values/currentness,
object semantics, global writer/consumer absence, MMIO/physical/DRAM identity,
mutability, protected reach and alias/bypass remain `UNKNOWN`.  Class C and
`NOT_ELIGIBLE` remain unchanged; no device action occurred.

The public manifest is 7,218 bytes, mode `0644`, SHA-256
`f534efeee1e12f18d3af40c107dbc6fbe938eae16d9013aa088d22d7c880af3e`.
Validation is 10 focused and 1,205 full serial unittest PASS (`skipped=1`) in
134.596 seconds, maximum RSS 347,740 KiB, zero swap.

## Experiment 020H static-slot function-role/base-origin metadata

Verification 020H re-decodes the exact 020G access set and analyzes only the
pinned role region `[0x9fc26e84,0x9fc26f60)` (220 bytes).  Strict RET X30 and
direct-B boundaries yield 7 bounded blocks; true function boundaries remain
`UNKNOWN`.  Direct BL sources to each bounded block entry and a backward
16-instruction base trace are retained without promoting a static VA to a
runtime pointer or controller address.

`PROVED`: 12 witness rows, 11 unique access VAs, 7 bounded blocks, nine
unsupported-role blocks and two local-read-shaped blocks;
ten unique `STATIC_SLOT_SEED` base definitions and one indexed
`ARITHMETIC_DERIVED` `MADD` base.  `SUPPORTED`: local helper/object role
consistency.  `HYPOTHESIS`: the family may be local configuration/helper
state.  `UNKNOWN`: true function boundaries, runtime execution/currentness and
values, indirect effects, object semantics, global writer/consumer absence,
ABI effects, MMIO/physical/DRAM identity, mutability/locking, protected reach,
aliasing and bypass.  Class C remains unchanged and 015/016 remain
`NOT_ELIGIBLE`.

The public manifest is 19,314 bytes, mode `0644`, SHA-256
`b306ca67675430314289fd79faa2e53b2d67994807d0b08bd91ced9b625faba2`.
Validation is 11 focused and 1,216 full serial unittest PASS (`skipped=1`) in
140.860 seconds, maximum RSS 349,728 KiB, zero swap, with deterministic
regeneration, redaction, no-clobber, and independent hostile-review `PASS`.
The next scored candidate is a bounded caller-context/entry-role trace (020I).

## Experiment 020I caller-context/entry-role metadata

Verification 020I re-decodes the exact 020H role rows and verifies 20 unique
block-entry direct-BL source/target edges.  Each source receives a backward
window of at most 16 instructions with strict RET X30, direct-B/BL, scalar or
UXTX memory, ADRP, ADD/SUB, MADD and MOV decoders; unsupported forms stop
fail-closed.  `PROVED`: 20/20 source/target edges and the bounded 12/6/2
classification split (`CALLER_CONTEXT_UNSUPPORTED`, `ARGUMENT_OR_UNKNOWN`,
`ARGUMENT_COPY_OR_CONSTANT`).  Static-slot-origin caller evidence is not
reached in these windows.  `SUPPORTED`: local caller-context shape only.
`HYPOTHESIS`: some callsites may be initialization/helper paths.
`UNKNOWN`: true function boundaries, runtime execution/currentness/values,
indirect effects, object semantics, global writer/consumer absence, ABI
effects, MMIO/physical/DRAM identity, mutability/locking, protected reach,
aliasing and bypass.  Class C remains unchanged and 015/016 remain
`NOT_ELIGIBLE`.

The public manifest is 12,472 bytes, mode `0644`, SHA-256
`03c463f667142a21641264ec2e4080d9d5f963c67776037ca9d6194a8a621608`.
Validation is 11 focused and 1,227 full serial unittest PASS (`skipped=1`) in
151.571 seconds, maximum RSS 356,228 KiB, zero swap, with deterministic
regeneration, redaction, no-clobber, and independent hostile-review `PASS`.
The next scored candidate is a bounded caller-context barrier/opcode inventory
(020J).

## Verification 019 suspend/permutation metadata

The imported V019 analyzer demonstrates a two-state tag oracle: an injective
synthetic map remains `MAP_INVARIANT`, while injected address-line permutations
are detected and decoded.  Two retained receipts report 4,194,304 tags,
25.090-second and 25.151-second corroborated deep suspends, and zero moved
tags in each run.  The bounded result is `PROVED`/`REFUTED` for those exact
receipts and offset domain; physical-page provenance, complete DRAM
coordinates, other state transitions and global mutability remain `UNKNOWN`.
The public manifests are 657 and 658 bytes, mode `0644`, SHA-256
`bf7c66c78993b24d02a46735abb77e7e40298d6230bc5438c3eb21028c51238b` and
`b9d5717f33349727da7523ea6ab003ce33ec6694fce3487370a802a1d2f4b4eb`.
Focused validation is 24/24 analyzer tests plus 5/5 private-receipt guard
tests, with C probe syntax checks and synthetic positive/negative gates; no
new device action occurred in this integration.  See
`docs/VERIFICATION019_INTEGRATION_REVIEW_2026-08-27.md`.

## 1b known-aperture reachability metadata

The 1b checkpoint parses the exact public `MEMORY_MAP.md`, 009 XPU policy,
010 initializer, 007 fixed-load watchdog and 005 control-node manifests. Both
selector branches enumerate the same eight known qhs_llcc-remapper/BIMC
addresses inside TZ-owned broad raw rows. The tested `0x09248080` narrow row is
branch-invariant. The fixed EL1 non-return and failed control-node route are
separate observations; the bit-3 HLOS predicate is non-discriminating and
neither result proves the refusing agent. Global reachability, alternate
apertures/initiators, final runtime policy, ordering, mutability, and bypass
remain `UNKNOWN`; Class C and `NOT_ELIGIBLE` are unchanged.

The audit-corrected v2 manifest is 24,690 bytes, mode `0644`, SHA-256
`da1f03f728435421dc3a33b25914117e8a098f443b599b7f50ccff51154b4fe3`.
Focused validation is 9/9 and the checkpoint is host-only with no device
action. The 2026-08-27 review is retained as historical provenance; its HLOS
interpretation is superseded by `docs/FINAL_REPORT_2026-08-29.md`.

## Experiment 020J caller-context barrier/opcode metadata

Verification 020J re-derived the exact 020I callsite set and inspected only
the first unsupported word in each of 12 bounded caller windows.  The 12 stop
VAs are unique and classify as `B_COND` 5, `CBZ_CBNZ` 2, `LDP_STP_PAIR` 2,
logical-immediate 2 and `BITFIELD` 1 (`BFXIL`); no row uses the
`UNKNOWN_OPCODE` fallback.  This is a strict finite opcode-family inventory,
not a continuation of data flow or a true-function/runtime/control-register
claim.  Runtime execution/currentness/values, indirect paths, object meaning,
MMIO/physical/DRAM identity, mutability/locking, protected reach and
alias/bypass remain `UNKNOWN`; Class C and `NOT_ELIGIBLE` remain unchanged.

The public manifest is 7,657 bytes, mode `0644`, SHA-256
`1fdb1f4ade702fdb2d6ffdc68669a9710c8152e225f89f02fb65c0d10f4c3d55`.
Validation is 7 focused and 1,234 full serial unittest PASS (`skipped=1`) in
164.114 seconds, maximum RSS 355,764 KiB, zero swap, with byte-identical
regeneration, redaction, no-clobber, exact-family and mutation negatives, and
independent hostile-review `PASS`.  The next bounded result is recorded below.

## Experiment 020K caller-context barrier operand/target metadata

Verification 020K re-derived the exact 12 020J unsupported stops and decoded
only their first words.  The 5/2/2/2/1 family split is unchanged; conditional
targets are four-byte aligned and remain in the same executable file-backed
segment.  The pair forms are scalar 64-bit `STP` with `+64` offset and `-16`
pre-index offset, the logical forms are identical 32-bit immediate encodings,
and the bitfield word is the 32-bit `BFXIL` alias.  A local loader independently
pins the XBL; raw words are published only as hashes and no trace continues
past a stop.

`PROVED` is limited to these finite operand fields and target checks.
Instruction effects, true-function/runtime semantics, physical/DRAM identity,
mutability, protected reach and alias/bypass remain `UNKNOWN`; Class C and
`NOT_ELIGIBLE` are unchanged.  The public manifest is 9,961 bytes, mode
`0644`, SHA-256
`90a0cf4d264c64d0d2836b567a2dc8ac5abff7809be839e5131fc7e91e32975a`.
Focused validation is 13/13 and the full serial suite is 1,288/1,288 PASS
(`skipped=1`) in 180.173 seconds, maximum RSS 363,772 KiB, zero swap.  The
independent hostile review is `PASS` after the XBL-loader provenance repair;
no device action occurred.  The next discriminator is 020L, a one-word census
of the unique conditional branch landing VAs, without path continuation.  See
`docs/VERIFICATION020K_INTEGRATION_REVIEW_2026-08-27.md`.

## Experiment 020L branch-target landing-word metadata

Verification 020L re-derived the exact seven unique conditional target VAs
from 020K and inspected one instruction word at each.  The strict family split
is ADRP x2, LDR_UNSIGNED x1, logical-immediate x2, MOV_REGISTER x1 and scalar
LDP x1.  The landing-word reader rejects `va % 4 != 0` before reading, then
requires an executable file-backed segment; source/dependency hashes are
pinned, raw words are hash-only and no target block is followed.

`PROVED` is limited to this finite target/family census and its gates.
Execution, function boundaries, runtime values, pointer/PA meaning,
MMIO/DRAM identity, mutability, protected reach and alias/bypass remain
`UNKNOWN`; Class C and `NOT_ELIGIBLE` are unchanged.  The public manifest is
5,109 bytes, mode `0644`, SHA-256
`cdb0db05596ad06ae179861a4083e08b116ce283f683dd5fae44efde020f85dc`.
Focused validation is 7/7 PASS, regeneration is byte-identical, and the
independent hostile review is `PASS`.  No device action occurred.  See
`docs/VERIFICATION020L_INTEGRATION_REVIEW_2026-08-27.md`.

## Integration validation and current reconciliation

Independent Experiment 026 integration validation is 25 focused and 581 full
repository unittest PASS, Python byte-compilation, public JSON safety,
byte-identical regeneration, manifest mode `0644`, and exact-XBL/final decoder
hostile-review PASS results recorded in
[EXP026_INTEGRATION_REVIEW_2026-08-26.md](EXP026_INTEGRATION_REVIEW_2026-08-26.md).
The historical Experiment 023 result remains explicitly `WITHHELD/NO-GO` and
is not promoted; its audit manifest is retained while raw evidence stays
private. Repaired Experiment 023R instead proves only allocation-offset/model
algebra and supports physical PA attribution within stated assumptions.
Experiment 027 is completed and integrated: its bounded
73-site census returns 71 `INDIRECT_OR_UNSUPPORTED`, 2
`NO_TARGET_WITHIN_MODEL`, zero `DCB_CONSUMER_PATH`, and zero
`MC_OR_SHRM_SYMBOLIC_TARGET`; exact inputs, exclusions, artifact pins, and
validation are recorded in the Experiment 027 integration review. Experiments
029, 031, 032, and 033 are also completed and integrated; their exact frontier
accounting, source-qualified transitions, artifact pins, and validation are
recorded in their integration reviews. Experiment 033 is the v4 residual
extension from commit `56b5ffa`: 352 selected occurrences / 219 unique VAs /
197 unique words, 308 reached events, 44 selected-not-reached, 44 new events
(`LDP` 38, `STP` 3, `LDRSW` 1, `LDRSB` 1, `DAIFClr` 1), six explicit STP lane
observations, and a 70/1 bounded site split that Experiment 034 subsequently
closes to 71/0 inside the static model. Exact external parent `247b0e1` is now
reconciled for 019A–023R/028/029A/030 with the bounded rows above, 296 focused
and 995 full tests, byte-identical fresh publications and hostile-review
`PASS`. Verification 015 is subsequently repaired as the bounded V015 row
above, with 44 focused / 1,039 full serial tests and hostile-review `PASS`; it
was rebuilt rather than merged from the moving branch. Verification 016 is
subsequently repaired from three pinned raw files with phase-specific controls,
two-pass consistency and model-scoped physical claims. Verification 017 remains
outside and is `UNBLOCKED_FOR_SEPARATE_AUDIT_NOT_PROMOTED`.

## Verification 015 metadata

- Intended target: `SM-A908N` / `SM8150`; transcript-attested target identity:
  `UNKNOWN`; operator/project-context status: `SUPPORTED`.
- Coordinate scope: `ALLOCATION_OFFSET_MODEL_COORDINATES`; pagemap: `BLIND`;
  effective contiguity: `UNKNOWN`.
- Exact private inputs: 15 condition transcripts + repeat + six-level sweep +
  two journals, all basename/size/SHA-256 pinned in the public manifest.
- Public manifest:
  `evidence/manifests/verification-015-runtime-invariance-20260826-01.manifest.json`,
  112,840 bytes, SHA-256
  `fab880dc50f8e66e74828a0276f8e5ab5ef9b1f2b2f2f9f032dcef03b6b98592`.
- Validation: 44 focused and 1,039 full serial unittest PASS; Python byte-
  compilation, byte-identical fresh generation, public safety, JSON/link/diff
  checks and stable-tree hostile review `PASS`. A fresh publisher output was
  observed as mode `0644`; no checked-out POSIX mode is asserted.
- Integration record:
  [VERIFICATION015_INTEGRATION_REVIEW_2026-08-27.md](VERIFICATION015_INTEGRATION_REVIEW_2026-08-27.md).

## Verification 016 metadata

Audit qualification (2026-08-29): the implementation/test PASS below proves
reproducibility against its encoded contract, not independent validity of the
statistic. The decisive high-bit labels depend on an unregistered upper median
over exact 16/32 mixtures; using the lower median changes the threshold from
299 to 356 and agreement from 7/7 to 5/7. Physical provenance remains blind.

- Intended target: `SM-A908N` / `SM8150`; transcript-attested target identity:
  `UNKNOWN`; operator/project-context status: `SUPPORTED`.
- Coordinate scope: `ALLOCATION_OFFSET_MODEL_COORDINATES`; pagemap: `BLIND`;
  physical PA/base/alignment/effective contiguity: `UNKNOWN`.
- Exact private inputs: three pinned JSONL files preserving 3×14
  discrimination, 1×9 held-out and 2×14 three-column sections. Probe source,
  repaired 023R dependency and V015 publication helper are also pinned.
- Public manifest:
  `evidence/manifests/verification-016-high-bit-relation-20260827-01.manifest.json`,
  59,504 bytes, SHA-256
  `72525cf994e52bbee1c3ed685c49a6ace4049cd7b279cb97811f6a0d3f4f773f`.
- Validation: 23 focused and 1,062 full serial unittest PASS; Python byte-
  compilation, strict phase/parser gates, byte-identical fresh generation,
  public safety, fresh mode `0644`, no-clobber publication and hostile-review
  `PASS`.
  No exact POSIX mode is asserted for checked-in artifacts.
- Integration record:
  [VERIFICATION016_INTEGRATION_REVIEW_2026-08-27.md](VERIFICATION016_INTEGRATION_REVIEW_2026-08-27.md).
