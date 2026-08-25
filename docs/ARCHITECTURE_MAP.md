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

`PROVED`: The exact DT supplies LLCC at `0x09200000 + 0x450000`, four bank
offsets, and broadcast offset `0x400000`. Evidence: `sm8150.dtsi:1971-1999`,
SHA-256 `c0d42e66ddd5640e2dd7b65527c25fb617008d94a6a04062b9e1077f0eb63849`.

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
does not label physical BA pins. PA9 and PA10 are `SUPPORTED` as two further
independent channel-like selection components. PA24..31, exact block/register
ownership, and complete-coordinate alias behaviour remain `UNKNOWN`.

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
| Who programs it? | `PROVED`: XBL programs the region remapper through `icbcfg` and copies section 16 to SHRM. `PROVED`: the exact SHRM section-16 consumers read listed controller words into a read-copy buffer; the observed section-16 paths do not write those addresses. Experiment 017 independently proves the exact XBL helper's store-base dataflow does not program candidate registers. Experiment 018 Stage 1A adds only literal/offset census evidence, Stage 2A refutes only its supported direct-definition path for four RX candidates, Stage 2B refutes only numeric target equality for two W-wide-move-resolved values, Stage 2C refutes only numeric target equality for a 48-row possible-value superset, and Stage 2D refutes only numeric target equality under explicit preservation/slot conditions; none proves writer absence or physical destination. AOP runtime DDR management is `PROVED`; final-decode writer remains `UNKNOWN`. |
| At what stage? | Region-remap programming during XBL DDR initialization before HLOS is `PROVED`; later mutability remains `UNKNOWN`. |
| Can EL1 observe it? | `PROVED` behaviorally: non-secure ION/CNTVCT timing exposes the low-24 bank-equivalence relation. Direct register routes remain `REFUTED`: `/dev/mem` is absent and the fixed protected load returned no value. After reset, Samsung Upload exports coherent set-0 words, but is not an EL1 runtime interface and omits remapper controls. Experiment 017 adds host-only static XBL read-copy evidence, not current-boot EL1 observability. |
| Can EL1 modify it? | No mutation is proved. The exact HLOS-visible XPU-disable allowlist has zero entries, and all known configuration apertures have branch-invariant TZ-owned coverage. Final runtime policy/lock readback is `UNKNOWN`. |
| Does EL2/EL3 lock it? | `PROVED`: QHEE applies ownership/stage-2/SMMU enforcement and TZ dynamically programs BIMC policies. `UNKNOWN`: final hardware write-disable bit and exact dispatcher/lock ordering. |
| Is there a post-transform security check? | `UNKNOWN`; the diagnostic coordinate formula and configuration-aperture coverage do not locate the data-path check. Dynamic BIMC MPU policy makes a later check plausible but does not place it relative to hidden/final decode. |
