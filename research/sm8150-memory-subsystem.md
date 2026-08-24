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
XOR, and cannot itself create a PA alias. `SUPPORTED`: it is the intended
hardware coordinate model. A hidden silicon transform remains `UNKNOWN`.

`SUPPORTED`: The decisive state is in memory-controller/PHY-coupled DDRSS logic
initialized by XBL/DDR DSF/DCB before general RAM becomes usable. Exact live XBL
proves DDR initialization, DCB loading and channel/rank training; the specific
decode writes remain unidentified.

## Candidate block/register inventory

The ranking reflects value for the attack-class question, not confidence that a
candidate is EL1-accessible.

| Rank | Candidate | Who/when | Base and offset | Width | EL1 read/write | Reset/boot/lock/owner | Confidence |
|---:|---|---|---|---|---|---|---|
| 1 | Per-channel MCCC token set | `PROVED`: selected section 16 plus exact `qhm_shrm` topology | bases `0x09250000`, `0x092d0000`, `0x09350000`, `0x093d0000`; set-0 token `0x46`, set-1 `0x44..0x47` | base-token/page interpretation `SUPPORTED`; offset scaling and access width `UNKNOWN` | `UNKNOWN/UNKNOWN`; broad surrounding TZ policy does not yet prove each data-page decision | values/reset/boot/lock `UNKNOWN`; SHRM visibility `PROVED` | Highest compact four-channel final-decode candidate; semantics still `HYPOTHESIS` |
| 2 | Per-channel MC page-token sets | `PROVED`: selected section 16 plus exact `qhm_shrm` topology | roots `0x09260000`, `0x092e0000`, `0x09360000`, `0x093e0000`; ten records through matching subpages | raw uint16 tokens `PROVED`; page and register semantics `SUPPORTED/UNKNOWN` | `UNKNOWN/UNKNOWN` | operation direction, values, reset, boot, lock `UNKNOWN` | Broadest exact finer-decode candidate set |
| 3 | MCCC master token set | `PROVED`: exact topology plus section-16 numeric match | base `0x090b0000`; set-0 `0xa5`, set-1 `0x0,0xa0,0xa2..0xa8` | token scaling/access width `UNKNOWN` | XBL boot map class is `NS_DEVICE`; post-boot EL1 read/write still `UNKNOWN` | values and lock `UNKNOWN`; SHRM target `PROVED` | High global interleave/decode candidate value |
| 4 | DDRSS register token set | `PROVED`: exact topology plus section-16 numeric match | base `0x090c0000`; set-0 tokens `0x16,0x17,0x2c` | token scaling/access width `UNKNOWN` | `UNKNOWN/UNKNOWN` | operation, values, and lock `UNKNOWN` | Small exact global candidate set |
| 5 | XBL ICB/qhs_llcc region remapper | `PROVED`: XBL programs it during DDR bring-up; exact row 7 selected | bases `0x09248080`, `0x092c8080`, `0x09348080`, `0x093c8080`; offsets `0x00..0x58` | exact writer uses 32-bit MMIO and 36-bit split address fields | `/dev/mem` and generic REPL routes `REFUTED`; fixed load returned no value and watchdog; write `UNKNOWN` | destination bases known; numeric words/source bases/interleave mask/lock `UNKNOWN`; no-HLOS policy coverage `PROVED` | Exact system-PA remap; final hash role `UNKNOWN` |

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

`PROVED` by Experiment 011: section 16 is structurally decoded and numerically
binds exact SHRM-visible MCCC/MC/DDRSS pages. `UNKNOWN`: its offset scaling,
operation direction, values, and whether any record changes address decode.
Final runtime policy/control words and where the data-path check sits relative
to hidden/final decode also remain `UNKNOWN`. Recovering the SHRM interpreter
is now the next host-only priority; repeating the denied configuration-aperture
load cannot answer it.
