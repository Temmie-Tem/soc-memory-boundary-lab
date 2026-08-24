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

`SUPPORTED`: The decisive state is in memory-controller/PHY-coupled DDRSS logic
initialized by XBL/DDR DSF/DCB before general RAM becomes usable. Exact live XBL
proves DDR initialization, DCB loading and channel/rank training; the specific
decode writes remain unidentified.

## Candidate block/register inventory

The ranking reflects value for the attack-class question, not confidence that a
candidate is EL1-accessible.

| Rank | Candidate | Who/when | Base and offset | Width | EL1 read/write | Reset/boot/lock/owner | Confidence |
|---:|---|---|---|---|---|---|---|
| 1 | XBL ICB/qhs_llcc region remapper | `PROVED`: XBL programs it during DDR bring-up; exact row 7 selected | bases `0x09248080`, `0x092c8080`, `0x09348080`, `0x093c8080`; offsets `0x00..0x58` | exact writer uses 32-bit MMIO and 36-bit split address fields | userland `/dev/mem` `REFUTED`; generic REPL adapter `REFUTED`; fixed instance-0 load returned no value and watchdog; write `UNKNOWN` | destination bases known; numeric words/source bases/interleave mask/lock `UNKNOWN`; tested page static owner `TZ` | Exact system-PA remap candidate; final DRAM-hash role `UNKNOWN` |
| 2 | `DC_NOC_BROADCAST_MPU` policy | `PROVED`: both exact TZ policy branches, consumed static-config path | XPU base `0x090e0000`; region 11 covers `0x09248000–0x09249000` | exact 32-byte policy record and XPU3 HAL conversion | static record grants no HLOS access; live denial `SUPPORTED`; register readback `UNKNOWN` | flags `0x9` = enabled/TZ owner; MSA-class RO; exact devcfg `disable_xpu_ac=0` | Strongest current explanation for fixed-read watchdog |
| 3 | Same-instance BIMC MPU configuration | `PROVED`: exact TZ registry plus error routes; absent from both static lists | `qhs_llcc + 0xe000`: `0x0924e000`, `0x092ce000`, `0x0934e000`, `0x093ce000` | register semantics `UNKNOWN` | no live access attempted | initializer, final policy, self-aperture coverage, lock and ordering `UNKNOWN` | Highest remaining protection-ordering value |
| 4 | Selected DCB section 16 + SHRM firmware path | `PROVED`: `/6003_0200_1_dcb.bin`, 560-byte section 16, installed SHRM blobs | `qhs_shrm_mem + 0x5100` (`0x09065100`) | structured data/firmware; semantics `UNKNOWN` | host-readable; runtime access `UNKNOWN` | SHRM lock behavior `UNKNOWN` | High remaining channel/bank decode value |
| 5 | Four-channel MCCC/MC windows in XBL topology | XBL/SHRM DDR bring-up | `qhs_mccc`, `qhs_llcc`, `qhs_mc` bases enumerated in exact topology | likely 32-bit; exact fields `UNKNOWN` | `UNKNOWN/UNKNOWN` | `UNKNOWN` | High for finer decode, no field yet |

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

`PROVED`: BIMC_MPU0..3 have exact registry and error-route entries but appear
in neither embedded static policy list. Locating their initializer is the next
host-only priority because they remain the leading candidates for data-path
protection ordering relative to the remapper and final MCCC/MC decode.
