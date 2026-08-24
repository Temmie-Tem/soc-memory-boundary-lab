# SM8150 Memory Subsystem Reconstruction

## Source-visible blocks

`PROVED`: Exact target source exposes CPU/interconnect traffic toward LLCC, an
LLCC-to-EBI_CH0 path, a DDRSS configuration slave on CNOC, LLCC cache-slice
registers, LLCC/DDR bandwidth monitors and AOP DDR performance messages.

`PROVED`: Exact XBL has a four-instance qhs_llcc region-remapper register space.
`UNKNOWN`: The exact later IP/fields that map system PA bits to channel/rank/
bank-group/bank/row/column. The Linux source contains no identified SM8150
implementation of that finer mapping.

`SUPPORTED`: The decisive state is in memory-controller/PHY-coupled DDRSS logic
initialized by XBL/DDR DSF/DCB before general RAM becomes usable. Exact live XBL
proves DDR initialization, DCB loading and channel/rank training; the specific
decode writes remain unidentified.

## Candidate block/register inventory

The ranking reflects value for the attack-class question, not confidence that a
candidate is EL1-accessible.

| Rank | Candidate | Who/when | Base and offset | Width | EL1 read/write | Reset/boot/lock/owner | Confidence |
|---:|---|---|---|---|---|---|---|
| 1 | XBL ICB/qhs_llcc region remapper | `PROVED`: XBL programs it during DDR bring-up | bases `0x09248080`, `0x092c8080`, `0x09348080`, `0x093c8080`; offsets `0x00..0x58` | exact writer uses 32-bit MMIO | userland `/dev/mem` `REFUTED` (`CONFIG_DEVMEM=n`); generic REPL adapter `REFUTED`; fixed inline no-load control passed but the paired one-load read produced no value and a retained watchdog; write `UNKNOWN` | boot values/lock/owner and watchdog cause after XBL `UNKNOWN` | Exact system-PA remap candidate; final DRAM-hash role `UNKNOWN` |
| 2 | DCB section 16 + SHRM firmware path | `PROVED`: XBL selects DCB, copies section 16, installs SHRM blobs | `qhs_shrm_mem + 0x5100` (`0x09065100`) | structured data/firmware; semantics `UNKNOWN` | host-readable; runtime access `UNKNOWN` | selected DCB and SHRM lock behavior `UNKNOWN` | High remaining channel/bank decode value |
| 3 | Four-channel MCCC/MC windows in XBL topology | XBL/SHRM DDR bring-up | `qhs_mccc`, `qhs_llcc`, `qhs_mc` bases enumerated in exact topology | likely 32-bit; exact fields `UNKNOWN` | `UNKNOWN/UNKNOWN` | `UNKNOWN` | High for finer decode, no field yet |
| 4 | CNOC DDRSS configuration endpoint `SLAVE_CNOC_DDRSS` | `PROVED`: endpoint exists; programmer `UNKNOWN` | endpoint-specific base/offset `UNKNOWN`; do not infer config-NOC aperture blindly | `UNKNOWN` | `UNKNOWN/UNKNOWN` | `UNKNOWN` | Medium: route proved, semantics absent |
| 5 | MCCC master/AOP and LLCC-to-DDR BWMON | XBL maps MCCC; AOP manages DDR; counters observe traffic | MCCC `0x090b0000–0x090b0fff`; BWMON `0x090cd000–0x090cdfff`; PMU `0x090cc000–0x090cc2ff` | likely 32-bit, field semantics incomplete | source-backed reads plausible; mapping write not exposed | XBL classifies MCCC `NS_DEVICE`; post-boot lock/access `UNKNOWN` | Medium landmark, low transform-field confidence |

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
