# SM8150 Memory Subsystem Reconstruction

## Source-visible blocks

`PROVED`: Exact target source exposes CPU/interconnect traffic toward LLCC, an
LLCC-to-EBI_CH0 path, a DDRSS configuration slave on CNOC, LLCC cache-slice
registers, LLCC/DDR bandwidth monitors and AOP DDR performance messages.

`UNKNOWN`: The exact IP name and register space that maps system PA bits to
channel/rank/bank-group/bank/row/column. The Linux source contains no identified
SM8150 implementation of that mapping.

`SUPPORTED`: The decisive state is in memory-controller/PHY-coupled DDRSS logic
initialized by XBL/DDR DSF/DCB before general RAM becomes usable. Exact live XBL
proves DDR initialization, DCB loading and channel/rank training; the specific
decode writes remain unidentified.

## Candidate block/register inventory

The ranking reflects value for the attack-class question, not confidence that a
candidate is EL1-accessible.

| Rank | Candidate | Who/when | Base and offset | Width | EL1 read/write | Reset/boot/lock/owner | Confidence |
|---:|---|---|---|---|---|---|---|
| 1 | XBL DSF/DCB final DDRSS decode write path | `PROVED`: XBL initializes/trains DDR before HLOS; decode subset `UNKNOWN` | live XBL/config offsets under analysis | likely 32-bit MMIO, exact `UNKNOWN` | static bytes acquired; live access `UNKNOWN` | boot values/lock owner `UNKNOWN` | Highest static-analysis value |
| 2 | Four board DCB/config blocks in `xbl_config--sdb2` | `PROVED`: exact loader validates `0x3404`/DSF `0x650000` and consumes five sections | ELF entry `0x148d0000`; section 16 copied to `0x09065100` | structured data; final-map field identity `UNKNOWN` | host-readable; runtime mutation not proposed | selected DCB and SHRM lock behavior `UNKNOWN` | High |
| 3 | CNOC DDRSS configuration endpoint `SLAVE_CNOC_DDRSS` | `PROVED`: endpoint exists; programmer `UNKNOWN` | endpoint-specific base/offset `UNKNOWN`; do not infer config-NOC aperture blindly | `UNKNOWN` | `UNKNOWN/UNKNOWN` | `UNKNOWN` | Medium: route proved, semantics absent |
| 4 | LLCC core/broadcast and HN-facing selection state | Linux programs cache slices at LLCC probe | base `0x09200000`; known cache offsets `0x21000+8*n`, `0x21004+8*n`, `0x21f00`, `0x21f04`, status `0x3000c` | source uses 32-bit regmap | source-backed read plausible; Linux writes cache-slice fields | cache fields boot values source-derived; decode role `REFUTED` for those known offsets | Medium landmark, low final-transform confidence |
| 5 | MCCC/AOP DDRSS control and LLCC-to-DDR BWMON | XBL maps MCCC; AOP manages DDR; counters observe traffic | MCCC `0x090b0000–0x090b0fff`; BWMON `0x090cd000–0x090cdfff`; PMU `0x090cc000–0x090cc2ff` | likely 32-bit, field semantics incomplete | source-backed reads plausible; mapping write not exposed | XBL classifies MCCC `NS_DEVICE`; post-boot lock/access `UNKNOWN` | Medium landmark, low transform-field confidence |

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

`PROVED`: XBL is a component that initializes DDR before Linux. `SUPPORTED`, not
`PROVED`: it also programs the final PA-to-DRAM transform; the exact MMIO write
chain must still be recovered.
