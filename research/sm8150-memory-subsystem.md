# SM8150 Memory Subsystem Reconstruction

## Source-visible blocks

`PROVED`: Exact target source exposes CPU/interconnect traffic toward LLCC, an
LLCC-to-EBI_CH0 path, a DDRSS configuration slave on CNOC, LLCC cache-slice
registers, LLCC/DDR bandwidth monitors and AOP DDR performance messages.

`UNKNOWN`: The exact IP name and register space that maps system PA bits to
channel/rank/bank-group/bank/row/column. The Linux source contains no identified
SM8150 implementation of that mapping.

`HYPOTHESIS`: The decisive state is in memory-controller/PHY-coupled DDRSS logic
initialized by XBL/DDR training firmware before general RAM becomes usable.
Prediction: exact boot firmware contains topology-dependent table/register writes
that are absent from the kernel.

## Candidate block/register inventory

The ranking reflects value for the attack-class question, not confidence that a
candidate is EL1-accessible.

| Rank | Candidate | Who/when | Base and offset | Width | EL1 read/write | Reset/boot/lock/owner | Confidence |
|---:|---|---|---|---|---|---|---|
| 1 | Final DDRSS MC/PHY address decode: channel/rank/bank/row mapping state | `HYPOTHESIS`: XBL/DDR training before HLOS | `UNKNOWN` | `UNKNOWN` | `UNKNOWN/UNKNOWN` | all `UNKNOWN`; secure/boot owner plausible but unproved | High architectural relevance, low identification confidence |
| 2 | XBL DDR configuration tables / generated register-write sequence | `HYPOTHESIS`: XBL or linked DDR firmware at boot | Firmware-relative address `UNKNOWN` | likely mixed, exact `UNKNOWN` | static read pending; runtime write owner `UNKNOWN` | artifact absent; lock state `UNKNOWN` | Highest next static-analysis value |
| 3 | CNOC DDRSS configuration endpoint `SLAVE_CNOC_DDRSS` | `PROVED`: endpoint exists; programmer `UNKNOWN` | endpoint-specific base/offset `UNKNOWN`; do not infer config-NOC aperture blindly | `UNKNOWN` | `UNKNOWN/UNKNOWN` | `UNKNOWN` | Medium: route proved, semantics absent |
| 4 | LLCC core/broadcast and HN-facing selection state | Linux programs cache slices at LLCC probe | base `0x09200000`; known cache offsets `0x21000+8*n`, `0x21004+8*n`, `0x21f00`, `0x21f04`, status `0x3000c` | source uses 32-bit regmap | source-backed read plausible; Linux writes cache-slice fields | cache fields boot values source-derived; decode role `REFUTED` for those known offsets | Medium landmark, low final-transform confidence |
| 5 | AOP DDRSS control and LLCC-to-DDR BWMON | Linux sends AOP perf/frequency message; counters observe traffic | QMP mailbox indirect; BWMON `0x090cd000 + 0x1000`; PMU `0x090cc000 + 0x300` | driver-specific 32-bit fields | source-backed reads plausible; mapping write not exposed | not an address-map interface in inspected source | Low transform confidence; useful timing/control landmark |

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

`SUPPORTED`, not `PROVED`: Linux is not the component that initially programs
the final transform. Absence in inspected source can be defeated by inline
firmware calls, undocumented drivers, or boot-programmed state.
