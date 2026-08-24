# Live Firmware Static Reconstruction — First Pass

Input: Experiment `004-live-firmware-readonly-20260825-01`.

All statements below refer to exact live partition bytes whose device-before,
host, and device-after SHA-256 values agree.

## XBL and DDR ownership

`PROVED`: Both `xbl` partitions are AArch64 ELF executables with entry
`0x1481c908`, but their hashes and program-segment sizes differ.

`PROVED`: `xbl--sdb1` identifies itself as
`BOOT.XF.3.0-00468-SM8150LZB-1`, variant `SDM855LA`, OEM `SWDK6110`.
`xbl--sdc1` has the same Qualcomm BOOT release but OEM `SWDG5312`.

`SUPPORTED`: `sdb1/sdb2` is the newer/currently relevant pair: the live kernel
and AOP also identify `SWDK6110`, `sdb2` contains an ELF `xbl_config`, while
`sdc2` has no ELF header and is mostly zero-filled with structured metadata near
its tail. `UNKNOWN`: the UFS boot-LUN selection was not read, so active-slot
identity is not promoted to `PROVED`.

`PROVED`: Exact XBL bytes contain the DDR first-pass initialization and training
implementation, including:

- `boot_extern_ddr_interface.c`, `HAL_DDR_Init()` and DDR failure handling;
- DCB pathname `/%04X_%04X_%01X_dcb.bin`, DCB size/CRC and DSF-version checks;
- read/write/RCW/DCC/DIT training over channel and rank;
- explicit four-channel structures and consistency checks;
- the diagnostic field `invert_row`.

These strings and the adjacent executable segment prove that XBL owns initial
DDR training/configuration. They do not prove that `invert_row` is the final
system-PA hash or that any mapping state remains mutable after boot.

`PROVED`: XBL's embedded UEFI platform map contains:

```text
0x090B0000, 0x00001000, "MCCC_MCCC_MSTR", AddDev,
MMAP_IO, UNCACHEABLE, MmIO, NS_DEVICE
```

This makes `0x090b0000–0x090b0fff` a source-backed MCCC boot-firmware landmark.
`UNKNOWN`: whether it contains PA-to-DRAM mapping fields. `NS_DEVICE` describes
the XBL mapping class; it does not prove post-boot EL1 access or lack of an XPU
lock.

`PROVED`: The populated `xbl_config--sdb2` ELF contains exactly four
`0x3404`-byte DCB load segments. All four have DSF version `0x00650000` and 18
nonempty header-indexed sections. Evidence:
`evidence/manifests/004-xbl-dcb-inventory.json`.

`PROVED`: Exact XBL loader disassembly requires a DCB size of decimal `13316`
(`0x3404`), checks `dcb+8 == 0x00650000`, and consumes header section indexes
`0`, `1`, `2`, `15`, and `16`. It copies section 16 to destination address
`0x09065100`, bounded to `0x0f00` bytes.

`PROVED` by Experiment 006: `0x09065100` is `qhs_shrm_mem + 0x5100`, and XBL
installs embedded SHRM data/instruction blobs during DDR bring-up. `PROVED` by
Experiment 008: retained boot-firmware evidence selects
`/6003_0200_1_dcb.bin`; its section 16 is 560 bytes and lands at the same
destination. `UNKNOWN`: whether that section contains final PA
interleave/hash state or whether SHRM turns it into locked controller registers.

## AOP

`PROVED`: `aop--sdd7` is an ARM ELF with entry `0x0b000009`, version
`AOP.HO.1.1-00230`, OEM `SWDK6110`.

`PROVED`: It contains `DDR_MGR`, DDR ISR, frequency/dependency/temperature,
`/pm/ddr`, `addr_hi/addr_lo`, and EBI/DDR level resources. This establishes AOP
runtime DDR power/performance involvement. No address-interleave/hash programming
interface has yet been identified.

## QHEE / hyp

`PROVED`: `hyp--sdd33` is an AArch64 ELF, SHA-256
`646f8fca08b0eff56b1d8415d81c3041a775c1871400dc57448cb5103405a8e1`.
Its first load segment starts at `0x85700000` and entry is `0x85710000`, both
inside the live DT `hyp_mem` range `0x85700000–0x85cfffff`.

`PROVED`: The image identifies `hyp.mbn` and contains hypervisor manager,
SMMU virtualization, memory ownership, HLOS asset protection, and kernel
protection strings. Thus QHEE/hypervisor firmware is supplied by the live `hyp`
partition. This still does not grant arbitrary EL2 runtime memory access.

## TrustZone and protection blocks

`PROVED`: `tz--sdd5` is an AArch64 ELF with entry `0x14680000`, SHA-256
`a5e6c574e18e2e576a25df6274b20bdb142386811dfda6383f86d7b1b3c102ab`.

`PROVED`: The exact image names `BIMC_MPU0`, `BIMC_MPU1`, `BIMC_MPU2`,
`BIMC_MPU3`, `MEMNOC_MS_MPU`, and `LLCC_BROADCAST_MPU`, alongside LLCC and
DDRSS error components.

`PROVED` by Experiment 008: primary TrustZone registry records assign exact IDs
and bases: `BIMC_MPU0..3` at `0x0924e000`, `0x092ce000`, `0x0934e000`,
`0x093ce000`; `MEMNOC_MS_MPU` at `0x096c0000`; `LLCC_BROADCAST_MPU` at
`0x0964e000`; and `DC_NOC_SHRM_MPU` at `0x09102000`.

`SUPPORTED`: TrustZone contains configuration/diagnostic knowledge for multiple
memory-protection blocks across BIMC/MEMNOC/LLCC. `UNKNOWN`: which are enabled,
their precise pipeline order, whether they cover configuration accesses, and
whether any performs a second check after final DRAM decode.

## Follow-up status

Experiment 006 completed the first structural follow-up:

1. all four DCBs are bound to exact selector names;
2. section 16 is proved to land at `qhs_shrm_mem + 0x5100` alongside installed
   SHRM firmware;
3. XBL's DDR remapper table and `/dev/icbcfg/boot` property chain are recovered;
4. the writer programs four qhs_llcc windows at `+0x8080`, offsets through
   `+0x58`.

The fixed live identity capture refuted using Linux SMEM raw fields as the XBL
DCB selector. Experiment 008 instead resolved the selector from retained XBL
logs and selected remapper row 7 for the exact 3072+3072 MiB rank topology.
Experiment 007's purpose-built single MMIO load returned no value and ended in
a retained watchdog, while its no-load control passed. Final channel/bank/row
hash fields, numeric boot remapper words, locks and enforcement ordering remain
`UNKNOWN`.

Current bypass state remains `UNKNOWN / NO BYPASS OBSERVED`.
