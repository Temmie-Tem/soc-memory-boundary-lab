# XBL → SHRM → ICB/LLCC Remapper Reconstruction

Inputs are the exact Experiment 004 live bytes:

- `xbl--sdb1.bin`, SHA-256
  `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`;
- `xbl_config--sdb2.bin`, SHA-256
  `0e9dfac1ddd0f9acc2cc899213e621490308f0cadf329814048edb7712e2484c`.

The reproducible public output is
`evidence/manifests/006-xbl-memory-pipeline-inventory.json`. Proprietary bytes
remain under the ignored `evidence/private/` tree.

## 1. Exact DCB identity and selector

`PROVED`: The `CFGL` table at `xbl_config` file offset `0x3000` binds the four
previously anonymous `0x3404`-byte ELF payloads to:

| Filename | Absolute file offset | DCB used bytes | Section 16 bytes |
|---|---:|---:|---:|
| `/6003_0100_1_dcb.bin` | `0x1079c` | `11692` | `568` |
| `/6003_0100_0_dcb.bin` | `0x13ba0` | `10596` | `348` |
| `/6003_0200_1_dcb.bin` | `0x16fa4` | `11820` | `560` |
| `/6003_0200_0_dcb.bin` | `0x1a3a8` | `10928` | `484` |

`PROVED`: Exact XBL constructs `/%04X_%04X_%01X_dcb.bin` as follows:

1. code at `0x14839d74` reads 32 bits from `0x01fc8000`;
2. bits `[31:16]` become the first `%04X` and bits `[15:0]` feed the second;
3. the loader at `0x1489f97c` masks the second value with `0xff00`;
4. code at `0x14839cb4` makes the last field `1` unless platform type is
   `0x0f`; the image's platform strings identify `0x0f` as RUMI.

`UNKNOWN`: Whether this live handset used revision `0x0100` or `0x0200`.
`SUPPORTED`: This live physical A90 uses the `_1` variant: sysfs reports `MTP`
and exact XBL selects zero only for platform type `0x0f`/RUMI.

`REFUTED`: Linux sysfs `raw_id/raw_version` can substitute for the XBL register
fields. Live values are decimal `165/3`, producing no exact CFGL name, whereas
XBL requires `0x6003` and revision `0x0100` or `0x0200`. Revision selection must
be recovered from XBL's `0x01fc8000` producer or equivalent boot evidence.

## 2. SHRM destination and firmware installation

`PROVED`: XBL initializes its shared DDR context with `qhs_shrm_mem` base
`0x09060000`. The exact topology also labels:

- `qhs_shrm_csr`: `0x09050000`;
- `qhs_shrm_mem`: `0x09060000`;
- `qhs_shrm_mpu_cfg`: `0x09102000`.

`PROVED`: The DCB loader copies section 16 to `0x09065100`, exactly
`qhs_shrm_mem + 0x5100`.

`PROVED`: XBL embeds and installs two SHRM blobs before continuing DDR bring-up:

| Role label | Source VA | Bytes | SHA-256 | First destination |
|---|---:|---:|---|---:|
| data | `0x148bb630` | `2152` | `e36ec8144e0d2280497ed167c41c86a94a3e25c74e380d7f75a5d0bc69d02564` | `0x09062100` |
| instruction | `0x148bbe98` | `23776` | `421824b417ab28e6c0d1802c05d7ce5422e93b116973ce7f039321fb5a01a1fd` | `0x09068000` |

The copy routines are `0x148aeb7c` and `0x148aebfc`; `0x148aeddc` invokes both
after `0x148aedbc` clears part of SHRM memory.

`UNKNOWN`: The SHRM instruction-set encoding and the semantic layout of DCB
section 16. The bytes prove a firmware/config transport path, not yet a final
channel/bank/row hash.

## 3. DDR remapper table

`PROVED`: Function `0x1483a6dc` is the owner of the diagnostic:
`**ERROR Can't find a matching entry in the DDR remapper table**`.
It obtains a rank/channel mask from `qhs_shrm_mem + 0x26`, sums populated memory
sizes, then searches 13 records at `0x14874a38`.

Each exact `0x20`-byte record is:

```text
u64 channel_rank_mask
u64 total_MiB
u64 region0_base
u64 region1_base
```

For the 6 GiB topology, the two rows are:

```text
mask=0x1, total=0x1800 MiB, region0=0x80000000, region1=0
mask=0x3, total=0x1800 MiB, region0=0x80000000, region1=0x140000000
```

`SUPPORTED`: The A90's nominal 6 GiB configuration should select one of these
rows. `/proc/meminfo` alone cannot prove the exact physical total or mask because
reserved memory is excluded.

For each of two regions, the function constructs a record containing current
base, size and selected remap base, then calls `0x14850694` with property device
`/dev/icbcfg/boot`.

## 4. DAL property resolution and concrete registers

`PROVED`: Replaying the exact DAL property parser gives this chain:

```text
DAL source                 0x14821ff0
  property binary          0x148239a0
  structure-pointer table  0x148235e0
  device table             0x14823fb8

/dev/icbcfg/boot
  string VA                0x1481dd37
  djb2 hash                0x8dfe53c3
  device entry             0x14824058
  property offset          0x414

icbcfg_info
  DAL type                 0x12 (structure pointer)
  structure index          6
  root                     0x148769f0
  sole chip record         0x14876998
```

The sole record has six mapping slots, four register instances, table count 36,
and register layout 1. Its register-base array at `0x14876978` contains:

```text
0x09248080
0x092c8080
0x09348080
0x093c8080
```

`PROVED`: Exact XBL topology labels the containing `0x09240000`, `0x092c0000`,
`0x09340000`, and `0x093c0000` windows `qhs_llcc`. Thus each remapper register
instance is at `qhs_llcc + 0x8080` for one of four DDR/LLCC paths.

`PROVED`: Layout-1 writer `0x1484fbbc` first clears the enable/control field at
offset `0x00`, writes the generated six-slot map, then sets bit 0. Across a full
configuration it touches 32-bit offsets `0x00, 0x04, ... 0x58` in every one of
the four windows.

`SUPPORTED`: These registers implement system-physical address region
placement/remapping during DDR bring-up. This follows from the exact remapper
table, its base/size/destination input records, the `icbcfg` call path and the
four qhs_llcc instances.

`UNKNOWN`: Whether these aperture/remap registers also perform final
channel/rank/bank/row/column hashing. They may be an earlier system-PA region
map, with finer DRAM decode occurring later in MCCC/MC/SHRM logic.

## 5. TrustZone cross-check

`PROVED`: The separate exact live TrustZone ELF (SHA-256
`a5e6c574e18e2e576a25df6274b20bdb142386811dfda6383f86d7b1b3c102ab`)
contains an independent DAL entry for the same device and the same four-base
layout-1 record:

```text
/dev/icbcfg/boot string     0x1c114b89
DAL device entry            0x1c116f48
djb2 hash                   0x8dfe53c3
property offset             0xeec
four-base record            0x1c13f658
register base table         0x1c13f638
```

Its record again has six mapping slots, four instances, table count 36 and
bases `0x09248080`, `0x092c8080`, `0x09348080`, `0x093c8080`.

`SUPPORTED`: Secure firmware carries direct knowledge/configuration capability
for the same remapper windows. `UNKNOWN`: Whether TrustZone invokes this path on
the A90 boot/runtime, whether it owns a lock, or whether the duplicated record
is an unused linked configuration.

## 6. Security consequence boundary

This result materially narrows the pipeline, but it is not an alias or bypass:

```text
XBL topology/rank discovery
  -> DDR remapper table
  -> ICB region records
  -> four qhs_llcc + 0x8080 register windows
  -> later MCCC/MC/PHY decode still partly UNKNOWN
```

`UNKNOWN`: Post-boot EL1 readability, writability and lock state.

`UNKNOWN`: Whether an XPU/MPU check is before or after this remap.

`UNKNOWN`: Whether changing any field can create two system PAs that reach one
DRAM location.

`REFUTED`: “No concrete SM8150 address-remap register candidate exists.” The
four exact windows are now source-backed candidates. The stronger statement
“the final DRAM hash is mutable from EL1” remains unsupported.

## 7. Cheapest next measurements

1. Implement a narrow kernel-space `ioremap/readl` adapter for only the four
   proved `0x5c`-byte windows. The current userland route is structurally absent:
   live `/proc/config.gz` has `CONFIG_DEVMEM=n` and a fixed `1:1` node returns
   `ENXIO` before MMIO.
2. Compare all four read-only instances and reconstruct the six programmed
   region slots.
3. Recover the exact `0x01fc8000` hardware revision producer to select the live
   DCB without misusing Linux SMEM raw fields.
4. Correlate boot values with the 6 GiB remapper row and `/proc/iomem`, then
   trace remaining SHRM/MCCC/MC channel/bank/row fields.

No controller write is justified by the current evidence.
