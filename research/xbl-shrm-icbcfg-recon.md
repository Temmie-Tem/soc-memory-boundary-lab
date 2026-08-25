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

`PROVED` by Experiment 008: the retained exact XBL log repeats
`Chip Revision @ 0x01fc8000 = 0x60030202` seven times and platform ID `8`
seven times. The records are internally consistent and select
`/6003_0200_1_dcb.bin`. Its SHA-256 is
`34caf815065e5fe3e80483e5348a59caa9dc249faa72d97e6e44f818d17ef607`;
its 560-byte section 16 SHA-256 is
`cdacfa45183be71c13884ed60dd883a7f94ba5fd4fb9cc92899fac4eb0298dc0`.

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

`PROVED` by Experiments 011/012: selected section 16 has header
`{8, 0x230, 0x1b8, 0x8e8}` and parses exactly into two compact record sets of
the form `{u8 base_count, u8 offset_count, u16 base_tokens[], u16
offset_tokens[]}`. The exact Xtensa helper at `0x2d8dc` computes
`(base_page << 12) + (offset_token << 2)` and copies each 32-bit register word
into a SHRM snapshot buffer. Both direct consumers pass direction zero, so the
observed path is a read inventory, not a write command stream. The selected
lists produce 430 and 64 register-word reads.

`PROVED` by Verification 002: the complete Xtensa image has one direct
workspace-base literal (`0x25100`) referenced by the two producers and no
direct u32 literal for derived destinations `0x25330`/`0x259e8` or their
physical addresses. Exact XBL nevertheless contains an external consumer: a
26-record raw-dump table at `0x14961730` whose index 19 maps
`0x09060000..0x0906ffff` to `SHRM_MEM.BIN`. Its AArch64 loop and dload call
chain are instruction-pinned, so the descriptor is consumed rather than
orphaned data.

`SUPPORTED`: this is a bootloader crash/download diagnostic export, not a
normal-HLOS runtime interface. Verification 012 later proved the gate,
collection, and coherent set-0 population; runtime HLOS access remains absent.

`PROVED` host-only by decoder commit `9fdd5d6`: a valid 64-KiB export can be
mapped immediately to 430 and 64 ordered source-register labels using the
committed section-16 inventory. The covered words do not include the remapper
window at `qhs_llcc + 0x8080`; remapper enable/slot/lock state stays outside
this route. Verification 012 later acquired and decoded one real dump; set 0 is
coherent, set 1 is excluded, and the remapper controls remain outside coverage.

`PROVED` live by Verifications 003/004: V2321 was initially `LOW` with
`androidboot.force_upload=0`, while the exact A90 4.14 source-backed dload
master parameter is `1`. The S22+ `qcom_dload_mode` module path does not exist
on this kernel; `msm_poweroff` is the exact owner. These values classify the
visible entry signals as incomplete, so no reset/dump collection was attempted
in those passes. Later verification proved FMM unlocked, used MID once, and
restored LOW.

`SUPPORTED`: base tokens are 4-KiB page numbers for exact SHRM topology targets.
`UNKNOWN`: exact set-0 semantics, lock state, whether any readback register
controls final address decode, and whether an indirect reverse-direction
invocation exists. The structured read list does not prove a writable
channel/bank/row hash.

## 2a. Exact XBL diagnostic coordinate model

`PROVED` by Experiment 011: Quest DDR failure recorder `0x1492234c` calls
reporter `0x149212c0`, whose exact format names rank/row/bank/channel/column.
For the retained 6-GiB topology it derives boundary `0x140000000`, exactly the
selected remapper row's rank-1 destination, and labels rank-relative bits as:

```text
row[31:16] bank[15:13] channel[10:9]
column={bits[12:11],bits[8:1]} byte[0]
```

The mapping is bijective. `REFUTED`: this bounded diagnostic formula itself
contains an XOR or physical alias. `UNKNOWN`: an additional transform hidden
from the diagnostic.

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

For a 6 GiB topology, the two relevant rows are:

```text
mask=0x1, total=0x1800 MiB, region0=0x80000000, region1=0
mask=0x3, total=0x1800 MiB, region0=0x80000000, region1=0x140000000
```

`PROVED` by Experiment 008: the retained XBL log reports rank 0 = 3072 MiB and
rank 1 = 3072 MiB six times with no conflicting value. Present-rank mask `0x3`
and total 6144 MiB uniquely select row 7, with destinations `0x80000000` and
`0x140000000`. This proof uses boot-firmware topology, not `/proc/meminfo`.

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

`PROVED`: Layout-1 writer `0x1484fbbc` first writes
`old_control & 0x3f0` at offset `0x00`, writes the generated six-slot map, places
the active-slot mask in bits `9:4`, then writes `(control & 0x3f0) | 1`. Slot 0
has an implicit zero start and an explicit 36-bit end. Slots 1 through 5 have
explicit 36-bit start/end pairs, each split into low 32 bits and a masked high
nibble. Across a full configuration it touches 32-bit offsets
`0x00, 0x04, ... 0x58` in all four windows.

`PROVED`, bounded to exact function bytes `0x1484fbbc..0x1484fe74`: no distinct
lock-register write occurs there. `UNKNOWN`: a later firmware or hardware lock.

`PROVED`: the remapper input producer copies per-channel rank sizes and source
bases from runtime DDR context offsets `0x158/0x178` and `0x1a8/0x1e8`; a rank
interleave mask is produced into config offset `0xc8`. The retained log proves
rank totals and selected destination bases, but not the per-channel source
bases or mask. Exact boot register words remain
`UNKNOWN_DEPENDS_ON_RUNTIME_DDR_CONTEXT`.

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

`PROVED` by Experiment 008: separate primary TrustZone registry records bind
`BIMC_MPU0..3` to IDs `0x2e,0x2f,0x3f,0x40` and bases
`0x0924e000,0x092ce000,0x0934e000,0x093ce000`. Each is
`qhs_llcc + 0xe000` in the same 64-KiB window whose remapper is at `+0x8080`.
This does not prove that an MPU protects its own configuration aperture.

`PROVED`: none of the five pinned XBL function bodies, nor their first 64 bytes,
occurs byte-identically in exact TZ. `UNKNOWN`: semantic-equivalent secure code
or runtime use of the duplicated DAL record.

## 6. Security consequence boundary

This result materially narrows the pipeline, but it is not an alias or bypass:

```text
XBL topology/rank discovery
  -> DDR remapper table
  -> ICB region records
  -> four qhs_llcc + 0x8080 register windows
  -> exact intended coordinate labels now recovered
  -> additional MCCC/MC/PHY hardware decode still partly UNKNOWN
```

`UNKNOWN`: Post-boot EL1 readability, writability and lock state.

`UNKNOWN`: Whether an XPU/MPU check is before or after this remap.

`UNKNOWN`: Whether changing any field can create two system PAs that reach one
DRAM location.

`REFUTED`: “No concrete SM8150 address-remap register candidate exists.” The
four exact windows are now source-backed candidates. The stronger statement
“the final DRAM hash is mutable from EL1” remains unsupported.

## 7. Successor status and cheapest next measurement

Experiment 007 implemented a purpose-specific map/unmap control and paired
single-load candidate. The control returned; the load returned no value and was
followed by a retained non-secure watchdog. This supplies no register word and
does not identify XPU, clock, power or ownership cause.

Experiment 008 resolved the exact DCB, row and writer semantics and proved the
same-window BIMC MPU configuration bases. Experiments 009/010 then resolved
static coverage and secure initializer authority. Experiment 011 eliminated
the XBL diagnostic formula itself as an alias source and exposed exact
section-16 controller-token sets. Experiment 012 recovered the SHRM consumer,
four-byte token scaling and direct read direction. Experiment 013 then proved
the complete snapshot workspace has no static HLOS grant; its no-load control
passed, while one fixed snapshot load returned no value and watchdog-reset.
Do not repeat that load. The next host-only target is any secure-firmware
consumer that exports the staged buffers through an existing HLOS-readable
diagnostic/shared-memory path.
