# Verification 002 — SHRM Snapshot Dump Export

## Question

After the fixed EL1 read of the protected SHRM snapshot workspace was blocked,
does the exact firmware contain another consumer that can carry the staged
controller words out of SHRM memory?

This verification separates two questions that must not be collapsed:

1. does *any* exact firmware export path cover the snapshot buffers; and
2. is there a normal-boot HLOS-readable runtime interface?

The first is now `PROVED` for an XBL crash/download raw-dump catalog. The second
remains `UNKNOWN`.

## Scope and exact input

- Exact A90 XBL: 4,194,304 bytes,
  SHA-256 `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`
- Embedded Xtensa SHRM image: 23,776 bytes,
  SHA-256 `421824b417ab28e6c0d1802c05d7ce5422e93b116973ce7f039321fb5a01a1fd`
- Public structural evidence:
  `evidence/manifests/verification-002-shrm-dump-export-20260825-01.manifest.json`
- Mode: `HOST_ONLY_READ_ONLY`
- Device, SMC, MMIO, EL2/EL3 runtime and protected-memory access: none

The analysis tool parses ELF mappings itself, discovers the descriptor from
its exact strings and fields, validates code-range hashes, and decodes only the
needed AArch64 `ADRP`/`ADD`/`CMP`/`BL` and Xtensa `L32R`/`CALL0` instructions.
The temporary full disassembly used during reconnaissance is not an input to
the generated manifest.

## 1. Bounded Xtensa consumer result

`PROVED`: the complete SHRM instruction blob contains exactly one direct
little-endian `0x25100` workspace-base literal, at local `0x2819c`.

Two coherent function streams load it into `a4` and call the common helper:

| Set | Function entry | `L32R` | direction | `CALL0` | destination |
|---|---:|---:|---:|---:|---:|
| 0 | `0x287f4` | `0x288a9` → `[0x2819c] = 0x25100` | `a2=0` at `0x288af` | `0x288c4` → `0x2d8dc` | local `0x25330`, physical `0x09065330` |
| 1 | `0x28dbc` | `0x28e15` → `[0x2819c] = 0x25100` | `a2=0` at `0x28e1b` | `0x28e30` → `0x2d8dc` | local `0x259e8`, physical `0x090659e8` |

The blob has no direct 32-bit literal for `0x25330`, `0x259e8`,
`0x09065330`, or `0x090659e8`.

`REFUTED`, narrowly: the exact embedded SHRM code contains a direct/literal
HLOS mailbox consumer for either derived destination.

`UNKNOWN`: a dynamically derived pointer, an external processor, or a
bootloader dump consumer is not excluded by that negative. The negative is
therefore not promoted to “no export exists.”

## 2. Exact XBL raw-dump descriptor

`PROVED`: XBL contains this 32-byte record at VA `0x14961990`, file offset
`0x33e960`:

```text
u64 physical_base       = 0x09060000
u64 size                = 0x00010000
u64 description_pointer -> "SHRM MEM region"
u64 filename_pointer    -> "SHRM_MEM.BIN"
```

The record is index 19 in a 26-record table beginning at `0x14961730` with
stride `0x20`. The complete table is pinned by SHA-256
`5f075f4850460326b5e7ef08f43cbddcf4f5b88835bed9ab2908e18eee01a641`.

The descriptor covers `0x09060000..0x0906ffff`, which contains:

- the complete section-16 workspace `0x09065100..0x09065fff`;
- set-0 snapshot start `0x09065330`; and
- set-1 snapshot start `0x090659e8`.

This directly refutes the statement that no exact firmware export path covers
the protected workspace.

## 3. The table is consumed, not orphaned data

The primary loop at `0x14917ca8..0x14917cf4` is pinned by SHA-256
`b7e02af33970d81ed6a38c643f96141ae88ad478efc53900317f4465f2138857`.
Its exact instruction sequence:

1. resolves table base `0x14961730` with `ADRP x9` plus `ADD #0x730`;
2. compares the index with `0x1a`;
3. loads `{physical_base,size}` into `x1,x2`;
4. loads `{description,filename}` into `x3,x4`;
5. advances by `0x20`; and
6. calls the region registrar at `0x14917670` with `w0=1`.

The pinned static call chain is:

```text
0x14902cc4 BL 0x14917740
                   |
0x1491777c BL 0x14917c60
                   |
0x14917cdc BL 0x14917670   (once per table record)
```

The same exact module contains `boot_raw_partition_ramdump.c`, `RawDump
successfully, Reset the device`, and explicit FMM/debug-level/ramdump-policy
gate strings.

`SUPPORTED`: this is a bootloader crash/download raw-dump catalog. It is not
evidence of an ordinary Android EL1/HLOS runtime API.

## 4. Mounted SD-card check

At verification time, host read-only enumeration showed removable
`/dev/sda1`, label `ANDROIDLABSD`, mounted at `/mnt/android-lab-sd`.

`PROVED`, bounded to the mounted filesystem at that time:

- no file named `SHRM_MEM.BIN`;
- no file named `rawdump.bin`;
- no exact Experiment-004 A90 partition filename (`xbl--sdb1.bin`,
  `xbl_config--sdb2.bin`, or `tz--sdd5.bin`); and
- the only `*A908*` path is the Samsung open-source kernel archive/directory.

Therefore the exact A90 boot-firmware bytes used here were not sourced from
the mounted SD card; they are the private Experiment-004 live partition
captures in this repository. The SD card does contain unrelated S22+ firmware
and tools, which are out of scope. This scan does not inspect archive contents
or prove that no differently named historical dump exists.

## Classification

```text
BOOTLOADER_RAWDUMP_EXPORT_PRESENT_HLOS_RUNTIME_EXPORT_UNPROVED
```

### PROVED

- A consumed exact XBL raw-dump descriptor covers both SHRM snapshots.
- The descriptor is index 19 of the exact 26-record primary table.
- The XBL consumer and its call chain are instruction-pinned.
- The Xtensa blob has two direction-zero snapshot producers and no direct
  destination literal consumer.

### SUPPORTED

- `SHRM_MEM.BIN` is a post-reset bootloader diagnostic route, not normal HLOS.
- If retail gates permit it and SHRM is populated at collection time, it is safer and more
  informative than retrying the denied EL1 load.

### HYPOTHESIS

- A successful dump may contain the 430/64 controller words populated by
  collection time. Prior-boot preservation is not required.

### REFUTED

- No exact firmware export path covers the protected SHRM workspace.
- The exact SHRM blob directly exports either destination through a literal
  HLOS mailbox path.

### UNKNOWN

- Current A90 FMM/debug-level/token eligibility.
- Whether the workspace is populated when XBL collects it. Stale or zero words
  are themselves measurable outcomes.
- The exact transport and whether a collection produces `SHRM_MEM.BIN` on this
  retail target.
- Any normal-boot HLOS-readable export of the same data.
- Controller-word values, lock state, and final-decode semantics.

## Prepared host decoder

Commit `9fdd5d6` added `tools/shrm_dump_decode.py`. With no dump it emits the
ordered register plan from the committed Experiment-012 manifest; with a dump
it validates the exact 64-KiB size and section-16 header before attaching
values to all `430 + 64 = 494` source-register labels. It rejects a zero-filled
file instead of misreporting 494 zero values.

`PROVED`: the decoder's staged inventory does not include any remapper control
window at `qhs_llcc + 0x8080`; it therefore cannot answer remapper enable,
active-slot, or lock-state questions. No real `SHRM_MEM.BIN` has been supplied,
so all controller values remain `UNKNOWN`.

## Next discriminator

Verifications 003/004 completed the read-only eligibility inventory and found
`debug_level=LOW`, `force_upload=0`, and dload master `1`; visible entry signals
are incomplete and actual FMM/token eligibility remains `UNKNOWN`. The cheapest
next action is host-only recovery of those producers and their reversible
control path. It should not repeat the blocked EL1 load or trigger a reset from
the current state. The eventual discriminator is collection-time population,
not the stronger requirement that a prior boot's bytes survive reset.

## Reproduce

```sh
python3 tools/sm8150_shrm_dump_export_inventory.py
python3 tools/sm8150_shrm_dump_export_inventory.py --replace
python3 -m unittest tests.test_sm8150_shrm_dump_export_inventory -v
python3 tools/shrm_dump_decode.py
python3 -m unittest tests.test_shrm_dump_decode -v
```
