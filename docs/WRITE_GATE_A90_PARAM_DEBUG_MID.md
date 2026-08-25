# WRITE GATE — A90 `param` debug level LOW → MID

Date: 2026-08-25

Target: Samsung Galaxy A90 5G `SM-A908N`, Snapdragon 855 / `SM8150`

Build binding: `A908NKSU5EWA3`, native runtime `v2321-usb-clean-identity-rodata`
Operator authorization: the operator explicitly approved both the exact-XBL
gate reconstruction and the subsequent minimal device test in this task.

## Decision

`APPROVED_FOR_ONE_BOUNDED_APPLY_AND_ONE_BOUNDED_RESTORE`

The write is not an unknown DDR, XPU, SMMU, EL2, EL3, bootloader, or firmware
register write. It is a known Samsung `param` field transition whose exact
consumer and offsets have been recovered from the retained A90 XBL and exact
Samsung kernel source.

## Exact target

- `PROVED`: live GPT/sysfs identity is `sda10`, `PARTNAME=param`, major/minor
  `8:10`, 20,480 sectors, 10 MiB, 4096-byte logical blocks.
- `PROVED`: partition-relative record base is `0x900000` from exact
  `CONFIG_SEC_PARAM_SIZE=0xA00000` and
  `SEC_PARAM_FILE_OFFSET=(SEC_PARAM_FILE_SIZE-0x100000)`.
- `PROVED`: target field is the 32-bit little-endian `debuglevel` at partition
  offset `0x900000`.
- `PROVED`: captured value is `0x574f4c44` (`DLOW`, kernel LOW).
- Intended value: `0x44494d44` (`DMID`, kernel MID).
- Exact byte delta: `44 4c 4f 57` → `44 4d 49 44`; only offsets
  `0x900001..0x900003` differ.
- The write command uses a four-byte input, `bs=4`, `count=1`,
  `seek=2359296`, and `conv=notrunc,fsync`. It cannot select another
  partition or offset through the CLI.

## Source provenance

- Exact A90 XBL SHA-256:
  `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.
- Static gate manifest:
  `evidence/manifests/verification-005-xbl-rawdump-gate-static-20260825-01.manifest.json`.
- Exact live capture manifest:
  `evidence/manifests/verification-006-a90-param-capture-20260825-01.manifest.json`.
- Private rollback image SHA-256:
  `1faafee97d08ff93b690dbcffe21d680f20232aa2d3dff5f462b747577bb4345`.
- Expected MID image SHA-256:
  `50e5c715fc72fb72780d251c3f8e2f19191060e7bcd9f7cb68f7d194e762c256`.

## Preconditions

- `PROVED`: device-before, host, and device-after hashes of the 10 MiB
  rollback image all match the original SHA-256 above.
- `PROVED`: `force_upload_flag=0`, `FMM_lock=0`, `dump_sink=0` in that image.
- `PROVED`: live `/proc/cmdline` independently reports LOW, force-upload zero,
  and USB-default sink zero.
- `PROVED`: live `msm_poweroff.download_mode=1`.
- Immediately before apply, the device partition must still hash to the exact
  original value. Otherwise the tool refuses the write.

## Expected effect

- `SUPPORTED`: after a normal reboot XBL should publish
  `androidboot.debug_level=0x494d` while force-upload and dump sink remain zero.
- `PROVED` statically: with FMM unlocked, non-LOW debug sets the XBL
  `vendor_allow` path without requiring `force_upload_flag=5` or a positive
  `TZ_ALLOWS_MEM_DUMP` result.
- The apply itself does not trigger a reset or raw dump. The raw-dump trigger is
  a separate, later effect after post-boot verification and host transport
  readiness.

## Alternative explanations

- Bootloader code could read a mirrored/cached record rather than the observed
  partition bytes; normal-reboot cmdline verification discriminates this.
- A later TZ/Sahara/XPU or transport policy may filter the registered dump
  catalog or `SHRM_MEM.BIN`; this write does not prove exportability.
- A lower layer may normalize MID back to LOW; full readback plus post-reboot
  cmdline distinguishes persistence from consumption.

## Risk

- Brick risk: low but non-zero because `param` is boot-consumed persistent
  storage. XBL/ABL/GPT/RPMB/QFPROM and security firmware are untouched.
- Data-loss risk: bounded to a four-byte write in `param`; an unexpected UFS or
  power failure during the sector update could damage that logical block.
- Security-boundary risk: this only enables an existing diagnostic gate. It
  does not itself read or modify protected memory.
- Operational risk: a later watchdog while MID is active may stop in USB upload
  mode instead of returning automatically; physical Download/Recovery remains
  the fallback.

## Rollback and recovery

1. Normal rollback writes the captured four bytes `DLOW` to the same exact
   offset once, then requires the full partition SHA-256 to equal the retained
   original.
2. The retained private 10 MiB image is the byte-exact recovery authority; it
   is mode `0600` and git-ignored.
3. If the apply result is ambiguous, do not replay. Read the full partition hash
   first and choose apply-state acceptance or a single rollback accordingly.
4. If native init does not return, use the already-established Samsung Download
   or TWRP recovery path; do not modify XBL/ABL.

## Measurements

- Full-partition SHA-256 before and after each bounded transition.
- Exact four-byte payload size and SHA-256.
- A90P1 begin/end receipt for the single `dd` effect.
- Post-reboot `/proc/cmdline`, force-upload, dump sink, dload master, runtime
  identity, and health.
- Final restored full-partition SHA-256 and LOW cmdline after the experiment.

## Why the write is necessary

Read-only evidence now proves the gate formula but cannot prove that this
specific live boot chain consumes the changed record or exposes the raw-dump
transport. MID is the minimum state change: changing force-upload or the dump
sink would add no discriminating value and would increase operational risk.
