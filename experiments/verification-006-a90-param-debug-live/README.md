# Verification 006–014 — A90 Minimum Debug Gate and Recovery

## Goal

Prove the exact live `param` state, apply only the minimum XBL gate change,
verify that XBL consumes it, trigger one source-backed panic, and restore the
device to its original LOW state without changing force-upload or dump sink.

## Initial byte-exact capture

`PROVED`: live GPT/sysfs bound `param` to `sda10`, `PARTNAME=param`, 10 MiB,
major/minor `8:10`, 20,480 sectors, start sector 125,080 and 4096-byte logical
blocks.

Device-before, host and device-after SHA-256 all equal:

```text
1faafee97d08ff93b690dbcffe21d680f20232aa2d3dff5f462b747577bb4345
```

The ignored mode-0600 rollback image is
`evidence/private/verification-006-a90-param-capture-20260825-01/param--sda10.bin`.
Its exact fields were:

```text
debuglevel        = DLOW
force_upload_flag = 0
FMM_lock          = 0
dump_sink         = 0
```

## Bounded transitions

The transition tool accepts only one exact four-byte write at partition offset
`0x900000` and validates the complete 10-MiB hash before and after. It cannot
select an arbitrary partition or offset.

| Verification | Effect | Full resulting SHA-256 | Result |
|---|---|---|---|
| 007 | `DLOW` → `DMID` | `50e5c715…` | `APPLIED_VERIFIED` |
| 008 | `DMID` → `DLOW` | `1faafee9…` | `RESTORED_VERIFIED` |
| 009 | `DLOW` → `DMID` | `50e5c715…` | `APPLIED_VERIFIED` |
| 013 | `DMID` → `DLOW` | `1faafee9…` | `RESTORED_VERIFIED` |

`PROVED`: only bytes `0x900001..0x900003` changed. Host-derived before/after
images prove `force_upload_flag`, `FMM_lock`, and `dump_sink` stayed zero.

## XBL consumption and trigger

`PROVED`: Verification 010 performed one orderly reboot. A new boot returned
with `androidboot.debug_level=0x494d` (MID), force-upload zero, dump-sink zero,
dload master one, and native selftest `fail=0`. This also confirms the static
outer-gate result: orderly MID boot returned normally rather than entering
rawdump.

`PROVED`: Verification 011 dispatched exactly one source-backed
`writefile /proc/sysrq-trigger c` effect after the collector was ready. It was
not retried. The A90 disconnected and enumerated as Samsung Upload.

## Transport correction

The initial collector was the pinned linux-msm `qdl v2.8`, filtered to one
name, `SHRM_MEM.BIN`. It waited only for Qualcomm USB `05c6` and captured no
file.

`REFUTED`: the exact crash-dump transport on this boot is Qualcomm Sahara
`05c6`.

Host kernel journal instead proves `04e8:685d`, product `MSM_UPLOAD`,
manufacturer Samsung. Verification 012 used that protocol and is documented
separately.

## Final state

`PROVED`: after collection, the device returned as native `04e8:6861`. The
complete `param` hash was restored to the original LOW image. Verification 014
then performed one normal reboot and proved:

```text
debug_level  = 0x4f4c (LOW)
force_upload = 0
dump_sink    = 0
download_mode = 1
selftest fail = 0
```

No XBL, ABL, TZ, hyp, devcfg, AOP, GPT, RPMB, QFPROM, controller, XPU, SMMU,
EL2, EL3, or protected-memory write occurred.

## Reproduce host validation

```sh
python3 -m unittest \
  tests.test_a90_param_capture \
  tests.test_a90_param_debug_transition \
  tests.test_a90_native_reboot_observe \
  tests.test_a90_sysrq_crash_once \
  tests.test_a90_shrm_ramdump_collect -v
```
