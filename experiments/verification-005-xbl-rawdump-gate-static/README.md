# Verification 005 — Exact XBL Rawdump Gate

## Question

Which exact conditions cause the retained A90 XBL to enter its raw-dump app,
admit the Samsung vendor memory-dump path, and register `SHRM_MEM.BIN`?

This verification was completed before changing the live `param` partition.
It is host-only static analysis of exact firmware and exact Samsung kernel
source.

## Exact inputs

- A90 XBL: 4,194,304 bytes, SHA-256
  `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`
- Bootloader/build: `A908NKSU5EWA3`
- Exact Samsung `sec_param` and panic/download-mode source, individually
  hashed in the public manifest
- Public result:
  `evidence/manifests/verification-005-xbl-rawdump-gate-static-20260825-01.manifest.json`

## Two gates, not one

`PROVED`: main XBL selects XBLRamDump only when either saved dload-cookie bits
4/5 are present or restart reason is `0x776655ee`. The saved bits are read from
`0x01fd3000` and consumed/cleared. Therefore a normal reboot with MID alone is
not expected to enter rawdump.

`PROVED`: once XBLRamDump is entered, its inner admission formula is:

```text
not FMM_locked
and not QUEST_DDR_special
and (
    debug != LOW
    or force_upload_flag == 5
    or three_key_override
    or TZ_ALLOWS_MEM_DUMP
)
```

The exact fields are in one Samsung `param` record:

| Field | Record offset | Exact relevant value |
|---|---:|---:|
| `debuglevel` | `0x000` | `DLOW` / `DMID` |
| `force_upload_flag` | `0x3f4` | enable is integer `5` |
| `FMM_lock` | `0x3fc` | deny magic `0x464d4f4e` |
| `dump_sink` | `0x400` | zero follows USB-default branch |

`PROVED`: when FMM is unlocked, `debug != LOW` admits the vendor path even
when force-upload is zero and `TZ_ALLOWS_MEM_DUMP` denies. Force-upload was
therefore unnecessary for the minimum experiment.

`PROVED`: full-catalog registration additionally requires saved cookie bit 4
or restart reason `0x776655ee`. The exact Samsung watchdog/panic source supplies
both full-dump dload type `0x10` and `SEC_DEBUG_MODE`, while the live dload
master remains enabled.

## Classification

```text
DEBUG_ONLY_SUFFICIENT_WHEN_OUTER_DUMP_TRIGGER_PRESENT
```

### PROVED

- MID alone satisfies the inner vendor gate when FMM is unlocked.
- MID alone does not satisfy main XBL's outer dump trigger.
- Force-upload and a positive TZ result are alternatives, not joint
  requirements, once MID supplies vendor admission.
- Rawdump record 19 is registered on the full-catalog path.

### REFUTED

- Both MID and force-upload must be set.
- An unknown positive “FMM cookie” must be invented; FMM is an exact deny lock.
- A normal orderly MID reboot should itself enter rawdump.

### UNKNOWN at this verification

- Live `param` field values.
- Exact retail USB protocol and selective-file behavior.
- Whether SHRM is populated when the bootloader exports it.

These three historical unknowns were subsequently resolved by Verifications
006 and 012; they are not current project unknowns.

## Reproduce

```sh
python3 tools/xbl_rawdump_gate_inventory.py
python3 -m unittest tests.test_xbl_rawdump_gate_inventory -v
```
