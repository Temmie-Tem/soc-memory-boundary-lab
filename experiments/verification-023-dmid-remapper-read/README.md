# Verification 023 — the remapper read at DMID

**Status: `EXECUTED 2026-08-27` — `REFUSED_AT_MID`, the pre-registered
expectation.**  The plan below was written and committed (`e7f3236`) before the
run so that the expectation was pre-registered rather than recalled.  The result
section at the end records what happened.  `CLASS C (TRANSFORM ONLY)` /
`NOT_ELIGIBLE` unchanged.

## The question

CVE-2020-11252 (Qualcomm bulletin, April 2021) describes "improper access
restrictions during trustzone initialization, as **xPU get disabled when memory
dumps are enabled**".  Every remapper access this project has attempted was made
with `androidboot.debug_level=0x4f4c` (LOW) — memory dumps disabled.  The one
condition the disclosed record says matters has never been tested here.

Does the fixed EL1 read at `0x09248080` behave differently at **MID**?

## Why this costs two boot flashes

`/dev/mem` is absent (`CONFIG_DEVMEM=n`) and the Experiment 005 control-node
route returned `ENXIO`.  The only proven EL1 read path to that address is the
Experiment 007 inline candidate, hooked at the boot-proven stock-kernel site.
It must be flashed to `boot` and rolled back.

## Sequence

1. `param` `DLOW → MID` — one four-byte write at offset `0x900000`, full 10 MiB
   hash verified before and after.  Reboot; confirm `0x494d` on the cmdline.
2. TWRP; flash the read candidate `6fe92825…`; reboot.  The candidate performs
   exactly `__ioremap(0x09248080, 0x5c, …)` → one 32-bit load → unmap.
3. Observe.  Collect `/proc/last_kmsg` if the device returns.
4. TWRP; flash the V2321 rollback `ca978551…`; reboot.
5. `param` `MID → LOW`; reboot; verify `0x4f4c`, `force_upload=0`,
   `dump_sink=0`, self-test `fail=0`.

The same-session DLOW baseline bark is deliberately **not** run first.  The
outcome is categorical — the watchdog barks, or a value is returned — so a
matched control is only needed in the branch where a value appears.  In that
branch the DLOW control is run before anything is concluded.

## The expectation, pre-registered

This build is `A908NKSU5EWA3`, kernel built 2023-01-12, roughly 21 months after
the April 2021 bulletin.  **The expected result is that it is patched and the
read barks again.**

- **Barks again** → XPU still enforces with memory dumps enabled.  Route 2
  closes on a measurement of the one untested condition instead of on an
  inference, and CVE-2020-11252 is shown patched on this build.
- **Returns a value** → XPU was disabled by a configuration reachable without an
  exploit.  That is P2 and a security-boundary-bypass indicator: stop
  immediately, collect only minimum reproducibility, root-cause and
  affected-range evidence, and switch to `POTENTIAL_SECURITY_BOUNDARY_BYPASS`
  disclosure mode.  No broad exploration follows a positive.

## Recovery assets verified before the run

| Asset | Bytes | SHA-256 |
|---|---:|---|
| `param` rollback (DLOW) | 10,485,760 | `1faafee97d08ff93b690dbcffe21d680f20232aa2d3dff5f462b747577bb4345` |
| V2321 `boot` rollback | 60,882,944 | `ca978551aabe4b39563abaf529ccf2522054952d8b2ad852e632d26da88168cb` |
| read candidate (rebuilt) | 60,882,944 | `6fe92825702f304a067fc716c3814a63b2f4e76198a054de4c666cad55a462ed` |

Device preflight at authoring: exact V2321 `SM-A908N`, `debug_level=0x4f4c`,
`force_upload=0x0`, `dump_sink=0x0`, uptime 62,351 s continuous.  33 focused
host tests pass.

## Known risk

Verification 006 proved that at MID a panic enumerates as Samsung Upload
(`04e8:685d`, `MSM_UPLOAD`) rather than warm-resetting.  At DLOW the Experiment
007 read barked and recovered on its own; at MID the same bark may enter upload
mode, which needs physical cable/button recovery.  The operator accepted this
before the run.

No `xbl`, `xbl_config`, `tz`, `hyp`, `devcfg`, `aop`, `abl`, GPT, RPMB, QFPROM,
XPU, SMMU, EL2, EL3 or protected-memory write is part of this sequence.

---

# Result — `REFUSED_AT_MID`

## Two changes to the plan, both forced by the target

**The probe address changed.**  No tool in this repository flashes the
Experiment 007 inline *remapper* candidate; `tools/a90_twrp_shrm_boot_flash.py`
flashes the Experiment 013 inline *SHRM* candidates.  The SHRM read at
`0x0906566c` (MCCC source register `0x09250118`) tests the same hypothesis and
is better instrumented: it has a pinned flash path, a paired no-load control
that returned the `0xc071` sentinel, and an explicit TZ error code in its
retained log rather than a bare bark.  It was used instead.

**The step order had to be inverted.**  The first attempt applied MID, rebooted
into MID, then entered TWRP to flash — and the candidate booted at **LOW**.  A
full `param` capture showed the partition back at `1faafee9…`/`DLOW`.

`PROVED`: a TWRP round trip resets `param.debuglevel` to `DLOW`.  This is a
standing constraint on any future experiment that needs both a flashed boot
image and a non-default debug level.  The repair is to flash first, then apply
the transition, then reboot without re-entering recovery.

## What the device recorded

The retained receipt is
`evidence/private/verification-023-last-kmsg-at-mid-20260827-01.last_kmsg.bin`,
2,097,136 bytes, SHA-256
`fdceab48dc267dd74ec6c70edbec6b51ee13dcd8532cf8b121c4fe93b425c66e`.

```text
DebugLevel : 1145654596
Watchdog bark! Now = 69.080467
Watchdog last pet at 58.080193
UploadCause[Non Secure Watchdog Bark], Don't check hangcnt
collect_rr_data : upload_cause = Non Secure Watchdog Bark
collect_rr_data : TZ OEM_RESET_REASON :: TZBSP_ERR_FATAL_NON_SECURE_WDT
```

`1145654596` is little-endian `DMID`.  The bootloader's own crash record states
the boot was at MID; the debug level is not asserted by this project's
narration.  The probe manifest records `value: null` and the device enumerated
as Samsung Upload `04e8:685d`, exactly as Verification 006 predicted for MID.

| | Experiment 013, at `DLOW` | Verification 023, at `DMID` |
|---|---|---|
| returned value | none | none |
| upload cause | `Non Secure Watchdog Bark` | same |
| TZ reset reason | `TZBSP_ERR_FATAL_NON_SECURE_WDT` | same |
| bark − last pet | 11.000279 s | 11.000274 s |

## Disposition

`PROVED` within this build and this one fixed load: the protected read is
refused with memory dumps enabled exactly as it is with them disabled.  The
watchdog path, the upload cause and the TZ reset reason are identical and the
timeout delta agrees to five microseconds.

`SUPPORTED`: CVE-2020-11252 does not apply to `A908NKSU5EWA3` — either patched
or never applicable to SM8150.  This is now a measurement of the one untested
condition rather than an inference from measurements taken only at `DLOW`.

`UNKNOWN`: whether other debug levels, dump sinks, or force-upload states behave
differently; whether any other aperture behaves differently at MID; the runtime
XPU register state; transform mutability; aliasing; and any bypass.  One load at
one address in one configuration is what was measured.

No security-boundary-bypass indicator appeared, so the stop condition did not
fire.  `CLASS C (TRANSFORM ONLY)` and `NOT_ELIGIBLE` are unchanged.

## Restoration, verified

| Asset | Final state |
|---|---|
| `param`, complete 10 MiB | `1faafee9…` — byte-identical to the pinned rollback |
| gate fields | `LOW` / `force_upload=0` / `FMM_lock=0` / `dump_sink=USB_DEFAULT` |
| `boot`, 60,882,944 B | `ca978551…` — V2321, readback verified |
| native self-test | `pass=11 warn=1 fail=0 entries=12` |
| device temporary files | `native-init.log` only |

Two `param` writes and two `boot` writes occurred, each verified by a complete
partition hash before and after.  No `xbl`, `xbl_config`, `tz`, `hyp`,
`devcfg`, `aop`, `abl`, GPT, RPMB, QFPROM, XPU, SMMU, EL2, EL3 or
protected-memory write occurred.  One recovery from Samsung Upload required a
physical power-button press, which the operator performed.
