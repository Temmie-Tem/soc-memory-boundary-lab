# Verification 023 — the remapper read at DMID

**Status at authoring: `PLANNED / NOT YET EXECUTED`.**  This file is written
before the run so that the expectation below is pre-registered rather than
recalled.  `CLASS C (TRANSFORM ONLY)` / `NOT_ELIGIBLE` at authoring time.

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
