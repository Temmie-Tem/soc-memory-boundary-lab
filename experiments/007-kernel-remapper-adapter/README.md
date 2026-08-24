# Experiment 007 — Kernel Remapper Read Adapter

State: `REFUTED GENERIC REPL ADAPTER / FIXED READ WATCHDOG, NO VALUE`.

## Question

Can post-boot EL1 map and read the first word of the four exact XBL-programmed
qhs_llcc remapper windows without changing controller state?

## Effective live attempt

The exact historical REPL candidate and regenerated System.map were verified,
then a fresh warm boot executed only:

```text
slide
__ioremap(0x09248080, 0x5c, 0x0068000000000707)
```

Retained `/proc/last_kmsg` proves the slide result and `__ioremap` return were
emitted. A `Non Secure Watchdog Bark` followed 3.027327 seconds after the map
return. `msm_readl` was never invoked, no register value was captured, and no
MMIO write was requested.

The existing call-safety classifier labels `__ioremap`, `__iounmap`, and
`msm_readl` `DENY`. The experiment wrapper had verified symbol identity and
JOPP prefixes but bypassed that classifier through the low-level session API.
That live path is now disabled without an override.

## Claim boundary

`PROVED`: the generic REPL callback-context mapping attempt is not a safe
adapter on this target and boot. That first watchdog is not evidence of an XPU
rejection because its intended bus read never occurred.

## Recovery

TWRP restored the V2321 boot image. Its exact 60,882,944-byte prefix readback
has SHA-256:

```text
ca978551aabe4b39563abaf529ccf2522054952d8b2ad852e632d26da88168cb
```

## Evidence

- Public result:
  `evidence/manifests/007-kernel-remapper-watchdog-20260825-01.manifest.json`
- Per-attempt public manifests:
  `evidence/manifests/007-kernel-remapper-control-repl-20260825-{01,02,03,04}.manifest.json`
- Raw REPL, retained-log, candidate, map, flash, and rollback evidence remains
  private and Git-ignored.

## Fixed inline comparison

A purpose-specific inline successor is now host-built at the already
boot-proven stock-kernel hook site. Both variants have no generic target or
arbitrary address and unmap before publishing a result:

- control `dbbf81f2…`: fixed map → immediate unmap → `0xc071`, no MMIO load;
- read `6fe92825…`: fixed map → one 32-bit load → immediate unmap → result.

Each candidate and 212-byte body reproduced byte-identically three times. The
control ran once and returned `0xc071` with healthy post-state. The read then
ran once, returned no value, disconnected USB/ACM, and retained a
`Non Secure Watchdog Bark` at 69.080426 s after the last watchdog pet at
58.080136 s. V2321 was restored and passed final health.

`PROVED`: the paired outcomes and retained reset evidence. `SUPPORTED`: the
single fixed load, rather than mapping alone, triggered the stall. `UNKNOWN`:
whether the cause is secure access control, missing power/clock state, an
incorrect runtime base, or another interconnect condition. Do not repeat the
same live load without a new discriminating hypothesis.

Evidence:

- `evidence/manifests/007-inline-remapper-candidates-20260825-01.manifest.json`
- `evidence/manifests/007-inline-remapper-control-live-20260825-01.manifest.json`
- `evidence/manifests/007-inline-remapper-read-live-20260825-01.manifest.json`
- `evidence/manifests/007-inline-remapper-read-watchdog-20260825-01.manifest.json`
- `evidence/manifests/007-inline-remapper-read-rollback-health-20260825-01.manifest.json`

The code-only TWRP System transition is implemented in
`tools/a90_twrp_system_boot.py`; it invokes the GUI main-loop exit variables,
not touch coordinates or the crashing `twrp reboot` command.
