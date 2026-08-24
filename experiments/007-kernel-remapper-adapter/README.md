# Experiment 007 — Kernel Remapper Read Adapter

State: `REFUTED GENERIC REPL ADAPTER / PURPOSE-BUILT ADAPTER UNKNOWN`.

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
adapter on this target and boot. `UNKNOWN`: whether the physical range itself
is readable from a purpose-built kernel worker. The watchdog is not evidence of
an XPU rejection because the bus read never occurred.

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

## Next experiment

A purpose-specific inline successor is now host-built at the already
boot-proven stock-kernel hook site. Both variants have no generic target or
arbitrary address and unmap before publishing a result:

- control `dbbf81f2…`: fixed map → immediate unmap → `0xc071`, no MMIO load;
- read `6fe92825…`: fixed map → one 32-bit load → immediate unmap → result.

Each candidate and 212-byte body reproduced byte-identically three times. The
control must pass one live invocation before the read image becomes eligible.
See
`evidence/manifests/007-inline-remapper-candidates-20260825-01.manifest.json`.
