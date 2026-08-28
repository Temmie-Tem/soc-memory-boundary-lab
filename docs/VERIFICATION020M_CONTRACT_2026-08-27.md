# Verification 020M contract - PA28 DT precondition snapshot

Before any PA28 timing/alias experiment, capture only the exact read-only DT
chain that binds ION heap 30 to `camera_mem_region`.  The fixed allowlist is
version, `/proc/cmdline`, the heap-30 directory, heap-30 `reg`, `memory-region`
and `name`, and the reserved-memory node's `reg`, `phandle`, `name`,
`ion,recyclable`, `no-map` and `reusable` properties.  Missing `no-map` and
`reusable` must be explicit `ENOENT` observations.  No ION allocation, mapping,
normal-RAM marker, MMIO, SMC, controller, firmware or protected-memory action
is permitted.

The target must match the exact A90 V2321 identity (`SM-A908N`, `SM8150`,
kernel `4.14.190-25818860-abA908NKSU5EWA3`, and the pinned cmdline tokens).
The existing loopback bridge is bound to `/dev/ttyACM0` and its A90 by-id
symlink; the process pin mode is recorded, not silently upgraded.  Host output
is written with `O_EXCL`/`O_NOFOLLOW`; the raw receipt is private and the public
manifest contains hashes and decoded DT semantics only.

This experiment can prove only advertised DT values and the heap-30/phandle
relationship.  Whether a 320 MiB allocation consumes the whole carveout,
physical-page identity, DRAM-coordinate behavior, `f(PA28)`, transform
mutability, protection ordering and any boundary bypass remain `UNKNOWN` until
a separate normal-RAM experiment.
