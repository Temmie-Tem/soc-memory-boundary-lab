# Verification 020M - PA28 DT precondition snapshot

This is the read-only precondition step for the next normal-RAM PA28 test.  It
binds the measured ION heap 30 (`camera_preview`) to the live device-tree node
`camera_mem_region`: both use phandle `0x67a`, whose `reg` is base
`0xc2000000`, size `0x14000000` (320 MiB).  `no-map` and `reusable` are queried
explicitly and retained as `ENOENT`; `ion,recyclable` is present.

The collector performs no allocation and no write.  It validates the exact
A90/SM8150 runtime and reads only a fixed list of version, cmdline and DT
paths.  The raw receipt is private; the public manifest is redacted to hashes
and decoded cells.  The current bridge process is recorded with its explicit
device path and whether strict realpath/glob options were present.

`PROVED`: the observed live DT advertisement and heap-30/phandle chain in the
retained receipt.  `SUPPORTED`: consistency with a fixed 320 MiB carveout.
`UNKNOWN`: actual allocation placement, physical page identity, complete DRAM
coordinates, `f(PA28)`, mutability and protection/bypass behavior.  Class C
and `NOT_ELIGIBLE` remain unchanged.

Reproduce with:

```sh
python3 tools/a90_pa28_dt_snapshot.py \
  --experiment-id verification-020M-pa28-dt-20260827-01
```

The command requires the already-bound A90 ACM bridge and writes a new private
receipt plus public manifest; it never overwrites an existing artifact.
