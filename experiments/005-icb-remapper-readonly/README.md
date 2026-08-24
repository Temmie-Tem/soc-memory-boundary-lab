# Experiment 005 — Live ICB Remapper Read-Only Snapshot

State: `READY / NOT RUN`.

Question: are the four XBL-programmed qhs_llcc remapper windows still readable
from the A90's post-boot EL1 environment?

Static provenance is `PROVED` by Experiment 006. The exact bases are:

```text
0x09248080
0x092c8080
0x09348080
0x093c8080
```

The default smoke reads only one 32-bit control word per instance:

```sh
python3 tools/a90_icb_remapper_snapshot.py \
  --experiment-id 005-icb-remapper-control-<timestamp>
```

If all four reads return and runtime identity remains unchanged, the full
layout read is:

```sh
python3 tools/a90_icb_remapper_snapshot.py \
  --experiment-id 005-icb-remapper-full-<timestamp> \
  --full
```

The tool accepts no physical address. `--full` expands only to the 23 proved
four-byte offsets from `+0x00` through `+0x58`, for 92 reads total. It supplies
Toybox `devmem` with address and 4-byte width but no data argument, so no MMIO
write is requested. The width syntax is confirmed by the
[Android Toybox primary source](https://android.googlesource.com/platform/external/toybox/+/0ff3e35973830ae6b34324c350573c5938dcd117/toys/other/devmem.c).
There is no retry.

Success proves only post-boot read visibility and boot values. A read failure
can mean `/dev/mem` policy, missing Toybox support, XPU denial, unmapped access,
or a locked/powered-off block; it does not by itself prove immutability.

Precondition still pending: exact A90 ACM endpoint reappears and is pinned to a
loopback bridge. It was absent during the 2026-08-25 host preparation.
