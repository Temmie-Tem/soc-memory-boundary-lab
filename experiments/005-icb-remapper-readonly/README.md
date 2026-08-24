# Experiment 005 — Live ICB Remapper Read-Only Snapshot

State: `REFUTED DIRECT /dev/mem ROUTE / MMIO READ STILL UNKNOWN`.

Question: are the four XBL-programmed qhs_llcc remapper windows still readable
from the A90's post-boot EL1 environment?

Static provenance is `PROVED` by Experiment 006. The exact bases are:

```text
0x09248080
0x092c8080
0x09348080
0x093c8080
```

## Live result

`PROVED`: The A90 was connected throughout. Host sysfs identified its dedicated
ACM interface as `04e8:6861` / `A90-LNX`; the apparent absence came from the
Codex sandbox omitting host `/dev` nodes. A host-side, exact-by-id loopback
bridge restored access without touching the other Samsung ACM interface.

The first control smoke stopped after one attempted word:

```text
devmem: /dev/mem: No such file or directory
```

No MMIO access occurred. A second bounded run created
`/dev/sdm855_mblab_mem` as character device `1:1`, invoked Toybox with
`-f /dev/sdm855_mblab_mem`, and again stopped after the first word:

```text
devmem: /dev/sdm855_mblab_mem: No such device or address
```

The temporary node's pre-clean, creation, cleanup, and post-clean absence check
all returned `ok`. Runtime identity was unchanged and final selftest was
`pass=11 warn=1 fail=0`.

`PROVED`: A subsequent exact live `/proc/config.gz` capture contains
`# CONFIG_DEVMEM is not set`. Exact board defconfig independently has the same
line. This explains the `1:1` open returning `ENXIO`.

`REFUTED`: The current kernel's userland `/dev/mem` route can observe these
registers. `UNKNOWN`: Whether a narrow kernel-space `ioremap/readl` adapter can
read them, whether an XPU blocks the access, and what boot values they contain.

## Collector contract

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

The tool accepts no physical address. It materializes only a fixed temporary
mem character node and removes it in an unconditional cleanup path. `--full`
expands only to the 23 proved four-byte offsets from `+0x00` through `+0x58`,
for 92 reads total. It supplies Toybox `devmem` with address and 4-byte width but
no data argument, so no MMIO write is requested. The width syntax is confirmed by the
[Android Toybox primary source](https://android.googlesource.com/platform/external/toybox/+/0ff3e35973830ae6b34324c350573c5938dcd117/toys/other/devmem.c).
There is no retry.

Success proves only post-boot read visibility and boot values. A read failure
can mean `/dev/mem` policy, missing Toybox support, XPU denial, unmapped access,
or a locked/powered-off block; it does not by itself prove immutability.

The full 92-word run is not eligible through this route because the kernel lacks
the `/dev/mem` backend. The next implementation target is a kernel-space helper
that maps only the four proved `0x5c`-byte windows and exposes read-only values.
