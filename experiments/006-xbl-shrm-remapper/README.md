# Experiment 006 — XBL/SHRM/ICB Remapper Reconstruction

Result: `PROVED` for the static call path and exact register windows;
`UNKNOWN` for runtime access, final DRAM hashing and any alias.

Exact live XBL and XBL-config bytes from Experiment 004 were analyzed host-only.
The reproducible tool:

```sh
python3 tools/xbl_memory_pipeline_inventory.py
```

parses the `CFGL` DCB names, validates DCB structure, hashes DCB section 16 and
the embedded SHRM blobs, decodes the 13-entry DDR remapper table, follows the
DAL `icbcfg_info` structure pointer, and emits only redistributable structural
metadata to:

```text
evidence/manifests/006-xbl-memory-pipeline-inventory.json
```

The key result is a four-instance, six-slot layout-1 remapper at:

```text
0x09248080, 0x092c8080, 0x09348080, 0x093c8080
```

Each is `qhs_llcc + 0x8080`; exact XBL touches 32-bit offsets through `+0x58`.
The separate exact TrustZone ELF contains the same `/dev/icbcfg/boot` identity,
six-slot layout and four register bases. This proves cross-world configuration
knowledge, not that secure-world runtime writes or locks them.
No device command or write was issued during the static phase.

The later live capture proved the A90 was connected; its ACM node was hidden
only inside the Codex sandbox. Live platform is `MTP`, supporting the `_1` DCB
variant. Linux SMEM `raw_id=165/raw_version=3` does not match any exact CFGL
selector, refuting that shortcut for choosing `0100` versus `0200`.

The next read-only tool is also prepared:

```sh
python3 tools/a90_icb_remapper_snapshot.py \
  --experiment-id 005-icb-remapper-control-<timestamp>
```

It accepts no address and defaults to four control-word reads. Only an explicit
`--full` expands to the exact 23 layout words per instance. Experiment 005 then
proved the current kernel has `CONFIG_DEVMEM=n`; a kernel-space adapter is now
required before actual register visibility can be tested.
