# Research Log

## 2026-08-25 — Phase 0/1 reconnaissance

1. `PROVED`: Read the existing project `AGENTS.md`, A90 target/goal contracts,
   and the six requested reports. The old repository was not modified. Its
   currently observed HEAD was `510d909eff0fe10e48f3bfff573bc17f59f0656a`;
   exact private artifacts are additionally bound by SHA-256 because they are
   not assumed to be tracked by that commit.
2. `PROVED`: Initialized this repository on local branch `main`; it has no Git
   remote, and raw evidence/device identifiers/firmware patterns are ignored.
3. `PROVED`: Revalidated RKP/UH/KDP config, exact `rkp_init()` callsite,
   `uh_call -> smc #0`, secure-buffer/SCM physical-range assignment, exact
   rebuild symbols and independently extracted stock symbols.
4. `REFUTED`: “The A90 self-built kernel disabled all RKP.” Only treating
   CFP/JOPP/ROPP as separately discussed is insufficient; all named RKP paths
   are enabled in the exact defconfig.
5. `PROVED`: Read AMD primary repository and pinned observed `main` to
   `6363c2e9721eae82e93ff2e6035e01ee6b01c463`; recorded its Family 16h
   registers, critical section and GF(2) solver without importing those
   implementation details into Qualcomm.
6. `PROVED`: Reconstructed source-visible SM8150 LLCC, LLCC-to-EBI, DDRSS CNOC,
   bandwidth monitor and AOP paths. No SM8150-specific Linux source found that
   programs CPU-PA to channel/rank/bank/row/column mapping.
7. `SUPPORTED`: Final mapping initialization is outside the inspected Linux
   source. This is not `PROVED` until the exact XBL/AOP/DDR firmware artifact and
   write call graph are acquired.
8. `REFUTED`: `mc_virt-base 0x09680000` is automatically the final memory
   controller MMIO base. The provider is virtual/bypass and upstream describes
   the range as unused/arbitrary for that driver.
9. Implemented dependency-free GF(2) tools and a binary-safe read-only A90
   snapshot collector. Ten unit tests passed. Collector SHA-256 at capture time:
   `e05fd1667c23888be743123f6b3791fbec8cbac24adcb4e296bc6b495f672084`.
   The committed EOF-normalized file is
   `aa6eaf9f2595dddb7e79ee4b6627dacdf95768a51ea3b2ca7b94475881f632b5`;
   the only byte difference is removal of one trailing blank line.
10. `PROVED`: Experiment 001 captured 12 successful read-only frames. Raw data is
   mode `0600`, ignored by Git, and represented by a redacted hash manifest.
11. A single transient UI `hide` command had been used before the new collector
    to release a busy automatic menu. It did not access memory/controller state.
    Experiment 001 itself issued only its fixed read-only allowlist.
12. `PROVED`: The temporary A90-pinned bridge on port 54322 was stopped after
    collection. The other attached Samsung endpoint received no command.

## Missing artifacts

- `REFUTED`: Exact on-device XBL/AOP/hyp/tz/config firmware is unavailable.
  Experiment 004 captured nine exact live artifacts with triple hash agreement.
- `PROVED`: QHEE/hyp firmware bytes and provider provenance are now bound to the
  live `hyp` partition and live `hyp_mem` load range.
- `UNKNOWN`: Live boot image and DTB byte hashes.

## 2026-08-25 — Experiment 004 live firmware acquisition

1. Rebound the exact A90 USB ACM endpoint and started a dedicated loopback-only
   bridge. The other attached Samsung endpoint was untouched.
2. Implemented a fixed-allowlist collector. It rejects arbitrary partition names,
   requires GPT/sysfs identity, exact expected size and `ro=1`, and parses binary
   frames by advertised byte count rather than delimiter search.
3. One initial smoke stopped before block data access because the host parser did
   not accept a successful zero-payload `mknodb` frame. The possible temporary
   node was immediately removed and absence verified. The parser and unconditional
   cleanup path were repaired and covered by a regression test.
4. A 128 KiB `devcfg` smoke then passed with equal device-before, host and
   device-after hashes and verified node cleanup.
5. Full capture acquired nine artifacts totaling 26,779,648 bytes. All triple
   hashes matched; five historical hashes also matched.
6. Post-capture `/dev` contained no temporary node, native selftest reported
   `fail=0`, and the bridge was stopped.
7. First-pass static analysis proved XBL DDR/DSF/DCB ownership, exact AOP DDR
   management, `hyp`-partition QHEE provenance, and concrete TrustZone names for
   BIMC/MEMNOC/LLCC MPUs. No transform register or bypass was claimed.
8. Exact loader disassembly and a reproducible DCB inventory proved four
   `0x3404` DCBs at DSF `0x00650000`. XBL consumes five section indexes and
   copies section 16 to `0x09065100`; SHRM consumption and final-map semantics
   remain `UNKNOWN`.

## 2026-08-25 — Experiment 006 XBL/SHRM/ICB remapper

1. `PROVED`: Parsed the exact `CFGL` descriptor table and bound the four DCB
   payloads to `6003_{0100,0200}_{0,1}` selector filenames.
2. `PROVED`: Recovered the selector code. XBL reads `0x01fc8000`, splits its
   hardware ID/version fields, masks version with `0xff00`, and derives the
   final bit from physical versus RUMI platform type.
3. `PROVED`: Identified `0x09060000` as `qhs_shrm_mem`; DCB section 16 lands at
   `+0x5100`. Hashed the exact embedded SHRM data and instruction blobs and
   traced their installation functions.
4. `PROVED`: Function `0x1483a6dc` searches a 13-row `{mask,total MiB,base0,
   base1}` DDR remapper table and calls `/dev/icbcfg/boot` for two regions.
5. `PROVED`: Replayed the DAL property lookup from its exact binary structures.
   The sole `icbcfg_info` record contains four qhs_llcc register instances at
   `0x09248080`, `0x092c8080`, `0x09348080`, and `0x093c8080`.
6. `PROVED`: Layout-1 writer `0x1484fbbc` uses 32-bit offsets `0x00..0x58` and
   brackets programming by clearing/setting the enable bit at offset zero.
7. `PROVED`: The separate exact TrustZone ELF contains the same DAL device hash,
   six-slot layout and four register bases. Secure-world runtime use/locking is
   `UNKNOWN`.
8. `SUPPORTED`: This is a system-PA region remapper. Its relation to final
   channel/bank/row hashing, post-boot access and protection ordering remains
   `UNKNOWN`; no alias or bypass was observed.
9. Implemented a reproducible static inventory, a fixed read-only SoC-identity
   collector, and regression tests. The final full suite passed 36 tests.
10. A live identity read was not attempted because `/dev/serial/by-id` and ACM
    endpoints were absent when checked. No device command or device write was
    issued during Experiment 006's current static phase.
11. Implemented a second fixed read-only collector for Experiment 005. It has no
    arbitrary-address option, defaults to four `+0x00` control reads, and only
    expands to the exact 92 layout words with `--full`. It remains unexecuted.

## 2026-08-25 — Experiment 005 live read-route qualification

1. `PROVED`: The handset was connected. Host sysfs exposed `ttyACM0` as
   `04e8:6861`, manufacturer `A90-LNX`, product `A90 Linux ARM64`; host `/dev`
   had the stable A90 by-id. The Codex sandbox alone omitted `/dev/ttyACM0` and
   `/dev/bus/usb`.
2. Started a host-side loopback bridge pinned to the exact A90 by-id and
   `/dev/ttyACM0`. The separate `04e8:6860` Samsung Android ACM endpoint was not
   selected.
3. Live identity/config capture returned SoC ID `339`, revision `2.2`, SMEM
   `raw_id=165`, `raw_version=3`, platform `MTP`, subtype `charm`, and unchanged
   `MemTotal=5,504,940 kB`.
4. `REFUTED`: Linux SMEM `raw_id/raw_version` directly encode XBL's DCB filename.
   The attempted `/00A5_0000_1_dcb.bin` is absent from exact CFGL; live DCB
   revision remains `UNKNOWN`.
5. First remapper control smoke attempted only `0x09248080`, width 32. Toybox
   stopped before MMIO because `/dev/mem` did not exist. Runtime version remained
   healthy.
6. Fixed the binary-safe A90P1 parser to preserve `[err]` frames rather than
   requiring `[done]`, then deliberately repeated that first word once to bind
   the exact error.
7. Implemented a fixed temporary-node path. `/dev/sdm855_mblab_mem` character
   device `1:1` was pre-cleaned, created, passed to `devmem -f`, removed in a
   `finally` path, and proved absent afterward. Open returned `ENXIO` (`No such
   device or address`) before MMIO.
8. `PROVED`: Live `/proc/config.gz` (compressed SHA-256
   `ff2543fee33573e8efe34110598e963d7ddc9c44fbbf5dc1256cd6edec0f8fde`)
   contains `# CONFIG_DEVMEM is not set`; exact board defconfig independently
   agrees. This explains the missing minor-1 backend.
9. No partition, memory, or MMIO write occurred. Final runtime selftest was
   `pass=11 warn=1 fail=0`, all temporary nodes were absent, and the bridge was
   stopped.
10. Current result is `REFUTED` only for the userland `/dev/mem` route. A narrow
    kernel-space read adapter remains the cheapest test of actual register/XPU
    accessibility.

## 2026-08-25 — Experiment 007 generic-REPL kernel adapter

1. `PROVED`: The old repository's current builder did not reproduce the live
   REPL image; it produced SHA-256 `1ba534…`. A provenance wrapper fetched the
   exact source blobs from commit `f44b34c8f44a9a01c99bb589644494c732a6c3fa`
   without modifying that repository and reproduced the pinned candidate
   `b846ae9f74d8ceb922bbcd854d78b6795ef833d61e38465d3cc474cb6f0dfb65`.
2. `PROVED`: TWRP remote hash, boot write, and 60,882,944-byte prefix readback
   all matched the candidate. Physical TWRP Reboot → System was required; CLI
   reboot attempts retained Samsung's recovery-enter parameter.
3. `PROVED`: Native version/health passed. The historical driver then passed
   two named static-image peeks and a verified `printk` sentinel call against
   the exact regenerated System.map.
4. Attempts 01 and 02 stopped at replay-safe slide-result capture before any
   map. Attempt 01 reproduced the previously documented marker-window failure;
   marker mode was removed. Attempt 02 showed the same no-result condition in
   the default path. Attempt 03 stopped on a preflight auto-menu `EBUSY`; moving
   `hide` before all preflight commands fixed that ordering defect.
5. After one warm reboot, attempt 04 recovered slide `0x110000` and invoked the
   fixed first call only:
   `__ioremap(0x09248080, 0x5c, 0x0068000000000707)`.
6. `PROVED`: `/proc/last_kmsg` contains an `A90R` slide record at 75.082095 s,
   an `A90R` call-return record at 75.653343 s, and a `Non Secure Watchdog Bark`
   at 78.680670 s. The delta from call return to bark is 3.027327 s.
7. `PROVED`: `msm_readl` was never invoked, no remapper register value was
   obtained, and no MMIO or memory write occurred. This result does not locate
   an XPU denial and does not prove that the remapper itself is unreadable.
8. Host classification after recovery returned `DENY` for `__ioremap`,
   `__iounmap`, and `msm_readl`. The wrapper's JOPP/prefix checks verified
   identity but incorrectly bypassed the existing deny-by-default call-safety
   policy by using `ReplSession.call_runtime` directly. The live entry point is
   now unconditionally disabled with no CLI override.
9. `PROVED`: The first rollback shell form had no effect; this was detected
   because prefix readback still matched the candidate. A corrected single
   remote command wrote V2321, and the full 60,882,944-byte readback matched
   `ca978551aabe4b39563abaf529ccf2522054952d8b2ad852e632d26da88168cb`.
   The temporary remote image was removed. Final native health awaits physical
   TWRP Reboot → System.
10. `REFUTED`: the generic REPL call sequence is a safe implementation of the
    narrow kernel adapter. `UNKNOWN`: whether a purpose-built kernel worker can
    map/read/unmap the same fixed window without the REPL callback-context
    watchdog.
