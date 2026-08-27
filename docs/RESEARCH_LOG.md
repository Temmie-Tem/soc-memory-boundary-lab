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
   all matched the candidate. At this point physical TWRP Reboot → System was
   used because the CLI reboot attempt crashed/restarted Recovery.
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
   The temporary remote image was removed. Final native health was later
   proved as version `0.9.285` and selftest `pass=11 warn=1 fail=0`.
10. `REFUTED`: the generic REPL call sequence is a safe implementation of the
    narrow kernel adapter. A later fixed inline comparison removed its generic
    call-target and callback sequencing as alternative explanations.
11. Host-only follow-up replaced the generic REPL with two 212-byte inline
    bodies at the same stock-kernel hook. Both hardcode `0x09248080`, `0x5c`,
    the protection value and direct call destinations; neither accepts an
    address or target and neither contains an MMIO store.
12. The control candidate `dbbf81f2…` performs map → immediate unmap → sentinel
    without a bus load. The read candidate `6fe92825…` differs by one fixed
    `ldr w20,[x19]`, then unmaps before printing. Candidate and body bytes for
    both modes reproduced three times.
13. `PROVED`: the control candidate was flashed with full-prefix readback,
    invoked once, returned `0x0000c071`, restored `panic_on_oops`, and retained
    version/selftest health. This made the one-load candidate eligible.
14. `PROVED`: Samsung TWRP 3.7.0_12-0 exposes the GUI reboot action through
    `tw_reboot_arg` and `tw_gui_done`. Setting `tw_reboot_arg=system` and then
    `tw_gui_done=1` through the FIFO exits the Recovery main loop and boots
    native without touch input. Direct `twrp reboot` instead crashed and
    restarted the Recovery process; raw reboot calls returned to Recovery.
15. `PROVED`: the read candidate was flashed once with exact full-prefix
    readback and invoked once with no automatic retry. It returned no value,
    disconnected USB/ACM, and warm-reset into the same candidate.
16. `PROVED`: retained `/proc/last_kmsg` SHA-256 `8701d073…` records watchdog
    bark at 69.080426 s, last pet at 58.080136 s, CPU alive mask `0x01`, and
    bootloader upload cause `Non Secure Watchdog Bark`. `SUPPORTED`: the fixed
    32-bit load, rather than mapping alone, triggered the system-wide stall.
    `UNKNOWN`: secure firewall, clock/power, runtime-base, or other fabric cause.
17. `PROVED`: V2321 was restored with a full 60,882,944-byte readback match and
    final native version/selftest `pass=11 warn=1 fail=0`. The read was not
    repeated.

## 2026-08-25 — Experiment 008 exact remapper/protection recombination

1. Ran a host-only recombination over four exact pins: XBL `e73a07a0…`, XBL
   config `0e9dfac1…`, TrustZone `a5e6c574…`, and retained last-kmsg
   `8701d073…`. No device, MMIO, partition, firmware, or controller access was
   performed.
2. `PROVED`: all seven retained chip records agree on
   `0x01fc8000 = 0x60030202`; all seven CDT records agree on platform ID `8`.
   Exact XBL selector rules therefore choose `/6003_0200_1_dcb.bin`, replacing
   the previous live-revision `UNKNOWN`.
3. `PROVED`: selected DCB SHA-256 is `34caf815…`, used size `11820`, DSF
   `0x00650000`; its 560-byte section 16 SHA-256 is `cdacfa45…` and its exact
   copy destination remains `0x09065100`.
4. `PROVED`: all six rank records agree on 3072+3072 MiB. Rank mask `0x3` and
   total 6144 MiB uniquely select remapper table row 7, destination bases
   `0x80000000` and `0x140000000`. The selector's 12-GiB special case is
   `REFUTED_FOR_THIS_BOOT`.
5. Pinned five exact XBL function ranges by hash. `PROVED`: layout 1 uses
   six 36-bit range slots split across low32/high4 fields, clears/disables
   control before programming, then installs bits `9:4` and enable bit 0.
   Inside exact function `0x1484fbbc..0x1484fe74` there is no distinct lock
   write; later firmware/hardware locking remains `UNKNOWN`.
6. `PROVED`: XBL consumes per-channel rank sizes/source bases from runtime DDR
   context and an interleave mask at config `+0xc8`. The retained evidence lacks
   source bases and that mask, so numeric boot register values are explicitly
   `UNKNOWN_DEPENDS_ON_RUNTIME_DDR_CONTEXT` rather than guessed.
7. `PROVED`: unique TrustZone primary registry records bind `BIMC_MPU0..3` to
   IDs `0x2e,0x2f,0x3f,0x40` and bases `0x0924e000`, `0x092ce000`,
   `0x0934e000`, `0x093ce000`. Each is `qhs_llcc + 0xe000` beside its exact
   remapper at `+0x8080`. `MEMNOC_MS_MPU`, `LLCC_BROADCAST_MPU`, and
   `DC_NOC_SHRM_MPU` were also bound to exact bases.
8. `PROVED`: exact TZ contains no byte-identical occurrence of any of the five
   pinned XBL functions or their first 64 bytes. Semantic-equivalent secure code
   and runtime invocation of TZ's duplicated `icbcfg` record remain `UNKNOWN`.
9. Four successful retained boots register LLCC PMU and LLCC-to-DDR monitors,
   disfavoring a whole-fabric-off explanation. The reset collector's XPU report
   was explicitly encrypted or unparsed; absence of a decoded XPU violation is
   not negative evidence.
10. Implemented `tools/sm8150_remapper_boundary_inventory.py` and six focused
    regression tests; the complete suite passes 66 tests. Regeneration is
    byte-identical and every public manifest parses as JSON. Tool SHA-256
    `f7369436326de88421e4c4e98c518bb5f59e9c5aa94a6f9b9311340da1a87bca`;
    public manifest SHA-256
    `b4bb1082df278b57055f164d3da9c3a2f420ac9cc3d904ccb1ea24e78b9f3f9a`;
    ignored mode-0600 derived record SHA-256
    `2154ee2af18d0e98b92f6658120cde89434433be8db8f592d026ad278b6660ff`.

## 2026-08-25 — Experiment 009 exact TrustZone XPU policy

1. Ran a host-only parser over exact TrustZone `a5e6c574…`, devcfg
   `03995782…`, and retained last-kmsg `8701d073…`. No device, MMIO,
   partition, controller, SCM, EL2, or EL3 access occurred.
2. `PROVED`: TZ's primary XPU registry at `0x1c1579e0` contains 48 24-byte
   `{id, base, name}` records. Pinned function
   `0x1c0fc890..0x1c0fca1c` walks it with a `0x18` stride and reads the
   selected hardware base, proving the table is consumed rather than
   string-only.
3. `PROVED`: selector function `0x1c0a2dfc..0x1c0a2ec4` returns either a
   43-descriptor table at `0x1c122100` or a 44-descriptor table at
   `0x1c121250`. Every descriptor ID/base matches the primary registry.
4. `PROVED`: both tables contain `DC_NOC_BROADCAST_MPU` id `0x3c`, base
   `0x090e0000`, with 40 MPU regions. In both, region 11 is identical:
   flags `0x9`, read `0x80000000`, write `0`, start `0x09248000`, exclusive
   end `0x09249000`. Thus the tested `0x09248080` load is inside the policy
   regardless of selector result.
5. `REFUTED`: the critical value is `0x80/0x80`. Raw little-endian bytes prove
   `read_vmid=0x80000000`, `write_vmid=0`.
6. Replayed and pinned exact MPU conversion function
   `0x1c0aa51c..0x1c0aa7e4`. `PROVED`: flags bit 3 selects TZ owner; read bit
   31 maps to the MSA-class read slot; standard VMID permission words are both
   zero; final client bytes are `0x11/0x08`. The record grants TZ-owner
   read/write and MSA-class read-only, but no ordinary HLOS VMID permission.
7. Comparative Qualcomm SDM660 access-control headers and an unstripped
   `ACXpu.o` at commit `b5e5bb9e…` supplied field/function names. They were
   explicitly kept `COMPARATIVE_NOT_EXACT_SM8150_SOURCE`; exact A90 function
   hashes, instructions, addresses, and data independently anchor every SM8150
   conclusion.
8. `PROVED`: exact devcfg's 40-entry DAL device table resolves `/ac/xpu` to
   `disable_xpu_ac`, type uint32, value `0`, with valid end marker
   `0xff00ff00`.
9. `PROVED`: TZ's global XPU error map assigns MEMNOC_MS_MPU and all four BIMC
   MPUs plus DC_NOC_BROADCAST/NON_BROADCAST and DC_NOC_SHRM to status bits.
   The handler includes config/client-port, `APROTNS`, and write/read fields.
10. `PROVED`: BIMC_MPU0..3 are absent from both embedded static policy lists.
    `UNKNOWN`: another TZ path, XBL, another secure component, or hardware
    defaults may initialize them; absence is not evidence of inactivity.
11. `SUPPORTED`: an active DC_NOC XPU/fabric denial is now the leading cause of
    the fixed load watchdog. `UNKNOWN`: the final programmed registers and a
    decoded syndrome. The retained collector reports only an encrypted or
    unparsed TZ log, so causality remains below `PROVED`.
12. Implemented `tools/sm8150_xpu_policy_inventory.py` plus seven focused
    tests. Public evidence is
    `009-xpu-policy-inventory-20260825-01.manifest.json`; the path-bearing
    mode-0600 record remains ignored. All 73 repository tests pass; all public
    manifests parse; private/public regeneration is byte-identical. Tool,
    public manifest, and private derived-record SHA-256 are respectively
    `88b6cd2e…`, `f5c661af…`, and `d90d48f7…`. No live access was repeated.

## 2026-08-25 — Experiment 010 QHEE/TZ initializer authority

1. Ran a host-only parser over exact XBL `e73a07a…`, TrustZone `a5e6c574…`,
   QHEE/hyp `646f8fca…`, and devcfg `03995782…`. No device, SMC, MMIO,
   partition, controller, EL2-runtime, or EL3-runtime access occurred.
2. Corrected the syscall-table model to exact 24-byte
   `{u32 reserved, u32 smc_id, u32 param_id, u32 flags, u64 handler}` records.
   `REFUTED`: treating an adjacent parameter/flag word as a handler pointer.
3. `PROVED`: exact QHEE registers HLOS SMC `0x02000c16` at `0x85723b90`.
   Its bounded handler validates buffer/VM/ownership/alignment state and calls
   local wrapper `0x8573581c`, structurally matching comparative
   `ACMapMemoryRange` and QHEE stage-2/SMMU access control. It does not directly
   call generic TZ wrapper `0x85718100`.
4. `PROVED`: exact TZ separately registers the same ID at `0x1c0a6de4`.
   Pinned direct branches reach assignment core `0x1c0a5564`, memory lock
   `0x1c0ab624`, internal lock `0x1c0ab6c8`, lock area `0x1c0a9d5c`, topology
   fanout `0x1c0a9e14`, and reconfigure `0x1c0a9f44`.
5. `PROVED`: topology code emits registered IDs `0x2e`, `0x2f`, `0x3f`, and
   `0x40` (`BIMC_MPU0..3`) and sometimes `0x3a`
   (`LLCC_BROADCAST_MPU`). `REFUTED`: static-list absence implies BIMC MPUs are
   unconfigured. Unregistered emitted IDs `0x51..0x54` remain `UNKNOWN`.
6. `PROVED`: exact TZ registers toggle SMC `0x02000c23`; its enable path
   restores a registry-resolved XPU and its disable path searches an allowed
   list whose exact count at `0x1c122a90` is zero. No arbitrary HLOS XPU
   disable/write primitive was obtained.
7. `PROVED`: QHEE's named RPM-region path calls two fixed TZ services, but the
   exact TZ `0x0200030f` handler is a single `RET`. Its app-region handler calls
   two QSEE region/list helpers and no reconstructed BIMC/XPU function directly.
8. `PROVED`: both embedded TZ policy branches cover every known remapper and
   BIMC configuration address with TZ-owned `MEMNOC_MS_MPU` region 0 and
   `CNOC_SNOC_MS_MPU` region 5. Both records contain no ordinary HLOS VMID
   permission. Instance 0 additionally has narrow DC_NOC regions 11 and 13.
9. `PROVED`: boot master-MPU selectors initialize `ANOC2_MPU`, `MSS_NAV_MPU`,
   and `CNOC_AOSS_MPU`, not BIMC. XBL BIMC literals reside in a TZ-branded XPU
   diagnostic table; `REFUTED`: literals alone prove main-XBL policy writes.
10. `SUPPORTED`: static config does not request the comparative secure-config-
    write-disable field, consistent with secure-world dynamic updates.
    `PROVED`: exact XPU3 restore/reset preserve control mask `0x2`.
    `UNKNOWN`: the final hardware bit and runtime policy registers.
11. QHEE/EL2 evidence is therefore material: it proves an independent
    ownership/stage-2/SMMU layer and prevents conflating `hyp_assign` with TZ
    BIMC control. Arbitrary EL2 private-memory R/W remains `UNKNOWN`.
12. Implemented `tools/sm8150_xpu_initializer_inventory.py` and eight focused
    tests. All 81 repository tests pass; public JSON parses; three generations
    are byte-identical. Tool, public manifest, and ignored mode-0600 private
    record SHA-256 are `10b13456…`, `baeef82f…`, and `dc4a664b…`.
    Current result is `CLASS A/B CANDIDATE FOR KNOWN CONTROLLER APERTURES`, not
    a complete structural-block proof and not a security-boundary bypass.

## 2026-08-25 — Experiment 011 exact XBL DRAM coordinate map

1. Ran a host-only parser over exact XBL `e73a07a…`, XBL config `0e9dfac1…`,
   and retained last-kmsg `8701d073…`. No device, SMC, MMIO, partition,
   controller, EL2-runtime, or EL3-runtime access occurred.
2. Pinned Quest DDR size accumulator `0x14921c74..0x14921d0c`, coordinate
   reporter `0x149212c0..0x149213ec`, and real failure recorder
   `0x1492234c..0x14922428`, plus every critical arithmetic instruction.
3. `PROVED`: the retained 6-GiB value makes the diagnostic rank boundary
   `0x80000000 + (6 << 29) = 0x140000000`, exactly remapper row 7's rank-1
   destination.
4. `PROVED`: rank-relative bits map as row `[31:16]`, bank `[15:13]`, channel
   `[10:9]`, column `[12:11]||[8:1]`, byte `[0]`. The partition is complete,
   non-overlapping and invertible. A 65,536-address control has no collision.
   `REFUTED`: the bounded formula itself contains XOR or creates an alias.
5. `SUPPORTED`: the formula is the intended PA-to-DRAM coordinate model because
   the exact failure recorder uses it. `UNKNOWN`: silicon may apply additional
   transform state omitted from that diagnostic.
6. Parsed selected DCB section 16 header `{8,0x230,0x1b8,0x8e8}` and both
   record sets exactly. Set 0 has 22 records/two padding records; set 1 has
   eight records/one padding record.
7. `PROVED`: section base tokens numerically equal `physical_base >> 12` for
   exact `qhm_shrm` per-channel MCCC/MC, MCCC-master, DDRSS, and SHRM-CSR
   bindings. `SUPPORTED`: they are page numbers in an SHRM register inventory.
   Offset scaling, flags, read/write direction, set meaning, values and locks
   remain `UNKNOWN`.
8. `PROVED`: `invert_row: %d` has one string occurrence and two pinned users
   that print and forward a local DDR-code flag outside the coordinate reporter.
   `REFUTED`: the string alone proves a final PA-row transform.
9. Implemented `tools/sm8150_dram_coordinate_inventory.py` and seven focused
   tests. All 88 repository tests pass; all public manifests parse; three
   private/public generations are byte-identical; modes are `0600/0644`.
   Tool, focused-test, public-manifest and ignored private-record SHA-256 are
   `15b2ffb9…`, `29d2358f…`, `93fbc870…`, and `90a50e31…`.
10. Current result is `CLASS A/B CANDIDATE / NO ALIAS PRIMITIVE OBSERVED`.
    The next cheapest step is static recovery of the SHRM section-16
    interpreter, not another blocked EL1 controller read.

## 2026-08-25 — Experiment 012 exact SHRM section-16 interpreter

1. Recovered the exact embedded SHRM instruction image as Xtensa code installed
   at physical `0x09068000`; its 23,776-byte source blob hash is
   `421824b4…`. The section workspace at physical `0x09065100` maps to Xtensa
   local address `0x25100` through the exact SHRM data/code installation
   offsets.
2. Pinned the common helper at Xtensa VA `0x2d8dc..0x2d959` by SHA-256
   `01fc5d83…`. The helper parses `u8 base_count`, `u8 offset_count`, `u16`
   base pages and `u16` offset tokens, then computes
   `(base_page << 12) + (offset_token << 2)`.
3. `PROVED`: direction zero reads each computed 32-bit register into a SHRM
   snapshot buffer. A nonzero direction is the reverse copy in the helper
   model, but no direct section-16 callsite in the bounded image passes it.
4. `PROVED`: exact callsites at `0x288a9` and `0x28e15` pass direction zero.
   The selected lists terminate after 20/7 non-padding records and produce
   430/64 register-word reads, fitting capacities `0x6b8/0x618` bytes.
5. `REFUTED`: interpreting offset tokens as 4-KiB offsets or treating the
   observed section-16 path as a transform-write primitive. Runtime values,
   lock state, final-decode meaning and any indirect reverse-direction use are
   still `UNKNOWN`.
6. Implemented `tools/sm8150_shrm_section16_inventory.py`, three focused tests,
   the private/public manifest pair and
   `experiments/012-shrm-section16-interpreter/README.md`. No device, SMC,
   MMIO, partition, EL2, EL3 or protected-memory action occurred.
7. Current result is
   `CLASS A/B CANDIDATE — SECTION-16 READ-ONLY SNAPSHOT / NO TRANSFORM-WRITE OR
   ALIAS PRIMITIVE OBSERVED`.

## 2026-08-25 — Experiment 013 SHRM snapshot protection and live preparation

1. Replayed both exact TrustZone policy branches over the complete section-16
   workspace `0x09065100..0x09065fff`; no device, SMC, MMIO, partition, EL2 or
   EL3 action occurred.
2. `PROVED`: each branch has exactly three covering enabled/TZ-owned regions:
   `DC_NOC_NON_BROADCAST_MPU` region 5 (`0x09060000..0x0906ffff`),
   `MEMNOC_MS_MPU` region 0, and `CNOC_SNOC_MS_MPU` region 5.
3. `PROVED`: all six branch/region matches exclude the comparative HLOS VMID
   from read and write. The narrow region's `read_vmid=0x40000000` is the exact
   MSA-class read-only slot, not HLOS; `write_vmid=0`.
4. `REFUTED`: the SHRM snapshot workspace is statically unprotected or granted
   to ordinary HLOS. Runtime XPU register state remains `UNKNOWN`.
5. Built pinned, fixed control/read boot candidates at the previously proved
   inline hook. Both target only physical `0x0906566c`, section-16 set-0 word
   207, which maps to source MCCC register `0x09250118`. The control has no bus
   load; the read has exactly one 32-bit load; neither accepts an address or
   contains a memory/MMIO store.
6. Candidate SHA-256 values are `d1d4956b…` (control) and `7ee6a41f…` (read).
   Initial state was `HOST_READY_CONTROL_ONLY`.
7. The control candidate was written once with full boot-prefix readback,
   code-booted from exact TWRP, and invoked once. It returned `0xc071`; version,
   selftest and `panic_on_oops` restore passed. V2321 was then restored by full
   prefix SHA-256 before read eligibility.
8. The read candidate was written once with full-prefix readback and invoked
   once. It returned no `A90R` value, disconnected USB, and was not retried.
9. Captured retained `/proc/last_kmsg`, 2,097,136 bytes, SHA-256 `92af2a21…`.
   It records bark `40.280410`, last pet `29.280131`, alive mask `0x07`,
   `Non Secure Watchdog Bark`, and `TZBSP_ERR_FATAL_NON_SECURE_WDT`.
10. `PROVED`: paired outcomes and reset identity. `SUPPORTED`: the sole extra
    `LDR W`, rather than mapping, caused the system-wide stall; static XPU
    denial explains it. Causal XPU syndrome remains `UNKNOWN`.
11. Restored V2321 with full-prefix SHA-256 `ca978551…`. Final native receipt
    proves version `0.9.285`, selftest `pass=11 warn=1 fail=0`, and battery
    100%. Current result is `CLASS A/B CANDIDATE — FIXED DIRECT EL1 SHRM READ
    BLOCKED / NO ALIAS OR BOUNDARY BYPASS OBSERVED`.

## 2026-08-25 — Verification 001 independent claim audit

1. Motivation is provenance, not hardware: every `PROVED` statement here is one
   agent's interpretation of the exact bytes, and Experiments 008–013 consume
   004/006 conclusions as pinned inputs, so an early misinterpretation would be
   inherited downstream. The existing quality signals do not test for this —
   unit tests prove parser determinism, hash pins prove input stability, and
   byte-identical regeneration proves tool reproducibility. None of the three
   proves the interpretation is correct.
2. Implemented `tools/independent_claim_audit.py`, which re-derives each audited
   claim from raw bytes without importing, calling, or reusing any other module
   in `tools/`. Structures are located by name and value search and then walked,
   so a claim can fail even when the original tool reproduces byte-identically.
   No AArch64 or Xtensa disassembler existed on the host, so minimal subset
   decoders were written for the audit.
3. `PROVED`: measured XBL and TrustZone SHA-256 equal the pinned values
   `e73a07a0…` and `a5e6c574…`. The prior analysis did run on these exact bytes.
4. `PROVED`: `icbcfg_info` and `/dev/icbcfg/boot` exist; the four claimed bases
   appear both as a `count=4` u64 array at VA `0x14876978`, referenced from
   `0x148769c0`, and as a u32 literal pool at VA `0x146aecb0`, at stride
   `0x80000`.
5. `PROVED`: the Experiment 009 claim resolves end to end. Registry record
   `{id=0x3c, base=0x090e0000, name → "DC_NOC_BROADCAST_MPU"}` matches policy
   entries at `0x1c1217a0`/`0x1c122628` by the low 16 bits of id `0x0001003c`;
   both declare `region_count=0x28=40` and point at region tables whose region
   11 is byte-identical: `flags=0x09`, `read=0x80000000`, `write=0x00000000`,
   `start=0x09248000`, `end_exclusive=0x09249000`, containing `0x09248080`.
6. `PROVED`: the Experiment 013 claim likewise resolves —
   `DC_NOC_NON_BROADCAST_MPU` (`id=0x3d`, base `0x090b4000`, 16 regions) region
   5 is `0x09060000..0x0906ffff` with `read=0x40000000`, `write=0x00000000` in
   both branches, containing the SHRM workspace.
7. `PROVED`: the XPU disable allowlist is a compile-time constant. Handler
   `0x1c0a9a44` calls leaf helper `0x1c0a2630`, which returns count and array
   pointer from fixed address `0x1c122a90`; that location holds `0`, so the
   `cbz` is always taken and the path returns `-16`.
8. `PROVED`: the SMC `0x0200030f` handler's first instruction at `0x1c050b9c`
   is `0xd65f03c0`, a single `RET`.
9. `PROVED`: the SHRM blob hash `421824b4…` and helper hash `01fc5d83…` both
   match, and the decisive instructions decode byte-exactly —
   `+0x24: 40 99 11` is `slli a9, a9, 12` and `+0x3e: 90 cc a0` is
   `addx4 a12, a12, a9`. Xtensa `ADDX4 ar,as,at` is `ar = (as << 2) + at`, so
   the pair is exactly `(base_page << 12) + (offset_token << 2)`.
10. Two notation issues, no substantive error: the helper range
    `0x2d8dc..0x2d959` is end-exclusive at 125 bytes, located by exhaustive
    search rather than assumed; and `0x09248fff` is not a stored value, the raw
    field being end-exclusive `0x09249000`.
11. `PROVED` and underweighted previously: region 11's write access word is
    `0x00000000`, so no client class holds write permission, not merely no
    ordinary HLOS VMID. Region 5 of `DC_NOC_NON_BROADCAST_MPU` matches. Sibling
    regions 12 (`0x40000000/0x40000000`) and 13 (`0xf0000000/0xf0000000`) show
    this is deliberate rather than a default.
12. Not audited: QHEE `hyp_assign` stage-2/SMMU path, TZ dynamic `BIMC_MPU0..3`
    initializer, the Experiment 011 Quest coordinate formula, the section-16
    callsites and their 430/64 counts, and the permission-conversion routine.
13. Added `tests/test_independent_claim_audit.py`. All 125 repository tests
    pass, all 33 public manifests parse, three consecutive manifest generations
    are byte-identical, and the public manifest mode is `0644`. Tool, test and
    manifest SHA-256 are `b6617c19…`, `2c42b6bd…` and `a722f0f6…`.
14. Result is `INDEPENDENT AUDIT — 7/7 CHECKED CLAIMS CONFIRMED / NO
    SUBSTANTIVE ERROR FOUND`. The security interpretation is explicitly not
    audited: the confirmed evidence concerns reachability, and protection
ordering relative to the final DRAM transform remains `UNKNOWN`.

## 2026-08-25 — Verification 002 exact SHRM dump export

1. Continued from Experiment 013 without another device command or protected
   load. Temporarily unpacked `binutils-xtensa-lx106` under `/tmp` and used it
   only for reconnaissance; the retained tool and manifest do not depend on
   that package or retain disassembly output.
2. Re-extracted the exact embedded SHRM blob from XBL and verified SHA-256
   `421824b4…`. The first extraction used the wrong ELF LOAD segment and failed
   the pin (`4bf8daac…`); it was discarded before analysis. The corrected
   `0x1489f800` segment mapping reproduced the exact pin.
3. Independently decoded the two Xtensa streams. `0x288a9` and `0x28e15` both
   load the sole local workspace literal at `0x2819c` (`0x25100`) into `a4`,
   set `a2=0`, and call helper `0x2d8dc` at `0x288c4`/`0x28e30`.
4. `PROVED`, bounded: the complete SHRM instruction blob has no direct u32
   literal for local destinations `0x25330`/`0x259e8` or physical destinations
   `0x09065330`/`0x090659e8`. A dynamically derived consumer remains
   `UNKNOWN`; this is not a global no-export claim.
5. Found exact XBL strings `SHRM MEM region` and `SHRM_MEM.BIN`, then recovered
   their unique 32-byte descriptor at VA `0x14961990`/file offset `0x33e960`:
   base `0x09060000`, size `0x10000`. It is index 19 in a contiguous 26-record
   table at `0x14961730`.
6. `PROVED`: AArch64 loop `0x14917ca8..0x14917cf4` resolves that table, compares
   against count `0x1a`, loads `{base,size,description,filename}`, advances by
   `0x20`, and calls registrar `0x14917670`. Pinned calls show
   `0x14902cc4 -> 0x14917740 -> 0x14917c60`, placing the consumer in the exact
   dload/rawdump path. Nearby exact strings name
   `boot_raw_partition_ramdump.c` and explicit FMM/debug-level gates.
7. `REFUTED`: no exact firmware export path covers the protected SHRM
   workspace. `SUPPORTED`: `SHRM_MEM.BIN` is a gated bootloader crash/download
   path, not normal Android/HLOS runtime visibility.
8. Read-only host enumeration showed `/dev/sda1` label `ANDROIDLABSD` mounted at
   `/mnt/android-lab-sd`. Exact searches found no `SHRM_MEM.BIN`, `rawdump.bin`,
   or Experiment-004 A90 partition filename. The only A908 path is Samsung's
   open-source kernel archive/directory; unrelated S22+ material was untouched.
9. Implemented `tools/sm8150_shrm_dump_export_inventory.py` and ten focused
   tests, generated a private/public manifest pair, and documented the result
   in `experiments/verification-002-shrm-dump-export/README.md`. All 135 tests
   pass, all 34 public manifests parse, consecutive generations are
   byte-identical, and modes are `0600/0644`. No device, SMC, MMIO, controller,
   partition, EL2/EL3 runtime or protected-memory action occurred.
10. Classification is
    `BOOTLOADER_RAWDUMP_EXPORT_PRESENT_HLOS_RUNTIME_EXPORT_UNPROVED`. The next
    discriminator is read-only A90 FMM/debug-level/RDX eligibility and existing
    dump-header inventory, not repetition of the denied EL1 load.

## 2026-08-25 — Verifications 003/004 A90 raw-dump eligibility

1. Reused only the read-surface concept from upstream
   `s22plus_reset_reason_readonly_probe.py`. A90 profile, binding and transport
   remained separate; `getprop` and ADB were excluded because V2321 has no
   Android property service.
2. Implemented `tools/a90_rawdump_eligibility_probe.py`. It first requires exact
   V2321 `0.9.285 / v2321-usb-clean-identity-rodata` and exact kernel, then
   issues only fixed `cat` reads through the pinned loopback A90P1 bridge. Ten
   focused tests cover the allowlist, target-first stop, redaction, no-clobber,
   cmdline parsing and conservative classification.
3. Verification 003 read the five S22+ precedent surfaces. `/proc/cmdline`
   returned `debug_level=0x4f4c`, `force_upload=0x0`, and `boot_recovery=0`.
   The S22+ `qcom_dload_mode` and ramoops `max_reason` module paths returned
   `rc=-2`; `panic=-1`, `panic_on_warn=0`.
4. Host analysis corrected the generation-specific path. Exact A90
   `msm-poweroff.c` SHA-256 `0a2b20ec…` declares default `download_mode=1` and
   `module_param_call`; Makefile builds `msm-poweroff.o`. The retained exact
   live config has `CONFIG_QCOM_DLOAD_MODE=y`, `CONFIG_QCOM_MINIDUMP=n`,
   `CONFIG_PSTORE=y`, `CONFIG_PSTORE_RAM=y`, and `CONFIG_PANIC_TIMEOUT=-1`.
5. Verification 004 added only fixed read
   `/sys/module/msm_poweroff/parameters/download_mode`; it returned `1`.
   Final observable signals are debug `NEGATIVE`, force-upload `NEGATIVE`,
   dload master `POSITIVE`.
6. Classification is `DUMP_ENTRY_SIGNALS_INCOMPLETE`; actual XBL eligibility
   stays `UNKNOWN` because FMM/policy/token/transport joins are unresolved.
   No reset, write, service action, MMIO, SMC, payload or retry occurred. The
   separate Samsung `04e8:6860` endpoint received no command.
7. Reframed the Verification-002 unknown from prior-boot preservation to
   collection-time population. Freshly populated, stale or zero staged words
   are all measurable; only availability at collection time matters.
8. Independently completed the host-only `SHRM_MEM.BIN` decoder in commit
   `9fdd5d6`. Its plan resolves all 430/64 staged words back to 494 source
   register labels and rejects wrong-size, wrong-header, and zero-filled
   inputs. The proved staged inventory does not reach the remapper `+0x8080`
   control window. At that point no real dump values had been decoded;
   Verification 012 later superseded this state.
9. Next work is host-only producer/control-path recovery for debug-level,
   force-upload and FMM/token. Experiment 014's timing model proceeds as the
   complementary behavioural track; it is host-ready but has no device phase.

## 2026-08-25 — Verification 005 exact XBL rawdump gates

1. Parsed exact A90 XBL `e73a07a…` and corrected a key image-boundary error:
   `0x14900000` is the separately mapped XBLRamDump image, not main XBL's entry.
2. `PROVED`: main XBL's outer dload decision at `0x14829f2c/0x14829f38`
   requires saved cookie bits `4/5` or restart reason `0x776655ee`. Saved bits
   are read/cleared through `0x14829a94` from `0x01fd3000`.
3. `PROVED`: XBLRamDump reads Samsung `param` offsets debug `+0x0`, force
   `+0x3f4`, FMM `+0x3fc`, and sink `+0x400`. FMM magic `0x464d4f4e` denies;
   exact force-upload enable is integer 5.
4. `PROVED`: with FMM unlocked and not on the Quest-DDR special path, non-LOW
   debug alone admits the vendor call even with force-upload zero and a denied
   `TZ_ALLOWS_MEM_DUMP` SMC. Full catalog registration separately requires
   cookie bit 4 or `SEC_DEBUG_MODE` restart reason.
5. `PROVED`: exact Samsung panic/watchdog source supplies both the outer full-
   dump dload cookie and `0x776655ee`; live dload master is one.
6. `REFUTED`: MID and force-upload must both be enabled. `REFUTED`: a positive
   TZ result is unconditionally required. `REFUTED`: orderly MID reboot alone
   enters rawdump.
7. Implemented `tools/xbl_rawdump_gate_inventory.py` and 14 focused tests;
   generated public manifest SHA-256 `5024b24e…`. Device access: none.

## 2026-08-25 — Verifications 006–010 live param qualification

1. Implemented a target-fixed 10-MiB `param` capture. Live GPT/sysfs resolved
   `sda10`, `PARTNAME=param`, major/minor `8:10`, and the exact expected size.
2. `PROVED`: device-before, host, and device-after SHA-256 all equal
   `1faafee97d08ff93b690dbcffe21d680f20232aa2d3dff5f462b747577bb4345`.
   The mode-0600 rollback image is private and Git-ignored.
3. `PROVED`: captured fields were DLOW, force-upload 0, FMM 0, and dump-sink 0.
4. Wrote a transition tool fixed to one four-byte field at partition offset
   `0x900000`. It derives complete expected LOW/MID images and refuses any
   unexpected full-partition pre/post hash.
5. Verification 007 applied DLOW→DMID once; Verification 008 restored DLOW once
   while qualifying the path; Verification 009 applied DMID once for the dump
   experiment. Every complete hash matched. Host images prove no force/FMM/sink
   byte changed.
6. Verification 010 performed one orderly reboot with MID. A new boot returned
   with `debug_level=0x494d`, force-upload 0, dump-sink 0, dload master 1, and
   selftest `fail=0`. This dynamically confirms that MID is consumed but does
   not supply the outer rawdump trigger.

## 2026-08-25 — Verifications 011–014 live SHRM acquisition and recovery

1. Pinned linux-msm qdl v2.8 and prepared a one-name `SHRM_MEM.BIN` Sahara
   filter before the trigger. Implemented a one-shot SysRq tool that refuses
   replay after an accepted begin frame.
2. Verification 011 dispatched exactly one `writefile /proc/sysrq-trigger c`.
   Exact source maps this to panic; no retry occurred after transport loss.
3. `REFUTED`: Qualcomm USB `05c6` Sahara/qdl is this A90 boot's crash-dump
   transport. qdl captured no file and was terminated without matching the
   live endpoint.
4. Host kernel journal instead records Samsung `04e8:685d`, product
   `MSM_UPLOAD`, manufacturer Samsung at 12:35:43 KST. Its eight-line,
   serial-free acquisition/return excerpt is pinned by SHA-256 `4b326be7…`.
5. Pinned `bkerler/sboot_dump` commit `8c9f6eb7…` and source SHA-256
   `7580a6c1…`. The live catalog showed 56 records and record 19 as the exact
   SHRM range; this console transcript was observed but not separately saved,
   so the count remains `SUPPORTED` rather than a pinned `PROVED` fact.
6. Selected only record 19. `PROVED`: acquired `SHRM_MEM.BIN` is exactly 65,536
   bytes, SHA-256
   `409550ad226443271a39b6bc060f0e8fb3224111cc03f07a6ee563eaa7098bb7`.
   No other memory record was collected.
7. The file reproduces the exact section-16 header at offset `0x5100`; the
   existing decoder mapped all 430 + 64 entries to labelled positions covering
   470 distinct source-register addresses.
8. `SUPPORTED`: set 0 is populated/coherent. It has 18 common `qhs_mc` offsets
   over four instances; 17 are identical and `+0x4d0` has one stable two-pair
   split. `REFUTED`: set 1 is a coherent current snapshot; all 64 values are
   distinct, all four MC `+0x80` values differ, and none of 24 exact overlaps
   matches set 0. Set-1 cause remains `UNKNOWN`.
9. Ranked five exact set-0 candidates while retaining semantic status
   `UNKNOWN`: MC `+0x400`, MC `+0x404`, MCCC `+0x118`, MC `+0x4d0`, and MCCC
   master `+0x294`. A comparative Qualcomm BIMC layout was explicitly rejected
   for direct naming because its `+0x400` mask/layout contradicts the A90 values.
10. `PROVED`: the dump still does not cover the separate remapper control
    windows at `+0x8080`. No alias, transform mutation, protected-boundary
    read, or isolation bypass was observed.
11. Sent the Samsung upload power-down command; host journal records disconnect
    then native `04e8:6861` return at 12:39:52. Verification 013 restored the
    original complete LOW partition hash. Verification 014 performed one new
    normal boot and proved LOW, force 0, sink 0, dload master 1, selftest
    `fail=0`.
12. Implemented `tools/sm8150_shrm_live_dump_analysis.py` and focused tests.
    Public manifest SHA-256 `ab1ce816…`; ignored private analysis SHA-256
    `ed5c39e9…`. Current state remains `NO_BOUNDARY_BYPASS_OBSERVED`.

## 2026-08-25 — Experiment 014 live GF(2) bank-hash recovery

1. Implemented a static AArch64 timing probe and target-fixed A90P1 runner.
   Probe source SHA-256 is `f5788486…`; binary SHA-256 is `552432c1…`.
   Exact target binding required SM-A908N/SM8150, V2321 `0.9.285`, kernel
   `4.14.190-25818860`, LOW, force-upload 0 and dump-sink 0.
2. `REFUTED`: cached anonymous RAM plus EL0 `DC CIVAC` alone is a sufficient
   DRAM classifier on this target. The results remained LLCC-confounded and
   were excluded from the recovered matrix.
3. Reconstructed the non-secure ION path. The live misc identity was `10:94`;
   flags-zero `user_contig` uses one SG entry and the exact kernel mmap path
   applies write-combine. Exact source commit is `510d909e…`; `ion.c` and
   `ion_cma_heap.c` hashes are `55dae52a…` and `3687c1c7…`. Secure heaps were
   enumerated but never selected.
4. Bound one 16-MiB allocation to PA `0xf0400000..0xf13fffff` using the unique
   256-page-aligned `/proc/kpageflags` buddy-transition window. The dma-buf
   remained pinned and a second scan found zero changed/lost pages.
5. Measured symmetric `B->A->B`/`A->B->A` reopen sequences against same-address
   baselines with 64 PA pairs and normally 1001 repetitions per pair. CPU7 was
   fixed at 2,841,600 kHz, DDR BW governor `performance` at reported `7980`,
   and CNTFRQ was 19.2 MHz.
6. `PROVED`, observed rank-relative bits `0..23`: PA16..PA23 XOR into the
   three-dimensional bank row space generated by PA13..PA15. One equivalent
   basis is `0x9d2000`, `0xa74000`, `0x4e8000`; basis labels are arbitrary.
   PA9/PA10 are `SUPPORTED` as additional independent channel-like selectors.
7. Four held-out kernel vectors have p10 >=536 milli-ticks; four one-bank-bit
   negatives have p90 <=222, leaving a 314 milli-tick gap. Same-row `D=0x800`
   controls remain within +/-6 milli-ticks. This `REFUTES` the Experiment-011
   no-XOR bank formula as the complete silicon bank map.
8. Implemented a pinned exact-firmware/SHRM literal audit. The real 64-KiB
   snapshot has no occurrence of any of the seven non-zero bank-row masks. The
   nine firmware images have zero aligned u32 hits; four apparent TZ matches
   are offset-mod-4 one inside monotonic u64 address tables stepping by
   `0x200000`. Direct literal attribution is `REFUTED`.
9. No MMIO, SMC, partition, firmware, EL2/EL3, XPU or protected-memory write
   occurred. The temporary ION node and remote probe were removed. Final exact
   V2321 health reports selftest `fail=0`, battery 100%.
10. Public timing, literal-audit and health manifest SHA-256 values are
    `7dc5050c…`, `50cdec42…`, and `e8219a53…`. Current classification is
    `NORMAL_RAM_HIDDEN_BANK_HASH_PROVED_NO_ALIAS_OR_BYPASS`; no physical-to-DRAM
    alias, transform mutation or boundary bypass was demonstrated.

## 2026-08-25 — Experiment 017 exact XBL MC table/read-copy cross-reference

1. Kept the phase host-only and read-only. The exact XBL input is 4,194,304
   bytes with SHA-256 `e73a07a0…`; no device, SMC or MMIO action occurred.
   Conceptual Experiments 015 (normal-RAM alias) and 016 (protected-boundary
   reach) remain reserved and `NOT ELIGIBLE`; 017 satisfies neither gate.
2. `PROVED`: VA `0x146b1218` maps through an exact ELF PT_LOAD to file offset
   `0x630b8`. The table has 122 nonzero aligned u64 addresses and a zero
   terminator at index 122; inclusive SHA-256 is `d5042980…`. Its structural
   shape is 30 four-instance MC groups plus two global entries.
3. `PROVED`: all 12 exact `qhs_mc +0x400/+0x404/+0x4d0` candidates are covered.
   `PROVED`: qhs_mccc `+0x118` and qhs_mccc_master `+0x294` are excluded from
   this table only. Existing Top-5 order is unchanged; coverage adds
   independent observation confidence, not semantic likelihood.
4. `PROVED`: cross-checking `tools.shrm_dump_decode.load_plan()` yields set0
   `100/430`, set1 `4/64`, union intersection `100`, table-only `22`, and
   SHRM-only `370`. This is address-list convergence only, not semantic
   identity or writer attribution.
5. `PROVED`: the exact helper range
   `0x146ae138..0x146ae18c` (end-exclusive, file `0x62318`, length `0x54`,
   SHA-256 `f325a8bf…`) statically constructs sentinel prefill followed by
   table-derived 32-bit loads and conditional stores to distinct VA
   `0x146bf300`. Identified store bases are only X12/X8, so this exact range
   is `REFUTED` as a candidate-register programming/mutation path.
6. The helper's code range is bounded, but traversal is zero-sentinel-only and
   has no independent hard 122-entry cap; the exact on-disk table terminates at
   index 122. Successful completion, partial/sentinel output,
   coherent/atomic/current status, MMIO side effects/faults, mutable runtime
   table contents/lock, post-boot writability, indirect BLR/tail reachability
   and current-boot execution remain `UNKNOWN`.
7. `PROVED`: a complete scan limited to direct BL instructions in file-backed
   executable PT_LOADs finds exactly two static callsites, at
   `0x146ae26c/file 0x6244c` and `0x14839f44/file 0x20f44`. No current-boot
   execution claim is made.
8. Generated the public manifest with:
   `python3 tools/sm8150_xbl_mc_snapshot_xref.py --output evidence/manifests/017-xbl-mc-snapshot-xref-20260825-01.manifest.json`.
   Manifest/tool/focused-test SHA-256 values are
   `b1db2123…` / `2baa9e3d…` / `5b0f6f3e…`; 20 focused tests and all 279
   repository unittest-discovery tests pass. The independent raw-byte review
   was a read-only re-derivation with no emitted
   artifact and therefore no review-artifact hash.
9. Current classification remains
   `TABLE_DRIVEN_REGISTER_READ_COPY_PATH_WRITER_AND_TRANSFORM_RELATION_UNKNOWN`;
   overall state remains Class C transform observation only. The earlier
   symbolic AArch64 store xref/backward-slice discriminator is covered by
   Experiments 018–022; unresolved dynamic bases, consumers and writers remain
   `UNKNOWN`, and no broad MMIO scan/device action is authorized. The
   subsequent Experiment 024 integration records the bounded resolution of
   the false-negative path; Experiment 025 later closes the intended static
   platform-query binding without closing runtime order or base currentness.

## 2026-08-25 — Experiment 018 XBL MC writer cross-reference Stage 1A

1. Kept the phase host-only and read-only. The exact XBL input is 4,194,304
   bytes with SHA-256
   `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`;
   no device, SMC or MMIO action occurred. Experiments 015 (normal-RAM alias)
   and 016 (protected-boundary reach) remain reserved and `NOT ELIGIBLE`.
2. Inventoried the four exact bases and 12 target addresses as little-endian
   u32/u64 views with file offsets, mapped VAs, alignment and PT_LOAD class.
   Each target's single 8-byte table encoding yields both the one aligned u64
   match and overlapping one aligned u32 match at the same file offset; these
   are two views of one table entry, not independent literals, with no separate
   target literal elsewhere. Only base
   `0x09260000` has an aligned outside-table u32, at file `0x80154` / VA
   `0x148bc254` in RWE; all bases have zero aligned u64 occurrences.
3. The exact file-backed PT_LOAD census is RX4/RWE2/RW3/OTHER0. Strict scalar
   STR W/X unsigned-immediate recognition is RX6945/RWE5169. Matching offsets
   are RX `{0x400:7,0x404:2,0x4d0:2}` and RWE
   `{0x400:1,0x404:1,0x4d0:1}`, 14 total; seven RX candidates are SP-based and
   the RWE three remain ambiguous code/data.
4. Stage 1A performs no base/effective-address resolution. The public
   resolved hit count is JSON `null`, not zero, and literal/offset equality is
   not a writer proof. No REFUTED writer claim is made; writer identity,
   unsupported/other store forms, dynamic/cross-block paths, AOP/TZ paths,
   runtime semantics/mutability, alias and bypass remain `UNKNOWN`.
5. The next discriminator was Stage 2A, limited to the four non-SP RX
   candidates (X8/X19); the seven SP candidates remain runtime-derived and the
   three RWE candidates remain ambiguous. An independent Luna raw-byte
   feasibility scan agreed on the 14 candidates and found no resolved target
   in its broader model, but emitted no artifact; this is supportive review,
   not manifest `PROVED` evidence.
6. Generated the public manifest with
   `python3 tools/sm8150_xbl_mc_writer_xref.py --output evidence/manifests/018-xbl-mc-writer-xref-stage1a-20260825-01.manifest.json`.
   Tool/ focused-test/manifest SHA-256 values are
   `9806b64c01f9965161966c88bbf5b943d953e790664c3136b2a116da63f8dc57`,
   `b5fbf50e545b9df86d45ac012106d8905af231d9e94b0b2dd1927ec365da13d8`, and
   `8861a5626576fac32a83c295c34be63f91fd5e3f4b434490d567fb2984bb192d`;
   8 focused and all 287 repository unittest-discovery tests pass. All 54
   public manifests parse as JSON, regeneration is byte-identical and the
   manifest mode is `0644`. Date: 2026-08-25 KST.

## 2026-08-25 — Experiment 018 XBL MC writer cross-reference Stage 2A

1. Kept the phase host-only and read-only. The exact XBL input remains
   4,194,304 bytes with SHA-256
   `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`;
   no device, SMC or MMIO action occurred.
2. Limited the model to the four pinned non-SP RX Stage 1A candidates:
   `0x14844b20/0x2bb20/X8/+0x400`,
   `0x14844c78/0x2bc78/X8/+0x4d0`,
   `0x146a70c0/0x2d6090/X8/+0x400`, and
   `0x14935bf4/0x312bc4/X19/+0x400`. Seven SP candidates remain
   runtime-derived and three RWE candidates remain ambiguous.
3. The same-block backward slice is capped at 128 aligned instructions. It
   supports only 64-bit MOVZ/MOVK and same-register `ADRP Xn; ADD Xn,Xn,#imm`.
   32-bit wide-move chains, MOVN, MOV aliases, wrong-source ADD, loads, MADD,
   branches/calls/returns, inbound direct-branch entries and all other
   unsupported definitions fail closed.
4. `PROVED`: exact outcomes are two `NO_DIRECT_CONSTANT_DEFINITION` results
   stopped by `WINDOW_LIMIT`, one `UNSUPPORTED_REGISTER_DEFINITION` for LDR
   X8 at `0x146a70b4`, and one `NO_DIRECT_CONSTANT_DEFINITION` stopped by a BL
   `CONTROL_TRANSFER` before the older X19 definition. No base resolves and no
   effective address equals a target.
5. The exact result is `resolved_base_count=0`,
   `resolved_target_hit_count=0`, classification
   `NO_RESOLVED_TARGET_STORE_WITHIN_STAGE2A_DIRECT_DEFINITION_RX_MODEL`.
   This refutes only the supported Stage 2A direct-definition path for the
   four stores; it does not prove writer absence. Writer identity, unsupported
   or dynamic paths, runtime execution/semantics/mutability, GF(2), alias,
   bypass, protected reach and other firmware remain `UNKNOWN`.
6. Generated the public manifest with
   `python3 tools/sm8150_xbl_mc_writer_stage2a.py --output evidence/manifests/018-xbl-mc-writer-xref-stage2a-20260825-01.manifest.json`.
   Tool/test/manifest SHA-256 values are
   `eb0a8ce21154d97d052de9f7e4e0de40f85087a8cb517179f7c44332e9d85eb0`,
   `1272fadb0bcc6b883f74577284312ee34678975fa7ba60377d05d86927960b3b`, and
   `eeed732e4a6cecd60453e9088d8c3d4c7ed207a1e7c723bae91e27033d134a4b`.
   Fourteen focused and 301 full unittest-discovery tests pass; all 55 public
   manifests parse as JSON and regeneration is byte-identical. Date:
   2026-08-25 KST; mode `HOST_ONLY_READ_ONLY`; public mode `0644`.

## 2026-08-25 — Experiment 018 XBL MC writer cross-reference Stage 2B

1. Kept the extension host-only and read-only over the exact 4,194,304-byte
   XBL (`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`);
   no device, SMC or MMIO action occurred. Experiments 015 and 016 remain
   reserved and `NOT ELIGIBLE`.
2. Limited analysis to the two Stage 2A `WINDOW_LIMIT` RX X8 stores at
   `0x14844b20/0x2bb20/+0x400` and `0x14844c78/0x2bc78/+0x4d0`. The maximum
   512-predecessor same-block model added only same-register 32-bit W-wide-move
   semantics, with W writes zero-extending into X8; mixed-width and unsupported
   definitions remain fail-closed.
3. Exact pins are `MOVZ W8,#0xf000` at VA/file
   `0x14844580`/`0x2b580` and `MOVK W8,#0x1489,LSL#16` at
   `0x1484458c`/`0x2b58c`. Both chains resolve X8 value `0x1489f000`; their
   computed XBL virtual-address values are `0x1489f400` and `0x1489f4d0` at
   distances 360/357 and 446/443. Both are outside file-backed PT_LOADs and
   neither numerically matches a target.
4. The exact result is `resolved_base_count=2`,
   `resolved_numeric_target_hit_count=0`, remaining Stage 2A unresolved count
   2, and classification
   `NO_NUMERIC_TARGET_ADDRESS_MATCH_WITHIN_STAGE2B_W_WIDE_MOVE_RX_MODEL`.
   `PROVED` is limited to this static numeric computation; `REFUTED` is limited
   to numeric equality under this model. VA-to-PA translation/identity,
   physical destination/ownership, execution, writer identity, semantics,
   mutability/lock, GF(2), alias, bypass and unsupported/dynamic paths remain
   `UNKNOWN`; no writer absence is claimed.
5. Generated the public manifest with
   `python3 tools/sm8150_xbl_mc_writer_stage2b.py --output evidence/manifests/018-xbl-mc-writer-xref-stage2b-20260825-01.manifest.json`.
   Tool/test/manifest SHA-256 values are
   `aa35d8b303a7ea32a086d601b1f08390b1cad0932f105209ac337f394813dbcb`,
   `af7ca7b46550dda13e85e517c0c1c1df19b6414549d06415316b6d428e020fc9`, and
   `a4715112e27c74e5548ecb49f09106c236146c8a0216c87446ddbd3c355ccca6`;
   10 focused and 311 full unittest-discovery tests pass. All 56 public
   manifests parse as JSON, regeneration is byte-identical and the manifest
   mode is `0644`. Date: 2026-08-25 KST.

## 2026-08-25 — Experiment 018 XBL MC writer cross-reference Stage 2C

1. Kept the stage host-only and read-only over the exact XBL
   (`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`);
   no device, SMC or MMIO action occurred. The scope is the remaining non-SP
   RX X8 store at `0x146a70c0/0x2d6090`, and Experiments 015/016 remain reserved
   and `NOT ELIGIBLE`.
2. Pinned the writer `[0x146a70a4,0x146a70dc)` (file `0x2d6074`, 56 bytes,
   SHA-256 `a50aaeb45c498a63e91704fc0ec4550b120ca0c1b691c238736b0532136dad6c`),
   wrapper (108 bytes,
   `24008bb23f54ed515774f020ac62cb3973b74dc57a41acd2bd358567863ad436`) and
   lookup (272 bytes,
   `9e54cfe4e5e2fad580b92c0853513f1be25046abeb00ff76db83d87ad3036046`).
   The executable PT_LOAD scan found exactly one direct BL caller at
   `0x146a67a4/0x2d5774`.
3. Decoded critical success-path pins: wrapper `X1=SP` to lookup, lookup-result
   branch to `0x146a67a0`, then `X0=SP` to the unique writer; lookup `X19=X1`,
   bounded W10 index/count loop, ID compare branch into the row pointer load,
   `LDR X8,[row+8]` and `STR X8,[X19]`; writer descriptor `+0x20` guard,
   `LDR X8,[X0]` and `STR W9,[X8,#0x400]`.
4. Parsed the retained table at `0x146aa4d0/0x2d94a0` as 48×16 bytes with
   SHA-256 `47a7f6195703f2f4d27cbe1e8bd0cc976600453a3ba4aebba98736ef8e03906e`.
   The following count u32 at `0x146aa7d0/0x2d97a0` is 48; all IDs and nonzero
   pointers are unique and all reserved +4 fields are zero. All 48 rows emit
   ID/base/possible `base+0x400`/numeric-match; zero target-base pointer matches
   and zero possible effective target matches were found.
5. The 48 values are a conservative possible-value superset because descriptor
   `+0x20` eligibility is runtime-dependent; no claim says all rows execute.
   Values are XBL effective-address values. `PROVED` is limited to the static
   path/table evidence; `REFUTED` only numeric target equality in this model.
   VA-to-PA/identity, physical destination/ownership, runtime mutation/currentness,
   indirect callers, execution, writer identity outside this path, semantics,
   mutability/lock, GF(2), alias and bypass remain `UNKNOWN`.
6. Generated the public manifest with
   `python3 tools/sm8150_xbl_mc_writer_stage2c.py --output evidence/manifests/018-xbl-mc-writer-xref-stage2c-20260825-01.manifest.json`.
   Tool/test/manifest SHA-256 values are
   `d53d820eb8d10e8417247fabbc0e3196f73c73584a6b7d79d583a96834c34d53`,
   `92c95472940937a7001fe48dd055b4c598fd290c28a1e15757d1c297ebf5f526`, and
   `e096562a35da93a1dac10a1651fc7eff08eecf05dafca4a789bae2fd50540c01`.
   Nine focused and 320 full unittest-discovery tests pass; all 57 public
   manifests parse as JSON, regeneration is byte-identical and mode is
   `0644`. Date: 2026-08-25 KST.

## 2026-08-26 — Experiment 018 XBL MC writer cross-reference Stage 2D

1. Kept the stage host-only/read-only over the exact XBL
   (`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`).
   The remaining non-SP RX candidate is `0x14935bf4/0x312bc4`, and no device,
   SMC or MMIO action occurred.
2. Pinned function `[0x14935960,0x14935edc)` / file `0x312930`, 1,404 bytes,
   SHA-256 `68739df6f843f790376eb0af47da22f0af5ebeb2421f05d29c3b5a8673983fd9`;
   the candidate is `STR X9,[X19,#0x400]`. The executable PT_LOAD census found
   one direct BL caller at `0x14949eec/0x326ebc` and zero direct B callers.
3. The caller pins W0=0, CBZ W0 to `0x14949ee4`, X1=SP+0xe0, W2=0 and the
   direct call. The callee pins W20=W0, W0≤7/X1-nonzero guards, the exact
   `SUB W12,W20,#2; CMP W12,#3; B.CS 0x14935aac` dispatch, W20≤1,
   X23 selection, X24=`0x85e9e570`, and MADD X19 with multiplier `0x600`.
   The `CBNZ W0,0x14935ce8` after the pre-MADD direct call makes W0=0 a
   runtime success precondition. Intrinsic bases are
   `0x85e9e570`/`0x85e9eb70`; the direct caller narrows W0 to zero.
4. The initializer `[0x14844580,0x14844dac)` / file `0x2b580`, 2,092 bytes,
   SHA-256 `65e117b99fd109cbb01531bd70fc2befe70c0b672a01afe6dd523bbebf1486cb`
   statically forms X8=`0x1489f000`, X5=`0x1483c904`, and stores X5 at
   `[X8,#0x3b0]`, resolving slot `0x1489f3b0`. Its runtime execution/later
   mutation remain `UNKNOWN`. The resolved target range
   `[0x1483c904,0x1483c9e8)` / file `0x23904` has SHA-256
   `5c979955c6d1cdfd541766ca3ea6964460803d61aa3d07bed0c74f60d3eec34e`, zero
   BL/BLR/BR transfers, one RET, in-range direct branches, and zero X19-X29
   definitions under an exact instruction-class/write-set audit. The
   pre-MADD direct callee range `[0x1493641c,0x1493697c)` has SHA-256
   `43fa9c70453b7ad1d8ff88d4ca07b375d2dc6b3b06e805339b2ad1927e4487e0`, a
   unique direct caller at `0x14935abc`, and pinned X24/X23 save/restore on
   its one normal RET.
5. Under explicit normal-return and static-initialized-slot conditions, the
   direct effective value is `0x85e9e970`; the intrinsic second value is
   `0x85e9ef70`; neither matches the 12 targets. The values lie in the
   memory-only tail of RW PT_LOAD `0x85e44000` (`filesz=0x43620`,
   `memsz=0x66038`, `p_vaddr=p_paddr`). Runtime import target/currentness,
   VA-to-PA/identity and physical destination/ownership remain `UNKNOWN`.
6. Generated the manifest with
   `python3 tools/sm8150_xbl_mc_writer_stage2d.py --output evidence/manifests/018-xbl-mc-writer-xref-stage2d-20260826-01.manifest.json`.
   Tool/test/manifest SHA-256 values are
   `95e53e25f288ba1ef09996ff73919c2ad1dd4186c4fec41dc84216d715ee8b26`,
   `23c91a14c16706b920b4c3556e85844543dc99545a2b7b6d864a8c09d35f6136`, and
   `48c7aa83d30844f1d42094fcb0f8d7dd13cf44265f9961167912792d014661c4`.
   Fourteen focused and 334 full unittest-discovery tests pass; all 58 public
   manifests parse as JSON, regeneration is byte-identical and mode is
   `0644`. Date: 2026-08-26 KST.

## 2026-08-26 — Experiment 018 XBL MC writer cross-reference Stage 2E

1. Kept the stage host-only/read-only over the exact XBL
   (`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`), with
   no device, SMC or MMIO action. Scope is only the seven RX SP-base
   candidates; the three RWE candidates remain outside this stage.
2. Independently pinned F1 `[0x1492df68,0x1492e718)` / file `0x30af38`, size
   `0x7b0`, SHA-256
   `941753add8e6b033096df1bce4b0950ed2ebaec8625e3147e0ba457279325e3b`, and
   F2 `[0x14936ae0,0x14937c18)` / file `0x313ab0`, size `0x1138`, SHA-256
   `861cf19f8c6c27e4be5f1dfa8b662d0723ed5b1d02a115266c00ab4165bf058e`.
   Direct-BL callers are exactly `0x1492ed64/0x30bd34` and
   `0x14936050/0x313020`; direct-B counts are zero.
3. Decoded all seven exact STR W/X unsigned-immediate forms with base SP.
   F1's local allocation is `0x5a0` and F2's is `0x490`; every access is
   wholly within its allocation. Range-hash-bound manifests within the
   recognized SP-write classes contain only the four frame updates per function;
   the explicit memory-writeback
   audit accounts for exactly four recognized sites per function (two SP and
   two non-SP). Recognized BR/BLR counts are zero, and the all-file-backed-
   executable-PT_LOAD-words direct-entry census finds one external BL to each
   function start and zero external entries to interiors. An independent GNU
   objdump 2.46 disassembly census, pinned by each exact range hash and not
   recomputed by this tool, reports F1 as 492 instructions with 134
   writeback-free SP-base accesses and F2 as 1,102 instructions with 168 such
   accesses. The same-function immediate-control CFG (BL modeled as
   fallthrough) has no recognized SP-write-class instruction after allocation
   on a path to each candidate; unsupported instruction effects remain
   `UNKNOWN`.
4. `PROVED` is limited to architectural SP-relative encodings, exact mappings,
   frame bounds and recognized-class static write audits. `SUPPORTED` is limited
   to the normal stack-frame/conforming-call premise, with normal-return/callee
   SP restoration separate from the same-function CFG result. `REFUTED` only interprets these seven
   forms as non-static absolute/controller-base stores within that premise.
   Absolute stack address, stack integrity/rebasing, VA-to-PA, physical
   destination, execution, indirect callers and writer identity remain
   `UNKNOWN`; Experiments 015/016 remain `NOT ELIGIBLE` and Class C is
   unchanged.
5. Generated the manifest with
   `python3 tools/sm8150_xbl_mc_writer_stage2e.py --output evidence/manifests/018-xbl-mc-writer-xref-stage2e-20260826-01.manifest.json`.
   Tool/test/manifest SHA-256 values are
   `16519db59009efc1d55bee8ef37046679261ba486703dcffd371bb639331cc74`,
   `174af64d6f536f2b44a8fe3301e53ea9d4ea5acfb50323fe783a2db714764563`, and
   `c52babccfcfe825df7477dffc9533754fe1afd656d3afd839a398b078477ee36`.
   Thirteen focused and 347 full unittest-discovery tests pass; all 59 public
   JSON files parse as JSON, regeneration is byte-identical and mode is
   `0644`. Date: 2026-08-26 KST.

## 2026-08-26 — Experiments 019–022 config/CDT integration

1. Integrated the four committed host-only, read-only experiments from commit
   `3dfa725`. Independent validation records **157 focused PASS**, **504 full
   unittest PASS**, four byte-identical manifest regenerations, and cached-tree
   review `PASS`. No device, SMC or MMIO action occurred. Class C remains
   `TRANSFORM ONLY`; Experiments 015/016 remain `NOT ELIGIBLE`.
2. Experiment 019 is `PROVED` only for strict syntactic candidate pair arrays
   in two key domains. The arrays are not proved register tables or consumers;
   absolute keys do not hit ranked MC bases, and section/base semantics,
   consumers and writer identity are `UNKNOWN`. The bounded stored/exact-wide/
   ORR audit finds `0x00003333` and `0x00300014` absent and two adjacent
   `0x00300033` sequences. No writer absence is claimed.
3. Experiment 020 is `PROVED` only for its bounded register-offset census and
   `SUPPORTED` for treating the largest RWE segment as a candidate segment.
   The narrow classifier has a pinned false negative at `0x14868a50`, so a
   general zero-walker claim is `REFUTED`. General walker, DCB consumer,
   runtime-base and writer identity remain `UNKNOWN`.
4. Experiment 021 is `PROVED` for one pinned bounded-copy target's direct
   census: seven `BL`, zero `B`, five local labels `{0,1,2,15,16}`, and two
   unlabelled sites. Other-section, indirect, other-copy and global delivery
   are `UNKNOWN`, not refuted; only local label completeness is `REFUTED`.
5. Experiment 022 is `PROVED` for `430/470/122/492` across two enumerated
   retained-evidence channels and their sparse observed density. Completeness
   is `REFUTED` by known `0x09248080`; implemented-register coverage remains
   `UNKNOWN`.
6. At this historical integration boundary, Experiment 023 was explicitly
   `WITHHELD/NO-GO` and not published. A later reconciliation retains its audit
   artifact as merge-history evidence without promotion; Experiment 023R is
   the separately repaired result.
   Its timing protocol is not comparable to Experiment 014 (fixed order, half
   warmup, `ISB`, summed reopen without `/2`); physical-allocation PA
   provenance is missing so a `+0x1000` countermodel fits the labels; and the
   full GF(2) matrix is non-unique. `PA24=b1^b2` is `SUPPORTED` only. Raw
   evidence remains private.
7. Experiment 024 was subsequently completed and integrated from commit
   `c62c33e`; its qualified static result is recorded below. The remaining
   current-base, runtime, semantic, and destination boundaries are
   `UNKNOWN`, including the unresolved `BLR X9` at `0x1486ac1c`. No device
   action or MMIO write occurred. See `docs/NEXT_EXPERIMENT_SCORECARD.md`.

## 2026-08-26 — Experiment 024 exact XBL six-byte walker integration

1. Integrated commit `c62c33e` as a host-only, read-only static analysis. The
   exact XBL input, two design-source snapshots, and Experiment 019 dependency
   are hash-pinned; no device, SMC, MMIO, protected-memory, normal-RAM, or
   activation action occurred. Class C remains `TRANSFORM ONLY`, and
   Experiments 015/016 remain `NOT ELIGIBLE`.
2. `PROVED`: the exact walker `[0x148689a0,0x14868a64)` is 196 bytes with
   range SHA-256
   `08265307d79c5f82b85266613f241ae160151dcfe51b19da108f9ad6c4e15021`.
   `UMADDL` uses a six-byte stride; flags/offset/value are loaded at `+0/+2/+4`;
   `0x8000` is the exact terminator; `B.EQ` returns before the conditional
   `STR W14,[X15,X13]`; and `LDRB` zero-extends the stored byte to a 32-bit
   word. Other nonterminator flag combinations may skip the store and flag
   semantics are `UNKNOWN`.
3. `PROVED`: an all-file-backed executable PT_LOAD census finds exactly three
   direct callers, `0x14868640`, `0x1486867c`, and `0x14868698`. Five nonzero
   provider alternatives select XBL-resident tables. Selector `== 0xf` has
   53 unique offsets; selector `!= 0xf` has 127; their cross-alternative
   syntactic union has 170 aligned offsets spanning `0x7000..0x7de0`; and
   the five alternatives contain 221 nonterminator records. Provider3 on
   selector `== 0xf` writes no pointer, returns count zero, and the pinned
   zero-count path reaches `RET` before table dereference.
4. `PROVED`: the five table alternatives are starts/counts/hashes
   `0x14880bee/43/f7b7ca7dae26320d69c87c9b4c59472eb0933aa7216936ed7564f78b770f643c`,
   `0x14880e70/90/8c26948bb9e7e24ae9c2d950412e851dd1e60e412aa4f82d7936c247103ac240`,
   `0x14880ba0/13/eac051599765de4842c6ecf7a6076813eac93a07cd052d829787b1095fa353b1`,
   `0x14880cf0/64/7c0fb81701455fb380cf4a2d1af4120a444a6be66235c2a87dad5ca2c932711f`,
   and `0x14880b40/16/1c596a44cbec1cdbcc5b23e81eccde1c20556b17ab3c434ef393c29ab63aa015`.
   Counts include the exact `0x8000/0/0/0` terminator.
5. `PROVED`: the two design-source UFS blocks are byte-identical (4,464
   bytes, SHA-256
   `cea31db3785be5916a1ff08d1c99b92155a7914b07d09ecb6c3638d8c16ff10a`).
   Under initialized-base retention, all 170 symbolic `BASE+offset`
   destinations lie in broader `ufshc` `ufs_phy` `[0x01d87000,0x01d87e00)`;
   167 lie in standalone `ufsphy_mem` `[0x01d87000,0x01d87da8)`, and
   `0x7dc4`, `0x7dd8`, `0x7de0` are the three beyond that narrower resource.
   The separate Experiment 019 eight-byte representation is structurally
   distinct; semantic DCB identity remains `UNKNOWN`.
6. `SUPPORTED`: the direct-call positive control supports a table-driven UFS
   interpretation only under initialized-base retention and store reach. The
   base is `UNKNOWN` because helper `0x1486abec` reaches runtime-BSS `BLR X9`
   at `0x1486ac1c`; selector/runtime execution, reached-store subset, flag
   semantics, live-DTB equality, DCB semantic alias/global consumer/writer,
   DDR/MC relation, GF(2), alias/bypass, and actual current destinations are
   also `UNKNOWN`. All 170 mappings are conditional symbolic supersets, not
   one execution/current destination set. No unconditional UFS or DDR
   refutation is made.
7. Tool/test/manifest SHA-256 values are
   `f0ccb5648b2cce4ab2b835e23c4658c976df9779b0ae6273767b59cc7b6a58bf`,
   `97c58a22c5c3e7e6cd5b7bc4f8d181c74050b2b530afac03eba3fbb946577f6d`, and
   `f9ac896d396650075ca9e66d8d805a2deaf40b0207e819cd94f8d638c8121b01`.
   Validation is 30 focused and 534 full unittest-discovery tests, 64 public
   JSON manifests, byte-identical regeneration, and two independent review
   `PASS` results recorded in
   `docs/EXP024_INTEGRATION_REVIEW_2026-08-26.md`. The public manifest is
   30,400 bytes, mode `0644`, at
   `evidence/manifests/024-xbl-six-byte-walker-20260826-01.manifest.json`.
8. Experiment 025 is the completed bounded static follow-up for the unresolved
   platform-query binding; its integration and exact claim boundaries are
   recorded below. Experiment 026 is now independently re-derived, committed,
   and integrated in the following section; all 025 ranges remain
   dependency-only for that result.

## 2026-08-26 — Experiment 025 XBL platform-query binding integration

1. Integrated commit `d743150` (parent `a68d2f1`) as a host-only, read-only
   static analysis of the exact SM8150 XBL. The exact input is 4,194,304 bytes
   with SHA-256
   `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.
   No device, SMC, MMIO, protected-memory, normal-RAM, or activation action
   occurred. Class C remains `TRANSFORM ONLY`; Experiments 015/016 remain
   `NOT ELIGIBLE`.
2. `PROVED`: platform-query helper `[0x1486abec,0x1486acac)` has one pinned
   direct caller at `0x1486847c`; it passes `X0=SP+0x10`, not main context
   `X19`. The helper loads, forms the attach-output address for, and reloads
   runtime slot `0x14890590`. The attach path pins service ID `0x02000139`
   through semantic `MOVZ/MOVK` instruction words.
3. `PROVED`: the static seed derives `X0=0x14875668` and outer record
   `X1=0x14875590` with count five; it selects descriptor `0x14824ab8`, factory
   `0x1484a880`, constructed object candidate `0x1488f418`, inline vtable
   `0x14824ad0 + 0x48`, and callback `0x1484a9d4`.
4. `PROVED`: bounded callback flow
   `0x1484a9d4 -> 0x1484a730 -> 0x1484a824 -> 0x1484aa30 -> 0x1484a854`
   has one recognized output write at `0x1484a9f4` to helper `SP+0xc`.
   Recognized nested recursion/status writes are only at `0x1488f3f9`,
   `0x14890ba0`, and `0x14890b90`; the bounded status helper has one decoded
   MMIO read at `0x01fc8004` and zero recognized MMIO writes.
5. The all-file-backed executable census plus pinned basic-block loop model
   accounts for recognized slot/address/list xrefs and is conservative coverage,
   not arbitrary-write absence. `SUPPORTED`: conditional intended binding can
   populate the slot and the recognized callback flow does not write caller
   context `+8`. `UNKNOWN`: runtime registration/order, slot value/object
   identity, actual `BLR X9` target, alternate BSS mutation/global aliases/
   unsupported writes, complete arbitrary-write absence, full `0x01d80000`
   base currentness, and live mapping or authority. Experiment 024's UFS
   mapping remains conditional.
6. Tool/test/README/manifest SHA-256 values are
   `16e9584a3043d76670c66b6a517e56c87267645506c1f76a040737d731b168b9`,
   `219227a927acb8a98d8e7294150c154b916795e709ab02bb076b946d8d7bb687`,
   `eb97735c91b79fb13f8feb40e9b98ffd7f2aa71a9dcc2fbe479fcdcf2e4014a3`, and
   `d3c405d7c8d23dc1cd65b1c578b4b4ce931d9bdfeb303c892e9c0c145c4c81cc`.
   The public manifest is 28,132 bytes, mode `0644`, at
   `evidence/manifests/025-xbl-platform-query-binding-20260826-01.manifest.json`.
7. Validation is 22 focused and 556 full unittest-discovery PASS, Python
   byte-compilation PASS, 65 public JSON manifests parsed, two fresh
   generations byte-identical, and two independent artifact-review PASS
   results. The durable integration-doc review is
   `docs/EXP025_INTEGRATION_REVIEW_2026-08-26.md`; two independent
   common-document reviews returned `PASS`.
8. Initial hostile artifact review findings were the B-vs-BL mask, stale
   ADRP/clobber/control-flow/BR false xrefs, missing semantic MOVZ/MOVK ID pin,
   bootstrap RET-range ambiguity, and incomplete Definition-of-done metadata.
   The committed artifact repairs the branch mask, page/clobber/CFG and false
   xref handling, semantic ID words, bootstrap range ending at `0x1484aa74`
   with `RET` at `0x1484aa70`, and target/precondition/non-applicable live
   artifact/publication/repetition metadata. Two independent final artifact
   reviews returned `PASS`; this does not pre-approve the common-document
   integration review.
9. The completed Experiment 026 result is recorded below and does not upgrade
   runtime order, slot value, actual `BLR` target, base currentness, or live
   mapping. Experiment 027 is now completed and integrated as a bounded DCB
   consumer/writer complement; its exact result and artifact pins are recorded
   in the current integration section. The subsequent Experiment 029 inventory
   and 031 scalar follow-up are recorded in the later sections; external Claude
   Experiments 028/030 remain outside and unreviewed here.

## 2026-08-26 — Experiment 026 XBL dispatch/order and slot-escape integration

1. Integrated commit `0305a03` as a host-only, read-only static analysis of
   the exact SM8150 XBL. The exact input is 4,194,304 bytes with SHA-256
   `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.
   The committed 025 dependency is size 28,132 with SHA-256
   `d3c405d7c8d23dc1cd65b1c578b4b4ce931d9bdfeb303c892e9c0c145c4c81cc`.
   No device, SMC, MMIO, protected-memory, normal-RAM, write, or activation
   action occurred. Class C remains `TRANSFORM ONLY`; Experiments 015/016
   remain `NOT ELIGIBLE`.
2. `PROVED`: registration helpers `[0x1482ecb4,0x1482edac)` pin the exact
   24-byte node shape (object/ID/next at `+0x0/+0x8/+0x10`) and list head
   `0x14890f60`; initializer loop `[0x1482edac,0x1482f0b4)`; table header
   `[0x14875534,0x14875568)` has count 2, row start `0x14875538`, cursor
   `0x1487554c`, and derived stride `0x18`.
3. `PROVED`: bootstrap caller `[0x14852ce0,0x14852d70)`, veneer
   `[0x14843d20,0x14843d50)`, alternates `[0x14828338,0x14828360)` and
   `[0x14828b44,0x14828c80)`, dispatcher `[0x14864834,0x148648c0)`, callers
   `[0x148641a4,0x1486420c)`, `[0x1486420c,0x1486424c)`,
   `[0x148642dc,0x148644cc)`, and `[0x1485a2ec,0x1485a30c)` have exact
   local/control/data edges, including dispatcher base/stride/index guard and
   symbolic pointer escape `0x146b30c0 + runtime_index*0x3f8` for modeled index
   `0..1`, not an exact runtime base. `SUPPORTED`: memory-only initializer-pool
   shape `[0x146b30c0,0x146b38b0)`, two-row `0x3f8` geometry. Pool
   contents/runtime values remain `UNKNOWN`.
4. The complementary all-file-backed executable census scans 847,465 words,
   excludes 622 words covered by the 025 dependency, recognizes 9 direct
   accesses (3 writes and 6 reads) and 2 pointer escapes, and finds zero
   recognized writes whose access intervals overlap slot
   `[0x14890590,0x14890598)`. This is bounded recognized-form coverage, not a
   global writer-absence claim.
5. The result taxonomy is `ORDER_OPEN` and
   `PROVED_BOUNDED_NO_RECOGNIZED_SLOT_MUTATION`. Runtime execution/order, slot
   value, object identity, `BLR` target, base currentness, writer absence and
   live authority remain `UNKNOWN`.
6. Tool/test/README/manifest SHA-256 values are
   `61b4f993678527b7cb1b024b0e8f5cdf4b965a9bf3aedc8a2a12214c8d26a5f8`,
   `3f8aad6ed90b8c16d4bece5dc272e402ddd4f91af35ae1a294c53beb6d5d9b41`,
   `392631c3ef6298b23ef52bdfe085d723b7bd5451dd10483e5296e4ab4c6e3d24`, and
   `2139b5d230be78d822eda656f2856a229894167938227d34a614dcabf16c7885`.
   The public manifest is 64,027 bytes, mode `0644`, at
   `evidence/manifests/026-xbl-dispatch-order-slot-escape-20260826-01.manifest.json`.
7. Validation is 25 focused and 581 full unittest-discovery PASS, Python
   byte-compilation PASS, public JSON safety PASS, two fresh generations
   byte-identical, and exact-XBL semantic plus final decoder hostile reviews
   `PASS`. The durable integration-doc review is
   `docs/EXP026_INTEGRATION_REVIEW_2026-08-26.md`.
8. Final hostile review repairs covered shifted-register ADD/SUB semantics,
   ORR masks and LSL-only coverage, unsupported UBFM/SBFM/pair/literal/
   register-offset/exclusive/LSE forms, SIMD/sign-extension/unprivileged
   variants, MTE ADDG/SUBG, undefined extended-register encodings, stale
   literal taint, SP/XZR handling, writeback overlap, conditional list-head
   semantics, symbolic pool addressing, and interval-overlap slot detection.
   Adversarial synthetic controls cover decoder false positives/negatives,
   clobbers, control flow, and positive/negative slot overlap. Experiment 027
   is now integrated as the completed bounded DCB consumer/writer complement;
   its 73-site result and validation are recorded in the following section.
   The subsequent Experiment 029 inventory and 031 scalar follow-up are
   recorded in the later sections; external Claude Experiments 028/030 remain
   outside and unreviewed here.

## 2026-08-26 — Experiment 027 DCB consumer/writer complement integration

1. Integrated commit `7aa1df7` as a host-only, read-only bounded CFG/dataflow
   transform over the exact SM8150 XBL, `xbl_config--sdb2.bin`, and semantic
   public dependency pins. No device, USB, SMC, MMIO, protected-memory,
   normal-RAM, boot, activation, or write action occurred. Class C remains
   `TRANSFORM ONLY`; Experiments 015/016 remain `NOT ELIGIBLE`.
2. `PROVED`: the XBL input is 4,194,304 bytes with SHA-256
   `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37` and
   `xbl_config--sdb2.bin` is 4,149,248 bytes with SHA-256
   `0e9dfac1ddd0f9acc2cc899213e621490308f0cadf329814048edb7712e2484c`.
   Experiment 019 sections `{6,7,8,10,11,12}` and section-7 keys `0x400` and
   `0x404`, each with value `0x10000000`, revalidate across four `0x3404`-byte
   DCB blocks at file offsets `0x1079c`, `0x13ba0`, `0x16fa4`, and `0x1a3a8`.
3. `PROVED`: Experiment 020 supplies 67 register-offset loop sites and eight
   computed-address idioms. Two dependency-owned register sites are excluded;
   65 register sites plus all 8 computed sites are analyzed, with three
   computed idioms represented by complete loop contexts and five by local
   forms, for 73 sites total. The exact candidate setter is
   `[0x9fc06410,0x9fc0643c)` with direct caller `0x9fc023f0` in
   `[0x9fc023e0,0x9fc02430)`; runtime object-field arguments and current
   destination remain `UNKNOWN`.
4. The implemented census returns 71 `INDIRECT_OR_UNSUPPORTED`, 2
   `NO_TARGET_WITHIN_MODEL`, zero `DCB_CONSUMER_PATH`, and zero
   `MC_OR_SHRM_SYMBOLIC_TARGET`. Two nonexclusive
   `SECTION_READER_PROXIMITY_ONLY` hypotheses are `0x148aa758` to reader
   `0x148ab138` at signed `-2528`/absolute `2528`, and `0x148ab4f8` to the
   same reader at signed `960`/absolute `960`; threshold is `0x1000` and
   `link_proof` is `NONE`. Zero target labels are bounded-model results, not
   global absence claims. Runtime base/current destination, execution/order,
   writer/global consumer identity, aliases, register semantics, unsupported
   forms, indirect targets, and post-boot mutation remain `UNKNOWN`.
5. Tool/test/README/manifest SHA-256 values are
   `11a4dab37e9a54e74ec93fba7c89524de1e77c7e71b86f105dd167d77780bcb9`,
   `683da291f4421b3af0c75be21093b2cad3bbb3bf4933e4f2a70910cde4aa1cda`,
   `dd722225be2bcc5faf4e0cd08b60b5385d6a9fb9249e5e54d1c2ee6d128cefd0`, and
   `d11785969f16ba09155a2305eefd091158abfc515bc64cf94cb34d573a302277`.
   The public manifest is 334,847 bytes, mode `0644`, at
   `evidence/manifests/027-dcb-consumer-writer-complement-20260826-01.manifest.json`.
6. Validation is 35 focused and 616 full unittest-discovery PASS in 86.100 s,
   Python byte-compilation, 67 public JSON manifests parsed, two fresh
   generations byte-identical, public safety/no-clobber checks, and independent
   hostile review `PASS` after fixes. The durable integration review is
   `docs/EXP027_INTEGRATION_REVIEW_2026-08-26.md`.
7. Experiment 029 subsequently completed the bounded unsupported-frontier
   inventory, and Experiment 031 completed the separately reviewed
   source-qualified scalar follow-up; both results are recorded below. External
   Claude Experiments 028/030 remain outside and unreviewed here. No result,
   score, authority, or review from either external experiment is claimed.

## 2026-08-26 — Experiment 029 unsupported-frontier integration

1. Integrated host-only, read-only Experiment 029 from commit `a495bdc`. It
   scans only the exact 71 Experiment 027 ranges labelled
   `INDIRECT_OR_UNSUPPORTED`; it does not extend the 027 decoder, infer CFG
   reachability, execute firmware, contact a device, read MMIO, or perform a
   write. Class C remains `TRANSFORM ONLY`; Experiments 015/016 remain
   `NOT ELIGIBLE`.
2. `PROVED`: the scanned ranges contain 1,992 occurrences at 1,180 unique
   VAs. The unsupported frontier is 352 occurrences at 219 unique VAs and
   197 unique raw words. The exact primary-class counts are
   `DECODER_EXTENSION_CANDIDATE` 161, `FLAG_ONLY_NO_GPR_DEF` 99,
   `TAINT_KILL_REQUIRED` 27, `CONTROL_OR_MEMORY_UNSUPPORTED` 54, and
   `UNKNOWN` 11. The four extension rankings are `BITFIELD_IMM` 120,
   `AND_SHIFT` 37, `EOR_SHIFT` 2, and `BIC_SHIFT` 2 occurrences.
3. Range membership and overlap labels are not reachability: 191 frontier
   occurrence rows overlap ranges and 161 occur in exactly one range, yielding
   133 frontier duplicate rows. Every candidate remains `HYPOTHESIS` with
   source provenance `UNKNOWN_REQUIRES_PRIMARY_SOURCE_REVIEW`, reachability
   `UNKNOWN_RANGE_MEMBERSHIP_IS_NOT_CFG_REACHABILITY`, and decoder safety
   `NOT_CLAIMED`. Writer absence remains `UNKNOWN`; no absence claim is made.
4. The checked public manifest is
   `evidence/manifests/029-dcb-unsupported-frontier-20260826-01.manifest.json`,
   628,525 bytes, mode `0644`, SHA-256
   `c6d46c382d7c091fffad137adb9491d107ff823ad6c6221f51eb627cc218f634`.
   Tool, focused-test, and experiment-README SHA-256 values are respectively
   `e5c491deaddafd4c60de7df3bfe0531f38bbd3740fe668942b912466ee86bca0`,
   `d5eebfcbf1b4332bfeef693802e9b554728480051bc61331e811993c8837a1f2`, and
   `805476c2aad021a781011c66910e819fd9bbf3dc1a05d84aa4435b9704274ef6`.
5. Validation is 17 focused and 633 full unittest-discovery PASS in 84.985 s,
   Python byte-compilation, 68 public JSON manifests, two fresh generations
   byte-identical to one another and the checked manifest, publication
   no-clobber/mode checks, and final independent hostile review `PASS`. The
   durable review is `docs/EXP029_INTEGRATION_REVIEW_2026-08-26.md`.

## 2026-08-26 — Experiment 031 scalar-frontier integration

1. Integrated host-only, read-only Experiment 031 from artifact commit
   `cd9f26e` plus reconciliation repair commit `12a8ebe`. No device, USB, SMC,
   MMIO, normal-RAM, protected-memory, boot, activation, or write action
   occurred. Class C remains `TRANSFORM ONLY`; Experiments 015/016 remain
   `NOT ELIGIBLE`.
2. `PROVED`: the exact XBL remains 4,194,304 bytes with SHA-256
   `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37` and
   the exact 027/029 source and manifest identities are checked before import.
   Scalar admission is qualified against Arm's primary A64 source DDI0602
   (ID092025), version 2025-09, source SHA-256
   `683025f0460c8af8d6711b764c5c4d51d1b56f38d78b618e6cb27d9abf4c853f`.
3. The selected 029 membership domain is exactly 283 occurrences / 160 unique
   VAs / 148 unique raw words. The bounded model reaches 250 selected events;
   33 selected occurrences are not reached. The residual is exactly 69
   occurrences / 59 unique VAs / 49 unique raw words across 20 sites:
   `PAIR_MEMORY` 48, `THREE_SOURCE_UNVALIDATED` 11, `SYSTEM_CONTROL` 4,
   `BIC_SHIFT` 2, `EOR_SHIFT` 2, and `SIGN_EXTENDING_MEMORY` 2.
4. The combined scalar-plus-dispatch v2 model transitions 51 of 71 baseline
   sites to bounded `NO_TARGET_WITHIN_MODEL`; 20 remain
   `INDIRECT_OR_UNSUPPORTED`. This is explicitly `V2_MODEL_ONLY` and
   `NO_ABSENCE_CLAIM`, not scalar-only closure. The separate
   `DIRECT_CONTROL_DISPATCH_REPAIR` contributes 143 events across 62 sites:
   `B.cond` 87, `CBZ/CBNZ` 28, `B` 15, and `TBZ/TBNZ` 13. No
   `DCB_CONSUMER_PATH` or `MC_OR_SHRM_SYMBOLIC_TARGET` is promoted.
5. Pair/sign-extending memory, system/control, three-source, `BIC`/`EOR`,
   indirect aliases, reserved/unknown encodings, and unsafe forms remain
   fail-closed. Runtime execution/order, current object/base values, physical
   destination, global consumer/writer identity, writability, alias behavior,
   security effect, `current_destination`, and `writer_absence` remain
   `UNKNOWN`.
6. Final artifact pins are tool 91,221 bytes / SHA-256
   `5263d8975e9d64809aed04763e0c5573458dabcc6ae7432763d2858a36fc267b`, tests
   18,751 bytes / SHA-256
   `3a81fb4b4fc3023e70918a1648b6f04bb50e0967d27a8f09dbf939f9b55eff6d`,
   Experiment README 7,580 bytes / SHA-256
   `12924ad1fcfeba580f57447e67f74d14743a5962046941ff3088e1b130d173de`, and
   checked manifest 1,327,118 bytes / mode `0644` / SHA-256
   `51a187195c16eb609d337305540fc6d20a09297f5ab76b054497c5c58c3a2e86`.
7. Validation is 19 focused and 652 tracked full unittest-discovery PASS in
   85.226 s, maximum RSS 220,684 KiB with no swaps, Python byte-compilation,
   69 public JSON manifests, two fresh generations byte-identical to the
   checked manifest, QEMU oracle 280/280, and final reconciliation hostile
   review `PASS`. The durable review is
   `docs/EXP031_INTEGRATION_REVIEW_2026-08-26.md`.
8. `PASS`: Experiment 031 narrows the bounded 027 frontier only. The 51-site
   result depends on the combined scalar and dispatch-repair model and must
   never be described as scalar-only closure or writer/consumer absence.
   Experiment 032 was selected at `82/100` for official-source qualification
   and bounded semantics for exact reached `MADD/UMADDL` plus `EOR/BIC`
   arithmetic blockers; it is completed and integrated in the following
   entry. The 10 reached `THREE_SOURCE` events are at sites 35/36/37/56;
   `EOR` has two events at sites 36/37; `BIC` has two at sites 1/52. Site
   35's indirect branch and site 56's pair remain fail-closed. Pair-memory was
   deferred because 38 of its 41 events are `LDP` and most of the remainder
   are SP epilogues, while arithmetic directly forms indexes/addresses in
   high-value runtime-alias/hash-like contexts.
9. At this dated Experiment-031 integration boundary, external Experiments 028
   and 030 were outside and unreviewed. The 2026-08-27 reconciliation below
   supersedes only that integration status.

## 2026-08-26 — Experiment 032 arithmetic-frontier integration

1. Integrated host-only, read-only Experiment 032 from artifact commit
   `d46c44c`, immediately after docs commit `e063181`. No device, USB, SMC,
   MMIO, normal-RAM, protected-memory, boot, activation, or write action
   occurred. Class C remains `TRANSFORM ONLY`; Experiments 015/016 remain
   `NOT ELIGIBLE`.
2. `PROVED`: the exact XBL input remains `xbl--sdb1.bin`, 4,194,304 bytes,
   SHA-256 `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.
   Exact 031/029/027 source and public-manifest identities were checked before
   dependency import. Arithmetic admission is qualified against Arm's primary
   A64 source DDI0602 (ID092025), version 2025-09, PDF SHA-256
   `683025f0460c8af8d6711b764c5c4d51d1b56f38d78b618e6cb27d9abf4c853f`.
3. The added source-qualified forms are modulo-width `MADD` (page 539),
   `UMADDL` (page 873), shifted `EOR` (page 354), and shifted `BIC` (page 62).
   The three-source mask is `0x7FE08000`; reserved selectors and MSUB,
   SMADDL/SMSUBL, and UMSUBL are rejected. Operands read pre-state, `Rd=31`
   discards to ZR, and only exact address-accumulator identities preserve an
   address origin. Pointer transforms, pair/sign-extending memory,
   system/control, indirect branches, and unknown forms remain fail-closed.
4. `PROVED`: the selected membership is exactly 298 occurrences / 175 unique
   VAs / 162 unique raw words across the 71 exact 029 ranges. It retains the
   031 domain (283 / 160 / 148) and adds 15 arithmetic rows across seven sites
   (15 / 15 / 14); 264 selected events are reached and 34 are selected-not-
   reached. The reached arithmetic identity is 14 events: `MADD` 3,
   `UMADDL` 7, `EOR` 2, and `BIC` 2.
5. The inherited 031 full-record equivalence is exact for 250 reached scalar
   extension events, 143 direct-control events, and 23 reached taint-kill
   events. The combined v3 model transitions 55 of 71 baseline sites to
   bounded `NO_TARGET_WITHIN_MODEL`; 16 remain `INDIRECT_OR_UNSUPPORTED`.
   Relative to 031, sites 1, 36, 37, and 52 transition, 51 remain no-target,
   and zero regressions occur. Zero `DCB_CONSUMER_PATH` and zero
   `MC_OR_SHRM_SYMBOLIC_TARGET` paths are promoted.
6. The residual syntactic frontier is exactly 54 occurrences / 44 unique VAs /
   35 unique raw words across 15 sites: `PAIR_MEMORY` 48,
   `SIGN_EXTENDING_MEMORY` 2, and `SYSTEM_CONTROL` 4. Range membership is
   not CFG reachability; the result is `V3_MODEL_ONLY` and
   `NO_ABSENCE_CLAIM`. Runtime execution/order, current destination, physical
   destination, global consumer/writer identity, writability, aliases, and
   `writer_absence` remain `UNKNOWN`.
7. Final artifact pins are tool 127,151 bytes / SHA-256
   `d4233d08ebe3c28cf803f5e9e1e564f1d9e40af12eca85498d23e569821219e2`, tests
   22,710 bytes / SHA-256
   `8bb006cb409235bff0b5a2d2fe2a00cae389eb5253124fcd580bb7713df4d3ad`,
   Experiment README 6,484 bytes / SHA-256
   `20292544e84c5a30876856043287cf6b712642309a6ccd7cfb3fa21702da7573`, and
   checked manifest 1,564,295 bytes / mode `0644` / SHA-256
   `beee3cdaa7d69f240310bed8b574f8dd81b00b48c2383f48dd849ebd36fb4b31`.
8. Validation is 18 focused PASS (maximum RSS 58,388 KiB, no swaps), 670
   full-discovery unittest PASS in 84.937 s (maximum RSS 233,928 KiB,
   swaps 0), Python byte-compilation, 70 public JSON manifests, two fresh
   generations byte-identical to the checked manifest, exact-word QEMU 56/56,
   synthetic QEMU 76/76, logical/three-source encoding grids totaling
   1,152/1,152, and final independent
   hostile review `PASS`. The durable review is
   `docs/EXP032_INTEGRATION_REVIEW_2026-08-26.md`.
9. `PASS`: Experiment 032 is integrated as a deterministic bounded arithmetic
   extension only. The next non-overlapping host-only selection is Experiment
   033 at `87/100`: source-qualify and model 41 reached `PAIR_MEMORY` events
   across 13 sites (38 `LDP`, 3 `STP`; 34 SP-based `LDP`), two sign-extending
   loads across two sites, and one `DAIFClr` system-control event spanning the
   15-site residual and 16-site fail-closed set. `STP` must be represented as
   two explicit store observations; unpredictable, overlap, and writeback forms
   remain fail-closed, as does site 35's indirect/runtime alias.
10. At this dated selection point, Experiment 033 outranked live capture and
    the then-withheld 023R because it closed a
    concrete reached residual from existing exact host inputs without a new
    device gate. At that boundary, Experiment 023R remained withheld because its timing protocol
    is not comparable to 014, physical-allocation PA provenance is missing,
    and the full GF(2) matrix was non-unique. External Experiments 028 and 030
    were likewise outside and unreviewed. The 2026-08-27 reconciliation below
    supersedes those integration statuses after repair.

## 2026-08-26 — Experiment 033 residual-memory frontier integration

1. Integrated host-only, read-only Experiment 033 from artifact commit
   `56b5ffa`. It extends the exact Experiment 032 scalar/arithmetic/direct-
   control model with source-qualified residual pair-memory,
   sign-extending-memory, and system-control forms. No device, USB, SMC, MMIO,
   normal-RAM, protected-memory, boot, activation, or write action occurred.
   Class C remains `TRANSFORM ONLY`; Experiments 015/016 remain
   `NOT_ELIGIBLE`.
2. The exact XBL input remains `xbl--sdb1.bin`, 4,194,304 bytes, SHA-256
   `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.
   The exact 032 source/public-manifest bytes and 032 manifest semantics were
   checked before importing 032. The pinned 032 module then checked the exact
   031/029/027 chain before each imported source or public-manifest use; the
   exact XBL was checked separately before analysis. Arm's primary DDI0602
   (ID092025), version 2025-09, was
   independently pinned at PDF SHA-256
   `683025f0460c8af8d6711b764c5c4d51d1b56f38d78b618e6cb27d9abf4c853f`.
3. `PROVED`: the v4 admission supports `LDP W/X` signed-offset and `LDP X`
   post-index (pages 437–439), `STP W/X` signed-offset (752–754), `LDRSW X`
   (465–466), `LDRSB W` (457–458), and exact `DAIFClr #IRQ`
   `0xd50342ff` (553–556). Pair loads use pre-state lane addresses, stores
   publish two lane observations, and base writeback is modulo 64 bits.
   Pre-index/unseen modes, SIMD/FP pairs, LDPSW, overlap/unpredictable forms,
   other system forms, indirect aliases, malformed words, and unsound memory
   provenance remain fail-closed. `DAIFClr` current exception level and
   `CheckDAIFAccess` outcome remain `UNKNOWN`.
4. The complete 029 frontier is selected as exactly 352 occurrences / 219
   unique VAs / 197 unique raw words. The run reaches 308 selected events and
   leaves 44 selected occurrences not reached. The 44 new events are `LDP` 38,
   `STP` 3, `LDRSW` 1, `LDRSB` 1, and `DAIFClr` 1. The three `STP` instructions
   produce six explicit lane observations. The inherited 032 full-record
   equality is exact for 264 reached extension events, 143 direct-control
   events, and 23 taint-kill events.
5. `PROVED`: the bounded site outcome is 70 `NO_TARGET_WITHIN_MODEL` and one
   `INDIRECT_OR_UNSUPPORTED`, with the latter remaining at site 35's unresolved
   indirect/runtime alias. Zero bounded `DCB_CONSUMER_PATH` and zero
   `MC_OR_SHRM_SYMBOLIC_TARGET` paths are promoted. Global writer identity or
   absence, current physical destination, protected-memory semantics,
   execution/order, aliases, and live authority remain `UNKNOWN`; these are
   bounded model outcomes, not global absence claims.
6. Final artifact pins are tool 172,708 bytes / SHA-256
   `aeb346253aab7860554c8a1cb627d04cbd56d9d82abf50a4a5b811da62a20f93`, tests
   20,273 bytes / SHA-256
   `58632f7a74772e2e86f1ff106c616fd85d0719781394a099cf0d411bb7258dba`,
   Experiment README 7,648 bytes / SHA-256
   `fb87bee1cbb001054389134afb8ae3c80da694d66355731848bc735a37189002`, and
   checked public manifest 2,017,356 bytes / mode `0644` / SHA-256
   `606723e5125d661c800b167133f2a9b69a3b8d47361b39176665a49be539e598`.
7. Validation is 15 focused PASS (maximum RSS 65,064 KiB, no swap), 685 full
   unittest-discovery PASS in 85.706 seconds (maximum RSS 253,944 KiB, swap
   0), Python byte-compilation, public JSON/private-path safety, byte-identical
   fresh publications, exact accounting/equivalence checks, GNU AArch64
   `objdump` agreement for all 29 unique reached residual words, and a QEMU
   AArch64 oracle for pair/sign-extension semantics. `DAIFClr` was not run in
   the EL0 oracle. Independent hostile review returned `PASS` with no P0–P2
   findings.
8. `PASS`: Experiment 033 is integrated as a deterministic bounded v4
   extension. It does not establish a live consumer, writer, current
   destination, transform mutation, physical-to-DRAM alias, protected reach,
   or isolation bypass. At this dated boundary, external Experiments 028 and
   030 were still outside and unreviewed.
9. Experiment 034 was selected at this point as the next highest-information, non-overlapping
   host-only follow-up. Current site-35 jump-table reconstruction is
   `HYPOTHESIS`, not closure: `BR X1` at `0x1484fa08`, candidate table base
   `0x14824cf0`, guarded `W9` index via `CMP W9,#4` plus `B.HI` at
   `0x1484f9f4/0x1484f9f8`, and `LDR X1,[X5,X9,LSL#3]` at `0x1484fa04`; five
   local little-endian entries are `0x1484fa3c`, `0x1484fa50`, `0x1484fa88`,
   `0x1484fa0c`, and `0x1484fa0c`. A pinned tool and tests must prove this
   pattern before site 35 is reclassified.

## 2026-08-26 — Experiment 034 site-35 jump-table integration

1. Integrated the completed host-only Experiment 034 artifact from commit
   `d5d8046`. No device, USB, SMC, MMIO, normal-RAM, protected-memory, boot,
   activation, or write action occurred. Class C remains `TRANSFORM ONLY`;
   Experiments 015/016 remain `NOT_ELIGIBLE`.
2. `PROVED`: exact contiguous dispatch at `0x1484f9f0..0x1484fa08` is
   `LDR W9,[SP,#36]`, `CMP W9,#4`, `B.HI`, `ADRP+ADD`,
   `LDR X1,[X5,X9,LSL#3]`, `BR X1`. It selects table `0x14824cf0`, file
   offset `0xbcf0`, containing five entries and four unique mapped, aligned
   local targets.
3. Four independent in-memory direct-edge substitutions are CFG-complete,
   contain no unsupported form, and each return `NO_TARGET_WITHIN_MODEL`.
   Exact replacement words are `0x14000001`, `0x1400000d`, `0x14000012`,
   and `0x14000020`; changed-byte counts are respectively 3, 3, 3, and 2.
4. `PROVED`: the composed outcome is 71 `NO_TARGET_WITHIN_MODEL` / zero
   fail-closed sites. The 71 baseline 033 records remain verbatim and the
   composed result is published separately. Exactly one site transitions and
   70 remain stable, with no regression and no bounded DCB-consumer or
   MC/SHRM-target promotion.
5. `UNKNOWN`: external/unmodeled entry paths, runtime `BR`/direct-`B`
   branch-type equivalence, execution/index/table contents, current
   destination, global writer/consumer absence, protected-memory semantics and
   any security effect. This is bounded static resolution, not an alias or
   bypass result.
6. Final artifacts are tool 56,864 bytes / SHA-256
   `7589b9f61d92fc835a2378f11106963c074619d59675209082ad919f823690a8`,
   tests 21,596 bytes / SHA-256
   `081b7334a4e88a04647d39e5657c13bcb537b374db192e0597b561ce02cae51b`,
   README 6,712 bytes / SHA-256
   `05a44b688afc6b23eec2e469c523bc6c780d3379ca6ff08f34b020da14bfc82a`,
   and manifest 2,241,492 bytes / mode `0644` / SHA-256
   `75728982e1622f3e807c367baff5cc87d18cff94fa2a9135699f3f836b804b92`.
7. Validation is 14 focused and 699 full unittest PASS, maximum RSS 125,552
   KiB and 274,656 KiB respectively, swap 0. Two fresh publications are
   byte-identical. Independent raw-byte and hostile reviews pass after a
   `CMP W` width-mask P2 was repaired and covered by 224 one-bit dispatch
   mutation controls.
8. The next selection at this point was external-line reconciliation. External 023R/028/
   029A/030 history is retained, but no result is promoted until phase
   provenance, bounded claim levels, reproduction commands, IDs/hashes and
   independent review are corrected. Experiment 035 is deferred.

## 2026-08-27 — exact-parent external-line reconciliation

1. Reconciled the independent history at exact merge parent `247b0e1` onto
   Experiment 034 artifact commit `d5d8046`. The moving branch name was not
   used as input identity. Later commits `05a4c5c`, `4b78b61`, `a297fde`,
   `b2b5068`, `6b3abc7`, and `c91f473` are excluded and unpromoted. No device,
   USB, SMC, MMIO, normal-RAM, protected-memory, boot, partition or write
   action occurred in this reconciliation.
2. Direct promotion was blocked and repaired for: Experiment 030 phase mixing;
   Experiment 022A's false completeness claim; Experiment 021A's two unlabelled
   direct-copy calls; Experiment 029A's extractor/audit filename mismatch;
   stale IDs/commands/hashes; Experiment 023R's all-`BLIND` pagemap provenance;
   overbroad 019A/020A/028/029A absence and semantic claims; and nonportable
   exact-mode assertions for checked-in artifacts.
3. `PROVED` by repaired 023R only in allocation-offset/model coordinates: 66
   summaries over 58 unique differences, threshold 359 with empty band
   182..537, one rank-three kernel and model bit-24 contribution `0b110`.
   Physical PA24/rank/base attribution is `SUPPORTED_WITHIN_MODEL` under the
   contiguous-qsecom plus Experiment-014-relation assumptions. Effective
   contiguity and direct physical-page identity remain `UNKNOWN` because all
   pagemap records are `BLIND`.
4. `PROVED` by 028 within its exact observed set and encodings: seven numeric
   model covectors and zero register-mask/index/triple matches among 494
   decoded registers, 274 nonzero. Two firmware literal hits are unaligned
   chance matches and the deterministic 200-decoy baseline averages 0.66 hits
   per mask. This is not controller-wide absence, a writer result, or physical-
   bank proof.
5. `PROVED` by 029A: deterministic flat ABL extraction binds exact source
   SHA-256 `1db19d11a5ce6865e3fbcabadfbdaa9045e75f144b8bc8593a58338c20a3120c`
   and decompressed-payload SHA-256
   `3fc653082e6acbfcfe3019c7d78b278326bc40de30a4f0325362fa6cce29011a`.
   The bounded stored controller-base/model-mask/triple searches are zero.
   Computed values, PE32 execution, runtime controller participation/writes,
   SMEM value and live DT remain `UNKNOWN`/`UNRETAINED_UNKNOWN`.
6. `REFUTED` by phase-preserving 030 only within the measured reopen model:
   upward class departure does not prove PA9/PA10 are independent channel
   selectors. Complete phase-B/phase-C spread triplets and phase-D PA9 are
   `SATURATING`; phase-D PA10 is `INCOMPLETE`. Their physical coordinate roles
   remain `UNKNOWN`.
7. Historical Experiment 023 is now retained as merge-history/audit evidence
   but remains `WITHHELD/NO-GO` and unpromoted; raw evidence remains private.
   Experiment 023R is the separately repaired result. No reconciled result
   establishes or globally refutes transform mutation, physical-to-DRAM alias,
   protected-memory reach, or isolation bypass.
8. Validation: 296 focused and 995 full unittest PASS; final full discovery ran
   in 108.700 seconds with maximum RSS 272,988 KiB and swap 0. Python byte-
   compilation, public JSON parsing/safety, deterministic byte-identical fresh
   generation for ten manifests and `git diff --check` pass. Independent
   hostile code/artifact review is `PASS` with no remaining P0–P2 after the
   repairs.
9. Class remains `CLASS C (TRANSFORM ONLY)`; Experiments 015/016 remain
   `NOT_ELIGIBLE`. The next selection is a separate commit-pinned repair/audit
   of Verification-015 runtime-invariance evidence. Its numerical result is
   evidence to verify, not yet integrated authority; the moving branch tip
   will not be merged wholesale.

## 2026-08-27 — Verification 015 runtime-invariance repair

1. Rebuilt Verification 015 on clean base `5a803fa` from exact retained inputs.
   Historical commits `05a4c5c`, `a297fde`, and `b2b5068` are evidence scope,
   not imported implementation; `4b78b61` review prose and later `6b3abc7`/
   `c91f473` results remain outside. No device, USB, reboot, bus-vote, SMC,
   MMIO, memory, partition, protected-memory or controller action occurred.
2. Bound 19 private artifacts by basename/size/SHA-256: 15 condition probe
   files, one repeat, one six-level sweep and two journals. Each is parsed and
   hashed from one stable snapshot, then independently re-read and required to
   match before publication. Strict parsing covers 43 sections, 633 summaries
   and 10,704 pair records; exact qsort-index recomputation has zero mismatches.
3. `PROVED` in `ALLOCATION_OFFSET_MODEL_COORDINATES`: all six condition-labelled
   sets contain the same 51 differences. Threshold/gap/runner-up/conflict tuples
   are TWRP pre7980 `371/344/7/25`, pre6881 `573/396/3/25`, post7980
   `365/346/13/25`, V2321 7980 `351/339/8/25`, V2321 L762
   `274/165/140/27`, and coldboot7980 `350/338/8/25`.
4. Four clean comparisons to V2321 L7980 have zero disagreements. L762 has
   exactly `0x100e000` and `0x1012000` excursions; it remains
   `REPEAT_REQUIRED`, so `all_invariant=false`. Six repeat groups derive their
   own thresholds, cover both excursions, and contain zero low/high flips. The
   repeat result does not promote the primary comparison.
5. The retained sweep contains exactly six requested bus-vote levels × two,
   not eleven. It is `RETRACTED_AND_EXCLUDED` from DDR-frequency or transform-
   transition inference because the reported higher-voter observation has no
   retained transcript. It is retained only as measurement-stability evidence.
6. `SUPPORTED`: stability across the operator-reported TWRP/V2321, reboot,
   kernel/userspace and coldboot contexts. Those identities are not attested by
   the raw probe records. Exact timestamps, build/two-environment transfer,
   reboot/power-cycle and complete rollback/recovery/final-state receipts remain
   `UNKNOWN` or incomplete. Pagemap is `BLIND`; effective contiguity and
   physical-page provenance remain `UNKNOWN`.
7. Final pins are analyzer 97,572 bytes / SHA-256
   `6fae489d27d03f94e9dcd89086027a4209988a67020620e54f1df7e22ca99e03`,
   tests 28,904 bytes /
   `ccd6604febeb3c16e40c253a51f5a3fe35c3c61dcd77f6757daa2a9b8ca23ceb`,
   README 11,820 bytes /
   `0c2166e25707ea1381850a64c3089afefccf4ec6f7102f7d1253addbc2461c2d`,
   and public manifest 112,840 bytes /
   `fab880dc50f8e66e74828a0276f8e5ab5ef9b1f2b2f2f9f032dcef03b6b98592`.
8. Validation is 44/44 focused PASS (maximum RSS 31,576 KiB, swap 0) and
   1,039/1,039 full serial unittest PASS in 109.389 seconds (maximum RSS
   275,168 KiB, swap 0). Python byte-compilation, byte-identical fresh manifest
   generation, public-safety/JSON/link/diff checks pass. Independent stable-tree
   hostile review returns `PASS` with no remaining P0–P2.
9. Class remains `CLASS C (TRANSFORM ONLY)`; numbered Experiments 015/016 remain
   `NOT_ELIGIBLE`. No alias, mutation, protected reach, protection ordering or
   bypass is proved. The next iteration is a retained-input Verification-016
   repair: preserve phases, remove filename-order merging, reconcile raw and
   prose, and keep PA25–PA27 physical attribution model-scoped until
   base/alignment/contiguity is proved. Verification 017 remains blocked.

## 2026-08-27 — Verification 016 retained high-bit repair

1. Rebuilt Verification 016 on current integration base rather than importing
   external implementation `6b3abc7`. No device, USB, allocation, memory, SMC,
   MMIO, controller, protected-memory, boot or partition action occurred.
2. Bound three private inputs by exact basename/size/SHA-256: three 14-key
   discrimination sections, one nine-key held-out section and two 14-key
   three-column passes. Probe source, repaired 023R manifest and repaired V015
   stable-read/publication helper are also pinned.
3. Rejected the external `setdefault()`/filename-order merge. Every phase has
   its own median map, widest-gap threshold, labels and exact same-phase
   `0x16000=CONFLICT` / `0x2000=NEGATIVE` controls. The two three-column passes
   are classified before averaging and must agree with their combine.
4. `PROVED` in `ALLOCATION_OFFSET_MODEL_COORDINATES`: bit25 split
   `339/295/22`, match `{14,21}`; bit26 `325/273/75`, match `{19}`; bit27
   `355/302/25`, match `{13,20}`. The two passes and combine retain
   `SELECTOR`, `SELECTOR`, and `SELECTOR_CANCELS_NEGATIVE_WITNESS`.
5. The separate held-out file agrees 7/7 with model-derived labels. Prediction
   preregistration and acquisition order/timestamp are not retained and remain
   `UNKNOWN`.
6. The retained files contain only two control/reference differences per phase.
   They do not establish the historical eight-kernel plus nine-negative `17/17`
   run. The external `192/170/506` tuple is not coherent with either retained
   three-column pass or their combine; its historical producer/cause is outside
   the canonical inputs.
7. Pagemap is `BLIND`. Physical PA identity for model bits 25–27,
   base/alignment and effective contiguity remain `UNKNOWN`; the producer's
   contiguous flag is retained only as `reported_contiguous`. Exact-byte/content
   stability is proved, not filesystem-inode provenance.
8. Independent hostile review found page-contract, unsupported causal-claim and
   nonfinite-JSON gaps. The parser now rejects zero differences, non-page-
   aligned offsets, either page endpoint out of range, NaN/Infinity, phase
   reorder, raw symlinks and hidden three-pass disagreement.
9. Final artifacts are analyzer 78,490 bytes / SHA-256
   `a1b804a3686ba3f7d87f89b68d88de67387c24de424eb396fc770629f0cf2bec`,
   tests 22,757 /
   `8a8221e7c03e4adbf6de7a7f27b773bea7b2e3d32405a44a9673aeab562e67bb`,
   README 8,276 /
   `706362bf45248c7c7af0b6e511f1ffd3edae9b9404b5ae13961e2acf71b771bf`,
   and public manifest 59,504 /
   `72525cf994e52bbee1c3ed685c49a6ace4049cd7b279cb97811f6a0d3f4f773f`.
10. Validation is 23 focused and 1,062 final full serial unittest PASS in
    117.328 seconds; full maximum RSS 277,724 KiB, swap 0. Three nonportable exact-0644 assertions on
    checked-in artifacts were removed while fresh publisher-mode tests remain.
    Final stable-tree hostile review reproduced all pins/manifest and returned
    `PASS` with no remaining P0–P2. Class remains `CLASS C (TRANSFORM ONLY)`; numbered 015/016 stay
    `NOT_ELIGIBLE`. Verification 017 is eligible only for separate audit.
11. The next selected iteration is a repaired, freshly retained normal-RAM
    storage-identity oracle. The historical Verification-018 public result has
    no retained raw transcript/provenance in this tree and will be reacquired
    only after host hardening and hostile review.

# 2026-08-27 — Verification 018 bounded allocation-local marker baseline

This entry records one completed autonomous iteration after the repaired V015
and V016 integrations.  It is a Verification record, not the numbered
Experiment 018 XBL writer line.

## Host construction and hostile review

The new probe (`tools/a90_alias_marker_probe.c`) is a static AArch64 C probe
with a strict `a90_alias_marker_v1` JSONL contract: one context, exact
`camera_preview` type 10/id 30 heap, pagemap observation, two controls, four
page-aligned anchors, two trials over bits 6..27, and one summary (190 records;
176 candidates).  It performs only allocation-local write-combine accesses and
never opens MMIO, SMC, secure/protected memory, a partition or a controller
register.  The host analyzer recomputes all markers, sentinels, candidate
verdicts, control gates and summary counts; malformed, duplicate, reordered,
foreign, nonfinite, incomplete or inconsistent records fail closed.  Synthetic
tests identify dropped bits 6/12/13/19/27, retain an injective negative and
keep an injective cross-state permutation outside this single-state oracle.

The first independent hostile review rejected live promotion until the runner
added predeclared source/binary pins and a reproducible build receipt, exact
bridge serial identity (`usb-A90-LNX...` -> `/dev/ttyACM0`), strict version and
command framing, sidecar/raw/receipt binding, bounded frame sizes, child
completion evidence and a total deadline.  A second review is retained as the
required challenge input; its residual objection is accepted as scope: this is
not a PFN/PTE/SG physical-alias proof or a cacheable-vs-noncacheable full
normal-RAM alias experiment.

## Live actions and receipts

The first live invocation stopped after read-only `version`/`cmdline` because
the actual version frame includes a parenthesized build and separate
`version:`/`kernel:` lines.  It retained an `INCIDENT` receipt with zero
preclean/upload/ION/probe/write actions.  No replay of an effect occurred.

After the parser was corrected from that retained frame, one fresh run used the
exact bridge and fixed command:

```text
run /tmp/a90-native/v018-alias-probe --ion-node /tmp/a90-native/v018-ion --seed 0x5da9f0e3c17b2846
```

The run bound `SM-A908N` / `SM8150`, V2321 `0.9.285`, kernel
`4.14.190-25818860-abA908N...`, debug level `0x4f4c`, force-upload `0`, and
dump sink `0`; the ION character identity was `10:94`.  The 256-MiB allocation
was prefaulted for pagemap observation, both mappings were distinct virtual
addresses, the same-storage control returned `ALIAS`, and the distinct-offset
control returned `DISTINCT`.  All 176 candidates were `DISTINCT` in both
trials.  The probe summary was `aliases=0 disturbed=0 clobbered_anchors=0
trial_disagreements=0 verdict=NO_ALIAS`.

The runner retained raw JSONL, framed probe output, the full bridge transcript
and a PASS receipt.  The temporary node, upload envelope and remote binary were
removed and absence-proved; remote binary hashes were identical before/after
the run; final V2321 selftest was `pass=11 warn=1 fail=0`.  Private hashes are:

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| build receipt | 773 | `40a338c2c96bc214ff89543cd9946e2243499e1f72f7b5819f0c748118c43872` |
| probe source | 22,191 | `cdc6f985fb8e2f37a3964a25f8d575ec1b3fe48eab71d084a30537c6fbe6f3bb` |
| probe binary | 710,408 | `33ef21a13ef79f6888b5a466644660ace3c6950664b1e2b497aad474f1487d56` |
| raw JSONL | 37,456 | `22bb53723a0e1305cdb1c8f4e169ef01e4d2605d1453685ac69faa0bee2a4751` |
| framed probe output | 37,497 | `f0f4af75e1525b23a4ff16cae202dab9cfef805844d57fc5aee766afe62aa8b7` |
| bridge transcript | 1,071,529 | `b8535e555fab04adf083a94de56e93526da7038ea8917648012fa38957672c52` |
| PASS receipt | 1,135,686 | `3d8bbba997045f2e53e4ea2ed5fa560ee7c3efad1971ff1991ee2465ba960352` |

The retained run did not exercise a transport timeout.  If the bridge times out
before returning a frame that contains the remote child PID, the current runner
records an incident but cannot independently prove that the remote child stopped
before cleanup; this recovery path is `UNKNOWN` and is not used to support the
`PASS` result above.

The sanitized public manifest is
`evidence/manifests/verification-018-a90-20260827-03.manifest.json`, 47,715
bytes, SHA-256
`4747a45c20b038b511c3310ebbdd4ac67f9885f29dfe2e3155882a3cf7eb0371`, mode
`0644`.  It reports `DEVICE_ACQUISITION_VALIDATED` and
`PROVED_NO_ALIAS_IN_EXACT_TESTED_OFFSET_PAIRS`; no raw bytes, private paths or
device secrets are published.

## Reclassification and next discriminator

`PROVED`: the exact one-state allocation-offset observations and all live
cleanup/health/build/target receipts.  `SUPPORTED`: this negative is useful as
a non-secure allocation-local storage-identity baseline.  `UNKNOWN`: PFNs/physical mapping,
effective contiguity, final DRAM coordinate, injective cross-state permutation,
transform-state mutability, protection ordering and any protected-boundary
reach.  `REFUTED` only: an alias in the tested candidate pairs for this run.

Class C (`TRANSFORM ONLY`) is unchanged; numbered Experiments 015/016 remain
`NOT_ELIGIBLE`.  The route-2 falsification challenge selected next is now
audited in `docs/ROUTE2_RANK_AUDIT_INTEGRATION_REVIEW_2026-08-27.md`; its Q1
bounded result is `SUPPORTED` and Q4 remains `UNKNOWN`.

# 2026-08-27 — Verification 017 post-decode bank-granularity audit

This is the host-only audit that V016's dependency gate made eligible.  It uses
no device, SMC, MMIO, protected-memory or controller action.  Claude's bounded
implementation was independently rechecked and then hardened here with exact
source pins, semantic manifest cross-checks, no-clobber `O_EXCL` publication,
page-aligned range validation, and explicit subtraction of reserved ranges
nested inside the broad `System RAM` resource.

## Inputs and computation

The pinned 023R relation manifest is 18,040 bytes / SHA-256
`5c3e14ff898c109de740d98260d974bca10751000f85977775cd467ac74aac2e`; the
pinned V016 high-bit manifest is 59,504 bytes / SHA-256
`72525cf994e52bbee1c3ed685c49a6ace4049cd7b279cb97811f6a0d3f4f773f`; and the
pinned `docs/MEMORY_MAP.md` is 9,428 bytes / SHA-256
`34496c0d92736f7df5b9da69f8bcadfe40fb3ee35558c1b10fab7d06dec86950`.  The
tool also checks that 023R retains a resolved unique rank-3 result and that
V016 retains exactly the equalities `{25:[14,21], 26:[19], 27:[13,20]}` before
running the model.

The recovered relation has rank three.  Its first nonzero contribution is bit
13, so the minimum class-change span is 8 KiB; the first three independent
contributions appear by bit 15, so a 64-KiB-aligned 64-KiB span covers all eight
model bank classes.  For an arbitrary base, 128 KiB is the conservative
guarantee.  Five protected carveouts (`hyp_mem`, `tima_region`, `rkp_region`,
`uh_heap_region`, `qseecom_region`) and nine explicitly unprotected System RAM
fragments meet that aligned-or-128-KiB bound under the
allocation-offset/model-coordinate projection.  The isolated 4-KiB System RAM fragment at
`0x80000000-0x80000fff` is retained as an explicit exclusion rather than
silently generalized.  The tool parses and cross-checks the fixed-range table
and `/proc/iomem` block against its calculation inputs.  It also constructs
injective and non-injective finite GF(2) completions with the same bank
projection, proving that the observed bank relation alone does not determine
complete-coordinate injectivity.

## Result

The canonical public manifest is
`evidence/manifests/verification-017-protection-bank-granularity-20260827-05.manifest.json`,
18,108 bytes, mode `0644`, SHA-256
`97ff68a2f8ebfb6313f228f2626f12f88260764a993f916ba1f97677d7b99f02`.  The
focused suite is 42/42 PASS; a fresh host publication is byte-identical to the
canonical manifest.  The full serial repository suite is 1,132/1,132 PASS
(`skipped=1`) in 113.958 seconds, maximum RSS 278,532 KiB, with zero swap.

`PROVED`: the model-coordinate rank/granularity, source semantic agreement, the
alignment-sensitive 64/128-KiB covering bounds, the model-projected per-range class histograms,
and the finite countermodel underdetermination.  `REFUTED` only within those
declared ranges: a check that observes only post-decode bank class cannot
separate protected from the explicitly unprotected comparison ranges.
`SUPPORTED`: the narrow bank-only shape does not explain protection separation,
leaving checks that retain additional address information as the remaining
structural possibility.
`UNKNOWN`: actual enforcement ordering, complete DRAM coordinates, physical
mapping, PA28+, transform mutability, global writer/register absence, and any
protected-memory reach or bypass.  Class C remains unchanged.

# 2026-08-27 — Route-2 writer/rank manifest audit

This host-only iteration pins the exact 027/029/030/031/032/033/034 public
manifests plus 023R and V016.  It verifies the bounded no-promoted-path result,
all 71 site identities, every transition identity/count balance, 032–034
quadrant counts, 030's inherited rank-3 dependency, and the distinction between
029 decoder ranking metadata and a relation row.  No device or controller action
was performed.

`SUPPORTED_BOUNDED_CLOSURE_UNKNOWN_GLOBAL`: Q1 has no promoted DCB-consumer or
MC/SHRM symbolic target path inside the declared models, but global writer,
runtime and indirect state remain `UNKNOWN`.  Q4 is
`UNKNOWN_NO_COMPLETE_029_034_RELATION_ROW_SET`: no explicit relation rows occur
in the named public fields, but unretained raw rows were not reconstructed.

The canonical public manifest is
`evidence/manifests/route2-rank-audit-20260827-01.manifest.json`, 9,607 bytes,
mode `0644`, SHA-256
`ec3ec693768bf1294366c5650ab9c5e76b27f9bdce049c7a6f2b205a00a72fb8`.  The
focused suite is 19/19 PASS; the full serial repository suite is 1,151/1,151
PASS (`skipped=1`) in 113.671 seconds, maximum RSS 290,844 KiB, with zero swap.
The hostile-review result is recorded in the integration review.

# 2026-08-27 — Verification 020A setter/base argument trace

This host-only iteration pins the exact XBL and the candidate setter range
`[0x9fc06410,0x9fc0643c)`.  It independently decodes the five static stores and
the singleton direct caller at `0x9fc023f0`, then traces only the 20-byte linear
pre-call block.  The setter contains one `XZR` zero and four argument-sourced
stores; the caller sources them from an opaque incoming object as
`W3=[X0+0x10]`, `X0=[X0+0x18]`, `X1=[X0+0x20]`, and `X2=[X0+0x28]`.

`PROVED`: exact input/range hashes, store shape, direct-caller singleton and
symbolic field origins.  `SUPPORTED`: the setter/caller edge is reproducible in
the bounded model and compatible with the prior candidate DDR-segment
inference.  `HYPOTHESIS`: the object may carry controller-base-like fields.
`UNKNOWN`: runtime object origin/value/type, boot execution/currentness, alternate
or indirect callers, mutability/locks, physical-to-DRAM mapping, protected reach
and alias/bypass.  `CLASS C (TRANSFORM ONLY)` and numbered 015/016 eligibility
are unchanged; no device action occurred.

The sanitized manifest is
`evidence/manifests/020A-setter-base-trace-20260827-01.manifest.json`, 9,171
bytes, mode `0644`, SHA-256
`edf62eb6c1d97a8113f5ba0894548e9d5fafc83eeefbc7976c808b0f7886c051`.  Focused
validation is 9/9; full serial validation and the final hostile review are in
`docs/VERIFICATION020A_INTEGRATION_REVIEW_2026-08-27.md`.

# 2026-08-27 — Verification 020B caller-object origin trace

This host-only iteration follows the exact sole direct caller of the 020A
consumer at `0x9fc023c8`.  The caller obtains an opaque `X0` token from
`BL 0x9fc160b8`, constructs a stack object at `SP+0x20` (including the exact
`STR X8`/`LDR Q0`/`STR Q0`/`LDP X11,X10` sequence), and passes that object to the
consumer.  The bounded stack model resolves the 020A setter arguments to
return-object offsets `0x0c` (W3), `0x18` (X0), `0x20` (X1), and `0x28` (X2).

`PROVED`: exact XBL/range/call-word/consumer-entry pins, singleton direct
caller, instruction forms and stack overwrite ordering.  `SUPPORTED`: the
caller/object edge is reproducible under the finite symbolic model.
`HYPOTHESIS`: the helper return may be a runtime configuration carrier.
`UNKNOWN`: runtime values, object type/currentness/static-object semantics,
indirect callers and writers, physical-to-DRAM mapping, mutability/locking,
protected reach, aliasing and bypass.  `CLASS C (TRANSFORM ONLY)` and
`NOT_ELIGIBLE` remain unchanged; no device action occurred.

The sanitized manifest is
`evidence/manifests/020B-caller-object-origin-20260827-01.manifest.json`,
18,518 bytes, mode `0644`, SHA-256
`61e5961620d78e766d3fbc586847f76feb0f07991e41326c4b971110cb2a082a`.
Validation is 7/7 focused and 1,167/1,167 full serial tests (`skipped=1`) in
116.419 seconds, maximum RSS 296,676 KiB, zero swap; deterministic
regeneration, public JSON/redaction, no-clobber and decoder-negative checks
pass.  Independent hostile review is `PASS` in
`docs/VERIFICATION020B_INTEGRATION_REVIEW_2026-08-27.md`.  The next scored
candidate is a separate bounded trace of the `0x9fc160b8` return helper.

# 2026-08-27 — Verification 020C return-helper origin trace

This host-only iteration follows the opaque return used by 020B.  The exact
helper `[0x9fc160b8,0x9fc160c4)` is `ADRP X0,0x9fc36000; ADD X0,#0x2c0; RET`,
yielding static ELF VADDR `0x9fc362c0`.  An executable PT_LOAD scan finds two
direct callers, `0x9fc22cc0` and `0x9fc26e2c`.  The 48-byte object-field source
range `[0x9fc362c0,0x9fc362f0)` is pinned by hash only; raw bytes and values are
not published.

`PROVED`: exact input/helper/object hashes, static return construction and
two-caller census.  `SUPPORTED`: this identifies the bounded source used by
020B and a second XBL path.  `HYPOTHESIS`: the static object may be shared
configuration data.  `UNKNOWN`: runtime contents/type/currentness, writer and
mutability/locking, indirect paths, physical-to-DRAM mapping, protected reach,
aliasing and bypass.  `CLASS C (TRANSFORM ONLY)` and `NOT_ELIGIBLE` remain
unchanged; no device action occurred.

The sanitized manifest is
`evidence/manifests/020C-return-helper-origin-20260827-01.manifest.json`, 5,498
bytes, mode `0644`, SHA-256
`ef89ae91fd7277454422fe9717aad762259645991b41797f8011b8dc5b43fdb2`.
Validation is 6/6 focused and 1,173/1,173 full serial tests (`skipped=1`) in
117.851 seconds, maximum RSS 297,324 KiB, zero swap; deterministic
regeneration, public JSON/redaction, no-clobber and decoder/cardinality
negative checks pass.  Independent hostile review is `PASS` in
`docs/VERIFICATION020C_INTEGRATION_REVIEW_2026-08-27.md`.  The next scored
candidate is a bounded trace of the second helper caller at `0x9fc26e2c`.

# 2026-08-27 — Verification 020D second-caller field-use trace

This host-only iteration traces the second direct caller at `0x9fc26e2c` of
the 020C helper.  The exact function loads object fields `+0x28`, `+0x30`,
`+0x38`, `+0x0c`, `+0x18`, and `+0x20`; six symbolic origins are stored to
static ELF VAs `0x9fc3e138`, `0x9fc3e140`, `0x9fc3e148`, `0x9fc3e150`,
`0x9fc3e158`, and `0x9fc3e160`.

`PROVED`: exact XBL/helper/caller/object hashes, decoder pins and the six
field-to-slot edges.  `SUPPORTED`: this is a second static consumer of the
shared 020C object.  `HYPOTHESIS`: the object/slots may be configuration state.
`UNKNOWN`: field values/type/currentness, slot semantics, writer timing,
mutability/locking, indirect paths, physical-to-DRAM mapping, protected reach,
aliasing and bypass.  `CLASS C (TRANSFORM ONLY)` and `NOT_ELIGIBLE` remain
unchanged; no device action occurred.

The sanitized manifest is
`evidence/manifests/020D-second-caller-field-use-20260827-01.manifest.json`,
10,181 bytes, mode `0644`, SHA-256
`9aa50ba0d1389584bb6b32435ff68b176d60aad9e822aabd6c503be21741b223`.
Validation is 6/6 focused and 1,179/1,179 full serial tests (`skipped=1`) in
117.908 seconds, maximum RSS 297,080 KiB, zero swap; deterministic
regeneration, public JSON/redaction, no-clobber and decoder/cardinality
negative checks pass.  Independent hostile review is `PASS` in
`docs/VERIFICATION020D_INTEGRATION_REVIEW_2026-08-27.md`.  The next scored
candidate is a bounded static-slot consumer census (020E).

# 2026-08-27 — Verification 020E bounded static-slot consumer census

This host-only, read-only iteration follows the six static ELF slots populated
by 020D.  An exact-XBL executable census recognizes only an `ADRP` to page
`0x9fc3e000` followed within eight instructions by an unsigned scalar
`LDR`/`STR` to one of the six pinned offsets.  Caller-saved direct `BL` is a
barrier; continuation across X19–X29 is explicitly conditional on AAPCS64
callee preservation.  Unknown instructions and indirect paths remain outside
the model.

`PROVED`: exact input/helper/caller/object hashes and 18 unique direct accesses
(6 stores, 12 loads), with 95 retained barriers (8 caller-saved calls and 87
unknown-instruction barriers).  `SUPPORTED`: the six slots have additional
static uses.  `HYPOTHESIS`: they may be shared configuration state.
`UNKNOWN`: global writer/consumer absence, ABI compliance/callee side effects,
runtime values/currentness/execution, slot semantics, MMIO/physical/DRAM
identity, mutability/locking, protected reach, aliasing and bypass.  `CLASS C
(TRANSFORM ONLY)` and `NOT_ELIGIBLE` remain unchanged; no device action
occurred.

The sanitized manifest is
`evidence/manifests/020E-static-slot-census-20260827-01.manifest.json`, 29,826
bytes, mode `0644`, SHA-256
`4c28b0cc0a113e099fe3b0ce2bd16a77ce0c9d9bfc799ca9494c52eed9c349ad`.
Validation is 7/7 focused and 1,186/1,186 full serial tests (`skipped=1`) in
119.090 seconds, maximum RSS 343,404 KiB, zero swap; deterministic
regeneration, public JSON/redaction, mode/no-clobber checks and independent
hostile review `PASS`.  The next scored candidate is a bounded load-use trace
over the twelve recognized loads (020F).

# 2026-08-27 — Verification 020F bounded static-slot load-use trace

This host-only, read-only iteration follows the twelve direct scalar loads
identified by 020E.  Each seed is traced for at most 16 instructions in the
same executable segment.  Caller-saved X0–X18/X30 calls and unsupported forms
stop fail-closed; continuation across X19–X29 is explicitly conditional on
AAPCS64.  MOVK on tainted registers stops without silently dropping residual
bits, and both CBNZ/TBNZ forms are decoded.

`PROVED`: exact XBL and mechanically hash-pinned 020E manifest dependency,
seed set, and bounded event set.  The model reports 16 use events (10
address-base, 2 arithmetic, 2 register-offset, 1 register-copy, 1 return)
and 11 barriers (4 caller-saved `BL`, 5 recognized control, 2 unknown), with
no tainted direct store in the supported windows.  `SUPPORTED`: several slot
values feed local address formation/arithmetic.  `HYPOTHESIS`: some may be
object pointers or local configuration fields rather than controller state.
`UNKNOWN`: global writer/consumer absence, ABI compliance/callee effects,
runtime execution/currentness/values, slot semantics, MMIO/physical/DRAM
identity, mutability/locking, protected reach, aliasing and bypass.  `CLASS C
(TRANSFORM ONLY)` and `NOT_ELIGIBLE` remain unchanged; no device action
occurred.

The sanitized manifest is
`evidence/manifests/020F-static-slot-load-use-20260827-01.manifest.json`,
13,069 bytes, mode `0644`, SHA-256
`d19687581d046c7b05841aef6340e9a1e3664c69e19903689d1c583aee5b9764`.
Validation is 9/9 focused and 1,195/1,195 full serial tests (`skipped=1`) in
123.910 seconds, maximum RSS 342,272 KiB, zero swap; deterministic
regeneration, public JSON/redaction, mode/no-clobber checks and independent
hostile review `PASS`.  The next scored candidate is bounded pointer/object
resolution for the address-use events (020G).

# 2026-08-27 — Verification 020G bounded static-slot pointer/object census

This host-only, read-only iteration re-decodes exactly the 020F address-use
events.  The bounded census contains 12 witnesses: 10 immediate
object-field-shaped accesses (7 `LDR`, 3 `STR`) and 2 `UXTX` register-offset
array-element-shaped loads.  The witnesses occupy 11 unique access VAs, with
one duplicate witness.  These are instruction-shape results only; runtime
base values/currentness, object semantics, global writer/consumer absence,
MMIO/physical/DRAM identity, mutability, protected reach and alias/bypass
remain `UNKNOWN`.  `CLASS C (TRANSFORM ONLY)` and `NOT_ELIGIBLE` remain
unchanged, and no device action occurred.

The sanitized manifest is
`evidence/manifests/020G-static-slot-pointer-object-census-20260827-01.manifest.json`,
7,218 bytes, mode `0644`, SHA-256
`f534efeee1e12f18d3af40c107dbc6fbe938eae16d9013aa088d22d7c880af3e`.
Focused tests are 10/10 and the full serial suite is 1,205/1,205 PASS
(`skipped=1`) in 134.596 seconds, maximum RSS 347,740 KiB, zero swap.  The
next scored candidate is a bounded static-slot function-role/base-origin
trace (020H).

# 2026-08-27 — Verification 020H static-slot function-role/base-origin trace

This host-only, read-only iteration re-decodes the exact 020G witnesses and
analyzes only the pinned 220-byte XBL region `[0x9fc26e84,0x9fc26f60)`.  Strict
RET X30/direct-B partitioning yields 7 bounded local blocks; BL is not treated
as a branch terminator.  True function boundaries are not inferred.  Direct
BL sources to each block entry and a backward trace of at most 16 instructions
classify each unique access base; a preceding STR never defines a base.

`PROVED`: 12 witness rows group into 11 unique access VAs and 7 bounded
blocks.  Nine blocks contain unsupported forms and two are
`LOCAL_READ_SHAPED_BLOCK`.  Ten unique bases are `STATIC_SLOT_SEED`; indexed
access `0x9fc26ea0` is `ARITHMETIC_DERIVED` from a bounded `MADD`.
`SUPPORTED`: local helper/object role consistency.  `HYPOTHESIS`: the family
may be local configuration/helper state.  `UNKNOWN`: true function
boundaries, runtime execution/currentness/values, indirect callers/callee
effects, object semantics, global writer/consumer absence, ABI effects,
MMIO/physical/DRAM identity, mutability/locking, protected reach, aliasing
and bypass.  `CLASS C (TRANSFORM ONLY)` and `NOT_ELIGIBLE` remain unchanged;
no device action occurred.

The sanitized manifest is
`evidence/manifests/020H-static-slot-function-role-base-origin-20260827-01.manifest.json`,
19,314 bytes, mode `0644`, SHA-256
`b306ca67675430314289fd79faa2e53b2d67994807d0b08bd91ced9b625faba2`.
Focused tests are 11/11 and the full serial suite is 1,216/1,216 PASS
(`skipped=1`) in 140.860 seconds, maximum RSS 349,728 KiB, zero swap.  The
next scored candidate is a bounded caller-context/entry-role trace (020I).

# 2026-08-27 — Verification 020I caller-context/entry-role trace

This host-only, read-only iteration re-derived the exact 020H role rows and
checked 20 unique block-entry direct-BL source/target edges.  A strict
backward window of at most 16 instructions yielded 12
`CALLER_CONTEXT_UNSUPPORTED`, 6 `ARGUMENT_OR_UNKNOWN`, and 2
`ARGUMENT_COPY_OR_CONSTANT` rows; no static-slot-origin caller was reached.
This is bounded negative/unknown evidence, not a global writer/consumer or
function-boundary proof.  Runtime values/currentness, indirect effects,
MMIO/physical/DRAM identity, mutability, protected reach and alias/bypass
remain `UNKNOWN`; `CLASS C (TRANSFORM ONLY)` and `NOT_ELIGIBLE` remain
unchanged.

The sanitized manifest is
`evidence/manifests/020I-static-slot-caller-context-entry-role-20260827-01.manifest.json`,
12,472 bytes, mode `0644`, SHA-256
`03c463f667142a21641264ec2e4080d9d5f963c67776037ca9d6194a8a621608`.
Focused tests are 11/11 and the full serial suite is 1,227/1,227 PASS
(`skipped=1`) in 151.571 seconds, maximum RSS 356,228 KiB, zero swap.

# 2026-08-27 — Verification 020J caller-context barrier/opcode inventory

This host-only, read-only iteration re-derived the exact 020I caller-context
set and inspected only the first unsupported instruction at each of its 12
bounded stop windows.  All 12 stop VAs are unique.  Strict ARM64 family masks
classify five `B_COND`, two `CBZ_CBNZ`, two scalar `LDP_STP_PAIR` (offset and
pre-index), two logical-immediate forms, and one 32-bit `BITFIELD` (`BFXIL`).
The `UNKNOWN_OPCODE` fallback is unused for this exact set.  No trace continues
past a barrier and no word is promoted to a pointer, PA, MMIO, controller,
DRAM, ownership or bypass claim.  `CLASS C (TRANSFORM ONLY)` and
`NOT_ELIGIBLE` remain unchanged; no device action occurred.

The sanitized manifest is
`evidence/manifests/020J-caller-context-barrier-opcode-inventory-20260827-01.manifest.json`,
7,657 bytes, mode `0644`, SHA-256
`1fdb1f4ade702fdb2d6ffdc68669a9710c8152e225f89f02fb65c0d10f4c3d55`.
Focused tests are 7/7 and the full serial suite is 1,234/1,234 PASS
(`skipped=1`) in 164.114 seconds, maximum RSS 355,764 KiB, zero swap.
Deterministic regeneration, redaction, no-clobber, dependency/cardinality/
family mutation negatives and independent hostile review all pass.  The next
scored candidate is a bounded barrier operand/target metadata inventory
(020K).

# 2026-08-27 — External line integration and 1b checkpoint

The external `research/xbl-config-cdt@99eb1dc` ref was audited without
fast-forwarding or resetting the current branch.  Additive commits
`db22fb1`, `96f8d4c` and `865593b` are integrated as commits `eb2f44d`,
`8c3d1c5` and `0e6bfd5`; the repaired 015/016/017/018 implementations remain
authoritative where the external add/add versions are weaker or semantically
different.  The complete 14-commit disposition is in
`docs/EXTERNAL_LINE_INTEGRATION_2026-08-27.md`.

The imported V019 public manifest reports zero moved tags across a reported
25.09-second deep suspend and its 23-test synthetic detector suite passes.
Because the external private raw receipt is absent here, this is
`SUPPORTED_EXTERNAL_MANIFEST_ONLY`, not a fresh live proof and not closure of
reopen condition 3.  The known-aperture 1b checkpoint remains `PROVED` only
for the tested TZ-owned/no-HLOS-grant candidates and the fixed EL1 failure;
global reachability is `UNKNOWN`.

# 2026-08-27 — Verification 015 bus-vote amendment

Two retained `msm-bus-dbg` excerpts were parsed in a separate host-only
amendment.  The client excerpt declares 66 clients and includes `disp_rsc_ebi`;
the EBI excerpt contains one initial 12.8 GB/s AB/IB row, two transient
zero-AB/400 MB/s IB rows and three restored 12.8 GB/s rows.  The strict
parser, exact input hashes, redaction/no-follow checks and deterministic
manifest pass.  This supports excluding the V015 bandwidth axis from DDR
frequency/transform-transition inference but does not establish a DDR clock
change.  Manifest SHA-256 is
`066d8fc708c5652cb53abfc78e4286b06ea9ec100cffeef5a10240420fb8582b`.

# 2026-08-27 — 1b known-aperture reachability checkpoint

The host-only 1b checkpoint reconciled exact public hashes for `MEMORY_MAP.md`
and the 009/010/007/005 manifests.  Both selector branches enumerate the same
eight qhs_llcc-remapper/BIMC candidates, and every candidate is covered by
TZ-owned `MEMNOC_MS_MPU` and `CNOC_SNOC_MS_MPU` hits with no HLOS read/write
grant.  The 009 narrow region for `0x09248080` is branch-invariant.  The fixed
EL1 load and the separate failed control-node read remain bounded observations;
watchdog causality is not promoted.

`PROVED` is limited to the eight static-policy candidates; `SUPPORTED` covers
the constraint on their tested route.  Global reachability, alternate
apertures, final runtime policy/register state, ordering, mutability, physical
mapping and bypass remain `UNKNOWN`.  Classification is still `CLASS C
(TRANSFORM ONLY)` and eligibility `NOT_ELIGIBLE`.  The public manifest is
13,885 bytes, mode `0644`, SHA-256
`b4135f22bff47df22cda674eeabfff909ef4d3bc2a1843b358be7556b6d5ff02`; focused
tests are 9/9 PASS.  No device action occurred.  The next scored candidate is
020K, still host-only and read-only.
