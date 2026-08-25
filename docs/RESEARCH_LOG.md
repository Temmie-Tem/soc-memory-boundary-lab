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
