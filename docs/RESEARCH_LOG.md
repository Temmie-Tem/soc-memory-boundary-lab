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
