# Initial Reconnaissance Status — 2026-08-25

Current research state: `NO_BOUNDARY_BYPASS_OBSERVED`

Current class: `CLASS C (TRANSFORM ONLY) — live normal-RAM timing proves a
hidden low-24-bit XOR bank-selection relation; direct EL1 controller/SHRM reads
remain blocked; no transform write, complete-coordinate alias,
protection-order mismatch, or boundary bypass has been observed`

Platform provenance: the A90 runtime, ACM bridge, REPL primitive, TWRP
code-boot and boot-prefix rollback used throughout are supplied by the upstream
`android-native-init-lab` project; see the Upstream section of `README.md`.
This derived project runs under a single binding constraint — anything that
cannot permanently brick the device may proceed quickly — so bootloader-class
partitions, fuses, RPMB and the partition table stay forbidden while volatile
controller writes do not.

Device mutation: Experiment 007 temporarily wrote the exact boot-only REPL,
fixed no-load control, and fixed one-load read candidates. Each transition was
bounded to the boot partition and verified by a 60,882,944-byte readback.
V2321 is restored and healthy. The experiment made no memory-controller,
MMIO, SCM, EL2, EL3, or protected-memory write; it attempted one fixed 32-bit
MMIO load.
Experiment 004 created and removed fixed temporary block-device nodes under
`/dev`; Experiment 005 created and removed one fixed temporary character node.
Experiments 008, 009, 010, 011, 012, Experiment 013 preparation, and
Verifications 001–002 were
entirely host-only. Experiment 013 then wrote exact control/read boot candidates
and V2321 rollbacks with full-prefix readback. It performed no controller,
memory, SCM, EL2, EL3, or protected-memory write and attempted one fixed
32-bit SHRM load. V2321 is restored and healthy.
Verifications 006–014 additionally captured the complete `param` partition,
changed only its four-byte debug field LOW→MID, dispatched one SysRq panic,
collected only `SHRM_MEM.BIN`, restored the original full partition hash, and
proved a subsequent LOW boot with selftest `fail=0`. Force-upload, FMM, and dump
sink remained zero. No controller, XPU, SMMU, SCM, EL2, EL3, firmware, GPT,
RPMB, QFPROM, or protected-memory write occurred.
Experiment 014 used only non-secure ION `user_contig` RAM and temporary files
below `/tmp/a90-native`. The temporary character node and probe were removed;
the final exact-target receipt reports V2321 `0.9.285`, selftest `fail=0`, and
battery 100%. No partition or hardware-control register was written.

Host-only Experiment 017 then cross-referenced the exact XBL MC address table
and helper read-copy path. It made no device, SMC or MMIO access and does not
satisfy reserved/`NOT ELIGIBLE` Experiments 015 (normal-RAM alias) or 016
(protected-boundary reach).

Host-only Experiment 018 Stage 1A now inventories exact XBL literals and a
strict STR W/X store-offset census for the 12 ranked MC targets. The exact
file-backed PT_LOAD census is RX4/RWE2/RW3, with 6945/5169 recognized forms
and 14 matching offsets (RX11, RWE3; seven RX candidates are SP-based). Each
target's single 8-byte table encoding yields both the one aligned u64 match
and the overlapping one aligned u32 match at the same file offset; these are
two views of one table entry, not independent stored literals, and there is no
separate target literal elsewhere. Only base `0x09260000` has an aligned u32
outside it, at file `0x80154` / VA `0x148bc254` in RWE. Stage 1A performs no
base/effective-address resolution, so its hit count is `null`, not zero, and
makes no writer claim. Experiments 015 and 016 remain reserved and `NOT
ELIGIBLE`.

Stage 2A now analyzes only the four non-SP RX candidates with a maximum 128-
instruction same-block direct-definition slice. It supports only 64-bit
`MOVZ/MOVK` and same-register `ADRP Xn; ADD Xn,Xn,#imm`, and fails closed at
branches, calls, returns, inbound block entries, boundaries and unsupported
definitions. Exact outcomes are two `WINDOW_LIMIT` no-definitions, one
unsupported LDR definition at `0x146a70b4`, and one BL `CONTROL_TRANSFER`
boundary. `resolved_base_count=0` and `resolved_target_hit_count=0`; the
classification is
`NO_RESOLVED_TARGET_STORE_WITHIN_STAGE2A_DIRECT_DEFINITION_RX_MODEL`. This
refutes only the supported Stage 2A direct-definition path, not writer
existence; SP/RWE and all other paths remain `UNKNOWN`.

Stage 2B now extends only the two Stage 2A window-limit X8 candidates with a
maximum-512 same-block W-wide-move model. The pinned `MOVZ W8,#0xf000` and
`MOVK W8,#0x1489,LSL#16` chain resolves XBL virtual-address value
`0x1489f000`, computing `0x1489f400` and `0x1489f4d0`; both are outside
file-backed PT_LOADs and neither numerically matches a target. The result is
`resolved_base_count=2`, `resolved_numeric_target_hit_count=0`, with
classification
`NO_NUMERIC_TARGET_ADDRESS_MATCH_WITHIN_STAGE2B_W_WIDE_MOVE_RX_MODEL`.
This refutes only numeric target equality in that model; physical destination,
VA-to-PA translation, writer identity and all unsupported/dynamic paths remain
`UNKNOWN`. Experiments 015 and 016 remain reserved and `NOT ELIGIBLE`.

## A. 현재까지 PROVED

- Exact A90 source, defconfig, System.map, independently extracted stock
  kallsyms, DTS/overlay and secure-buffer/RKP callsites were rechecked by path,
  line and SHA-256; existing prose was not treated as authority.
- `CONFIG_UH_RKP`, `CONFIG_RKP_KDP`, `CONFIG_RKP_NS_PROT`,
  `CONFIG_RKP_DMAP_PROT`, JOPP and ROPP remain enabled. `rkp_init()` calls
  `uh_call(... RKP_START ...)`, and `uh_call` reaches `smc #0`.
- `hyp_assign_phys/table` and `qcom_scm_assign_mem` name physical ranges plus
  VMID/permission data for SCM MP service calls.
- The exact SM8150 DT/source contains LLCC, LLCC-to-EBI_CH0, a CNOC DDRSS
  configuration endpoint, LLCC/DDR bandwidth monitors and AOP DDR perf/frequency
  messages.
- Live A90 capture `001-baseline-live-20260825-01` produced 12 successful,
  binary-safe read-only frames. It proved live `hyp_mem`, TIMA, RKP, UH heap and
  QSEECom advertised ranges and fixed current runtime/kernel identity.
- AMD's demonstrated primitive is a temporary Family 16h DRAM bank-map/
  swizzle/swap state change plus a controlled uncacheable access and GF(2)/Z3
  alias recovery; those details are AMD facts only.
- Experiment 004 captured nine exact live boot-firmware artifacts with matching
  device-before/host/device-after SHA-256. Exact XBL owns DDR DSF/DCB training;
  exact AOP manages DDR runtime state; exact `hyp` supplies QHEE; exact `tz`
  names BIMC/MEMNOC/LLCC memory-protection units.
- Experiment 006 binds all four DCBs to exact selector filenames, proves the
  section-16 path into SHRM, recovers XBL's 13-row DDR remapper table, and
  follows `icbcfg_info` to four `qhs_llcc + 0x8080` register windows:
  `0x09248080`, `0x092c8080`, `0x09348080`, `0x093c8080`. Layout 1 touches
  32-bit offsets `0x00..0x58` in each window.
- Experiment 008 resolves the exact live selection from retained boot-firmware
  evidence: `/6003_0200_1_dcb.bin`, two 3072-MiB ranks, mask `0x3`, and unique
  remapper row 7 with destinations `0x80000000` and `0x140000000`.
- Experiment 011 pins the real XBL Quest DDR failure recorder and its coordinate
  reporter. For the retained 6-GiB topology it derives rank boundary
  `0x140000000`, exactly row 7's rank-1 destination, then maps rank-relative PA
  bits to row `[31:16]`, bank `[15:13]`, channel `[10:9]`, column
  `[12:11]||[8:1]`, and byte `[0]`.
- That diagnostic bit partition is complete, non-overlapping, and invertible.
  Its exact bounded formula has no XOR and no PA-to-coordinate collision.
- Selected DCB section 16 parses exactly into two compact base-token/offset-
  token sets with 22 and 8 records. Base tokens numerically equal
  `physical_base >> 12` for exact `qhm_shrm` MCCC, MC, MCCC-master, DDRSS, and
  SHRM-CSR topology bindings.
- Experiment 012 recovers the exact Xtensa SHRM helper at `0x2d8dc`. It
  computes `(base_page << 12) + (offset_token << 2)` and direction zero reads
  each 32-bit word into a SHRM snapshot buffer. The two exact section-16
  callsites pass direction zero and produce 430/64 reads; the observed path is
  not a transform-write command stream.
- Experiment 013 proves both exact TZ selector branches place the complete
  `0x09065100–0x09065fff` snapshot workspace inside three enabled, TZ-owned
  regions. The exact narrow region is `DC_NOC_NON_BROADCAST_MPU` region 5 at
  `0x09060000–0x0906ffff`; all six branch/region matches exclude ordinary HLOS
  read and write.
- Experiment 013's fixed no-load control mapped/unmapped snapshot word
  `0x0906566c` and returned `0xc071`. The paired body differs by exactly one
  32-bit instruction (`MOVZ` versus `LDR W`); the one-load path returned no
  value, disconnected USB, and retained `Non Secure Watchdog Bark` with
  `TZBSP_ERR_FATAL_NON_SECURE_WDT`. It was not retried. V2321 full-prefix
  rollback and final `selftest fail=0` are proved.
- Exact layout-1 code encodes six 36-bit ranges as low32/high4 fields, disables
  the four instances before programming and enables them afterward. There is no
  distinct lock-register write inside that exact bounded XBL function; later
  firmware/hardware locking remains `UNKNOWN`.
- The separate exact TrustZone ELF contains the same `/dev/icbcfg/boot` DAL
  identity and four-base, six-slot layout record. Runtime invocation/locking is
  still `UNKNOWN`.
- Experiment 009 proves the primary TZ registry is a consumed 48-record table,
  not string-only metadata. Both embedded policy-selector branches contain a
  40-region `DC_NOC_BROADCAST_MPU` policy at `0x090e0000`.
- In both branches, region 11 is enabled, TZ-owned, covers
  `0x09248000–0x09248fff`, and therefore contains the tested PA
  `0x09248080`. Its raw access words are `0x80000000/0x00000000`, not
  `0x80/0x80`.
- The pinned exact TZ conversion path produces zero standard VMID permission
  words and client-permission bytes `0x11/0x08`: TZ-owner read/write plus
  MSA-class read-only, with no ordinary HLOS VMID grant. Exact devcfg sets
  `/ac/xpu:disable_xpu_ac = 0`.
- The exact TZ error router assigns `DC_NOC_BROADCAST_MPU` to global status
  bank 0 bit 29 and also assigns all four BIMC MPUs. `BIMC_MPU0..3` are absent
  from both embedded static policy lists.
- Experiment 010 proves that absence does not mean inactivity. The separate
  exact TZ memory-assignment fallback reaches memory-lock, topology fanout and
  dynamic `BIMC_MPU0..3` reconfiguration; some topologies also program
  `LLCC_BROADCAST_MPU`.
- Exact QHEE independently registers HLOS SMC `0x02000c16`. Its bounded
  `hyp_assign` handler validates ownership and calls a local stage-2/SMMU
  access-control wrapper; it does not directly call QHEE's generic TZ SMC
  wrapper or the TZ BIMC functions.
- Exact TZ registers XPU toggle SMC `0x02000c23`, but its disable path's
  allowed-base count is zero. Its enable path restores only a registered XPU,
  so this is not an arbitrary HLOS XPU-write or disable primitive.
- Both exact TZ selector branches cover every known remapper and BIMC
  configuration aperture with TZ-owned `MEMNOC_MS_MPU` region 0 and
  `CNOC_SNOC_MS_MPU` region 5; neither record grants ordinary HLOS VMID access.
- The boot master-MPU loop initializes `ANOC2_MPU`, `MSS_NAV_MPU`, and
  `CNOC_AOSS_MPU`, not `BIMC_MPU0..3`. XBL's BIMC literals are in a TZ-branded
  XPU diagnostic table and do not prove a main-XBL policy writer.
- Four successful retained boots register LLCC PMU and LLCC-to-DDR monitors.
  The reset XPU diagnostic is encrypted or unparsed, so it supplies no decoded
  violation and cannot exclude one.
- Live host sysfs proves the A90 remained connected as `04e8:6861`/`A90-LNX`;
  only the Codex sandbox omitted its `/dev/ttyACM0` node. A pinned host bridge
  completed live identity/config and Experiment 005 observations.
- Live `/proc/config.gz` proves `# CONFIG_DEVMEM is not set`. A fixed `1:1`
  character node therefore opens with `ENXIO`; cleanup and final runtime health
  (`pass=11 warn=1 fail=0`) were proved.
- Experiment 007 reproduced the exact historical REPL candidate
  (`b846ae9f…`), proved its named peek/call selftest, and then ran one fixed
  `__ioremap(0x09248080, 0x5c, PROT_DEVICE_nGnRE)` attempt after a fresh warm
  boot. Retained `/proc/last_kmsg` contains the slide result, the `__ioremap`
  return, and a `Non Secure Watchdog Bark` 3.027327 seconds later.
- `msm_readl` was never invoked in the generic attempt and no remapper value
  was read. The exact V2321 rollback prefix SHA-256 is `ca978551…`; native
  version and selftest `pass=11 warn=1 fail=0` are `PROVED` after rollback.
- The fixed inline no-load control (`dbbf81f2…`) returned sentinel `0xc071` and
  preserved runtime health. Its paired one-load candidate (`6fe92825…`) then
  ran once: no value returned, USB/ACM disconnected, and retained last-kmsg
  records a bark at 69.080426 s, last pet at 58.080136 s, bootloader cause
  `Non Secure Watchdog Bark`, and warm reset. `SUPPORTED`: the one fixed load,
  rather than mapping alone, triggered the stall. The result does not identify
  a firewall, XPU, clock/power, or ownership cause by itself. Combined with
  Experiment 009, an active `DC_NOC_BROADCAST_MPU` denial is now `SUPPORTED`,
  not yet causally `PROVED` because no decoded syndrome or runtime register
  readback exists.
- Verification 001 independently re-derived seven load-bearing static claims
  from the raw bytes without reusing any repository tool, and all seven were
  `CONFIRMED`. The full Experiment 009 chain resolves end to end: registry
  `{id=0x3c, base=0x090e0000, name → "DC_NOC_BROADCAST_MPU"}` → both policy
  entries (`region_count=40`) → byte-identical region 11
  (`read=0x80000000`, `write=0x00000000`, `0x09248000..0x09249000` exclusive).
  The XPU disable allowlist is a compile-time `0` at fixed `0x1c122a90`; SMC
  `0x0200030f` is a single `RET` (`0xd65f03c0`); the SHRM helper's decisive
  instructions decode byte-exactly as `slli a9, a9, 12` and
  `addx4 a12, a12, a9`.
- `PROVED` by that audit and previously underweighted: region 11's write access
  word is `0x00000000`, so **no** client class holds write permission, not
  merely no ordinary HLOS VMID. `DC_NOC_NON_BROADCAST_MPU` region 5 matches.
  Sibling regions 12 and 13 carry `0x40000000/0x40000000` and
  `0xf0000000/0xf0000000`, so the write denial is deliberate, not a default.
- The audit checks static facts only. It does not verify their security
  interpretation, and every `UNKNOWN` in section D stands unchanged.
- Verification 002 proves exact XBL has a consumed 26-record raw-dump table at
  `0x14961730`. Index 19 is a 32-byte descriptor for physical
  `0x09060000..0x0906ffff`, description `SHRM MEM region`, filename
  `SHRM_MEM.BIN`; that range contains the complete section-16 workspace and
  both snapshot destinations.
- Its exact primary loop at `0x14917ca8` loads each record as base/size and
  description/filename, advances by `0x20`, and calls registrar `0x14917670`.
  The pinned dload call chain is `0x14902cc4 -> 0x14917740 -> 0x14917c60`.
- The embedded Xtensa blob has one direct `0x25100` literal, referenced by the
  two direction-zero producers. It has no direct u32 literal for `0x25330`,
  `0x259e8`, or their physical addresses. This is a bounded direct/literal
  negative, not proof against dynamically derived consumers.
- A read-only check of mounted `ANDROIDLABSD` found no `SHRM_MEM.BIN`,
  `rawdump.bin`, or exact Experiment-004 A90 firmware filename. Its only A908
  item is the Samsung open-source kernel archive/directory; the exact firmware
  input remains the private live capture in this repository.
- Verifications 003/004 bound exact V2321 before every read and used no
  property service. Live `/proc/cmdline` reports
  `androidboot.debug_level=0x4f4c` (`LOW`),
  `androidboot.force_upload=0x0`, and normal boot-recovery value `0`.
- The S22+ precedent path
  `/sys/module/qcom_dload_mode/parameters/download_mode` is absent on A90.
  Exact A90 4.14 source instead binds `module_param_call(download_mode, ...)`
  to `msm-poweroff.o`; its source-backed live path
  `/sys/module/msm_poweroff/parameters/download_mode` returns `1`.
- Live `panic=-1` and `panic_on_warn=0`. Exact A90 `kernel/panic.c` proves a
  negative nonzero timeout skips delay then calls `emergency_restart()`.
  The newer ramoops `max_reason` parameter is absent, while the retained live
  config independently has `CONFIG_PSTORE=y` and `CONFIG_PSTORE_RAM=y`.
- No reset/dump attempt followed Verifications 003/004 themselves. A separate
  Samsung `04e8:6860` endpoint received no command; only the pinned A90P1
  `04e8:6861` bridge was used.
- Host-only decoder commit `9fdd5d6` loads the committed Experiment-012 plan
  and labels all 494 staged words in a structurally valid `SHRM_MEM.BIN`.
  Twenty focused tests prove the `430/64` shape, ordering, bounds, value
  placement, header/size rejection and zero-dump rejection. `PROVED`: the
  staged inventory does not reach the remapper window at `+0x8080`.
- Verification 005 pins the exact main-XBL outer trigger and XBLRamDump inner
  gate. MID is sufficient for inner vendor admission with FMM unlocked; a
  dload cookie or `0x776655ee` restart reason is independently required outside.
- Verification 006 captured all 10 MiB of live `param` with equal
  device-before/host/device-after SHA-256. It proved `DLOW`, force-upload `0`,
  FMM lock `0`, and dump sink `0` before any mutation.
- The bounded transition changed only the four-byte debug field. A normal MID
  boot proved XBL consumption without rawdump entry; one later SysRq panic
  supplied the outer trigger and was not replayed.
- Host journal proves the crash transport is Samsung `04e8:685d / MSM_UPLOAD`,
  followed by disconnect and return of native `04e8:6861`. The 05c6 Sahara/qdl
  collector captured no file.
- Verification 012 acquired exactly one 65,536-byte `SHRM_MEM.BIN`, SHA-256
  `409550ad226443271a39b6bc060f0e8fb3224111cc03f07a6ee563eaa7098bb7`.
  Its exact header validates at dump offset `0x5100`, and all 494 staged words
  map to the Experiment-012 register plan.
- Set 0 is `SUPPORTED` as populated controller state: 17/18 common four-instance
  MC offset groups are identical and the last is a stable two-by-two split.
  Set 1 is `REFUTED` as a coherent current snapshot: 64/64 values are distinct,
  its four MC `+0x80` values all differ, and 0/24 shared addresses match set 0.
- The original full `param` SHA-256 was restored. A subsequent new boot proved
  LOW, force-upload 0, dump-sink 0, dload master 1, and selftest `fail=0`.
- Experiment 014 bound a single-SG, write-combine, non-secure ION allocation to
  stable PA `0xf0400000..0xf13fffff`. A unique `/proc/kpageflags` transition
  window and a pinned dma-buf showed all 4096 pages with zero changed/lost
  pages; secure heaps were never selected.
- Live row-conflict timing proves that rank-relative PA bits `16..23` contribute
  XOR terms to a three-dimensional bank-selection row space generated from
  PA13..PA15. Four held-out kernel vectors and four one-bank-bit negatives have
  a 314 milli-tick p10/p90 separation gap; same-row `D=0x800` controls remain
  centred near zero.
- One equivalent observed bank basis is
  `0x9d2000, 0xa74000, 0x4e8000`. This basis is not a claim about named hardware
  BA-bit order; it identifies the invariant GF(2) row space.
- Literal audit searched all seven non-zero combinations across the nine pinned
  Experiment-004 images and the real 64-KiB SHRM snapshot. SHRM has no hit at
  any alignment; firmware has zero aligned u32 hits. All four raw TZ substring
  hits are one-byte-shifted pieces of monotonic 64-bit address tables, not
  direct hash-mask constants.
- Experiment 017 proves the exact XBL table at VA `0x146b1218` / file
  `0x630b8`: 122 nonzero u64 addresses plus a zero terminator, inclusive hash
  `d5042980…`, structurally 30 four-instance MC groups plus two globals. It
  covers all 12 `qhs_mc +0x400/+0x404/+0x4d0` candidates and excludes
  `qhs_mccc +0x118` plus `qhs_mccc_master +0x294` from this table only. The
  independent SHRM-plan intersections are set0 `100/430`, set1 `4/64`, union
  `100`, table-only `22`, SHRM-only `370`.
- Experiment 017's exact helper range is `0x146ae138..0x146ae18c`
  (end-exclusive), file `0x62318`, 0x54 bytes, hash `f325a8bf…`. Static
  control flow constructs sentinel prefill and conditional 32-bit read/copy to
  distinct VA `0x146bf300`; store bases inside the range are only X12/X8, so
  this helper is not a candidate-register writer. The table is an exact
  on-disk zero-sentinel table; helper traversal has no hard 122-entry cap.
  Exactly two direct BL callsites occur in file-backed executable PT_LOADs;
  current-boot execution and indirect/tail reachability remain `UNKNOWN`.
- Experiment 017 command was
  `python3 tools/sm8150_xbl_mc_snapshot_xref.py --output evidence/manifests/017-xbl-mc-snapshot-xref-20260825-01.manifest.json`.
  Public manifest/tool/focused-test SHA-256 are respectively
  `b1db2123…` / `2baa9e3d…` / `5b0f6f3e…`; 20 focused and all 279 repository
  unittest-discovery tests pass. An
  independent read-only raw-byte review accepted the result and emitted no
  artifact or artifact hash. Date: 2026-08-25 KST; device/SMC/MMIO access: none.
- Experiment 018 Stage 1A proves the exact XBL literal and strict store-offset
  census only: each target's single 8-byte table encoding yields the one
  aligned u32/u64 matches at the same file offset (two views of one entry, not
  independent literals), with no separate target literal elsewhere; the one
  aligned outside-table base literal is the RWE `0x80154`/`0x148bc254` fact,
  and matching offsets total 14. The public resolved hit count is `null` and
  classification is `STAGE1A_LITERAL_AND_STORE_OFFSET_CENSUS_WRITER_UNKNOWN`;
  literal or offset equality is not a writer proof. Stage 2A then analyzed only
  four non-SP RX candidates; seven SP candidates remain runtime-derived and
  three RWE candidates remain ambiguous.
- Experiment 018 Stage 2A proves the bounded model outcome for exactly four
  pinned non-SP RX candidates: two window-limit no-definitions, one unsupported
  LDR-to-X8 definition at `0x146a70b4`, and one BL control boundary before the
  older X19 definition. It resolves zero bases and zero exact target hits. The
  result refutes only this supported direct-definition path and makes no claim
  that no writer exists.
- Experiment 018 command was
  `python3 tools/sm8150_xbl_mc_writer_xref.py --output evidence/manifests/018-xbl-mc-writer-xref-stage1a-20260825-01.manifest.json`.
  Public manifest/tool/focused-test SHA-256 are respectively
  `8861a5626576fac32a83c295c34be63f91fd5e3f4b434490d567fb2984bb192d`,
  `9806b64c01f9965161966c88bbf5b943d953e790664c3136b2a116da63f8dc57`, and
  `b5fbf50e545b9df86d45ac012106d8905af231d9e94b0b2dd1927ec365da13d8`;
  8 focused and all 287 repository unittest-discovery tests pass. All 54
  public manifests parse as JSON and the generated manifest is mode 0644.
  Date: 2026-08-25 KST; device/SMC/MMIO access: none.
- Experiment 018 Stage 2A command was
  `python3 tools/sm8150_xbl_mc_writer_stage2a.py --output evidence/manifests/018-xbl-mc-writer-xref-stage2a-20260825-01.manifest.json`.
  Tool/test/manifest SHA-256 values are
  `eb0a8ce21154d97d052de9f7e4e0de40f85087a8cb517179f7c44332e9d85eb0`,
  `1272fadb0bcc6b883f74577284312ee34678975fa7ba60377d05d86927960b3b`, and
  `eeed732e4a6cecd60453e9088d8c3d4c7ed207a1e7c723bae91e27033d134a4b`;
  14 focused and 301 full repository unittest-discovery tests pass; all 55
  public manifests parse as JSON and regeneration is byte-identical; mode
  `0644`; device/SMC/MMIO access: none.
- Experiment 018 Stage 2B command was
  `python3 tools/sm8150_xbl_mc_writer_stage2b.py --output evidence/manifests/018-xbl-mc-writer-xref-stage2b-20260825-01.manifest.json`.
  Tool/test/manifest SHA-256 values are
  `aa35d8b303a7ea32a086d601b1f08390b1cad0932f105209ac337f394813dbcb`,
  `af7ca7b46550dda13e85e517c0c1c1df19b6414549d06415316b6d428e020fc9`, and
  `a4715112e27c74e5548ecb49f09106c236146c8a0216c87446ddbd3c355ccca6`;
  10 focused and 311 full repository unittest-discovery tests pass; all 56
  public manifests parse as JSON and regeneration is byte-identical; mode
  `0644`; device/SMC/MMIO access: none.

## B. 현재 HYPOTHESIS

- One or more section-16 readback registers may expose or derive the now-proved
  XOR bank-selection state not represented by the XBL diagnostic formula.
- The final bank-selection owner is MCCC/MC or closely coupled DDRSS logic
  initialized before HLOS. Prediction: exact init stores or register semantics
  will encode a row space equivalent to `0x9d2000/0xa74000/0x4e8000`, although
  not necessarily as those literal masks.
- The retained watchdog may be the XPU denial's downstream fabric response.
  Static policy coverage and lack of an HLOS grant support this; the encrypted
  or unparsed TZ log prevents a causal syndrome match.
- One or more coherent set-0 MC/MCCC words may encode geometry, channel
  selection, or a hidden transform term. Their repeated/two-by-two structure
  makes this testable, but no semantic assignment is presently proved.

## C. REFUTED

- “The A90 self-built kernel disabled all RKP/QHEE paths.”
- “Mapping an EL2 interface/range proves arbitrary EL2 private-memory R/W.”
- “A similar hash exists, therefore the AMD vulnerability exists on Qualcomm.”
- “`mc_virt-base = 0x09680000` alone identifies final memory-controller decode
  registers.”
- “RKP appearing in a broad `/proc/iomem` System RAM resource proves it is
  accessible/unprotected.”
- “Linux `raw_id/raw_version` directly supply XBL's DCB filename fields.” Live
  values `165/3` do not match exact CFGL `0x6003/{0x0100,0x0200}`.
- “The exact live DCB revision remains unknown.” Retained XBL/CDT records select
  `/6003_0200_1_dcb.bin` without using Linux SMEM fields.
- “XBL's special 12-GiB remap case applies to this boot.” Exact topology is
  3072+3072 MiB and selects the ordinary 6-GiB row 7.
- “The current kernel can read the remapper through `/dev/mem`.” Live config has
  `CONFIG_DEVMEM=n`; the fixed `1:1` node fails at open before MMIO.
- “The generic REPL `__ioremap -> msm_readl -> __iounmap` sequence is a safe
  narrow kernel adapter.” The first verified `__ioremap` return was followed by
  a non-secure watchdog before `msm_readl`; all three targets are also `DENY`
  under the existing host call-safety classifier.
- “The tested `0x09248080` address lies outside the exact TrustZone XPU policy.”
  Both selector branches cover it with the same `DC_NOC_BROADCAST_MPU` region.
- “The critical policy word is `0x80`.” The exact little-endian uint32 field is
  `0x80000000`.
- “The critical static record grants ordinary HLOS access.” Its exact
  conversion has no HLOS VMID bit and no standard VMID permission word.
- “`BIMC_MPU0..3` are unconfigured because they are absent from both static
  policy lists.” Exact TZ memory-lock code configures them dynamically.
- “Kernel `hyp_assign` directly programs TZ's BIMC XPU.” Exact QHEE intercept
  instead uses its local ownership/stage-2/SMMU mapping path; TZ has a separate
  same-ID fallback implementation.
- “The HLOS-visible XPU toggle can disable a selected controller XPU.” Its
  exact allowed-disable count is zero.
- “The named RPM-region SMC unlocks an XPU in this exact TZ build.” The exact
  TZ handler for `0x0200030f` is a single `RET`.
- “The exact XBL diagnostic coordinate formula itself contains an XOR/hash or
  admits two physical addresses for one DRAM coordinate.” Its 32 input bits are
  partitioned exactly once and the inverse reconstructs the PA.
- “The `invert_row` string alone proves final PA-to-row transform state.” Its
  two pinned users report and forward a local DDR-code flag outside the Quest
  coordinate reporter.
- “Section 16's raw offset tokens imply 4-KiB register offsets or an observed
  write primitive.” The exact SHRM helper proves four-byte scaling and read
  direction for both direct consumers.
- “The SHRM snapshot workspace is statically unprotected or granted to HLOS.”
  Both exact policy branches cover it with the same three TZ-owned regions and
  no comparative HLOS VMID bit.
- “The purpose-built direct EL1 path can observe staged MCCC snapshot word
  `0x0906566c` on this boot.” The only eligible one-load attempt returned no
  value and ended in a non-secure watchdog reset.
- “No exact firmware export path covers the protected SHRM workspace.” XBL's
  consumed raw-dump descriptor covers the full enclosing 64-KiB region.
- “The exact SHRM blob directly exports either derived snapshot through a
  literal HLOS mailbox path.” Neither destination/local physical literal exists
  in the complete blob; the proved export consumer is external XBL code.
- “The S22+ `qcom_dload_mode` sysfs path transfers unchanged to A90.” The exact
  path is absent; the source-backed A90 owner is `msm_poweroff`.
- “Current V2321 has positive observable raw-dump entry signals.” Debug level
  and force-upload are both negative despite the positive dload master switch.
- “Both MID and force-upload are required for A90 rawdump.” Exact XBL and the
  successful live run used MID with force-upload zero.
- “The exact A90 crash transport is Qualcomm 05c6 Sahara/qdl.” The live target
  enumerated as Samsung `04e8:685d / MSM_UPLOAD`; qdl captured no file.
- “No real `SHRM_MEM.BIN` can be collected on this retail target.” Verification
  012 collected and structurally decoded the exact 64-KiB file.
- “Set 1 is a coherent current controller snapshot.” Its captured statistical
  and cross-set consistency checks fail.
- “The dump contains the remapper control window at `+0x8080`.” All staged
  same-page words are below that window.
- “The XBL diagnostic `bank=PA[15:13]` formula is the complete silicon
  bank-selection function.” Experiment 014's held-out live timing requires row
  bits `16..23` in the bank-selection row space.
- “Anonymous cached RAM plus EL0 `DC CIVAC` alone is a valid DRAM classifier on
  this target.” Its result remained LLCC-confounded; the retained proof uses a
  write-combine ION mapping instead.
- “Raw `0x009d2000`, `0x00a74000`, or `0x003a6000` byte matches in the exact TZ
  image directly attribute the hash to TrustZone.” All are unaligned windows
  inside 64-bit address tables advancing by `0x200000`.
- “The exact 0x54-byte helper programs/writes the candidate controller
  addresses.” Its table-derived registers are load bases only; the identified
  STR store bases are X12/X8, the fixed read-copy-buffer aliases.
- “The helper independently enforces a maximum of 122 iterations.” Its
  traversal is zero-sentinel-only; the exact on-disk table's terminator is at
  index 122.

## D. UNKNOWN

- Contributions from rank-relative PA bits `24..31`, exact physical channel
  equations beyond independent PA9/PA10 components, and the reason PA4/PA5
  produce intermediate timing.
- Exact semantic names, bitfields, and lock/writability state of coherent set-0
  section-16 registers; any indirect helper invocation with reverse direction;
  and final-decode meaning.
- Final runtime XPU register state and a decoded XPU syndrome for the fixed
  staged-MCCC read. The observed reset is exact; XPU as its root cause remains
  `SUPPORTED`, not `PROVED`.
- Numeric boot remapper values, runtime MMIO writability, and lock state.
  Destination regions and rank sizes are known, but runtime per-channel source
  bases and the interleave mask are missing. Static TZ policy ownership is now
  proved; its final hardware register state and the precise watchdog response
  remain unresolved.
- Final boot/runtime `BIMC_MPU0..3` policy and control-register values. The TZ
  dynamic initializer is proved, but its runtime inputs, topology selector and
  post-programming readback are not.
- Which exact MCCC/MC/DDRSS register represents or derives the proved bank hash,
  who writes it, and whether it is writable or locked after boot.
- Protection ordering and existence of a post-transform security check.
- Any deterministic normal-RAM DRAM alias or protected-boundary consequence.
- Live boot-image and live-DTB byte hashes.
- Why set 1 is stale/unpopulated/uninitialized; only its use as a coherent
  current snapshot is refuted.
- Any normal-boot HLOS-readable export of the set-0 words. The proved Samsung
  Upload path is post-reset bootloader diagnostics, not an EL1 runtime mapping.
- Experiment 017's successful runtime completion, partial/sentinel output,
  coherent/atomic/current status, MMIO read side effects or faults, mutable
  runtime table contents/lock, indirect BLR/tail-call reachability, and any
  other writer/programmer for these candidates.
- Experiment 018 Stage 1A's base/effective-address resolution, writer identity,
  all unsupported store forms, dynamic/cross-block/cross-call paths, AOP/TZ
  paths, runtime execution/semantics/mutability, alias/bypass, and the meaning
  of the literal/offset matches remain `UNKNOWN`. The RWE three are ambiguous;
  the seven SP-based RX candidates are runtime-derived. No REFUTED writer claim
  is made.
- Experiment 018 Stage 2A leaves the seven SP candidates, three RWE candidates,
  unsupported/cross-block/cross-call/dynamic paths, runtime execution and all
  writer/semantic/mutability/GF(2)/alias/bypass questions `UNKNOWN`.
- Experiment 018 Stage 2B leaves VA-to-PA translation/identity, physical
  destination, execution, writer identity, mixed-width/unsupported/dynamic
  paths, semantics, mutability/lock, GF(2), alias and bypass `UNKNOWN`. Its
  two computed values are XBL virtual-address values only; neighboring ELF
  headers do not establish physical RAM ownership.

## E. SDM855 physical→DRAM pipeline 후보

```text
CPU VA -> ARM stage-1 -> system PA -> NoC/interconnect
       -> four qhs_llcc ICB region-remap windows
       -> XBL intended rank/row/bank/channel/column model
       -> observed low-24 XOR bank selection (PROVED relation; owner UNKNOWN)
       -> PHY -> LPDDR4X coordinate
```

The CPU/MMU, source-visible interconnect endpoints, LLCC/EBI direction, XBL's
four-window region-remap programming, diagnostic formula, and a distinct live
bank-selection relation are `PROVED`. The exact block/register implementing
that relation and precise protection ordering remain `UNKNOWN`.

## F. protection pipeline 후보

```text
EL1 physical range + VMIDs/perms -> QHEE hyp_assign -> stage-2/SMMU ownership
same SMC ID, separate TZ fallback -> memory lock -> dynamic BIMC MPU policy
RKP metadata -> UH call -> SMC -> QHEE/RKP enforcement
EL1 access to qhs_llcc remapper -> DC_NOC_BROADCAST_MPU policy decision
```

Kernel inputs/call boundaries and the static DC_NOC policy covering the tested
configuration PA are `PROVED`; final runtime XPU registers and the protection
position relative to DRAM decode remain `UNKNOWN`.

## G. 가장 가능성 높은 controller/register 후보 Top 5

1. `PROVED value / UNKNOWN semantics`: four `qhs_mc +0x400`, all
   `0xc003ffff`; Experiment 017 adds exact table/read-copy coverage and
   independent observation confidence only.
2. `PROVED value / UNKNOWN semantics`: four `qhs_mc +0x404`, all
   `0x00003333`; Experiment 017 adds exact table/read-copy coverage and
   independent observation confidence only.
3. `PROVED value / UNKNOWN semantics`: four `qhs_mccc +0x118`, all
   `0x00111111`; Experiment 017 excludes these from its table only and does
   not downgrade their transform-state likelihood.
4. `PROVED value pattern / UNKNOWN semantics`: four `qhs_mc +0x4d0`, first
   pair `0x00300014`, second pair `0x00300033`; Experiment 017 adds exact
   table/read-copy coverage and independent observation confidence only.
5. `PROVED value / UNKNOWN semantics`: `qhs_mccc_master +0x294 = 0x00001111`;
   Experiment 017 excludes it from its table only and does not downgrade its
   transform-state likelihood.

Full addresses, values, and qualification fields are in the Verification-012
public manifest and experiment README.

## H. EL1에서 현재 관측 가능한 부분

`PROVED`: `/proc/iomem`, `/proc/meminfo`, live DT reserved-memory, runtime/kernel
identity, LLCC/BWMON resource landmarks, kernel SCM/UH interfaces and their
source-visible PA inputs. `REFUTED`: current-kernel userland `/dev/mem` access.
`REFUTED`: the generic REPL call chain as a safe read adapter. `PROVED`: a
fixed inline map/unmap control can return safely; a paired one-load execution
returned no value and ended in watchdog reset. `PROVED`: its PA is in a
TZ-owned static XPU region with no HLOS grant. `SUPPORTED`: XPU/fabric denial;
final runtime policy remains `UNKNOWN`. Exact XBL's post-reset raw-dump catalog
and one real export are `PROVED`, but they are not an EL1/HLOS runtime API.
`PROVED`: EL1-visible `/proc/kpageflags`, non-secure ION CMA, CNTVCT and normal
RAM timing expose the low-24 bank equivalence relation without controller MMIO.
After final restoration, EL1 observes LOW, force-upload `0`, dump-sink `0`,
dload master `1`, and selftest `fail=0`.

## I. EL2/QHEE가 담당하는 것으로 보이는 부분

`PROVED`: UH/RKP has an EL1-to-SMC call path; exact `hyp` firmware loads into
live `hyp_mem` and contains kernel/ownership protection. Exact QHEE intercepts
SMC `0x02000c16` and enforces ownership with its local stage-2/SMMU access-
control path, separate from TZ's BIMC implementation. `UNKNOWN`: arbitrary EL2
runtime R/W, DDR decode ownership and final protection ordering.

## J. EL3/TrustZone이 담당하는 것으로 보이는 부분

`PROVED`: SCM MP is the kernel-facing boundary. Exact TrustZone consumes its
48-entry XPU registry; both static-policy branches configure
`DC_NOC_BROADCAST_MPU` region 11 over the tested remapper PA as TZ-owned with no
HLOS grant, and exact devcfg does not disable XPU access control. Its separate
assignment fallback dynamically configures `BIMC_MPU0..3`; the XPU-disable SMC
has a zero-entry allowlist. `UNKNOWN`: final register readback and whether any
check is after final DRAM decode.

## K. AMD Skitter 공격과 구조적으로 같은 부분

`PROVED`: both platforms have an XOR-expressible bank-selection relation that
can be reasoned about over GF(2). `SUPPORTED`: both attack questions contain a
system PA, a protection/ownership decision, later DRAM-coordinate selection,
controller state, and the need to distinguish cache/virtual effects from an
actual physical-to-DRAM alias.

## L. AMD와 구조적으로 다른 부분

`PROVED`: AMD's exact Family 16h registers and PCI/MSR access method have no
identified SM8150 equivalent. AMD demonstrates Normal-World transform-state
mutation and a resulting alias; SM8150 currently demonstrates only passive
normal-RAM observation of a bank row space. `SUPPORTED`: Qualcomm's
LLCC/NoC/AOP/QHEE/SCM partitioning creates different owners and potential later
enforcement layers. SM8150 register identity, mutability, lock state and
ordering remain `UNKNOWN`, so this is not yet a structural impossibility proof.

## M. 가장 값싼 다음 실험

Do not repeat the fixed protected load. Experiment 018 Stage 2B completed the
cheap host-only same-block W-wide-move extension for the two Stage 2A window-
limit X8 candidates; both computed values miss the 12 numeric targets. The
seven SP candidates remain runtime-derived and the three RWE candidates remain
ambiguous; all dynamic, cross-block/call and unsupported paths remain
`UNKNOWN`. Any future writer xref must stay host-only and explicitly scoped; do
not perform a broad MMIO scan or device action. A cold-boot repetition is not a
substitute for this writer xref.

## N. 가장 위험한 아직 금지된 실험

Treating a section-16 offset token as a byte offset and writing the resulting
MCCC/MC address. The exact helper proves four-byte scaling for its read path,
but no safe write semantics, restore state, or runtime values are known. Writing
the proved `qhs_llcc + 0x8080` map words while memory traffic is active is also
high risk because it can redirect system PA. Neither is justified without exact
semantics, boot values, a one-core/cache-safe critical section, restore path,
and watchdog/recovery behavior.

Reconciled with the operating policy: neither write is brick-capable, so
neither is forbidden by the binding constraint, and the "watchdog/recovery
behavior" prerequisite is now met by three retained resets. What still
withholds them is information, not safety — set-0 values are available only in
a post-reset snapshot, exact semantics are unknown, and no live readback path
can verify or restore a mutation. They remain low-yield blind writes.

Experiments 015 (normal-RAM alias) and 016 (protected-boundary reach) remain
reserved and `NOT ELIGIBLE`; Experiments 017 and 018 do not satisfy either
gate.

## O. 현재 취약점 가능성 평가

No numeric probability is justified.

Evidence for the attack class being relevant:

- SM8150 has distinct LLCC-to-EBI and DDRSS configuration paths.
- Exact XBL programs a topology-dependent system-PA remapper in four qhs_llcc
  instances before HLOS; exact retained topology selects row 7.
- Qualcomm primary filings describe channel/bank XOR hashing as a design class.
- Protection APIs name system physical ranges; they do not themselves reveal
  final decoded DRAM coordinates.
- A real post-reset snapshot now exposes coherent MC/MCCC value patterns that
  can be cross-checked independently against normal-RAM timing.
- Live write-combine normal-RAM timing now proves a hidden low-24 XOR
  bank-selection relation with held-out positive and one-bank-bit negative
  controls. The transform side of the question is therefore real, rather than
  inferred from patents or diagnostic strings.
- Experiment 017 adds exact-XBL table/read-copy observation confidence for the
  three qhs_mc candidate groups, but does not prove any writer, mutation,
  alias, protected reach or bypass. Experiments 015 and 016 remain `NOT
  ELIGIBLE`.
- Experiment 018 Stage 1A adds exact-XBL literal and syntactic store-offset
  census confidence only: 14 matching offsets (RX11/RWE3), seven SP-based RX
  candidates, and no base/effective-address resolution. It does not prove any
  writer, mutation, alias, protected reach or bypass; 015 and 016 remain `NOT
  ELIGIBLE`.
- Experiment 018 Stage 2A does not prove any writer, mutation, alias, protected
  reach or bypass. It only refutes the supported direct-definition model for
  the four analyzed RX candidates; 015 and 016 remain `NOT ELIGIBLE`.
- Experiment 018 Stage 2B adds numeric-address confidence only for its two
  W-wide-move-resolved X8 candidates. It refutes only exact numeric target
  equality within that model; it does not prove any physical destination,
  writer, mutation, alias, protected reach or bypass. Experiments 015 and 016
  remain `NOT ELIGIBLE`.

Evidence against a presently usable bypass:

- No remapper value has been obtained and no post-boot write has been
  demonstrated. The only fixed read attempt ended in a watchdog reset.
- The first generic-REPL `__ioremap` attempt returned but then caused a
  non-secure watchdog before any `msm_readl`, so that adapter path is retired.
- The purpose-built no-load control passed, but its paired single-load candidate
  produced no value and a second retained non-secure watchdog. This is evidence
  against a presently usable EL1 observation primitive, not proof of a lock or
  firewall.
- The live kernel has `CONFIG_DEVMEM=n`; both default and temporary-node
  userland read paths stop before reaching MMIO.
- No SM8150 Linux code programming such a transform was found, and no exact
  firmware register write has yet been attributed to the recovered row space.
- No normal-RAM physical-to-DRAM alias exists in evidence.
- The recovered bank hash alone does not create a complete-coordinate alias;
  its conflict witnesses intentionally share a bank while selecting different
  rows. The exact XBL diagnostic coordinate formula is also bijective and
  cannot itself create an alias.
- Exact QHEE ownership/stage-2/SMMU enforcement is separate from TZ's dynamic
  BIMC policy, adding a second boundary rather than exposing generic control.
- Every known remapper/BIMC configuration aperture is covered in both static
  TZ policy branches, and the only identified HLOS-visible XPU toggle has a
  zero-entry disable allowlist.
- The complete SHRM snapshot workspace is independently covered by three
  enabled TZ-owned regions in both policy branches, with no ordinary HLOS read
  or write grant.
- The purpose-built paired test separated mapping from access: map/unmap passed,
  while the sole extra load produced no value and a retained non-secure watchdog
  reset. This is strong evidence against usable direct EL1 visibility.
- Exact XBL's alternative is a gated crash/download raw-dump catalog, not a
  normal-world register or shared-memory primitive. Its existence improves
  observability but does not supply transform mutation or an alias.
- The successful export required a persistent debug-level change plus a crash;
  after restoration the current boot is again LOW/force-upload 0. This is a
  diagnostic route, not an always-available runtime primitive.
- Secure ownership, boot-time locking, or a post-transform check could each
  independently make the AMD attack class fail.
- Exact TrustZone firmware names multiple BIMC/MEMNOC/LLCC MPUs, increasing the
  concrete evidence for additional enforcement layers. Experiment 009 proves
  narrow DC_NOC coverage of the tested remapper PA; Experiment 010 proves
  broad branch-invariant no-HLOS coverage for all known remapper/BIMC apertures
  and a separate dynamic BIMC policy path.
- Exact devcfg leaves XPU access control enabled (`disable_xpu_ac=0`), and the
  boot path consumes the selected static policy table.

Critical unknowns are exact set-0 register semantics, any normal-HLOS runtime
export, hash-register identity and encoding, lock/writability state, indirect
reverse-direction use, PA24..31 contributions, final XPU/remapper/MCCC/MC
readback, dynamic BIMC policy inputs, protection ordering, and deterministic
complete-coordinate alias behavior. The defensible current conclusion is
`NORMAL-RAM LOW-24 XOR BANK HASH PROVED / SECURE CONTROLLER APERTURES PROVED /
TRANSFORM MUTATION AND COMPLETE-COORDINATE ALIAS UNPROVED / NO BOUNDARY BYPASS
OBSERVED`.
