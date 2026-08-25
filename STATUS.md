# Initial Reconnaissance Status — 2026-08-25

Current research state: `NO_BOUNDARY_BYPASS_OBSERVED`

Current class: `A/B CANDIDATE — static controller-aperture policy and secure
initializer paths proved; exact XBL diagnostic mapping is bijective and
non-aliasing; section-16 is a read-only SHRM snapshot path whose complete
workspace has no static HLOS grant and whose fixed direct EL1 read path ended
in watchdog reset; exact XBL has a gated crash/download `SHRM_MEM.BIN` export
covering the workspace, but normal-HLOS visibility, indirect write paths,
hidden transform and protection ordering remain unresolved; current V2321 dump
entry signals are incomplete (`LOW`, force-upload 0, dload master 1)`

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
- No reset/dump attempt followed these reads. A separate Samsung `04e8:6860`
  endpoint received no command; only the pinned A90P1 `04e8:6861` bridge was
  used.
- Host-only decoder commit `9fdd5d6` loads the committed Experiment-012 plan
  and labels all 494 staged words in a structurally valid `SHRM_MEM.BIN`.
  Twenty focused tests prove the `430/64` shape, ordering, bounds, value
  placement, header/size rejection and zero-dump rejection. `PROVED`: the
  staged inventory does not reach the remapper window at `+0x8080`.

## B. 현재 HYPOTHESIS

- Final hardware PA-to-coordinate state may extend beyond the now-proved,
  bijective XBL diagnostic formula through SHRM/MCCC/MC logic not yet decoded.
- One or more section-16 readback registers may expose hidden XOR, interleave,
  or swizzle state not represented by the diagnostic formula.
- The retained watchdog may be the XPU denial's downstream fabric response.
  Static policy coverage and lack of an HLOS grant support this; the encrypted
  or unparsed TZ log prevents a causal syndrome match.
- A successful XBL raw-dump collection may contain 430/64 controller words
  populated by collection time. Prior-boot preservation is not required;
  stale or zero words are themselves measurable outcomes. This predicts a
  64-KiB `SHRM_MEM.BIN` whose workspace header and staged ranges validate
  against the pinned layout.

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

## D. UNKNOWN

- Whether hardware adds any transform beyond the exact XBL diagnostic
  channel/rank/bank/row/column model.
- Runtime values and lock state of the section-16 readback registers; any
  indirect helper invocation with reverse direction; and final-decode meaning.
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
- Exact hidden/final channel/bank/row decode state, if any, after the proved
  region-remapper call graph.
- Protection ordering and existence of a post-transform security check.
- Any deterministic normal-RAM DRAM alias or protected-boundary consequence.
- Live boot-image and live-DTB byte hashes.
- Whether current retail FMM/debug-level/token policy permits the exact XBL
  raw-dump path; whether SHRM is populated at collection time; the operative
  SD/USB transport; and any normal-boot HLOS-readable export of the same words.
- Which exact persistent/boot producer supplies `androidboot.debug_level` and
  `androidboot.force_upload`, whether a reversible bounded control exists, and
  how FMM/token policy joins those values.

## E. SDM855 physical→DRAM pipeline 후보

```text
CPU VA -> ARM stage-1 -> system PA -> NoC/interconnect
       -> four qhs_llcc ICB region-remap windows
       -> XBL intended rank/row/bank/channel/column model
       -> possible additional SHRM/MCCC/MC hardware transform (UNKNOWN)
       -> PHY -> LPDDR4X coordinate
```

The CPU/MMU, source-visible interconnect endpoints, LLCC/EBI direction, XBL's
four-window region-remap programming, and diagnostic coordinate formula are
`PROVED`; additional hardware decode and precise protection ordering remain
`HYPOTHESIS/UNKNOWN`.

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

1. `PROVED readback candidate / UNKNOWN final-decode meaning`: per-channel MCCC
   at `0x09250000`, `0x092d0000`, `0x09350000`, `0x093d0000`; exact SHRM reads
   use `(page<<12)+(token<<2)` with `0x46` and `0x44..0x47` families.
2. `PROVED readback candidate / UNKNOWN final-decode meaning`: per-channel MC
   roots `0x09260000`, `0x092e0000`, `0x09360000`, `0x093e0000`; ten records
   cover the root plus six matching non-root subpage families.
3. `PROVED readback candidate / UNKNOWN semantics`: MCCC master `0x090b0000`, with
   compact tokens `0xa5` and `0x0,0xa0,0xa2..0xa8`.
4. `PROVED readback candidate / UNKNOWN semantics`: DDRSS regs `0x090c0000`, tokens
   `0x16,0x17,0x2c`.
5. `PROVED system-PA remapper / UNKNOWN final-hash role`: four
   `qhs_llcc + 0x8080` windows with 36-bit fields through `+0x58`.

Full per-candidate fields are in `research/sm8150-memory-subsystem.md`.

## H. EL1에서 현재 관측 가능한 부분

`PROVED`: `/proc/iomem`, `/proc/meminfo`, live DT reserved-memory, runtime/kernel
identity, LLCC/BWMON resource landmarks, kernel SCM/UH interfaces and their
source-visible PA inputs. `REFUTED`: current-kernel userland `/dev/mem` access.
`REFUTED`: the generic REPL call chain as a safe read adapter. `PROVED`: a
fixed inline map/unmap control can return safely; a paired one-load execution
returned no value and ended in watchdog reset. `PROVED`: its PA is in a
TZ-owned static XPU region with no HLOS grant. `SUPPORTED`: XPU/fabric denial;
final runtime policy and decode register values remain `UNKNOWN`. Exact XBL's
post-reset raw-dump catalog is `PROVED`, but it is not an EL1/HLOS runtime API.
EL1 can observe property-free gate inputs: current values are `LOW`,
force-upload `0`, dload master `1`, panic `-1`, and panic-on-warn `0`.

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

`SUPPORTED`: Both research questions contain system PA, a protection/ownership
decision, a later DRAM coordinate mapping, possible controller state, and the
need to distinguish cache/virtual aliases from actual physical-to-DRAM aliases.

## L. AMD와 구조적으로 다른 부분

`PROVED`: AMD's exact Family 16h registers and PCI/MSR access method have no
identified SM8150 equivalent. The recovered SM8150 XBL diagnostic formula is a
direct bit partition with no XOR and no alias, unlike AMD's demonstrated
mutable bank-map primitive. `SUPPORTED`: Qualcomm's LLCC/NoC/AOP/QHEE/SCM
partitioning creates different owners and potential later enforcement layers.
Hidden hardware state, mutability, lock state and ordering remain `UNKNOWN`, so
this difference is not yet a complete structural impossibility proof.

## M. 가장 값싼 다음 실험

Do not repeat the fixed load or trigger a reset: the read-only eligibility
inventory is complete and current visible signals are negative. The next
cheapest step is host-only recovery of the exact producers and reversible
control path for `androidboot.debug_level` and `androidboot.force_upload`, plus
the FMM/token join. In parallel, Experiment 014 remains host-ready for a
normal-RAM timing implementation. The SHRM decoder is already ready for the
first valid dump; controller values remain `UNKNOWN` until such a file exists.

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
withholds them is information, not safety — no boot values are readable from
EL1, so a write cannot be verified, restored, or interpreted. They are blind
writes with near-zero yield, not prohibited actions.

## O. 현재 취약점 가능성 평가

No numeric probability is justified.

Evidence for the attack class being relevant:

- SM8150 has distinct LLCC-to-EBI and DDRSS configuration paths.
- Exact XBL programs a topology-dependent system-PA remapper in four qhs_llcc
  instances before HLOS; exact retained topology selects row 7.
- Qualcomm primary filings describe channel/bank XOR hashing as a design class.
- Protection APIs name system physical ranges; they do not themselves reveal
  final decoded DRAM coordinates.

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
- No SM8150 Linux code programming such a transform was found.
- No normal-RAM physical-to-DRAM alias exists in evidence.
- The exact XBL diagnostic coordinate formula is bijective, contains no XOR,
  and cannot itself create an alias. Any analogue now requires hidden hardware
  state not represented by that formula.
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
- The current boot supplies `LOW` and `force_upload=0`; therefore the proved
  catalog is not presently backed by positive observable entry signals.
- Secure ownership, boot-time locking, or a post-transform check could each
  independently make the AMD attack class fail.
- Exact TrustZone firmware names multiple BIMC/MEMNOC/LLCC MPUs, increasing the
  concrete evidence for additional enforcement layers. Experiment 009 proves
  narrow DC_NOC coverage of the tested remapper PA; Experiment 010 proves
  broad branch-invariant no-HLOS coverage for all known remapper/BIMC apertures
  and a separate dynamic BIMC policy path.
- Exact devcfg leaves XPU access control enabled (`disable_xpu_ac=0`), and the
  boot path consumes the selected static policy table.

Critical unknowns are the reversible producer/control path for current negative
gate values, FMM/token eligibility, collection-time population for the proved XBL
snapshot-dump path, any normal-HLOS runtime export, runtime snapshot values,
lock state, indirect
reverse-direction use, runtime source-base/interleave state, final
XPU/remapper/MCCC/MC readback, dynamic BIMC policy inputs, protection ordering,
any transform hidden from the diagnostic, and deterministic alias behavior. The
defensible current conclusion is `SECURE CONTROLLER-APERTURE POLICY/INITIALIZER
PROVED / SHRM SECTION-16 READ-ONLY SNAPSHOT PROVED FOR DIRECT CONSUMERS / XBL
RAWDUMP EXPORT PRESENT BUT HLOS RUNTIME EXPORT UNPROVED / XBL DIAGNOSTIC MAP
NON-ALIASING / HIDDEN FINAL TRANSFORM UNKNOWN / NO BYPASS OBSERVED`.
