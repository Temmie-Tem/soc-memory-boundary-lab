# Initial Reconnaissance Status — 2026-08-25

Current research state: `NO_BOUNDARY_BYPASS_OBSERVED`

Current class: `UNKNOWN — not enough evidence for A, B, C, D, or E`

Device mutation: no partition, memory-controller, MMIO, SCM, EL2, EL3, or
protected-memory write. Experiment 004 created and removed fixed temporary
block-device nodes under `/dev`; partition data access was read-only.

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
- The separate exact TrustZone ELF contains the same `/dev/icbcfg/boot` DAL
  identity and four-base, six-slot layout record. Runtime invocation/locking is
  still `UNKNOWN`.

## B. 현재 HYPOTHESIS

- Final SM8150 PA-to-channel/rank/bank/row/column state extends beyond, or is
  partly encoded by, the now-proved ICB/LLCC region remapper and the remaining
  SHRM/MCCC/MC logic not yet isolated from PHY training.
- Some channel/bank selection may be XOR-linear over address bits.
- QHEE/TrustZone may own or lock relevant configuration, but no owner/lock
  evidence exists yet. TrustZone's duplicate `icbcfg` record makes this a
  narrower, directly testable hypothesis.

## C. REFUTED

- “The A90 self-built kernel disabled all RKP/QHEE paths.”
- “Mapping an EL2 interface/range proves arbitrary EL2 private-memory R/W.”
- “A similar hash exists, therefore the AMD vulnerability exists on Qualcomm.”
- “`mc_virt-base = 0x09680000` alone identifies final memory-controller decode
  registers.”
- “RKP appearing in a broad `/proc/iomem` System RAM resource proves it is
  accessible/unprotected.”

## D. UNKNOWN

- Exact final channel/rank/bank/row/column transform fields. A system-PA region
  remapper now has exact MMIO bases/offset range; its finer DRAM-decode role is
  `UNKNOWN`.
- Reset value, boot value, runtime readability/writability, lock state and owner.
- Exact final-decode XBL/DCB programming call graph and register fields. The
  firmware bytes themselves are now `PROVED` available.
- Protection ordering and existence of a post-transform security check.
- Any deterministic normal-RAM DRAM alias or protected-boundary consequence.
- Live boot-image and live-DTB byte hashes.

## E. SDM855 physical→DRAM pipeline 후보

```text
CPU VA -> ARM stage-1 -> system PA -> NoC/interconnect
       -> four qhs_llcc ICB region-remap windows
       -> later MCCC/MC address decode/interleave/hash
       -> PHY -> LPDDR4X coordinate
```

The CPU/MMU, source-visible interconnect endpoints, LLCC/EBI direction and XBL's
four-window region-remap programming are `PROVED`; the finer channel/bank/row
decode and precise protection ordering remain `HYPOTHESIS/UNKNOWN`.

## F. protection pipeline 후보

```text
EL1 physical range + VMIDs/perms -> SCM MP call -> secure owner/firewall state
RKP metadata -> UH call -> SMC -> QHEE/RKP enforcement
```

Kernel inputs/call boundaries are `PROVED`; exact enforcement hardware and its
position relative to final decode are `UNKNOWN`.

## G. 가장 가능성 높은 controller/register 후보 Top 5

1. `PROVED region remapper / UNKNOWN final hash`: four XBL-programmed
   `qhs_llcc + 0x8080` windows at `0x09248080`, `0x092c8080`, `0x09348080`,
   `0x093c8080`, using 32-bit offsets through `+0x58`.
2. `PROVED transport / UNKNOWN semantics`: DCB section 16 copied to
   `qhs_shrm_mem + 0x5100` and consumed alongside installed SHRM firmware.
3. `PROVED landmarks / high remaining-decode value`: four-channel `qhs_mccc`,
   `qhs_llcc`, and `qhs_mc` windows encoded in exact XBL topology.
4. `PROVED endpoint / UNKNOWN semantics`: `SLAVE_CNOC_DDRSS` configuration path.
5. `PROVED landmark / low final-hash confidence`: XBL MCCC master
   `0x090b0000`, AOP DDR manager, and LLCC-to-DDR BWMON `0x090cd000`.

Full per-candidate fields are in `research/sm8150-memory-subsystem.md`.

## H. EL1에서 현재 관측 가능한 부분

`PROVED`: `/proc/iomem`, `/proc/meminfo`, live DT reserved-memory, runtime/kernel
identity, LLCC/BWMON resource landmarks, kernel SCM/UH interfaces and their
source-visible PA inputs. `UNKNOWN`: final decode register values.

## I. EL2/QHEE가 담당하는 것으로 보이는 부분

`PROVED`: UH/RKP has an EL1-to-SMC call path; exact `hyp` firmware loads into
live `hyp_mem` and contains kernel/ownership protection. `UNKNOWN`: arbitrary
EL2 runtime R/W, DDR decode ownership and final protection ordering.

## J. EL3/TrustZone이 담당하는 것으로 보이는 부분

`PROVED`: SCM MP is the kernel-facing boundary, and exact TrustZone bytes name
BIMC_MPU0..3, MEMNOC_MS_MPU and LLCC_BROADCAST_MPU. `UNKNOWN`: which are enabled
and whether any check is after final decode.

## K. AMD Skitter 공격과 구조적으로 같은 부분

`SUPPORTED`: Both research questions contain system PA, a protection/ownership
decision, a later DRAM coordinate mapping, possible XOR/interleave state, and the
need to distinguish cache/virtual aliases from actual physical-to-DRAM aliases.

## L. AMD와 구조적으로 다른 부분

`PROVED`: AMD's exact Family 16h registers and PCI/MSR access method have no
identified SM8150 equivalent. `SUPPORTED`: Qualcomm's LLCC/NoC/AOP/QHEE/SCM
partitioning creates different owners and potential later enforcement layers.
Mutability, lock state and ordering are still `UNKNOWN`, so this difference is
not yet a structural impossibility proof.

## M. 가장 값싼 다음 실험

Capture the fixed live SoC identity fields to select one DCB, then read only
`+0x00..+0x58` from the four proved qhs_llcc remapper windows. Comparing the
four boot-programmed maps is now the cheapest test of visibility and lock/access
state; no write is needed. Fixed-address collectors for both steps are
implemented and host-tested.

## N. 가장 위험한 아직 금지된 실험

Writing the enable or map words in any proved `qhs_llcc + 0x8080` window while
ordinary memory traffic is active. It can redirect the system-PA aperture,
corrupt arbitrary RAM or wedge the boot. No write is eligible until boot values,
field semantics, post-boot lock state, a one-core/cache-safe critical section,
an exact restore path and watchdog/recovery behavior are established.

## O. 현재 취약점 가능성 평가

No numeric probability is justified.

Evidence for the attack class being relevant:

- SM8150 has distinct LLCC-to-EBI and DDRSS configuration paths.
- Exact XBL programs a topology-dependent system-PA remapper in four qhs_llcc
  instances before HLOS.
- Qualcomm primary filings describe channel/bank XOR hashing as a design class.
- Protection APIs name system physical ranges; they do not themselves reveal
  final decoded DRAM coordinates.

Evidence against a presently usable bypass:

- No post-boot EL1 read or write of the proved remapper windows has yet been
  demonstrated.
- No SM8150 Linux code programming such a transform was found.
- No normal-RAM physical-to-DRAM alias exists in evidence.
- Secure ownership, boot-time locking, or a post-transform check could each
  independently make the AMD attack class fail.
- Exact TrustZone firmware names multiple BIMC/MEMNOC/LLCC MPUs, increasing the
  concrete evidence for additional enforcement layers.

Critical unknowns are the exact transform state and owner, its post-boot lock/
access state, firewall ordering, and deterministic alias behavior. The only
defensible current conclusion is `UNKNOWN / NO BYPASS OBSERVED`.
