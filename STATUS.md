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

## B. 현재 HYPOTHESIS

- Final SM8150 PA-to-channel/rank/bank/row/column state resides in the subset of
  XBL DSF/DCB-driven DDRSS controller logic not yet isolated from PHY training.
- Some channel/bank selection may be XOR-linear over address bits.
- QHEE/TrustZone may own or lock relevant configuration, but no owner/lock
  evidence exists yet.

## C. REFUTED

- “The A90 self-built kernel disabled all RKP/QHEE paths.”
- “Mapping an EL2 interface/range proves arbitrary EL2 private-memory R/W.”
- “A similar hash exists, therefore the AMD vulnerability exists on Qualcomm.”
- “`mc_virt-base = 0x09680000` alone identifies final memory-controller decode
  registers.”
- “RKP appearing in a broad `/proc/iomem` System RAM resource proves it is
  accessible/unprotected.”

## D. UNKNOWN

- Exact final-transform block, MMIO base/offset, width and semantics.
- Reset value, boot value, runtime readability/writability, lock state and owner.
- Exact final-decode XBL/DCB programming call graph and register fields. The
  firmware bytes themselves are now `PROVED` available.
- Protection ordering and existence of a post-transform security check.
- Any deterministic normal-RAM DRAM alias or protected-boundary consequence.
- Live boot-image and live-DTB byte hashes.

## E. SDM855 physical→DRAM pipeline 후보

```text
CPU VA -> ARM stage-1 -> system PA -> NoC/interconnect -> LLCC/HN-facing path
       -> DDRSS MC address decode/interleave/hash -> PHY -> LPDDR4X coordinate
```

The CPU/MMU, source-visible interconnect endpoints, LLCC and EBI direction are
`PROVED`; precise HN/MC/PHY ordering and the transform location are
`HYPOTHESIS/UNKNOWN`.

## F. protection pipeline 후보

```text
EL1 physical range + VMIDs/perms -> SCM MP call -> secure owner/firewall state
RKP metadata -> UH call -> SMC -> QHEE/RKP enforcement
```

Kernel inputs/call boundaries are `PROVED`; exact enforcement hardware and its
position relative to final decode are `UNKNOWN`.

## G. 가장 가능성 높은 controller/register 후보 Top 5

1. `SUPPORTED`: exact XBL DSF/DCB write path; firmware and training ownership
   are proved, final-decode subset still `UNKNOWN`.
2. `SUPPORTED`: populated `xbl_config--sdb2` ELF and repeated configuration
   blocks. Four `0x3404` DCBs and XBL's section-consumption path to
   `0x09065100` are `PROVED`; final-map field identity remains `UNKNOWN`.
3. `PROVED endpoint / UNKNOWN semantics`: `SLAVE_CNOC_DDRSS` configuration path.
4. `PROVED landmark / low transform confidence`: LLCC base `0x09200000`; known
   `0x21000...` fields are cache-slice configuration, not proved decode fields.
5. `PROVED landmarks / low transform-field confidence`: XBL MCCC
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

Determine the live-selected one of four DCBs, then trace DCB section 16 from the
proved `0x09065100` destination through SHRM/DSF into controller writes. This is
host-only and is now the shortest path to exact base/offset/lock candidates.

## N. 가장 위험한 아직 금지된 실험

Writing an unidentified DDRSS decode/interleave/lock register and issuing a
memory access while the new state is active. It can redirect ordinary traffic,
corrupt arbitrary RAM or wedge memory irrecoverably for the boot. No such write
is eligible without an exact register, one-core/cache-safe critical section,
restore path, watchdog/recovery proof and a written gate.

## O. 현재 취약점 가능성 평가

No numeric probability is justified.

Evidence for the attack class being relevant:

- SM8150 has distinct LLCC-to-EBI and DDRSS configuration paths.
- Qualcomm primary filings describe channel/bank XOR hashing as a design class.
- Protection APIs name system physical ranges; they do not themselves reveal
  final decoded DRAM coordinates.

Evidence against a presently usable bypass:

- No EL1-readable or writable final-transform state has been identified.
- No SM8150 Linux code programming such a transform was found.
- No normal-RAM physical-to-DRAM alias exists in evidence.
- Secure ownership, boot-time locking, or a post-transform check could each
  independently make the AMD attack class fail.
- Exact TrustZone firmware names multiple BIMC/MEMNOC/LLCC MPUs, increasing the
  concrete evidence for additional enforcement layers.

Critical unknowns are the exact transform state and owner, its post-boot lock/
access state, firewall ordering, and deterministic alias behavior. The only
defensible current conclusion is `UNKNOWN / NO BYPASS OBSERVED`.
