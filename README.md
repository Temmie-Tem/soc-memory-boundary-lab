# SDM855 Memory Boundary Lab

Private, evidence-led research into the final system-physical-address to DRAM
mapping on Samsung SM-A908N / Qualcomm SM8150.

The central question is whether a Normal World physical address can be checked
by one protection layer but later transformed to a different protected DRAM
destination. This repository does **not** assume the AMD Skitter Creek result
applies to Qualcomm.

This is a derived project. See [Upstream](#upstream) for the platform it
observes from and the safety method it inherits.

Current phase: source reconstruction plus bounded, source-backed live
observation. Experiment 007 first retired a generic REPL mapping path after a
watchdog before its intended MMIO read. A fixed inline no-load control later
passed; the paired candidate's single fixed 32-bit load produced no value and
was followed by a retained `Non Secure Watchdog Bark`. `SUPPORTED`, not
`PROVED`: the load caused the stall. V2321 was restored by verified boot-prefix
readback and passed final native health. No DDR/controller, XPU, SMMU, SCM,
EL2, EL3, or protected-memory write has been performed.

Host-only Experiment 008 then resolved the exact live DCB and remapper row from
the retained boot records, pinned the six-slot 36-bit XBL writer, and bound
TrustZone `BIMC_MPU0..3` records to `qhs_llcc + 0xe000` beside each remapper at
`+0x8080`. This narrows the ownership question but does not prove policy
coverage, post-boot mutability, an alias, or a bypass.

Host-only Experiment 009 now proves static policy coverage for the tested
instance-0 page. Both exact TrustZone selector branches place `0x09248080` in
enabled, TZ-owned `DC_NOC_BROADCAST_MPU` region 11; exact permission conversion
grants no ordinary HLOS access, and exact devcfg has `disable_xpu_ac=0`.
`SUPPORTED`, not causally `PROVED`: XPU/fabric denial explains the fixed-load
watchdog. A decoded syndrome and final runtime policy readback are still absent.

Host-only Experiment 010 now resolves the missing initializer boundary.
QHEE's exact `hyp_assign` intercept enforces ownership through its local
stage-2/SMMU access-control path, while a separate same-ID TrustZone fallback
reaches dynamic `BIMC_MPU0..3` reconfiguration. The HLOS-visible XPU toggle
cannot disable any XPU because its exact allowed-disable count is zero. Both TZ
policy branches also cover all four remapper and BIMC configuration apertures
with broad TZ-owned records containing no HLOS grant. This is strong Class A/B
candidate evidence for the known controller apertures, not a proof that the
overall AMD attack class is structurally impossible: the final DRAM transform
and post-transform protection ordering remain `UNKNOWN`.

Host-only Experiment 011 recovers an exact XBL Quest DDR diagnostic formula.
For the retained 6-GiB topology its rank boundary is `0x140000000`, exactly
the selected remapper row's rank-1 destination. Rank-relative PA bits map
linearly and bijectively to row/bank/channel/column, with no XOR and no alias in
that bounded formula. Selected DCB section 16 also parses into two exact token
sets whose base tokens match SHRM-visible MCCC/MC/DDRSS pages. Hidden hardware
transform state, token semantics, mutability, and protection ordering remain
`UNKNOWN`; no alias or bypass has been observed.

Host-only Experiment 012 then recovers the exact Xtensa SHRM section-16
consumer. Its helper computes `(base_page << 12) + (offset_token << 2)` and
reads each 32-bit register into a SHRM snapshot buffer. Both exact callsites
pass the read direction; the selected lists produce 430 and 64 register-word
reads and no transform-write stream. Runtime register values and any indirect
reverse-direction path remain `UNKNOWN`.

Host-only Experiment 013 proves that the complete SHRM snapshot workspace is
inside three enabled, TZ-owned regions in both exact policy branches. The
narrow `DC_NOC_NON_BROADCAST_MPU` region is exactly
`0x09060000..0x0906ffff`; none of the six branch/region matches grants ordinary
HLOS read or write. The fixed no-load control at snapshot word `0x0906566c`
returned `0xc071`; its paired candidate differed by one instruction and made
one 32-bit load, returned no value, disconnected USB, and ended in a retained
`Non Secure Watchdog Bark` / `TZBSP_ERR_FATAL_NON_SECURE_WDT`. The operation
was not retried. V2321 was restored by full-prefix SHA-256 and passed final
selftest with zero failures. This blocks the tested direct EL1 snapshot path;
it does not prove that XPU is the causal root or that no hidden transform
exists.

Host-only Verification 001 then audited the evidence chain itself. Every
`PROVED` statement here is one agent's interpretation of the exact bytes, and
Experiments 008–013 consume 004/006 conclusions as pinned inputs, so an early
misinterpretation would be inherited downstream. Seven load-bearing static
claims were re-derived from raw bytes without reusing any repository tool, and
all seven were `CONFIRMED`, with no substantive error and two notation issues.
The audit also records a fact the experiments underweighted: the remapper and
SHRM policy regions deny write to **every** client class, not merely to ordinary
HLOS. It verifies static facts only, not their security interpretation.

Host-only Verification 002 then traced consumers beyond the blocked EL1 path.
Exact XBL contains and actively enumerates a 26-record crash/download raw-dump
table whose index 19 exports the full `0x09060000..0x0906ffff` SHRM range as
`SHRM_MEM.BIN`, covering both snapshot buffers. This refutes “no firmware
export path exists,” but does **not** prove a normal Android/HLOS interface:
FMM/debug-level/token eligibility, reset-time preservation, and actual retail
collection remain `UNKNOWN`. A read-only mounted-SD check found neither
`SHRM_MEM.BIN` nor `rawdump.bin`; the exact A90 firmware used here remains the
private Experiment-004 live capture, not an SD-card artifact.

Claim vocabulary is deliberately closed:

- `PROVED`: directly demonstrated by named source, artifact, or repeated result.
- `SUPPORTED`: multiple observations support the claim, but a decisive link is missing.
- `HYPOTHESIS`: falsifiable explanation with a stated prediction.
- `UNKNOWN`: evidence is presently insufficient.
- `REFUTED`: named evidence contradicts the claim.

Start with [STATUS.md](STATUS.md), then [docs/ARCHITECTURE_MAP.md](docs/ARCHITECTURE_MAP.md)
and [docs/EXPERIMENT_MATRIX.md](docs/EXPERIMENT_MATRIX.md). The cache/VA/PTE/
DMA/IOMMU controls for a future normal-RAM proof are specified in
[docs/NORMAL_RAM_ALIAS_DESIGN.md](docs/NORMAL_RAM_ALIAS_DESIGN.md).

Exact live `xbl/xbl_config/aop/devcfg/tz/hyp/abl` artifacts were acquired in
Experiment 004. Raw bytes remain private; the first static reconstruction is in
[research/live-firmware-static-recon.md](research/live-firmware-static-recon.md).
Experiment 006 follows the exact DCB/SHRM path into the concrete four-instance
ICB/LLCC remapper; see
[research/xbl-shrm-icbcfg-recon.md](research/xbl-shrm-icbcfg-recon.md).
Experiment 007 records both the retired generic path and the completed fixed
inline control/read comparison; see
[experiments/007-kernel-remapper-adapter/README.md](experiments/007-kernel-remapper-adapter/README.md).
Experiment 008's exact evidence recombination is in
[experiments/008-remapper-boundary/README.md](experiments/008-remapper-boundary/README.md).
Experiment 009's consumed XPU policy and permission reconstruction is in
[experiments/009-xpu-policy/README.md](experiments/009-xpu-policy/README.md).
Experiment 010's QHEE/TZ authority split and dynamic BIMC initializer are in
[experiments/010-xpu-initializer/README.md](experiments/010-xpu-initializer/README.md).
Experiment 011's exact diagnostic coordinate formula and DCB/SHRM register-token
inventory are in
[experiments/011-dram-coordinate-map/README.md](experiments/011-dram-coordinate-map/README.md).
Experiment 012's exact SHRM interpreter and read-only section-16 conclusion are
in
[experiments/012-shrm-section16-interpreter/README.md](experiments/012-shrm-section16-interpreter/README.md).
Experiment 013's exact SHRM workspace policy and fixed live-probe preparation
are in
[experiments/013-shrm-snapshot-boundary/README.md](experiments/013-shrm-snapshot-boundary/README.md).
Verification 001's independent re-derivation of the load-bearing static claims
is in
[experiments/verification-001-independent-claim-audit/README.md](experiments/verification-001-independent-claim-audit/README.md).
Verification 002's exact XBL `SHRM_MEM.BIN` descriptor and raw-dump consumer
chain are in
[experiments/verification-002-shrm-dump-export/README.md](experiments/verification-002-shrm-dump-export/README.md).
The exact A90 TWRP code-only System transition is documented in
[docs/A90_TWRP_CODE_BOOT.md](docs/A90_TWRP_CODE_BOOT.md).

Raw dumps, device identifiers, boot/firmware images, and full transcripts are
kept below `evidence/private/` and ignored by Git. Redacted hash manifests are
kept in `evidence/manifests/`.

## Upstream

This research is derived from the local **`android-native-init-lab`** project
(`Temmie-Tem/android-native-init-lab`), which builds a minimal native
Linux-style userspace on Android vendor kernels. That project supplies the
entire platform this repository observes from; none of it originates here.

| Used here | Supplied by upstream |
|---|---|
| V2321 runtime, `pass=11 warn=1 fail=0` selftest | A90 native init baseline |
| `A90-LNX` / `04e8:6861` ACM bridge | USB ACM/NCM stack |
| REPL slide recovery, peek/call, and its call-safety classifier | `workspace/public/src/scripts/revalidation/a90_repl.py` |
| TWRP code-only boot, 60,882,944-byte boot-prefix readback | F1 boot-only transfer process |
| Verified rollback, no-replay, target isolation, health closure | `AGENTS.md` safety contract and `DEVICE_ACTION_PROCESS_V2.md` |

Upstream device-action risk tiers (`H0` host-only, `D0` connected read-only,
`D1` attended non-partition, `F1` boot-only transfer, `R1` privileged
root-data) are the vocabulary behind this repository's experiment design. In
upstream terms, Experiments 008–012 and Verifications 001–002 are `H0`;
Experiments 001/005/006 live capture is `D0`; and the boot-candidate
transitions in Experiments 007 and 013 are `F1`.

### Operating policy for this derived project

Upstream governance is deliberately **not** inherited wholesale. This project
runs under a single binding constraint set by the maintainer:

> Anything that cannot permanently brick the device may be implemented and
> executed quickly, without the upstream per-action approval ladder.

Practically, that draws the line at persistence rather than at hazard:

| Permitted — volatile, recovered by power cycle | Forbidden — irreversible |
|---|---|
| Controller/remapper/MCCC/MC MMIO writes | `xbl`, `xbl_config`, `tz`, `hyp`, `devcfg`, `aop`, `abl` partition writes |
| Any non-persistent register mutation | QFPROM/eFuse writes (one-time programmable) |
| Watchdog reset and warm reboot | RPMB, secure storage, anti-rollback counters |
| Boot-partition candidates with verified rollback | GPT/partition-table edits; interrupting a partition write |

The bootloader-class partitions are the real boundary: corrupting them leaves
no recovery path on this device without an authorized firehose programmer, and
upstream `AGENTS.md` permanently forbids the `qdl`/Sahara path for the same
reason.

The recoverable side of that line is empirically demonstrated, not assumed:
Experiments 007 (twice) and 013 (once) each ended in `Non Secure Watchdog
Bark`, warm reset, intact V2321 by full-prefix SHA-256, and a passing native
selftest.

Two consequences are recorded deliberately:

- Some gates in this repository are stricter than the policy above. In
  particular `STATUS.md` section N withholds a remapper write partly for
  unknown "watchdog/recovery behavior", which the three retained resets now
  establish. Where a gate and this policy disagree, the gate is the
  conservative historical position, not a safety requirement.
- Device-state history is split. Upstream's `CAMPAIGN_LEDGER_A90.md` does not
  record this project's device actions, so upstream alone is not a complete
  account of the A90's physical state.
