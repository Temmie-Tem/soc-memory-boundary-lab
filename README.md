# SDM855 Memory Boundary Lab

Private, evidence-led research into the final system-physical-address to DRAM
mapping on Samsung SM-A908N / Qualcomm SM8150.

The central question is whether a Normal World physical address can be checked
by one protection layer but later transformed to a different protected DRAM
destination. This repository does **not** assume the AMD Skitter Creek result
applies to Qualcomm.

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
The exact A90 TWRP code-only System transition is documented in
[docs/A90_TWRP_CODE_BOOT.md](docs/A90_TWRP_CODE_BOOT.md).

Raw dumps, device identifiers, boot/firmware images, and full transcripts are
kept below `evidence/private/` and ignored by Git. Redacted hash manifests are
kept in `evidence/manifests/`.
