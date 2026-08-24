# SDM855 Memory Boundary Lab

Private, evidence-led research into the final system-physical-address to DRAM
mapping on Samsung SM-A908N / Qualcomm SM8150.

The central question is whether a Normal World physical address can be checked
by one protection layer but later transformed to a different protected DRAM
destination. This repository does **not** assume the AMD Skitter Creek result
applies to Qualcomm.

Current phase: source reconstruction plus source-backed, read-only observation.
Experiment 007 temporarily booted a fixed REPL candidate; its first
`__ioremap` returned and then the device hit a non-secure watchdog before any
MMIO read. V2321 was restored by verified boot-prefix readback. No
DDR/controller, XPU, SMMU, SCM, EL2, EL3, or protected-memory write has been
performed.

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
Experiment 007 retires the generic-REPL mapping path and leaves a purpose-built
kernel adapter as the next read-only test; see
[experiments/007-kernel-remapper-adapter/README.md](experiments/007-kernel-remapper-adapter/README.md).

Raw dumps, device identifiers, boot/firmware images, and full transcripts are
kept below `evidence/private/` and ignored by Git. Redacted hash manifests are
kept in `evidence/manifests/`.
