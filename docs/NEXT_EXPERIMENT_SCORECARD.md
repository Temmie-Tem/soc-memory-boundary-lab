# Next-experiment scorecard — 2026-08-26

This scorecard ranks host-only follow-up work after Experiments 019–022. It
does not grant live, device, SMC, MMIO, write, or Experiments 015/016
authority. Pre-experiment design observations are not `PROVED`; Experiment 024
conclusions remain next-stage until a qualified, independently reviewed
manifest is committed and integrated.

| Rank | Experiment | Information target | Scope and gate | Status |
|---:|---|---|---|---|
| 1 | 024 | Decide whether Experiment 020's pinned narrow-model false negative is a UFS-PHY path rather than a DDR/MC/DCB path. | Host-only: resolve the exact six-byte walker, its three direct callers/table providers, runtime-base provenance, and XBL-local table alternatives; then cross-check two pinned A90 design-source snapshots while keeping live-DTB identity `UNKNOWN`. Re-derive every design observation into a new manifest before assigning final labels. | `NEXT HOST-ONLY`; highest information value |
| 2 | 023R | Re-test the timing claim only after the protocol and provenance defects are repaired. | Require a protocol comparable to Experiment 014 (including ordering, warmup, barriers, and reopen accounting), physical-allocation PA provenance, and a unique full GF(2) matrix. `PA24=b1^b2` can remain `SUPPORTED` until those gates pass. | `LATER`; 023 is withheld/`NO-GO` and not public |

## Experiment 024 design boundary

The following are `HYPOTHESIS`/next-stage design observations, not final
`PROVED` conclusions: an initializer at `0x1486aafc` returning
`0x01d80000`; a direct six-byte-record walker in
`0x148689a0..0x14868a64`; direct callers at `0x14868640`, `0x1486867c`, and
`0x14868698`; and five XBL-resident six-byte tables. Candidate provider entries
at `0x1486a9b4`, `0x1486a9ec`, and `0x1486aa20`, their selector branches, and
the five table alternatives remain design-only in this scorecard; promotion
requires a qualified, independently reviewed manifest to pin their provenance
and flow. The exact XBL input is
identified by SHA-256
`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.
The two design-source snapshots are not the live DTB; the live DTB hash remains
`UNKNOWN`. The Samsung A908N OSRC DTSI is SHA-256
`c0d42e66ddd5640e2dd7b65527c25fb617008d94a6a04062b9e1077f0eb63849`, size
102,419 bytes, from `OSRC Kernel.tar.gz` (SHA-256
`403fdc49f086d238c01a796c390083c3c47c1754c218e228f29b55cc7c35d554`). The
public r3q DTSI is a corroborating proxy only, SHA-256
`38db804d589bb01206adbf2a351c4d074f5c92f7ef351dc3976cbcb846f1a31c`,
from `kernel_samsung_r3q@e1d271581eff`, file
`arch/arm64/boot/dts/qcom/sm8150.dtsi`. The full files differ, but the complete
UFS node block is byte-identical (4,464 bytes, SHA-256
`cea31db3785be5916a1ff08d1c99b92155a7914b07d09ecb6c3638d8c16ff10a`).
Both sources map `ufsphy_mem` at `0x1d87000+0xda8` and the `ufshc` resource
named `ufs_phy` at `0x1d87000+0xe00`. These details guide the bounded static
reconstruction only. Do not promote them to final `PROVED` facts until a
qualified, independently reviewed Experiment 024 manifest is committed and
integrated.

The decision is specifically whether the false negative is a UFS-PHY table
walk rather than a DDR/MC/DCB writer. Runtime base provenance, table-provider
identity, section semantics, register ownership and any writer interpretation
remain `UNKNOWN` until qualified evidence resolves them. In particular,
every-success-path base
preservation is not currently provable: helper `0x1486abec` reaches an
unresolved `BLR X9` at `0x1486ac1c` before the walkers. Main/local direct stores
show no overwrite, but the current base remains `UNKNOWN`; resolving the BLR
target may be a follow-on if 024 cannot close it. No device action or MMIO
write is part of this scorecard.

## Experiment 023R prerequisites

Experiment 023 is explicitly withheld as `NO-GO`: its timing order is not
comparable to Experiment 014 (fixed order, half warmup, `ISB`, and summed
reopen without `/2`), physical allocation PA provenance is missing so a
`+0x1000` countermodel still fits the labels, and the full GF(2) matrix is
non-unique. Its raw evidence is private and is not integrated or published.
Only a repaired rerun satisfying all three prerequisites may enter the
scorecard as evidence; until then `PA24=b1^b2` is `SUPPORTED`, not `PROVED`.
