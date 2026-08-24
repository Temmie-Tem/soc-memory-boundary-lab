# Experiment Matrix

| ID | Hypothesis / question | Observable prediction | Controls | State/result |
|---|---|---|---|---|
| 001 | Live target exposes stable topology and reserved ranges read-only. | A90P1 `cat/ls` returns framed, hashable data and binary DT cells. | Fixed allowlist, no retry, target-pinned bridge, host parser tests. | `PROVED`, one live capture; repeat count 1. |
| 002 | Cold boots retain identical fixed carveouts. | DT `reg` values and structural `/proc/iomem` holes match across cold boot A/B. | Same kernel/runtime, hashes, compare dynamic counters separately. | `UNKNOWN`, not yet run. |
| 003 | Stock-like and research boots advertise the same protected ranges. | Fixed ranges equal; differences are attributable to overlays/runtime. | Bind exact boot artifact; do not equate version string with image hash. | `UNKNOWN`. |
| 004 | Exact live boot-firmware bytes can be acquired without partition writes. | Device pre-hash, host raw hash and device post-hash match for every allowlisted partition. | Live GPT/sysfs identity, `ro=1`, exact byte count, bounded size, fixed node names, cleanup inventory. | `PROVED`: nine artifacts, 26,779,648 bytes; all triple hashes match. |
| 005 | Source-backed LLCC/BWMON/MCCC registers are readable from EL1. | Known ID/status/counter fields return plausible values without abort. | Read only exact documented widths; known-negative unmapped read in emulator/host only, never blind device scan. | `UNKNOWN`; adapter not yet executed. |
| 006 | Final address mapping is programmed by XBL/DDR DSF/DCB. | XBL config consumption leads to topology-dependent MMIO writes. | Exact live firmware hashes and call-graph provenance; distinguish training/perf from map programming. | `SUPPORTED`: XBL DDR/DSF/DCB ownership proved; exact decode writes unknown. |
| 007 | Normal-RAM bank/channel relationships fit a stable GF(2) model. | Timing clusters produce a cross-validated XOR matrix. | Fresh pages, pagemap/PA proof, randomized pairs, cache flush, frequency pinning, hold-out pairs. | `UNKNOWN`. |
| 008 | A controlled transform state creates physical-to-DRAM alias. | `PA_A != PA_B` but writes through one are observed through the other after cache-neutral independent reads. | Prove distinct PTE/PAs; CPU and DMA controls; cache maintenance; reboot/state restoration; unchanged-state negative control. | `BLOCKED BY WRITE GATE`; no candidate register. |
| 009 | A normal-RAM alias reaches a protected boundary. | Only after 008, a minimal non-secret marker/boundary test differs between normal and alias path. | No dump, exact ordering proof, secondary enforcement control. | `NOT ELIGIBLE`. |

## Experiment 001 metadata

- Target model: `SM-A908N`
- SoC: `SM8150`
- Firmware/build: runtime `v2321-usb-clean-identity-rodata`; Android kernel build
  `A908NKSU5EWA3`
- Kernel: `4.14.190-25818860`, exact live build string in private record
- Kernel build/hash: live bytes `UNKNOWN`; host-extracted v2321 kernel candidate
  SHA-256 `d97eb6c7291477000299fae1c4272105e95fe77df09631ae13099303510b5263`;
  exact rebuild System.map SHA-256
  `573d61f1d6fcefbe3f9b0b1ccb88dad92eeddbb449ad45baa26c22233c25bf74`
- Boot image hash: live bytes `UNKNOWN`; host candidate SHA-256
  `ca978551aabe4b39563abaf529ccf2522054952d8b2ad852e632d26da88168cb`
- DTB hash: live bytes `UNKNOWN`
- Timestamp: `2026-08-25 03:31:00 KST`
- Preconditions: owner-pinned A90 ACM bridge; research runtime at prompt; no
  protected-memory or MMIO access
- Exact action: fixed `version`, `/proc` `cat`, reserved-memory `ls`, and five
  DT `reg` `cat` commands emitted by `tools/a90_acm_snapshot.py`
- Result: all 12 A90P1 frames `rc=0 status=ok`
- Raw artifact: private JSON, 28,353 bytes, SHA-256
  `977320c895c0098d6de5ff6bead3baf1cf654b203687a60f804078a4b1305a18`
- Public manifest SHA-256:
  `b616639b3afe8e43b74c4417fef02e54e2f8f549f0cdd85f466af20fa8cd8705`
- Collector SHA-256 at capture time:
  `e05fd1667c23888be743123f6b3791fbec8cbac24adcb4e296bc6b495f672084`
- Committed collector after EOF-only normalization:
  `aa6eaf9f2595dddb7e79ee4b6627dacdf95768a51ea3b2ca7b94475881f632b5`
- Repetition count: 1

## Experiment 004 metadata

- Target: live pinned `SM-A908N`, `SM8150`
- Runtime/kernel: `v2321-usb-clean-identity-rodata`,
  `4.14.190-25818860-abA908NKSU5EWA3`
- Timestamp: `2026-08-25 03:59:30–03:59:36 KST`
- Exact action: live sysfs GPT identity/size/`ro`; temporary block node;
  device SHA-256; exact-size A90P1 `cat`; device SHA-256; node removal
- Result: nine artifacts, 26,779,648 bytes; every before/host/after hash equal
- Historical comparison: all five previously measured hashes equal
- Device write: none; filesystem-only temporary `/dev` nodes removed
- Postcondition: no `sdm855_mblab_*` node, selftest `fail=0`, bridge stopped
- Public manifest SHA-256:
  `1ed4b8b14b2e0ccf2d4ae084ea413e0395d9dc488dd5d2bb1dd872fbe20d9247`
- Capture tool SHA-256:
  `b6dd2c928447d1ca3fba34be7adbabc0aaf2152b0211b44c06e2de8c81e3c652`
- Frame helper SHA-256:
  `288291dc8025d1a7bbad4541cee417953cd820b0836056c62012a530b790adbd`
- DCB inventory manifest SHA-256:
  `aa6467904f88fd3370c87c7847f2dcb11b28b3f07e5e4b6a489de879bdcf7157`
- DCB inventory tool SHA-256:
  `7ef54d9a6c7c82a7282b5beb6cafda4f9351afbdca8530097f66367ea33804a7`
- Repetition count: 1 full capture, preceded by one 128 KiB `devcfg` transport smoke
