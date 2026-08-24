# Experiment Matrix

| ID | Hypothesis / question | Observable prediction | Controls | State/result |
|---|---|---|---|---|
| 001 | Live target exposes stable topology and reserved ranges read-only. | A90P1 `cat/ls` returns framed, hashable data and binary DT cells. | Fixed allowlist, no retry, target-pinned bridge, host parser tests. | `PROVED`, one live capture; repeat count 1. |
| 002 | Cold boots retain identical fixed carveouts. | DT `reg` values and structural `/proc/iomem` holes match across cold boot A/B. | Same kernel/runtime, hashes, compare dynamic counters separately. | `UNKNOWN`, not yet run. |
| 003 | Stock-like and research boots advertise the same protected ranges. | Fixed ranges equal; differences are attributable to overlays/runtime. | Bind exact boot artifact; do not equate version string with image hash. | `UNKNOWN`. |
| 004 | Exact live boot-firmware bytes can be acquired without partition writes. | Device pre-hash, host raw hash and device post-hash match for every allowlisted partition. | Live GPT/sysfs identity, `ro=1`, exact byte count, bounded size, fixed node names, cleanup inventory. | `PROVED`: nine artifacts, 26,779,648 bytes; all triple hashes match. |
| 005 | The exact XBL-programmed qhs_llcc remapper windows are readable post-boot from EL1. | Four control words, then 92 layout words, return stable 32-bit values without abort. | Fixed addresses only; temporary fixed `1:1` node; default four-word smoke; explicit `--full`; unconditional cleanup; no MMIO write/retry/arbitrary address. | `REFUTED` for current-kernel `/dev/mem`: absent node then `ENXIO`; live config has `CONFIG_DEVMEM=n`. Hardware/kernel-adapter readability remains `UNKNOWN`. |
| 006 | Address-region mapping is programmed by XBL/DDR DSF/DCB/ICB. | XBL config consumption leads to topology-dependent MMIO writes. | Exact live firmware hashes and call-graph provenance; distinguish region remap from final channel/bank hash. | `PROVED`: four qhs_llcc remapper bases and `+0x00..+0x58` writer recovered; final DRAM hash role `UNKNOWN`. |
| 007 | Normal-RAM bank/channel relationships fit a stable GF(2) model. | Timing clusters produce a cross-validated XOR matrix. | Fresh pages, pagemap/PA proof, randomized pairs, cache flush, frequency pinning, hold-out pairs. | `UNKNOWN`. |
| 008 | A controlled transform state creates physical-to-DRAM alias. | `PA_A != PA_B` but writes through one are observed through the other after cache-neutral independent reads. | Prove distinct PTE/PAs; CPU and DMA controls; cache maintenance; reboot/state restoration; unchanged-state negative control. | `NOT ELIGIBLE`: region-remap candidates exist, but readback/lock state, safe restore and a normal-RAM alias hypothesis are not proved. |
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

## Experiment 006 metadata

- Inputs: exact Experiment 004 `xbl--sdb1`, `xbl_config--sdb2`, and `tz--sdd5`
  artifacts, respectively SHA-256 `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`,
  `0e9dfac1ddd0f9acc2cc899213e621490308f0cadf329814048edb7712e2484c`,
  and `a5e6c574e18e2e576a25df6274b20bdb142386811dfda6383f86d7b1b3c102ab`
- Exact action: host-only ELF/CFGL/DCB parsing, SHRM blob hashing, remapper-table
  parsing and DAL structure-pointer traversal
- Result: four exact qhs_llcc remapper bases, layout-1 offsets through `+0x58`,
  plus a matching TrustZone record
- Static phase device command/write: none; subsequent live selector/config
  capture is recorded below
- Public manifest SHA-256:
  `39469ac59ef0e3a2b9858b7435a4433def58d57407a4066da3854cfdd24409a5`
- Static inventory tool SHA-256:
  `be9aa3cbb477f47539ef7da1ba75b1785bdaefd5ebdb4fb56ea49fbe9440e6b7`
- Read-only identity collector SHA-256:
  `0b4f99ee1d79ebc586807d88a9bea00f6edcd8409e29c6fdbbe7c34c00ae4f99`
- Fixed ICB remapper collector SHA-256:
  `4020d7e550589d50e466c009fd356f5f2ab16898e731d1fa07d69a2038bd0f1d`
- A90 frame helper SHA-256:
  `86a6c2f82cd7ac3b9f5885b1eafa727cc463ea8be2915b259a83f2036fab3402`
- Host verification: 38 unit tests pass; regenerated static manifest is byte-identical

## Experiment 006 live selector/config metadata

- Live values: SoC ID `339`, revision `2.2`, Linux SMEM `raw_id=165`,
  `raw_version=3`, platform `MTP`, subtype `charm`
- `REFUTED`: treating Linux `raw_id/raw_version` as XBL's direct
  `0x6003/{0x0100,0x0200}` filename fields; the attempted derivation is absent
  from exact CFGL
- Physical-platform `_1` variant: `SUPPORTED` by live `MTP` plus XBL's
  non-RUMI condition; exact DCB revision remains `UNKNOWN`
- Superseding live identity/config manifest SHA-256:
  `d4bea281c1533a162d7fa077a12cf0c780b8dcc175fc62b36631a1e29ff7f5d1`
- Superseding private raw snapshot SHA-256:
  `1c4ebf17ec35ba33e36b988effe153a24e7fd9dd2498745b8597f3593dee86c1`

## Experiment 005 live metadata

- Exact target: host sysfs `04e8:6861`, product `A90-LNX`, interface
  `A90 Linux ARM64`; target-pinned by-id bridge; other Samsung ACM untouched
- First attempt: one 32-bit read at `0x09248080`; failed before MMIO because
  `/dev/mem` was absent
- Second attempt: temporary `/dev/sdm855_mblab_mem` character node `1:1` created;
  the same read failed at open with `ENXIO`; node cleanup and absence proved
- Memory/MMIO writes: none; temporary devfs-node mutation only
- First public manifest SHA-256:
  `2010907bb1d7e652352a526cda59069b08e7e40ad7a290bd0b6a48379ce069f6`
- Node-backed public manifest SHA-256:
  `35e96ea34bb2d2fea643edcd408710e44c6a936d7ef395859db119d0fa5d31e3`
- Live config: gzip payload SHA-256
  `ff2543fee33573e8efe34110598e963d7ddc9c44fbbf5dc1256cd6edec0f8fde`,
  selected line `# CONFIG_DEVMEM is not set`
- Exact board defconfig SHA-256:
  `3d90a83d61a7a1873249642f7657c572e06f91a61bc3e5b737758f08ec765216`,
  same `CONFIG_DEVMEM=n` result
- Final health: runtime version payload unchanged; selftest
  `pass=11 warn=1 fail=0`; bridge stopped
