# Experiment Matrix

| ID | Hypothesis / question | Observable prediction | Controls | State/result |
|---|---|---|---|---|
| 001 | Live target exposes stable topology and reserved ranges read-only. | A90P1 `cat/ls` returns framed, hashable data and binary DT cells. | Fixed allowlist, no retry, target-pinned bridge, host parser tests. | `PROVED`, one live capture; repeat count 1. |
| 002 | Cold boots retain identical fixed carveouts. | DT `reg` values and structural `/proc/iomem` holes match across cold boot A/B. | Same kernel/runtime, hashes, compare dynamic counters separately. | `UNKNOWN`, not yet run. |
| 003 | Stock-like and research boots advertise the same protected ranges. | Fixed ranges equal; differences are attributable to overlays/runtime. | Bind exact boot artifact; do not equate version string with image hash. | `UNKNOWN`. |
| 004 | Exact live boot-firmware bytes can be acquired without partition writes. | Device pre-hash, host raw hash and device post-hash match for every allowlisted partition. | Live GPT/sysfs identity, `ro=1`, exact byte count, bounded size, fixed node names, cleanup inventory. | `PROVED`: nine artifacts, 26,779,648 bytes; all triple hashes match. |
| 005 | The exact XBL-programmed qhs_llcc remapper windows are readable post-boot from EL1. | Four control words, then 92 layout words, return stable 32-bit values without abort. | Fixed addresses only; temporary fixed `1:1` node; default four-word smoke; explicit `--full`; unconditional cleanup; no MMIO write/retry/arbitrary address. | `REFUTED` for current-kernel `/dev/mem`: absent node then `ENXIO`; live config has `CONFIG_DEVMEM=n`. Hardware/kernel-adapter readability remains `UNKNOWN`. |
| 006 | Address-region mapping is programmed by XBL/DDR DSF/DCB/ICB. | XBL config consumption leads to topology-dependent MMIO writes. | Exact live firmware hashes and call-graph provenance; distinguish region remap from final channel/bank hash. | `PROVED`: four qhs_llcc remapper bases and `+0x00..+0x58` writer recovered; final DRAM hash role `UNKNOWN`. |
| 007 | A narrow kernel path can read the exact remapper windows post-boot. | Fixed map/read/unmap returns a stable 32-bit control word without reset. | Exact candidate/map hashes; one fixed base first; no MMIO write/retry/arbitrary address; retained reset log; verified rollback. | `REFUTED` for the generic REPL adapter: `__ioremap` returned, then a non-secure watchdog occurred before `msm_readl`. Purpose-built adapter readability remains `UNKNOWN`. |
| 008 | Exact retained boot evidence resolves the live DCB/remapper row and TZ protection adjacency. | One DCB and table row match; exact TZ registry binds same-instance MPU configuration bases. | Four SHA-256-pinned private inputs; consistent repeated boot values; structural ELF/registry validation; no device access. | `PROVED`: `/6003_0200_1_dcb.bin`, row 7, six 36-bit slots, and `BIMC_MPU0..3` at matching `qhs_llcc+0xe000`; runtime register words/coverage `UNKNOWN`. |
| 009 | Static TZ/XBL/AOP consumers distinguish remapper security ownership from sub-aperture clock/fault gating. | Registry consumers, access policy, clock vote, or fault-response path names `+0x8080`/same window. | Host-only exact bytes; code/data xrefs; no MMIO retry or inferred register semantics. | `PROVED` static coverage: both TZ policy branches place `0x09248080` in TZ-owned `DC_NOC_BROADCAST_MPU` region 11 with no HLOS grant; `SUPPORTED` XPU/fabric denial; causal syndrome/runtime readback `UNKNOWN`. |
| 010 | Identify BIMC_MPU0..3 initialization and separate QHEE ownership enforcement from TZ XPU control. | Exact secure paths supply BIMC policies; any HLOS XPU-control SMC has a bounded allowlist; all known controller apertures can be checked against both policy branches. | Host-only exact XBL/TZ/hyp/devcfg bytes; function/data/SMC-record pins; comparative names separated from exact claims; no device/SMC/MMIO access. | `PROVED`: QHEE `hyp_assign` uses local stage-2/SMMU AC; separate TZ fallback dynamically reconfigures BIMC_MPU0..3; XPU-disable allowlist count 0; all eight apertures have broad branch-invariant no-HLOS coverage. Final data-path ordering `UNKNOWN`; no bypass. |
| 011 | Exact XBL exposes a PA-to-DRAM-coordinate model and selected DCB section 16 identifies candidate controller state. | A real DDR failure path computes rank/row/bank/channel/column; section tokens match SHRM-visible MCCC/MC pages. | Three exact SHA-256 pins, bounded function/word hashes, inverse-coordinate control, structural two-set parser, no device/SMC/MMIO. | `PROVED`: current formula is linear, complete, and bijective with no XOR/alias; section tokens match five controller families. Hidden hardware transform and token semantics `UNKNOWN`; no bypass. |
| 012 | Exact SHRM section-16 consumer establishes token scaling and direction. | Xtensa helper computes controller addresses and stages reads/writes according to a direction argument; exact callsites reveal the observed mode. | Exact XBL/SHRM blob hashes, parser/callsite fingerprints, offset formula, capacity/count checks, no device/SMC/MMIO. | `PROVED`: `(base_page<<12)+(offset<<2)`; both direct consumers pass read direction and produce 430/64 snapshot reads. Section-16 write primitive `REFUTED` for observed paths; runtime values/locks/indirect paths `UNKNOWN`. |
| 013 | Does either exact TZ branch grant HLOS access to the SHRM snapshot workspace? | Every covering policy region can be resolved and permission-decoded; a fixed snapshot word can then be tested with a paired no-load control. | Exact TZ hash, complete `0xf00` range, both selector branches, fixed one-word candidate, no runtime address/write input. | `PROVED` static: three TZ-owned regions per branch cover the complete workspace and all exclude HLOS read/write. Fixed control/read candidates are host-built; live control is `NOT RUN`. |
| 014 | Normal-RAM bank/channel relationships fit a stable GF(2) model not already explained by the exact diagnostic formula. | Timing clusters require address terms absent from the XBL coordinate model and cross-validate on held-out pairs. | Fresh pages, PA proof, randomized pairs, cache control, frequency pinning, formula-derived negative/positive groups. | `NOT ELIGIBLE`: a safe independent DRAM-coordinate observation path remains unresolved. |
| 015 | A controlled transform state creates physical-to-DRAM alias. | `PA_A != PA_B` but writes through one are observed through the other after cache-neutral independent reads. | Prove distinct PTE/PAs; CPU and DMA controls; cache maintenance; reboot/state restoration; unchanged-state negative control. | `NOT ELIGIBLE`: candidate tokens exist, but operation semantics, readback/lock state, safe restore, and an alias-producing state are not proved. |
| 016 | A normal-RAM alias reaches a protected boundary. | Only after 015, a minimal non-secret marker/boundary test differs between normal and alias path. | No dump, exact ordering proof, secondary enforcement control. | `NOT ELIGIBLE`. |

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
- At Experiment 006 time, physical-platform `_1` was only `SUPPORTED` by live
  `MTP` and the revision was `UNKNOWN`; Experiment 008 supersedes both with
  retained XBL/CDT proof of `/6003_0200_1_dcb.bin`
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

## Experiment 007 kernel-adapter metadata

- Target: exact `SM-A908N` / `SM8150`; the separate attached `SM-S906N`
  endpoint received no command
- Candidate: historical live-proven REPL boot SHA-256
  `b846ae9f74d8ceb922bbcd854d78b6795ef833d61e38465d3cc474cb6f0dfb65`
- System.map SHA-256:
  `9e6a1d6f322344e3d6fced7e6d29a254e1516cc5163bad8595388a9d0d02ec3a`
- Preconditions: candidate boot prefix verified in TWRP; native health
  `pass=11 warn=1 fail=0`; named REPL peek/call selftest passed; one fresh warm
  boot before the effective attempt
- Attempts 01 and 02: stopped at replay-safe slide-result capture noise; no map
  or MMIO operation
- Attempt 03: stopped at preflight `EBUSY`; no REPL or MMIO operation
- Attempt 04 exact action: recover slide, invoke only
  `__ioremap(0x09248080, 0x5c, 0x0068000000000707)`; intended next actions were
  `msm_readl` and `__iounmap`
- Result: retained log records the slide and `__ioremap` return, followed
  3.027327 seconds later by `Non Secure Watchdog Bark`; `msm_readl` was never
  invoked and zero register values were obtained
- Call-safety audit: existing classifier returns `DENY` for `__ioremap`,
  `__iounmap`, and `msm_readl`; the experiment wrapper incorrectly bypassed
  that policy by calling the low-level session API directly
- MMIO/memory writes: none; boot-partition writes were the exact candidate and
  verified V2321 rollback only
- Effective-attempt collector SHA-256:
  `63130ace433f76acf79470219faf9023624d2e3a9d66fc24f9eebef3b81648b6`
- Public watchdog manifest:
  `evidence/manifests/007-kernel-remapper-watchdog-20260825-01.manifest.json`
- Raw retained watchdog evidence SHA-256:
  `d89347a270e52519559a9ff12b44d46dabd8d5d8e87af28e9efe601370d22c54`
- Rollback: TWRP boot-prefix size `60,882,944`, SHA-256
  `ca978551aabe4b39563abaf529ccf2522054952d8b2ad852e632d26da88168cb`;
  final native runtime health `pass=11 warn=1 fail=0`
- Repetition count: one effective `__ioremap` call; it is not eligible for
  repetition through the generic REPL path
- Host-only successor control: boot SHA-256 `dbbf81f26cd3d9d2d52d2a2dbe84575b759b45cea8946d02646bd4503ad08247`,
  body SHA-256 `0a094ef803e78c773bb548f12c4eb364da27b4b3681dc0d4b37edbf883cf30a7`;
  map → immediate unmap → `0xc071`, zero MMIO loads
- Host-only successor read: boot SHA-256 `6fe92825702f304a067fc716c3814a63b2f4e76198a054de4c666cad55a462ed`,
  body SHA-256 `730f420b219f9ad3ab7da5488f5b8dac3638099cc0007aad7dd31ddfb53982d6`;
  exactly one fixed 32-bit load and unmap before result
- Both successors reproduced byte-identically three times
- Control live result: one invocation returned `0x0000c071`, post-health OK;
  public manifest `007-inline-remapper-control-live-20260825-01`
- Read live result: one invocation, no automatic retry, no returned value,
  USB/ACM disconnect and retained `Non Secure Watchdog Bark` at 69.080426 s;
  public derived manifest `007-inline-remapper-read-watchdog-20260825-01`
- Final rollback: V2321 full-prefix readback match and native selftest
  `pass=11 warn=1 fail=0`; the fixed read is not eligible for repetition

## Experiment 008 exact remapper-boundary metadata

- Experiment ID: `008-remapper-boundary-inventory-20260825-01`
- Target model / SoC: exact retained `SM-A908N` / `SM8150`
- Firmware/build: XBL `BOOT.XF.3.0-00468-SM8150LZB-1`, exact Experiment 004
  XBL/XBL-config/TZ partition hashes pinned by the tool
- Kernel build/hash: no kernel executed in this host-only phase; retained log
  input is exact Experiment 007 artifact SHA-256 `8701d073…`
- Boot image / DTB / research-kernel hash: no new boot artifact; V2321 was
  already restored and health-proved after Experiment 007; live DTB remains
  `UNKNOWN`
- Timestamp: `2026-08-25 07:10 KST`
- Preconditions: exact four inputs present and matching pinned sizes/hashes;
  no connected-device or MMIO precondition
- Exact action: `python3 tools/sm8150_remapper_boundary_inventory.py --replace`
- Result: exact DCB `/6003_0200_1_dcb.bin`; rank topology 3072+3072 MiB;
  unique row 7; 36-bit layout-1 writer; four same-window BIMC MPU registry
  records; numeric boot words and protection coverage remain `UNKNOWN`
- Log reference: private retained last-kmsg SHA-256 `8701d073…`; seven
  consistent chip/CDT observations and six consistent rank observations
- Public manifest SHA-256:
  `b4bb1082df278b57055f164d3da9c3a2f420ac9cc3d904ccb1ea24e78b9f3f9a`
- Private derived record SHA-256:
  `2154ee2af18d0e98b92f6658120cde89434433be8db8f592d026ad278b6660ff`
- Tool SHA-256:
  `f7369436326de88421e4c4e98c518bb5f59e9c5aa94a6f9b9311340da1a87bca`
- Host verification: 66 unit tests pass; all public manifests parse; final
  private/public outputs reproduce byte-identically
- Repetition count: one final exact parser run; repeated boot values are counted
  independently in the manifest
- Device/MMIO/controller writes: none; device access: none

## Experiment 009 exact XPU-policy metadata

- Experiment ID: `009-xpu-policy-inventory-20260825-01`
- Target model / SoC: exact retained `SM-A908N` / `SM8150`
- Firmware/build: exact Experiment 004 TrustZone and devcfg partition hashes,
  pinned by the tool
- Kernel build/hash: no kernel executed in this host-only phase; retained log
  input is exact Experiment 007 artifact SHA-256 `8701d073…`
- Boot image / DTB / research-kernel hash: no new boot artifact or device
  action; V2321 remains the last health-proved runtime; live DTB remains
  `UNKNOWN`
- Timestamp: `2026-08-25 07:43 KST`
- Preconditions: exact TZ, devcfg, and last-kmsg inputs present and matching
  pinned sizes/hashes; no connected-device or MMIO precondition
- Exact action: `python3 tools/sm8150_xpu_policy_inventory.py --replace`
- Result: consumed 48-entry registry; two policy branches with identical
  `DC_NOC_BROADCAST_MPU` coverage of `0x09248080`; TZ owner, MSA-class
  read-only, no HLOS grant; `disable_xpu_ac=0`; XPU denial `SUPPORTED`
- Log reference: retained last-kmsg SHA-256 `8701d073…`; decoded XPU syndrome
  absent because the collector reports encrypted/unparsed TZ log
- Public manifest SHA-256:
  `f5c661af73cd6b4a0d423ef44a59b11cba0e208ad178670ff2dabf097bf2e4e6`
- Private derived record SHA-256:
  `d90d48f776907d23e29b593e3f9eb36c841c84a3ed663703fad018c4c69cff2c`
- Tool SHA-256:
  `88b6cd2ee74ce3e3b50efd59ce64886f5bd66098b50636b766a6213d6361ae3e`
- Focused-test SHA-256:
  `dd17da25f1a99a6ba123e9cd252650bc8219dc1208e3c9d9732c78b6ab81896d`
- Host verification: seven focused tests and all 73 repository tests pass; all
  public manifests parse; final private/public outputs reproduce byte-identically
- Repetition count: one final parser generation; the same live MMIO load was
  not repeated
- Device/MMIO/controller writes: none; device access: none

## Experiment 010 exact XPU-initializer metadata

- Experiment ID: `010-xpu-initializer-inventory-20260825-01`
- Target model / SoC: exact retained `SM-A908N` / `SM8150`
- Firmware/build: exact Experiment 004 XBL, TrustZone, QHEE/hyp, and devcfg
  partition hashes pinned by the tool; no substituted generation or target
- Kernel build/hash: no kernel executed in this host-only phase
- Boot image / DTB / research-kernel hash: no new boot artifact and no device
  action; V2321 remains the last health-proved runtime; live DTB remains
  `UNKNOWN`
- Timestamp: `2026-08-25 08:18 KST`
- Preconditions: all four exact inputs present and matching pinned sizes and
  SHA-256; no connected-device, SMC, or MMIO precondition
- Exact action:
  `python3 tools/sm8150_xpu_initializer_inventory.py --replace`
- Result: exact QHEE `hyp_assign` uses local stage-2/SMMU access control;
  separate TZ same-ID fallback reaches dynamic `BIMC_MPU0..3` policy; XPU
  disable allowlist count is zero; all eight known controller apertures have
  branch-invariant broad TZ-owned/no-HLOS static coverage
- Log reference: none; this phase consumed only exact firmware images and did
  not infer runtime values from a device log
- Public manifest SHA-256:
  `baeef82f8f0fad7c7e897e3c373dacd129b7f2ed22d78c075a94141ee36c1ce2`
- Private derived record SHA-256:
  `dc4a664b2d9a01982b37684a4e63dd8e5183f41f6fbec191a1169d8ee418133a`
- Tool SHA-256:
  `10b134568213973ef6a69a57a0c384442f27fb8011f008cb23a60ecfd7939005`
- Focused-test SHA-256:
  `c7d1fd557f0499673cbcdf0d7824f54ce002b28ac04a9946f2cb3551bb81ed33`
- Host verification: eight focused tests and all 81 repository tests pass;
  every public manifest parses; three consecutive private/public generations
  are byte-identical; private mode `0600`, public mode `0644`
- Repetition count: one final analysis result, regenerated three times only for
  deterministic host verification
- Device/SMC/MMIO/controller/partition writes: none; device access: none

## Experiment 011 exact DRAM-coordinate metadata

- Experiment ID: `011-dram-coordinate-inventory-20260825-01`
- Target model / SoC: exact retained `SM-A908N` / `SM8150`
- Firmware/build: exact Experiment 004 XBL and XBL-config partition hashes;
  selected `/6003_0200_1_dcb.bin`, DSF `0x00650000`
- Kernel build/hash: no kernel executed in this host-only phase; retained log
  input is exact Experiment 007 artifact SHA-256 `8701d073…`
- Boot image / DTB / research-kernel hash: no new boot artifact and no device
  action; V2321 remains the last health-proved runtime; live DTB remains
  `UNKNOWN`
- Timestamp: `2026-08-25 08:41 KST`
- Preconditions: all three exact inputs present and matching pinned sizes and
  SHA-256; no connected-device, SMC, or MMIO precondition
- Exact action:
  `python3 tools/sm8150_dram_coordinate_inventory.py --replace`
- Result: exact Quest reporter's rank boundary equals remapper row 7;
  rank-relative coordinate formula is complete, bijective and contains no XOR;
  section 16 supplies exact MCCC/MC/MCCC-master/DDRSS/SHRM-CSR token matches;
  hidden hardware transform and token semantics remain `UNKNOWN`
- Log reference: retained last-kmsg SHA-256 `8701d073…`; six consistent
  3072+3072 MiB topology observations
- Public manifest SHA-256:
  `93fbc8702f90980b9c85cab983a7b8e23260394a9cb4ed7881188bc0435a0c5c`
- Private derived record SHA-256:
  `90a50e319050266c3a11128f917c90cc386f0eaaacfae32d253e2ed4fe923f21`
- Tool SHA-256:
  `15b2ffb9a74e8b8821148ea3f458a305fe05b99cfe81636bf1a515f9732cc495`
- Focused-test SHA-256:
  `29d2358f8982a86437c0ca791ca5e5d57452e67385a36f148caaa0ca1daf724f`
- Host verification: seven focused tests and all 88 repository tests pass;
  every public manifest parses; three consecutive private/public generations
  are byte-identical; private mode `0600`, public mode `0644`
- Repetition count: one final analysis result, regenerated three times only for
  deterministic host verification
- Device/SMC/MMIO/controller/partition writes: none; device access: none
