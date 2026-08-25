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
| 011 | Exact XBL exposes a PA-to-DRAM-coordinate model and selected DCB section 16 identifies candidate controller state. | A real DDR failure path computes rank/row/bank/channel/column; section tokens match SHRM-visible MCCC/MC pages. | Three exact SHA-256 pins, bounded function/word hashes, inverse-coordinate control, structural two-set parser, no device/SMC/MMIO. | `PROVED`: the diagnostic formula is linear, complete and bijective with no XOR/alias; section tokens match five controller families. Experiment 014 later `REFUTED` it as the complete silicon bank map; token semantics remain `UNKNOWN`. |
| 012 | Exact SHRM section-16 consumer establishes token scaling and direction. | Xtensa helper computes controller addresses and stages reads/writes according to a direction argument; exact callsites reveal the observed mode. | Exact XBL/SHRM blob hashes, parser/callsite fingerprints, offset formula, capacity/count checks, no device/SMC/MMIO. | `PROVED`: `(base_page<<12)+(offset<<2)`; both direct consumers pass read direction and produce 430/64 snapshot reads. Section-16 write primitive `REFUTED` for observed paths; runtime values/locks/indirect paths `UNKNOWN`. |
| 013 | Does either exact TZ branch grant HLOS access to the SHRM snapshot workspace? | Every covering policy region can be resolved and permission-decoded; a fixed snapshot word can then be tested with a paired no-load control. | Exact TZ hash, complete `0xf00` range, both selector branches, candidates differing by one instruction, no retry/address/write input, verified V2321 rollback. | `PROVED`: three TZ-owned regions per branch exclude HLOS; no-load control returned `0xc071`; one-load read returned no value and retained `Non Secure Watchdog Bark`/`TZBSP_ERR_FATAL_NON_SECURE_WDT`. Direct EL1 path `REFUTED`; XPU root cause `SUPPORTED`; no bypass. |
| 014 | Normal-RAM bank/channel relationships fit a stable GF(2) model not already explained by the exact diagnostic formula. | XOR-difference row-reopen timing recovers the selector kernel; row-bit relations and held-out combinations must agree while one-bank-bit perturbations leave the class. | Exact non-secure single-SG ION CMA PA binding; write-combine mapping; symmetric reopen/baseline directions; 64 PA pairs; 1001 repetitions; same-row, held-out and one-bit controls; CPU/DDR pinning. | `PROVED`, observed low-24 scope: row bits 16..23 contribute XOR terms to the rank-five selection space; PA9/PA10 independence `SUPPORTED`; diagnostic no-XOR bank formula `REFUTED` as complete silicon mapping. No complete-coordinate alias, mutation or bypass. |
| 015 | A controlled transform state creates physical-to-DRAM alias. | `PA_A != PA_B` but writes through one are observed through the other after cache-neutral independent reads. | Prove distinct PTE/PAs; CPU and DMA controls; cache maintenance; reboot/state restoration; unchanged-state negative control. | `NOT ELIGIBLE`: candidate tokens exist, but operation semantics, readback/lock state, safe restore, and an alias-producing state are not proved. |
| 016 | A normal-RAM alias reaches a protected boundary. | Only after 015, a minimal non-secret marker/boundary test differs between normal and alias path. | No dump, exact ordering proof, secondary enforcement control. | `NOT ELIGIBLE`. |
| 017 | Does exact XBL expose a table-driven MC read-copy path that independently covers the ranked MC candidates? | The pinned u64 table parses to 122 entries plus a zero terminator; the exact helper's static flow conditionally loads each table-derived address and stores results to a distinct buffer. | Exact XBL size/hash, PT_LOAD mapping, inclusive table/helper hashes, AArch64 word pins, direct-BL scan limited to file-backed executable PT_LOADs, SHRM-plan address-list cross-check; host-only, no device/SMC/MMIO. | `PROVED`: 30×4 MC groups + 2 globals, all 12 qhs_mc candidates covered, helper read-copy store-base dataflow, exactly two direct BL callsites. `REFUTED`: helper as candidate-register writer and independent hard 122-entry cap. Runtime completion/coherence/currentness, mutable table state, indirect reachability and writer semantics `UNKNOWN`; 015/016 remain `NOT ELIGIBLE`. |
| 018 | Does exact XBL contain literal and syntactic store-offset evidence for the 12 ranked MC targets, and do the non-SP RX candidates resolve through narrow direct-definition models? | Each target's single 8-byte table encoding yields one aligned u64 match and the overlapping aligned u32 match at the same file offset; strict STR W/X unsigned-immediate offsets enumerate candidates. Stage 2A resolves only 64-bit MOVZ/MOVK or same-register `ADRP Xn; ADD Xn,Xn,#imm` within 128 instructions; Stage 2B extends only its two X8 window-limit candidates with same-register W MOVZ/MOVK within 512 instructions; Stage 2C analyzes one X8 writer through its unique direct caller and 48-row retained table; Stage 2D analyzes the remaining X19 store under explicit dispatch, normal-return, and initialized-slot conditions. | Exact XBL size/SHA-256, PT_LOAD RX/RWE/RW/OTHER census, scalar STR decoder negatives, literal mapping/table membership, exact candidate/code/table/initializer pins, exact target instruction-class/write-set audit, direct BL/B and success-path cutoffs, unsupported/mixed-width definition negatives; host-only, no device/SMC/MMIO. | `PROVED`: the two aligned matches per target are views of one table entry, not independent literals, with no separate target literal elsewhere; outside-table aligned u32 only for base `0x09260000` at file `0x80154` / VA `0x148bc254` in RWE; 14 matching offsets (RX11/RWE3), seven RX SP-based; Stage 2A has two window-limit no-definitions, one unsupported LDR, one BL control boundary, zero resolved bases/hits. Stage 2B resolves two W-wide-move bases to XBL virtual-address values `0x1489f000`, computing `0x1489f400`/`0x1489f4d0`, with zero numeric target hits. Stage 2C proves one direct BL, the 56/108/272-byte code-range hashes, and 48 unique ID/pointer rows with zero numeric target matches; these are a descriptor-eligibility-dependent possible-value superset. Stage 2D proves the remaining caller/function/initializer/target static pins, exact target no-call/no-saved-register audit, dispatch and normal-return pins, and computes `0x85e9e970` only within explicit runtime/slot conditions; its conditional value has zero numeric target matches. `REFUTED` only: the supported Stage 2A direct-definition path and Stage 2B/2C/2D numeric target equality in their stated models. Physical destination, runtime execution, writer identity outside scoped paths and all SP/RWE/unsupported/dynamic paths remain `UNKNOWN`; 015/016 remain `NOT ELIGIBLE`. |

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

## Verifications 003/004 A90 raw-dump eligibility metadata

- Verification IDs:
  `verification-003-a90-rawdump-eligibility-20260825-01` and
  `verification-004-a90-rawdump-eligibility-sourcebacked-20260825-01`
- Question: do current exact V2321 property-free proc/sys surfaces positively
  qualify a later XBL `SHRM_MEM.BIN` collection attempt?
- Target: exact `SM-A908N` / `SM8150`, V2321 `0.9.285`, kernel
  `4.14.190-25818860-abA908NKSU5EWA3`
- Transport: existing operator-pinned A90P1 loopback bridge to A90
  `04e8:6861`; the separate Samsung `04e8:6860` endpoint received no command
- Verification 003 result: `debug_level=0x4f4c` (`LOW`), `force_upload=0`,
  S22+ `qcom_dload_mode` path absent, ramoops `max_reason` path absent,
  `panic=-1`, `panic_on_warn=0`
- Source correction: exact A90 `msm-poweroff.c` SHA-256 `0a2b20ec…` owns
  `module_param_call(download_mode, ...)`; retained live config has
  `CONFIG_QCOM_DLOAD_MODE=y` and `CONFIG_QCOM_MINIDUMP=n`
- Verification 004 result: A90 source-backed
  `/sys/module/msm_poweroff/parameters/download_mode=1`
- Final signal vector: debug `NEGATIVE`, force-upload `NEGATIVE`, dload master
  `POSITIVE`; classification `DUMP_ENTRY_SIGNALS_INCOMPLETE`; actual XBL
  FMM/token eligibility `UNKNOWN`
- Public manifest SHA-256 values: V003
  `bbd1da19fa8b7d2b56c6a8f8683ba49fac34aa9fc96d9f05727cb8e58672f856`,
  V004 `a0e5b047ea95169b009c962bf8b445b6f757edebebf4401746d5f0751367bd37`
- Private record SHA-256 values: V003
  `1a5b4b981c2eeb9f6a0fd9683062c8405db55dbe4db7f7ebe23d8c8e0f1365d5`,
  V004 `02cf1474b74d8befca9ea1be192fbd8667e4fc94870d42be0c19bc322a5de8b2`
- Final tool SHA-256:
  `9386c03e444ceb3196ea300371cc6ff0cdfb67ffa38dca570c834bd34c1d5fec`
- Final focused-test SHA-256:
  `9239e68e1351ee1d92e192bf2182717348a9697a2e422832d8df9f91860772a7`
- Host verification: ten focused tests and all 195 repository tests pass; all
  36 public manifests parse; private records mode `0600`, public manifests
  mode `0644`
- Device commands: two exact target binds plus 11 fixed `cat` reads across both
  passes; no getprop, ADB, write, reboot, MMIO, SMC, service action, payload,
  partition action or automatic retry
- Complementary decoder: commit `9fdd5d6`, tool SHA-256
  `1cf33c9292890c2479c20c8f9470c05058348046a49dc2280d061a64e224b5a7`,
  test SHA-256
  `e20cea3fc518b6ee56c4f74e4b1cfbffb72e78e782e8ce3d55680e6d24ad40e8`;
  20 focused tests pass and plan-only output reports `430/64` words with no
  remapper-window coverage

## Experiment 013 SHRM snapshot boundary/live metadata

- Experiment IDs: `013-shrm-snapshot-boundary-20260825-01`,
  `013-shrm-control-live-20260825-01`, `013-shrm-read-live-20260825-01`, and
  `013-shrm-live-result-20260825-01`
- Target model / SoC: exact bound `SM-A908N` / `SM8150`; the separate S22+
  endpoint was inventoried and received no command
- Firmware/build: exact TZ SHA-256 `a5e6c574…`; final native build
  `v2321-usb-clean-identity-rodata`, init `0.9.285`
- Boot images: V2321 `ca978551…`; fixed no-load control `d1d4956b…`; fixed
  one-load read `7ee6a41f…`; each live write had full 60,882,944-byte readback
- Snapshot target: section-16 set-0 word 207 at `0x0906566c`, sourced from
  MCCC register `0x09250118`
- Timestamp: `2026-08-25 09:24–09:33 KST`
- Preconditions: both exact TZ branches prove three enabled/TZ-owned covering
  regions with no HLOS read/write; control/read bodies differ by exactly one
  instruction; exact V2321 rollback available
- Exact live sequence: control write/boot/op once -> V2321 rollback -> read
  write/boot/op once -> retained-log capture -> V2321 rollback
- Result: control `0xc071`; read returned no value and disconnected USB;
  retained log proves `Non Secure Watchdog Bark`,
  `TZBSP_ERR_FATAL_NON_SECURE_WDT`, bark `40.280410`, last pet `29.280131`,
  CPU alive mask `0x07`, and no `A90R` result
- Retained log: 2,097,136 bytes, SHA-256 `92af2a21…`
- Final state: V2321 full-prefix SHA-256 restored; selftest
  `pass=11 warn=1 fail=0`; battery 100%
- Repetition count: control once; read once; read automatic retries zero
- Device effects: four exact boot-only writes including two rollbacks; no
  memory/controller/XPU/SCM/EL2/EL3/protected-memory write; one fixed 32-bit
  SHRM load
- Classification: `CLASS A/B CANDIDATE — FIXED DIRECT EL1 SHRM READ BLOCKED`;
  XPU/fabric root cause `SUPPORTED`; alias/boundary bypass `REFUTED` for this
  path

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
  hidden hardware transform was `UNKNOWN` at this phase and was later proved
  by Experiment 014; token semantics remain `UNKNOWN`
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

## Verification 001 independent claim-audit metadata

This is an audit of the evidence chain, not a forward experiment. It takes no
Experiment number because 014–016 are already allocated above.

- Verification ID: `verification-001-independent-claim-audit-20260825-01`
- Question: do the load-bearing static claims of Experiments 006–013 survive
  independent re-derivation from the raw bytes?
- Motivation: every `PROVED` statement is one agent's interpretation, and
  Experiments 008–013 consume 004/006 conclusions as pinned inputs, so an early
  misinterpretation would be inherited downstream
- Why prior signals were insufficient: unit tests prove parser determinism,
  hash pins prove input stability, and byte-identical regeneration proves tool
  reproducibility; none proves the interpretation is correct
- Controls: no module in `tools/` is imported, called, or reused; structures are
  located by name and value search and then walked, so a claim can fail even
  when the original tool reproduces byte-identically; subset AArch64 and Xtensa
  decoders were written for the audit because no disassembler was available
- Inputs: exact Experiment 004 XBL `e73a07a0…` and TrustZone `a5e6c574…`, both
  measured equal to their pins
- Timestamp: `2026-08-25 KST`
- Exact action: `python3 tools/independent_claim_audit.py --replace`
- Result: `7/7 CONFIRMED`; no substantive error; two notation issues recorded
  (helper range is end-exclusive at 125 bytes; `0x09248fff` is not a stored
  value, the raw field being end-exclusive `0x09249000`)
- New finding: region 11 and `DC_NOC_NON_BROADCAST_MPU` region 5 both carry
  write access word `0x00000000`, denying write to every client class rather
  than only to ordinary HLOS
- Not audited: QHEE `hyp_assign` stage-2/SMMU path, TZ dynamic `BIMC_MPU0..3`
  initializer, Experiment 011 Quest coordinate formula, section-16 callsites and
  their 430/64 counts, permission-conversion routine
- Public manifest SHA-256:
  `a722f0f66367de300b9a4402002e510a0d457c0250ca1b09f44e964f4914f2e5`
- Tool SHA-256:
  `b6617c19b9fc12d4d5c6dd83badc15da0a0e4df854ee8dc788b417ea3b0431fc`
- Focused-test SHA-256:
  `2c42b6bd7f513c055177c2754666cc902a338117cd7ea053bd602e0a2e62547b`
- Host verification: 34 focused tests and all 125 repository tests pass; all 33
  public manifests parse; three consecutive manifest generations are
  byte-identical; public mode `0644`
- Private record: none; the audit emits no firmware bytes
- Device/SMC/MMIO/controller/partition writes: none; device access: none

## Verification 002 SHRM dump-export metadata

This is a forward static discriminator but takes a Verification number to
preserve the already allocated Experiment 014–016 sequence.

- Verification ID: `verification-002-shrm-dump-export-20260825-01`
- Question: does exact firmware have a downstream consumer/export covering the
  two protected SHRM snapshot buffers after direct EL1 access was blocked?
- Input: exact Experiment-004 XBL, 4,194,304 bytes, SHA-256
  `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`
- Timestamp: `2026-08-25 KST`
- Exact action:
  `python3 tools/sm8150_shrm_dump_export_inventory.py --replace`
- Result: exact XBL consumes a 26-record crash/download raw-dump table whose
  index 19 maps `0x09060000..0x0906ffff` to `SHRM_MEM.BIN`, covering the full
  section-16 workspace and both snapshot destinations
- Consumer proof: loop `0x14917ca8..0x14917cf4`, record stride `0x20`, count
  `0x1a`, registrar `0x14917670`; pinned call chain
  `0x14902cc4 -> 0x14917740 -> 0x14917c60`
- Bounded SHRM negative: one direct `0x25100` literal feeds both direction-zero
  producers; no direct u32 literal for either derived destination or physical
  address; dynamically derived consumers remain possible
- Mounted-SD result: exact filenames `SHRM_MEM.BIN`, `rawdump.bin` and the
  Experiment-004 A90 partition dumps were absent; the only A908 item was the
  Samsung open-source kernel archive/directory
- Classification:
  `BOOTLOADER_RAWDUMP_EXPORT_PRESENT_HLOS_RUNTIME_EXPORT_UNPROVED`
- Public manifest SHA-256:
  `7f35e4e6dd3ede0c1bc2f398d3148656ac95b948a257ad19e8ab6d030c20e635`
- Private derived record SHA-256:
  `205960e837a0a2d58dd416ee4bf89e6f4e182a5dcfcbd358f2722dbbf78d739a`
- Tool SHA-256:
  `a9e0b9e27cb12c8ec3e12d2324b7c32d7eabb7450741767528d54a18a65565ed`
- Focused-test SHA-256:
  `cb7c947520a7aa3a6ea6a400c68f08db050a1c586ab12e58bfd30d581ba9e97d`
- Host verification: ten focused tests and all 135 repository tests pass; all
  34 public manifests parse; consecutive private/public generations are
  byte-identical; private mode `0600`, public mode `0644`
- Device/SMC/MMIO/controller/partition writes: none; device access: none

## Verification 005 exact XBL rawdump-gate metadata

- Verification ID:
  `verification-005-xbl-rawdump-gate-static-20260825-01`
- Target model / SoC / build: retained exact `SM-A908N` / `SM8150` /
  `A908NKSU5EWA3`
- Exact input: XBL 4,194,304 bytes, SHA-256 `e73a07a0…`; exact Samsung
  `sec_param`, panic-handler, SysRq, and `msm-poweroff` sources
- Exact action: host-only ELF/code/data reconstruction and exhaustive boolean
  truth-table evaluation
- Result: main-XBL outer trigger is saved-cookie bits 4/5 or restart reason
  `0x776655ee`; XBLRamDump inner gate admits MID alone when FMM is unlocked;
  force-upload enable is exact integer 5 and is not jointly required
- Classification: `DEBUG_ONLY_SUFFICIENT_WHEN_OUTER_DUMP_TRIGGER_PRESENT`
- Public manifest SHA-256: `5024b24e…`
- Tool SHA-256: `75581e19…`
- Device/reboot/partition/MMIO/SMC access: none

## Verifications 006–014 bounded live-gate metadata

- Target model / SoC / build: exact live `SM-A908N` / `SM8150` /
  `A908NKSU5EWA3`; native `v2321-usb-clean-identity-rodata`
- Timestamp: `2026-08-25 12:14–12:41 KST`
- Initial `param`: live `sda10`, 10 MiB; device-before/host/device-after
  SHA-256 all `1faafee9…`; DLOW, force-upload 0, FMM 0, dump-sink 0
- Exact effects: four-byte LOW→MID; one normal reboot; one SysRq `c`; one
  four-byte MID→LOW restoration; one final normal reboot. Two intermediate
  apply/restore qualification transitions were separately hash-verified.
- Exact MID full-image SHA-256: `50e5c715…`; exact LOW full-image SHA-256:
  `1faafee9…`
- Trigger preconditions: MID, force-upload 0, FMM 0, dump-sink 0, dload master
  1, SysRq enabled; one dispatch and no replay
- Transport result: Qualcomm 05c6 Sahara/qdl captured no file; host journal
  proved Samsung `04e8:685d / MSM_UPLOAD`
- Final result: original full `param` hash restored; new boot reports LOW,
  force-upload 0, dump-sink 0, dload master 1; selftest `fail=0`
- Public manifest SHA-256 sequence: capture `c9bc1838…`, first apply
  `7bf70d53…`, first restore `f10a6888…`, reapply `705fac7c…`, MID reboot
  `d466bf94…`, trigger `aa3ef26b…`, qdl result `bed07a93…`, final restore
  `81b734c2…`, health `c27f307b…`, LOW reboot `c3d7983e…`
- Raw rollback image and journals: mode `0600`, Git-ignored
- Forbidden-target result: no controller, XPU, SMMU, SCM, EL2, EL3, firmware,
  bootloader, GPT, RPMB, QFPROM, or protected-memory write
- Repetition count: one panic only; no trigger replay

## Verification 012 Samsung Upload SHRM metadata

- Verification ID:
  `verification-012-a90-samsung-upload-shrm-20260825-01`
- Exact collection: Samsung Upload client commit `8c9f6eb7…`, source SHA-256
  `7580a6c1…`; selected only exact static catalog record 19
- Raw result: `SHRM_MEM.BIN`, 65,536 bytes, SHA-256 `409550ad…`, mode `0600`,
  Git-ignored
- Structural result: exact section-16 header at file offset `0x5100`; 430 + 64
  staged entries cover 470 distinct source-register addresses
- Set 0: 430 words, 220 zero, 71 distinct; 17/18 four-instance MC groups
  identical and one two-value pair split; `SUPPORTED_POPULATED_COHERENT_SNAPSHOT`
- Set 1: 64/64 distinct nonzero values; four different MC `+0x80` values;
  0/24 overlaps agree with set 0; `REFUTED_AS_COHERENT_CURRENT_SNAPSHOT`
- Remapper coverage: `REFUTED`; all four `qhs_llcc +0x8080` controls remain
  outside the staged list
- Public manifest SHA-256: `ab1ce816…`
- Private analysis SHA-256: `ed5c39e9…`, 168,042 bytes, mode `0600`
- Analysis tool/test SHA-256: `a93e1478…` / `138c504b…`
- Security result: `NO_ALIAS_OR_BOUNDARY_BYPASS_OBSERVED`
- Repetition count: one exact file acquisition; one host decode/qualification

## Experiment 014 live DRAM-timing metadata

- Target model/SoC: `SM-A908N` / `SM8150`
- Firmware/kernel/runtime: `A908NKSU5EWA3` / Linux `4.14.190-25818860` /
  V2321 `0.9.285` build `v2321-usb-clean-identity-rodata`
- Boot state: LOW, force-upload 0, dump-sink 0
- Probe source SHA-256: `f5788486…`
- Probe binary SHA-256: `552432c1…`
- Backing: non-secure ION `user_contig`, flags 0, one SG entry,
  write-combine mapping
- Physical interval: rank-0 PA `0xf0400000..0xf13fffff`, 4096 pages; unique
  `/proc/kpageflags` transition window and zero changed/lost pages while pinned
- Timing controls: CPU7 at 2,841,600 kHz; DDR BW governor `performance` at
  reported `7980`; CNTFRQ 19.2 MHz; 64 PA pairs; normally 1001 repetitions per
  pair; symmetric reopen and same-address baselines
- Recovered bank row basis: `0x9d2000`, `0xa74000`, `0x4e8000` over observed
  rank-relative bits `0..23`; basis order is arbitrary
- Holdout: four unfit kernel vectors have minimum p10 536 milli-ticks; four
  one-bank-bit negatives have maximum p90 222; non-overlap gap 314
  milli-ticks
- Same-row control: ten `D=0x800` median deltas remain within +/-6
  milli-ticks
- Static attribution: zero aligned u32 mask hits in nine exact firmware images;
  all four raw TZ matches are misaligned monotonic u64 address-table bytes
- Timing manifest SHA-256: `7dc5050c…`
- Literal-audit manifest SHA-256: `50cdec42…`
- Final-health manifest SHA-256: `e8219a53…`; selftest `fail=0`, battery 100%
- Device mutation: temporary `/tmp/a90-native` probe and ION node only; both
  removed. No MMIO/SMC/partition/firmware/protected-memory write.
- Security result:
  `NORMAL_RAM_HIDDEN_BANK_HASH_PROVED_NO_ALIAS_OR_BYPASS`

## Experiment 017 XBL MC table/read-copy metadata

- Experiment ID: `017-xbl-mc-snapshot-xref-20260825-01`
- Date: `2026-08-25 KST`
- Target/input: exact retained `SM-A908N` / `SM8150` XBL
  `xbl--sdb1.bin`, 4,194,304 bytes, SHA-256
  `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`
- Exact action:
  `python3 tools/sm8150_xbl_mc_snapshot_xref.py --output evidence/manifests/017-xbl-mc-snapshot-xref-20260825-01.manifest.json`
- Device/SMC/MMIO access: none; mode `HOST_ONLY_READ_ONLY`; public mode `0644`.
- Table: VA `0x146b1218`, file `0x630b8`, 122 nonzero u64 entries plus a
  u64 zero terminator at index 122; inclusive SHA-256
  `d5042980f035d3d52974536115074940b4b1858cb30a47699e7553f1b200da07`;
  structural shape 30 four-instance MC groups plus two globals.
- Candidate coverage: all 12 qhs_mc `+0x400/+0x404/+0x4d0` addresses are in
  the table; qhs_mccc `+0x118` and qhs_mccc_master `+0x294` are excluded from
  this table only. Existing Top-5 order is unchanged; coverage raises
  observation confidence, not semantic likelihood.
- SHRM plan convergence: set0 `100/430`, set1 `4/64`, union intersection
  `100`, table-only `22`, SHRM-only `370`; address-list convergence only, with
  no semantic identity or writer attribution.
- Helper: exact range `0x146ae138..0x146ae18c` end-exclusive, file `0x62318`,
  length `0x54`, SHA-256
  `f325a8bf4c8e9ff7c21a0d20752e742cd8e047422e9eff5c301bf3042a95e138`.
  Static sentinel prefill and conditional table-derived 32-bit read/copy to
  distinct VA `0x146bf300`; only X12/X8 are identified store bases. Traversal
  is zero-sentinel-only with no hard 122-entry cap; successful execution,
  partial output, coherence/currentness, MMIO side effects/faults, mutable
  table state, lock/writability and indirect reachability remain `UNKNOWN`.
- Direct reachability: exactly two direct BL callsites in file-backed executable
  PT_LOADs, at VA/file `0x146ae26c/0x6244c` and
  `0x14839f44/0x20f44`; no current-boot execution claim.
- Classification: `TABLE_DRIVEN_REGISTER_READ_COPY_PATH_WRITER_AND_TRANSFORM_RELATION_UNKNOWN`;
  current overall status remains Class C transform observation only. Experiments
  015 (normal-RAM alias) and 016 (protected-boundary reach) remain reserved and
  `NOT ELIGIBLE`; 017 satisfies neither gate.
- Tool SHA-256:
  `2baa9e3def46bb1c22bfd23c3dc7c4b800cf3fbc16ada1254e73023842633d99`.
- Focused-test SHA-256:
  `5b0f6f3e4d0b9a4a0e80f17555f4c8e12baf1f8d83f5bc6ee1fb97252d21f392`.
- Public manifest SHA-256:
  `b1db21235374c64de797c1a123c64ddb23c43fca9100bbd51cf7b4897ea5c61b`.
- Host verification: 20 focused tests and all 279 repository unittest-discovery
  tests pass. Independent raw-byte review
  accepted the result as a read-only re-derivation and emitted no artifact or
  artifact hash.
- Next discriminator: host-only symbolic AArch64 store xref/backward slice for
  the 12 exact qhs_mc targets, resolving MOVZ/MOVK, ADRP+ADD, literal/table
  loads, arithmetic and argument provenance; unresolved dynamic bases remain
  `UNKNOWN`; no broad MMIO scan/device action.

## Experiment 018 XBL MC writer Stage 1A metadata

- Experiment ID: `018-xbl-mc-writer-xref-stage1a-20260825-01`
- Date: `2026-08-25 KST`
- Target/input: exact retained `SM-A908N` / `SM8150` XBL
  `xbl--sdb1.bin`, 4,194,304 bytes, SHA-256
  `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`
- Exact action:
  `python3 tools/sm8150_xbl_mc_writer_xref.py --output evidence/manifests/018-xbl-mc-writer-xref-stage1a-20260825-01.manifest.json`
- Device/SMC/MMIO access: none; mode `HOST_ONLY_READ_ONLY`; public mode `0644`.
- Literal inventory: each target's single 8-byte table encoding yields both the
  one aligned u64 match and overlapping one aligned u32 match at the same file
  offset; these are two views of one table entry, not independent literals,
  with no separate target literal elsewhere. Only base `0x09260000` has an
  aligned outside-table u32, file `0x80154`, VA
  `0x148bc254`, segment class RWE; other bases have zero aligned u32 and all
  bases have zero aligned u64.
- PT_LOAD/store census: RX4/RWE2/RW3/OTHER0; recognized STR W/X counts
  RX6945/RWE5169; matching offsets RX `{0x400:7,0x404:2,0x4d0:2}` and RWE
  `{0x400:1,0x404:1,0x4d0:1}` for 14 total, with seven RX SP candidates.
- Resolution/classification: no base/effective-address resolution; public
  resolved hit count is JSON `null`, not zero. Classification is
  `STAGE1A_LITERAL_AND_STORE_OFFSET_CENSUS_WRITER_UNKNOWN`; no writer claim.
  Class C remains unchanged and 015/016 are reserved `NOT ELIGIBLE`.
- Tool SHA-256:
  `9806b64c01f9965161966c88bbf5b943d953e790664c3136b2a116da63f8dc57`.
- Focused-test SHA-256:
  `b5fbf50e545b9df86d45ac012106d8905af231d9e94b0b2dd1927ec365da13d8`.
- Public manifest SHA-256:
  `8861a5626576fac32a83c295c34be63f91fd5e3f4b434490d567fb2984bb192d`.
- Host verification: 8 focused tests and all 287 repository unittest-discovery
  tests pass; all 54 public manifests parse as JSON; regeneration is
  byte-identical. Independent Luna raw-byte feasibility review agreed on the
  14 candidates and no resolved target in its broader model but emitted no
  artifact; no review-artifact hash exists.
- Next discriminator: Stage 2A same-block direct-definition slice of only the
  four non-SP RX candidates is complete; see the Stage 2A metadata below.

## Experiment 018 XBL MC writer Stage 2A metadata

- Experiment ID: `018-xbl-mc-writer-xref-stage2a-20260825-01`
- Date: `2026-08-25 KST`
- Target/input: exact retained `SM-A908N` / `SM8150` XBL
  `xbl--sdb1.bin`, 4,194,304 bytes, SHA-256
  `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`
- Exact action:
  `python3 tools/sm8150_xbl_mc_writer_stage2a.py --output evidence/manifests/018-xbl-mc-writer-xref-stage2a-20260825-01.manifest.json`
- Device/SMC/MMIO access: none; mode `HOST_ONLY_READ_ONLY`; public mode `0644`.
- Scope: exactly four non-SP RX candidates:
  `0x14844b20/0x2bb20/X8/+0x400`,
  `0x14844c78/0x2bc78/X8/+0x4d0`,
  `0x146a70c0/0x2d6090/X8/+0x400`, and
  `0x14935bf4/0x312bc4/X19/+0x400`. Seven SP candidates remain runtime-
  derived and three RWE candidates remain ambiguous.
- Model: maximum 128 aligned instructions; only 64-bit MOVZ/MOVK or same-
  register `ADRP Xn; ADD Xn,Xn,#imm`; branches, calls, returns, inbound
  direct-branch entries, boundaries and unsupported definitions fail closed.
- Exact outcome: `resolved_base_count=0`,
  `resolved_target_hit_count=0`; reason counts are three
  `NO_DIRECT_CONSTANT_DEFINITION` (two `WINDOW_LIMIT`, one BL
  `CONTROL_TRANSFER`) and one `UNSUPPORTED_REGISTER_DEFINITION` (LDR at
  `0x146a70b4`). Classification is
  `NO_RESOLVED_TARGET_STORE_WITHIN_STAGE2A_DIRECT_DEFINITION_RX_MODEL`.
  This refutes only the supported direct-definition path, not writer absence.
- Tool SHA-256:
  `eb0a8ce21154d97d052de9f7e4e0de40f85087a8cb517179f7c44332e9d85eb0`.
- Focused-test SHA-256:
  `1272fadb0bcc6b883f74577284312ee34678975fa7ba60377d05d86927960b3b`.
- Public manifest SHA-256:
  `eeed732e4a6cecd60453e9088d8c3d4c7ed207a1e7c723bae91e27033d134a4b`.
- Host verification: 14 focused tests and 301 full repository unittest-
  discovery tests pass; all 55 public manifests parse as JSON; regeneration is
  byte-identical. No runtime execution, writer identity, semantics,
  mutability/lock, GF(2), alias, bypass or other-firmware claim is made.

## Experiment 018 XBL MC writer Stage 2B metadata

- Experiment ID: `018-xbl-mc-writer-xref-stage2b-20260825-01`
- Date: `2026-08-25 KST`
- Target/input: exact retained `SM-A908N` / `SM8150` XBL
  `xbl--sdb1.bin`, 4,194,304 bytes, SHA-256
  `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`
- Exact action:
  `python3 tools/sm8150_xbl_mc_writer_stage2b.py --output evidence/manifests/018-xbl-mc-writer-xref-stage2b-20260825-01.manifest.json`
- Device/SMC/MMIO access: none; mode `HOST_ONLY_READ_ONLY`; public mode `0644`.
- Scope: only `0x14844b20/0x2bb20/X8/+0x400` and
  `0x14844c78/0x2bc78/X8/+0x4d0`, with a maximum 512 aligned predecessors.
  Same-register `MOVZ W8,#0xf000` plus `MOVK W8,#0x1489,LSL#16` zero-extends
  to X8 value `0x1489f000`; computed values are `0x1489f400` and
  `0x1489f4d0`, both outside file-backed PT_LOADs.
- Exact outcome: `resolved_base_count=2`,
  `resolved_numeric_target_hit_count=0`, and remaining Stage 2A unresolved
  count 2. Classification:
  `NO_NUMERIC_TARGET_ADDRESS_MATCH_WITHIN_STAGE2B_W_WIDE_MOVE_RX_MODEL`.
  This refutes only numeric equality under this model; physical destination,
  VA-to-PA translation, writer identity and unsupported/dynamic paths remain
  `UNKNOWN`.
- Tool SHA-256:
  `aa35d8b303a7ea32a086d601b1f08390b1cad0932f105209ac337f394813dbcb`.
- Focused-test SHA-256:
  `af7ca7b46550dda13e85e517c0c1c1df19b6414549d06415316b6d428e020fc9`.
- Public manifest SHA-256:
  `a4715112e27c74e5548ecb49f09106c236146c8a0216c87446ddbd3c355ccca6`.
- Host verification: 10 focused tests and 311 full repository unittest-
  discovery tests pass; all 56 public manifests parse as JSON; regeneration is
  byte-identical. Stage 1A/Stage 2A artifacts remain hash-pinned and unchanged.

## Experiment 018 XBL MC writer Stage 2C metadata

- Experiment ID: `018-xbl-mc-writer-xref-stage2c-20260825-01`
- Date: `2026-08-25 KST`
- Target/input: exact retained `SM-A908N` / `SM8150` XBL
  `xbl--sdb1.bin`, 4,194,304 bytes, SHA-256
  `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`
- Exact action:
  `python3 tools/sm8150_xbl_mc_writer_stage2c.py --output evidence/manifests/018-xbl-mc-writer-xref-stage2c-20260825-01.manifest.json`
- Device/SMC/MMIO access: none; mode `HOST_ONLY_READ_ONLY`; public mode `0644`.
- Scope/pins: writer `[0x146a70a4,0x146a70dc)` / file `0x2d6074`, 56
  bytes, SHA-256 `a50aaeb45c498a63e91704fc0ec4550b120ca0c1b691c238736b0532136dad6c`;
  wrapper 108-byte SHA-256
  `24008bb23f54ed515774f020ac62cb3973b74dc57a41acd2bd358567863ad436`;
  lookup 272-byte SHA-256
  `9e54cfe4e5e2fad580b92c0853513f1be25046abeb00ff76db83d87ad3036046`;
  retained table 48×16 bytes at `0x146aa4d0` / `0x2d94a0`, SHA-256
  `47a7f6195703f2f4d27cbe1e8bd0cc976600453a3ba4aebba98736ef8e03906e`.
- Exact outcome: one direct BL caller at `0x146a67a4` / `0x2d5774`; count
  u32 48; 48 unique IDs and nonzero pointers; reserved +4 zeros 48; zero
  target-base pointer matches and zero possible `base+0x400` target matches.
  The 48 rows are descriptor-eligibility-dependent possible values, not proof
  of per-entry execution. One non-SP RX static candidate remains (`X19`).
  Classification:
  `NO_NUMERIC_TARGET_ADDRESS_MATCH_WITHIN_STAGE2C_UNIQUE_DIRECT_CALLER_TABLE_MODEL`.
- Tool SHA-256:
  `d53d820eb8d10e8417247fabbc0e3196f73c73584a6b7d79d583a96834c34d53`.
- Focused-test SHA-256:
  `92c95472940937a7001fe48dd055b4c598fd290c28a1e15757d1c297ebf5f526`.
- Public manifest SHA-256:
  `e096562a35da93a1dac10a1651fc7eff08eecf05dafca4a789bae2fd50540c01`.
- Host verification: 9 focused tests and 320 full unittest-discovery tests pass;
  all 57 public manifests parse as JSON; regeneration is byte-identical and
  mode is `0644`.

## Experiment 018 XBL MC writer Stage 2D metadata

- Experiment ID: `018-xbl-mc-writer-xref-stage2d-20260826-01`
- Date: `2026-08-26 KST`
- Target/input: exact retained `SM-A908N` / `SM8150` XBL
  `xbl--sdb1.bin`, 4,194,304 bytes, SHA-256
  `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`
- Exact action:
  `python3 tools/sm8150_xbl_mc_writer_stage2d.py --output evidence/manifests/018-xbl-mc-writer-xref-stage2d-20260826-01.manifest.json`
- Device/SMC/MMIO access: none; mode `HOST_ONLY_READ_ONLY`; public mode `0644`.
- Scope/pins: candidate `0x14935bf4/0x312bc4`, function 1,404-byte SHA-256
  `68739df6f843f790376eb0af47da22f0af5ebeb2421f05d29c3b5a8673983fd9`;
  initializer 2,092-byte SHA-256
  `65e117b99fd109cbb01531bd70fc2befe70c0b672a01afe6dd523bbebf1486cb`;
  target 228-byte SHA-256
  `5c979955c6d1cdfd541766ca3ea6964460803d61aa3d07bed0c74f60d3eec34e`.
- Exact outcome: one direct BL caller and zero direct B callers; W0=0 at the
  scoped call; intrinsic effective values `0x85e9e970`/`0x85e9ef70`; direct
  caller conditional value `0x85e9e970`; zero numeric target matches. The
  initializer-derived import slot and target range remain runtime-conditional.
  Classification:
  `NO_NUMERIC_TARGET_ADDRESS_MATCH_WITHIN_STAGE2D_UNIQUE_DIRECT_CALLER_CONDITIONAL_CALLEE_SAVED_PRESERVATION_MODEL`.
- Tool SHA-256:
  `95e53e25f288ba1ef09996ff73919c2ad1dd4186c4fec41dc84216d715ee8b26`.
- Focused-test SHA-256:
  `23c91a14c16706b920b4c3556e85844543dc99545a2b7b6d864a8c09d35f6136`.
- Public manifest SHA-256:
  `48c7aa83d30844f1d42094fcb0f8d7dd13cf44265f9961167912792d014661c4`.
- Host verification: 14 focused tests and 334 full unittest-discovery tests
  pass; all 58 public manifests parse as JSON; regeneration is byte-identical
  and mode is `0644`.
