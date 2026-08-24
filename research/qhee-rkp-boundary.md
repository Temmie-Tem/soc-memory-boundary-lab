# QHEE / RKP Boundary

## What is proved

- `PROVED`: Exact defconfig enables UH/RKP, KDP, NS protection, direct-map
  protection and CFP JOPP/ROPP.
- `PROVED`: `rkp_init()` obtains RKP bitmaps then starts the UH RKP app through
  `uh_call`; the assembly entry issues `smc #0`.
- `PROVED`: Live DT advertises `hyp_mem` at `0x85700000–0x85cfffff`, RKP at
  `0xb0200000–0xb03fffff`, and `uh_heap_region` at
  `0xb0400000–0xb17fffff`.
- `PROVED`: `/proc/iomem` omits `hyp_mem` from System RAM, while its broad
  resource view includes the RKP range inside System RAM.
- `PROVED`: The exact rebuild and independently extracted stock kallsyms both
  retain kernel-to-hypervisor/SCM interfaces and RKP-related symbols.
- `PROVED`: The live `hyp` partition was captured byte-for-byte. It is an
  AArch64 ELF loading at `0x85700000`, entering at `0x85710000`, and identifies
  `hyp.mbn`, memory ownership, SMMU virtualization and kernel asset protection.
  Its exact SHA-256 is recorded in the Experiment 004 manifest.
- `PROVED` by Experiment 010: QHEE's exact syscall table registers HLOS
  memory-assignment SMC `0x02000c16` at handler `0x85723b90`. The 24-byte record
  is independently pinned with parameter ID `0x1117` and flags `0x80000000`.
- `PROVED`: that handler validates buffers, VM lists, ownership and page
  alignment, then calls exact local wrapper `0x8573581c`. The wrapper's
  structure and comparative `ACMapMemoryRange` API identify this as QHEE's
  stage-2/SMMU access-control path.
- `PROVED`: the bounded `hyp_assign` handler does not directly call QHEE's
  generic TZ SMC wrapper at `0x85718100`. QHEE ownership enforcement and TZ's
  same-ID dynamic BIMC fallback are separate implementations.
- `PROVED`: QHEE's named RPM-region and app-region handlers call specific TZ
  services rather than exposing a generic XPU writer. The exact TZ RPM handler
  is a single `RET`; the exact app-region handler only calls its QSEE region/list
  helpers directly.

## What is not proved

- `UNKNOWN`: Arbitrary read/write of EL2 private runtime memory.
- `UNKNOWN`: Whether RKP/XPU enforcement compares pre-transform or
  post-transform address signals.
- `UNKNOWN`: Whether final DDR decode state is mapped, readable, or writable at
  EL1.
- `UNKNOWN`: Whether QHEE's production dispatcher always intercepts the
  duplicate `0x02000c16` before TZ under every boot state. Normal production
  interception is `SUPPORTED`, not promoted from table structure alone.
- `UNKNOWN`: Whether QHEE validates/locks final DDR decode state. Its proved
  HLOS memory-assignment path controls ownership/stage-2/SMMU mappings, not the
  identified TZ BIMC policy registers.

`REFUTED`: “RKP range appears as System RAM, so it is unprotected.” A resource
label cannot substitute for a controlled access result and ignores dynamic
stage-2/XPU permission mechanisms.

`REFUTED`: “Prior EL2 work is irrelevant.” It supplies the exact independent
ownership layer in the candidate attack pipeline and prevents conflating an
HLOS `hyp_assign` call with arbitrary EL3 XPU control. It still does not prove
arbitrary read/write of EL2 private memory.
