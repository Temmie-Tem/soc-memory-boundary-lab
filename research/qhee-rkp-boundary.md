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

## What is not proved

- `UNKNOWN`: Firmware bytes supplying the QHEE/hyp runtime and their exact hash.
- `UNKNOWN`: Arbitrary read/write of EL2 private runtime memory.
- `UNKNOWN`: Whether RKP/XPU enforcement compares pre-transform or
  post-transform address signals.
- `UNKNOWN`: Whether final DDR decode state is mapped, readable, or writable at
  EL1.
- `UNKNOWN`: Whether EL2 validates/locks DDR decode state or delegates it to EL3.

`REFUTED`: “RKP range appears as System RAM, so it is unprotected.” A resource
label cannot substitute for a controlled access result and ignores dynamic
stage-2/XPU permission mechanisms.
