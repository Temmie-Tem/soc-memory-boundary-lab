# Experiment 010 — QHEE/TZ XPU Initializer and Authority Boundary

Result: `PROVED SEPARATE QHEE AND TZ ENFORCEMENT PATHS / PROVED DYNAMIC BIMC
POLICY / NO BYPASS`.

## Question

Who initializes `BIMC_MPU0..3`, what does the exact HLOS `hyp_assign` path
actually control, and is there an EL1-visible SMC that can disable or rewrite
the XPU policy protecting the remapper/controller apertures?

## Inputs and action

The host-only tool `tools/sm8150_xpu_initializer_inventory.py` pins:

- XBL SHA-256
  `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`;
- TrustZone SHA-256
  `a5e6c574e18e2e576a25df6274b20bdb142386811dfda6383f86d7b1b3c102ab`;
- QHEE/hyp SHA-256
  `646f8fca08b0eff56b1d8415d81c3041a775c1871400dc57448cb5103405a8e1`;
- devcfg SHA-256
  `0399578253dd293dfc961c6a1077f660834df3ae5e1d65555f4225e327a03d14`.

It validates ELF mappings, exact 24-byte syscall records, function hashes,
instruction words, direct branch targets, XPU registry entries, both static
policy arrays, topology tables, and XBL diagnostic records. It performs no
device, SMC, MMIO, partition, or firmware access.

```sh
python3 tools/sm8150_xpu_initializer_inventory.py --replace
```

Public result:
`evidence/manifests/010-xpu-initializer-inventory-20260825-01.manifest.json`.
The path-bearing result remains ignored and mode `0600` under
`evidence/private/`.

Comparative Qualcomm SDM660 headers and unstripped objects at commit
`b5e5bb9ed6c92442fd502b3e726d7c8024dc0763` supply names and field
documentation only. Every address, SMC record, branch, value, and policy below
is independently pinned to the exact A90 firmware.

## Correct syscall-record layout

`PROVED`: both exact TZ and QHEE tables use 24-byte records:

```c
struct syscall_record {
    uint32_t reserved;
    uint32_t smc_id;
    uint32_t param_id;
    uint32_t flags;
    uint64_t handler;
};
```

The relevant exact bindings are:

| Owner | SMC | Handler | Meaning/boundary |
|---|---:|---:|---|
| QHEE | `0x02000c16` | `0x85723b90` | HLOS `hyp_assign` intercept |
| TZ | `0x02000c16` | `0x1c0a6de4` | separate secure-world fallback |
| TZ | `0x02000c23` | `0x1c0a9a44` | XPU enable/disable toggle |
| QHEE/TZ | `0x0200030f` | `0x857161c0` / `0x1c050b9c` | RPM-region service |
| QHEE/TZ | `0x32000105` | `0x85716348` / `0x1c0c30f8` | app-region notification |

The earlier provisional interpretation that the word adjacent to an SMC ID
was its handler is `REFUTED`; it is the parameter ID/flags portion of this
record.

## QHEE `hyp_assign` is not the TZ BIMC writer

`PROVED`: exact QHEE handler `0x85723b90` validates the input buffers, source
and destination VM lists, page alignment, and ownership. It directly calls
the local `0x8573581c` access-control mapping wrapper, whose exact structure
matches the comparative `ACMapMemoryRange` API and leads to QHEE's internal
stage-2/SMMU implementation.

`PROVED`: that bounded QHEE handler does not directly call QHEE's generic TZ
SMC wrapper at `0x85718100`. Therefore kernel `hyp_assign` does not itself prove
a write to TZ's BIMC XPU registers.

`SUPPORTED`: on the production boot path QHEE's same-ID intercept handles the
HLOS request before the separate TZ fallback. Runtime dispatcher precedence is
not promoted to `PROVED` merely from duplicate table entries.

## TZ fallback reaches dynamic BIMC policy

`PROVED`: the exact TZ same-ID fallback follows this chain:

```text
SMC 0x02000c16
  -> 0x1c0a6de4 assignment handler
  -> 0x1c0a5564 assignment core
  -> 0x1c0ab624 memory lock
  -> 0x1c0ab6c8 internal lock
  -> 0x1c0a9d5c MPU lock-area
  -> 0x1c0a9e14 topology fanout
  -> 0x1c0a9f44 MPU reconfigure
```

The six-entry topology jump table at `0x1c122b40` selects code that emits
registered XPU resources `0x2e`, `0x2f`, `0x3f`, and `0x40` — exact
`BIMC_MPU0..3` — and in some cases `0x3a`, exact
`LLCC_BROADCAST_MPU`. IDs `0x51..0x54` are also emitted in one topology branch
but have no entry in the exact primary registry; their target-specific meaning
and runtime reachability remain `UNKNOWN`.

This `REFUTES` the Experiment 009 inference that absence from the two static
policy arrays might mean BIMC MPU inactivity. Those arrays do not initialize
`BIMC_MPU0..3`; the memory-lock path configures them dynamically.

## Named QHEE/TZ services do not expose a generic writer

`PROVED`: QHEE's RPM-region path calls TZ SMCs `0x02000310` and
`0x0200030f`, then installs fixed RPM mappings. The exact TZ handler for
`0x0200030f` is one instruction, `RET`. Thus the firmware string describing an
“XPU unlock RPM Regions” operation does not establish an XPU mutation in this
exact TZ build.

`PROVED`: QHEE's app-region handler calls TZ SMC `0x32000105`. The exact TZ
handler calls `0x1c0c54e8` and `0x1c03aa8c` for QSEE region/list handling and
does not directly call the reconstructed BIMC/XPU routines.

## XPU toggle is not a usable EL1 disable primitive

`PROVED`: exact TZ registers SMC `0x02000c23`. Its enable path converts the
supplied base to a registered XPU ID and invokes HAL restore. Its disable path
requires a nonsecure-device check and then searches the allowed-disable list
returned by `0x1c0a2630`.

`PROVED`: the exact allowed-disable count at `0x1c122a90` is zero. Therefore no
base can pass that list on this build. The handler is neither an arbitrary
register writer nor a usable XPU-disable primitive for HLOS.

`PROVED`: exact QHEE contains no literal `0x02000c23`; exact TZ contains no
literal `0x02000c24` (`TZ_MPU_LOCK_HLOS_REGION`). Literal absence is bounded
evidence and is not generalized into proof that no semantically equivalent
constructed-ID path could exist elsewhere.

## All known controller apertures have branch-invariant static coverage

`PROVED`: both exact TZ selector branches cover all eight known addresses —
four remappers and four `BIMC_MPU` bases — with both:

```text
MEMNOC_MS_MPU region 0
  0x00000000–0x10000000, flags 0x9, read/write 0x80000000

CNOC_SNOC_MS_MPU region 5
  0x09000000–0x09800000, flags 0x9, read/write 0xf0000000
```

Both are TZ-owned and contain no ordinary HLOS VMID grant. Instance 0 has
additional `DC_NOC_BROADCAST_MPU` coverage: region 11 over the remapper page
and region 13 over `BIMC_MPU0`.

`SUPPORTED`: those policies explain why direct EL1 access to a known controller
aperture is unavailable. Final post-boot register readback is still `UNKNOWN`,
so static content is not mislabeled as runtime state.

## Boot master-MPU loop and XBL boundary

`PROVED`: boot function `0x1c0a40f8` invokes initializer `0x1c0ace70` with
selectors `0x1e`, `0x23`, and `0x1d`. Their exact records resolve to
`ANOC2_MPU`, `MSS_NAV_MPU`, and `CNOC_AOSS_MPU`. That loop does not initialize
`BIMC_MPU0..3`.

`PROVED`: XBL contains `{resource ID, base}` records for the four BIMC MPUs in
a secondary region carrying `XPU_VER_20190409225523` and
`QC_IMAGE_VERSION_STRING=TZ.XF.5.2-00181`, alongside XPU violation-reporting
material. `REFUTED`: those literals alone prove that the main XBL program
writes BIMC policy registers. The exact TZ dynamic chain above is the first
positive initializer evidence.

## Lock-state boundary

`SUPPORTED`: the inspected TZ static-config construction begins with
`0x0001c800`, whose comparative secure-config-write-disable field is not set,
consistent with later secure-world lock/unlock operations.

`PROVED`: exact XPU3 init only null-checks its second configuration argument;
it does not consume that field as a final hardware lock decision. Exact restore
and reset preserve control-register mask `0x2` while changing enable state.

`UNKNOWN`: the actual boot/runtime value of that preserved hardware bit. This
experiment does not prove the controller permanently unlocked or writable from
Normal World.

## Result

Current classification is deliberately bounded:

```text
CLASS A OR B CANDIDATE — CONTROLLER APERTURES ONLY
NO SECURITY BOUNDARY BYPASS OBSERVED
```

QHEE/EL2 work is directly useful: it proves that the HLOS ownership API is an
independent stage-2/SMMU enforcement layer and separates it from TZ's dynamic
BIMC XPU implementation. It does not grant arbitrary EL2 memory access or
arbitrary XPU control.

The cheapest next experiment remains host-only: isolate the final MCCC/MC/SHRM
physical-address-to-channel/bank/rank transform and determine whether memory
data-path protection evaluates its input before or after that transform. A
repeat of the already denied controller load has no new discriminating value.
