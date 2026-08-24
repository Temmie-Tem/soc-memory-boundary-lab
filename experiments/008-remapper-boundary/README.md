# Experiment 008 — Exact Remapper / Protection-Bank Recombination

Result: `PROVED STATIC BOOT CONFIGURATION / UNKNOWN RUNTIME VALUES / NO BYPASS`.

## Question

Can the exact retained A90 boot log resolve the previously unknown DCB and
remapper-table choice, and can exact TrustZone structures narrow the security
owner of the four `qhs_llcc + 0x8080` windows?

## Inputs and action

The host-only tool `tools/sm8150_remapper_boundary_inventory.py` pins and parses:

- XBL SHA-256 `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`;
- XBL config SHA-256 `0e9dfac1ddd0f9acc2cc899213e621490308f0cadf329814048edb7712e2484c`;
- TrustZone SHA-256 `a5e6c574e18e2e576a25df6274b20bdb142386811dfda6383f86d7b1b3c102ab`;
- retained last-kmsg SHA-256
  `8701d073e86728790c33f05dce21891ca3454f5b778d92285ce3b5bc33216b93`.

It performs no device, MMIO, partition, or firmware write. Reproduction:

```sh
python3 tools/sm8150_remapper_boundary_inventory.py --replace
```

Public result:
`evidence/manifests/008-remapper-boundary-inventory-20260825-01.manifest.json`.
The path-bearing derived record remains ignored and mode `0600` under
`evidence/private/`.

## Exact boot selection

`PROVED`: All seven retained chip-revision records agree on
`0x01fc8000 = 0x60030202`; all seven CDT records agree on platform ID `8`.
The exact XBL selector therefore produces:

```text
hardware ID       0x6003
hardware version  0x0200
physical platform 1 (platform 8 is not RUMI 0x0f)
DCB filename      /6003_0200_1_dcb.bin
```

The selected DCB SHA-256 is `34caf815…`, used size is `11820`, and its
560-byte section 16 SHA-256 is `cdacfa45…`; XBL copies it to `0x09065100`.

`PROVED`: All six retained topology records agree on rank 0 = 3072 MiB and
rank 1 = 3072 MiB. Rank mask `0x3` and total 6144 MiB uniquely choose table row
7:

```text
region 0 destination  0x80000000
region 1 destination  0x140000000
```

The 12-GiB special-case predicate in the selector is `REFUTED_FOR_THIS_BOOT`.

## Exact writer

Five exact XBL function ranges are pinned by SHA-256. The layout-1 commit at
`0x1484fbbc..0x1484fe74`:

1. writes `old_control & 0x3f0` to `+0x00` for each instance;
2. writes six 36-bit range slots as low 32 bits plus a masked high nibble at
   `+0x04..+0x58`;
3. installs the active-slot mask in control bits `9:4`;
4. writes `(control & 0x3f0) | 1` to enable each instance.

`PROVED` within that exact function boundary: there is no distinct lock-register
write. `UNKNOWN`: a later TrustZone operation or hardware write-once lock.

The selected destination bases and rank sizes are known, but XBL takes each
rank's source base and interleave state from a runtime DDR context. Those bytes
were not captured. Exact boot register values therefore remain
`UNKNOWN_DEPENDS_ON_RUNTIME_DDR_CONTEXT`; they are not inferred from Linux
`/proc/iomem`.

## TrustZone / protection relationship

`PROVED`: TrustZone's primary 24-byte resource records bind:

```text
BIMC_MPU0  id 0x2e  base 0x0924e000
BIMC_MPU1  id 0x2f  base 0x092ce000
BIMC_MPU2  id 0x3f  base 0x0934e000
BIMC_MPU3  id 0x40  base 0x093ce000
```

For every instance, the remapper is at `qhs_llcc + 0x8080` and its BIMC MPU
configuration block is at the same window's `+0xe000`. TrustZone also binds
`MEMNOC_MS_MPU`, `LLCC_BROADCAST_MPU`, and `DC_NOC_SHRM_MPU` to exact bases.

This proves same-instance configuration knowledge, not that the MPU protects
its own configuration aperture or that TrustZone invokes its duplicated
`icbcfg` record. The exact TZ image contains no byte-identical copy of the five
pinned XBL function bodies or their first 64 bytes; a semantic equivalent is
still `UNKNOWN`.

Retained successful boots register LLCC PMU and LLCC-to-DDR monitors four times,
so a whole-fabric power-off explanation is disfavored. Separate gating or
security ownership of `+0x8080` remains possible. The reset collector started
`print_xpu_info`, but explicitly reported that the TZ log was encrypted or not
parsed. Absence of a decoded XPU violation is therefore not negative evidence.

## Classification and next step

Current classification remains `NO_BOUNDARY_BYPASS_OBSERVED / CLASS UNKNOWN`.
No remapper value, EL1 write, DRAM alias, or protection-ordering result exists.

The cheapest discriminating successor is host-only Experiment 009: trace the
TrustZone resource-record consumers plus qhs_llcc clock/fault-response ownership
to decide whether the fixed read watchdog is compatible with an XPU denial,
sub-aperture gating, or a stale/non-runtime register window. The same live load
must not be repeated without a new prediction.
