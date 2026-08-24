# Experiment 009 — Exact TrustZone XPU Policy Reconstruction

Result: `PROVED STATIC POLICY COVERAGE / SUPPORTED XPU-DENIAL CAUSE / NO BYPASS`.

## Question

Does the exact A90 TrustZone image contain and consume an XPU policy that
covers the failed EL1 read at `0x09248080`, and does that policy grant ordinary
HLOS access?

## Inputs and action

The host-only tool `tools/sm8150_xpu_policy_inventory.py` pins and parses:

- TrustZone SHA-256
  `a5e6c574e18e2e576a25df6274b20bdb142386811dfda6383f86d7b1b3c102ab`;
- devcfg SHA-256
  `0399578253dd293dfc961c6a1077f660834df3ae5e1d65555f4225e327a03d14`;
- retained last-kmsg SHA-256
  `8701d073e86728790c33f05dce21891ca3454f5b778d92285ce3b5bc33216b93`.

It performs no device or MMIO access. Reproduction:

```sh
python3 tools/sm8150_xpu_policy_inventory.py --replace
```

Public result:
`evidence/manifests/009-xpu-policy-inventory-20260825-01.manifest.json`.
The path-bearing derived result remains ignored and mode `0600` under
`evidence/private/`.

## Consumed registry and policy lists

`PROVED`: TZ has a 48-record registry at `0x1c1579e0`, with 24-byte records:

```c
struct xpu_registry_record {
    uint64_t resource_id;
    uint64_t mmio_base;
    uint64_t name_pointer;
};
```

The pinned lookup function `0x1c0fc890..0x1c0fca1c` walks that table with a
`0x18` stride and reads hardware capability registers from the selected base.
The records are therefore runtime-consumed data, not isolated strings.

`PROVED`: selector function `0x1c0a2dfc..0x1c0a2ec4` chooses one of two static
policy arrays:

| Branch | Array | Count |
|---|---:|---:|
| selector byte `< 2` | `0x1c122100` | 43 |
| selector byte `>= 2` | `0x1c121250` | 44 |

Every descriptor's ID/base pair matches the primary registry. Both arrays
contain one `DC_NOC_BROADCAST_MPU` descriptor at base `0x090e0000` with 40
MPU-region records. The boot initialization path calls the pinned static-config
loop, which calls the per-device configuration routine and ultimately the HAL
resource-group writer.

## Critical region

Both selector branches contain the same 32-byte region record:

```text
resource           DC_NOC_BROADCAST_MPU (id 0x3c)
region index       11
flags              0x00000009 (enabled + TZ owner)
read_vmid          0x80000000
write_vmid         0x00000000
start              0x09248000
end exclusive      0x09249000
tested PA          0x09248080
```

`PROVED`: `0x09248080` is inside this region regardless of which embedded
policy array the selector returns.

The previous preliminary reading of `0x80000000` as `0x80` was wrong and is
`REFUTED`; the field is a little-endian 32-bit value.

## Permission conversion

The exact `0x1c0aa51c..0x1c0aa7e4` MPU conversion routine was replayed and
pinned by function hash plus critical instruction words. For region 11 it
constructs:

```text
HAL config type                 0 (TZ/secure owner)
standard multi-VMID perms       0x00000000, 0x00000000
client-permission bytes         0x11, 0x08
TZ-owner access                 read + write
MSA-class client access         read only
ordinary HLOS VMID access       none
```

The `0x80000000` read bit maps to the same client-permission slot that the exact
routine assigns when flag bit 2 selects the MSA owner. Flag bit 3 selects TZ
ownership and adds TZ owner read/write. No standard VMID bit survives the
conversion, and the comparative Qualcomm access-control definition identifies
HLOS as VMID 3 (`0x8`), which is absent from both masks.

Comparative field names and layouts were checked at commit
`b5e5bb9ed6c92442fd502b3e726d7c8024dc0763` of the public
`David112x/android-firmware-qti-sdm660` mirror. This is not exact SM8150 source;
all SM8150 addresses, branches, values, and conversions above are independently
pinned to the exact A90 binary. Comparative source locations:
[AccessControlTz.h](https://github.com/David112x/android-firmware-qti-sdm660/blob/b5e5bb9ed6c92442fd502b3e726d7c8024dc0763/trustzone_images/core/securemsm/accesscontrol/api/AccessControlTz.h)
and
[HALxpu3.h](https://github.com/David112x/android-firmware-qti-sdm660/blob/b5e5bb9ed6c92442fd502b3e726d7c8024dc0763/trustzone_images/core/kernel/xpu3/hal/inc/HALxpu3.h).

## Enable and error-path evidence

`PROVED`: exact devcfg contains `/ac/xpu:disable_xpu_ac` as a uint32 value `0`.
This is evidence against an intentional static XPU-disable setting; it is not a
runtime register readback.

`PROVED`: the TZ global error-router table maps:

```text
bank 0 bit 20  MEMNOC_MS_MPU
bank 0 bit 25  BIMC_MPU0
bank 0 bit 26  BIMC_MPU1
bank 0 bit 27  BIMC_MPU2
bank 0 bit 28  BIMC_MPU3
bank 0 bit 29  DC_NOC_BROADCAST_MPU
bank 0 bit 31  DC_NOC_NON_BROADCAST_MPU
bank 1 bit 13  DC_NOC_SHRM_MPU
```

The exact handler contains config/client-port, `APROTNS`, and read/write error
decoding. The retained reset collector entered `print_xpu_info`, but the TZ log
was encrypted or unparsed, so no syndrome identifies the faulting block.

`PROVED`: BIMC_MPU0..3 do not appear in either of these two embedded static
policy lists. This does not prove that they are disabled; XBL, another secure
component, hardware defaults, or another TZ path may initialize them.

## Result and boundary

`SUPPORTED`: the single EL1 load is strongly compatible with an active
`DC_NOC_BROADCAST_MPU` denial or its downstream fabric response. This is now a
better explanation than a whole-LLCC-fabric power-off, because successful boots
register LLCC/DDR monitoring endpoints and the exact policy denies ordinary
HLOS access to the tested page.

`UNKNOWN`: final post-boot XPU register values, the decoded fault syndrome, and
whether a separate sub-aperture clock condition contributed. Therefore the
watchdog's causal label remains `SUPPORTED`, not `PROVED`.

No address-transform value, EL1 write primitive, DRAM alias, protected-memory
access, or security-boundary bypass was obtained. Current classification is:

```text
CLASS A OR B SECURITY POLICY PRESENT
NO BOUNDARY BYPASS OBSERVED
```

The cheapest next experiment is still host-only: locate who initializes
`BIMC_MPU0..3` and recover the ordering between `DC_NOC_BROADCAST_MPU`, the
four `qhs_llcc + 0x8080` remappers, and the later DRAM decode. Repeating the
same live load has no new discriminating value.
