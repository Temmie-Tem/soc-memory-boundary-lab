# TrustZone / XPU Boundary

`PROVED`: Exact target kernel passes physical range descriptors and VMID/
permission lists through SCM memory-protection service calls. Secure-buffer
locking uses SCM MP services as well.

`PROVED`: Live DT advertises `qseecom_region` at
`0xa6000000–0xa83fffff`; exact live evidence takes precedence over the generic
base-DTS value.

`PROVED` with Experiment 010's boundary: QHEE's HLOS memory-assignment path
updates its local ownership/stage-2/SMMU state, while a separate TZ same-ID
fallback reaches dynamic BIMC MPU policy. Their production dispatch ordering
and final hardware register values remain `SUPPORTED/UNKNOWN` respectively.

`PROVED`: Exact live `tz` bytes name `BIMC_MPU0..3`, `MEMNOC_MS_MPU`, and
`LLCC_BROADCAST_MPU`. This replaces a generic XPU hypothesis with concrete
SM8150 firmware block names, but does not yet establish enablement or ordering.

`PROVED` by Experiment 008: these are not strings alone. Unique primary
24-byte registry records have the form `{u64 id, u64 base, u64 name_pointer}`
and bind:

| Resource | ID | Base |
|---|---:|---:|
| `BIMC_MPU0` | `0x2e` | `0x0924e000` |
| `BIMC_MPU1` | `0x2f` | `0x092ce000` |
| `BIMC_MPU2` | `0x3f` | `0x0934e000` |
| `BIMC_MPU3` | `0x40` | `0x093ce000` |
| `MEMNOC_MS_MPU` | `0x4b` | `0x096c0000` |
| `LLCC_BROADCAST_MPU` | `0x3a` | `0x0964e000` |
| `DC_NOC_SHRM_MPU` | `0x4d` | `0x09102000` |

Each `BIMC_MPU<n>` base is `qhs_llcc + 0xe000` in the same instance whose
remapper starts at `qhs_llcc + 0x8080`. This is an exact same-window relation;
it does not establish that the MPU protects its own configuration window.

## Experiment 009 policy consumer and tested-page coverage

`PROVED`: the full primary table has 48 records and is consumed by exact
function `0x1c0fc890..0x1c0fca1c`. The function validates a resource ID,
searches the table with stride `0x18`, retrieves its base/name, and reads
capability registers from that base. The registry is therefore executable
configuration metadata, not a set of unreferenced strings.

`PROVED`: exact selector `0x1c0a2dfc..0x1c0a2ec4` chooses one of two embedded
policy arrays. The `< 2` branch has 43 descriptors; the `>= 2` branch has 44.
Both contain one `DC_NOC_BROADCAST_MPU` descriptor at `0x090e0000`, with 40
32-byte MPU region records. Both contain the identical critical record:

| Field | Exact value |
|---|---:|
| region index | `11` |
| flags | `0x00000009` |
| read VMID/access word | `0x80000000` |
| write VMID/access word | `0x00000000` |
| start | `0x09248000` |
| end exclusive | `0x09249000` |

`PROVED`: the fixed EL1 load PA `0x09248080` is inside that range under either
selector result. The preliminary interpretation of the access word as `0x80`
is `REFUTED`; its exact little-endian uint32 value is `0x80000000`.

`PROVED`: exact conversion function `0x1c0aa51c..0x1c0aa7e4` consumes the
32-byte record, selects TZ owner from flag bit 3, and produces standard VMID
permission words `0/0` plus client-permission bytes `0x11/0x08`. Exact branch
semantics and comparative XPU3 field definitions resolve this as:

```text
owner                         TZ
TZ-owner permission           read + write
MSA-class client permission   read only
ordinary HLOS VMID            no read or write grant
```

The `0x80000000` read bit reaches the same client-permission slot that the exact
routine uses for MSA-owner self-access. No low/standard VMID bit survives the
conversion; comparative Qualcomm access-control definitions identify HLOS as
VMID 3 (`0x8`), which is absent.

`PROVED`: exact devcfg resolves `/ac/xpu:disable_xpu_ac` to uint32 `0`.
`SUPPORTED`: the normal boot applies the policy. A final hardware register
readback is still `UNKNOWN`, so static policy is not silently promoted to live
register proof.

`PROVED`: TZ's error-router table maps `DC_NOC_BROADCAST_MPU` to global status
bank 0 bit 29; BIMC_MPU0..3 map to bits 25..28. The exact handler can classify
configuration/client-port errors and report `APROTNS`, read/write, master/VMID,
and matched resource-group fields.

`PROVED`: neither embedded static policy array contains BIMC_MPU0..3. This
means only that this particular static-list path does not initialize them.
Their final state remains `UNKNOWN`; Experiment 010 resolves their initializer.

## Experiment 010 dynamic initializer and control boundary

`PROVED`: exact TZ separately registers SMC `0x02000c16` at handler
`0x1c0a6de4`. Its assignment core calls `0x1c0ab624`, whose internal lock path
tail-calls `0x1c0a9d5c`, topology fanout `0x1c0a9e14`, and reconfigure routine
`0x1c0a9f44`.

`PROVED`: the topology fanout emits exact registered IDs `0x2e`, `0x2f`,
`0x3f`, and `0x40` (`BIMC_MPU0..3`), plus `0x3a`
(`LLCC_BROADCAST_MPU`) on some branches. This is the positive dynamic
initializer evidence missing from Experiment 009. IDs `0x51..0x54` occur in
one code branch but are absent from the exact primary registry; their meaning
and runtime execution are `UNKNOWN`.

`PROVED`: this TZ chain is not the exact QHEE HLOS `hyp_assign` implementation.
QHEE independently registers the same SMC ID and uses a local
ownership/stage-2/SMMU access-control mapper. `SUPPORTED`: normal HLOS requests
are intercepted there before the separate TZ fallback.

`PROVED`: exact TZ exposes XPU toggle SMC `0x02000c23`, but the disable branch
requires membership in an exact allowed-base array whose count at
`0x1c122a90` is zero. The enable branch resolves a supplied base to an existing
registry ID and invokes HAL restore. It does not supply arbitrary MMIO data or
an HLOS XPU-disable primitive.

`PROVED`: exact QHEE contains no literal `0x02000c23`, and exact TZ contains no
literal `0x02000c24` (`TZ_MPU_LOCK_HLOS_REGION`). This is bounded literal/table
evidence, not a claim that constructed or semantically different SMCs are
impossible.

`PROVED`: both embedded static-policy branches cover all eight known
remapper/BIMC configuration addresses through the same two records:

| Resource | Region | Range | Access words | Result |
|---|---:|---|---|---|
| `MEMNOC_MS_MPU` | 0 | `0x00000000–0x10000000` | `0x80000000/0x80000000` | TZ owner, no HLOS VMID |
| `CNOC_SNOC_MS_MPU` | 5 | `0x09000000–0x09800000` | `0xf0000000/0xf0000000` | TZ owner, no HLOS VMID |

Instance 0 additionally has `DC_NOC_BROADCAST_MPU` region 11 over its remapper
and region 13 over `BIMC_MPU0`. The broad two-policy result, unlike region 11,
is invariant across all four instances.

`SUPPORTED`: these policies are the direct reason EL1 cannot use the known
configuration apertures. Final hardware register readback is `UNKNOWN`.

`SUPPORTED`: exact static config starts from `0x0001c800` without requesting
the comparative secure-config-write-disable field, consistent with secure-
world dynamic updates. `PROVED`: exact XPU3 init only null-checks its second
configuration argument, and restore/reset preserve control mask `0x2` while
changing enable state. `UNKNOWN`: the final boot/runtime value of that
preserved hardware bit.

`PROVED`: The same TrustZone ELF also contains `/dev/icbcfg/boot` DAL identity
and the exact four qhs_llcc remapper bases used by XBL. `SUPPORTED`: secure
firmware has configuration knowledge for that region-remap block. `UNKNOWN`:
whether secure-world invokes it, locks it, or merely links an unused platform
record.

`PROVED`: exact TZ contains no byte-identical occurrence of the five pinned XBL
functions (DDR config producer/merge, remapper selector, layout-1 commit and
ICB set-region), including no match for their first 64 bytes. This narrows a
direct shared-code hypothesis but does not refute a semantic equivalent.

`SUPPORTED`: retained successful boots registering LLCC PMU, LLCC-to-DDR BWMON
and latency monitors disfavor a whole LLCC/DDR fabric power-off explanation.
Combined with the exact tested-page policy, XPU/fabric denial is the leading
watchdog explanation. The `+0x8080` sub-aperture may still have a separate
clock/power condition, so that alternative is not `REFUTED`.

`UNKNOWN`: the reset collector entered `print_xpu_info` but immediately stated
that the TZ log was encrypted or not parsed. There is no decoded XPU violation,
but that absence cannot be used as evidence against an XPU fault.

`PROVED`: `DC_NOC_BROADCAST_MPU` static policy covers the tested configuration
PA with no HLOS grant. `SUPPORTED`: its enforcement prevented the EL1 load
from completing. Its exact fabric placement and response mechanism remain
`UNKNOWN`.
`UNKNOWN`: Whether it checks the system address before final DRAM decode, a
decoded destination, or both. `UNKNOWN`: Which state is controlled by EL3 versus
QHEE/EL2 is now partly resolved — QHEE owns the independent stage-2/SMMU
assignment layer and TZ owns the dynamic BIMC policy path — but their ordering
relative to final DRAM decode remains `UNKNOWN`. Final lock/reset state also
remains `UNKNOWN`.

No protected-memory read or write has been attempted. A future boundary test is
ineligible until a deterministic normal-RAM physical-to-DRAM alias and ordering
evidence both exist.
