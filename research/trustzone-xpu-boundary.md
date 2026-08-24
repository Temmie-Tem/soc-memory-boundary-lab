# TrustZone / XPU Boundary

`PROVED`: Exact target kernel passes physical range descriptors and VMID/
permission lists through SCM memory-protection service calls. Secure-buffer
locking uses SCM MP services as well.

`PROVED`: Live DT advertises `qseecom_region` at
`0xa6000000–0xa83fffff`; exact live evidence takes precedence over the generic
base-DTS value.

`SUPPORTED`: A secure-world component configures ownership/firewall state in
response to SCM MP calls. This follows from the API purpose and call boundary,
but the exact hardware block and register writes remain unobserved.

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
The `+0x8080` configuration sub-aperture may still have separate clock, power or
security ownership.

`UNKNOWN`: the reset collector entered `print_xpu_info` but immediately stated
that the TZ log was encrypted or not parsed. There is no decoded XPU violation,
but that absence cannot be used as evidence against an XPU fault.

`UNKNOWN`: XPU/MPU location along the SM8150 memory path.
`UNKNOWN`: Whether it checks the system address before final DRAM decode, a
decoded destination, or both. `UNKNOWN`: Which state is controlled by EL3 versus
QHEE/EL2. `UNKNOWN`: The lock and reset behavior of final mapping state.

No protected-memory read or write has been attempted. A future boundary test is
ineligible until a deterministic normal-RAM physical-to-DRAM alias and ordering
evidence both exist.
