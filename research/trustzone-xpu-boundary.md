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

`UNKNOWN`: XPU/MPU location along the SM8150 memory path.
`UNKNOWN`: Whether it checks the system address before final DRAM decode, a
decoded destination, or both. `UNKNOWN`: Which state is controlled by EL3 versus
QHEE/EL2. `UNKNOWN`: The lock and reset behavior of final mapping state.

No protected-memory read or write has been attempted. A future boundary test is
ineligible until a deterministic normal-RAM physical-to-DRAM alias and ordering
evidence both exist.
