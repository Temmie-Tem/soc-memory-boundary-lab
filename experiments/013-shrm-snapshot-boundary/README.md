# Experiment 013 — SHRM Snapshot Boundary

## Question

Does either exact TrustZone XPU policy branch grant ordinary HLOS direct access
to the SHRM section-16 snapshot workspace at `0x09065100..0x09065fff`?

This phase is host-only. It parses the exact retained TrustZone image and
performs no device, SMC, MMIO, partition, EL2, EL3, or protected-memory access.

## Result

`PROVED`: both embedded policy branches place the complete 0xf00-byte workspace
inside the same three enabled, TZ-owned regions:

| XPU | Region | HLOS read | HLOS write |
|---|---|---:|---:|
| `DC_NOC_NON_BROADCAST_MPU` | `0x09060000..0x0906ffff` | no | no |
| `MEMNOC_MS_MPU` | `0x00000000..0x0fffffff` | no | no |
| `CNOC_SNOC_MS_MPU` | `0x09000000..0x097fffff` | no | no |

The narrow SHRM region has `read_vmid=0x40000000` and
`write_vmid=0x00000000`. Exact permission conversion identifies that bit as an
MSA-class read-only grant, not the comparative HLOS VMID.

`REFUTED`: the snapshot workspace is statically unprotected or explicitly
granted to ordinary HLOS in either embedded policy branch.

`SUPPORTED`: a direct EL1 read is expected to be denied by active XPU policy or
its downstream fabric response.

`UNKNOWN`: final runtime XPU register state and whether one fixed EL1 read
returns a value, faults locally, stalls, or causes a watchdog reset.

## Fixed live pair prepared

The host-built pair targets only SHRM set-0 word 207 at physical
`0x0906566c`. Experiment 012 binds that destination to source MCCC register
`0x09250118`.

- control `d1d4956b…`: fixed map/unmap and `0xc071`, no bus load;
- read `7ee6a41f…`: the same path with exactly one 32-bit load.

Neither candidate accepts a runtime address or call target, and neither
contains a memory/MMIO store. Current state is `HOST_READY_CONTROL_ONLY`; the
control must run cleanly and V2321 recovery must remain verified before the
read candidate can become eligible.

```text
CLASS A/B CANDIDATE — SHRM SNAPSHOT HAS NO STATIC HLOS GRANT
NO ALIAS OR SECURITY-BOUNDARY BYPASS OBSERVED
```

The public result is
`evidence/manifests/013-shrm-snapshot-boundary-20260825-01.manifest.json`.
The path-bearing record remains ignored and mode `0600` under
`evidence/private/`.
