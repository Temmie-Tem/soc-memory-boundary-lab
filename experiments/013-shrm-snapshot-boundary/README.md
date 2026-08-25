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

`UNKNOWN`: final runtime XPU register state and a decoded XPU syndrome.

## Fixed live pair prepared

The host-built pair targets only SHRM set-0 word 207 at physical
`0x0906566c`. Experiment 012 binds that destination to source MCCC register
`0x09250118`.

- control `d1d4956b…`: fixed map/unmap and `0xc071`, no bus load;
- read `7ee6a41f…`: the same path with exactly one 32-bit load.

Neither candidate accepts a runtime address or call target, and neither
contains a memory/MMIO store.

## Live result

`PROVED`: the no-load control returned `0xc071` with healthy post-state. After
verified V2321 rollback, the paired read candidate was flashed with full-prefix
readback and invoked once. It returned no value and disconnected USB. The
retained 2,097,136-byte log records:

```text
Watchdog bark! Now = 40.280410
Watchdog last pet at 29.280131
cpu alive mask from last pet 07
UploadCause[Non Secure Watchdog Bark]
TZBSP_ERR_FATAL_NON_SECURE_WDT
```

No `A90R` result is present. The control/read bodies differ at exactly byte
offsets `76..79`: one control `MOVZ` versus one read `LDR W` instruction.

`SUPPORTED`: the single fixed load, rather than mapping alone, caused the
system-wide stall. The exact no-HLOS policies make XPU/fabric denial the best
current explanation, but no decoded runtime XPU syndrome exists.

The read was not retried. V2321 was restored with full-prefix SHA-256
`ca978551…`; final native version is `0.9.285`, selftest is
`pass=11 warn=1 fail=0`, and battery was 100%.

```text
CLASS A/B CANDIDATE — FIXED DIRECT EL1 SHRM READ BLOCKED
NO ALIAS OR SECURITY-BOUNDARY BYPASS OBSERVED
```

The public result is
`evidence/manifests/013-shrm-snapshot-boundary-20260825-01.manifest.json`.
The path-bearing record remains ignored and mode `0600` under
`evidence/private/`.
