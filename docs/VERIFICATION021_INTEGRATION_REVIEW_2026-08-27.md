# Verification 021 carveout-exhaustion integration review - 2026-08-27

## Review result

The residual-allocation design is a valid, bounded precondition discriminator
for the PA28 timing candidate. Holding the measured 320 MiB `camera_preview`
allocation and testing down to 4 KiB gives direct information about remaining
allocatable capacity; the 5/5 before and 5/5 after controls make an
`ENOMEM`-under-hold result interpretable. It is more informative about
allocation extent than the 020 ceiling ladder alone and remains safer than any
controller or protected-memory action.

The retained 021 receipt reduces to `HOLD_CONSUMES_POOL`: all five controls
before and after succeed, all five probes under the hold fail, and the full
320 MiB hold succeeds. This is a receipt-level result. It is
`SUPPORTED_WITHIN_RETAINED_RECEIPT`, not an exact-device `PROVED` claim,
because the receipt has no same-run target identity, bridge binding, command
argv, timestamp, process-exit or final-health evidence.

## Retained evidence and provenance

The canonical private receipt is:

```text
evidence/private/verification-021-carveout-exhaustion-20260827-01/carveout-exhaustion.jsonl
basename: carveout-exhaustion.jsonl
size_bytes: 2368
sha256: cb16a3c1ba64f6050a52edd2e2fefe9a405d96fde86928cfe344b74764d28694
```

The public v2 manifest is
`evidence/manifests/verification-021-carveout-exhaustion-20260827-01.manifest.json`.
Its `input` and `provenance.raw_receipt` entries pin that exact basename,
size and SHA. The reducer uses stable `O_NOFOLLOW` regular-file reads and
`require_metadata` rejects retained-pin size or SHA mutation. The production
CLI requires the same canonical pin, and `analyse()` rejects noncanonical input
metadata, so a same-schema replacement cannot be silently reduced.

The retained producer source is `a90_heap_exhaustion_probe.c`, 6,491 bytes,
SHA-256
`02dc73f8731bcdfb6e82d8fb29df2ca73e57a51003435506a29cdd10798126f8`.
The operator-reported binary is `a90_heap_exhaustion_probe`, SHA-256
`9361018ea2e9f9169ed8e204c259a243647700448aa31f5515f2e599a4815303`, but the
binary is not retained and its size was not recorded. The manifest therefore
uses `status: NOT_RETAINED` and `size_bytes: null`; it does not claim a
reproducible executed binary.

The raw receipt's provenance disposition is:

| Item | Disposition |
|---|---|
| target identity | `UNKNOWN_UNRETAINED` / not same-run attested |
| bridge/device binding | `UNKNOWN_UNRETAINED` / not same-run attested |
| executed argv | `UNKNOWN_UNRETAINED` / no command receipt |
| timestamp and final health | `UNKNOWN_UNRETAINED` / no lifecycle record |
| source | `RETAINED_SOURCE` |
| binary | `NOT_RETAINED` |

The separate 020M manifest contains its own target and bridge evidence, but it
cannot be substituted for a 021 same-run attestation. No current bridge or
operator report was inferred into the v2 manifest.

For the conditional DT interpretation, the reducer independently pins and
validates `verification-020m-pa28-dt-20260827-03.manifest.json` at 8,246 bytes,
SHA-256
`69b087bd5a6aa279fff9c943405b46491381f3461c5ea1ac57f4d2f287d8ad9a`.
It requires the exact `ion_heap30`/`camera_mem_region` phandle/reg chain,
target/version, and strict bridge fields before publishing the conditional
span. A dependency mutation fails closed; this validation still does not turn
the separate 020M run into a 021 same-run target attestation.

## Claim disposition and boundaries

`SUPPORTED_WITHIN_RETAINED_RECEIPT`: a 320 MiB hold on the selected heap left
zero allocatable probes at the tested 4 KiB floor, with both controls firing.

`SUPPORTED_CONDITIONAL`: if the 021 selected heap is the heap-30
`camera_mem_region` chain independently advertised by 020M, the result is
consistent with a 320 MiB pool extent and the conditional span
`[0xc2000000, 0xd6000000)`.

`UNKNOWN_UNRETAINED`: exact 021 target/bridge/uptime, physical page identity,
effective contiguity, complete DRAM coordinates, `f(PA28)`, extent variation,
transform mutability, cleanup/final health, and access-control behavior.

`NOT_AUTHORIZED`: no controller, MMIO, SMC, SCM, EL2/EL3, protected-memory,
partition, firmware, mapping, read or write action follows from this result.
`CLASS C (TRANSFORM ONLY)` and `NOT_ELIGIBLE` remain unchanged.

## Safety and rollback

The producer's bounded action surface is ION heap enumeration plus allocation
and immediate close on the named non-secure heap. The held descriptor is closed
before the after-control; normal process termination also closes descriptors.
No allocated memory is mapped, read or written. This integration review made
no device contact and created no binary or raw receipt. A future run must
retain same-run target/bridge preflight, command records, cleanup and final
health, and must stop before any controller or protected-memory action. There
is no rollback write authorized by this experiment.

## Artifact pins and host validation

| Artifact | Size | SHA-256 |
|---|---:|---|
| `tools/a90_carveout_exhaustion_analysis.py` | 17,947 | `cd37a03f1f9dcf14035228053e772c6c0b3a046d498d8dd258f07ef81a49cc21` |
| `tests/test_a90_carveout_exhaustion_analysis.py` | 14,002 | `c1d21d25fb69dd9b0450a3a0c6075371265aa317c824616b6d339272f88b978c` |
| `tools/a90_heap_exhaustion_probe.c` | 6,491 | `02dc73f8731bcdfb6e82d8fb29df2ca73e57a51003435506a29cdd10798126f8` |
| `docs/VERIFICATION021_CONTRACT_2026-08-27.md` | 4,480 | `2bd84335031a5eb3df8b17559ab8ce3322ef8053293824e9f4632e17d455e93c` |
| `experiments/verification-021-carveout-exhaustion/README.md` | 9,764 | `3a50a2b7f3ce78260072124d68e2f544021360f27799a753142335fe095eb016` |
| `evidence/manifests/verification-021-carveout-exhaustion-20260827-01.manifest.json` | 4,586 | `82471b458f87e1ed86596ab08c97bab743ee868edf98d7d272c1d131046c168b` |

The focused analyzer suite is 26/26 PASS. It covers control gates, missing
phases, failed hold, surviving-page negative, DT-size mismatch, symlink and
non-regular-file rejection, size mutation, same-size SHA mutation, exact input
metadata, manifest receipt pinning, and explicit no-inference provenance.
The analyzer also passes Python byte-compilation. No device command was run as
part of this integration repair.
