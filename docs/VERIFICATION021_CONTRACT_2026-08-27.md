# Verification 021 contract - carveout exhaustion and provenance boundary

Verification 021 is a bounded allocation-extent experiment for the PA28
normal-RAM candidate. It holds a full 320 MiB allocation from the named
`camera_preview` heap, probes the same heap at 16 MiB, 4 MiB, 1 MiB, 64 KiB and
4 KiB while the hold is live, and repeats those probes before and after the
hold. The extent verdict is admissible only when all five `control_before` and
all five `control_after` probes succeed. Zero `under_hold` successes then
produces `HOLD_CONSUMES_POOL`; any control failure produces
`INSTRUMENT_FAILED`; one or more residual successes produces
`HOLD_LEAVES_ROOM`.

The retained producer receipt is private:

```text
basename: carveout-exhaustion.jsonl
size_bytes: 2368
sha256: cb16a3c1ba64f6050a52edd2e2fefe9a405d96fde86928cfe344b74764d28694
schema: a90_heap_exhaustion_v1
```

The host reducer reads that receipt only through an `O_NOFOLLOW` descriptor,
requires a regular file, checks the descriptor identity and size before and
after the read, hashes the exact bytes, and exposes the resulting metadata in
the v2 public manifest. The production CLI accepts only the canonical basename,
size and SHA pin above; an arbitrary same-schema JSONL cannot silently replace
the retained receipt. A retained metadata pin must be checked with
`require_metadata`; a size or content mutation is a failure, including a
same-size SHA mutation. The analyzer does not execute the C probe or contact a
device.

## Provenance requirements

The 021 JSONL producer emitted only context/probe/hold/summary records. It did
not retain a same-run target preflight, bridge/device binding, command argv,
timestamp, process-exit or final-health receipt. The manifest must therefore
set all of these to `UNKNOWN_UNRETAINED` and must not inherit identity from the
current host, bridge, or the separate 020M collection.

The retained source is pinned as:

```text
basename: a90_heap_exhaustion_probe.c
size_bytes: 6491
sha256: 02dc73f8731bcdfb6e82d8fb29df2ca73e57a51003435506a29cdd10798126f8
status: RETAINED_SOURCE
```

The reported executed binary is explicitly incomplete provenance:

```text
basename: a90_heap_exhaustion_probe
size_bytes: null
sha256: 9361018ea2e9f9169ed8e204c259a243647700448aa31f5515f2e599a4815303
status: NOT_RETAINED
```

`size_bytes: null` means the binary size was not retained; it is not a claim
that the binary was zero bytes. No binary is to be recreated for this
host-only integration repair.

## Safety and rollback contract

The future device probe may use only `ION_IOC_HEAP_QUERY` and allocation/close
on the explicitly named non-secure `camera_preview` heap. It must not map, read
or write allocated memory and must not access registers, MMIO, SMC, SCM,
EL2/EL3, protected memory, partitions or firmware. The hold must be closed
before the trailing control; process exit must close outstanding descriptors.
The operator must retain cleanup and final-health evidence in the same receipt.
No rollback write or protected-memory recovery path is authorized by this
contract.

The 020M DT snapshot may be used as an independently pinned dependency for the
advertised heap/phandle/reg semantics. It cannot attest that the 021 allocation
ran on the same target, bridge or uptime. Until a future receipt includes that
same-run preflight, the allocation result is `SUPPORTED_WITHIN_RETAINED_RECEIPT`
only; exact-device `PROVED` status is not available.

The host reducer does use one canonical dependency before emitting a conditional
span: `verification-020m-pa28-dt-20260827-03.manifest.json`, 8,246 bytes,
SHA-256
`69b087bd5a6aa279fff9c943405b46491381f3461c5ea1ac57f4d2f287d8ad9a`.
It validates that manifest's schema/experiment identity, exact target/version,
strict `/dev/ttyACM0` bridge fields, heap-30 `0x67a` memory-region phandle, and
`camera_mem_region` base `0xc2000000`, size `0x14000000`, end
`0xd6000000`, including the explicit optional-property results. A mutated or
replaced dependency fails closed; direct `analyse()` calls cannot derive the
span from a hardcoded DT constant.

## Completion gate

Completion requires the v2 analyzer output, the exact private-receipt
basename/size/SHA pin, retained-source metadata, explicit unretained-binary
status, negative mutation tests, and a review that preserves the
`CLASS C (TRANSFORM ONLY)` / `NOT_ELIGIBLE` boundary. This contract itself
contains no device action and no new raw receipt or executable artifact.
