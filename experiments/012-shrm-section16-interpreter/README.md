# Experiment 012 — SHRM Section-16 Interpreter

## Question

Does the exact SM8150 SHRM firmware treat DCB section 16 as a mutable
controller-programming stream, or as a read-only register snapshot list?

This phase is host-only. It does not execute the Xtensa image and performs no
device, SMC, MMIO, partition, EL2, EL3, or protected-memory access.

## Exact inputs

- XBL: `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`
- XBL config: `0e9dfac1ddd0f9acc2cc899213e621490308f0cadf329814048edb7712e2484c`
- embedded SHRM instruction blob at XBL VA `0x148bbe98`, 23,776 bytes:
  `421824b417ab28e6c0d1802c05d7ce5422e93b116973ce7f039321fb5a01a1fd`
- selected DCB `/6003_0200_1_dcb.bin`, section 16:
  `cdacfa45183be71c13884ed60dd883a7f94ba5fd4fb9cc92899fac4eb0298dc0`

The public structural output is
`evidence/manifests/012-shrm-section16-inventory-20260825-01.manifest.json`.
The path-bearing record is ignored and mode `0600` under `evidence/private/`.

## Exact consumer recovered

`PROVED`: the embedded SHRM code is installed by XBL at physical
`0x09068000`, with Xtensa code base `0x28000`. The SHRM data image is installed
at `0x09062100`; the section-16 workspace therefore appears to the Xtensa code
at virtual `0x25100`, corresponding exactly to physical `0x09065100`.

The common helper at Xtensa VA `0x2d8dc..0x2d959` is pinned by SHA-256
`01fc5d83049d3fff7db6aa10a316dfbd07dfbd87093bb0b5a5d722aa3dfe211b`. Its
bounded instruction sequence does the following for every record:

```text
base_page = u16(base_tokens[i])
offset    = u16(offset_tokens[j])
register  = (base_page << 12) + (offset << 2)
```

The `addx4` use is decisive: offset tokens are scaled by four bytes, not by
four kilobytes. The helper stages one 32-bit word per computed register.

`direction == 0` reads the computed register into the destination snapshot
buffer. `direction != 0` is the reverse copy direction in the helper model.

## Two exact callsites

The pinned callsite at `0x288a9` reads list 0 (`header[0] == 0x8`) and stores
results at workspace offset `header[1] == 0x230`, with capacity
`header[3] - header[1] == 0x6b8` bytes.

The pinned callsite at `0x28e15` reads list 1 (`header[2] == 0x1b8`) and stores
results at workspace offset `header[3] == 0x8e8`, with capacity
`0xf00 - header[3] == 0x618` bytes.

Both exact callsites set the helper's direction argument to zero immediately
before the call. The selected section therefore produces:

| list | records before zero terminator | computed register reads | output capacity |
|---|---:|---:|---:|
| 0 | 20 | 430 | 430 words |
| 1 | 7 | 64 | 390 words |

The first list exactly fills its 0x6b8-byte output buffer. The second list is
well within its 0x618-byte buffer.

## Security interpretation

`PROVED`, bounded to the exact blob and its two direct consumers: section 16
is consumed as a read-only controller-register snapshot inventory. It is not a
Normal-World or SHRM write command stream in these call paths.

`SUPPORTED`: the lists cover exact SHRM-visible MCCC, MC, MCCC-master, DDRSS,
SHRM-CSR and LLCC-related pages. This makes returned words useful evidence for
final-decode research, but no runtime word is present in the static capture.

`REFUTED`: treating an offset token as a 4-KiB page offset; treating section 16
itself as proof of a write primitive; or treating the two observed consumers as
controller-transform mutation.

`UNKNOWN`: the values returned by the reads, whether any read register controls
final PA-to-DRAM decode, whether an indirect path invokes the helper with the
reverse direction, and protection ordering relative to the read targets.

## Result

```text
CLASS A/B CANDIDATE — SECTION-16 READ-ONLY SNAPSHOT
NO TRANSFORM-WRITE OR ALIAS PRIMITIVE OBSERVED
```

This closes the cheapest static question about section-16 direction and
scaling. A live read of the SHRM snapshot buffer or a separately authorized
read-only route to the listed controller words would be a new experiment; it
would not justify writing any listed address.
