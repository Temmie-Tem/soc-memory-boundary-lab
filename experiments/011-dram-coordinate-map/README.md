# Experiment 011 — Exact XBL DRAM Coordinate Map

## Question

Does the exact A90 XBL expose a physical-address-to-DRAM-coordinate formula,
and does selected DCB section 16 identify the controller state that could make
that formula mutable?

This phase is host-only. It performs no device, SMC, MMIO, controller, EL2,
EL3, partition, or protected-memory access.

## Exact inputs

- XBL SHA-256
  `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`
- XBL config SHA-256
  `0e9dfac1ddd0f9acc2cc899213e621490308f0cadf329814048edb7712e2484c`
- retained last-kmsg SHA-256
  `8701d073e86728790c33f05dce21891ca3454f5b778d92285ce3b5bc33216b93`
- selected DCB `/6003_0200_1_dcb.bin`, SHA-256 `34caf815…`
- selected section 16: 560 bytes, SHA-256 `cdacfa45…`

Public structural evidence is in
`evidence/manifests/011-dram-coordinate-inventory-20260825-01.manifest.json`.
The path-bearing derived record remains mode `0600` under ignored
`evidence/private/`.

## Exact Quest DDR coordinate reporter

`PROVED`: exact XBL function `0x149212c0..0x149213ec` is called by the real
failure recorder at `0x1492234c..0x14922428`. Its format string names:

```text
rank, row, bank, ch, column
```

The reporter first derives a rank boundary from a runtime DDR-size value. The
size accumulator at `0x14921c74..0x14921d0c` sums memory-range size fields
shifted by ten and prints the result as DDR size in GiB. For the retained
3072+3072 MiB topology, the result is 6 and the reporter computes:

```text
rank1_base = 0x80000000 + (6 << 29)
           = 0x140000000
```

`PROVED`: this is exactly remapper row 7's rank-1 destination. The current
rank ranges are therefore:

```text
rank 0: 0x080000000–0x13fffffff
rank 1: 0x140000000–0x1ffffffff
```

For `offset = PA - selected_rank_base`, the pinned XBL instructions compute:

```text
row       = offset[31:16]
bank      = offset[15:13]
channel   = offset[10:9]
column    = offset[12:11] || offset[8:1]
byte_x16  = offset[0]
```

`PROVED`: these fields partition all 32 rank-relative address bits without a
gap or overlap. The inverse reconstruction reproduces the original PA, and a
65,536-address negative-control domain has no coordinate collision.

`REFUTED`: this bounded diagnostic formula itself contains an XOR/hash or can
produce `PA_A != PA_B` for one coordinate. It is a bijection.

`SUPPORTED`, not `PROVED`: the formula is the intended hardware coordinate
model. The support is strong because XBL uses it in its actual Quest DDR
failure path. `UNKNOWN`: silicon may apply an additional hash/swizzle that the
diagnostic deliberately omits.

## Selected DCB section 16

`PROVED`: the section header is four little-endian `uint16_t` values:

```text
0x0008  0x0230  0x01b8  0x08e8
```

Starting at offset `0x8`, both regions parse exactly to their declared ends as:

```c
uint8_t base_count;
uint8_t offset_count;
uint16_t base_tokens[base_count];
uint16_t offset_tokens[offset_count];
```

Set 0 has 22 records including two zero padding records. Set 1 has eight
records including one zero padding record.

`PROVED`: token families numerically equal `physical_base >> 12` for exact
`qhm_shrm` topology targets:

| Candidate | Exact topology bases | Section-16 token records |
|---|---|---|
| per-channel MCCC | `0x09250000`, `0x092d0000`, `0x09350000`, `0x093d0000` | set 0 token `0x46`; set 1 tokens `0x44..0x47` |
| per-channel MC | `0x09260000`, `0x092e0000`, `0x09360000`, `0x093e0000` plus subpages | ten records across both sets |
| MCCC master | `0x090b0000` | set 0 `0xa5`; set 1 `0x0,0xa0,0xa2..0xa8` |
| DDRSS regs | `0x090c0000` | set 0 `0x16,0x17,0x2c` |
| SHRM CSR | `0x09050000` | both sets `0x45..0x4b` |

`SUPPORTED`: base tokens are 4-KiB page numbers and section 16 is an SHRM
register-access/configuration inventory. This follows from the independent
numeric matches and XBL's proved copy to `qhs_shrm_mem + 0x5100`.

`UNKNOWN`: offset-token scaling, flag bits, read/write opcode, the meaning of
the two sets, execution order, runtime value, lock state, and whether any token
controls final address decode. Register byte addresses are not guessed by
multiplying tokens by four.

## `invert_row` boundary

`PROVED`: `invert_row: %d` occurs once in the exact embedded DDR code. Two
pinned users print and forward a local flag to common DDR routines. Neither is
the Quest coordinate reporter.

`REFUTED`: the string alone proves a mutable PA-to-row transform. It remains
possible that the flag affects a training pattern or controller behavior, but
that semantic link is not established.

## Protection ordering

Experiment 011 does not locate QHEE or TZ enforcement relative to this
coordinate model:

```text
system PA
  -> QHEE stage-2/SMMU ownership: exact ordering UNKNOWN
  -> TZ/BIMC MPU data-path decision: exact ordering UNKNOWN
  -> diagnostic/final coordinate decode: relation UNKNOWN
```

Broad secure policy over the controller configuration apertures is already
proved by Experiments 009/010. That does not prove a post-transform data-path
check.

## Result

```text
CLASS A/B CANDIDATE — NO ALIAS PRIMITIVE OBSERVED
```

The useful search space is now smaller:

1. the known XBL coordinate model itself is non-aliasing;
2. a Qualcomm analogue would require hidden hardware state or one of the still
   semantically unresolved SHRM/MCCC/MC tokens;
3. no Normal World observation, mutation, alias, or boundary bypass has been
   obtained.

The cheapest next experiment is still host-only: recover the SHRM section-16
interpreter or find another exact consumer that establishes token scaling,
operation direction, and execution set. Repeating the blocked EL1 controller
load has no new discriminating value.
