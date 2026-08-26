# Experiment 030 — Does the bank relation extend below the page?

## Question

Experiment 023R proved a rank-3 relation over PA13..PA24. Experiment 014
reported PA9 and PA10 as "two further independent selection components
consistent with channel selection", ranked `SUPPORTED`, which would make the
full selector rank 5. Since 014's window was PA0..PA23 and 023R's is
PA13..PA24, the two numbers are not in conflict on their face — but whether
they describe one selector or two windows depends on what PA9 and PA10 do.

## Result

They do something, and it is not what the evidence for them assumed.

014's test was that adding PA9 or PA10 to the kernel witness `0x16000` made the
result leave the conflict class. That observation reproduces exactly. The
inference from it does not, because a difference can leave the conflict class
in two opposite directions and only one of them means the bit selects
anything:

- **downward**, to the non-conflict level, is what a selection component does:
  the two addresses stop sharing a bank, so nothing interferes;
- **upward**, past the conflict level, is a different event entirely.

PA9 and PA10 leave upward. The control that separates the two cases is to add
the bit to a difference that is already *non*-conflicting.

## Measurement

Same apparatus as Experiment 023R: `qsecom` carveout at physical `0xa6000000`,
32 MiB write-combine ION allocation, CPU7 at 2,841,600 kHz,
`cpu-llcc-ddr-bw` `performance` at 7,980, 1001 repetitions, 64 pairs,
alternating order, `dsb ld`, per-reopen milli-ticks. The probe's sub-page
restriction was lifted: offsets are page aligned and the allocation base is
page aligned, so a pair's low bits differ by exactly the difference's low bits
with no carry.

Three reference levels, measured in the same run:

| Level | Difference | Median delta |
|---|---|---:|
| Same row, same everything | `0x800` | **19** |
| Different row, different bank (non-conflict) | `0x2000` | **168** |
| Different row, same bank (conflict) | `0x16000` | **538** |

Each low bit was then measured three ways: alone, added to the conflicting
witness, and added to the non-conflicting witness.

| Bit | Alone | With `0x16000` | With `0x2000` | Verdict |
|---:|---:|---:|---:|---|
| PA0–PA3 | 16–22 | 534–542 | 164–170 | INERT |
| PA4 | 22 | 367 | −4 | MODULATING |
| PA5 | −19 | 271 | −68 | MODULATING |
| PA6–PA8 | 20–23 | 538–543 | 158–162 | INERT |
| **PA9** | **717** | **702** | **702** | **SATURATING** |
| **PA10** | **453** | **461** | **463** | **SATURATING** |
| PA11, PA12 | 21, 11 | 537, 538 | 154, 160 | INERT |

**No low bit behaves as a selection component.** Nine are inert, confirming
014's list of bits that preserved the class. PA4 and PA5 move the levels
unevenly, which is why 014 excluded them as intermediate. PA9 and PA10 drive
the conflicting and non-conflicting witnesses to *the same* value — once either
is set, the bank relation is no longer visible through the metric at all.

The reading is robust: it holds across both offset modes, at 32 and 64 pairs,
and for three separate kernel witnesses (`0x16000`, `0x2c000`, `0x102000`),
which give `+PA9` medians of 759, 758 and 760 against their own conflict levels
of 541, 543 and 532.

## Why "channel selection" specifically is falsified

If PA9 selected the channel, a conflicting pair with PA9 added would land in
different channels, nothing would interfere, and the delta would fall to the
non-conflict level near 168. It rises to about 760 — well above the conflict
level of 538. The channel hypothesis makes a directional prediction and the
measurement contradicts it.

That is not a claim that the bits are inert. A penalty *larger* than a bank
conflict is what a rank or bank-group change costs, and the boot log's
`LPDDR4Y  Enabled = 2` is consistent with a second rank. This experiment does
not assign a DRAM coordinate to either bit; it establishes that the reopen
delta saturates on them and therefore cannot.

## Boot-chain geometry recovered along the way

From the retained boot log, read-only: `LPDDR4Y  Enabled = 2`,
`DDR vendor:Samsung@0x860051c0`, `DDR Frequency, 1353 MHz`,
`Total DDR Size: 0x000000017CC00000`, `Memory Base Address: 0x80000000`. SMEM
is at physical `0x86000000`, 2 MiB, `no-map`, so the vendor string's address
sits inside it. The structure itself was not read: `CONFIG_DEVMEM is not set`
in this kernel, so there is no `/dev/mem` path to it, and no kernel-mediated
interface exposing it was found.

## Claims and ranking

`PROVED`: the three reference levels above; that PA0–PA3, PA6–PA8, PA11 and
PA12 are inert against both a conflicting and a non-conflicting witness; that
PA9 and PA10 drive both witnesses to the same value, independent of which
witness is used, across three witnesses, two offset modes and two pair counts;
and that no bit below PA13 lowers a conflicting difference to the non-conflict
level.

`REFUTED`: that PA9 and PA10 are channel-selection bits, since a channel
difference removes interference and would lower the delta rather than raise it
above the conflict level. Also refuted is the inference from "left the conflict
class" to "independent selection component", which does not distinguish
departure upward from departure downward and which the non-conflicting-witness
control settles.

`UNKNOWN`: what PA9 and PA10 do select, if anything — rank and bank group are
consistent with a penalty above a bank conflict but are not established here;
PA4 and PA5, whose uneven movement this experiment does not resolve either;
and the contents of the SMEM DDR structure, which this kernel offers no way to
read.

Consequence for Experiment 023R: its rank-3 result stands and is not extended
downward. The selector's rank over PA13..PA24 is 3; a rank-5 selector over a
wider window is not established by PA9 and PA10, so the two remaining
dimensions, if they exist, are not located.

Classification is unchanged: `CLASS C (TRANSFORM ONLY)` /
`NO_BOUNDARY_BYPASS_OBSERVED`. Experiments 015 and 016 remain `NOT ELIGIBLE`.

## Reproduction and provenance

```sh
# on device, read-only:
#   ./a90_region_probe_r qsecom 32 1001 64 7 spread <differences>
python3 tools/a90_low_bit_selector_analysis.py \
  --raw <private raw directory> \
  --output evidence/manifests/030-low-bit-selector-20260826-01.manifest.json
python3 -m unittest -v tests.test_a90_low_bit_selector_analysis
```

- Focused result: 14 tests pass. Full repository discovery: 570 tests pass.
- Raw phase output is retained privately under
  `evidence/private/030-low-bit-selector-20260826-01/`; the public manifest
  carries its SHA-256 digests only.
- Date: 2026-08-26 KST. Mode: `DEVICE_READ_ONLY`; allocate, map, read, free.
  No governor, register, partition or boot-image write; the device stayed in
  recovery.
