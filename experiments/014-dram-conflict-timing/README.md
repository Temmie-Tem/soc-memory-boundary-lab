# Experiment 014 — Live DRAM Conflict Timing

## Question

Does the real SM-A908N/SM8150 PA-to-bank/channel selection relation equal the
no-XOR diagnostic formula recovered in Experiment 011, or does silicon apply a
finer GF(2) transform that the diagnostic omits?

## Result

`PROVED`, for rank-relative PA bits `0..23` in the observed rank-0 window: the
real bank-selection equivalence relation contains XOR terms from row bits
`16..23`. It is not the diagnostic `bank = PA[15:13]` relation.

`SUPPORTED`: PA9 and PA10 are two further independent selection components
consistent with channel selection. The experiment does not assign physical
channel labels to them.

`REFUTED`: Experiment 011's direct bit partition is the complete silicon
bank-selection mapping. It remains a proved XBL diagnostic formula, but not a
complete model of the observed hardware relation.

`UNKNOWN`: the responsible MC/MCCC/remapper register, its encoding, writer,
post-boot writability and lock owner; contributions from PA bits `24..31`;
protection ordering; and any physical-to-DRAM alias or protected-memory effect.

Current classification:

```text
NORMAL_RAM_HIDDEN_BANK_HASH_PROVED_NO_ALIAS_OR_BYPASS
NO_BOUNDARY_BYPASS_OBSERVED
```

## Exact target and backing

- Target: `SM-A908N`, `SM8150`, bootloader `A908NKSU5EWA3`.
- Runtime: V2321 `0.9.285`, build `v2321-usb-clean-identity-rodata`.
- Kernel: `Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64`.
- Boot state: `debug_level=LOW`, `force_upload=0`, `dump_sink=0`.
- Probe source SHA-256:
  `f5788486f7410984bca0c7a31241c10d9a7078f6d1abcb753f6ccbc2ce62fe75`.
- Static AArch64 probe SHA-256:
  `552432c1270affcdb9433f3a8aa7a7e0a28d3011abfc1f4ec57aa1f5715910a9`.
- CPU7 was pinned at 2,841,600 kHz; the
  `soc:qcom,cpu-llcc-ddr-bw` governor was `performance` at its reported maximum
  `7980`; `CNTFRQ_EL0 = 19.2 MHz`.

The final measurements used only the non-secure ION `user_contig` heap with
flags zero. Exact kernel source maps that allocation write-combine, and the
heap produced one SG entry. A unique `/proc/kpageflags` buddy transition bound
the 4096 mapped pages to the stable contiguous PA interval
`0xf0400000..0xf13fffff`; a second scan while the dma-buf remained pinned found
zero changed or lost pages. Secure ION heaps were enumerated but never selected.

Source provenance is upstream A90 kernel commit
`510d909eff0fe10e48f3bfff573bc17f59f0656a`: `ion.c:493-505` applies
`pgprot_writecombine` when `ION_FLAG_CACHED` is absent, while
`ion_cma_heap.c:60-142` allocates contiguous CMA pages and constructs a
one-entry SG table. Those files have SHA-256 `55dae52a…` and `3687c1c7…` in
the retained exact source tree. The live heap query independently returned
`user_contig`, type 4, ID 26.

## Measurement

For each PA pair `(A,B)`, the probe compares two symmetric reopen sequences:

```text
relation: B -> A -> timed B    and    A -> B -> timed A
baseline: A -> A -> timed A    and    B -> B -> timed B
delta   : trimmed_mean(relation) - trimmed_mean(baseline)
```

Each retained difference used 64 physical pairs and normally 1001 repetitions
per pair. A 10% trimmed mean at 1/1000 counter-tick resolution reduced timer
quantisation without changing the raw tick samples.

Same-row control `D=0x800` stayed centred at zero. In the held-out set, the
kernel-class minimum p10 was 536 milli-ticks and the one-bank-bit negative
maximum p90 was 222 milli-ticks, leaving a 314 milli-tick non-overlap gap.

The earlier anonymous cached mapping plus `DC CIVAC` path is `REFUTED` as a
sufficient DRAM classifier on this target: its timing remained LLCC-confounded.
That negative result is retained rather than mixed with the write-combine ION
dataset.

## Recovered GF(2) relation

Using PA13, PA14 and PA15 as an arbitrary three-vector bank basis, the unique
kernel-class relation for each tested row bit was:

| Row bit | Equivalent bank-basis contribution |
|---:|---|
| 16 | `13 xor 14` |
| 17 | `14 xor 15` |
| 18 | `13 xor 14 xor 15` |
| 19 | `13 xor 15` |
| 20 | `13` |
| 21 | `14` |
| 22 | `15` |
| 23 | `13 xor 14` |

One equivalent basis for the observed bank-selection row space is therefore:

```text
b0 = PA13 xor PA16 xor PA18 xor PA19 xor PA20 xor PA23
b1 = PA14 xor PA16 xor PA17 xor PA18 xor PA21 xor PA23
b2 = PA15 xor PA17 xor PA18 xor PA19 xor PA22
```

These are row-space equations, not claimed hardware `BA0/BA1/BA2` labels. Any
invertible change of the three output basis vectors represents the same bank
equivalence relation.

## Independent controls

The four held-out kernel vectors were never used to fit the matrix:

```text
0x0003a000  0x0024a000  0x00c84000  0x0095c000
```

All four re-entered the narrow conflict class. Flipping one bank-basis bit in
each produced:

```text
0x00038000  0x00248000  0x00c86000  0x0095e000
```

All four left that class. Adding PA9 or PA10 to the known kernel witness
`0x00016000` also left the class. Adding low bits `0..3`, `6..8`, `11` or `12`
preserved it. PA4/PA5 produced intermediate timing and are deliberately
excluded; their burst/byte-lane meaning is `UNKNOWN`.

## Why this is not an alias proof

A bank hash selects only part of a DRAM coordinate. Two PAs sharing its bank
output can still select different rows or columns, as these conflict witnesses
do. This experiment therefore proves a hidden bank-selection transform, not
that two distinct physical addresses reach the same complete DRAM cell.

No controller register, XPU, SMMU, SCM, EL2, EL3, partition, firmware or
protected-memory write occurred. The temporary ION node and remote probe were
removed; final exact-target health reports `selftest fail=0`.

## Static attribution check

The seven non-zero linear combinations of the three recovered bank rows were
searched in all nine exact Experiment-004 firmware images and the pinned real
64-KiB `SHRM_MEM.BIN`. The SHRM snapshot has no match at any alignment, and the
firmware images have no aligned little-endian 32-bit literal. Four raw
substring hits in `tz--sdd5.bin` occur
at file offsets congruent to one modulo four and are bytes inside monotonic
64-bit address tables such as `0x9d000000, 0x9d200000, 0x9d400000`.

`REFUTED`: those raw TrustZone substring hits directly encode the bank hash.
Encoded, split, computed or register-field representations remain `UNKNOWN`;
literal absence does not remove the ranked SHRM register candidates.

## Evidence

- Timing reduction:
  `evidence/manifests/014-dram-conflict-timing-20260825-01.manifest.json`
- Exact-firmware literal audit:
  `evidence/manifests/014-bank-hash-literal-audit-20260825-01.manifest.json`
- Final native health:
  `evidence/manifests/014-a90-final-health-20260825-01.manifest.json`
- Raw timing records, transport transcripts and firmware bytes:
  `evidence/private/` (mode-restricted and Git-ignored)

## Reproduce

```sh
python3 tools/a90_dram_timing_analysis.py \
  --output /tmp/014-dram-conflict-timing.manifest.json
python3 tools/a90_bank_hash_literal_audit.py \
  --output /tmp/014-bank-hash-literal-audit.manifest.json
python3 -m unittest \
  tests.test_dram_conflict_model \
  tests.test_a90_dram_timing_live \
  tests.test_a90_dram_timing_analysis \
  tests.test_a90_bank_hash_literal_audit -v
```
