# Experiment 028 — Does the pinned bank relation appear in firmware or live registers?

## Why this is not a repeat of the earlier audit

`tools/a90_bank_hash_literal_audit.py` already searched the exact firmware for
Experiment 014's bank basis. That audit had two defects, and Experiment 023R
supplies what is needed to repair both.

**Its target was wrong.** It searched the row space of the Experiment 014
basis, which omitted PA24. 023R resolved PA24's contribution as `0b110` and
pinned the kernel uniquely. Only three of the seven covectors it searched are
in the real row space:

| | Value |
|---|---|
| Searched, and in the relation | `0x0074e000`, `0x009d2000`, `0x00e9c000` |
| Searched, but the relation never had it | `0x003a6000`, `0x004e8000`, `0x00a74000`, `0x00d3a000` |
| In the relation, never searched | `0x013a6000`, `0x014e8000`, `0x01a74000`, `0x01d3a000` |

Four of its seven targets were values the relation does not contain, and four
real ones were never looked for. Its negative was therefore partly vacuous.

**Its negative had no scale.** A mask over PA13..PA24 with six to eight set
bits occurs in megabytes of firmware by chance. Without knowing that rate,
neither "no hit" nor "two hits" means anything.

## Why the row space is the whole target

A conflict measurement determines `ker f`, not `f`; 168 bases in `GL(3,2)`
describe the same kernel and predict identical conflicts. The kernel's
annihilator — the row space — is the same for every one of them. Its seven
nonzero covectors are therefore the complete target set, and searching 168
bases separately would be redundant. A test enumerates all 168 and asserts the
row space is invariant.

With PA24 in `b1` and `b2`, the rows are `0x009d2000`, `0x01a74000`,
`0x014e8000` and the row space is:

```text
0x0074e000  0x009d2000  0x00e9c000  0x013a6000
0x014e8000  0x01a74000  0x01d3a000
```

## Inputs

- The Experiment 004 captured images: `xbl` and `xbl_config` (both slots),
  `tz`, `hyp`, `devcfg`, `aop`, `abl` — 10 files, each hashed into the manifest.
- `SHRM_MEM.BIN`, 65,536 bytes, from the Verification 012 Samsung Upload capture.
- The 494 decoded controller registers from that capture's analysis, 274 of
  them nonzero, covering 470 distinct source-register addresses.

Host-only. The device was not contacted.

## Four encoding families, all negative

| Family | What was tested | Result |
|---|---|---|
| Stored 32-bit literal | each covector as a little-endian word in every image | 2 hits |
| Register mask | every covector at every bit alignment 0..20, with and without an enable bit in position 0 | 0 |
| Packed bit indices | field widths 4, 5, 6, 8 and index bases 0, 9, 13, with a zero field read both as unused and as index zero | 0 |
| Adjacent triple | three words at stride 4 or 8 spanning the whole row space, any alignment | 0 |

The two literal hits are below chance. Two hundred decoy masks drawn over the
same address bits with the same popcount profile produce 132 hits, so a mask of
this shape occurs 0.66 times per mask across these images and seven real masks
would be expected to produce about 4.6 hits by coincidence alone. Two is fewer
than that, so the literal family is `BELOW_CHANCE` rather than a weak positive.

The register-mask family is the one that would have mattered most: had any
decoded controller register held a covector under any alignment, that register
would be the transform's storage, which is precisely the precondition for P1.
None does.

The observed candidate values are structured, but not as this relation.
`qhs_mc +0x400` reads `0xc003ffff` identically in all four instances,
`+0x404` reads `0x00003333`, `qhs_mccc +0x118` reads `0x00111111`, and
`qhs_mccc_master +0x294` reads `0x00001111`. The repeating nibbles are what
motivated testing the index-encoding family; none of them decodes to a
covector. `qhs_mc +0x4d0` is the only ranked candidate that differs between
instances — `0x00300014` on two and `0x00300033` on the other two.

## What this negative does and does not bound

It is bounded by observability, and Experiment 022A already measured that
bound. Each MC instance contributes 42 observed addresses across a 9,305-word
observed span — **0.4514%** of that span, and 0.2563% of the instance's full
64 KiB. A register holding the relation outside those 42 addresses would not
appear here. This refutes the hypothesis *for the observed register set*, not
for the controller.

It is bounded by image searchability. `abl` is included among the targets, but
Experiment 021A measured its `PT_LOAD` payload at 2,293,760 bytes with `_FVH`
at payload offset `0x28` and Shannon entropy 8.000 bits/byte. A literal search
over compressed content cannot fail informatively, so `abl` contributes a void
rather than a negative and its inclusion in the target list must not be read
as coverage.

It is bounded by encoding family. Four were tested; others exist.

And it is consistent with the relation never being stored at all. Qualcomm's
US12380019B2 describes an SoC creating hashing regions at boot, and a relation
derived at boot from detected DRAM geometry need not appear as a literal in any
image. This audit cannot distinguish "derived at boot" from "stored where we
cannot see", and does not claim to.

## Claims and ranking

`PROVED`: the corrected row space and its invariance across all 168 bases of
the kernel; that four of the earlier audit's seven targets are values the
relation does not contain and four real covectors were never searched; a
measured chance rate of 0.66 literal hits per mask across these images; and
zero matches in all of the register-mask, index-encoding and adjacent-triple
families over the stated inputs.

`REFUTED`, over the observed register set only: that any of the 494 decoded
controller registers holds a covector of the bank relation under any bit
alignment, with or without an enable bit, or as packed field indices. Also
refuted: the earlier audit's target set as a correct statement of the relation.

`UNKNOWN`: whether the relation is stored anywhere outside the 0.4514% of each
MC instance that is observed; whether it exists as a literal inside `abl`,
which is not searchable in its present form; whether it is derived at boot
rather than stored; and the identity of any writer.

Classification is unchanged: `CLASS C (TRANSFORM ONLY)` /
`NO_BOUNDARY_BYPASS_OBSERVED`. This experiment removes candidate encodings; it
demonstrates no alias, no mutation, no reach, and no bypass. Experiments 015
and 016 remain `NOT ELIGIBLE`.

## Cheapest next discriminator

Make `abl` searchable. It is the only captured image whose literal search is
currently vacuous, and Experiment 021A recorded it as `NOT SEARCHABLE` rather
than negative. Walking the UEFI firmware volume — FV header, FFS files,
sections, LZMA/Tiano decompression — turns a void into evidence either way, and
is host-only.

## Reproduction and provenance

```sh
python3 tools/a90_bank_relation_encoding_audit.py \
  --capture <private capture directory> \
  --shrm <private SHRM_MEM.BIN> \
  --analysis <private analysis JSON> \
  --output evidence/manifests/028-bank-relation-encoding-audit-20260826-01.manifest.json
python3 -m unittest -v tests.test_a90_bank_relation_encoding_audit
```

- Tool SHA-256:
  `c6d9a27a933dfcbe12f1321ec16f65e3a4df6de5adc39682fcfb5399408e89f2`.
- Focused result: 25 tests pass. Full repository discovery: 538 tests pass.
- Date: 2026-08-26 KST. Mode: `HOST_ONLY_READ_ONLY`; device, SMC and MMIO
  access: none.

The public manifest contains masks, hashes, counts, offsets and
classifications only. It contains no raw firmware bytes and no private absolute
paths.
