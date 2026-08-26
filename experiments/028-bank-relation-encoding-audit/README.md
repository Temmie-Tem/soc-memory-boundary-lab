# Experiment 028 — Do the validated model-coordinate bank masks appear in firmware or live registers?

## Why this is not a repeat of the earlier audit

`tools/a90_bank_hash_literal_audit.py` already searched the exact firmware for
Experiment 014's model-coordinate bank basis. That audit had two defects, and
Experiment 023R supplies what is needed to repair both.

**Its target was wrong.** It searched the row space of the Experiment 014
model basis, which omitted model bit 24. 023R resolved the allocation-offset
model-bit-24 contribution as `0b110` and pinned the kernel uniquely. Only three
of the seven covectors it searched are in the validated model row space:

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

## Why the model-coordinate row space is the whole target

A conflict measurement determines `ker f`, not `f`; 168 bases in `GL(3,2)`
describe the same kernel and predict identical conflicts. The kernel's
annihilator — the row space — is the same for every one of them. Its seven
nonzero covectors are therefore the complete target set, and searching 168
bases separately would be redundant. A test enumerates all 168 and asserts the
row space is invariant.

With allocation-offset/model bit 24 in `b1` and `b2`, the rows are `0x009d2000`, `0x01a74000`,
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
  them nonzero, covering 470 distinct source-register addresses. Around each
  ranked MC instance, the enumerated sample is 42 addresses over a 9,305-word
  observed span: **0.4514%** observed-span address density.

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
would be a high-priority candidate for transform storage and P1 follow-up.
That match was not observed in the bounded register set; a match itself would
still require semantic confirmation.

The observed candidate values are structured, but not as this relation.
`qhs_mc +0x400` reads `0xc003ffff` identically in all four instances,
`+0x404` reads `0x00003333`, `qhs_mccc +0x118` reads `0x00111111`, and
`qhs_mccc_master +0x294` reads `0x00001111`. The repeating nibbles are what
motivated testing the index-encoding family; none of them decodes to a
covector. `qhs_mc +0x4d0` is the only ranked candidate that differs between
instances — `0x00300014` on two and `0x00300033` on the other two.

## What this negative does and does not bound

It is bounded by observability, and Experiment 022A already measured that
bound. The register result is over exactly **494 decoded registers**, of which
**274 are nonzero**; each MC instance contributes 42 observed addresses across
a 9,305-word observed span — **0.4514%** of that span, and 0.2563% of the
instance's full 64 KiB. A register holding the relation outside those 42
addresses would not appear here. This refutes the hypothesis *for the observed
register set*, not for the controller, and does not establish global absence.

It is bounded by image searchability. `abl` is included among the targets, but
Experiment 021A measured its `PT_LOAD` payload at 2,293,760 bytes with `_FVH`
at payload offset `0x28` and Shannon entropy 8.000 bits/byte. A literal search
over unparsed or compressed content cannot fail informatively, so `abl`
contributes an `UNKNOWN` searchability observation rather than a negative and
its inclusion in the target list must not be read as coverage. Experiment 029A
later extracts the retained ABL volume; this audit's ABL status is the
pre-extraction boundary.

It is bounded by encoding family. Four were tested; others exist.

And it is consistent with the relation never being stored at all. Qualcomm's
US12380019B2 describes an SoC creating hashing regions at boot, and a relation
derived at boot from detected DRAM geometry need not appear as a literal in any
image. This audit cannot distinguish "derived at boot" from "stored where we
cannot see", and does not claim to.

## Claims and ranking

`PROVED` in allocation-offset/model coordinates: the corrected row space and
its invariance across all 168 bases of the kernel; that four of the earlier
audit's seven targets are values the relation does not contain and four real
covectors were never searched; a measured chance rate of 0.66 literal hits per
mask across these images; and zero matches in all of the register-mask,
index-encoding and adjacent-triple families over the stated inputs.

Physical attribution of those numeric masks and spans is only
`SUPPORTED_WITHIN_MODEL`, inherited from 023R's contiguous-qsecom and
Experiment-014 assumptions; the 023R pagemap is `BLIND`.

`REFUTED`, over the observed register set only: that any of the **494 decoded
controller registers (274 nonzero)** holds a covector of the bank relation
under any bit alignment, with or without an enable bit, or as packed field
indices. The result is bounded to the **0.4514% observed span** around each
ranked instance and is not a global absence claim. Also refuted: the earlier
audit's target set as a correct statement of the relation.

`UNKNOWN`: whether the relation is stored anywhere outside the 0.4514% of each
MC instance that is observed; whether it exists as a literal inside the
pre-extraction ABL representation; whether it is derived at boot rather than
stored; and the identity of any writer. Experiment 029A supplies a separate
ABL extraction result and does not widen this observed-register negative.

Classification is unchanged: `CLASS C (TRANSFORM ONLY)` /
`NO_BOUNDARY_BYPASS_OBSERVED` within the bounded host audit. This experiment
does not observe or prove global absence of alias, mutation, reach, or bypass;
those boundaries remain `UNKNOWN`. Experiments 015 and 016 remain
`NOT ELIGIBLE`.

## Historical next discriminator

Make `abl` searchable. This was the candidate follow-up when Experiment 028
was authored: it was the only captured image whose literal search was vacuous,
and Experiment 021A recorded an unparsed high-entropy observation rather than
a negative. Experiment 029A now performs the separate UEFI-volume extraction;
the historical follow-up is therefore superseded and does not alter this
audit's observed-register scope.

## Reproduction and provenance

```sh
python3 tools/a90_bank_relation_encoding_audit.py \
  --capture <private capture directory> \
  --shrm <private SHRM_MEM.BIN> \
  --analysis <private analysis JSON> \
  --relation-manifest <023R public manifest> \
  --output evidence/manifests/028-bank-relation-encoding-audit-20260826-01.manifest.json
python3 -m unittest -v tests.test_a90_bank_relation_encoding_audit
```

The reproduction command is a `REDACTED_REPRODUCTION_TEMPLATE`: private input
and output paths are redacted while the exact target and 023R relation hashes
are pinned; it is not an executed-command receipt.

- Historical producer tool SHA-256 (the immutable pre-repair manifest):
  `c6d9a27a933dfcbe12f1321ec16f65e3a4df6de5adc39682fcfb5399408e89f2`.
- Current verifier tool SHA-256: `e806017d51dcf090eae069be8a89561cf3e91d1d4552d78f7a2170308cdce297`.
- Current verifier focused-test SHA-256: `ee74fb2a2d18fff869b9388e594405c768d11ab1485dbcec211cec1de6eb640a`.
- Historical producer manifest SHA-256: `1b381eae606be1adfa21ca1b15306903add291a8c9a7d5ad8e507f577ba4990d`.
- Repaired public manifest SHA-256: `1ac85954028ef16071c654c5704600285bae09650888424f9756de1215b3351b`.
- Validated 023R relation-manifest SHA-256:
  `5c3e14ff898c109de740d98260d974bca10751000f85977775cd467ac74aac2e`.
- Focused result: 29 tests pass. Full repository discovery is not rerun here.
- Date: 2026-08-26 KST. Mode: `HOST_ONLY_READ_ONLY`; device, SMC and MMIO
  access: none.

The public manifest contains masks, hashes, counts, offsets and
classifications only. It contains no raw firmware bytes and no private absolute
paths.
