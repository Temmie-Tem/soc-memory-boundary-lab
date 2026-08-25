# Experiment 019 — DCB register-programming tables

## Question

Experiment 018 searched the exact XBL for stores to twelve ranked absolute MC
addresses and found no writer inside four progressively wider static models.
A target-first search cannot distinguish "no writer exists" from "the writer
never names the address". This experiment asks the complementary question:
does the boot chain program controller registers from *data*, and if so, does
that data reach the ranked candidates?

## Scope and eligibility

Host-only, read-only static evidence over the nine exact Experiment-004
firmware images. No device, SMC, MMIO, normal-RAM, protected-memory or
runtime-register access. Conceptual Experiments 015 (controlled normal-RAM
alias) and 016 (protected-boundary reach) remain reserved and `NOT ELIGIBLE`;
this experiment satisfies neither gate.

The ELF walk is written independently of the other `tools/` modules. Reusing an
existing parser would make the result inherit that parser's mapping, which is
the circularity Verification 001 exists to avoid.

## Result

`PROVED`: the `xbl_config` DCB carries register-programming tables — zero-
terminated `(key, value)` u32 arrays — in two distinct forms. Twenty-eight
tables across the four DCB blocks pass a strict acceptance test: at least four
entries, every key 4-byte aligned, keys strictly ascending, and an all-zero
terminator occupying the final eight bytes.

`PROVED`: one form uses **absolute** MMIO addresses and the other uses
**base-relative offsets** with no base stored in the section. The second form
is why no absolute target address need appear as a firmware literal, which
independently explains the Experiment 018 Stage 1A literal census.

`REFUTED`: the DCB programs the twelve ranked absolute MC targets. No absolute
table reaches any of the four ranked bases, and the only base-relative table
carrying the ranked offsets does not carry the measured values.

`UNKNOWN`: the implicit base of every base-relative table; whether any ranked
value is computed rather than stored; whether DDR training firmware outside
these nine partitions writes them; register semantics; the relation to the
Experiment 014 GF(2) bank relation; post-boot writability; alias; bypass.

Current classification is unchanged:

```text
CLASS C (TRANSFORM ONLY)
NO_BOUNDARY_BYPASS_OBSERVED
```

## Exact inputs

All nine Experiment-004 images are pinned by size and SHA-256 and the tool
refuses to run on anything else. The DCB source is `xbl_config--sdb2.bin`,
4,149,248 bytes, SHA-256
`0e9dfac1ddd0f9acc2cc899213e621490308f0cadf329814048edb7712e2484c`.

It contains four PT_LOAD segments of exactly `0x3404` bytes at file offsets
`0x1079c`, `0x13ba0`, `0x16fa4` and `0x1a3a8`. Each is one DCB configuration
with a 22-slot section directory of `{u16 data_offset, u16 size}` from
offset `0x0c`.

The companion `xbl_config--sdc2.bin` contains **zero** `0x3404`-byte segments.
Whether that slot uses a different layout or is unpopulated is `UNKNOWN`.

## Accepted tables

DCB block 0, with the strict test applied:

| Section | Form | Entries | Key range |
|---:|---|---:|---|
| 5 | absolute address | 66 | `0x090c0010`..`0x090c8118` |
| 6 | base-relative offset | 17 | `0x028908`..`0x02c668` |
| 7 | base-relative offset | 22 | `0x0000a0`..`0x00088c` |
| 8 | base-relative offset | 18 | `0x000004`..`0x000154` |
| 10 | base-relative offset | 169 | `0x000010`..`0x00082c` |
| 11 | base-relative offset | 152 | `0x000010`..`0x0007ec` |
| 12 | base-relative offset | 92 | `0x000010`..`0x000f48` |

Sections 13 and 14 parse as pairs but fail the ascending-key test, so they are
recorded as `NOT_A_REGISTER_TABLE` rather than promoted. Section 16 is the
Experiment-012 SHRM snapshot list and is not a programming table.

Every key in the one absolute table lies in a single 64-KiB block,
`0x090c0000`. None of the four ranked MC bases (`0x09260000`, `0x092e0000`,
`0x09360000`, `0x093e0000`) is reached by any absolute table.

## Cross-block variance

The four DCB blocks are four configurations. Sections 3, 4 and 17 are byte-
identical across all four; every other section differs. Within the accepted
tables:

| Section | Distinct keys | Present in all four | Value varies |
|---:|---:|---:|---:|
| 5 | 66 | 59 | 6 |
| 6 | 30 | 16 | 0 |
| 7 | 22 | 21 | 1 |
| 8 | 20 | 18 | 3 |
| 10 | 178 | 152 | 56 |
| 11 | 165 | 122 | 39 |
| 12 | 97 | 42 | 25 |

Sections 10, 11 and 12 carry the configuration-dependent fields. Section 7 is
effectively fixed: one key of twenty-two varies.

## The ranked offsets

Exactly one accepted table contains the ranked offsets, and it is section 7:

```text
0x0a0 = 0x0b0b5058      0x400 = 0x10000000      0x420 = 0x10000000
0x0b0 = 0x000a005a      0x404 = 0x10000000      0x424 = 0x10000000
                        0x408 = 0x10000000      0x428 = 0x10000000
0x880 = 0x00000100      0x40c = 0x20000300      0x42c = 0x20000301
0x884 = 0x00000101      0x440 = 0x10000000      0x460 = 0x10000000
0x888 = 0x00000102      ...                     ...
0x88c = 0x00000103      0x44c = 0x20000302      0x46c = 0x20000303
```

Four groups of four registers, each group's final value carrying an instance
index `0`..`3`. Those values are identical in all four DCB blocks.

Verification 012 measured live `qhs_mc +0x400 = 0xc003ffff` and
`+0x404 = 0x00003333`. Section 7 holds `0x10000000` at both. `REFUTED`:
section 7's implicit base is `qhs_mc`. Its actual base is `UNKNOWN`; the
four-instance shape is suggestive but is not evidence of identity.

## Ranked value materialisation audit

For each Verification-012 ranked live value, all three single-instruction
constant paths were tested across all nine exact images: presence as a stored
32-bit little-endian word at any alignment; the `MOVZ`/`MOVK` wide-move
halfword encodings; and the `ORR`/`MOV` logical-immediate encoding.

| Live value | Candidate | Stored word | Wide-move | `ORR` imm |
|---|---|---|---|---|
| `0xc003ffff` | `qhs_mc +0x400` | 24, `hyp` only | excluded | encodable, 0 sites |
| `0x00003333` | `qhs_mc +0x404` | 0 | excluded | not encodable |
| `0x00111111` | `qhs_mccc +0x118` | 3, `tz` only | not excluded | not encodable |
| `0x00300014` | `qhs_mc +0x4d0` | 0 | not excluded | not encodable |
| `0x00300033` | `qhs_mc +0x4d0` | 0 | not excluded | not encodable |
| `0x00001111` | `qhs_mccc_master +0x294` | 18 | excluded | not encodable |

`PROVED`: `0x00003333` is absent from every single-instruction constant path in
all nine images. `0xc003ffff` and `0x00001111` are absent from both wide-move
and `ORR`-immediate paths; neither appears in `xbl--sdb1.bin` at all.

Two limits are load-bearing and are not softened here. The wide-move test is a
one-sided necessary condition: it asks whether both halfword encodings occur
anywhere in the image set, not whether they occur as an adjacent pair in one
register, so `excluded` is decisive and `not excluded` is inconclusive. And
`0x00111111`, `0x00001111`, `0x00003333`, `0x00300014` and `0x00300033` are all
repeating-nibble patterns that a short loop builds without leaving any constant
anywhere; for those, literal absence is weak evidence. `0xc003ffff` is not such
a pattern, so its absence carries more weight.

`0xc003ffff` occurring 24 times in `hyp--sdd33.bin` and nowhere else is
recorded as an observation, not as attribution. QHEE runs after DDR
initialisation and the value is a plausible generic mask; no writer path was
established and none is claimed.

## What this does and does not settle

It settles that data-driven controller programming exists in this boot chain
and that the ranked candidates are not among its targets. Combined with
Experiment 017 — where the only confirmed path touching those addresses is a
read-only snapshot copier — and Experiment 018's four negative writer models,
four independent methods have now failed on the same twelve addresses.

The parsimonious reading is no longer that the writer is well hidden. It is
that the ranked candidate set, which Verification 012 itself published as
`UNKNOWN` for every row after rejecting the comparative Qualcomm label, is not
where the Experiment 014 bank relation lives. Hardwired reset defaults and
wrong-address remain jointly consistent with all current evidence and are not
separated here.

## Cheapest next discriminator

Recover the implicit bases of sections 10, 11 and 12 by locating their DCB
consumers in XBL, which must read the section directory at `0x0c + index*4`
and pair each offset with a base register. Those three tables hold the
configuration-dependent fields and span offsets `0x10`..`0xf48`, a plausible
controller window.

Base recovery by cross-matching against the live SHRM snapshot was attempted
and is `REFUTED` as a method on this target: set 0 holds 430 registers with
only 71 distinct values, 220 of them zero, so value agreement carries too
little information. The highest-scoring candidates were page-unaligned and
arrived in consecutive four-address runs, the signature of coincidence.

## Evidence

- `evidence/manifests/019-dcb-register-programming-20260826-01.manifest.json`

The manifest contains hashes, addresses, counts, classifications and claim
metadata only. It contains no raw firmware bytes and no private paths.

## Reproduce

```sh
python3 tools/sm8150_dcb_register_program_inventory.py \
  --output evidence/manifests/019-dcb-register-programming-20260826-01.manifest.json
python3 -m unittest -v tests.test_sm8150_dcb_register_program_inventory
```

## Provenance

- Tool SHA-256:
  `5a64b45e4da0ca1302b5e6114fdd7a66f71edcbfed8f66ca5367ebff11dd1a6d`.
- Focused-test SHA-256:
  `bf65f080f9982afc143c0cb1a4462e3ddfcaae4cd3baedd1512c9bd0421a5d52`.
- Public manifest SHA-256:
  `c3164f1675d89ffcdd57aae349c75411fdf6b712f9dc32c9403b8671549d4792`.
- Focused result: 39 tests pass. Full repository unittest discovery on this
  branch: 359 tests pass.
- Regeneration is byte-identical; manifest mode is `0644`.
- Date: 2026-08-26 KST.
- Mode: `HOST_ONLY_READ_ONLY`; device, SMC and MMIO access: none.
- Produced in a separate git worktree on branch `research/xbl-config-cdt`,
  concurrently with the Experiment 018 Stage 2D work on `main`. The shared
  documents `STATUS.md`, `docs/EXPERIMENT_MATRIX.md` and `docs/RESEARCH_LOG.md`
  are deliberately untouched here and are reconciled at integration.
