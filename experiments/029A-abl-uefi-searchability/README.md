# Experiment 029A — Make `abl` searchable, then run the searches that were vacuous

Numbered `029A`, not `029`. This experiment and the concurrent
`029-dcb-unsupported-frontier` were assigned the same number independently on
2026-08-26. That one is on `main` with Experiments 031, 032 and 033 built on top
of it, so it keeps the bare number and this one takes the suffix, following the
`023R` precedent. Nothing about the result changed.

## Why

Experiment 021 measured the `abl` `PT_LOAD` payload at 2,293,760 bytes with
`_FVH` at payload offset `0x28` and Shannon entropy 8.000 bits/byte, and
recorded it `NOT SEARCHABLE`. That was the right call, and it was deliberately
distinguished from a negative — but it left one captured image as a void.
Experiment 028 listed `abl` among its targets, so for `abl` its negative proved
nothing. This experiment removes the void so the negative can be real.

Host-only. The one device read was the live device tree, described at the end.

## Structure recovered

```text
abl--sdd8.bin        ELF32, PT_LOAD file 0x3000, vaddr 0x9fa00000, 0x230000 bytes
└── FV               EFI_FIRMWARE_FILE_SYSTEM2, len 0x230000, header 0x48, rev 2
    └── FFS 0x0B     FIRMWARE_VOLUME_IMAGE, size 0x12c8f9
        └── SECTION 0x02  GUID_DEFINED, EE4E5898-3914-4259-9D6E-DC7BD79403CF
            └── LZMA  props 0x5d, dict 0x1000000, declared 0x48b148
                └── FV  len 0x48b140, 4 files
                    ├── FFS_PAD
                    ├── Odin         APPLICATION / PE32, 1,810,432 bytes
                    ├── LinuxLoader  APPLICATION / PE32, 2,433,024 bytes
                    └── Cryptest     APPLICATION / PE32,   520,192 bytes
```

The LZMA output is 4,763,976 bytes and matches the size its header declares.
That is the previously unsearchable content; the three PE32 modules total
4,763,648 bytes and live inside it, so they are the same bytes viewed per
module, not additional coverage.

## Two parsing details that decide whether this works

**A pad file's name GUID is legitimately all-`ff`.** Terminating the file walk
on an all-`ff` *name* stops at the first pad file. In this image the inner
volume opens with a pad, so that mistake reports a well-formed volume as
containing zero files — which looks like a correct parse of an empty volume
rather than a bug. The walk terminates on a fully erased 24-byte *header*
instead.

**A large file carries its size after the header.** When the 24-bit size field
reads `0xffffff` and the large-file attribute is set, the real size is a 64-bit
field following the header, and a fixed 24-byte header misparses it. Both are
covered by tests.

One further correction: the `.lzma` alone format may declare an unknown size
with an all-`ff` marker, which is a valid stream. Rejecting it as a size
mismatch would refuse legitimate input, so the size is verified only when one
is actually declared. The captured blob does declare `0x48b148`, and the output
matches it.

## The searches, now that they mean something

Run over the extracted bytes with the Experiment 028 audit:

| Family | Result |
|---|---|
| Row-space literal | **0 hits** |
| Adjacent triple spanning the row space | 0 |

The chance baseline over this content is 1.01 hits per decoy mask, so seven
real covectors would be expected to produce about **7.07** hits by coincidence
alone. Observing zero is decisively below that. Experiment 028's negative now
covers `abl` on evidence rather than by listing it.

`abl` also contains no literal reference to the DDR controller at all. The four
`qhs_mc` instance bases `0x09260000`, `0x092e0000`, `0x09360000`, `0x093e0000`,
the `qhs_mccc` base `0x09250000` and the `qhs_mccc_master` base `0x090b0000`
each occur **zero** times in the decompressed content.

## What `abl` does with DDR: it consumes, it does not program

Every DDR reference is on the consumer side. `abl` obtains geometry through
SMEM and a DDR Info protocol — `"Error getting DDR Info, Plz check SMEM version
(see EFISmem.h)"`, `"INFO: Unable to get DDR Info protocol:%r"`, `"DDR Header
Revision =0x%x"` — and writes it into the kernel's device-tree memory node:
`ddr_device_type`, `ddr_device_rank_ch%d`, `ddr_device_hbb_ch%d_rank%d`.

`hbb` is the highest bank bit, which would bear directly on the measured bank
relation. On this device it is not propagated: the live device tree's
`/proc/device-tree/memory/` carries only `ddr_device_type = 0x00000007`, with
no rank or hbb property. That matches `abl`'s own diagnostic, `"ddr_device_rank,
HBB not supported in Revision=0x%x"` — the DDR info structure revision on this
boot predates the field. There is therefore no propagated bank-geometry value
to compare against Experiment 023R's relation, and that absence is a measured
fact rather than an unchecked assumption.

## Claims and ranking

`PROVED`: the volume structure above, including the LZMA size agreement; that
the decompressed content is 4,763,976 plain bytes containing the three named
PE32 modules with the hashes recorded in the manifest; that the bank relation's
row space does not occur in it as a literal or as a spanning adjacent triple,
against a measured chance expectation of about 7 hits; that no `qhs_mc`,
`qhs_mccc` or `qhs_mccc_master` instance base occurs in it; and that the live
device tree carries `ddr_device_type` only.

`REFUTED`: Experiment 021's `NOT SEARCHABLE` status for `abl`, which no longer
holds — the image is searchable and has been searched. Also refuted, for `abl`
specifically, is any suggestion that it participates in controller
programming: it neither names a controller base nor carries the relation.

`UNKNOWN`: everything the extraction cannot reach. The three PE32 modules were
extracted but not disassembled, so a value computed at runtime rather than
stored would not appear; `abl` runs long after DRAM training, so its silence
about the controller bounds only `abl`; and the DDR Info structure that SMEM
supplies is not in this capture.

Classification is unchanged: `CLASS C (TRANSFORM ONLY)` /
`NO_BOUNDARY_BYPASS_OBSERVED`. Experiments 015 and 016 remain `NOT ELIGIBLE`.

## Reproduction and provenance

```sh
python3 tools/abl_uefi_extract.py \
  --image <private abl image> --dump-dir <scratch> \
  --output evidence/manifests/029A-abl-uefi-extraction-20260826-01.manifest.json
python3 tools/a90_bank_relation_encoding_audit.py \
  --capture <scratch> \
  --output evidence/manifests/029A-bank-relation-audit-over-abl-20260826-01.manifest.json
python3 -m unittest -v tests.test_abl_uefi_extract
```

- Focused result: 18 tests pass. Full repository discovery: 556 tests pass.
- Date: 2026-08-26 KST. Mode: `HOST_ONLY_READ_ONLY` apart from one read-only
  device-tree read; no MMIO, SMC, register, partition or boot-image access.

The public manifests contain structure, hashes, counts and classifications
only. They contain no raw firmware bytes and no private absolute paths.
