# Experiment 029A — Make `abl` searchable, then run the searches that were vacuous

Numbered `029A`, not `029`. This experiment and the concurrent
`029-dcb-unsupported-frontier` were assigned the same number independently on
2026-08-26. That one is on `main` with Experiments 031, 032 and 033 built on top
of it, so it keeps the bare number and this one takes the suffix, following the
`023R` precedent. Nothing about the result changed.

## Why

Experiment 021A measured the `abl` `PT_LOAD` payload at 2,293,760 bytes with
`_FVH` at payload offset `0x28` and Shannon entropy 8.000 bits/byte, and
recorded it `NOT SEARCHABLE`. That was the right call, and it was deliberately
distinguished from a negative — but it left one captured image as a void.
Experiment 028 listed `abl` among its targets, so for `abl` its negative proved
nothing. This experiment removes the void so the negative can be real.

Host-only. No live device-tree artifact is an input to this repair. A prior
device-tree observation is not retained here as a public/private property dump
or hash, so the live-DT claim remains explicitly `UNRETAINED_UNKNOWN` below.

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

The extractor's dump contract is deliberately tied to the audit's input
contract: every extracted blob is written as one flat, deterministic filename
ending in `.bin`. The audit's `capture.glob("*.bin")` therefore includes the
decompressed LZMA payload and all three PE32 modules. Logical UEFI paths stay
in the manifest, alongside their corresponding `dump_name`; no caller-side
rename or undocumented shell step is needed.

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

The seven numeric covectors and their literal/triple searches are scoped to the
validated 023R allocation-offset/model relation. Any physical bank-row
attribution is only `SUPPORTED_WITHIN_MODEL` under 023R's contiguous-qsecom and
Experiment-014 assumptions; the underlying physical-page map is `BLIND`.

`abl` also contains none of the listed DDR-controller base literals. The four
`qhs_mc` instance bases `0x09260000`, `0x092e0000`, `0x09360000`, `0x093e0000`,
the `qhs_mccc` base `0x09250000` and the `qhs_mccc_master` base `0x090b0000`
each occur **zero** times as exact stored u32 little-endian values in the
decompressed content.

The ABL bank-relation audit supplies no decoded register capture: register
observation and register-family negative claims are therefore
`NOT_APPLICABLE`, not a zero-register absence result. Its bounded refutations
cover only the exact numeric literal and tested adjacent-triple encodings.

## Static DDR references: consumer-shaped names, runtime still unknown

The decompressed payload contains DDR Info diagnostics — `"Error getting DDR
Info, Plz check SMEM version (see EFISmem.h)"`, `"INFO: Unable to get DDR Info
protocol:%r"`, `"DDR Header Revision =0x%x"` — and device-tree property names:
`ddr_device_type`, `ddr_device_rank_ch%d`, `ddr_device_hbb_ch%d_rank%d`.
The exact counts are reproduced in the separate semantic-audit manifest. These
strings are static naming evidence only; they do not prove that a path executes
or that it writes a device tree.

`hbb` is the highest bank bit and would bear directly on the measured bank
relation, but no retained public/private DT payload, property dump, or DT hash
is available for this audit. Whether `/proc/device-tree/memory/` carried only
`ddr_device_type`, carried rank/HBB properties, or carried another value is
therefore `UNRETAINED_UNKNOWN`; it is not a measured absence in this record.

## Claims and ranking

`PROVED`: the volume structure above, including the LZMA size agreement; that
the decompressed content is 4,763,976 plain bytes containing the three named
PE32 modules with the hashes recorded in the manifests; that the bank
relation's allocation-offset/model row space does not occur in it as an exact
stored literal or as a tested spanning adjacent triple; that no `qhs_mc`, `qhs_mccc` or
`qhs_mccc_master` instance base occurs in it as an exact stored literal; and
that the named DDR strings occur with the counts recorded by the semantic
audit.

`REFUTED` as a current post-extraction status: `NOT SEARCHABLE` no longer
holds because the image is now parsed and its decompressed payload is searched.
Experiment 021A's historical observation about the unparsed high-entropy
representation remains valid. For `abl` specifically, the semantic audit also
refutes only the presence of an exact stored
controller-base literal, row-space literal, or tested adjacent triple in the
searched decompressed payload.

`UNKNOWN`: everything the extraction cannot reach. The three PE32 modules were
extracted but not disassembled, so computed values and runtime controller
programming/participation remain unknown; `abl` runs long after DRAM training,
so its static silence about the controller bounds only the tested stored forms
in `abl`; the DDR Info structure that SMEM supplies is not in this capture; and
the live device-tree property set and hash are `UNRETAINED_UNKNOWN`.

Classification is unchanged: `CLASS C (TRANSFORM ONLY)` /
`NO_BOUNDARY_BYPASS_OBSERVED`. Experiments 015 and 016 remain `NOT ELIGIBLE`.

## Reproduction and provenance

```sh
# use a fresh scratch directory so only this extraction is audited
python3 tools/abl_uefi_extract.py \
  --image <private abl image> --dump-dir <scratch> \
  --output evidence/manifests/029A-abl-uefi-extraction-20260826-01.manifest.json
python3 tools/a90_bank_relation_encoding_audit.py \
  --capture <scratch> \
  --experiment-id 029A-bank-relation-audit-over-abl \
  --source-manifest <029A extraction manifest> \
  --relation-manifest <023R public manifest> \
  --output evidence/manifests/029A-bank-relation-audit-over-abl-20260826-01.manifest.json
python3 tools/a90_abl_semantic_audit.py \
  --image <private abl image> \
  --relation-manifest <023R public manifest> \
  --output evidence/manifests/029A-abl-semantic-audit-20260826-01.manifest.json
python3 -m unittest -v tests.test_abl_uefi_extract
python3 -m unittest -v tests.test_a90_abl_semantic_audit
```

These are `REDACTED_REPRODUCTION_TEMPLATE`s: private image/scratch/output
paths are redacted, while the exact extraction and 023R relation dependencies
are pinned by manifest hash; the templates are not executed-command receipts.

- Focused result: 20 extractor, 29 bank-audit, and 8 semantic-audit tests pass.
  Full repository discovery was not rerun for this repair.
- Current verifier extractor tool SHA-256:
  `047cc74a023e05e7bec80384b5939a4c406a5a8575587a01c0643280cd7a8ab4`.
- Current verifier bank-audit tool SHA-256:
  `e806017d51dcf090eae069be8a89561cf3e91d1d4552d78f7a2170308cdce297`.
- Current verifier semantic-audit tool SHA-256:
  `40ac0c1300f1d469fd7f9ee1f9941d04a7ac849acdb95ce1f94853e9d470fcf2`.
- Current verifier extractor focused-test SHA-256:
  `994a947e62843da0b6964b1b50ccacc356aff6fe660d3596b74e8397f6738613`.
- Current verifier bank-audit focused-test SHA-256:
  `ee74fb2a2d18fff869b9388e594405c768d11ab1485dbcec211cec1de6eb640a`.
- Current verifier semantic-audit focused-test SHA-256:
  `f2711eba7b9ad256c93cf196dbaa90fbc34b9835862f20244925433831334854`.
- Repaired extraction manifest SHA-256:
  `ce127f159db7008d1846750f73685e4afb081c7a769d65e0ea1ccf1afd92f701`.
- Repaired bank-audit manifest SHA-256:
  `ab70da1d900337622780ae26f820971f3df8a6714b99e1f81fdcabf9e084fbf4`.
- Repaired semantic-audit manifest SHA-256:
  `4f2bbff05a6bb2bc3ed3f6f6522d04689570d4121d3d7dfd7c674b2065788db5`.
- Validated 023R relation-manifest SHA-256:
  `5c3e14ff898c109de740d98260d974bca10751000f85977775cd467ac74aac2e`.
- Date: 2026-08-26 KST. Mode: `HOST_ONLY_READ_ONLY`; no device, MMIO, SMC,
  register, partition, boot-image or live-DT access occurred in this repair.

The public manifests contain structure, hashes, counts, classifications,
provenance and the deterministic dump names only. They contain no raw firmware
bytes and no private absolute paths. Rollback, recovery and live device
binding are `NOT_APPLICABLE` to the host extraction because the source image
was already captured and the extractor never contacts a device. The semantic
audit additionally publishes source-image, volume and module hashes, exact
static counts, and the explicit live-DT `UNRETAINED_UNKNOWN` boundary.
The extraction manifest records target/build/timestamp/command/repetition
metadata; the bank-relation audit records both its exact source-manifest hash
and the 023R relation-manifest hash, as well as the 200-trial decoy baseline.
