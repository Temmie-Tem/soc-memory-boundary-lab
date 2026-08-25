# Experiment 018 — XBL MC writer cross-reference, Stage 1A + Stage 2A + Stage 2B + Stage 2C

## Scope and eligibility

Experiment 018 Stage 1A, Stage 2A and Stage 2B are host-only, read-only static evidence
over the exact retained SM8150 XBL. They make no device, SMC, MMIO, normal-RAM,
protected-memory or runtime-register access. Stage 2A resolves only the four
pinned non-SP RX candidates through a deliberately small direct-definition
model; Stage 2B extends only the two Stage 2A window-limit X8 candidates with a
deliberately small W-wide-move model; Stage 2C covers the remaining X8 writer
candidate through its unique direct caller and retained table. None of these
stages identifies a writer outside its model.

Conceptual Experiment 015 (controlled normal-RAM alias) and Experiment 016
(protected-boundary reach through that alias) remain reserved and `NOT
ELIGIBLE`. Stage 1A satisfies neither gate. Class C transform observation only
remains the current classification.

## Exact input and literal inventory

- XBL: `xbl--sdb1.bin`, exactly 4,194,304 bytes.
- XBL SHA-256:
  `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.
- Target set: four bases
  `0x09260000`, `0x092e0000`, `0x09360000`, `0x093e0000`, crossed with
  offsets `0x400`, `0x404`, and `0x4d0` (12 addresses).
- Each target's single 8-byte little-endian table encoding yields both the one
  aligned u64 match and the overlapping one aligned u32 match at the same file
  offset. These are two views of one table entry, not independent stored
  literals; there is no separate target literal elsewhere in the exact image.
- Only base `0x09260000` has an aligned u32 occurrence outside that table:
  file offset `0x80154`, VA `0x148bc254`, in an RWE PT_LOAD. The other three
  bases have zero aligned u32 occurrences, and every base has zero aligned u64
  occurrences. Incidental unaligned byte matches are not aligned literals.

The Experiment-017 table is at VA `0x146b1218` / file `0x630b8`; the Stage 1A
inventory records table membership, mapped VA, segment class and alignment for
each u32/u64 occurrence.

## PT_LOAD and store-offset census

The exact file-backed PT_LOAD census is RX 4, RWE 2, RW 3, OTHER 0. Strict
scalar AArch64 STR W/X unsigned-immediate recognition counts are RX 6945 and
RWE 5169. Matching candidate offsets are:

| Segment class | `+0x400` | `+0x404` | `+0x4d0` | Total |
|---|---:|---:|---:|---:|
| RX | 7 | 2 | 2 | 11 |
| RWE | 1 | 1 | 1 | 3 |
| Total | 8 | 3 | 3 | 14 |

Seven RX candidates use SP as their base. RWE decodes are ambiguous
code/data and are not promoted to proved instructions.

Stage 1A performs no base-register or effective-address resolution, so the
public `resolved_target_hit_count` is JSON `null`, not numeric zero. Literal
or offset equality is not a writer proof. The classification is
`STAGE1A_LITERAL_AND_STORE_OFFSET_CENSUS_WRITER_UNKNOWN`.

## Claims and limits

`PROVED`: exact XBL pinning, the 12-target/four-base literal inventory, the
PT_LOAD census, and the strict syntactic STR W/X offset census.

There is no `REFUTED` writer claim in Stage 1A. Actual writer identity and all
base/effective-address resolution, dynamic/cross-block paths, other store
forms, other firmware, register semantics, mutation, alias/bypass and runtime
execution remain `UNKNOWN`. AOP/TZ scope is not broadened without
source-backed writer or literal evidence.

## Stage 2A direct-definition slice

Stage 2A analyzes only these four non-SP RX candidates from the pinned Stage 1A
census:

| Store VA / file offset | Base | Offset |
|---|---|---|
| `0x14844b20` / `0x2bb20` | X8 | `+0x400` |
| `0x14844c78` / `0x2bc78` | X8 | `+0x4d0` |
| `0x146a70c0` / `0x2d6090` | X8 | `+0x400` |
| `0x14935bf4` / `0x312bc4` | X19 | `+0x400` |

The backward window is at most 128 aligned instructions. It stops at segment or
window boundaries, direct/indirect branches, calls, returns and recognized
inbound direct-branch block entries. Supported provenance is only 64-bit
`MOVZ` followed by zero or more same-register `MOVK`, or same-register
`ADRP Xn; ADD Xn,Xn,#imm`. 32-bit wide-move chains, `MOVN`, MOV aliases,
wrong-source `ADD`, loads, MADD and all other definitions fail closed.

Exact outcomes are:

| Candidate | Outcome | Stop/reason |
|---|---|---|
| `0x14844b20` | unresolved | `NO_DIRECT_CONSTANT_DEFINITION` / `WINDOW_LIMIT` |
| `0x14844c78` | unresolved | `NO_DIRECT_CONSTANT_DEFINITION` / `WINDOW_LIMIT` |
| `0x146a70c0` | unresolved | `UNSUPPORTED_REGISTER_DEFINITION` (`LDR` at `0x146a70b4`) |
| `0x14935bf4` | unresolved | `NO_DIRECT_CONSTANT_DEFINITION` / `CONTROL_TRANSFER` (BL boundary) |

`resolved_base_count=0` and `resolved_target_hit_count=0`. The exact
classification is
`NO_RESOLVED_TARGET_STORE_WITHIN_STAGE2A_DIRECT_DEFINITION_RX_MODEL`.
This refutes only the supported Stage 2A direct-definition path for these four
candidate stores; it does not state or imply that no writer exists. The seven
SP candidates remain runtime-derived `UNKNOWN`, and the three RWE candidates
remain `NOT_ATTEMPTED_RWE_AMBIGUOUS`/`UNKNOWN`. Writer identity, unsupported or
dynamic paths, execution, semantics, mutability/lock, GF(2), alias, bypass and
other firmware remain `UNKNOWN`.

## Stage 2B W-wide-move extension

Stage 2B analyzes only the two Stage 2A `WINDOW_LIMIT` X8 candidates, with a
maximum 512 aligned predecessor instructions and the same segment, basic-block,
direct-branch and control-transfer boundaries:

| Store VA / file offset | Base | Offset |
|---|---|---|
| `0x14844b20` / `0x2bb20` | X8 | `+0x400` |
| `0x14844c78` / `0x2bc78` | X8 | `+0x4d0` |

It adds only same-register 32-bit `MOVZ W8` followed by `MOVK W8` semantics;
the W writes zero-extend into X8. Both exact chains pin `MOVZ W8,#0xf000` at
VA/file `0x14844580`/`0x2b580` and `MOVK W8,#0x1489,LSL#16` at
`0x1484458c`/`0x2b58c`. The resulting XBL virtual-address value is
`0x1489f000`; the two computed effective values are `0x1489f400` and
`0x1489f4d0`, at distances 360/357 and 446/443 instructions respectively.
Neither value numerically equals a target, and both lie outside a file-backed
PT_LOAD. These are computed XBL effective-address values, not physical
destinations; VA-to-PA translation/identity and physical RAM/MC ownership are
`UNKNOWN`.

`PROVED`: the exact static W-wide-move model resolves both scoped bases and
computes those two non-target numeric values. `REFUTED` only: exact numeric
equality to one of the 12 target address values under this model. Runtime
execution, writer identity, unsupported/mixed-width/dynamic/cross-block/call
paths, physical destination, register semantics, mutability/lock, GF(2), alias,
bypass and other firmware remain `UNKNOWN`; this does not state or imply that
no writer exists. The classification is
`NO_NUMERIC_TARGET_ADDRESS_MATCH_WITHIN_STAGE2B_W_WIDE_MOVE_RX_MODEL`.

## Stage 2C unique direct-caller retained-table path

Stage 2C examines the remaining non-SP RX X8 store candidate at
`0x146a70c0` / file `0x2d6090`, `STR W9,[X8,#0x400]`, inside writer range
`[0x146a70a4,0x146a70dc)`. The writer range is 56 bytes at file `0x2d6074`
with SHA-256
`a50aaeb45c498a63e91704fc0ec4550b120ca0c1b691c238736b0532136dad6c`.
Its wrapper is `[0x146a6744,0x146a67b0)` / file `0x2d5714`, 108 bytes,
SHA-256 `24008bb23f54ed515774f020ac62cb3973b74dc57a41acd2bd358567863ad436`;
the lookup is `[0x146a7a08,0x146a7b18)` / file `0x2d69d8`, 272 bytes,
SHA-256 `9e54cfe4e5e2fad580b92c0853513f1be25046abeb00ff76db83d87ad3036046`.

The exact executable-segment scan finds one direct BL caller,
`0x146a67a4` / file `0x2d5774`. Decoded pins show wrapper `X1=SP` to lookup,
a lookup-result branch to `0x146a67a0`, then `X0=SP` to the unique writer.
The lookup derives X19 from X1, bounds its W10 index by the count loaded from
`[X10,#0x7d0]`, forms 16-byte rows, compares IDs, and on a match loads the
pointer at row `+8` and stores it through `[X19]`. The writer's success
fall-through loads X8 from `[X0]` and has `STR W9,[X8,#0x400]`, gated by its
descriptor `+0x20` field.

The retained table is VA `0x146aa4d0` / file `0x2d94a0`, 48 × 16 bytes,
SHA-256
`47a7f6195703f2f4d27cbe1e8bd0cc976600453a3ba4aebba98736ef8e03906e`.
The following u32 at VA/file `0x146aa7d0` / `0x2d97a0` is 48; all 48 IDs and
nonzero pointers are unique and all reserved `+4` u32 fields are zero. Every
row is emitted as an ID, base value, possible `base+0x400` effective value and
numeric target-match flag. No pointer equals one of the four target bases, and
no possible `base+0x400` equals any of the 12 targets.

These 48 values are `table_derived_possible_effective_values`: a conservative
success-path superset, not proof that every row passes the runtime descriptor
`+0x20` eligibility condition or that every store executes. Values are XBL
effective-address values; VA-to-PA/identity, physical destination/ownership,
runtime table mutation/currentness, indirect callers, execution and writer
identity outside this direct path remain `UNKNOWN`. `PROVED` is limited to the
decoded static path and table/list convergence; `REFUTED` only numeric equality
to the 12 targets in this model. The remaining non-SP RX static candidate count
is one (`X19`); this does not eliminate other X8 writer paths. Classification:
`NO_NUMERIC_TARGET_ADDRESS_MATCH_WITHIN_STAGE2C_UNIQUE_DIRECT_CALLER_TABLE_MODEL`.

## Reproduction and provenance

```sh
python3 tools/sm8150_xbl_mc_writer_xref.py \
  --output evidence/manifests/018-xbl-mc-writer-xref-stage1a-20260825-01.manifest.json
python3 -m unittest -v tests.test_sm8150_xbl_mc_writer_xref
python3 tools/sm8150_xbl_mc_writer_stage2a.py \
  --output evidence/manifests/018-xbl-mc-writer-xref-stage2a-20260825-01.manifest.json
python3 -m unittest -v tests.test_sm8150_xbl_mc_writer_stage2a
python3 tools/sm8150_xbl_mc_writer_stage2b.py \
  --output evidence/manifests/018-xbl-mc-writer-xref-stage2b-20260825-01.manifest.json
python3 -m unittest -v tests.test_sm8150_xbl_mc_writer_stage2b
python3 tools/sm8150_xbl_mc_writer_stage2c.py \
  --output evidence/manifests/018-xbl-mc-writer-xref-stage2c-20260825-01.manifest.json
python3 -m unittest -v tests.test_sm8150_xbl_mc_writer_stage2c
```

- Tool SHA-256:
  `9806b64c01f9965161966c88bbf5b943d953e790664c3136b2a116da63f8dc57`.
- Focused-test SHA-256:
  `b5fbf50e545b9df86d45ac012106d8905af231d9e94b0b2dd1927ec365da13d8`.
- Public manifest SHA-256:
  `8861a5626576fac32a83c295c34be63f91fd5e3f4b434490d567fb2984bb192d`.
- Focused result: 8 tests pass.
- Full repository unittest discovery: 287 tests pass.
- Public manifest inventory: all 54 manifests parse as JSON.
- Regeneration is byte-identical; manifest mode is `0644`.
- Date: 2026-08-25 KST.
- Mode: `HOST_ONLY_READ_ONLY`; device, SMC and MMIO access: none.

## Stage 2B provenance

- Tool SHA-256:
  `aa35d8b303a7ea32a086d601b1f08390b1cad0932f105209ac337f394813dbcb`.
- Focused-test SHA-256:
  `af7ca7b46550dda13e85e517c0c1c1df19b6414549d06415316b6d428e020fc9`.
- Public manifest SHA-256:
  `a4715112e27c74e5548ecb49f09106c236146c8a0216c87446ddbd3c355ccca6`.
- Focused result: 10 tests pass; full repository unittest discovery: 311
  tests pass.
- Public manifest inventory: all 56 manifests parse as JSON; regeneration is
  byte-identical; mode is `0644`.
- Date: 2026-08-25 KST.
- Mode: `HOST_ONLY_READ_ONLY`; device, SMC and MMIO access: none.

## Stage 2C provenance

- Tool SHA-256:
  `d53d820eb8d10e8417247fabbc0e3196f73c73584a6b7d79d583a96834c34d53`.
- Focused-test SHA-256:
  `92c95472940937a7001fe48dd055b4c598fd290c28a1e15757d1c297ebf5f526`.
- Public manifest SHA-256:
  `e096562a35da93a1dac10a1651fc7eff08eecf05dafca4a789bae2fd50540c01`.
- Focused result: 9 tests pass; full repository unittest discovery: 320 tests
  pass.
- Public manifest inventory: all 57 manifests parse as JSON; regeneration is
  byte-identical; mode is `0644`.
- Date: 2026-08-25 KST.
- Mode: `HOST_ONLY_READ_ONLY`; device, SMC and MMIO access: none.

The public manifest contains hashes, addresses, counts, segment classes and
claim classifications only; it contains no firmware bytes or private absolute
paths.

## Stage 2A provenance

- Tool SHA-256:
  `eb0a8ce21154d97d052de9f7e4e0de40f85087a8cb517179f7c44332e9d85eb0`.
- Focused-test SHA-256:
  `1272fadb0bcc6b883f74577284312ee34678975fa7ba60377d05d86927960b3b`.
- Public manifest SHA-256:
  `eeed732e4a6cecd60453e9088d8c3d4c7ed207a1e7c723bae91e27033d134a4b`.
- Focused result: 14 tests pass.
- Full repository unittest discovery after Stage 2A: 301 tests pass.
- Public manifest inventory: all 55 manifests parse as JSON; regeneration is
  byte-identical; mode is `0644`.
- Date: 2026-08-25 KST.
- Mode: `HOST_ONLY_READ_ONLY`; device, SMC and MMIO access: none.
