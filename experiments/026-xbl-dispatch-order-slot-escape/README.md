# Experiment 026 — bounded XBL dispatch/order and slot-escape census

## Question and scope

Can the exact A90/SM8150 XBL image independently pin the registration helper,
initializer-table cursor, dispatcher/pool, bootstrap, veneer, alternate paths,
and callers around the Experiment 025 platform-query chain?  Does a
complementary, fail-closed address census recognize any mutation of runtime
slot `0x14890590`, the registration globals/list, the factory-object window,
or bootstrap state?

This is host-only, read-only static analysis.  It performs no device, USB,
SMC, MMIO, protected-memory, runtime-register, boot, activation, or write
action.  Static branch/data edges are local facts only; they do not prove that
an edge executed or establish relative boot order.

The public result remains `CLASS C (TRANSFORM ONLY)`.  Experiment 025 is a
semantic dependency, not a source of duplicated range claims.  Its Class C
classification, runtime order/slot/BLR/base `UNKNOWN` boundaries are checked
before this manifest is published.

## Exact inputs

| Input | Size | SHA-256 |
|---|---:|---|
| `xbl--sdb1.bin` | 4,194,304 | `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37` |
| Experiment 025 manifest | 28,132 | `d3c405d7c8d23dc1cd65b1c578b4b4ce931d9bdfeb303c892e9c0c145c4c81cc` |

The firmware is parsed as an ELF64 little-endian AArch64 image.  The
memory-only PT_LOAD containing the requested initializer pool is retained in
the ELF inventory, but it has no file-backed bytes and therefore no byte hash.

## Independently pinned ranges

All file-backed ranges below are checked for VA, file offset, size, SHA-256,
and selected instruction words.  The registration-helper request names the
244-byte core `[0x1482ecb4,0x1482eda8)`; the public result additionally pins
the 248-byte function enclosure `[0x1482ecb4,0x1482edac)` so the `RET` at
`0x1482eda8` is included.

| Component | VA range | File offset | Size | SHA-256 |
|---|---|---:|---:|---|
| registration-helper core | `[0x1482ecb4,0x1482eda8)` | `0x15cb4` | 244 | `a06e6ddaaab9efa5fa4756926554d7be8824c27a40dff7173011caf08162d34d` |
| registration-helper enclosure | `[0x1482ecb4,0x1482edac)` | `0x15cb4` | 248 | `a603e4dbf24dd86e1487695f7adc3ae6dad23da7c091a074119f55c8b66bc9d7` |
| initializer loop | `[0x1482edac,0x1482f0b4)` | `0x15dac` | 776 | `b17d7aeb92f959c8c47bc0d3b1a970c2483d649d29749b1e2fc80a6e1a7b4cbd` |
| table header | `[0x14875534,0x14875568)` | `0x54f14` | 52 | `472a39ffae4ed0c869c5f39b2bbd6104b6fab39bc12982bc7e848207585b232a` |
| bootstrap caller | `[0x14852ce0,0x14852d70)` | `0x39ce0` | 144 | `0d8fe60229edeeb076d0e1e684356f7b518df766517d9a8ba51fffaff42f48bf` |
| veneer | `[0x14843d20,0x14843d50)` | `0x2ad20` | 48 | `dca21f62f4878aba67add52fcaeef6b04de9f5b3ef1ff6a5f99612e508c76f1f` |
| alternate one | `[0x14828338,0x14828360)` | `0xf338` | 40 | `fc0344cec688fe4cdaa5b0708023ae7a27516ce8c5c5d341e0f8602865103b6d` |
| alternate two | `[0x14828b44,0x14828c80)` | `0xfb44` | 316 | `b008d12e3f1a8dad8621a057c3e71c543709810375b2c85a1bec82a2440567e4` |
| main dispatcher | `[0x14864834,0x148648c0)` | `0x4b834` | 140 | `519df36f8fd0c91b7b09564254b0e32377dc0f78158f5c7b088a4721e45ab309` |
| caller/context init | `[0x148641a4,0x1486420c)` | `0x4b1a4` | 104 | `6bbd29427c6cb5853b47a6d6e529d5cf66207d2873e94042f8688bd790e49429` |
| caller/dispatcher wrapper | `[0x1486420c,0x1486424c)` | `0x4b20c` | 64 | `2df6fdc5eff88cb71e1df58d7bdc0d9433b97b16d66855f0811ffad956f55eef` |
| caller/service path | `[0x148642dc,0x148644cc)` | `0x4b2dc` | 496 | `de5b437bb270fecfe558b9c0e097ff4eb4566480c177f6b530ee90b0777095cc` |
| caller/bootstrap entry | `[0x1485a2ec,0x1485a30c)` | `0x412ec` | 32 | `0516e6042e3bffa173786336e107925e497ff6fdbcc5467ca0554272cca90124` |
| memory-only initializer pool | `[0x146b30c0,0x146b38b0)` | not file-backed | 2,032 | not file-backed |

## Static findings

`PROVED`: the registration helpers use a 24-byte node shape: object pointer at
`+0`, service ID at `+8`, and next pointer at `+16`.  The list-head global is
`0x14890f60`, inside the target registration-global interval.  Create,
initialize, append, and lookup control edges and their exact local stores are
pinned; runtime list contents and execution are `UNKNOWN`.  The store at
`0x1482ed68` is conditional: it writes the global head only on the empty-list
branch, otherwise it writes `tail_node+0x10` (the tail's next field).

`PROVED`: the table header contains count `2` at `0x14875534`.  Two rows of
stride `0x18` begin at `0x14875538` and fill the pinned header range.  The
initializer cursor starts at row `+0x14`, reads the kind at cursor `-4`, reads
the ID at cursor `0`, and advances by `0x18`.  The loop back edge and its three
direct calls to registration helper `0x1482ed24` are exact local edges.  A
direct call to the Experiment 025 wrapper is recorded as a dependency edge,
not a duplicate claim.

`PROVED`: the dispatcher at `0x14864834` reads a byte index from context
`[X19,#9]`, checks `X8 <= 1`, and forms

```
pool_row = 0x146b30c0 + index * 0x3f8
```

It passes the symbolic row pointer
`0x146b30c0 + X8*0x3f8` as `X0` to direct `BL 0x1483c73c` and stores the
row pointer into the context object.  It then directly calls the Experiment
025 main initializer at `0x14868418`; that call is a dependency edge only.
The pool is memory-only, so its bytes and runtime values remain `UNKNOWN`.

`PROVED`: bootstrap, veneer, alternate, and caller ranges contain the exact
direct-BL/unconditional-branch edges recorded in the manifest.  Alternate two
directly calls the initializer loop, and the caller chain reaches the main
dispatcher through `0x1486420c`; indirect `BLR` selections remain unresolved.

## Complementary target census

The census scans every word in file-backed executable PT_LOADs while skipping
the exact Experiment 025-supported code idioms/ranges.  It recognizes only
tested forms: ADR/ADRP; MOVZ/MOVK/MOVN; ADD/SUB immediate, shifted-register,
and extended-register forms with exact shift/extension semantics; ORR W/X
copies/shifts and logical immediates; unsigned, unscaled, pre/post-index,
accurately-modeled pair (including Rt2), LDR W/X literal, and register-offset
forms with exact UXTW/UXTX/SXTW/SXTX option and S scaling; and argument taint
into direct BL/BLR/BR.

UBFM/SBFM aliases, AND/ORN logical-register forms, exclusive/LSE atomics,
LDRSW/PRFM literals, invalid register-offset options, unsupported shifts, and
other unrecognized encodings are explicitly `UNKNOWN` rather than treated as
address proofs.

The exact result is:

- `PROVED_BOUNDED_NO_RECOGNIZED_SLOT_MUTATION` for runtime slot
  `0x14890590` (zero recognized direct writes outside the 025 exclusion).
- Recognized direct accesses include registration-head/global locations in
  `[0x14890f50,0x14890f68)`, a bootstrap-state access around `0x1488af58`,
  and accesses in the factory-object window `[0x1488f400,0x1488f440)`.
- The scanner reports a direct store at `0x1484b0ec` to `0x1488f438` and a
  direct argument escape at `0x1484bdc0`; these are static recognized facts,
  not proof that the paths execute.
- Computed runtime indexes/pointers, merged control-flow fixed points,
  unresolved memory contents/aliases, indirect branch targets, and unknown
  AArch64 memory encodings remain explicitly `UNKNOWN`.  `writer_absence_claim`
  is `false`; an empty recognized slot-write set is never a global absence
  claim.

The registration helper's list-head stores and Experiment 025's slot/factory
idioms are not silently counted twice: the manifest names the exclusion ranges
and keeps the 025 semantic dependency separate from the new range proofs.

## Taxonomy and boundaries

- `ORDER_OPEN`: static local edges do not close runtime execution, caller/path
  selection, alternate dispatch, pool contents, or relative boot order.
- `PROVED_BOUNDED_NO_RECOGNIZED_SLOT_MUTATION`: no recognized slot write in
  the implemented/excluded census scope; this is not writer absence.
- Runtime order, runtime slot/object identity, runtime BLR target, and current
  base authority are always `UNKNOWN` in this host-only result.

The result is not a device capability, activation gate, boundary bypass, or
promotion of Experiment 025's unresolved base.

## Reproduce and validate

```sh
out_dir=$(mktemp -d /tmp/exp026-xbl-dispatch-order-slot-escape.XXXXXX)
python3 tools/sm8150_xbl_dispatch_order_slot_escape.py \
  --firmware-dir evidence/private/004-live-firmware-readonly-20260825-01 \
  --dependency evidence/manifests/025-xbl-platform-query-binding-20260826-01.manifest.json \
  --output "$out_dir/manifest.json"

python3 -m unittest -v tests.test_sm8150_xbl_dispatch_order_slot_escape
python3 -m py_compile tools/sm8150_xbl_dispatch_order_slot_escape.py
```

The focused suite contains 25 synthetic/exact-image tests, including negative
controls for shifted-register semantics, AND-vs-ORR opcode confusion,
UBFM/SBFM and exclusive/LSE rejection, pair Rt2 kill, literal form rejection,
register-offset option/S scaling, conditional list-tail semantics, symbolic
pool escapes, clobbers, branches, and publication no-clobber behavior.

Publication uses `O_EXCL`, `O_NOFOLLOW` when available, and mode `0644`; an
existing output is never clobbered.  Fresh generation is deterministic and
must be byte-identical.  No device command is part of this experiment.

## Evidence and provenance

- `evidence/manifests/026-xbl-dispatch-order-slot-escape-20260826-01.manifest.json`
- Tool SHA-256: `61b4f993678527b7cb1b024b0e8f5cdf4b965a9bf3aedc8a2a12214c8d26a5f8`
- Focused-test SHA-256: `3f8aad6ed90b8c16d4bece5dc272e402ddd4f91af35ae1a294c53beb6d5d9b41`
- Public manifest SHA-256: `2139b5d230be78d822eda656f2856a229894167938227d34a614dcabf16c7885`
- Mode: `HOST_ONLY_READ_ONLY`; device/SMC/MMIO access: none
