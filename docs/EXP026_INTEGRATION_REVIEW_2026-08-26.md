# Experiment 026 integration review — 2026-08-26

## Scope

This review integrates committed host-only Experiment 026 implementation
`0305a03` into the common research documents. The implementation is a
read-only static analysis of the exact SM8150 XBL and a bounded complementary
address-escape census. It performs no device, SMC, MMIO, protected-memory,
normal-RAM, write, or activation action. Experiment 025 is consumed only as a
semantically validated dependency; its ranges are not re-claimed. Class C
remains `TRANSFORM ONLY`, and Experiments 015/016 remain `NOT ELIGIBLE`.

The public artifact is
`evidence/manifests/026-xbl-dispatch-order-slot-escape-20260826-01.manifest.json`,
size 64,027 bytes, mode `0644`, SHA-256
`2139b5d230be78d822eda656f2856a229894167938227d34a614dcabf16c7885`.
No private firmware bytes, absolute paths, device identifiers, or live values
are added to the public integration.

## Artifact pins

| Artifact | SHA-256 |
|---|---|
| `tools/sm8150_xbl_dispatch_order_slot_escape.py` | `61b4f993678527b7cb1b024b0e8f5cdf4b965a9bf3aedc8a2a12214c8d26a5f8` |
| `tests/test_sm8150_xbl_dispatch_order_slot_escape.py` | `3f8aad6ed90b8c16d4bece5dc272e402ddd4f91af35ae1a294c53beb6d5d9b41` |
| `experiments/026-xbl-dispatch-order-slot-escape/README.md` | `392631c3ef6298b23ef52bdfe085d723b7bd5451dd10483e5296e4ab4c6e3d24` |
| `evidence/manifests/026-xbl-dispatch-order-slot-escape-20260826-01.manifest.json` | `2139b5d230be78d822eda656f2856a229894167938227d34a614dcabf16c7885` |

The exact XBL input is bound by size 4,194,304 and SHA-256
`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.
The committed Experiment 025 dependency is bound by size 28,132 and SHA-256
`d3c405d7c8d23dc1cd65b1c578b4b4ce931d9bdfeb303c892e9c0c145c4c81cc`.

## Validation

- Focused Experiment 026 unittest suite: **25 PASS**.
- Full repository unittest discovery at the reviewed tree: **581 PASS**.
- Python byte-compilation of the reviewed tool and focused test: **PASS**.
- Public JSON safety parse: **PASS** for all 66 public manifests.
- Two fresh Experiment 026 generations: **byte-identical** to the committed
  manifest.
- Public manifest mode: `0644`; O_EXCL/O_NOFOLLOW publication, no-clobber,
  and path-safety checks pass.
- Markdown relative-link check and `git diff --check`: **PASS**.
- Exact-XBL semantic review and final decoder hostile review after the listed
  repairs: **PASS**.

## Integrated bounded result

`PROVED`: the independently pinned registration helpers are
`[0x1482ecb4,0x1482edac)` and contain the exact 24-byte node shape (object at
`+0x0`, identifier at `+0x8`, next at `+0x10`) and list-head handling at
`0x14890f60`. The initializer loop is
`[0x1482edac,0x1482f0b4)`. The table header is
`[0x14875534,0x14875568)`: count is two, rows begin at `0x14875538`, the
cursor is at `0x1487554c`, and the derived row stride is `0x18`.

`PROVED`: the bounded bootstrap caller
`[0x14852ce0,0x14852d70)`, veneer `[0x14843d20,0x14843d50)`, alternates
`[0x14828338,0x14828360)` and `[0x14828b44,0x14828c80)`, dispatcher
`[0x14864834,0x148648c0)`, callers
`[0x148641a4,0x1486420c)`, `[0x1486420c,0x1486424c)`,
`[0x148642dc,0x148644cc)`, and `[0x1485a2ec,0x1485a30c)` have the pinned
local control/data edges, including dispatcher base/stride/index guard and
symbolic pointer escape `0x146b30c0 + runtime_index*0x3f8` for modeled index
`0..1`, not an exact runtime base. `SUPPORTED`: the memory-only initializer
pool shape is `[0x146b30c0,0x146b38b0)`, with two-row `0x3f8` geometry. Pool
contents and runtime values remain `UNKNOWN`; the local pointer escape to the
direct `BL` and main-initializer call is proved only within this static model.

The complementary all-file-backed executable census scans 847,465 words and
excludes 622 words covered by the Experiment 025 dependency. Its implemented
forms recognize 9 direct accesses (3 writes and 6 reads) and 2 pointer
escapes across the bounded slot, registry, registration-global, factory, and
bootstrap windows. It finds zero recognized writes whose access intervals
overlap slot `[0x14890590,0x14890598)`. This is a bounded recognized-form
result, not a global writer-absence claim.

The result taxonomy is `ORDER_OPEN` and
`PROVED_BOUNDED_NO_RECOGNIZED_SLOT_MUTATION`. Runtime execution/order, slot
value, `BLR` target, base currentness, object identity, and writer absence
remain `UNKNOWN`; no runtime authority or device conclusion follows.

## Independent hostile review

The final decoder review returned `PASS` after correcting or narrowing the
following risks: shifted-register ADD/SUB semantics; ORR masks and the former
LSL-only coverage (the final decoder supports the tested LSL/LSR/ASR forms);
UBFM/SBFM, pair, literal, register-offset, exclusive/LSE,
and unsupported memory forms; SIMD/sign-extension/unprivileged variants;
MTE ADDG/SUBG and undefined extended-register encodings; stale literal
taint; SP/XZR handling; writeback base/destination overlap; conditional
head-versus-tail list semantics; symbolic dispatcher pool addressing; and
interval-overlap slot classification. Adversarial synthetic controls cover
false positives, false negatives, clobbers, control flow, decoder errors, and
positive/negative slot overlap.

## Final disposition

`PASS`: Experiment 026 is integrated with the bounded labels above. The
separately reviewed next host-only follow-up is Experiment 027, scored `79/100`,
over the 020 67 register-offset loop sites minus the 024 walker plus all 8
computed-address sites, including loop stores `0x1484b9a0`, `0x146aea20`, and
`0x9fc05ef4`; its setter is `[0x9fc06410,0x9fc0643c)` with caller
`0x9fc023f0`. Required outcomes are `DCB_CONSUMER_PATH`,
`MC_OR_SHRM_SYMBOLIC_TARGET`, `NO_TARGET_WITHIN_MODEL`, and
`INDIRECT_OR_UNSUPPORTED`; implementation and preliminary hashes are not part
of this review. The 024 walker/caller ranges and the overlapping 020 subrange
remain excluded controls. The rawdump slot/object alternative remains
unselected because record 19 maps `SHRM_MEM.BIN`
`[0x09060000,0x09070000)` and retained `ocimem`
`[0x14680000,0x146c0000)` neither covers `0x14890590`; Samsung Upload supplies
only `SHRM_MEM.BIN`, Sahara is `NO_SHRM_DUMP_CAPTURED`, survival is `UNKNOWN`,
and no safe arbitrary XBL-BSS path is available. No device action is proposed
by the scorecard; future action needs a separate exact-bound contract/gates.
The integration does not upgrade runtime order or slot mutation, does not claim
global writer absence, and does not change Class C or 015/016 eligibility.
