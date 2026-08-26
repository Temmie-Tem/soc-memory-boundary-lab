# Experiment 025 integration review — 2026-08-26

## Scope

This review integrates the committed host-only Experiment 025 implementation
`d743150` (parent `a68d2f1`) into the common research documents:

- `README.md`
- `STATUS.md`
- `docs/ARCHITECTURE_MAP.md`
- `docs/EXPERIMENT_MATRIX.md`
- `docs/NEXT_EXPERIMENT_SCORECARD.md`
- `docs/RESEARCH_LOG.md`
- `research/sm8150-memory-subsystem.md`

The exact public artifact is
`evidence/manifests/025-xbl-platform-query-binding-20260826-01.manifest.json`,
size 28,132 bytes, mode `0644`, SHA-256
`d3c405d7c8d23dc1cd65b1c578b4b4ce931d9bdfeb303c892e9c0c145c4c81cc`.
Commit `d743150` also contains the companion experiment README; this review
records its hash below. No firmware bytes, private absolute paths, device
identifiers, or live values are added to the public integration. This review
grants no device, SMC, MMIO, write, or Experiments 015/016 authority.

## Artifact pins

| Artifact | SHA-256 |
|---|---|
| `tools/sm8150_xbl_platform_query_binding.py` | `16e9584a3043d76670c66b6a517e56c87267645506c1f76a040737d731b168b9` |
| `tests/test_sm8150_xbl_platform_query_binding.py` | `219227a927acb8a98d8e7294150c154b916795e709ab02bb076b946d8d7bb687` |
| `experiments/025-xbl-platform-query-binding/README.md` | `eb97735c91b79fb13f8feb40e9b98ffd7f2aa71a9dcc2fbe479fcdcf2e4014a3` |
| `evidence/manifests/025-xbl-platform-query-binding-20260826-01.manifest.json` | `d3c405d7c8d23dc1cd65b1c578b4b4ce931d9bdfeb303c892e9c0c145c4c81cc` |

The exact XBL input is bound by size 4,194,304 and SHA-256
`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.
Experiment 024 is consumed as a semantically validated dependency, including
its conditional mapping and unresolved `BLR X9` at `0x1486ac1c`; its
conditional UFS mapping is not upgraded by this review.

## Validation

- Focused Experiment 025 unittest suite: **22 PASS**.
- Full repository unittest discovery at the reviewed tree: **556 PASS**.
- Public tracked JSON manifests: **65** parsed successfully.
- Python byte-compilation of the reviewed tool and focused test: **PASS**.
- Two fresh Experiment 025 generations: **byte-identical** to the committed
  manifest.
- Public manifest mode: `0644`; publication/no-clobber and safety checks pass.
- Markdown relative-link check and `git diff --check`: **PASS**.
- No private absolute-path leakage was introduced in the integration diff.

## Integrated bounded result

Experiment 025 is `COMPLETED` as `HOST_ONLY_READ_ONLY` static analysis of the
exact SM8150 XBL. It remains `CLASS C (TRANSFORM ONLY)`; no device, SMC, MMIO,
protected-memory, normal-RAM, or activation action occurred.

`PROVED`: the exact platform-query helper `[0x1486abec,0x1486acac)` has one
pinned direct caller at `0x1486847c`, which passes `X0=SP+0x10`; the main
initializer context is `X19` and is not forwarded. The helper loads, forms the
attach-output address for, and reloads runtime slot `0x14890590`. The exact
registry attach path materializes service ID `0x02000139` with semantic
`MOVZ/MOVK` instruction pins.

`PROVED`: the static seed derives `X0=0x14875668` and outer record
`X1=0x14875590`; that record has count five and selects descriptor
`0x14824ab8`, whose factory is `0x1484a880`. The bounded factory path constructs
candidate object `0x1488f418`, whose inline vtable is `0x14824ad0` and whose
`+0x48` entry is callback `0x1484a9d4`.

`PROVED`: the bounded callback path is
`0x1484a9d4 -> 0x1484a730 -> 0x1484a824 -> 0x1484aa30 -> 0x1484a854`.
Its one recognized output write at `0x1484a9f4` targets the helper's `SP+0xc`
output slot. The recognized nested writes are limited to recursion/status BSS
at `0x1488f3f9`, `0x14890ba0`, and `0x14890b90`; the bounded status helper has
one decoded MMIO read at `0x01fc8004` and zero recognized MMIO writes. The
all-file-backed executable census and pinned loop blocks account for the
recognized direct slot/address/list xrefs; they are conservative coverage, not
an arbitrary-write-absence proof.

`SUPPORTED`: conditional intended binding can populate the output slot and
return a callback result through the helper's stack output, and the recognized
callback flow does not write the caller context `+8` field. `UNKNOWN`: runtime
registration/order, current slot value/object identity, actual `BLR X9` target,
alternate BSS mutation/global aliases/unsupported writes, full preservation or
currentness of initialized base `0x01d80000`, and any live mapping or authority.
Class C is unchanged; Experiments 015/016 remain `NOT ELIGIBLE`.

## Independent hostile review

The initial hostile artifact pass identified the following documentary or
decoder risks. Each was repaired in the committed Experiment 025 artifact:

1. The direct-branch decoder's `B` versus `BL` mask could admit link-form
   false positives. The branch-class mask and direct-call census were tightened
   so only the intended instruction class is accepted.
2. Stale ADRP/clobber/control-flow assumptions and BR false xrefs could make
   unrelated data or unreachable blocks appear to bind the registry or slot.
   Page formation, register clobbers, bounded control-flow blocks, and branch
   target classification were pinned and false xrefs removed.
3. The service-ID path lacked a semantic `MOVZ/MOVK` value pin. The exact
   high/low instruction words and resulting ID `0x02000139` are now required.
4. The lazy-bootstrap range did not pin the terminal `RET` precisely. The
   bounded range now ends at `0x1484aa74` and pins `RET` at `0x1484aa70`.
5. Definition-of-done metadata was incomplete. Target identity, exact XBL
   binding, host-only non-applicable live artifacts, precondition, recovery and
   rollback status, negative-control contract, publication mode, and
   deterministic two-generation validation are now explicit.

After these corrections, two independent final artifact reviews returned
`PASS` on artifact hashes, range and word pins, claim vocabulary, conservative
census scope, public/private separation, dependency handling, and the
Definition-of-done metadata.

Two further read-only reviewers independently checked this common-document
integration after the corrected Experiment 026 range was applied. Both
returned `PASS` on the Experiment 025 claims and labels, artifact pins and
validation counts, artifact-review/integration-review separation, links and
public/private boundary, stale-next cleanup, Class C/015/016 status, and the
design-only Experiment 026 transition. Neither reviewer edited or committed
the reviewed files.

## Final disposition

`PASS`: the committed Experiment 025 artifact, two independent artifact
reviews, and two independent common-document reviews pass. The next primary
selection is Experiment 026; its ranges are design inputs only until
independently re-derived and pinned. Runtime order, slot value, `BLR` target,
base currentness, live mapping, Class C status, and 015/016 eligibility remain
unchanged.
