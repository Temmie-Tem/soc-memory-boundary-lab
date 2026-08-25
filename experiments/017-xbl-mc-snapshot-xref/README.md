# Experiment 017 — XBL MC table-driven read-copy cross-reference

## Scope and eligibility

Experiment 017 is host-only static evidence for the exact retained SM8150 XBL.
It does not execute on the device and does not access a device, SMC, MMIO,
normal RAM, protected memory, or a runtime register.

Conceptual Experiment 015 (a controlled normal-RAM alias) and Experiment 016
(protected-boundary reach through that alias) remain reserved and `NOT
ELIGIBLE`. Experiment 017 satisfies neither gate: it proves no alias, mutation,
protected reach, or bypass.

## Exact inputs and table

- XBL: `xbl--sdb1.bin`, exactly 4,194,304 bytes.
- XBL SHA-256:
  `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.
- Table VA/file offset: `0x146b1218` / `0x630b8`.
- Table: 122 nonzero little-endian u64, 4-byte-aligned MMIO addresses followed
  by a u64 zero terminator at index 122.
- Inclusive table bytes SHA-256:
  `d5042980f035d3d52974536115074940b4b1858cb30a47699e7553f1b200da07`.
- Structural shape: 30 four-instance MC groups (120 entries) plus two global
  entries. The source PT_LOAD `PF_W` bit is an ELF permission fact only; it
  does not prove runtime table writability or mutation.

The exact table contains all four instances of each `qhs_mc +0x400`,
`qhs_mc +0x404`, and `qhs_mc +0x4d0` candidate (12 addresses total). It
excludes all four `qhs_mccc +0x118` addresses and the
`qhs_mccc_master +0x294` address from this table only. That exclusion does not
mean those candidates are absent from transform state.

The independent address-list cross-check against
`tools.shrm_dump_decode.load_plan()` is:

| Plan | Distinct addresses | Intersection with XBL table |
|---|---:|---:|
| set 0 | 430 | 100 |
| set 1 | 64 | 4 |
| union | 470 | 100 |
| table-only | — | 22 |
| SHRM-union-only | 370 | — |

This is address-list convergence only. It does not prove semantic identity or
writer attribution.

## Fixed-range static helper evidence

The analyzed helper code range is `0x146ae138..0x146ae18c` (end-exclusive),
file offset `0x62318`, length `0x54`, SHA-256
`f325a8bf4c8e9ff7c21a0d20752e742cd8e047422e9eff5c301bf3042a95e138`.

Its static control flow forms table VA `0x146b1218` with `ADRP X9` and
`ADD X9,#0x218`. The first zero-sentinel loop prefills fixed destination VA
`0x146bf300` with `0xdededede`; the second zero-sentinel loop constructs each
table-derived pointer, issues `LDR W10,[X10]`, and, if that load returns, issues
`STR W10,[X8],#4` to the distinct output buffer. Identified store bases inside
the exact `0x54`-byte range are only `X12` and `X8`; this refutes the helper as
a candidate-controller programming/mutation path.

The code-range analysis is bounded, but runtime traversal is
`ZERO_SENTINEL_ONLY`; there is no independent hard 122-entry iteration cap.
The exact on-disk table happens to terminate at index 122. Successful runtime
execution/completion, partial or sentinel output, output coherence/atomicity/
currentness, MMIO read side effects/faults, mutable runtime table contents,
post-boot writability/lock state, and indirect BLR/tail-call reachability are
all `UNKNOWN`.

A complete scan of direct BL instructions in file-backed executable PT_LOADs
finds exactly two static callers:

- VA `0x146ae26c`, file offset `0x6244c`;
- VA `0x14839f44`, file offset `0x20f44`.

The exact instruction words are pinned by the analyzer but are not emitted in
the public JSON. These are direct reachability facts only; neither caller is
claimed to execute on the current boot.

## Claims and ranking

`PROVED`: exact table structure, candidate address coverage, SHRM address-list
convergence, and the conditional static read-copy data flow above.

`REFUTED`: this exact helper programs/writes the candidate controller
addresses, and this helper independently enforces a hard 122-iteration cap.

`UNKNOWN`: any other writer/programmer, register bit semantics, relation to the
measured GF(2) bank function, runtime completion/coherence/currentness, MMIO
side effects/faults, runtime table mutation/lock, indirect reachability,
post-boot writability, alias, or protected-boundary bypass.

The existing Verification-012 Top-5 order is unchanged:

1. `qhs_mc +0x400`
2. `qhs_mc +0x404`
3. `qhs_mccc +0x118`
4. `qhs_mc +0x4d0`
5. `qhs_mccc_master +0x294`

The three MC groups with exact table/read-path coverage gain independent
observation confidence only; their semantic likelihood does not increase. The
absent MCCC candidates are not downgraded beyond table exclusion.

Current classification remains `CLASS C (TRANSFORM ONLY)`: the low-24 GF(2)
bank relation is proved behaviorally, but no PA alias, transform mutation,
protected reach, or bypass is proved.

## Cheapest next discriminator

Use a host-only symbolic AArch64 store cross-reference/backward slice for the
12 exact `qhs_mc` targets (four instance bases × `+0x400`, `+0x404`, `+0x4d0`).
Resolve effective addresses through `MOVZ/MOVK`, `ADRP+ADD`, literal/table
loads, arithmetic, and argument provenance. Accept only exact target matches;
keep unresolved dynamic bases `UNKNOWN`. Do not perform a broad MMIO scan or
any device action.

## Reproduction and provenance

```sh
python3 tools/sm8150_xbl_mc_snapshot_xref.py \
  --output evidence/manifests/017-xbl-mc-snapshot-xref-20260825-01.manifest.json
python3 -m unittest -v tests.test_sm8150_xbl_mc_snapshot_xref
```

- Public manifest SHA-256:
  `b1db21235374c64de797c1a123c64ddb23c43fca9100bbd51cf7b4897ea5c61b`.
- Tool SHA-256:
  `2baa9e3def46bb1c22bfd23c3dc7c4b800cf3fbc16ada1254e73023842633d99`.
- Focused-test SHA-256:
  `5b0f6f3e4d0b9a4a0e80f17555f4c8e12baf1f8d83f5bc6ee1fb97252d21f392`.
- Focused result: 20 tests pass.
- Full repository unittest discovery: 279 tests pass.
- Independent raw-byte review: accepted read-only re-derivation; no review
  artifact was emitted, so no review-artifact hash exists.
- Date: 2026-08-25 KST.
- Mode: `HOST_ONLY_READ_ONLY`; device, SMC and MMIO access: none.

The public manifest contains hashes, addresses, counts, classifications, and
static semantic metadata only. It contains no raw firmware bytes or private
absolute paths.
