# Experiment 034 integration review — 2026-08-26

## Scope and authority boundary

This review integrates the completed host-only Experiment 034 artifact from
commit `d5d8046`. It resolves only Experiment 033 site 35's exact bounded
indirect jump table. It performs no device, USB, SMC, MMIO, normal-RAM,
protected-memory, boot, activation, or write action. Class C remains
`TRANSFORM ONLY`; Experiments 015 and 016 remain `NOT_ELIGIBLE`.

The exact XBL input is `xbl--sdb1.bin`, 4,194,304 bytes, SHA-256
`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.
The tool pins and semantically validates the exact Experiment 033 tool and
manifest before importing their already-hashed source bytes. Runtime execution,
table contents, current physical destination, global writer/consumer absence,
and protected-memory semantics remain `UNKNOWN`.

## Artifact pins

| Artifact | Size | Mode | SHA-256 |
|---|---:|---:|---|
| `tools/sm8150_dcb_site35_jump_table.py` | 56,864 | `0644` | `7589b9f61d92fc835a2378f11106963c074619d59675209082ad919f823690a8` |
| `tests/test_sm8150_dcb_site35_jump_table.py` | 21,596 | `0644` | `081b7334a4e88a04647d39e5657c13bcb537b374db192e0597b561ce02cae51b` |
| `experiments/034-dcb-site35-jump-table/README.md` | 6,712 | `0644` | `05a44b688afc6b23eec2e469c523bc6c780d3379ca6ff08f34b020da14bfc82a` |
| Checked public manifest | 2,241,492 | `0644` | `75728982e1622f3e807c367baff5cc87d18cff94fa2a9135699f3f836b804b92` |

The public manifest is
`evidence/manifests/034-dcb-site35-jump-table-20260826-01.manifest.json`.
It contains no firmware bytes, private path, device identifier, runtime value,
or secret.

## Exact dispatch and table result

`PROVED`: the site-35 dispatch is the contiguous sequence
`LDR W9,[SP,#36]`; `CMP W9,#4`; `B.HI 0x1484fb9c`;
`ADRP X5,0x14824000`; `ADD X5,X5,#0xcf0`;
`LDR X1,[X5,X9,LSL#3]`; `BR X1`, at
`0x1484f9f0..0x1484fa08`. The table is therefore at `0x14824cf0`, file
offset `0xbcf0`, and its exact 40 bytes have SHA-256
`6c58a7dff5de7e6bc512bd83a5ce4f84499b2c89c0ff0a71b58b972c7f3dce61`.
The five entries are `0x1484fa3c`, `0x1484fa50`, `0x1484fa88`,
`0x1484fa0c`, and `0x1484fa0c`: four unique, mapped, aligned local targets
with multiplicity retained.

Guard coverage is proved only for the exact Experiment 033 bounded traversal
entered at site head `0x1484f954`. It has no modeled direct edge into the
dispatch after the `W9` load. External or otherwise unmodeled entries remain
`UNKNOWN`.

## Bounded synthetic resolution

Each unique target was evaluated in an independent in-memory copy of the exact
XBL by replacing only the `BR X1` word at `0x1484fa08` with the measured direct
`B` word:

| Target | Direct word | CFG states | Observations | Handled forms |
|---|---:|---:|---:|---:|
| `0x1484fa0c` | `0x14000001` | 186 | 7 | 19 |
| `0x1484fa3c` | `0x1400000d` | 181 | 5 | 19 |
| `0x1484fa50` | `0x14000012` | 190 | 6 | 20 |
| `0x1484fa88` | `0x14000020` | 212 | 10 | 23 |

All four runs are CFG-complete, have no unsupported form, and produce
`NO_TARGET_WITHIN_MODEL`. The first three words differ from the original in
three bytes and the last in two bytes; the manifest retains exact changed-byte
indices and synthetic-image hashes. No bounded `DCB_CONSUMER_PATH` or
`MC_OR_SHRM_SYMBOLIC_TARGET` is promoted.

`PROVED`: the composed Experiment 034 result is 71
`NO_TARGET_WITHIN_MODEL` and zero fail-closed sites. The manifest retains all
71 baseline Experiment 033 site records verbatim and publishes the composed
result separately, so it does not relabel baseline evidence. Relative to 033,
exactly one site transitions and 70 remain stable; there are no regressions.

`UNKNOWN`: direct `B` and indirect `BR` differ in architectural branch-type and
PSTATE.BTYPE behavior, which the model does not represent. Runtime equivalence,
execution/order, actual index, current table contents, aliases, current
destination, global absence, protected-memory semantics, and any Qualcomm
security effect remain unproved.

## Validation and disposition

- Focused suite: **14/14 PASS**; Python byte-compilation: **PASS**; maximum RSS
  **125,552 KiB**, swap **0**.
- Full repository discovery: **699/699 PASS** in **89.234 s**; maximum RSS
  **274,656 KiB**, swap **0**.
- Two fresh publications are byte-identical to the checked manifest.
- An independent raw-byte oracle recomputed the dispatch, table, direct words,
  changed bytes, synthetic hashes, and exact baseline identity.
- Negative controls include all 224 one-bit dispatch mutations. A hostile
  review found a `CMP W` width-mask P2; the decoder and regression controls were
  repaired, after which the same reviewer returned **PASS** with no P0-P2.

`PASS`: Experiment 034 closes the last blocker inside the bounded static model
only. It does not prove a DCB consumer, controller target, writer, transform
mutation, physical-to-DRAM alias, protected reach, or security-boundary bypass.
The next selection is the audited reconciliation of the external 023R/028/
029A/030 evidence line; Experiment 035 is deferred until that evidence has
phase-preserving provenance and bounded claims.
