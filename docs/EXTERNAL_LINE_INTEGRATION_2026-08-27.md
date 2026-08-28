# External `research/xbl-config-cdt` integration audit — 2026-08-27

## Scope

The external ref is `research/xbl-config-cdt@99eb1dc` with parent
`247b0e1`.  Its worktree is prunable, but the Git ref and all 14 commits are
readable.  This audit covers all 14 rows: the two patch-equivalent changes
(`4b78b61` and `c91f473`) are retained as dispositions rather than replayed,
and the other 12 are classified individually below.  The current branch is
not fast-forwarded or reset to that ref: doing so would remove the current
020A–020J and 034 evidence.

The integration rule is to preserve the current repaired implementation when an
external implementation is weaker or semantically incompatible, while
retaining additive primary-source reviews and new evidence.  A commit is
marked `INTEGRATED_EQUIVALENT` only when the current artifact and review
directly carry its bounded result; this is not a claim that the commit hash is
an ancestor.

## Commit disposition

| External commit | Content | Disposition |
|---|---|---|
| `05a4c5c` | initial Verification 015 runtime comparison | `INTEGRATED_EQUIVALENT` via repaired `1182f12`; external implementation not cherry-picked over stricter parser/gates |
| `4b78b61` | external reconciliation review | `INTEGRATED_EQUIVALENT` via `787c8b4` and `docs/EXTERNAL_REVIEW_RESPONSE_2026-08-27.md` |
| `a297fde` | 015 coldboot/power-cycle condition | `INTEGRATED_EQUIVALENT` in retained six-condition V015 evidence; no weaker code overwrite |
| `b2b5068` | retract vacuous DDR-bandwidth interpretation | `INTEGRATED_EQUIVALENT` in V015 scope; bus-vote axis remains excluded from transform claims |
| `6b3abc7` | initial V016 PA25–PA27 analysis | `INTEGRATED_EQUIVALENT` via repaired `746def0`; phase-separated retained parser preserved |
| `c91f473` | initial V017 bank-granularity audit | `INTEGRATED_EQUIVALENT` via hardened V017 commits `651d0a5`/`c7ae4f2`/`0929539` |
| `db22fb1` | BadRAM/DisARMed/PMPlease reuse review | `INTEGRATED_EXACT` as additive commit `eb2f44d`, [external reuse review](EXTERNAL_REUSE_REVIEW_2026-08-27.md) |
| `0d2c1bf` | first V018 alias-marker oracle | `INTEGRATED_EQUIVALENT` via repaired `49c3381`; current analyzer already contains synthetic positive and fail-closed gates |
| `ace5e9b` | V018 no-alias acquisition/manifest | `INTEGRATED_EQUIVALENT` only within the retained repaired V018 scope; external implementation/manifest is not used to replace it |
| `96f8d4c` | deep-suspend permutation experiment | `INTEGRATED_EXACT` as additive commit `8c3d1c5`; its raw-receipt gap is closed by local follow-up `1bc494e`, with two retained runs and `MAP_INVARIANT` |
| `5323d17` | V015 bus-vote transcript and V017/V018 wording corrections | `INTEGRATED_PARTIAL`: 128 KiB arbitrary-base wording and access-control distinction are current; the bus transcript remains a supplementary evidence task, and no overstrong “unrestored vote” claim is imported |
| `865593b` | four-route/XPU/signature analysis | `INTEGRATED_EXACT` as additive commit `0e6bfd5`; claims retain `PROVED`/`SUPPORTED`/`UNKNOWN` labels |
| `b33339b` | route-2 response and V017/V018 corrections | `INTEGRATED_PARTIAL`: handoff wording and scope repairs are current; current repaired files are preserved rather than add/add overwritten |
| `99eb1dc` | 029–034 Q4 audit amendment | `INTEGRATED_AUDIT_ONLY`: the audit is reviewed, but Q4 remains `UNKNOWN` because the complete relation-row set is not retained |

The additive commits are now in the current branch as `eb2f44d`, `8c3d1c5`
and `0e6bfd5`; the remaining dispositions are represented by this audit and
the current exact artifacts.  No external branch reset, force update, or
device action occurred.

The subsequent local V019 retention/repetition commit is `1bc494e`.  It is not
part of the external 14-commit ref; it replaces the dangling private-receipt
links with real regular files, retains the original and second-run receipts,
and adds the private-tree symlink guard.  Both analyzer regenerations are
byte-identical to the public manifests.  The device-side transition was
reversible and restored; no controller, security-boundary or partition write
was performed.

## 1b reachability checkpoint

Reopen condition 1 is split into 1a (identify a writer) and 1b (demonstrate a
Normal-World-reachable aperture).  The retained A90 evidence already proves,
for the eight known remapper/BIMC candidates, TZ-owned MPU coverage with no
HLOS VMID grant in both policy branches; a fixed EL1 load at `0x09248080`
ended in a watchdog, and `/dev/mem` is unavailable under the current kernel.
That is `PROVED` for the tested candidates, not global aperture absence.  A
static writer identification without a reachable hole therefore remains
research value only and does not reopen a security route.  No new 1b write,
SCM mutation, XPU/SMMU change or protected-memory access is justified by the
external commits.

## Current conclusion

The imported literature, V019 result and route analysis do not change
`CLASS C (TRANSFORM ONLY)` or numbered Experiments 015/016 `NOT_ELIGIBLE`.
The V019 raw-receipt gap is closed for the tested deep-suspend transition, but
global/other-state mutability and the unknown parts of 1b remain.  The bounded
1b checkpoint is recorded separately; 020K/020L remain host-only/read-only
static work.

## Integration validation

The additive V015 bus-vote amendment focused suite is 9/9 PASS, the V019
synthetic detector/gate suite is 24/24 PASS, the private-receipt guard is 5/5
PASS, and the 1b checkpoint suite is 9/9 PASS.  The post-V019 repository suite
and post-020L suite are recorded in their respective integration reviews;
`git diff --check` passes for this audit.  This document itself performed no
device action; the retained V019 transition record states its reversible
device actions and restoration.
