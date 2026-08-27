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
| `96f8d4c` | deep-suspend permutation experiment | `INTEGRATED_EXACT` as additive commit `8c3d1c5`; public manifest is retained, but the private raw receipt is absent here, so live result is `SUPPORTED_EXTERNAL_MANIFEST_ONLY` |
| `5323d17` | V015 bus-vote transcript and V017/V018 wording corrections | `INTEGRATED_PARTIAL`: 128 KiB arbitrary-base wording and access-control distinction are current; the bus transcript remains a supplementary evidence task, and no overstrong “unrestored vote” claim is imported |
| `865593b` | four-route/XPU/signature analysis | `INTEGRATED_EXACT` as additive commit `0e6bfd5`; claims retain `PROVED`/`SUPPORTED`/`UNKNOWN` labels |
| `b33339b` | route-2 response and V017/V018 corrections | `INTEGRATED_PARTIAL`: handoff wording and scope repairs are current; current repaired files are preserved rather than add/add overwritten |
| `99eb1dc` | 029–034 Q4 audit amendment | `INTEGRATED_AUDIT_ONLY`: the audit is reviewed, but Q4 remains `UNKNOWN` because the complete relation-row set is not retained |

The additive commits are now in the current branch as `eb2f44d`, `8c3d1c5`
and `0e6bfd5`; the remaining dispositions are represented by this audit and
the current exact artifacts.  No external branch reset, force update, or
device action occurred.

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

The imported literature, V019 public result and route analysis do not change
`CLASS C (TRANSFORM ONLY)` or numbered Experiments 015/016 `NOT_ELIGIBLE`.
The highest residuals are the missing V019 raw receipt and the global/unknown
parts of 1b, not a reason to overwrite repaired evidence.  The bounded 1b
checkpoint is now recorded separately; 020K is therefore the next candidate,
still constrained to host-only/read-only analysis.

## Integration validation

The additive V015 bus-vote amendment focused suite is 9/9 PASS, the imported
V019 synthetic detector/gate suite is 23/23 PASS, and the 1b checkpoint suite
is 9/9 PASS.  After those files and the documentation updates were present,
the repository discovery suite was run once serially: **1,275/1,275 PASS**,
`skipped=1`, elapsed 156.785 s, maximum RSS 357,788 KiB, swap 0, exit status
0.  `git diff --check` also passed.  No device, USB, reboot, MMIO, SCM,
protected-memory or partition action occurred during this integration.
