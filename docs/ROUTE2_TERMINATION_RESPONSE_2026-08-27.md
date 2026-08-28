# Route-2 termination response — 2026-08-27

This is an independent response to
`docs/CODEX_HANDOFF_ROUTE2_TERMINATION_2026-08-27.md`.  It is a falsification
record, not a consensus request.  A statement is counted only when its exact
source or retained artifact is available in this repository; an external
branch reference is labelled as such and does not silently promote a claim.

## Accepted corrections

The privilege-difference framing describes the routes tested so far.  It is not
an exhaustion proof and must not be used as one.  A zero or negative privilege
difference means only that no eligible primitive has been established in the
tested scope.

The four V018 findings are accepted.  In particular, the two-VA same-dma-buf
positive control required by `docs/NORMAL_RAM_ALIAS_DESIGN.md` was absent from
the earlier implementation; the retained A90 acquisition in
`verification-018-a90-20260827-02` uses the repaired implementation and both
controls.  Its result remains allocation-local, not physical-PA evidence.

## Q1 — writer/register route

**`SUPPORTED` bounded closure; `UNKNOWN` global closure.**  The retained
029–034 reviews close only their bounded static models: no source-pinned,
reachable producer to a ranked transform register is promoted.  They preserve
dynamic bases, indirect calls, unsupported forms, runtime execution/currentness
and global writer identity as `UNKNOWN`.  The parent memory-map evidence also
records TZ-owned MPU coverage with no HLOS grant over the known remapper/BIMC
apertures and one fixed EL1 load ending in a watchdog.  This is access-control
evidence for the tested apertures, not a global writer-absence proof.

Reopen condition 1 is therefore amended: a source-pinned writer/effective
address is a research lead, but the security route reopens only when the
aperture is also demonstrably reachable from Normal World under a testable
precondition.  Track this as 1a (identification) and 1b (reachability) if useful.

## Q2 — post-decode granularity

**`PROVED` only for the narrow bank-only shape in the retained
allocation-offset/model projection; actual ordering is `UNKNOWN`.**  The pinned
V016/023R relation has rank three and a minimum class-change span of 8 KiB.  A
64-KiB span covers all eight classes when aligned to a 64-KiB block; at an
arbitrary base the conservative guarantee is 128 KiB.  The V017 tool tests the
alignment-sensitive statement and the base countermodel explicitly.  Every
listed protected carveout and every explicitly unprotected comparison range is
at least 128 KiB (or aligned), so a check observing only the post-decode bank
index cannot separate those ranges under the model projection.

The repaired public manifest is `...-05` (18,108 bytes, SHA-256
`97ff68a2f8ebfb6313f228f2626f12f88260764a993f916ba1f97677d7b99f02`); it
semantically matches the pinned 023R kernel basis and MEMORY_MAP ranges before
calculating the histograms.

This does not identify QHEE/TZ/XPU ordering, prove a complete DRAM coordinate,
prove physical contiguity, or show that a transform is mutable.  It is a
granularity exclusion, not a physical-isolation or bypass result.

## Q3 — V018/V019 gates

**V018: `PROVED` within the bounded acquisition scope.**  The live receipt,
source/binary/build pins, strict 190-record parser, two controls, sidecars,
cleanup/absence proof and final health are independently revalidated.  Pagemap
is `BLIND`; physical mapping, contiguity and complete-coordinate alias remain
`UNKNOWN`.

**V019: `PROVED`/`REFUTED` within a bounded scope.**  The public analyzer,
tests and manifest from external commit `96f8d4c` are integrated additively,
and follow-up `1bc494e` retains the original receipt plus an independent
second deep-suspend receipt.  Both corroborated runs report zero moved tags in
the declared offset domain; a cable-attached control is explicitly
`SUSPEND_NOT_REACHED`.  This refutes a map change only for that tested
deep-suspend transition and domain.  Physical contiguity, complete
coordinates, other state transitions and global mutability remain `UNKNOWN`;
it does not close every form of reopen condition 3.  See
`docs/VERIFICATION019_INTEGRATION_REVIEW_2026-08-27.md` and
`docs/VERIFICATION019_RAW_RETENTION_2026-08-27.md`.

## Q4 — contradiction with rank three

**`UNKNOWN`.**  The independent Route-2 audit is now recorded in
`evidence/manifests/route2-rank-audit-20260827-01.manifest.json`.  It validates
the exact 029–034 bytes, site/transition metadata, 030's inherited rank-3
dependency, and the absence of explicit relation rows in the declared fields.
It still does not contain the complete 029–034 raw relation-row set, so it does
not count “no contradiction” as a global result.  V015/V016/V017 agreement and
this bounded field audit are not a review of unretained raw rows; Q4 remains
open to a retained algebraic counterexample.

## External integration delta

The following external-branch commits were reported for review.  The current
branch now carries additive artifacts where appropriate and keeps repaired
equivalents authoritative; each status below is bounded rather than a claim
that the external commit is an ancestor:

| Commit | Reported content | Status in this repository |
|---|---|---|
| `c91f473` | initial V017 bank-granularity audit | superseded by the hardened V017 files and manifest `...-05` |
| `db22fb1` | BadRAM/DisARMed/PMPlease/Battering RAM reuse review | integrated additively as `eb2f44d`; no unlicensed code vendored |
| `0d2c1bf`, `ace5e9b` | external V018 implementation/acquisition | superseded by retained `49c3381` V018 implementation |
| `96f8d4c` | deep-suspend cross-state test | integrated additively as `8c3d1c5`; raw-receipt gap closed by local `1bc494e`, with two bounded `MAP_INVARIANT` runs |
| `5323d17` | wording corrections and retained transcript | wording/access-control corrections are integrated; bus transcript is tracked as a separate supplementary amendment |
| `865593b` | remaining-route/XPU/signature analysis | integrated additively as `0e6bfd5`; exact claims retain their labels |

The complete 14-commit disposition, including the repaired-equivalent
replacements for `05a4c5c`, `a297fde`, `b2b5068`, `6b3abc7`, `c91f473`,
`0d2c1bf`, `ace5e9b`, `5323d17`, `b33339b` and `99eb1dc`, is recorded in
`docs/EXTERNAL_LINE_INTEGRATION_2026-08-27.md`.  Current repaired analyzers
are intentionally not overwritten by weaker add/add implementations.

The 99eb1dc audit was independently re-run against the current retained 033
and 034 manifests: both `sites` arrays are canonical-JSON identical (71/71),
the site-35 baseline still carries `status`, `current_destination` and
`writer_absence` as `UNKNOWN`, and two fresh 034 generations are byte-identical
to the retained manifest.  These checks strengthen the bounded audit, but do
not create the missing complete relation-row set; Q4 therefore remains
`UNKNOWN`, consistent with the more conservative current disposition.

## 1b — known-aperture reachability checkpoint

The bounded 1b checkpoint is now independently implemented and host-validated
from exact public hashes.  Both selector branches enumerate the same eight
known qhs_llcc-remapper/BIMC candidates; every candidate is covered by
TZ-owned `MEMNOC_MS_MPU` and `CNOC_SNOC_MS_MPU` hits with no HLOS read/write
grant.  The tested `0x09248080` narrow region is branch-invariant.  The fixed
EL1 load produced no value before the retained `Non Secure Watchdog Bark`, and
the separate control-node route recorded one failed read and zero writes.

This is `PROVED` only for those eight static-policy candidates and
`SUPPORTED` as a constraint on their tested Normal-World route.  It is not a
global reachability or writer-absence proof: alternate apertures, final
runtime state, exact watchdog causality, enforcement ordering, transform
mutability, physical mapping, aliases and bypass remain `UNKNOWN`.  The
public 13,885-byte manifest is
`evidence/manifests/verification-1b-known-aperture-reachability-20260827-01.manifest.json`
with SHA-256
`b4135f22bff47df22cda674eeabfff909ef4d3bc2a1843b358be7556b6d5ff02`;
focused tests are 9/9 PASS.  This does not promote a controller write or
protected-memory test, and Class C / `NOT_ELIGIBLE` remain unchanged.

## Conditional endpoint

The endpoint may be stated only conditionally:

```text
No tested route currently supplies a Normal-World transform mutation or a
complete physical-to-DRAM non-injective map, while every bounded static route
preserves its dynamic and access-control unknowns.
```

This is not “no writer exists”, “no alias exists globally”, “SM8150 is
unaffected”, or “the AMD class is impossible”.  Reopen on a reachable,
source-pinned transform writer; a physically proved contiguous non-secure pool
of at least 512 MiB; a controlled state transition that changes the map; or a
deterministic non-injective complete-coordinate relation.  A protected-boundary
indicator switches immediately to minimum-evidence disclosure mode.
