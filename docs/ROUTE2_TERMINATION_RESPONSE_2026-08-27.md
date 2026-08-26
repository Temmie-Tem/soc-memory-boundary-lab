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

**V019: not integrated here.**  The external branch reports commit `96f8d4c`
and a deep-suspend result, but its raw receipt and implementation are not part
of this repository's retained evidence.  That report is a lead for a separate
reconciliation, not proof in this line and not an automatic closure of reopen
condition 3.

## Q4 — contradiction with rank three

**`UNKNOWN`.**  This response does not contain the complete 029–034 raw row set
or an independent comparison manifest.  It therefore does not count “no
contradiction” by concurrence.  A future audit must reparse those exact rows in
their declared coordinate domain and compare them with the retained V015/V016
algebra.  V015/V016/V017 agreement alone is not a review of every 029–034 row.

## External integration delta

The following external-branch commits were reported for review.  Only the V017
logic was imported after source inspection; the remaining items stay labelled
as external until their artifacts are independently retained:

| Commit | Reported content | Status in this repository |
|---|---|---|
| `c91f473` | initial V017 bank-granularity audit | superseded by the hardened V017 files and manifest `...-05` |
| `db22fb1` | BadRAM/DisARMed/PMPlease/Battering RAM reuse review | external reference; no unlicensed code vendored |
| `0d2c1bf`, `ace5e9b` | external V018 implementation/acquisition | superseded by retained `49c3381` V018 implementation |
| `96f8d4c` | deep-suspend cross-state test | external reference; not yet integrated or counted |
| `5323d17` | wording corrections and retained transcript | external reference; relevant cautions are recorded here |
| `865593b` | remaining-route/XPU/signature analysis | external reference; source/evidence reconciliation pending |

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
