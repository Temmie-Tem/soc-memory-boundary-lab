# Codex handoff — route-2 termination challenge (2026-08-27)

This document is a challenge handoff, not a consensus request.  The purpose is
to make the independent line try to falsify the current Class-C boundary before
any termination claim is accepted.  A reviewer must use the retained source,
raw-input pins, manifests and commit graph, not this summary alone.

## Current proposition under challenge

`CLASS C (TRANSFORM ONLY)` remains the current disposition.  The strongest
retained result is a three-dimensional XOR bank-selection relation observed in
normal, non-secure allocation-offset/model coordinates.  No transform-state
write, complete-coordinate alias, protected-memory reach or boundary bypass is
proved.  The fact that a privilege difference is zero or negative is not by
itself a proof that the route is exhausted; it only means that no eligible
primitive has been established in the tested scope.

The proposed endpoint is therefore conditional:

```text
No tested route supplies a Normal-World transform mutation or a complete
physical-to-DRAM non-injective map, while every bounded static route remains
explicit about its unsupported/dynamic residuals.
```

This wording must not be strengthened to “no writer exists”, “no alias exists
globally”, or “the AMD class is impossible on SM8150”.

## Integration delta that must be reviewed

The earlier external line knew only its V015-era material.  The current exact
parent and subsequent repairs add the following evidence and corrections:

| Item | Current evidence / commit | Effect on the challenge |
|---|---|---|
| V015 invariance repair | `1182f12` (source external `05a4c5c`) | Four clean condition comparisons agree on all 51 labels; weak L762 remains `REPEAT_REQUIRED`; the TWRP “5931 cliff” is removed as an unretained environment artifact. |
| Review response | `787c8b4` (external `4b78b61`) | Seven concrete source/evidence defects are upheld and recorded; the eighth is rejected because it restated an existing UNKNOWN boundary; the 0o644 portability issue is reported but not imported. |
| V016 high-bit repair | `746def0` | Separate PA25/26/27 model-bit contributions are retained with two-pass consistency and 7/7 held-out model agreement; physical PA/base/contiguity remain UNKNOWN under BLIND pagemap. |
| V017 granularity audit | current change, live memory-map input and 023R kernel basis semantically pinned | In the retained allocation-offset/model projection, the exact rank-3 relation covers all eight bank classes in a 64-KiB-aligned 64-KiB span (128 KiB arbitrary-base guarantee); the narrow bank-only post-decode enforcement shape is refuted as a separator for the listed protected/unprotected ranges. Countermodels leave complete-coordinate injectivity underdetermined; actual ordering remains UNKNOWN. |
| 029–034 frontier | integrated in `STATUS.md`, `docs/EXP029_*` through `docs/EXP034_*` | Arithmetic, memory-form, system-control and site-35 bounded models close to 71 `NO_TARGET_WITHIN_MODEL` rows, but dynamic/indirect/runtime writer identity remains UNKNOWN. |
| New V018 baseline work | current change, live evidence `verification-018-a90-20260827-02` | Strict 190-record allocation-local marker oracle, exact type-10/id-30 `camera_preview` gate, source/binary/build/receipt pins, sidecar transcript checks and synthetic controls are now retained. The live result is `NO_ALIAS` only over 176 exact one-state allocation-offset pairs; pagemap is `BLIND`, so it is not physical alias evidence. |

The external V015/V016 source commits and the integrated parent must be kept
distinct.  A moving branch, operator report, or unretained transcript cannot
promote a claim above the exact retained artifact.

## Four falsification questions

### 1. Did 029–034 leave a live route to register/writer identification?

**Current answer: SUPPORTED bounded closure, UNKNOWN global closure.**  The
retained 029–034 reviews report zero bounded DCB-consumer/MC-symbolic-target
paths where their model can resolve one, and site 35 is closed inside its
guarded table model.  The same records explicitly preserve dynamic bases,
indirect calls, runtime execution/currentness, unsupported instructions and
global writer identity as `UNKNOWN`.  Therefore the route is not a proved live
writer path, but it is also not a global absence proof.  Separately, the parent
memory-map evidence proves no HLOS grant over the known remapper/BIMC apertures
and one fixed EL1 load fails; a static writer identification alone would not
make an aperture reachable.

To falsify this answer, identify an exact, source-pinned path from an executed
or reachable producer to a ranked MCCC/MC/DDRSS transform-state register,
including effective address, width, writer and a runtime or boot-stage
precondition.  A numeric literal, table membership, or bounded no-target row is
not sufficient.

### 2. Does the V017 post-decode-granularity argument hold?

**Current answer: PROVED only for the narrow bank-only shape in the retained
model projection; actual ordering remains UNKNOWN.**  The exact pinned V016/023R
relation has a minimum class-change span of 8 KiB.  A 64-KiB span covers all
eight classes when aligned to a 64-KiB block;
for an arbitrary base the conservative guarantee is 128 KiB.  Every listed
protected carveout and every explicitly unprotected System RAM comparison
fragment is at least 128 KiB (or aligned), so a check that sees only the
post-decode bank index cannot separate those ranges.  The corrected result is
recorded in `verification-017-protection-bank-granularity-20260827-05.manifest.json`
(18,108 bytes, SHA-256
`97ff68a2f8ebfb6313f228f2626f12f88260764a993f916ba1f97677d7b99f02`).

The result does not establish a complete post-transform coordinate, locate
QHEE/TZ/XPU enforcement relative to final DRAM decode, or prove a mutable
downstream transform.  Those remain `UNKNOWN`; the result must not be turned
into a physical-isolation or bypass conclusion.

To falsify the bounded argument, show from the exact retained algebra and
declared address domains that a listed range fails the eight-class coverage, or
provide a concrete post-transform enforcement ordering that changes the
implication.  A complete-coordinate or controller-level claim is not a
counterexample to this bank-only statement.

### 3. Do the V018/V019 gates contain a defect?

**Current answer: V018's exact live acquisition is validated within its bounded
allocation-local scope; V019 remains separately scoped.**  The V018 analyzer
rejects malformed, partial, duplicated or reordered 190-record transcripts,
recomputes markers and sentinels, requires both controls, and keeps physical
provenance UNKNOWN.  An independent review found that an allocation-local WC
oracle is not a physical PFN/PTE/SG alias proof and that a caller-selected binary
must be pinned before bridge contact; those P1s are now closed by the retained
source/binary/build and live receipts.  The validated result still does not
promote the old unretained V018 manifest into a physical claim.  V019’s retained
status and scope must be checked from its own files; no V018 result may transfer
into its row.

To falsify this gate, demonstrate a concrete parser/probe/receipt path that can
produce an admissible negative while a control, exact binary/source pin, cleanup,
final health, or target binding is false.  A successful synthetic self-test is
not device authority.

### 4. Does any 029–034 result contradict the rank-3 relation?

**Current answer: UNKNOWN, with a bounded field audit complete.**  The
independent Route-2 manifest validates the exact 029–034 bytes, stable site and
transition metadata, 030's inherited rank-three dependency, and the absence of
explicit relation rows in the declared 029/031–034 fields.  It does not contain
the complete raw relation-row set, so it must not count “no contradiction” as a
global result.  V015 preserves cross-condition label invariance, V016 adds model
bits 25–27 with the same rank-three shape, and V017's source cross-check agrees
with those equalities; none of those facts reviews unretained raw rows.

The audit artifact is
`evidence/manifests/route2-rank-audit-20260827-01.manifest.json` (9,607 bytes,
SHA-256
`ec3ec693768bf1294366c5650ab9c5e76b27f9bdce049c7a6f2b205a00a72fb8`).  To
reopen Q4, provide an exact retained observation or algebraic counterexample in
the same declared coordinate domain that requires rank four or otherwise
violates the repaired kernel/match tests.  A different runtime environment, a
stale unretained sweep, or a semantic guess about one ranked register is not a
contradiction.

## Reopen conditions

Any one of the following reopens the investigation and cancels a termination
claim:

1. **Reachable register identification:** an exact writer path reaches a
   transform-state register through a source-pinned effective address and a
   testable boot/runtime precondition, **and the aperture is demonstrably
   reachable from Normal World**.  Identification without a reachable hole is
   research value, not a security-route reopening.  These may be tracked as
   1a (identification) and 1b (reachability) if needed.
2. **Large ordinary-RAM pool:** a reproducible non-secure, physically proved
   contiguous allocation of at least 512 MiB is available with PFN/PTE/SG
   identity and no secure/protected ownership.
3. **Moving map:** a controlled, reversible state transition changes the
   observed physical-to-DRAM relation and the change survives cache, virtual,
   DMA and IOMMU negative controls.
4. **Non-injective map:** any state yields a repeated complete DRAM coordinate
   for distinct, kernel-proved physical pages, or an equivalent deterministic
   alias that survives the required controls.

The first two conditions reopen route feasibility; the last two are security-
relevant indicators.  If a protected carveout is reached or a protection check
is bypassed, stop broad probing and switch to minimum-evidence disclosure mode.

## Review protocol

The independent reviewer should answer the four questions with one of
`PROVED`, `SUPPORTED`, `HYPOTHESIS`, `UNKNOWN`, or `REFUTED`, cite exact files
and lines, and list any counterexample.  “I agree” is not a sufficient result.
If questions 3 or 4 are falsified, the endpoint is cancelled and the next
experiment is selected from the new discriminator.  If all four survive, the
result is still a conditional Class-C endpoint with the reopen conditions above,
not a global Qualcomm or AMD non-vulnerability claim.

## Integration update — 2026-08-27

The external `research/xbl-config-cdt@99eb1dc` line has been audited against
the current repaired branch.  Its additive literature review, remaining-route
analysis and V019 public analyzer are integrated without replacing the repaired
015/016/017/018 implementations.  V019 is currently
`SUPPORTED_EXTERNAL_MANIFEST_ONLY`: its public manifest reports a corroborated
deep-suspend null, but the private raw receipt is not present in this worktree.
The complete commit-by-commit disposition is in
`docs/EXTERNAL_LINE_INTEGRATION_2026-08-27.md`.

The 1b checkpoint is explicit: for the eight known remapper/BIMC candidates,
the retained TZ policy covers the apertures with no HLOS grant and the fixed
EL1 load at `0x09248080` watchdogs.  This is `PROVED` for those tested
apertures, not global absence.  Static identification without a demonstrably
reachable hole remains research value only and does not reopen the security
route.  Q4 remains `UNKNOWN` because the complete 029–034 relation-row set is
not retained.

That checkpoint is now implemented as a separate host-only artifact.  Both
selector branches were parsed from exact hashes and yielded the same eight
candidate addresses with TZ-owned broad coverage and no HLOS read/write grant;
the fixed-load and control-node observations were revalidated as bounded
evidence.  Global reachability, alternate apertures, final runtime policy,
watchdog causality, ordering, mutability and bypass remain `UNKNOWN`.  The
13,885-byte manifest is
`evidence/manifests/verification-1b-known-aperture-reachability-20260827-01.manifest.json`
with SHA-256
`b4135f22bff47df22cda674eeabfff909ef4d3bc2a1843b358be7556b6d5ff02`; its
focused suite is 9/9 PASS.  The result remains Class C and does not authorize
020K to leave its host-only/read-only scope.
