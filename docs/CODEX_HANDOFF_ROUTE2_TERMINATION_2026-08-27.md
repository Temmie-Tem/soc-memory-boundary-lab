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
| 029–034 frontier | integrated in `STATUS.md`, `docs/EXP029_*` through `docs/EXP034_*` | Arithmetic, memory-form, system-control and site-35 bounded models close to 71 `NO_TARGET_WITHIN_MODEL` rows, but dynamic/indirect/runtime writer identity remains UNKNOWN. |
| New V018 baseline work | current change, live evidence `verification-018-a90-20260827-02` | Strict 190-record allocation-local marker oracle, exact type-10/id-30 `camera_preview` gate, source/binary/build/receipt pins, sidecar transcript checks and synthetic controls are now retained. The live result is `NO_ALIAS` only over 176 exact one-state allocation-offset pairs; pagemap is `BLIND`, so it is not physical alias evidence. |

The external V015/V016 source commits and the integrated parent must be kept
distinct.  A moving branch, operator report, or unretained transcript cannot
promote a claim above the exact retained artifact.

## Four falsification questions

### 1. Did 029–034 leave a live route to register/writer identification?

**Current answer: SUPPORTED bounded closure, UNKNOWN global closure.**  The
exact rows in 029–034 report zero bounded DCB-consumer/MC-symbolic-target paths
where their model can resolve one, and site 35 is now closed inside its guarded
table model.  The same records explicitly preserve dynamic bases, indirect
calls, runtime execution/currentness, unsupported instructions and global
writer identity as `UNKNOWN`.  Therefore the route is not a proved live writer
path, but it is also not a global absence proof.

To falsify this answer, identify an exact, source-pinned path from an executed
or reachable producer to a ranked MCCC/MC/DDRSS transform-state register,
including effective address, width, writer and a runtime or boot-stage
precondition.  A numeric literal, table membership, or bounded no-target row is
not sufficient.

### 2. Does the V017 post-decode-granularity argument hold?

**Current answer: UNKNOWN / separate audit required.**  V016 now satisfies the
input dependency gate, but no integrated V017 audit has been accepted.  A bank
only relation or a diagnostic coordinate model does not establish a complete
post-transform coordinate, and neither one locates QHEE/TZ/XPU enforcement
relative to final DRAM decode.  The audit must preserve that distinction and
must not turn a granularity argument into a physical-isolation proof.

To falsify the bounded argument, show from exact retained algebra and address
domains that the claimed granularity conclusion is invalid, or show a concrete
post-transform enforcement ordering that changes the implication.  If neither
is available, retain `UNKNOWN`, not `PROVED`.

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

**Current answer: no contradiction in the retained bounded coordinates;
physical attribution remains UNKNOWN.**  The 029–034 static results concern
candidate writer/data-flow paths, not the measured relation’s full physical
coordinate semantics.  V015 preserves cross-condition label invariance, and
V016 adds model bits 25–27 with the same rank-three shape in its declared
allocation-offset/model scope.  None of those facts identifies PA bits, a
controller register, or a complete DRAM map.

To falsify this answer, provide an exact retained observation or algebraic
counterexample in the same declared coordinate domain that requires rank four
or otherwise violates the repaired kernel/match tests.  A different runtime
environment, a stale unretained sweep, or a semantic guess about one ranked
register is not a contradiction.

## Reopen conditions

Any one of the following reopens the investigation and cancels a termination
claim:

1. **Reachable register identification:** an exact writer path reaches a
   transform-state register through a source-pinned effective address and a
   testable boot/runtime precondition.
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
