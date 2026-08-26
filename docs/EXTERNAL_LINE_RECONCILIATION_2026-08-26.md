# External 019A–030 line reconciliation — 2026-08-26

## Integration boundary

This review preserves the independently produced branch exactly through pinned
merge parent `247b0e1` while treating every
external claim as evidence to revalidate, not authority. The current branch
was based at Experiment 034 artifact commit `d5d8046`; the merge base is
`84f9def`. A read-only `git merge-tree` and the final `merge --no-ff
--no-commit` showed no path conflict: the external line contributes 39 files,
and Experiment 034 remains present. The moving branch name is not the input
identity.

After this merge began, `research/xbl-config-cdt` advanced through
`05a4c5c`, `4b78b61`, `a297fde`, `b2b5068`, `6b3abc7`, and `c91f473`.
Those commits and their runtime-transition, retraction/power-cycle, PA25–27,
and post-decode-check results are not in this tree, were not reviewed for this
iteration, and are not promoted here. Verification 015 remains outside this
pinned merge and does not change Experiments 015/016 eligibility.

The imported history includes original commits for 019A–022A, 023/023R, 028,
029A and 030 plus the external merge through main's Experiment 033. The `A`
suffix preserves independently assigned number collisions; it does not make an
A-line result newer or more authoritative than the bare-number main result.
Where claims conflict, exact counterexamples and current bounded semantics win.

No device, USB, SMC, MMIO, memory, boot, partition, or write action occurs in
this reconciliation. It reuses exact retained private inputs read-only and
publishes only redacted manifests. Class C remains `TRANSFORM ONLY`;
Experiments 015 and 016 remain `NOT_ELIGIBLE`.

## Audit findings that blocked direct promotion

The external line was not promoted unchanged. Primary and independent review
identified these material issues:

1. Experiment 030 merged duplicate difference keys from multiple acquisition
   phases with `dict.update()`. Later phase-D values silently replaced phase-C
   values, producing a manifest whose numeric rows did not match its README.
2. Experiment 022A claimed its two observation channels were complete even
   though exact known address `0x09248080` lies outside both. Completeness is
   `REFUTED`; density is descriptive coverage of the enumerated channels only.
3. Experiment 021A promoted absent local labels into a delivery refutation even
   though two of seven direct bounded-copy calls have `dcb_section=null`.
   Other-section/global/indirect delivery remains `UNKNOWN`.
4. Experiment 029A's extractor wrote filenames without `.bin`, while the 028
   audit consumed only `*.bin`. The documented command therefore did not
   reproduce the claimed ABL input set without an unrecorded rename.
5. Renumbering left stale experiment IDs, bare-test commands, and historical
   hashes presented as current. Historical producer identity and current
   verifier identity are now separated.
6. Experiment 023R's pagemap records are all `BLIND`. The unique base-offset
   solve can support an absolute allocation base only within its contiguous-
   qsecom plus Experiment-014-relation model; it is not direct physical-page
   provenance.
7. Experiment 029A inferred absence of runtime controller participation from
   absence of stored literals and repeated a live-DT property observation for
   which no retained DT payload/hash was present. Exact stored-form negatives
   are retained; computed/runtime participation and the live-DT property set
   are `UNKNOWN`.
8. Although the original 019A/020A UNKNOWN blocks already retained several
   global boundaries, other prose promoted syntactic pair arrays to register-
   programming semantics and overgeneralized local literal/consumer models.
   The reconciliation makes those claim levels consistent: pair arrays, local
   loops, direct literals and recognized consumers are bounded; implicit bases,
   alternative encodings, indirect paths and semantic identity remain
   `UNKNOWN`.

## Corrected behavioral evidence

### Experiment 023R

`PROVED`: the repaired observation protocol records 66 summaries over 58
unique differences, with 1001 repetitions, alternating order, 17 warmups and
the corrected divisor. It retains a separation threshold of 359 with an empty
gap from 182 through 537. In allocation-offset/model coordinates, exhaustive
discrimination retains bit-24 contribution `0b110` with 18 held-out
agreements, a nine-dimensional span has one consistent rank-three kernel, and
ranks one, two, four and five are refuted within that algebra.

`SUPPORTED_WITHIN_MODEL`: mapping those allocation-offset results to physical
PA24/rank three, the unique offset `0x0`, model base `0xa6000000`, and an
independent physical region. This requires a contiguous qsecom allocation and
the Experiment 014 relation over PA13..PA23. Direct physical page identity and
effective contiguity remain `UNKNOWN` because every pagemap record is `BLIND`;
the raw probe's reported `contiguous=true` is retained only as a reported field,
not evidence.

### Experiment 030

The corrected analyzer preserves every phase's median map, mode, pair count,
context and raw hash. It never selects a winner by filename order.

`PROVED`: spread-mode phase B measures PA10 as `506/500/464`, and phase C
measures PA9 as `717/702/702` and PA10 as `453/461/463`; the complete triplets
are `SATURATING`. Stride-mode phase D measures PA9 as `762/753/760`, also
`SATURATING`, but contains only PA10-alone `503`. Its two PA10 witness
combinations are absent, so phase-D PA10 is `INCOMPLETE`. The earlier mixed
manifest's phase-D PA10 `461/463` values came from another phase and are
discarded.

`REFUTED` within the measured reopen model: interpreting PA9/PA10 merely
leaving the conflict class upward as proof that they are independent channel
selectors. PA9 is cross-mode saturation evidence; PA10 saturation is supported
by complete retained spread-mode phases B and C, not a complete phase-D
cross-mode triplet. Whether either bit contributes jointly to channel, rank,
bank group or another coordinate, and the meaning of the larger penalty,
remain `UNKNOWN`.

## Corrected static evidence

### Experiment 028

`PROVED`: the validated 023R allocation-offset/model result yields seven
nonzero numeric covectors. Across the exact tested firmware set, two literal hits are
unaligned chance matches; the deterministic 200-decoy baseline is 0.66 hits per
mask. Among 494 decoded retained controller registers, 274 nonzero, the tested
register-mask, packed-index and adjacent-triple families produce zero matches.

`REFUTED` only for that observed set, those numeric masks and those encodings:
a decoded observed register directly storing a model covector. Physical-bank
attribution of the target set is `SUPPORTED_WITHIN_MODEL`, not proved. The 42 addresses over each
9,305-word ranked-instance span represent 0.4514% observed-span address
density, not implemented-register coverage. Everything outside the observed
set, derived state, writer identity and runtime mutation remain `UNKNOWN`.

### Experiment 029A

The extractor now emits deterministic flat `.bin` names with collision and
symlink guards, so the documented `*.bin` audit contract is executable without
an unrecorded rename. The exact ABL source is 4,194,304 bytes, SHA-256
`1db19d11a5ce6865e3fbcabadfbdaa9045e75f144b8bc8593a58338c20a3120c`.
The canonical decompressed payload is 4,763,976 bytes, SHA-256
`3fc653082e6acbfcfe3019c7d78b278326bc40de30a4f0325362fa6cce29011a`,
and contains Odin, LinuxLoader and Cryptest PE32 modules with individual hashes.

`PROVED`: exact stored u32 searches over the canonical decompressed payload
return zero listed qhs_mc/MCCC/MCCC-master base literals, zero validated 023R
model-mask literals and zero tested spanning adjacent triples. Physical-bank
meaning of those masks is `SUPPORTED_WITHIN_MODEL`. Exact ASCII counts are 2
error, 1 protocol, 1 revision, 3 type, 4 rank, 4 HBB and 1 unsupported-revision
diagnostic/property occurrence. These are static naming/encoding results only.
The PE32 modules are not disassembled; computed values, execution, controller
participation/writes and the SMEM DDR-info value remain `UNKNOWN`. The prior
live-DT property statement is `UNRETAINED_UNKNOWN` because no exact retained
DT payload or hash is an input.

### Experiments 019A–022A

These are retained as complementary bounded analyses, not replacements for
main's 019–022. Candidate DCB pair-array shapes, register-offset and computed-
address censuses, local copy callers and observation-channel density may inform
new hypotheses. They do not establish a register-table semantic identity,
implicit base, runtime consumer, writer, current destination, or global
absence. Main's corrected 021 and 022 boundaries remain controlling wherever
the A-line prose previously overreached.

## Artifact pins

Historical producer pins and current tool/test hashes are recorded in each
experiment README. The reconciled public manifests are:

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| 019A DCB candidate arrays | 39,876 | `54ec8762ec8c437cd4b29690fc37376892608f3ed5e53d2eec0a2f56009baea1` |
| 020A bounded XBL cross-reference | 24,006 | `ed6cd5e988cbf5af67f8fd88a949b90b7169967265e44631b3acd23c14719572` |
| 021A bounded delivery paths | 10,213 | `05ed171f960ea909f71eeea2127e9f26e016e510b4d39dbb390758d3c09b8955` |
| 022A observation coverage | 17,216 | `7e365211af1b92fc5b26788fad1cfca47c436e10d1a2bea8dce7ad75d513ca9e` |
| 023 historical withheld result | 7,090 | `297ecfcbfd8a47a61b18ba4f6e957d393ea4bdaeccb9954cac6705fc4637e953` |
| 023R repaired model result | 18,040 | `5c3e14ff898c109de740d98260d974bca10751000f85977775cd467ac74aac2e` |
| 028 bounded encoding audit | 7,330 | `1ac85954028ef16071c654c5704600285bae09650888424f9756de1215b3351b` |
| 029A ABL extraction | 4,679 | `ce127f159db7008d1846750f73685e4afb081c7a769d65e0ea1ccf1afd92f701` |
| 029A ABL numeric-mask audit | 6,423 | `ab70da1d900337622780ae26f820971f3df8a6714b99e1f81fdcabf9e084fbf4` |
| 029A ABL semantic audit | 13,480 | `4f2bbff05a6bb2bc3ed3f6f6522d04689570d4121d3d7dfd7c674b2065788db5` |
| 030 phase-preserving low-bit result | 25,831 | `28f167a67a8d32c56a227e01f93ea243ff9bb2eb1ba4bb1007524b9c71b0a73f` |

Command strings containing `<...>` are explicitly labelled
`REDACTED_REPRODUCTION_TEMPLATE`; they are not executed-command receipts.
Exact logical inputs and dependency manifests are pinned by size/hash.

## Validation and security disposition

No imported or corrected result establishes transform-state mutation,
physical-to-DRAM aliasing, protected-memory reach, or a protection-check/
destination mismatch. The evidence improves the measured transform model and
removes several static encodings and one low-bit interpretation. It does not
meet either Experiment 015 or 016 gate.

- Primary combined external suite: **296/296 PASS**, maximum RSS **142,124
  KiB**, swap **0**. Final changed subset: **92/92 PASS**, maximum RSS **53,080
  KiB**, swap **0**.
- Final repository discovery: **995/995 PASS** in **108.700 s**, maximum RSS
  **272,988 KiB**, swap **0**.
- Python byte-compilation, `git diff --check`, and every public-manifest JSON
  parse pass. No public manifest contains a private absolute path or raw
  firmware bytes.
- Ten promoted/reconciled manifests regenerate byte-identically from exact
  retained inputs. Fresh publisher outputs were observed as mode `0644`; exact
  checked-out POSIX permission bits are not part of Git artifact identity. The historical 023
  artifact is retained as `WITHHELD/NO-GO`, not promoted.
- Independent hostile review drove repair of phase mixing, claim scope,
  dependency identity, zero-register semantics, model/physical coordinate
  separation, command-template labeling and mode portability. Final code and
  artifact review is **PASS** with no remaining P0–P2.

`PASS`: exact external parent `247b0e1` is reconciled as bounded evidence.
Class C remains `TRANSFORM ONLY`; no alias, mutation, protected reach or bypass
is proved or globally refuted. The next iteration is a separate, commit-pinned
audit/repair of later Verification-015 runtime-invariance evidence. It must not
merge the moving branch tip wholesale and must retain `REPEAT_REQUIRED` until
raw paths, provenance, six-level scope, repeat evidence and recovery/final-
state receipts are reconciled.
