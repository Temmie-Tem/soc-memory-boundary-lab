# Config/CDT integration review — 2026-08-26

This review integrates the host-only Experiments 019–022 from commit
`3dfa725` into the common research narrative. It records public, bounded
claims only; raw firmware, dumps, device identifiers and private evidence are
not reproduced here.

## Validation

- Independent focused validation: **157 PASS**.
- Full repository unittest discovery: **504 PASS**.
- Four manifest regenerations were **byte-identical**.
- Cached-tree review: **PASS**.
- Mode for the integrated experiments: `HOST_ONLY_READ_ONLY`; no device, SMC
  or MMIO action.

## Integrated conclusions

| Experiment | Integrated conclusion |
|---:|---|
| 019 | `PROVED`: strict syntactic candidate pair arrays exist in two key domains. They are not proved register tables or consumers. Absolute keys do not hit ranked MC bases. Sections, implicit bases, consumers, register semantics and writer identity are `UNKNOWN`. Bounded stored/exact-wide/ORR materialisation finds `0x00003333` and `0x00300014` absent; `0x00300033` has two adjacent sequences. No writer absence is claimed. |
| 020 | `PROVED`: the bounded register-offset census, exact candidate-segment store observations, and pinned false negative at `0x14868a50`. `SUPPORTED`: treating the largest RWE segment as a candidate by size/content only. Its controller identity, general walkers, DCB consumers, and writer identity remain `UNKNOWN`. |
| 021 | `PROVED`: the pinned bounded-copy target has seven direct `BL` and zero direct `B` edges. Only five are locally labelled `{0,1,2,15,16}`; two are unlabelled. Other-section direct/global delivery is `UNKNOWN`, not refuted. |
| 022 | `PROVED`: `430/470/122/492` are counts for two enumerated retained-evidence channels only, with sparse observed density. Completeness is `REFUTED` by known `0x09248080`; implemented-register coverage is `UNKNOWN`. |

Class remains `C (TRANSFORM ONLY)`. Experiments 015 and 016 remain
`NOT ELIGIBLE`.

## Withheld and next stage

At this review's integration boundary, Experiment 023 was explicitly
`WITHHELD/NO-GO` and not public. A later external-line reconciliation retains
its audit artifact as merge-history evidence without promoting it; Experiment
023R is the separately repaired result.
Its protocol is not comparable to Experiment 014 (fixed order, half warmup,
`ISB`, summed reopen without `/2`); physical allocation PA provenance is
missing, so a `+0x1000` countermodel fits the labels; and the full GF(2)
matrix is non-unique. `PA24=b1^b2` is `SUPPORTED` only. Raw evidence remains
private.

Experiment 024 is the highest-information next host-only step. Its design
must resolve Experiment 020's exact six-byte walker, three direct callers/table
providers, runtime-base provenance and XBL-local table alternatives, followed
by a cross-check of two pinned A90 design-source snapshots. Neither is the
live DTB; live-DTB identity remains `UNKNOWN`. The design observations are
`HYPOTHESIS`/next-stage until a qualified, independently reviewed 024 manifest
is committed and integrated. See
[NEXT_EXPERIMENT_SCORECARD.md](NEXT_EXPERIMENT_SCORECARD.md). No device action
or MMIO write is authorized by this review. Every-success-path base
preservation is itself `UNKNOWN` until the unresolved `BLR X9` at
`0x1486ac1c` (reached from helper `0x1486abec`) is accounted for; absence of
main/local direct stores does not prove current-base preservation.
