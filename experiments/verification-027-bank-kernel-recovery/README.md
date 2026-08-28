# Verification 027 — polynomial-time bank-kernel recovery from retained timing

`docs/BROAD_SURVEY_2026-08-27.md` recorded Knock-Knock (arXiv 2509.19568) as a
live literature line this project had not used, and the final report listed the
port as `not started`. This is the port, run against the corpus this project has
already collected. No device was touched and no allocation was made.

## The reformulation

The existing method tests candidate masks one at a time, which is exponential in
the number of address bits. Every measurement already answers a linear question:

    XOR difference d collides in the row buffer  <=>  same bank  <=>  f(d) = 0

so each CONFLICT says `d ∈ ker f`. The span of the observed conflicts is a lower
bound on the kernel, and Gaussian elimination over GF(2) computes it in
polynomial time.

Each NEGATIVE says `f(d) ≠ 0`, which supplies something no per-difference
analysis can: **a falsification test.** If a negative difference lies inside the
span of the conflicts, that is a contradiction, because linearity forces the
span to sit inside the kernel.

## Two scope rules, both established by measurement

**Sub-page differences are out of domain.** Every contradiction in
`030-low-bit-selector` phase C came from differences below 4 KiB. Those are
column and burst bits, not bank bits. Restricting to `>= 0x2000` (PA13, this
project's stated model floor) removes them:

| phase | sub-4K differences | contradictions |
|---|---:|---:|
| A | 0 | 0 |
| B | 3 | 1 |
| C | 12 | 2 → 0 after restriction |
| D | 3 | 1 |

**Datasets are never pooled.** Physical provenance is `BLIND` on this target —
pagemap reports no PFN for dma-buf, so `pa_a`/`pa_b` are `declared_base + offset`
and are coherent only inside one allocation. This is not asserted; it is the
tool's own negative control, and it must keep failing:

| analysis | contradictions | PA13 control |
|---|---:|---|
| per dataset | 0 in 30 of 33 | correct |
| all pooled | 44 | **wrongly inside the kernel** |

The pooled run places `0x2000` — the project's canonical fast control — inside
the recovered kernel. No dataset ever measured it as a conflict; it arrives as
an XOR combination of conflicts drawn from allocations at different unknown
physical bases. If `pooled_negative_control` ever comes back consistent, the
per-dataset rule is unnecessary and the BLIND-provenance argument needs redoing.

## Out-of-sample validation

Fitted on the non-held-out runs of an experiment, then used to predict the
held-out run. The two error directions are not symmetric and are reported
separately: a **false conflict** (predicted same-bank, measured different-bank)
falsifies the kernel; a **missed conflict** only means the fit set did not span
the whole kernel.

| held-out set | conflicts | negatives | false conflicts |
|---|---|---|---:|
| V016 `pa25-27-heldout` | 5/5 | 4/4 | **0** |
| 023 `phase4-heldout` | 1/4 | 3/3 | **0** |

V016 predicts perfectly out of sample. The 023 fit set spanned only part of the
kernel, so it missed three conflicts — incompleteness, not error. **No false
conflict occurred in either.** The falsifiable direction passed.

## What this establishes, and what it does not

`SUPPORTED`: the retained measurements are internally consistent with a linear
bank function on 30 of 33 usable runs, and a kernel fitted on one run predicts another
without falsification.

`SUPPORTED`: **rank ≥ 2**, independently. A genuine global lower bound needs
differences whose every nonempty XOR combination was measured as a negative;
`0x2000` and `0x1000000` with their XOR `0x1002000` supply one in nine runs.

`NOT ESTABLISHED HERE`: rank 3. No retained run contains an XOR-closed *triple*
of negatives, because the experiments were designed to test named candidate
masks rather than to cover such triples. This does not contradict the project's
rank-3 result; it means this independent route reaches 2 and stops.

The tool reports `restricted_rank_upper_bound` separately and labels it as
such — it bounds `f` on the subspace a given run observed, **not** the global
rank. A run that probed a one-dimensional slice reports 1 while the global rank
is 3; reading that column as a global bound would be a mistake.

## A third scope rule, caught by the tool's own control

The widest gap is only the *candidate* cut. `030-low-bit-selector` phases A and
C have three median clusters, and their widest gap falls **above** the conflict
cluster: the threshold lands at 671.5 and 623.0 while the canonical conflict
control `0x16000` sits at 558 and 544. The control is then classified as a
negative, almost nothing remains in the conflict set, and the run passes the
linearity test **vacuously** — no conflicts, no span, so no contradiction is
reachable.

The project's rule has always been widest gap *and* controls bracketing the
candidates. The first version of this tool implemented only the first half and
counted both vacuous passes as successes. `check_controls_bracket` now refuses
any run whose threshold puts `0x16000` below it or `0x2000` above it. The
honest corpus figures are 33 usable runs and 30 consistent, not 35 and 32.

## Quality signal

The consistency test flags runs without knowing any ground truth.
`v2321-L762-pass0` carries 9 contradictions; its siblings under identical
context (same heap, same 32 MiB, same CPU) carry 0. Its cluster separation is
165 with the slow cluster starting at 357, against 311 and 515 for
`v2321-L7980-pass0`. The conflict signal in that run is diluted.

## The cheapest measurement that would close the gap — two differences

A triple needs all seven of its nonempty XOR combinations measured as negatives.
Searching the corrected corpus for the triple closest to complete gives a much
smaller answer than expected: **six of seven are already measured, and two
independent triples are each one difference short.**

| triple | already measured | missing |
|---|---:|---|
| `0x2000`, `0x4000`, `0x1000000` | 6 of 7 | **`0x6000`** |
| `0x2000`, `0x8000`, `0x1000000` | 6 of 7 | **`0xa000`** |

Neither `0x6000` nor `0xa000` has ever been measured anywhere in the corpus, at
any page size, under any schema. Everything else is in hand: `0x2000` in 39
runs, `0x4000` in 12, `0x1000000` in 13, `0x1002000` in 12, `0x1004000` in 12,
`0x1006000` in 18.

So the whole distance between `rank ≥ 2` and `rank ≥ 3` on this independent
route is **two differences in one ordinary run**, and because the two triples
share only `0x2000` and `0x1000000`, measuring both yields two confirmations
rather than one.

The prediction is definite and falsifiable. Under the established basis
`f(PA13) = 001`, `f(PA14) = 010`, `f(PA15) = 100`, both new differences have
non-zero image — `f(0x6000) = 011`, `f(0xa000) = 101` — so both must measure as
negatives. **A conflict at either one would contradict the rank-3 model**, which
is what makes the run worth doing rather than a formality.

`tools/a90_pa28_probe_v022r.c` already accepts an arbitrary trailing difference
list, so this needs no new code: it is the existing 11-difference run shape with
`0x6000` and `0xa000` substituted for two of the candidates.

## Provenance

- tool `tools/dram_bank_kernel_recovery.py`, tests
  `tests/test_dram_bank_kernel_recovery.py` (29 focused tests)
- manifest `evidence/manifests/verification-027-bank-kernel-recovery-20260827-01.manifest.json`,
  24,233 bytes,
  `3381916e878bd3362b25f21a687ac18a0f77999c67d40d44814f9a11c40b23ba`
- inputs: 35 retained private JSONL runs, read only. `HOST_ONLY_REANALYSIS`;
  no device access, no MMIO, no allocation, no firmware bytes.
- `CLASS C (TRANSFORM ONLY)` unchanged. This is model work; it bears on the
  `UNKNOWN` complete-coordinate question, not on P1 or P2.
