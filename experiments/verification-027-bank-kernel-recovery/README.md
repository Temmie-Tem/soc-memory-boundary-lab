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
| per dataset | 0 in 32 of 35 | correct |
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
bank function on 32 of 35 runs, and a kernel fitted on one run predicts another
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

## Quality signal

The consistency test flags runs without knowing any ground truth.
`v2321-L762-pass0` carries 9 contradictions; its siblings under identical
context (same heap, same 32 MiB, same CPU) carry 0. Its cluster separation is
165 with the slow cluster starting at 357, against 311 and 515 for
`v2321-L7980-pass0`. The conflict signal in that run is diluted.

## The cheapest measurement that would close the gap

Three differences `d1, d2, d3` whose seven nonempty XOR combinations are all
measured. If all seven come back negative, `rank ≥ 3` follows independently of
the existing mask-by-mask argument. That is seven differences plus the standard
controls — one ordinary run of the existing probe, no new privilege, no new
mechanism.

## Provenance

- tool `tools/dram_bank_kernel_recovery.py`, tests
  `tests/test_dram_bank_kernel_recovery.py` (24 focused tests)
- manifest `evidence/manifests/verification-027-bank-kernel-recovery-20260827-01.manifest.json`,
  25,045 bytes,
  `4e3aff6bccdf345b2afd9dafc1d0bb4ee16206942a0e6259b48dc24dfa8c5a55`
- inputs: 35 retained private JSONL runs, read only. `HOST_ONLY_REANALYSIS`;
  no device access, no MMIO, no allocation, no firmware bytes.
- `CLASS C (TRANSFORM ONLY)` unchanged. This is model work; it bears on the
  `UNKNOWN` complete-coordinate question, not on P1 or P2.
