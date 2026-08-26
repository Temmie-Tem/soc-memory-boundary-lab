# Response to the 019A–030 line reconciliation — 2026-08-27

`docs/EXTERNAL_LINE_RECONCILIATION_2026-08-26.md` raised eight findings against
this line. Each was checked against the retained evidence rather than accepted
or disputed on reading. **Seven are upheld.** One is not, and one defect in the
reviewing line is reported below.

Verification used the same discipline the review asks of this line: a finding is
upheld only when the raw artifact shows it, not when the description is
plausible.

## Upheld

**1 — Experiment 030 merged acquisition phases with `dict.update()`.** Upheld.
`tools/a90_low_bit_selector_analysis.py:149` was a flat update across phase
files, so file order decided the winner among phases with different pair counts
and offset modes. The raw phases confirm the consequence: phase D contains
`0x400` (PA10 alone) at 32 pairs and does not contain `0x16400` or `0x2400` at
all, while phase C contains all three at 64 pairs. A merged PA10 row therefore
paired a stride-mode alone-value with spread-mode witnesses. PA9 is unaffected —
phase C gives `717/702/702` and phase D `762/753/760`, both complete.

The consequence for the published claim is narrower than the defect. The
headline table was phase C throughout and is internally consistent; what was
wrong is the scope sentence in `experiments/030-low-bit-selector-scope/README.md`
line 66, "holds across both offset modes, at 32 and 64 pairs". That is true of
PA9 and false of PA10. The corrected analyser was re-run here against the
retained phases and reproduces the review's result exactly: phase A
`INCOMPLETE/INCOMPLETE`, phase B `SATURATING/SATURATING`, phase C
`SATURATING/SATURATING`, phase D `SATURATING/INCOMPLETE`, with
`all_consistent: true` and no disagreements. No phase contradicts another; the
defect was that incompleteness was hidden rather than reported.

**2 — Experiment 022A claimed complete observation channels.** Upheld.
`experiments/022A-observation-coverage/README.md:31` states the union of the two
channels "is the complete set this project can name without a device read", and
`0x09248080` does not appear anywhere in the 022A manifest. Completeness is
`REFUTED`; the density figure describes the enumerated channels only.

**3 — Experiment 021A promoted absent labels into a delivery refutation.**
Upheld. The 021A manifest contains exactly two `"dcb_section": null` entries
among the direct bounded-copy calls, so two of seven are uncharacterised and
other-section, global and indirect delivery remain `UNKNOWN`.

**4 — Experiment 029A's filename contract did not match 028's consumption.**
Upheld, and the mismatch is total rather than partial. The extractor writes
`(out / name.replace("/", "_"))` with no suffix, and the four extracted blobs
are named `abl/file@0x48/lzma` and three `.../PE32` paths — none ends in `.bin`.
`tools/a90_bank_relation_encoding_audit.py:304` globs `*.bin`. Zero of four
inputs would have been read; the documented command could not have produced the
claimed input set without an unrecorded rename.

**5 — Renumbering left stale identifiers.** Upheld, and worse than described.
The renumbering regex used `\b<module>\b`, which does not match inside
`tests.test_sm8150_<module>` because `test_` ends in a word character. Four
README commands were therefore not rewritten: `019A:214`, `020A:242`,
`021A:129`, `022A:137`. Those module names still resolve — to the bare-numbered
line's tests, which arrived with the merge. The commands do not fail; they pass
while validating different code than the experiment they document. A silent
wrong result is worse than a broken command.

**6 — Experiment 023R's base is model-conditional, not measured provenance.**
Upheld. Every pagemap record is `BLIND`, and the README nonetheless lists the
base under `PROVED`. The behavioural solve eliminates candidate offsets given a
contiguous `qseecom` allocation and the Experiment 014 relation over PA13..PA23;
that is `SUPPORTED_WITHIN_MODEL`, and the review's relabelling is correct.

**7 — Experiment 029A asserted a live device-tree observation without retained
evidence.** Upheld. The README states at line 18 that "the one device read was
the live device tree" and draws on it at lines 88 and 104, while neither 029A
manifest contains any device-tree payload, hash or property record. This is the
same class of failure the standing evidence discipline exists to prevent, and it
is the reason the `verification-015` record re-captured its DDR level sweep
rather than reusing an interactive one that had no retained transcript.

## Not upheld

**8 — 019A/020A static shapes do not establish global absence.** The statement
is true, and both experiments already say so in their own `UNKNOWN` blocks:

- 019A: "the implicit base of every base-relative table; whether any ranked
  value is computed rather than stored; whether DDR training firmware outside
  these nine partitions writes them; register semantics".
- 020A: "`REFUTED`: AOP consumes the DCB base-relative tables or references the
  ranked controller instances. `UNKNOWN`: whether AOP reaches them indirectly,
  through a pointer it receives rather than a literal it holds."

Both refutations are already stated as bounded model-refutations with the
residual named. Nothing in either file claims global register-programming,
consumer, writer or target absence. Finding 8 restates a boundary that the
artifacts already draw; it is a reasonable thing to record in an integration
review, but it is not a defect and should not be carried in the same list as
findings 1–7, which each identify something the artifacts got wrong.

If a specific sentence in either README does overclaim, quoting it would settle
this immediately and the correction would be made.

## A defect in the reviewing line

`tests/test_sm8150_dcb_unsupported_frontier.py:129` and
`tests/test_sm8150_dcb_residual_memory_frontier.py:301` both assert

```python
self.assertEqual(stat.S_IMODE(MANIFEST_PATH.stat().st_mode), 0o644)
```

on a git-tracked file. Git records only the executable bit, so the mode of a
checked-out file comes from the checking-out user's umask. Under `umask 002` —
the Ubuntu and Debian default with user-private groups — both tests fail with
`AssertionError: 436 != 420` while the manifest content hash passes. This is
reproducible in any worktree created under that umask and is unrelated to
manifest integrity, which the preceding size and SHA-256 assertions already
cover.

The mode assertion is left in place here rather than changed, since these are
the reviewing line's files. Removing the two lines, or comparing against the
process umask, would make the suite portable.

## Corrections made in this line

Findings 1–7 are accepted. The corrected `a90_low_bit_selector_analysis.py`
already carried on `main` reproduces against the retained phases and is not
duplicated here. The remaining README and contract corrections belong with
whichever line ends up owning those files after integration; this document
records the verification so the decision is not made on an unchecked list.
