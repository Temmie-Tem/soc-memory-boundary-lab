# Verification 018 integration review — 2026-08-27

## Review boundary

This review covers the repaired allocation-local marker oracle and one fresh
exact A90 acquisition.  It does not promote numbered Experiments 015/016,
does not prove physical PA-to-DRAM aliasing, and does not touch a controller,
XPU, SMMU, SCM, EL2/EL3, protected memory or a partition.

The implementation is intentionally separate from the numbered Experiment 018
XBL MC-writer cross-reference.  The route-2 termination challenge is recorded
separately in `docs/CODEX_HANDOFF_ROUTE2_TERMINATION_2026-08-27.md`.

## Independent hostile findings and repairs

The first hostile pass returned `NO-GO` for physical-alias promotion.  Its
actionable findings were repaired before the live run:

1. A caller-selected binary is no longer enough.  The runner requires the exact
   checked-in probe source path, predeclared source/binary size and SHA-256,
   and a private reproducible static-build receipt before the first bridge
   command.  The final AArch64 binary was built twice byte-identically.
2. Loopback alone is no longer treated as hardware identity.  The runner binds
   the unique `serial_tcp_bridge.py` process configured for `127.0.0.1:54321`,
   `/dev/ttyACM0`, `--expect-realpath /dev/ttyACM0`, and the exact A90 USB
   identity symlink.
3. Version and command identity now reject conflicting/duplicate runtime,
   build, kernel and cmdline fields.  Target frames, source/binary/build
   descriptors and current runner/bridge hashes are retained and rechecked.
4. Live probe framing delegates to the strict analyzer parser and requires the
   exact 190-record order/shape.  Controls, marker/sentinel values, candidate
   offsets and summary are recomputed; failed controls and repeated-trial
   disagreement cannot yield an admissible negative.
5. Raw probe output and bridge transcript are retained as sidecars.  Cleanup,
   remote absence, upload hash stability, child completion and final self-test
   are required by the PASS receipt.  A transport timeout with a retained child
   PID has a bounded terminate/check path and never triggers a replay.  If the
   bridge times out before exposing a PID, the runner records an incident and
   cannot promote the run to PASS.

The residual limitation is accepted as scope, not hidden: the one ION dma-buf
has no kernel-proved PFN/PTE/SG identity in this run, the mapping is
write-combine only, and no cacheable/noncacheable or cross-state permutation
trial is attempted.  Therefore the result is an allocation-offset storage
identity baseline, not a physical alias or security-boundary proof.

## Host verification

The final checked-in probe source is 22,191 bytes with SHA-256
`cdc6f985fb8e2f37a3964a25f8d575ec1b3fe48eab71d084a30537c6fbe6f3bb`.  The
static AArch64 binary is 710,408 bytes with SHA-256
`33ef21a13ef79f6888b5a466644660ace3c6950664b1e2b497aad474f1487d56`.
The private build receipt is 773 bytes with SHA-256
`40a338c2c96bc214ff89543cd9946e2243499e1f72f7b5819f0c748118c43872`.

Focused analyzer/live tests: 28/28 PASS.  Python byte-compilation, strict
JSON/public-safety checks, AArch64 `-O2 -static -Wall -Wextra -Werror` build,
two-build byte identity, and `git diff --check` pass.  The full serial suite
also passes 1,090/1,090 with maximum RSS 278,560 kB and no swap use.

## Live evidence

The first invocation (`verification-018-a90-20260827-01`) stopped after
read-only `version`/`cmdline` because the target's actual version frame has a
parenthesized build plus separate `version:`/`kernel:` lines.  Its private
receipt is `INCIDENT`, with zero preclean/upload/ION/probe/write actions; it was
not replayed as an effect.

The corrected invocation (`verification-018-a90-20260827-02`) is a PASS receipt
for the exact `SM-A908N` / `SM8150` V2321 target.  It used a type-10/id-30
`camera_preview` 256-MiB write-combine allocation, two distinct virtual
mappings, four fixed anchors, bits 6..27 and two trials.  The same-storage
control was `ALIAS`; the distinct-offset control was `DISTINCT`; all 176
candidate pairs were `DISTINCT`; `aliases=0`, `disturbed=0`,
`clobbered_anchors=0`, and `trial_disagreements=0`.  Pagemap was `BLIND` with
zero present/nonzero PFNs.  Remote binary hashes matched before/after, all
three remote temporary paths were absence-proved, and final self-test was
`pass=11 warn=1 fail=0`.

Private artifacts remain ignored.  Their exact hashes are recorded in
`docs/RESEARCH_LOG.md`; the sanitized public manifest is
`evidence/manifests/verification-018-a90-20260827-03.manifest.json` (47,715
bytes, SHA-256
`4747a45c20b038b511c3310ebbdd4ac67f9885f29dfe2e3155882a3cf7eb0371`, mode
`0644`).  The public manifest contains no raw transcript, private absolute
path, device credential or secret.

## Verdict and residual unknowns

`PROVED`: the exact one-state allocation-offset observations, target/build/
command/cleanup/final-health receipts and analyzer recomputation.  `SUPPORTED`:
this is a useful non-secure allocation-local storage-identity baseline.  `UNKNOWN`: physical
PA/PFN mapping, effective contiguity, final DRAM coordinates, cross-state
injective permutation, transform-state mutability, protection ordering and
protected reach.  The runner's transport-timeout termination when no child PID
is exposed is also `UNKNOWN`; the retained run did not time out.  `REFUTED` only
within scope: a candidate-pair alias in this acquisition.

Disposition remains `CLASS C (TRANSFORM ONLY)`.  The analyzer status is
`DEVICE_ACQUISITION_VALIDATED` with
`PROVED_NO_ALIAS_IN_EXACT_TESTED_OFFSET_PAIRS`; this text must not be shortened
to “no physical alias” or “no Qualcomm bypass”.  Numbered Experiments 015/016
remain `NOT_ELIGIBLE`.
