# Verification 019 raw-receipt retention and repetition — 2026-08-27

## What this closes

The current branch records V019 as `SUPPORTED_EXTERNAL_MANIFEST_ONLY` because
the private raw suspend receipt was absent, and
`docs/EXTERNAL_LINE_INTEGRATION_2026-08-27.md` scopes that label as *pending
raw-receipt retention*.  That condition is now met twice over: the original
receipt is retained, and an independent second suspend was acquired on the
device.  This document states only what a verifier can re-check; it does not
itself change a status field.

## Root cause of the absence

`evidence/private/verification-019-suspend-permutation-20260827-01` was not a
directory.  It was a **symbolic link into a scratch worktree**, and pruning that
worktree dangled the link, so the receipt left the repository's view while the
public manifest stayed behind.  `evidence/private/verification-018-alias-marker-20260827-01`
had the same shape.  Both links were removed and replaced with real
directories.

The analyzers already refuse to *read* through a link (`O_NOFOLLOW`); nothing
refused to *retain* through one.  `tests/test_evidence_private_no_symlinks.py`
closes that side with four positive assertions and one negative control that
rebuilds the exact dangling-link shape and requires the guard to fire.

## Run 1: the original receipt, recovered

The target had not rebooted since the original run, so the original output file
was still present at its device path and was read back unmodified.

| | |
|---|---|
| Retained at | `evidence/private/verification-019-suspend-permutation-20260827-01/suspend-permutation.jsonl` |
| Bytes / mode | 930 / `0600` |
| SHA-256 | `6f34e725f2a5faed2340c1a5294500ee37b946a6f2e1feed877f7b0e8b5946c6` |

Re-running `tools/a90_suspend_permutation_analysis.py` over that receipt
reproduces the published manifest **byte for byte**:
`bf7c66c78993b24d02a46735abb77e7e40298d6230bc5438c3eb21028c51238b`.  That
equality is what pins manifest `…-01` to its source; the receipt is the
original bytes, not a reconstruction.

## Run 2: an independent second suspend

Acquired 2026-08-27 at 14:20 KST on the same uninterrupted boot, with the probe
rebuilt from the checked-in `tools/a90_suspend_permute_probe.c`
(`aarch64-linux-gnu-gcc -O2 -static -Wall -Wextra -Werror`, binary SHA-256
`74fce617b6154749d3d295b7f8347625abfdf72e9710920ba753759e458f5f1e`) and
hash-verified on the device after upload.

| | Run 1 | Run 2 |
|---|---|---|
| Baseline mismatches (instrument gate) | 0 | 0 |
| Suspended | 25.090 s | 25.151 s |
| `suspend_stats/success` | 0 → 1 | 1 → 2 |
| `suspend_stats/fail` | 13, unchanged | 25, unchanged |
| Tags moved | 0 of 4,194,304 | 0 of 4,194,304 |
| Verdict | `MAP_INVARIANT` | `MAP_INVARIANT` |

Run 2 reached suspend on its **first** attempt, so the blocker diagnosis is not
a one-off: `icnss` disabled plus the cable out is sufficient, and nothing else
had to be cleared.

| | |
|---|---|
| Retained at | `…-02/suspend-permutation.jsonl` |
| Bytes / SHA-256 | 931 / `84ce2e88acdc3a956794feb57f968490aa3c2a05ff196dc3fc82a62dcf5bf395` |
| Public manifest | `evidence/manifests/verification-019-suspend-permutation-20260827-02.manifest.json`, SHA-256 `b9d5717f33349727da7523ea6ab003ce33ec6694fce3487370a802a1d2f4b4eb` |

## A retained negative control

A third run, launched with the cable still attached, is retained as a control
rather than a result: twelve consecutive `EBUSY` attempts, `success` unchanged
at 1, `fail` 13 → 25, verdict `SUSPEND_NOT_REACHED`.  Its baseline pass was
clean, so the instrument was working and the run failed for exactly the stated
reason.  This is the independent reproduction of the `usb_notify` blocker.
Retained at `…-02/suspend-permutation-usb-attached-blocked.jsonl`, 3,265 bytes,
SHA-256 `fff1126a5b00690abc28a29b8fe145369a651c7bb7c8d45a89499213cd134298`.

## Device actions, restoration and health

One ION allocation in the process's own `camera_preview` heap; one temporary
ION character node; one `power/wakeup` attribute set to `disabled` and
**restored to `enabled`**; one string written to `/sys/power/state`.  No
register, MMIO, SMC, SCM, EL2/EL3, protected-memory, partition or
firmware-write operation occurred.

The uploaded probe, the temporary node, the base64 envelope and every
intermediate output file were removed; `/tmp/a90-native` was left holding only
the pre-existing `native-init.log` and the original run-1 receipt.  After
restoration the enabled wakeup-source set is identical to the pre-run set
(`icnss`, `ssusb`, `pm8150_rtc`, two `power-on`, `gpio_keys`); `pm8150_rtc` was
never touched, because the `CLOCK_BOOTTIME_ALARM` resume depends on it.  The
target reports the same build on the same uninterrupted boot: uptime advanced
48,539 s → 49,833 s with no reset, and `suspend_stats` reads `success=2`,
`fail=25`, matching the three runs exactly.

## Scope, unchanged

Two suspends instead of one raise the repetition count and remove the
retention caveat.  They do not widen the domain: this is still offset bits
6..27 of one 256 MiB `camera_preview` allocation at 64-byte granularity, and
offset differences equal physical differences only under the contiguity
Verification 016 established behaviourally.  Complete DRAM coordinates, other
state transitions, transform mutability, protected reach and every P2 route
remain `UNKNOWN`.  `CLASS C (TRANSFORM ONLY)` and `NOT_ELIGIBLE` are unchanged;
no boundary-bypass indicator appeared in either run.

## What an integrator should re-check

1. `tests/test_evidence_private_no_symlinks.py` passes, and its negative
   control fails when the dangling shape is rebuilt.
2. The retained run-1 receipt regenerates manifest `…-01` byte for byte.
3. Manifest `…-02` regenerates from the run-2 receipt, and its synthetic
   positive control still reports `MAP_CHANGED` with all moves decoded.
4. Whether `SUPPORTED_EXTERNAL_MANIFEST_ONLY` should now be replaced, and with
   what — that judgement is the integrator's, not this document's.
