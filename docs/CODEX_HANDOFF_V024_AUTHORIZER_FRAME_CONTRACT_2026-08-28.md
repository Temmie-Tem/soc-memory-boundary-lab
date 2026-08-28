# Codex handoff — the READ authorizer's frame gap is 25 ids wide, not one

This follows the `stophud` defect you found from the round-trip test failure.
Your diagnosis was right and your fix direction is right. This document reports
that the gap is systematic rather than a single missing frame class, so a repair
scoped to `stophud` would leave the same hole open in 24 other places.

Read against `tools/a90_inline_remapper_mid_probe.py`
`abb3d8a31f5406d4…` and `tools/a90_verification024_finalize.py`
`2955c787fbefc6b5…` as of 2026-08-28 08:59.

## The general form

The two gates disagree about what a control receipt has to *contain*:

| Gate | Guards | Validates |
|---|---|---|
| `verify_control_manifest` | the one-shot READ dispatch | **summary fields** |
| `_validate_frame_list` | publication | **the frames that produced them** |

The authorizer is not missing a frame validator. It has two, and they are
thorough: `_validate_fixed_op_frame` for `fixed_op_4`, and
`_validate_panic_frames` for the panic group. `_frame_by_id` — which enforces
exactly-one, argv binding, matching begin/end sequence, `rc == 0`,
`status == "ok"` — is called from **only one place**, inside
`_validate_panic_frames`.

So the authorizer requires these frames to exist and be well formed:

```
fixed_op_4
panic_before   panic_zero_verify   panic_restore_verify
```

and no others.

## What it accepts without evidence

`_validate_current_boot_attestation` takes the attestation **record**, not the
frame list — its signature has no `frames` parameter and its body contains zero
occurrences of `frame`. It checks the summary object against fixed constants and
returns. Nothing then requires that the raw frame list contains the sixteen
`boot_attest_*` frames that record claims to summarise.

The same holds for health: the authorizer checks the field `health_after_ok`,
never a `selftest_after` frame.

Frame ids the finalizer enumerates and the authorizer never names:

```
boot_attest_capture              boot_attest_hash
boot_attest_mkdir                boot_attest_mknod
boot_attest_size                 boot_attest_stat_node
boot_attest_remove_file          boot_attest_remove_node
boot_attest_node_absent          boot_attest_file_absent
boot_attest_pre_node_absent      boot_attest_pre_file_absent
  (plus the four *_not_symlink variants)

version_before    version_after
cmdline_before    cmdline_after
selftest_before   selftest_after
soc_id_before     soc_id_after

stophud_1..3
```

That is 25 ids. `stophud` is one of them.

## Why the ordering matters

The finalizer catches all of this — but it runs at publication, after the
dispatch. A control receipt asserting `health_after_ok: true` and carrying a
well-formed `current_boot_attestation` record, whose raw frame list contains
neither `selftest_after` nor any `boot_attest_*` frame, authorises the one-shot
read and is refused afterwards.

That is the same cost shape reported in
`docs/CODEX_HANDOFF_V024_REVIEW_COMPLETE_2026-08-28.md` §2: an expensive,
physically-attended, non-replayable run is spent and then discarded by a gate
that could have refused it beforehand.

## Suggested repair

Give both gates one shared frame-contract function, and have
`verify_control_manifest` call it over the full expected id set rather than
adding `stophud` to its current pair. The finalizer already computes that set in
`_expected_full_frame_ids`; the authorizer needs the same list, not a second
copy of it — two enumerations of the same contract is exactly how this drifted.

Where the authorizer legitimately needs to be laxer than the finalizer, that
should be one explicit, named exemption rather than silence.

## Correction to my previous report

I told the operator the authorizer "does not look at the frame list at all."
That was wrong, and it came from grepping a 160-line window of a 381-line
function. It validates two frame classes thoroughly and omits the rest. The
accurate statement is the one above: summary fields are checked, the evidence
behind them is not.

## Resolution and regression record

The 0a63b92 finding was valid for the review snapshot named in that audit. The
current resolution is the b773c66 delegation in `verify_control_manifest()`;
it did not merely add more summary-field checks. The authorizer delegates to
the complete `finalizer.validate_control()` contract, which reuses the single
`_expected_full_frame_ids` implementation for the full producer sequence.

Regression commit 943a032 uses the actual mocked producer baseline, removes
each of the 41 raw and journal frame positions (including duplicate IDs),
rebinds the public hash and size, and confirms that summaries, attestation and
health remain unchanged while both gates reject. Representative extra and
reordered frames are rejected as well. Root revalidation passed 130/130 with
maximum RSS 98,656 KiB and zero swaps. This is host-only evidence: it grants
no `verification-024-control-r2` live authority and made zero device contacts.
