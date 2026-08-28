# Reading the defenses backwards — 2026-08-27

The question that produced this document: *if Qualcomm and Samsung hardened to
this degree, something must have been wrong.* That is a sound way to read
defenses, and on this target it produces a specific, testable answer.

## The shape of the protection is not architectural

`evidence/manifests/009-xpu-policy-inventory-20260825-01.manifest.json` records
the XPU regions around the `qhs_llcc` remapper. Put side by side, the middle row
does not belong to the pattern:

| Region | Size | Read VMID | Write VMID |
|---|---:|---|---|
| `0x09240000..0x09245000` | 20 KiB | `0x40000000` | `0x40000000` |
| **`0x09248000..0x09249000`** | **4 KiB** | **`0x80000000`** | **`0x00000000`** |
| `0x09249000..0x0924c000` | 12 KiB | `0x40000000` | `0x40000000` |
| `0x0924e000..0x09250000` | 8 KiB | `0xf0000000` | `0xf0000000` |

Three things separate the remapper page from its own neighbourhood:

1. **`write_vmid = 0x00000000`.** Not "TZ only" — *no VMID at all*. The
   neighbours on both sides are symmetric read/write to one VMID; this page is
   writable by nobody through this policy.
2. **A different reader.** `0x80000000` rather than the `0x40000000` used
   immediately above and below it.
3. **A non-standard construction.** `standard_multi_vmid_permission_words` are
   `0x00000000, 0x00000000`; the grant comes from
   `exact_constructed_client_permission_bytes` `0x11, 0x08`. The permission was
   built by a special path, not emitted by the ordinary one.

It is identical in both selector branches. Broad policies look like
architecture — `MEMNOC_MS_MPU` over `0x00000000..0x10000000` is a floor plan. A
single 4 KiB page carved out of a uniform neighbourhood, given a different
reader, a non-standard permission construction, and **zero writers**, looks like
a response to something.

## The historical record names what

Three disclosed Qualcomm issues sit on exactly this surface:

| Issue | What it was | Why it matters here |
|---|---|---|
| **CVE-2020-11252**, Qualcomm bulletin April 2021 | "improper access restrictions during trustzone initialization, as **xPU get disabled when memory dumps are enabled**"; Snapdragon Mobile among the affected families | This is P2 for the *entire XPU regime*, not one register. A Normal-World-selectable configuration turning the target-side protection off is precisely the aperture this project has failed to find by every other route. |
| **RPM-region boundary error from improper XPU configuration** | a malicious application could trigger memory corruption and execute code with elevated privileges | XPU *misconfiguration*, not XPU bypass — the policy tables have been wrong before |
| **CVE-2022-22063** | APCS boot remapper, non-secure EL1 reconfigurable, full R/W/X into hypervisor memory | already recorded in `docs/PRIOR_ART.md`; checked and does not transfer to SM8150 |

CVE-2020-11252 is the one that matters. It says the protection this project
keeps running into has a documented off switch, and that the switch was reachable
from configuration rather than from an exploit.

## The gap in this project's own evidence

The read that produced `Non Secure Watchdog Bark` at `0x09248080`
(`experiments/007-kernel-remapper-adapter`) was performed on **2026-08-24,
20:46–21:40 UTC**. The debug-level transitions
(`experiments/verification-006-a90-param-debug-live`) were performed on
**2026-08-25, from 12:18 UTC**. The device's current cmdline is
`androidboot.debug_level=0x4f4c` = **LOW**.

So every remapper access this project has attempted was made with memory dumps
**disabled**. The condition CVE-2020-11252 describes — memory dumps enabled —
has never been tested against the remapper. The project's negative result on
route 2 rests on measurements taken only in the state where the protection is
expected to be on.

That is not a flaw in the measurements. It is an untested condition, and it is
the single condition the disclosed record says matters.

## The experiment

Fully within precedent. Verification 006 performed the `DLOW ↔ DMID` transition
**four times** — journals 007 and 009 `APPLIED_VERIFIED`, 008 and 013
`RESTORED_VERIFIED` — and recorded that an orderly MID boot returns normally
rather than entering upload mode. `param` is not a bootloader-class partition
and is outside the forbidden set in `docs/THREAT_MODEL.md`.

1. Confirm the current state is `DLOW` and re-establish the baseline bark.
2. Apply `DLOW → DMID`, reboot so the level takes effect.
3. Repeat the bounded read at `0x09248080`.
4. Restore `DMID → DLOW`, reboot, verify.

The outcome is decidable either way:

- **The read barks again.** XPU still enforces with memory dumps enabled. The
  route closes on a *measurement* of the one untested condition instead of on an
  inference, and CVE-2020-11252 is shown patched on this build.
- **The read returns a value.** XPU was disabled by a configuration reachable
  without an exploit. That is P2, and it is a security-boundary-bypass
  indicator: stop immediately, collect only minimum reproducibility, root-cause
  and affected-range evidence, and switch to disclosure mode.

## The expectation, stated before the run

This build is `A908NKSU5EWA3`, kernel built 2023-01-12 — roughly 21 months after
the April 2021 bulletin. **The expected result is that it is patched and the read
barks again.** Recording that expectation in advance is the point: a negative
here is worth having precisely because it was not assumed, and a positive would
be worth stopping for.

## Ranking

`PROVED`: the VMID asymmetry, the non-standard permission construction, and the
selector-branch invariance — read from the retained 009 manifest.

`PROVED`: the ordering of this project's own experiments, from their retained
timestamps — every remapper access was made at `DLOW`.

`SUPPORTED`: that the `0x09248000` page's protection is a targeted lockdown
rather than generic layout, from its contrast with its immediate neighbours.

`UNKNOWN`: whether CVE-2020-11252 applies to SM8150 specifically; whether this
build carries the fix; and what the remapper read does at `DMID`.

`CLASS C (TRANSFORM ONLY)` and `NOT_ELIGIBLE` unchanged. Nothing here has been
executed; this document proposes and does not report.
