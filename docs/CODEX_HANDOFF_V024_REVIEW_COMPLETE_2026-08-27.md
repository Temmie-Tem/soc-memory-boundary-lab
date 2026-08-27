# Codex handoff — Verification 024, completed review pass

The previous handoff
(`docs/CODEX_HANDOFF_V024_BUSY_CHANNEL_2026-08-27.md` §4) closed as a partial
review: only the `exchange()` call surface, argv surface and fixed-constant
sourcing of `tools/a90_inline_remapper_mid_probe.py` had been examined, because
the file was still being edited. This document discharges that debt. The probe
body, lifecycle and failure paths have now been reviewed, together with the two
mechanisms that were added after the first pass.

Reviewed at `tools/a90_inline_remapper_mid_probe.py`
`cb2c661fad9bb7c09006d43a98547cbc82c654cde560b8fc5d89f721e785a541` and
`tools/a90_twrp_remapper_boot_flash.py`
`d7a504f551c3b454e9e6a398a4e88e698618b06fe77e0ef23b754fbfe667325f`.
Both were content-stable across the review. 22/22 focused tests pass.

## 1. The `busy` repair was adopted, and is correct where it landed

The preferred fix was taken: one bounded `stophud`, retried only on an explicit
`rc=-16 status=busy`, at most three times, with every refusal retained. The
reasoning that licenses the retry — **`busy` means the command never ran** — is
stated in the contract and the exception is explicitly not extended to op 4,
flash, `param`, sysctl, reboot, or an ambiguous transport outcome. `stop_autohud`
is a dedicated function with a fixed argv and exactly one call site.

## 2. Finding (blocking for the sequence, not for the probe) — the repair stopped at the probe boundary

Verification 023 did not fail inside a probe. It failed in the reboot observer.
Those tools are unchanged:

| Tool | `busy`/`stophud`/`autohud` occurrences | Last touched |
|---|---:|---|
| `tools/a90_native_reboot_observe.py` | 0 | `a35777e` (unrelated) |
| `tools/a90_param_capture.py` | 0 | — |
| `tools/a90_param_debug_transition.py` | 0 | — |

Contract steps 4, 7 and 11 run through these three, and every one of them runs
**immediately after a boot** — the window in which `autohud` has just restarted.

`wait_for_new_boot` looks protected because it catches exceptions and polls to a
deadline. It is not. The loop retries but has no means of clearing the
contention: it never issues `stophud`, so a holding `autohud` is simply
re-encountered until the deadline expires, and the run then fails with
`new native boot not observed: … rc=-16 status=busy` **even though the reboot
succeeded**. That is verbatim what happened in 023. `_preflight`
(`tools/a90_native_reboot_observe.py`, `_read` → `exchange`) has no tolerance at
all and fails hard on first contact.

Cost, read against the contract:

- **Step 4 / step 7** — a hard failure here is fails-closed and cheap; no
  experiment effect has been dispatched.
- **Step 11** — this is the rollback verification and final health. A `busy`
  there leaves the lifecycle incomplete, which under the write gate *prevents
  public promotion* of a run that actually succeeded. Three boot-prefix writes,
  up to two `param` transitions and a likely physical power-button action are
  discarded on an instrument artifact.

The fix is the same bounded `stophud` already written in the probe, applied
after each boot in these three tools, or hoisted into the shared command layer
they all use.

## 3. Finding (documentation, inherited — not a V024 regression) — torn-write recovery is unspecified

`tools/a90_twrp_remapper_boot_flash.py` reads the **live** boot prefix hash and
requires membership in the profile's predecessor set before writing:

```
ALLOWED_PREDECESSORS["rollback"] = {CONTROL_SHA256, READ_SHA256}
```

If the single `dd` is torn — USB drop, TWRP crash — the boot prefix hashes to
none of the three pinned images, and the `rollback` profile is then **refused**:
the scripted recovery path is unavailable in exactly the state that needs it.

Three things bound this, and they are why it is reported as documentation rather
than as a defect:

1. The device is not at risk. `recovery` is a separate partition and is
   untouched, so TWRP remains reachable and a manual flash still recovers.
2. It is inherited, not introduced. `tools/a90_twrp_shrm_boot_flash.py` carries
   the identical set and completed a full live control → read → rollback run.
3. The guard is defensible on its own terms: after a torn write the state is
   unknown, and a human looking before scripting a partition write is the right
   default.

The actual gap is that no runbook states this. A grep across `docs/` and
`experiments/` finds no torn-write or manual-recovery procedure. Recommend one
short paragraph in the write gate naming the manual TWRP path, so the operator
is not deriving it under pressure.

## 4. Verified clean

Each of these was checked against the code, not against the contract's
description of the code.

| Mechanism | Result |
|---|---|
| Current-boot attestation direction | `dd if=<node> of=<file>` — read-only. The probe issues no partition write; the `of=/dev/block/sda24` occurrence at `verify_flash_journal` is an expected-argv value being compared, not an effect |
| Attestation target identity | `sda24` uevent `MAJOR`/`MINOR`/`DEVNAME`/`DEVTYPE`/`PARTN`/`PARTNAME`, sector count, `ro`, then `stat` `rdev=259:27` on the created node — double-bound |
| Attestation cleanup | pre-cleanup with absence proof before `mknodb`; post-cleanup outside the `try`, run unconditionally, and a cleanup error is raised even on the success path |
| Ordering | attestation → `panic_on_oops` 0 → `PREPARED` → dispatch → restore, with the arm record made durable *before* the sysctl write |
| `panic_on_oops` grounding | Not merely asserted. `a90_inline_shrm_probe.py`, `a90_inline_remapper_probe.py` and `a90_repl_mmio_snapshot.py` all set 0 before the op, so the historical comparison condition is genuinely preserved. The asymmetric handling matches the retained receipts exactly: `007-inline-remapper-control-live` (value `0x0000c071`) records `panic_on_oops_restored: true`, `007-inline-remapper-read-live` and `013-shrm-read-live` (no value) record `false` |
| One-shot guarantee | `dispatch_count = 1` and `EFFECT_DISPATCH_STARTED` are journalled **before** the call; total device loss cannot erase the fact that exactly one dispatch was armed |
| Fixed op input | `session._op_values(OP_FIXED_READ, (), replay_safe=False)` — empty argument tuple, no caller-controlled address or value; the address is baked into the hash-pinned boot candidate |
| Post-reset contamination | the `*_after` block is gated behind `dispatch_returned` **and** `panic_restore_verified`; neither can hold after a reset, so validation reads can never run against a fresh boot |
| Post-dispatch silence | the ambiguous branch performs host-only journalling and sends no restore, bridge or health command |
| Flash write bounds | fixed `count=DD_BLOCK_COUNT` prevents a longer staging object from extending the write; endpoint revalidated immediately before the write with no command interposed; full readback verified |

## 5. Scope

This pass plus the previous one covers both tools end to end. Not covered: the
live sequence itself, and the three tools in §2, which were read only far enough
to establish the finding.
