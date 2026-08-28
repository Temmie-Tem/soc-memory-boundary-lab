# Verification 024 live execution log — 2026-08-28

## Current state

**`CONTROL_BOOTED / PARAM_EFFECT_NOT_DISPATCHED / PARSER_REPAIR_GO /
RESUME_READY`.**

All times below are UTC. Raw A90P1 frames, the complete cmdline, transient boot
identity and partition journals remain under `evidence/private/`.

## Completed effects

`PROVED`:

- `03:39:00–03:39:28`: the exact V2321 native target entered Recovery once.
  `verification-024-recovery-entry-control` ended `RECOVERY_OBSERVED` on exact
  `SM-A908N/r3q`, TWRP `3.7.0_12-0`; dispatch count was one and replay was
  false.
- `03:39:47–03:39:53`: the control flash owner accepted predecessor
  `ca978551...`, wrote once, read back exactly 60,882,944 bytes as
  `dbbf81f2...`, removed staging, and ended
  `PASS_READBACK_AND_CLEANUP`. Replay was false.
- `03:40:08–03:40:19`: the System-boot owner dispatched the control boot once
  and observed the Recovery endpoint disconnect. Replay was false.

`SUPPORTED`: the current native boot is the verified control candidate. The
current boot prefix will be re-attested immediately before fixed op 4; until
that succeeds, current-running-image identity is not promoted to `PROVED`.

## Pre-effect refusals

`PROVED`: neither refusal reached the four-byte `param` effect.

1. `verification-024-param-control-apply-mid` ended
   `PRE_EFFECT_PREFLIGHT_INCOMPLETE`: the first post-boot `stophud` exchange
   timed out without a complete A90P1 frame. Its journal records
   `effect_dispatched=false`, `write_count=0`, `partition_writes=false`, and
   `reconcile_required=false`. A subsequent read-only version command returned
   one complete frame, separating channel readiness from the param effect.
2. `verification-024-param-control-apply-mid-r2` ended the same pre-effect
   status because the live kernel cmdline contains one legitimate double ASCII
   space. Its journal independently records no effect, no write, no replay and
   no reconciliation requirement.

The retained cmdline is 2,513 bytes, SHA-256
`e326100bfec8cb595a413c968dc565bbab47327324423ba5420b3a75b41fbf23`,
with exactly one double-space at offset 446 between keys
`androidboot.keymaster` and `androidboot.ulcnt`. The complete value is private.

## Host repair and review

The four V024 lifecycle parsers now treat one-or-more ASCII spaces as token
delimiters while continuing to reject tabs, vertical tabs, form feeds,
embedded/bare CR/LF, NUL, surrounding spaces, repeated terminal newlines,
duplicate keys and unknown bare flags. Exact required target values are
unchanged.

Independent frozen-hash review returned `GO`: 870/870 whitespace rows and
743/743 frame-regression rows passed, with `P0=0` and `P1=0`. The affected set
passed 112/112 and the six-module gate passed 180/180. Public boot-ID redaction
then passed 87 hostile assertions and 19/19 focused tests. The complete final
suite passed 1,891 tests with one skip in 195.938 seconds under
`ulimit -v 4194304`, at 890,136 KiB maximum RSS, zero test-process swaps and no
kernel OOM event.

`UNKNOWN`: the remapper read result remains unmeasured. Classification remains
`CLASS C (TRANSFORM ONLY)` / `NOT_ELIGIBLE`.

## Resume point

Start a new, non-replayed param transaction from fresh exact native binding.
It must prove stable LOW before one `DLOW -> DMID` write. The two refused IDs
remain immutable evidence and are never reused.
