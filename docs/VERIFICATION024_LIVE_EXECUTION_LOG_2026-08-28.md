# Verification 024 live execution log — 2026-08-28

## Current state

**`CONTROL_BOOTED / PARAM_MID_PROVED / CONTROL_FIXED_OP_NOT_DISPATCHED /
CONTROL_R2_RECONCILIATION_REQUIRED`.**

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
- `04:58:02–04:58:05`: the fourth, fresh `param` owner proved stable LOW
  `c0c71474...`, dispatched one four-byte `DLOW -> DMID` write, and proved
  stable MID `9b85da06...`. Complete transfer hashes were
  `1faafee9... -> 50e5c715...`; byte 0 remained `0x00`; force-upload, FMM and
  dump-sink fields were unchanged. Write count was one and replay was false.
- `04:58:29–04:59:21`: one native reboot consumed MID. A new boot returned as
  exact `SM-A908N/SM8150`, V2321, `debug_level=0x494d`, force-upload `0`,
  dump-sink `0`, download mode `1`, and self-test `11/1/0/12`. Reboot dispatch
  count was one and replay was false.

`SUPPORTED`: the current native boot is the verified control candidate. The
current boot prefix will be re-attested immediately before fixed op 4; until
that succeeds, current-running-image identity is not promoted to `PROVED`.

## Pre-effect refusals

`PROVED`: none of the three refusals reached the four-byte `param` effect.

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
3. `verification-024-param-control-apply-mid-r3` passed the repaired cmdline
   gate, created the fixed temporary block node, then exposed a second
   host/live mismatch: native `stat` uses CRLF between its two lines and no
   terminal newline. The old tool left its private status at `PREFLIGHT`, but
   both private and public evidence record `effect_dispatched=false`, no
   partition write, and the exact parser error. An independent absence command
   after the failure returned `rc=0,status=ok`, proving the node was removed.

The retained cmdline is 2,513 bytes, SHA-256
`e326100bfec8cb595a413c968dc565bbab47327324423ba5420b3a75b41fbf23`,
with exactly one double-space at offset 446 between keys
`androidboot.keymaster` and `androidboot.ulcnt`. The complete value is private.

The exact live block-node `stat` value is 39 bytes, SHA-256
`0993514304d5b15b220d3b97c687e7ebd086ec7d67c7e2543bd5da0adb39a97c`,
with semantic value `mode=0600 uid=0 gid=0 size=0`, CRLF, then `rdev=8:10`
and no terminal newline. The diagnostic node was removed in a `finally` path
and its absence was verified; no read or write was issued through it.

## Control pre-dispatch incident

`PROVED`: `verification-024-control` did not dispatch fixed op 4 and did not
start the temporary panic transition. Its private/public triplet records
`REFUSED_PRE_DISPATCH`, `dispatch_count=0`, `effect_dispatched=false`, no
semantic claim, no boot attestation, no partition/MMIO write, and no returned
value. The exact retained hashes are:

| Artifact | Size | SHA-256 |
|---|---:|---|
| public incident | 3,715 | `fcdeaf36d10c112751c0c429eb9834b140bbefb7e83ad18051f9f73e4f237af4` |
| private raw | 4,952 | `4adbdfccb68232f42e6c6a60a57c8acb0be98db5ba01d77db4750993c11ca649` |
| private journal | 4,662 | `e6d4589be21c11601a4f0be91a1a3d992b66b17dfe80a896a8d8f176ebb77b04` |

The old wrapper rejected a complete non-empty `stophud` success payload before
returning it to the shared arbiter. Commit `6eaad666...` pins that producer;
the old inline source is `0b171d4c...`, old arbiter is `5da86cb9...`, and
transport source is `0f50a204...` (150,104 bytes).

`UNKNOWN_IDEMPOTENT`: the discarded frame bytes cannot be reconstructed, so
whether that one `stophud` call actually stopped a running HUD is unknown. The
exact source makes either success path idempotent. This does not weaken the
`PROVED` zero fixed-op/panic/partition/MMIO result and is not authority to
reuse the original experiment ID.

Live source-backed receipts prove that successful `stophud` payloads are
exactly `autohud: stopped` (16 bytes, `2ff11ad1...`) or
`autohud: not running` (20 bytes, `9c49f25b...`); an exact busy refusal has an
empty payload. The former empty-success assumption is `REFUTED`.

## Host repair and review

The four V024 lifecycle parsers now treat one-or-more ASCII spaces as token
delimiters while continuing to reject tabs, vertical tabs, form feeds,
embedded/bare CR/LF, NUL, surrounding spaces, repeated terminal newlines,
duplicate keys and unknown bare flags. Exact required target values are
unchanged.

Independent frozen-hash review returned `GO`: 870/870 whitespace rows and
743/743 frame-regression rows passed, with `P0=0` and `P1=0`. The affected set
passed 112/112 and the six-module gate passed 180/180. Public boot-ID redaction
then passed 87 hostile assertions and 19/19 focused tests. After the live stat
and incident-journal repair, independent review passed a 48-row four-path stat
matrix, 24 transition state-machine scenarios, 835 frame attacks and 204
cmdline attacks with `P0=P1=P2=0`. The complete final suite passed 1,895 tests
with one skip in 198.129 seconds under `ulimit -v 4194304`, at 893,252 KiB
maximum RSS, zero test-process swaps and no kernel OOM event.

The post-incident stop-HUD repair then converged through hostile rounds 24–26.
The shared contract accepts only the two source-defined success strings and an
empty `-16/busy` payload, canonical A90P1 fields, one exact terminal/prompt
tail, payload at most 20 bytes and transcript at most 4,096 bytes. Invalid
complete frames are retained once as validation errors, never transport
errors; callback mutation and cross-consumer size drift are rejected. The
final exact eleven-module set passed 319 tests, maximum RSS 349,056 KiB and
zero process swaps. The complete repository suite then finished 1,916 tests
with 1,915 passed and one skipped in 198.868 seconds, maximum RSS 893,116 KiB,
zero process swaps and no kernel OOM event. Independent review reports Part A
`P0=P1=P2=0`.

The native-reboot public v1 projection exposed one transient raw boot UUID.
That v1 is retained only as a private 1,884-byte archive with SHA-256
`3a91e6ea...`. The source journal (`8760aa1f...`, 22,905 bytes) and physical
claim (`03d1f63e...`, 663 bytes) produced a deterministic public v2 of 2,140
bytes, SHA-256 `fbe92a29...`, containing only the ASCII/no-newline boot-ID
hash. Source inode, mode, owner, size, hash, mtime and ctime were unchanged
across the host-only repair; no source had an open writer. A second invocation
verified the repaired state without changing its bytes. Under this explicit
immutable-evidence precondition, independent Part B review is
`P0=P1=P2=0`. A malicious non-cooperating same-UID writer is outside this
authority model; every later consumer must still revalidate the pinned hashes.
The exact operator transcript projection and its bounded evidence grade are in
`docs/VERIFICATION024_REBOOT_PUBLIC_REPAIR_RECEIPT_2026-08-28.md`.

`UNKNOWN`: the remapper read result remains unmeasured. Classification remains
`CLASS C (TRANSFORM ONLY)` / `NOT_ELIGIBLE`.

## Resume point

Do not rerun `verification-024-control`: it is immutable incident evidence.
Before another device command, implement and review one fixed
`verification-024-control-r2` owner. It must create its O_EXCL intent before
validating and hash-binding the exact old triplet, record the historical frame
as unrecoverable, permit only a new idempotent `stophud` qualification, and
retain the original `(mode,candidate,boot_id)` semantic-claim key. The old ID
becomes predecessor-only in the producer, finalizer, READ authorizer and
last-kmsg source validator; no dual-ID fallback or r3 is permitted.

The current persistent state is already proven MID. No further `param` write
or reboot is needed before r2 unless a fresh read-only preflight disproves that
state. The three refused param IDs and the original control ID remain immutable
and are never reused.
