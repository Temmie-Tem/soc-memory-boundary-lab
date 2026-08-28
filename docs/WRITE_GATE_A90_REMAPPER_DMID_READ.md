# Write gate — A90 exact remapper read at DMID

**Gate status: `LIVE_CONTROL_BOOTED / PARAM_EFFECT_NOT_DISPATCHED /
PARSER_REPAIR_GO / RESUME_READY`.** This gate covers only
Verification 024 on exact `SM-A908N`/`SM8150`.

## Exact target and necessity

The target read is one 32-bit load at physical address `0x09248080` after an
`__ioremap` of exactly `0x5c` bytes. It is necessary because Verification 023
substituted the SHRM page `0x0906566c`; the remapper page has a distinct narrow
`DC_NOC_BROADCAST_MPU` policy and remains untested at `DMID`.

## Writes

- boot prefix: exactly 60,882,944 bytes per transition, fixed chain
  `V2321 -> control -> read -> V2321`, each with complete before/after SHA-256;
- `param`: exactly four bytes at partition offset `0x900000`, fixed
  `DLOW -> DMID`, once for the control and once for the read only if its
  post-TWRP state is exact LOW; conditional `DMID -> DLOW` only if TWRP has
  not restored the stable LOW state. Every entry/restoration decision uses
  the fixed `[1,0xA00000)` hash plus decoded gate fields; byte 0 is retained
  and full-hash-bound but excluded from state eligibility;
- runtime sysctl: fixed `panic_on_oops: 1 -> 0` immediately before each op;
  restore and verify `1` on every returning op, or defer to post-reset/final
  verification after a watchdog disconnect;
- current-boot attestation: one fixed temporary block node and one
  60,882,944-byte prefix file under `/tmp/a90-native`, removed with strict
  absence before op dispatch;
- native command arbitration: fixed `stophud` at each native lifecycle-tool
  entry point; only explicit `busy/-16` refusals may be retried, at most three
  attempts total. The retained source proves that an already-stopped call is
  idempotent and returns zero; non-busy or ambiguous transport errors stop;
- experiment-owned TWRP staging file and host journals only.

There is no MMIO write. The control contains no MMIO load; the read contains
one fixed-width load and no caller-controlled address, width or value.

## Risk and recovery

Expected failure is a non-secure watchdog followed by Samsung Upload. It may
require one physical power-button action. Permanent-brick and data-loss risk
are bounded by leaving XBL, ABL, TZ, HYP, GPT, RPMB and QFPROM untouched and by
retaining exact V2321/LOW rollback images. Download and TWRP recovery paths are
not modified.

If the sole boot-prefix `dd` is interrupted, its unknown partial hash is
deliberately outside the normal predecessor set, so the candidate flash helper
refuses replay. The separate
`tools/a90_twrp_boot_rollback_recovery.py` owner consumes only the exact
ambiguous journal, binds the exact A90 Recovery target and current boot state,
and permits at most one fixed V2321 rollback-prefix write. It closes with zero
writes if rollback is already complete and never writes the experimental
candidate.

If a four-byte `param` effect becomes ambiguous, the normal transition helper
is not replayed. `tools/a90_param_debug_recovery_live.py` source-binds that
ambiguous journal, captures the complete partition with before/host/after
hashes, and permits at most one fixed DLOW repair only for exact MID or a torn
debug field over an otherwise exact LOW image. Any difference outside that
field is a refusal.

Every Recovery/ADB subprocess has a fixed finite timeout. A pre-effect timeout
is a refusal. A timeout after the durable partition-write marker is recorded as
ambiguous, and only reconciliation or the fixed source-bound recovery owner
above is allowed. It never means an ad-hoc candidate replay.

Any target ambiguity, unexpected predecessor hash, partial readback, missing
journal, failed TWRP binding, or rollback/health failure stops the sequence.
An ambiguous read effect is never repeated. A returned value is a security
indicator and permits rollback plus minimum evidence only.

## Measurement

The required evidence is exact MID cmdline attribution, current boot-prefix
hash matching the selected candidate, fixed flash-journal hashes, verified
`panic_on_oops` transition/restoration state, one-dispatch receipt, returned
value or no-value transport outcome, upload/watchdog/TZ reset evidence where
applicable, full boot/param rollback hashes, and final V2321
`panic_on_oops=1` plus self-test `11/1/0/12`.

Host qualification on 2026-08-28 rehashed every complete boot/param artifact
and the fixed 88-byte op buffer. After the live cmdline parser repair, the
execution closure passed 1,891 serial tests with one skip under a 4-GiB
virtual-memory ceiling, at 890,136 KiB maximum RSS, zero test-process swaps and
no kernel OOM event. Independent hostile review passed 743 frame rows, 156
stable-`param`/static rows and 870 whitespace rows with `P0=0` and `P1=0`.
Fresh exact A90 binding remains required before each live action.
