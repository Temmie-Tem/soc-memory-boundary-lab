# Write gate — A90 exact remapper read at DMID

**Gate status: `PRE_REGISTERED / NOT_EXECUTED`.** This gate covers only
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
  not restored the exact LOW image;
- experiment-owned TWRP staging file and host journals only.

There is no MMIO write. The control contains no MMIO load; the read contains
one fixed-width load and no caller-controlled address, width or value.

## Risk and recovery

Expected failure is a non-secure watchdog followed by Samsung Upload. It may
require one physical power-button action. Permanent-brick and data-loss risk
are bounded by leaving XBL, ABL, TZ, HYP, GPT, RPMB and QFPROM untouched and by
retaining exact V2321/LOW rollback images. Download and TWRP recovery paths are
not modified.

Any target ambiguity, unexpected predecessor hash, partial readback, missing
journal, failed TWRP binding, or rollback/health failure stops the sequence.
An ambiguous read effect is never repeated. A returned value is a security
indicator and permits rollback plus minimum evidence only.

## Measurement

The required evidence is exact MID cmdline attribution, fixed candidate hashes,
one-dispatch receipt, returned value or no-value transport outcome, upload/
watchdog/TZ reset evidence where applicable, full boot/param rollback hashes,
and final V2321 self-test `11/1/0/12`.
