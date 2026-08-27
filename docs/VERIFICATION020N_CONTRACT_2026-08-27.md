# Verification 020N contract - bounded normal-RAM PA28 timing candidate

## Status and ownership

020N is the selected next discriminator after the independently retained 020M
DT precondition and 021 allocation-extent evidence.  This change is design and
host-validation only: the new probe is **not executed on a device**, and no
020N live receipt or result is claimed.  The new files are owned by 020N:

```text
tools/a90_pa28_timing_probe.c
tools/a90_pa28_timing_analysis.py
tests/test_a90_pa28_timing_analysis.py
docs/VERIFICATION020N_CONTRACT_2026-08-27.md
experiments/verification-020N-pa28-timing/README.md
```

The separately introduced `tools/a90_pa28_probe.c` is Verification 022's
broader future candidate.  It is not copied, modified, or promoted by 020N;
it remains unexecuted until it has its own fixed wrapper, receipt schema,
independent review, and authorization.  020N therefore has one bounded
probe/analyzer surface and does not share 022's dynamic arguments or
pagemap-based provenance path.

## Objective

If a future, separately authorized run satisfies the exact 020M and 021 gates,
measure a normal-RAM timing candidate for the offset pair whose fixed
difference is `0x10000000` (one bit at PA28).  The pair is taken inside one
full-size `camera_preview` allocation.  The measurement is a bank/reopen
timing discriminator only; it is not an alias proof, a physical-address
receipt, a controller test, or a protected-memory test.

## Required independent preconditions

The host reducer opens all inputs as stable regular files with `O_NOFOLLOW`
and rejects size, inode, timestamp, or SHA-256 drift before reduction.

1. 020M public manifest
   `verification-020m-pa28-dt-20260827-03.manifest.json` is pinned at 8,246
   bytes, SHA-256
   `69b087bd5a6aa279fff9c943405b46491381f3461c5ea1ac57f4d2f287d8ad9a`.
   Its private raw receipt pin is 15,435 bytes,
   `40a3207d3f822775c4506415a579e993c07a6a7f9ff998e41a6f76cb6216a2ec`.
   The reducer requires exact target `SM-A908N` / `SM8150`, heap id 30/name
   `camera_preview`, phandle `0x67a`, base `0xc2000000`, size
   `0x14000000`, present `ion,recyclable`, and explicit `ENOENT` absence of
   `no-map` and `reusable`.
2. 021 public manifest
   `verification-021-carveout-exhaustion-20260827-01.manifest.json` is pinned
   at 4,586 bytes, SHA-256
   `82471b458f87e1ed86596ab08c97bab743ee868edf98d7d272c1d131046c168b`.
   The required schema is `a90_carveout_exhaustion_v2`; it must retain the
   successful 320-MiB hold, `HOLD_CONSUMES_POOL`, 5/5 controls before and
   after, zero allocations under hold, and `instrument_ok=true`.

The 020M DT advertisement and 021 extent receipt are separate evidence.  They
make a full-size test feasible and support the declared span condition; they
do not by themselves establish a future allocation's page identity or timing
outcome.

## Fixed probe surface

The new C probe accepts no arguments (`argc` must be one).  It hardcodes and
checks all of the following:

| Field | Fixed value |
|---|---|
| ION heap | `camera_preview`, type 10, id 30 |
| Allocation | 320 MiB = 335,544,320 bytes; ION flags 0 (write-combine mapping) |
| Candidate difference | `0x10000000` |
| Negative differences | `0x10002000` and `0x10004000` (PA28 plus one known bank-bit perturbation) |
| Pair offsets | eight fixed page-aligned offsets, each checked before pointer formation |
| CPU | CPU 7 |
| Repetitions / warmups | 1001 / 17 per pair, alternating relation and baseline order |
| Reduction | 10% trimmed reopen deltas, divided by two reopens |
| Cache control | one-page anonymous cached mapping with fixed `dc civac` samples |

The probe performs only `ION_IOC_HEAP_QUERY`, one own-allocation
`ION_IOC_ALLOC`, a shared mapping of that allocation, and reads/writes inside
the process-owned normal-RAM mappings.  It has no dynamic command, path,
heap, size, difference, or repetition input.  It does not open pagemap, form
physical addresses, inspect MMIO, invoke SMC/SCM, access secure/protected
memory, or write a controller, partition, firmware, or unrelated device
memory.  Any missing heap, type/id drift, failed full allocation, mapping
failure, out-of-range fixed pair, or failed control aborts the probe.

The raw record explicitly carries `pagemap=NOT_USED` and
`physical_address_provenance=NOT_COLLECTED`.  The host reducer rejects a
receipt that changes either value or introduces an unrecognized record.

## Receipt and host reduction

The probe schema is `a90_pa28_timing_probe_v1`.  A complete receipt must have
exactly one context, heap, allocation, summary, and the following records:

```text
control: cache_maintenance
measurement: same_offset
measurement: pa28_candidate
measurement: negative_bank_bit13
measurement: negative_bank_bit14
```

The reducer (`a90_pa28_timing_analysis.py`) requires the exact parameter and
safety fields, percentile ordering, fixed differences, 8 pairs, 1001
repetitions, 17 warmups, and successful statuses.  It requires the same-offset
median to be centered on zero and the candidate p10 to exceed both negative
control p90 values by at least 100 milli-ticks.  Failure is
`PA28_UNRESOLVED`/`INSTRUMENT_FAILED`; it is never rewritten as a negative.

If every control and separation gate passes, the bounded reduction may label
the statistics `PA28_TIMING_CANDIDATE`.  That label is deliberately below
`PROVED`: it does not establish `f(PA28)`, a physical address, an alias, a
complete DRAM coordinate, or any security-boundary reach.  The generated
manifest remains `CLASS C (TRANSFORM ONLY)` / `NOT_ELIGIBLE` and contains only
input pins, offsets, summaries, and explicit unknowns, never raw receipt
bytes or private paths.  Publication uses `O_EXCL`, `O_NOFOLLOW`, fsync, and
refuses an existing output.

## Stop gates

Stop before any live use if either dependency changes, target/heap/allocation
identity differs, the exact fixed surface cannot be attested, a cache or
same-offset/negative control fails, a receipt contains pagemap or physical
provenance, or a timing class overlaps the negatives.  A transport timeout or
partial receipt is an incident, not a replay trigger.  A timing candidate does
not authorize any protected-memory, controller, SMC, MMIO, firmware,
partition, reboot, or follow-up mutation.

## Host-only validation

The intended checks are:

```sh
gcc -std=c11 -Wall -Wextra -Werror -fsyntax-only \
  tools/a90_pa28_timing_probe.c
python3 -m unittest -v tests.test_a90_pa28_timing_analysis
```

These commands inspect or compile locally only.  No device command is part of
020N's current implementation pass.
