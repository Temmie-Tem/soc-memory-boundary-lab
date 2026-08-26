# Verification 019 — does the DRAM map survive a suspend/resume?

`MAP_INVARIANT`. 0 of 4,194,304 tags moved across a corroborated 25.09-second
deep suspend.

## Why this state change and not another

Verification 018 established that a single-state marker sweep is blind to a
permutation by construction: within any one state every marker reads back
exactly where it was written. `docs/PRIOR_ART.md` states what an alias
candidate must satisfy — `Me a == Mf t` — which is a relation between *two*
states. Two states are what this project has never had.

Verification 015's conditions were all disqualified, for one of two reasons:

| Condition | Why it could not carry a marker |
|---|---|
| reboot, cold power cycle, TWRP ↔ V2321 | the allocation is destroyed, so nothing survives to compare |
| devfreq level | the DDR OPP never moved at all — retracted in `b2b5068`, because `disp_rsc_ebi` votes 12.8 GB/s statically from boot |

Suspend is the first state change that both takes the DRAM controller through a
real transition — self-refresh and power collapse under `mem_sleep = deep` —
and leaves the allocation in place. It is also a legitimate Normal-World
transition, which is the shape P2 has always needed.

## Getting there was the hard part

Suspend had never been attempted on this system: `suspend_stats` read
`success=0, fail=0`. The first thirteen attempts all returned `EBUSY`
instantly, with `last_failed_dev` and `last_failed_step` empty and every
sub-counter zero — which made the sysfs statistics useless for diagnosis.

The kernel log gave the answer directly, and should have been read first:

```
PM: Preparing system for sleep (deep)
PM: Syncing filesystems ...
intr_sync: detected wakeup events before sync
active wakeup source: <name>
Abort: intr_sync failed
```

Samsung's `intr_sync` aborts *before* the freeze step, which is why no step
counter ever incremented. The blockers were layered, and none of them is a
property of the SoC — they are all consequences of running V2321 native init,
which has no userspace to consume what the vendor drivers hold:

| Blocker | Held since | Cleared by |
|---|---|---|
| `18800000.qcom,icnss` | boot + 430 s, ~3.1 hours, never released | `disabled` → its `power/wakeup` |
| `usb_notify` | while the cable is attached; a bare wakeup source with no device, so no sysfs control | unplugging |
| `ssr(modem)`, `pil-modem` | appeared once; also no sysfs control | did not recur |

With `icnss` disabled and the cable out, the **first** attempt succeeded.

## The suspend is corroborated three ways

| Witness | Value |
|---|---|
| `CLOCK_BOOTTIME` − `CLOCK_MONOTONIC` | 25.622 − 0.532 = **25.090 s** |
| `suspend_stats/success` | 0 → **1**, with `fail` unchanged at 13 |
| RPMh `master_stats` APSS | `Sleep Count: 0x1`, duration `0x1cb5f5cf` ticks ÷ 19.2 MHz = **24.96 s** |

The first is the load-bearing one: `CLOCK_MONOTONIC` excludes time spent
suspended and `CLOCK_BOOTTIME` includes it, so their difference *is* the
suspended interval. The third is independent of the kernel's own accounting —
the SoC resource manager recorded the APSS entering hardware sleep, so this was
a real power collapse and not a software-only pass. MPSS shows `Sleep Count:
0x0`; the modem never slept.

## Result

`camera_preview`, 256 MiB, one tag per 64-byte line — 4,194,304 tags covering
offset bits 6..27.

| | |
|---|---|
| Baseline pass, before suspend | **0 mismatches** — the instrument gate |
| Suspended | 25.090 s, corroborated |
| Tags moved | **0 of 4,194,304** |

`MAP_INVARIANT`, `invariance_is_admissible: true`.

## Why the gates are the point

A null result here means nothing unless the tags were readable beforehand *and*
the state change demonstrably happened. Both are enforced, and each way of
failing either one is a separate test asserting that
`invariance_is_admissible` goes false rather than the null passing quietly. The
thirteen `SUSPEND_NOT_REACHED` runs are exactly the case that would otherwise
have been misreported as invariance.

The detector is also shown to be able to report the opposite. `mix` is
splitmix64, a bijection, so it inverts exactly: a location holding another
location's tag names its own source. The synthetic control permutes one address
bit, and every decoded move must point back to that bit — it does, for bits 6,
7, 11 and 12. A permutation, had one occurred, would have been read off
directly rather than merely detected.

## Claims and ranking

`PROVED`: that the system entered deep suspend for 25.09 s, by three
independent witnesses including the SoC's own sleep counter; that all 4,194,304
tags were in their original locations afterwards; and that the analysis detects
and correctly decodes a permutation when one is present.

`PROVED`: the diagnosis of why suspend was unreachable — `icnss` holding a
wakeup source indefinitely under V2321, `usb_notify` while attached — each
named by the kernel at the moment of abort.

`REFUTED`, for this transition: that the address-to-DRAM map changes across a
suspend/resume cycle. Over offset bits 6..27 in this allocation, at 64-byte
granularity, nothing moved.

`UNKNOWN`, unchanged: whether any transform is mutable by a state change this
project has not reached; where the check sits in the data path; and P2 on every
route already refuted. Offset differences equal physical differences only under
the contiguity Verification 016 established behaviourally.

This is the first *direct* test of P1 mutability rather than an argument about
it, and it is a negative. The premise of Verification 017 stands — enforcement
cannot be bank-granular, so a mutable map would matter — but no state change
available from Normal World moves the map.

Class C `TRANSFORM ONLY` is unchanged. No boundary-bypass indicator appeared;
had a tag moved, the standing stop condition would have applied.

## Device actions

Allocate, map, write and read inside the process's own ION allocation, free.
One temporary ION node, removed. Two `power/wakeup` attributes set to
`disabled` and **restored to `enabled`** afterwards — a documented, reversible
Linux PM interface. One string written to `/sys/power/state`. No register,
MMIO, SMC, EL2/EL3, protected-memory or partition access.

Suspend was authorised under the standing contract as a transient, manually
recoverable transition with the operator physically present, and resume never
depended on that: a `CLOCK_BOOTTIME_ALARM` was armed before every attempt and
no attempt was made without one.

## Reproduce

```
aarch64-linux-gnu-gcc -O2 -static -Wall -Wextra \
  -o a90_suspend_permute tools/a90_suspend_permute_probe.c
./a90_suspend_permute camera_preview 256 90 25 12 /dev/ion out.jsonl

python3 tools/a90_suspend_permutation_analysis.py \
  --raw evidence/private/verification-019-suspend-permutation-20260827-01/suspend-permutation.jsonl \
  --output evidence/manifests/verification-019-suspend-permutation-20260827-01.manifest.json
python3 -m unittest -v tests.test_a90_suspend_permutation_analysis
```

The analysis runs its synthetic control with or without `--raw`, so the
detector can be verified on the host before the device is touched.
