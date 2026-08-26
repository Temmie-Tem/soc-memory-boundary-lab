# Verification 017 — can a bank-granular check separate protected memory?

Host-only. No device access, no new measurement. Everything here follows from
the relation Experiment 023R recovered and Verification 016 extended, and from
carveout bases already `PROVED` from the live device tree.

## Why

The Skitter question decomposes into two premises. P1: a mutable address
transform sits downstream of the protection check. P2: Normal World can reach
the state that changes it. P2 is closed on every route this project has tested.
P1 has an unexamined half — *where the check sits relative to the transform* has
been `UNKNOWN` since Experiment 008, and no experiment has proposed a way at it,
because observing enforcement ordering in the data path needs either a
controller write or a protected read, and both are outside the standing
authority.

One part of the ordering can be settled without either, and it needed the
relation to be wide enough to be worth asking.

## The argument

Experiment 023R recovered a rank-3 GF(2) bank-selection relation; Verification
016 extended it to PA27 with the rank unchanged. Rank 3 means **eight bank
classes**. The lowest address bit carrying a contribution is PA13, so the class
changes every **8 KiB**, and three independent contributions have appeared by
PA15, so any region of **64 KiB** or more covers all eight classes.

Every protected carveout on this target is megabytes wide. So is the
unprotected `System RAM` around them.

| Region | Pages | Classes covered |
|---|---:|---:|
| `hyp_mem` `0x85700000` +6 MiB | 1,536 | 8/8 |
| `tima_region` `0xB0000000` +2 MiB | 512 | 8/8 |
| `rkp_region` `0xB0200000` +2 MiB | 512 | 8/8 |
| `uh_heap_region` `0xB0400000` +20 MiB | 5,120 | 8/8 |
| `qseecom_region` `0xA6000000` +36 MiB | 9,216 | 8/8 |
| System RAM `0x80002000-0x856fffff` | 22,270 | 8/8 |
| System RAM `0x85d00000-0x85dfffff` | 256 | 8/8 |
| System RAM `0x9c400000-0x9fffffff` | 15,360 | 8/8 |
| System RAM `0xa8400000-0xafffffff` | 31,744 | 8/8 |
| System RAM `0xb0200000-0xbcbfffff` | 51,712 | 8/8 |
| System RAM `0xc1c01000-0x1ffffffff` | 1,303,551 | 8/8 |

Protected and unprotected memory occupy exactly the same eight bank classes.
A check that saw only a bank index could not tell them apart.

Even the smallest protected region, TIMA at 2 MiB, is 32 times the span needed
to cover every class. The margin is not narrow.

## An independent cross-check fell out of this

Verification 016 determined by measurement that `f(PA25) = f(PA14) = f(PA21)`,
`f(PA26) = f(PA19)` and `f(PA27) = f(PA13) = f(PA20)`. Experiment 023R's solved
table, produced earlier from a different heap, region and runtime, already
contains `f(PA14) = f(PA21) = 0b010` and `f(PA13) = f(PA20) = 0b001`.

The two agree on every pair. Neither was fitted to the other, and the analysis
asserts the agreement rather than assuming it — a disagreement is reported, and
the test suite injects one to confirm it would be caught.

## What this settles, and what it does not

`REFUTED`: that enforcement on this target could read only post-decode **bank**
coordinates. It could not distinguish TIMA from ordinary `System RAM` if it did,
because both occupy all eight classes.

This does **not** settle the ordering question, and it should not be read as
doing so. The full DRAM coordinate — channel, rank, bank, row, column — is a
bijection with the physical address whenever the map is invertible, so a check
on the complete post-decode coordinate carries exactly the same information as a
check on the address and is not distinguishable this way. What is excluded is
the *narrow* post-decode check.

That exclusion is the one that mattered, though. A narrow post-decode check is
the only shape of enforcement that would have made the transform irrelevant:
if protection were expressed in bank terms, changing the address-to-bank map
would move protected and unprotected data together and nothing would escape.
Since enforcement must retain address information the bank index does not carry,
a mutable map downstream of it would move data under a check that cannot see the
move. That is the Skitter mechanism, and this is the first evidence that its
premise holds structurally on SM8150 rather than by analogy with AMD.

## Claims and ranking

`PROVED`: the class-change granularity of 8 KiB and the 64 KiB covering span,
both derived from the relation; the per-region class histograms above; and the
agreement between Verification 016's discrimination and Experiment 023R's
solved table.

`REFUTED`: a bank-granular post-decode check as the enforcement mechanism on
this target, for the carveouts listed and under the recovered relation.

`SUPPORTED`: that P1's premise — enforcement above a transform that can move
data beneath it — is structurally available on SM8150. This is an argument from
granularity, not an observation of the data path, and it is weaker than a
measurement would be.

`UNKNOWN`, unchanged: where the check actually sits in the data path; whether
any transform is mutable at all; and P2 on any route not already refuted. The
relation's own bounds also carry: PA28 and above are unmeasured, and every
region here is assumed contiguous in the sense the device tree declares.

Class C `TRANSFORM ONLY` is unchanged. Nothing here is a bypass, an alias, or a
mutation; it narrows one `UNKNOWN` by exclusion.

## Reproduce

```
python3 tools/a90_protection_bank_granularity.py \
  --output evidence/manifests/verification-017-protection-bank-granularity-20260827-01.manifest.json
python3 -m unittest -v tests.test_a90_protection_bank_granularity
```

No private inputs. The manifest is fully derived and contains no device data.
