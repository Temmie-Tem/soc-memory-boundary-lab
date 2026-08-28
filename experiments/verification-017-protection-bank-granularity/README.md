# Verification 017 — can a bank-granular check separate protected memory?

Host-only. No device access, no new measurement. Everything here follows from
the relation Experiment 023R recovered and Verification 016 extended, and from
carveout bases already `PROVED` from the live device tree.

The analyzer pins and semantically parses the exact public inputs before
calculating anything.  It rejects a changed 023R kernel basis, changed fixed
reserved range, changed `/proc/iomem` range, malformed range section, or
duplicate source object key rather than silently applying the hardcoded model
to a different source.

| Input | Bytes | SHA-256 |
|---|---:|---|
| `023R-repaired-region-bank-relation-20260826-01.manifest.json` | 18,040 | `5c3e14ff898c109de740d98260d974bca10751000f85977775cd467ac74aac2e` |
| `verification-016-high-bit-relation-20260827-01.manifest.json` | 59,504 | `72525cf994e52bbee1c3ed685c49a6ace4049cd7b279cb97811f6a0d3f4f773f` |
| `MEMORY_MAP.md` | 9,428 | `34496c0d92736f7df5b9da69f8bcadfe40fb3ee35558c1b10fab7d06dec86950` |

If any pinned input changes, analysis stops rather than silently reusing stale
region or relation data. The public manifest contains sanitized basenames,
sizes and hashes only.

## Why

The Skitter question decomposes into two premises. P1: a mutable address
transform sits downstream of the protection check. P2: Normal World can reach
the state that changes it. P2 is not globally closed: known remapper and
controller apertures have no HLOS grant in the retained TZ policy and one fixed
EL1 load failed, while dynamic/indirect routes remain `UNKNOWN`. P1 has an
unexamined half — *where the check sits relative to the transform* has been
`UNKNOWN` since Experiment 008.

This audit does not attempt a controller write or protected read. Those actions
would require their own exact write-gate and are unnecessary for the bounded
bank-granularity exclusion below.

One part of the ordering can be settled without either, and it needed the
relation to be wide enough to be worth asking.

## The argument

Experiment 023R recovered a rank-3 GF(2) bank-selection relation; Verification
016 extended it to PA27 with the rank unchanged. Rank 3 means **eight bank
classes**. The lowest address bit carrying a contribution is PA13, so the
minimum class-change span is **8 KiB**, and three independent contributions have appeared by
PA15, so any **64 KiB-aligned** region of 64 KiB or more covers all eight
classes. At an arbitrary base the conservative guarantee is **128 KiB**: that
width is certain to contain an aligned 64 KiB sub-block. A 64 KiB region at an
arbitrary base can cover as few as four classes; this distinction is checked by
the host sweep and is not hidden by an unconditional number.

Every protected carveout on this target is megabytes wide. So is the
unprotected `System RAM` around them.

The comparison uses only page-aligned `System RAM` fragments at least 128 KiB
long (or 64 KiB-aligned fragments at least 64 KiB long). The isolated 4-KiB
`0x80000000-0x80000fff` fragment is retained as an explicit exclusion because
a bank-only check could distinguish such a sub-span; it is not silently treated
as representative ordinary RAM.

| Region | Pages | Classes covered |
|---|---:|---:|
| `hyp_mem` `0x85700000` +6 MiB | 1,536 | 8/8 |
| `tima_region` `0xB0000000` +2 MiB | 512 | 8/8 |
| `rkp_region` `0xB0200000` +2 MiB | 512 | 8/8 |
| `uh_heap_region` `0xB0400000` +20 MiB | 5,120 | 8/8 |
| `qseecom_region` `0xA6000000` +36 MiB | 9,216 | 8/8 |
| System RAM `0x80002000-0x856fffff` | 22,270 | 8/8 |
| System RAM `0x85d00000-0x85dfffff` | 256 | 8/8 |
| System RAM `0x85f40000-0x85ffffff` | 192 | 8/8 |
| System RAM `0x9c400000-0x9fffffff` | 15,360 | 8/8 |
| System RAM `0xa8400000-0xafffffff` | 31,744 | 8/8 |
| System RAM `0xb1800000-0xbcbfffff` | 46,080 | 8/8 |
| System RAM `0xc0000000-0xc10fffff` | 4,352 | 8/8 |
| System RAM `0xc1300000-0xc13fffff` | 256 | 8/8 |
| System RAM `0xc1c01000-0x1ffffffff` | 1,303,551 | 8/8 |

Under this **allocation-offset/model-coordinate projection**, protected and
unprotected ranges occupy exactly the same eight bank classes. A check that saw
only a bank index could not tell them apart in that projection. This is not a
proof that the listed physical ranges share a complete DRAM coordinate: physical
mapping, effective contiguity and the complete coordinate remain `UNKNOWN`.

Even the smallest protected region, TIMA at 2 MiB, is 16 times the arbitrary-
base span needed to cover every class. The margin is not narrow.

## An independent cross-check fell out of this

Verification 016 determined by measurement that `f(PA25) = f(PA14) = f(PA21)`,
`f(PA26) = f(PA19)` and `f(PA27) = f(PA13) = f(PA20)`. Experiment 023R's solved
table, produced earlier from a different heap, region and runtime, already
contains `f(PA14) = f(PA21) = 0b010` and `f(PA13) = f(PA20) = 0b001`.

The two agree on every pair. Neither was fitted to the other, and the analysis
asserts the agreement rather than assuming it — a disagreement is reported, and
the test suite injects one to confirm it would be caught.

## Bank relation is not a complete-coordinate result

The analyzer constructs three finite GF(2) countermodels over the exact
allocation-offset/model bits PA13..PA27. All preserve the same first three bank
output rows. One appends every retained high model bit and is injective; one
omits one high coordinate and is non-injective; and one keeps only the bank
projection and has the large kernel already seen in the timing relation. The
first non-zero null address of the folded model is `0x08002000`, the exact
PA13/PA27 equality measured by Verification 016. These are abstract
completions, not claims about physical DRAM coordinates.

Therefore the same observed rank-3 bank relation is compatible with both a
one-to-one complete-coordinate map and a non-injective map. The audit proves
underdetermination of complete-coordinate injectivity; it does not choose one
for silicon. A bank collision is a necessary condition for a complete alias in
these models, never sufficient evidence of one.

## What this settles, and what it does not

`REFUTED` within the listed ranges and recovered relation **as a model
projection**: a check that reads only post-decode **bank** coordinates cannot
distinguish TIMA from ordinary `System RAM`, because both occupy all eight
projected classes. This is not a statement that the physical ranges are known
to be contiguous or aliasing, and it is not proof of the actual ordering or of
a complete-coordinate check.

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

`PROVED`: the minimum class-change span of 8 KiB; the 64 KiB covering span for
64 KiB-aligned regions and 128 KiB for arbitrary bases, both derived from the
relation and the second checked by a 512-base sweep per size; the model-
projected per-region class histograms above; the source kernel-basis and
MEMORY_MAP semantic matches; the injective/non-injective abstract countermodels;
and the agreement between Verification 016's discrimination and Experiment
023R's solved table.

`REFUTED` within the listed ranges and recovered relation as a model projection:
a check that reads only post-decode **bank** coordinates cannot distinguish TIMA
from ordinary `System RAM`, because both occupy all eight projected classes.
This is a statement about that narrow enforcement shape, not proof of the
actual ordering or of a complete-coordinate check.

`PROVED` within the abstract countermodel: the rank-3 bank relation alone
proves neither complete-coordinate injectivity nor complete-coordinate alias.
Both an injective and a non-injective completion preserve the exact bank
projection.

`SUPPORTED`: the bank-only exclusion leaves enforcement that retains additional
address information as the remaining structural possibility, so a downstream
mutable transform is not ruled out by bank granularity alone. This is an
argument from a model projection, not an observation of the physical data path,
and it is weaker than a measurement would be.

`UNKNOWN`, unchanged: where the check actually sits in the data path; whether
any transform is mutable at all; P2 on any route not already refuted; the
complete DRAM coordinates and their injectivity; the physical status of the
ranges; and which abstract ordering model, if any, matches hardware. The
relation's own bounds also carry: PA28 and above are unmeasured, and every
region here is assumed contiguous in the sense the device tree declares.

Class C `TRANSFORM ONLY` is unchanged. Nothing here is a bypass, an alias, or a
mutation; it narrows one `UNKNOWN` by exclusion.

## Reproduce

```
python3 tools/a90_protection_bank_granularity.py \
  --output evidence/manifests/verification-017-protection-bank-granularity-20260827-05.manifest.json
python3 -m unittest -v tests.test_a90_protection_bank_granularity
```

The output is created with `O_EXCL`/`O_NOFOLLOW`, mode `0644`, and no-clobber;
the existing `...-01` file is the unpinned predecessor from the external branch
and is retained only for provenance. No private inputs are read and the
manifest is fully derived; it contains no device data. The fresh publication
used for this revision is `...-05` (18,108 bytes, SHA-256
`97ff68a2f8ebfb6313f228f2626f12f88260764a993f916ba1f97677d7b99f02`, mode
`0644`).
