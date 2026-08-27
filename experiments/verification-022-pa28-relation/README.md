# Verification 022 — f(PA28) (retained-receipt model extension)

**Disposition: `SUPPORTED_WITHIN_RETAINED_RECEIPT`.** The retained two-phase
receipt selects `f(PA28) = 010 = f(PA14)` within the recovered rank-3 model.
This is not a new device run and does not prove a physical alias, complete
address mapping, transform mutability, or a bypass.

## What made this runnable

Verification 016 recovered the relation up to model bit PA27 and left *whether
the pattern continues above it* `UNKNOWN`. The obstacle was never subtle: a pair
differing in only bit 28 needs a span exceeding `2^28`, and the 256 MiB
allocations of V016, V018 and V019 miss that by exactly one bit.

Three results removed it, in order:

| | |
|---|---|
| V020 | measured `camera_preview`'s ceiling at **320 MiB**, not the 256 MiB previously asserted |
| V021 | proved a full-size allocation **consumes the whole carveout** — with 320 MiB held, not one 4 KiB page remains, between two 5/5 controls |
| device tree | publishes that carveout at base **`0xC2000000`** |

The retained dependencies therefore provide the model's declared relation
`offset o -> 0xC2000000 + o`; the analyzer still treats the 022 target and
bridge provenance as `UNKNOWN_UNRETAINED` because no same-run preflight receipt
was retained.

## What changed in the instrument

`tools/a90_region_probe_r.c` required a power-of-two allocation and had to
*solve* for the allocation's offset inside its region behaviourally, sweeping
bits 13..23 to measure an alignment it could not read. 320 MiB is not a power of
two, and the base is now known, so `tools/a90_pa28_probe.c` verifies instead of
solving:

```c
if (((base + a) ^ (base + b)) != difference) { ++rejected_carry; continue; }
```

Every candidate pair must have the physical XOR its difference names. A carry
that would smear a single-bit difference across bits it does not isolate cannot
enter the sample. That is strictly stronger than assuming a power-of-two size,
and it is what allows a non-power-of-two span to be used at all.

The timing core, barriers, warmups, alternation, trimming and divisor are copied
verbatim from `a90_region_probe_r.c`, which copied them verbatim from Experiment
014. No instrumentation difference is introduced.

Across the retained phases, **3,029 pair records re-check with 0 mismatches** —
every retained pair isolates exactly the bit its difference names. For
`0x10000000` the receipt reports 147 of 256 offsets rejected for range and **0
for carry**. These are receipt facts, not an assertion that a current device
run has been reproduced.

## Question one — is `f(2^28)` nonzero?

`camera_preview`, 320 MiB, 201 repetitions, 256 pairs, CPU 7, `spread` offsets,
`dsb_ld`, `kept_times_two`. Two bracketed passes.

| Difference | Pairs | Median | Band |
|---|---:|---:|---|
| `0x16000` — same-phase CONFLICT control | 256 | 546 / 543 | 506..593 |
| `0x2000` — same-phase NEGATIVE control | 256 | 149 / 145 | 86..211 |
| **`0x10000000`** | 109 | **217 / 220** | 139..316 |

Both passes agree. The `0x10000000` distribution is **unimodal**, and its
maximum (369) sits below the CONFLICT control's minimum (444) — the two do not
overlap at the pair level, let alone at the median.

So flipping PA28 alone does not present as a same-bank-different-row conflict:
`f(2^28) ≠ 0`.

## Question two — which element is it?

`f(PA13)`, `f(PA14)`, `f(PA15)` = `001`, `010`, `100` are a basis of GF(2)^3, so
a nonzero `f(2^28)` is one of seven vectors. Testing `2^28` against every
combination decides it: `f(2^28 ⊕ b) = 0` exactly when `f(2^28) = f(b)`, so
**exactly one of the seven must conflict**, and which one names the answer.

| Difference | Vector | Median | |
|---|---|---:|---|
| `0x10000000` | `000` | 218 | |
| `0x10002000` | `001` | 167 | |
| **`0x10004000`** | **`010`** | **540** | **CONFLICT** |
| `0x10006000` | `011` | 136 | |
| `0x10008000` | `100` | 214 | |
| `0x1000a000` | `101` | 186 | |
| `0x1000c000` | `110` | 198 | |
| `0x1000e000` | `111` | 189 | |

One fired, and it landed on the CONFLICT control exactly — median 540 against
the control's 540. The separation is not marginal in any sense: the gap that
sets the threshold is **322** while the next largest gap is **22**, a 14.6×
margin; and the winner's minimum pair delta (468) exceeds every other
candidate's maximum (369), so the classes are disjoint pair-by-pair and not only
in aggregate.

`f(PA28) = 010 = f(PA14)`.

## Why the seven-way test is its own control

If the relation did not extend to bit 28 — if bit 28 selected something outside
the recovered rank-3 space — **none** of the seven would conflict, and the
analyzer reports `OUTSIDE_RANK_3_SPACE` rather than resolving. If the model were
wrong, more than one could fire, and it reports
`AMBIGUOUS_MULTIPLE_CONFLICTS`. Exactly one firing is the outcome the model
predicts and the only one that resolves. Tests drive all three cases, and drive
a different synthetic winner to a different vector, so the answer is read off
the data rather than baked in.

## Claims and ranking

`SUPPORTED_WITHIN_RETAINED_RECEIPT`: the retained medians and bands above;
that every one of 3,029 retained pairs re-checks as isolating its named bit;
that the same-phase controls fired in both retained phases; and that exactly
one of seven candidates conflicted. The reducer emits
`SUPPORTED_MODEL_EXTENSION`, not `PROVED`.

`UNKNOWN_UNRETAINED`: exact same-run target, bridge, command-line, and timing
identity for the retained raw receipts. The current source is a repaired
bounded probe and was not the binary used for the retained receipt.

`UNKNOWN`, unchanged: whether the pair `0x10000000` presented as negative
because bit 28 selects a bank, a rank, or a channel — the measurement separates
selection bits from row bits and does not distinguish among selectors; complete
DRAM coordinates; whether the relation holds above PA28, which this allocation
cannot reach; transform mutability; protection ordering; and every
access-control question.

`pagemap` was `BLIND` for the whole retained mapping, as it has been
throughout — the model base came from the pinned device-tree snapshot and
V021's pinned extent measurement, not from the kernel.

`CLASS C (TRANSFORM ONLY)` and `NOT_ELIGIBLE` unchanged. This extends the model
by one bit. It is a measurement, not an aperture: it says where bits land, not
who may write the transform. No boundary-bypass indicator appeared.

## Provenance

The raw receipts and dependency manifests are pinned by the reducer. The
source below includes the post-review range, overflow, fixed-argument, heap,
and ION-path gates; it was not run on a device in this hardening pass:

| | SHA-256 |
|---|---|
| `tools/a90_pa28_probe.c` (25,030 B, repaired source) | `b324c1c3332c61b00f6d6e5c75891721be4a5fb2a998c7f0222900d4eba5e199` |
| historical binary pin (776,256 B, not retained) | `9959674add623891a80be57d1f139d6af1cc622359e4972a08b61133500afa51` |
| `…-01/pa28-existence.jsonl` (194,481 B) | `d0136222fe6b9d211c6f073fec6844b3817c92e25b6e5a00d15cb9b3787ec49b` |
| `…-01/pa28-identification.jsonl` (283,197 B) | `12cd383679524978b4beff7801816e5a4dc8fa9852972701c1395b50f205fa79` |
| pinned 020M public dependency (8,246 B) | `69b087bd5a6aa279fff9c943405b46491381f3461c5ea1ac57f4d2f287d8ad9a` |
| pinned 021 public dependency (4,586 B) | `82471b458f87e1ed86596ab08c97bab743ee868edf98d7d272c1d131046c168b` |

The public manifest is redacted: private receipt paths and payloads are not
published. Its `provenance` section deliberately records target, bridge,
commands, and timestamp as `UNKNOWN_UNRETAINED` / not same-run attested.

## Device actions

The retained raw receipt records one 320 MiB `camera_preview` allocation,
mapping, reads, free, and a temporary ION node. This hardening pass performed
no device action and did not rerun the probe. The bounded source contains no
MMIO, SMC, SCM, EL2/EL3, protected-memory, partition, firmware, or protected
write operation; allocation and mapping remain the probe's stated read-only
evidence surface.

## Reproduce

```
aarch64-linux-gnu-gcc -O2 -static -Wall -Wextra -Werror \
  -o a90_pa28_probe tools/a90_pa28_probe.c
./a90_pa28_probe camera_preview 320 201 256 7 spread 0xC2000000 <ion-node> \
  0x16000 0x2000 0x10002000 0x10004000 0x10006000 0x10008000 \
  0x1000a000 0x1000c000 0x1000e000 0x16000 0x2000

python3 tools/a90_pa28_relation_analysis.py \
  --raw evidence/private/verification-022-pa28-relation-20260827-01/pa28-existence.jsonl \
  --raw evidence/private/verification-022-pa28-relation-20260827-01/pa28-identification.jsonl \
  --output evidence/manifests/verification-022-pa28-relation-20260827-01.manifest.json
python3 -m unittest tests.test_a90_pa28_relation_analysis
```

The direct probe command is an exact, bounded interface: heap, allocation,
repetitions, pair count, CPU, `spread`, base, and the difference vocabulary are
fixed; the ION node must be `/dev/ion` or a safe basename below
`/tmp/a90-native/`, and the final open uses `O_NOFOLLOW`. Do not execute it as
part of host verification. The host analyzer's production path is the command
above with the two retained raw inputs; it rechecks canonical raw pins, both
phase/cardinality/control gates, 020M/021 semantic and hash pins, source hash,
pair arithmetic, and redacted publication before emitting the model-only
manifest.
