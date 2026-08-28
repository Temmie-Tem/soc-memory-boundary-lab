# Verification 022 contract — retained PA28 relation reducer

Status: host-only hardening complete; no device execution in this pass.

## Scope and disposition

`tools/a90_pa28_relation_analysis.py` consumes exactly the retained existence
and identification JSONL receipts for Verification 022. It emits a redacted
public manifest only after canonical raw-input pins, strict record shape, phase
identity/cardinality, pair arithmetic, same-phase controls, and pinned 020M and
021 dependencies pass. The result is
`SUPPORTED_WITHIN_RETAINED_RECEIPT` / `SUPPORTED_MODEL_EXTENSION`; it is not a
`PROVED` physical alias, complete DRAM map, transform-mutation result, or
access-control/bypass result.

The exact target and bridge for the historical raw acquisition are
`UNKNOWN_UNRETAINED`. No same-run preflight, command receipt, timestamp, or
binary artifact is synthesized by the reducer.

## Fixed measurement contract

The retained context must be exactly:

- model intent `SM-A908N`, SoC `SM8150`;
- heap `camera_preview`, type `10`, id `30`;
- allocation `320 MiB`, `256` pairs, `201` repetitions, CPU `7`;
- `spread` offsets, alternating order, `dsb_ld`, `kept_times_two`, warmups `17`;
- declared base `0xc2000000`, `cntfrq` `19200000`;
- pagemap status `BLIND`, with 81920 pages and zero present/nonzero PFNs.

The existence phase contains exactly two summaries each for controls
`0x16000` and `0x2000`, plus two `0x10000000` summaries. The identification
phase contains exactly two summaries for each control and one for each of
`0x10002000`, `0x10004000`, `0x10006000`, `0x10008000`, `0x1000a000`,
`0x1000c000`, and `0x1000e000`. Each summary accounts for exactly 256 pairs
including range and carry rejects. Every pair recomputes `pa_a = base + offset`,
`pa_b = base + (offset XOR value)`, and `pa_a XOR pa_b = value`; the emitted
`pa_xor` field is never trusted.

## Dependency and publication pins

The reducer pins the exact public manifests below and validates their semantic
claims before reduction:

| dependency | size | SHA-256 |
|---|---:|---|
| `verification-020m-pa28-dt-20260827-03.manifest.json` | 8246 | `69b087bd5a6aa279fff9c943405b46491381f3461c5ea1ac57f4d2f287d8ad9a` |
| `verification-021-carveout-exhaustion-20260827-01.manifest.json` | 4586 | `82471b458f87e1ed86596ab08c97bab743ee868edf98d7d272c1d131046c168b` |

The repaired source pin is `tools/a90_pa28_probe.c`, 25,030 bytes,
SHA-256 `b324c1c3332c61b00f6d6e5c75891721be4a5fb2a998c7f0222900d4eba5e199`.
The historical 776,256-byte binary pin is retained as `NOT_RETAINED`; it is
not conflated with the repaired source. The public manifest is generated once
with `O_EXCL`, `O_NOFOLLOW`, mode `0644`, and a directory fsync; it contains
hashes and semantic attestations, never private raw payloads or paths.

## Probe safety contract

The direct C probe has a bounded interface. It accepts only the fixed heap,
320 MiB, 201 repetitions, 256 pairs, CPU 7, `spread`, base `0xc2000000`, and
the explicit 022 difference vocabulary. The ION path is `/dev/ion` or a safe
basename under `/tmp/a90-native/`; the final open uses `O_NOFOLLOW`. Heap type
10/id 30 is required and the allocation mask shift is guarded by the fixed
id. Pair pointers are formed only after allocation-range, base-overflow, and
physical-XOR checks. The probe has no MMIO/SMC/protected-memory/partition or
firmware write path; host verification never invokes it.

## Required verification

```sh
gcc -std=c11 -Wall -Wextra -Werror -fsyntax-only tools/a90_pa28_probe.c
python3 -m unittest -v tests.test_a90_pa28_relation_analysis
```

The focused suite includes synthetic alternate winners, missing phase/control
and candidate negatives, pair/base arithmetic mutations, canonical pin drift,
symlink/non-regular/size mutation checks, dependency drift, and C-source
ordering/surface assertions.
