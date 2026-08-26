# Experiment 029 — Unsupported DCB frontier

## Question

What exact instruction forms remain outside the deliberately small
Experiment 027 AArch64 decoder inside its fail-closed DCB-related ranges?

## Scope and authority boundary

This is a host-only, read-only syntactic inventory for the exact A90 5G
SM-A908N / SM8150 XBL input (`xbl--sdb1.bin`, 4,194,304 bytes,
SHA-256 `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`).
Only the **71** Experiment 027 sites labelled `INDIRECT_OR_UNSUPPORTED` are
scanned. The 027 source and public manifest are hash-pinned and their
semantic boundary is checked before the dependency is imported.

Membership in one of these bounded ranges is not CFG reachability, execution,
or a current destination. No device, SMC, MMIO, normal-RAM, protected-memory,
or runtime-register access occurred. This experiment does not extend the 027
decoder, establish consumer or writer absence, or create live authority.

## Occurrences versus unique values

An **occurrence** is one raw instruction word encountered at one virtual
address for one scanned range. If ranges overlap, the same VA is intentionally
counted once per containing range. A **unique VA** deduplicates those repeated
range observations; a **unique raw word** deduplicates the instruction words
independently of their addresses.

| Scanned domain | Occurrences | Unique VAs | Unique raw words |
|---|---:|---:|---:|
| All 71 ranges | 1,992 | 1,180 | — |
| Recognized by Experiment 027 | 1,640 | 961 | — |
| Unsupported frontier | 352 | 219 | 197 |

The identities are exact: `1,640 + 352 = 1,992` and `961 + 219 = 1,180`.
Frontier occurrence rows are sorted by VA, site index, and raw word. The
public manifest retains raw instruction words and VAs only; it contains no
firmware bytes or private paths.

## Overlap accounting

Within the 352 frontier occurrences, 191 occurrence rows are in overlapping
ranges and 161 are in exactly one range. Those rows correspond to 58
overlapped unique VAs and 161 non-overlapped unique VAs. Frontier duplicate
multiplicity is therefore `352 - 219 = 133` (also `191 - 58 = 133`). Across
all recognized and frontier range members, the all-range overlap multiplicity
is **812**. The overlap label
`UNREACHABLE_OR_OVERLAP_UNKNOWN` is orthogonal to the primary instruction
class; it does not mean that an instruction is unreachable.

## Primary classification

| Primary class | Frontier occurrences |
|---|---:|
| `DECODER_EXTENSION_CANDIDATE` | 161 |
| `FLAG_ONLY_NO_GPR_DEF` | 99 |
| `TAINT_KILL_REQUIRED` | 27 |
| `CONTROL_OR_MEMORY_UNSUPPORTED` | 54 |
| `UNKNOWN` | 11 |

Every class is a static, conservative label. Source provenance is
`UNKNOWN_REQUIRES_PRIMARY_SOURCE_REVIEW`; reachability is
`UNKNOWN_RANGE_MEMBERSHIP_IS_NOT_CFG_REACHABILITY`; decoder safety is
`NOT_CLAIMED`.

The four extension candidates are ranked by unique VA count first, then
unique raw-word count, occurrence count, and family name:

| Rank | Family | Unique VAs | Unique words | Occurrences |
|---:|---|---:|---:|---:|
| 1 | `BITFIELD_IMM` | 56 | 54 | 120 |
| 2 | `AND_SHIFT` | 14 | 14 | 37 |
| 3 | `EOR_SHIFT` | 2 | 2 | 2 |
| 4 | `BIC_SHIFT` | 2 | 1 | 2 |

All four are `HYPOTHESIS` only. They are not architecture-source findings,
decoder-safety approvals, or reachability claims. One indirect/runtime-alias
site (027 site index 35) is retained separately with no reachability claim.

## Classification and unknowns

```text
CLASS C (TRANSFORM ONLY)
BOUNDED_UNSUPPORTED_FRONTIER_INVENTORY_UNKNOWN
NOT_ELIGIBLE
```

The exact XBL/dependency identities and deterministic range accounting are
proved observations. Range reachability, source provenance, decoder safety,
runtime aliases, current destinations, execution order, and global consumer or
writer presence remain `UNKNOWN`. Experiment 027's writer-absence field is
also explicitly `UNKNOWN`; no global absence conclusion is made.

## Reproducibility

The checked public artifact is generated from the exact private XBL input and
the public Experiment 027 dependency. Use an exact firmware directory and a
public manifest directory supplied by the operator:

```sh
python3 tools/sm8150_dcb_unsupported_frontier.py \
  --firmware-dir <exact-firmware-dir> \
  --manifest-dir <public-manifest-dir> \
  --output <public-manifest-path>
python3 -m unittest -v tests.test_sm8150_dcb_unsupported_frontier
```

Two fresh generations were byte-identical to one another and to the checked
manifest. Publication uses `O_EXCL` and `O_NOFOLLOW`, refuses clobbering, and
sets mode `0644`.

## Final artifact hashes

These hashes were recorded after the final Experiment 029 stabilization:

| Artifact | Size | SHA-256 |
|---|---:|---|
| Frozen `tools/sm8150_dcb_unsupported_frontier.py` | 43,950 | `e5c491deaddafd4c60de7df3bfe0531f38bbd3740fe668942b912466ee86bca0` |
| Experiment 027 tool dependency | 86,782 | `11a4dab37e9a54e74ec93fba7c89524de1e77c7e71b86f105dd167d77780bcb9` |
| Experiment 027 public manifest dependency | 334,847 | `d11785969f16ba09155a2305eefd091158abfc515bc64cf94cb34d573a302277` |
| Checked Experiment 029 public manifest | 628,525 | `c6d46c382d7c091fffad137adb9491d107ff823ad6c6221f51eb627cc218f634` |
| Focused Experiment 029 test file | 24,461 | `d5eebfcbf1b4332bfeef693802e9b554728480051bc61331e811993c8837a1f2` |

The focused tests independently cover exact input/hash and semantic mutation
rejection before dependency import, recognized/frontier separation, the exact
71-site scope, all occurrence/unique/overlap identities, `unique_va_records`,
unique-VA candidate ranking, positive/negative/reserved encoding masks
(including bitfield `opc=3` and add/sub `S`/`Rd` behavior), primary versus
orthogonal labels, UNKNOWN provenance/reachability/safety, public safety,
two deterministic generations, and `O_EXCL`/`O_NOFOLLOW`/no-clobber/mode 0644.
