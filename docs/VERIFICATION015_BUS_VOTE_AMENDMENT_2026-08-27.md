# Verification 015 bus-vote amendment — 2026-08-27

## Boundary and exact inputs

This is a host-only, read-only amendment to the repaired Verification-015
record.  It does not rerun or replace the repaired V015 analyzer.  No device,
USB, reboot, bus-vote write, SMC, MMIO, memory, partition, protected-memory,
firmware, or controller action occurred.

The parser reads two retained private excerpts through regular-file,
`O_NOFOLLOW`, size, content-stability, and SHA-256 checks:

| Input | Bytes | SHA-256 |
|---|---:|---|
| `msm-bus-dbg-client-list.txt` | 64 | `62e38404fa83ce2f44e135744695f8c992652cf0daf775d70478b1cc80909413` |
| `msm-bus-dbg-disp_rsc_ebi.txt` | 571 | `90d5954aa11eaf064fef1737be7f742aada351ddbeaabd2d1bab2cb17f2aa1e2` |

The private directory and raw transcript bytes are not published.  The public
artifact is
`evidence/manifests/verification-015-bus-vote-amendment-20260827-01.manifest.json`.

## Strict result

The client excerpt declares **66** clients and retains four relevant names:
`clk_dispcc_debugfs`, `disp_rsc_ebi`, `disp_rsc_llcc`, and `disp_rsc_mnoc`.
`disp_rsc_ebi` is present.

The EBI excerpt contains six exact entries:

| Phase | Entries | AB bytes/s | IB bytes/s |
|---|---:|---:|---:|
| Initial static vote | 1 | 12,800,000,000 | 12,800,000,000 |
| Transient low vote | 2 | 0 | 400,000,000 |
| Restored static vote | 3 | 12,800,000,000 | 12,800,000,000 |

The parser requires the exact line grammar, entry cardinality, field values,
phase order, and restored-equals-initial invariant.  It publishes timestamps,
current selectors, master/slave IDs, and numeric rates as structured metadata;
it does not publish raw transcript lines.

## Interpretation and limits

`PROVED`: the retained excerpts have the exact pinned bytes and the sequence
above.  `SUPPORTED`: the excerpt supports retaining the V015 bandwidth axis
as a bus-vote stability supplement.  The static 12.8 GB/s EBI vote means the
six requested devfreq levels cannot, from this excerpt alone, establish a
DDR operating-point change.  The transient 400 MB/s entry is recorded as
observed transcript content and is not promoted to a DDR-clock transition.

`UNKNOWN`: DDR operating-point selection, clock readback, bus aggregation
outside the excerpt, runtime execution/order, transform mutability, physical
mapping, protection ordering, aliasing, and bypass.  This amendment makes no
writer-absence or controller-authority claim.

Classification remains `CLASS C (TRANSFORM ONLY)` and eligibility remains
`NOT_ELIGIBLE`.  The numbered conceptual Experiments 015/016 remain
`NOT_ELIGIBLE`.

## Validation

The standalone tool is
`tools/a90_v015_bus_vote_amendment.py`, schema
`a90-v015-bus-vote-amendment-v1`.  Its focused suite is
`tests/test_a90_v015_bus_vote_amendment.py`.

- Python byte-compilation passed for the tool and focused tests.
- Focused tests: **9/9 PASS**.
- Deterministic regeneration produced a 5,686-byte mode-`0644` manifest with
  SHA-256 `066d8fc708c5652cb53abfc78e4286b06ea9ec100cffeef5a10240420fb8582b`.
- Redaction, exact hashes, semantic mutations, no-follow/regular-file checks,
  deterministic encoding, and no-clobber publication passed.

The amendment is additive and does not overwrite the repaired V015 analyzer,
README, or manifest.  Runtime repetitions, rollback, recovery, and target
health are `NOT_APPLICABLE` because no device state was touched.
