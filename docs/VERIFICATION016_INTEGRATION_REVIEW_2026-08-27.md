# Verification 016 retained-input integration review — 2026-08-27

## Integration boundary

This is a clean retained-input reconstruction, not a cherry-pick of external
commit `6b3abc716f8c7a9938ca6acfbf17b6f126ef5701`.  That commit identified the
question and supplied historical context, but its implementation flattened
overlapping acquisition sections with `setdefault()`, used filename order to
select values, mixed three-column and discrimination phases, promoted
behavioural contiguity under `BLIND` pagemap, omitted the held-out result from
its manifest, and used an ordinary clobbering write.

No device, USB, allocation, memory, SMC, MMIO, controller, protected-memory,
boot or partition action occurred in this integration.  It analyses the exact
retained private bytes read-only and emits one sanitized public manifest.

## Exact inputs

| Input | Bytes | SHA-256 |
|---|---:|---|
| `pa25-27-discriminate.jsonl` | 142,987 | `0b269229a1607c6894fea15c21008ed3651b29faf02b9bc6cd851878c6030754` |
| `pa25-27-heldout.jsonl` | 30,770 | `38649c2d2f73be05ef238c20cdc69880b391547f84fe48cd656fff9343be91b0` |
| `pa25-27-three-column.jsonl` | 94,966 | `4cea5779ebdace6cc9817de591c8cff81dbd7f029ad78f46d8711708758c950f` |
| Probe source `a90_region_probe_r.c` | 19,337 | `2dbc81ef7595d30f627df8d28d24e21603d8c1c174074e85593b9fe8df5569e9` |
| Repaired 023R dependency manifest | 18,040 | `5c3e14ff898c109de740d98260d974bca10751000f85977775cd467ac74aac2e` |
| Repaired V015 stable-read/publication helper | 97,572 | `6fae489d27d03f94e9dcd89086027a4209988a67020620e54f1df7e22ca99e03` |

The raw directory must contain exactly the three named files.  Every input is
bound by basename, size and SHA-256, read from a regular non-symlink descriptor,
independently re-read, and required to retain identical bytes before a result is
published.  This is exact-byte/content stability, not filesystem-inode
provenance; a same-content inode replacement does not change an analysis value
and inode identity is explicitly `UNKNOWN_NOT_CLAIMED`.

## Parser and phase repair

The repaired parser preserves three 14-key discrimination sections, one
nine-key held-out section, and two 14-key three-column passes.  It rejects
malformed/nonfinite JSON, missing or duplicate records, nonzero-schema drift,
zero differences, non-page-aligned pair offsets, either page-sized XOR endpoint
outside the 256-MiB mapping, post-summary pairs, duplicate per-difference
offsets, pair-count mismatch, and qsort p10/median/p90 mismatch.  Section order
is checked by each model bit's exact expected key set.

Every discrimination phase, the held-out phase, both three-column passes, and
the combined three-column result independently require `0x16000=CONFLICT` and
`0x2000=NEGATIVE`.  Both three-column passes are classified before averaging;
the build fails if either pass or their floor-mean result disagrees on a bit's
verdict.  Thus neither filename order nor an average can hide a phase conflict.

## Bounded result

`PROVED` from the retained bytes, strictly in
`ALLOCATION_OFFSET_MODEL_COORDINATES`:

| Phase | Threshold | Gap | Runner-up | Empty band | CONFLICT |
|---|---:|---:|---:|---|---:|
| model bit 25 discrimination | 339 | 295 | 22 | 192..487 | 3 |
| model bit 26 discrimination | 325 | 273 | 75 | 189..462 | 2 |
| model bit 27 discrimination | 355 | 302 | 25 | 204..506 | 3 |
| held-out | 299 | 276 | 38 | 161..437 | 5 |
| two-pass three-column | 358 | 304 | 136 | 206..510 | 2 |

The exact equal-contribution matches are model bit 25 to bits 14/21, model bit
26 to bit 19, and model bit 27 to bits 13/20.  The independent 023R dependency
already contains the implied lower-bit kernel equalities `0x204000` and
`0x102000`.

| Model bit | pass 0 | pass 1 | floor mean | verdict in all three |
|---:|---|---|---|---|
| 25 | 186/161/226 | 118/105/186 | 152/133/206 | `SELECTOR` |
| 26 | 161/161/149 | 139/121/124 | 150/141/136 | `SELECTOR` |
| 27 | 145/158/527 | 118/139/493 | 131/148/510 | `SELECTOR_CANCELS_NEGATIVE_WITNESS` |

The separate held-out file has seven model-derived agreements out of seven:
four `CONFLICT` and three `NEGATIVE`.  This is an out-of-sample retained-file
agreement; prediction preregistration and acquisition ordering/timestamps are
not attested and remain `UNKNOWN`.

`SUPPORTED_WITHIN_MODEL`: the three higher allocation-offset/model bits
duplicate existing contributions, so the supported rank remains three.  This
does not establish their physical PA identity or a named channel/bank/rank
register interpretation.

The historical `17/17` text described eight kernel plus nine negative controls,
not 17 copies of the two phase references.  Those 17 measurements are not in
the retained V016 files.  Therefore only the claim that the retained artifact
establishes `17/17` is `REFUTED_AS_RETAINED_EVIDENCE`; whether a separate
unretained run occurred and what it returned remain `UNKNOWN`.

The historical `192/170/506` tuple is not a coherent tuple from either retained
three-column pass or their combine.  The exact external Git implementation can
reproduce it by first-value, filename-order mixing, but that historical source
is not a canonical manifest input.  The public manifest therefore refutes only
coherence with the retained phases and leaves the historical producer/cause
`UNKNOWN`; this integration review records the separate Git-history
explanation as context, not canonical proof.

## Physical and security boundary

All pagemap records are `BLIND`.  The producer field `contiguous=true` is kept
only as `reported_contiguous`.  Effective physical contiguity, physical PA
mapping for model bits 25–27, allocation base/alignment, and target/build/action
attestation remain `UNKNOWN` or supported only by an unretained operator report.

No complete-coordinate alias, transform mutation, protected-memory reach,
protection-order mismatch or boundary bypass is observed or proved.  Class
remains `CLASS C (TRANSFORM ONLY)` and numbered conceptual Experiments 015/016
remain `NOT_ELIGIBLE`.  The dependency gate for a separate Verification 017
audit is now satisfied, but its external implementation and claims are
`UNBLOCKED_FOR_SEPARATE_AUDIT_NOT_PROMOTED`.

## Final artifacts and validation

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| Analyzer | 78,490 | `a1b804a3686ba3f7d87f89b68d88de67387c24de424eb396fc770629f0cf2bec` |
| Focused tests | 22,757 | `8a8221e7c03e4adbf6de7a7f27b773bea7b2e3d32405a44a9673aeab562e67bb` |
| Experiment README | 8,276 | `706362bf45248c7c7af0b6e511f1ffd3edae9b9404b5ae13961e2acf71b771bf` |
| Public manifest | 59,504 | `72525cf994e52bbee1c3ed685c49a6ace4049cd7b279cb97811f6a0d3f4f773f` |

- Focused V016 suite: 23/23 PASS; maximum RSS 24,684 KiB, swap 0 on the
  phase/parser repair run.
- V016 plus the three checked-file-mode portability repairs: 69/69 PASS;
  maximum RSS 144,740 KiB, swap 0.
- Final full serial repository discovery: 1,062/1,062 PASS in 117.328 seconds;
  maximum RSS 277,724 KiB, swap 0.
- Python byte-compilation, strict JSON, exact raw/dependency pins, independent
  arithmetic reconstruction, public-safety checks, fresh mode `0644`, no-clobber
  publication, README reproduction, byte-identical canonical encode, and
  `git diff --check` pass.
- Independent hostile review found two P2 and two P3 issues in the first stable
  candidate.  Page-range validation, unsupported causal attribution, and
  nonfinite JSON were repaired; inode provenance was explicitly narrowed to
  exact-byte/content stability. Final stable-tree review then reproduced all
  pins and the canonical manifest, ran 23/23 focused tests, and returned `PASS`
  with no remaining P0–P2. Its sole status nuance is resolved here: “blocked”
  applied until this dependency gate passed; V017 is now audit-eligible but
  remains explicitly unpromoted.

## Disposition

`PASS`: the retained numerical/model result is internally reproducible,
bounded, and independently reviewed. It does not grant live-device or
security-boundary authority. Class C remains unchanged; V017 requires its own
audit, and Verification 018 now supplies a separate repaired allocation-local
baseline with its own fresh raw provenance.
