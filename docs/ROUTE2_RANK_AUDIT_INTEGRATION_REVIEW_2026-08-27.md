# Route-2 rank/writer audit integration review — 2026-08-27

## Review boundary

This iteration is host-only and read-only.  It parses only nine tracked public
JSON manifests: 027, 029, 030, 031, 032, 033, 034, 023R and V016.  It does not
contact the A90, issue SMC/MMIO operations, read protected memory or mutate any
device state.

Iteration snapshot: target scope `SM-A908N/SM8150` (device binding
`NOT_APPLICABLE` because there was no device contact), repository branch
`codex/config-cdt-integration`, pre-iteration HEAD `0929539e2633b0724344d8928a34841c2a15762d`,
and a dirty tree containing only this iteration's Route-2 additions plus the
root documentation updates.  Host tool `Python 3.14.4` on `Linux
7.0.0-30-generic x86_64` was used.  Live repetitions, rollback, recovery and
target-health receipts are `NOT_APPLICABLE`: no device effect was possible.

## Exact inputs and semantic gates

Every input is opened with `O_NOFOLLOW`, read through a stable descriptor and
checked against its pinned byte count and SHA-256.  Duplicate JSON object keys
are rejected.  The audit then checks the semantic fields rather than trusting
the hashes alone:

- 027 retains 73 sites with `71 INDIRECT_OR_UNSUPPORTED`, `2
  NO_TARGET_WITHIN_MODEL`, `2 SECTION_READER_PROXIMITY_ONLY`, and explicit
  global writer `UNKNOWN`/`writer_absence_claim=false`.
- 029 retains the same dependency boundary and no global writer claim.
- 031–034 retain 71 sequential site identities, zero promoted
  `DCB_CONSUMER_PATH` and `MC_OR_SHRM_SYMBOLIC_TARGET` paths, empty promoted
  path arrays, and explicit global writer `UNKNOWN` fields.
- Every 031–034 `actual_delta_vs_*` record has `transition_identity=true`, and
  each retained row transition is checked against its predecessor/current
  labels and fail-closed flags.  The aggregate has a nonnegative,
  predecessor/current-label-consistent baseline/remaining/transitioned count
  independently recomputed from those same rows.
  Every 032–034 quadrant map is independently recomputed
  from row labels and compared with its declared counts; maps with an
  `expected_counts` field also match that field, and every map declares zero
  regressions.  The four site arrays are
  byte-level semantic identity matches by `(site_index, range, store_va)`.
- 030's inherited relation dependency is pinned to 023R, rank 3,
  contribution `0b110`, `validated=true`, and `SUPPORTED_WITHIN_MODEL` physical
  classification.  023R is resolved/unique rank 3 and V016 retains the exact
  `{25:[14,21], 26:[19], 27:[13,20]}` matches.

## Results

Q1 is `SUPPORTED_BOUNDED_CLOSURE_UNKNOWN_GLOBAL`: no promoted writer or
controller-symbolic path appears in the declared static models, but dynamic,
indirect, runtime and global writer identity remain `UNKNOWN`.

Q4 is `UNKNOWN_NO_COMPLETE_029_034_RELATION_ROW_SET`.  The audit finds four 029
decoder-candidate ordering fields, one inherited 030 relation dependency, and
no explicit relation rows in 029 or 031–034.  That is a bounded field census,
not a proof that unretained raw rows contain no contradiction with rank three.

The public result is
`evidence/manifests/route2-rank-audit-20260827-01.manifest.json`, 9,607 bytes,
mode `0644`, SHA-256
`ec3ec693768bf1294366c5650ab9c5e76b27f9bdce049c7a6f2b205a00a72fb8`.

`PROVED`: exact input identity and semantic gates above; bounded zero-path and
site/transition checks; 030's rank-3 inheritance; and the absence of explicit
relation rows in the named public fields.

`SUPPORTED`: the bounded static line supports no promoted writer path inside
its declared models.

`UNKNOWN`: global writer/consumer absence, runtime execution/order/current
destination, indirect aliases, complete relation contradiction status,
physical DRAM coordinates, transform mutability and protected-memory reach.

`CLASS C (TRANSFORM ONLY)` remains unchanged.

## Validation and hostile review

The focused suite is 19/19 PASS.  A separate host-process recheck repeated the
input pin, Q1/Q4 status, site identity, scope and byte-identical manifest
assertions.  The full serial repository suite is 1,151/1,151 PASS
(`skipped=1`) in 113.671 seconds, maximum RSS 290,844 KiB, with zero swap.  No
device action is applicable.
