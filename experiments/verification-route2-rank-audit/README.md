# Route-2 falsification audit — 2026-08-27

Host-only, read-only.  This iteration audits the exact public manifests behind
the Route-2 handoff; it does not access the A90, issue SMC/MMIO operations, or
touch controller/protected memory state.

## Questions and boundaries

Q1 asks whether the retained 027/029/031–034 bounded models promote a reachable
writer to a ranked transform register.  The audit checks exact manifest bytes,
semantic counts, empty promoted-path arrays, stable 71-site identity, and the
explicit `writer_absence=UNKNOWN`/`writer_absence_claim=false` boundary.  It
also checks every 031–034 transition identity and balances the transition counts
against independently expected and row-recomputed remaining/transitioned site counts.  Every
032–034 quadrant map is recomputed from row labels and compared with its
declared counts; maps that publish `expected_counts` must match that field too,
and every map must report zero regressions.  A zero bounded target count is
therefore reported as `SUPPORTED` bounded
closure, not global writer absence.

Q4 asks whether any 029–034 result contradicts the repaired rank-3 relation.  The
audit pins 023R and V016, verifies 030's inherited rank-3 dependency, and scans
the exact 029–034 manifest fields.  The four `029` `rank` values are decoder
candidate ordering metadata; 030 has one inherited relation dependency; 031–034
contain no explicit rank/relation rows.  Consequently Q4 remains `UNKNOWN`:
the complete 029–034 raw row set was not present in these public manifests, and
absence of a row in a bounded summary is not a contradiction proof.

## Pinned inputs

All nine JSON inputs are size/SHA-256 pinned by the analyzer.  The public
manifest records only basenames, sizes and hashes.  Duplicate JSON keys,
changed hashes, changed semantic counts, changed site identity, failed
transition identity/count checks, and quadrant maps that do not recompute from
their row labels are rejected.

## Result

`CLASS C (TRANSFORM ONLY)` remains unchanged.

`PROVED`:

- all pinned 029–034 bytes and JSON objects validate;
- 027 and 031–034 publish no bounded DCB-consumer or MC/SHRM symbolic target;
- 031–034 preserve the same 71 site identities and regression-free transition
  checks;
- 030 inherits the exact validated 023R rank-3 relation;
- 029 ranking fields are ordering metadata, not relation rows; no explicit
  relation rows occur in 029 or 031–034.

`SUPPORTED`: the bounded static line supports a no-promoted-writer-path result
inside its declared models.

`UNKNOWN`: global writer/consumer presence, runtime execution and ordering,
current destinations, indirect aliases, complete relation contradiction status,
physical DRAM coordinates, transform mutability and protected-memory reach.

The canonical public manifest is 9,607 bytes, mode `0644`, SHA-256
`ec3ec693768bf1294366c5650ab9c5e76b27f9bdce049c7a6f2b205a00a72fb8`.  The
focused suite is 19/19 PASS; the full repository suite is 1,151/1,151 PASS
(`skipped=1`) with zero swap, as recorded in the integration review.

## Reproduction

```text
python3 tools/a90_route2_rank_audit.py \
  --output evidence/manifests/route2-rank-audit-20260827-01.manifest.json
python3 -m unittest -v tests.test_a90_route2_rank_audit
```

The output is canonical JSON, created once with `O_EXCL`/`O_NOFOLLOW`, mode
`0644`, and contains no private paths or raw firmware.  No device action or
rollback is applicable to this host-only iteration.
