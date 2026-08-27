# Verification 020M integration review - 2026-08-27

## Exact live receipt and boundary

The 020M collector used the already-running loopback A90P1 bridge and a fixed
read-only allowlist.  It first validated the exact V2321 A90 identity, then
queried only `/proc/cmdline`, the ION heap directory, heap-30 `reg`,
`memory-region` and `name`, and the `camera_mem_region` `reg`, `phandle`,
`name`, `ion,recyclable`, `no-map` and `reusable` properties.  It performed no
ION allocation, mapping, register/MMIO/SMC access, firmware/partition write or
protected-memory access.

The canonical private receipt is a regular `0600` file of 15,435 bytes,
SHA-256 `40a3207d3f822775c4506415a579e993c07a6a7f9ff998e41a6f76cb6216a2ec`.
The canonical public manifest is 8,246 bytes, mode `0644`, SHA-256
`69b087bd5a6aa279fff9c943405b46491381f3461c5ea1ac57f4d2f287d8ad9a`.
Two preliminary receipts remain retained; this canonical run was acquired
after restarting the bridge with strict `--expect-realpath` and
`--device-glob` pins, both recorded as true in the manifest.

## Claim disposition

`PROVED`: on this exact live runtime, heap 30 reports `0x1e`, its
`memory-region` phandle is `0x67a`, and `camera_mem_region` has the same
phandle with `reg` base `0xc2000000`, size `0x14000000` (320 MiB).  The
`no-map` and `reusable` files both return the expected `ENOENT`; the
`ion,recyclable` property is present.  The receipt and manifest retain all
command/result hashes.

`SUPPORTED`: the DT chain is consistent with a fixed advertised 320-MiB
carveout for heap 30, and therefore makes a full-size PA28 offset test
feasible.  `UNKNOWN`: whether a live 320-MiB allocation consumes the whole
carveout, physical page identity, complete DRAM coordinates, the value of
`f(PA28)`, transform mutability, protection ordering and any bypass.

The result remains `CLASS C (TRANSFORM ONLY)` / `NOT_ELIGIBLE`.  This is a
precondition snapshot, not a PA28 timing or alias result; no security-boundary
reopen is claimed.

## Artifact pins

| Artifact | Size | SHA-256 |
|---|---:|---|
| `tools/a90_pa28_dt_snapshot.py` | 15,745 | `8fb7db5be5e0f48e25746a217a360dae9170dd962f1d80da84ff957afdb109af` |
| `tests/test_a90_pa28_dt_snapshot.py` | 4,257 | `b6db04bd7c18bcd7bd7c922f2853b162b3b0641e70de883b5124349fb108408e` |
| `docs/VERIFICATION020M_CONTRACT_2026-08-27.md` | 1,388 | `3a680c4792d147f7920d3ba746424a6b5014377d6fcbb8b86fae418da8832ef6` |
| `experiments/verification-020M-pa28-dt/README.md` | 1,417 | `93721f84d03887d04f29f9d618be0a52eb24f87d18c10093289dcc06bd21440f` |
| `evidence/manifests/verification-020m-pa28-dt-20260827-03.manifest.json` | 8,246 | `69b087bd5a6aa279fff9c943405b46491381f3461c5ea1ac57f4d2f287d8ad9a` |

## Host validation

The focused host suite is 8/8 PASS and Python byte-compilation passes.  Target
identity, command-surface, phandle/reg mutation, expected-property-error,
no-clobber and redaction boundaries are covered by negative tests.  The
collector writes private/public artifacts with `O_EXCL` and `O_NOFOLLOW` and
refuses to overwrite an existing receipt.
