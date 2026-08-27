# Verification 1b known-aperture reachability checkpoint — 2026-08-27

## Boundary

This is a host-only, read-only reconciliation of existing public evidence.  It
does not start Verification 020K and does not contact a device.  No ADB/ACM,
SMC, MMIO, normal-RAM, protected-memory, partition, firmware, or controller
write was performed.  The checkpoint is intentionally limited to the eight
known qhs_llcc-remapper/BIMC candidate apertures; it is not a global
Normal-World reachability proof.

## Exact public inputs

The tool reads each input through a regular-file and `O_NOFOLLOW` descriptor,
checks size/content stability, and verifies the exact SHA-256 before parsing.
Only sanitized basenames, sizes, and hashes are retained in the public
manifest.

| Input | Bytes | SHA-256 |
|---|---:|---|
| `MEMORY_MAP.md` | 9,428 | `34496c0d92736f7df5b9da69f8bcadfe40fb3ee35558c1b10fab7d06dec86950` |
| `009-xpu-policy-inventory-20260825-01.manifest.json` | 60,193 | `f5c661af73cd6b4a0d423ef44a59b11cba0e208ad178670ff2dabf097bf2e4e6` |
| `010-xpu-initializer-inventory-20260825-01.manifest.json` | 41,566 | `baeef82f8f0fad7c7e897e3c373dacd129b7f2ed22d78c075a94141ee36c1ce2` |
| `007-inline-remapper-read-watchdog-20260825-01.manifest.json` | 2,900 | `50d0e324f4356c4ba12c848d86e9563d1f82cfc789981516e05c901dd8d4bb82` |
| `005-icb-remapper-control-node-20260825-01.manifest.json` | 1,819 | `35e96ea34bb2d2fea643edcd408710e44c6a936d7ef395859db119d0fa5d31e3` |

## Bounded result

The exact 010 initializer manifest enumerates four remapper/BIMC pairs:

| Instance | qhs_llcc remapper | BIMC MPU |
|---:|---|---|
| 0 | `0x09248080` | `0x0924e000` |
| 1 | `0x092c8080` | `0x092ce000` |
| 2 | `0x09348080` | `0x0934e000` |
| 3 | `0x093c8080` | `0x093ce000` |

Both exact selector branches enumerate the same eight addresses.  For every
address, both broad policy hits are present:

- `MEMNOC_MS_MPU`, `0x00000000..0x10000000`
- `CNOC_SNOC_MS_MPU`, `0x09000000..0x09800000`

Every one of those hits is retained as `owner=TZ`, `hlos_read=false`, and
`hlos_write=false`.  The 009 policy manifest independently confirms the
narrow `DC_NOC_BROADCAST_MPU` region
`0x09248000..0x09249000` for the tested instance-0 address in both selector
branches, with no HLOS grant.

The retained 007 evidence records one fixed 32-bit EL1 load at
`0x09248080`, no observed value, and a subsequent `Non Secure Watchdog Bark`
followed by warm reset.  The retained 005 control-node attempt records one
read attempt, zero successful reads, `ENXIO`-shaped `rc=1` failure metadata,
and no memory/MMIO writes.  These are separate observations; the checkpoint
does not claim that the watchdog's precise causal layer is proven.

## Reachability disposition

`PROVED` within the bounded static model: all eight known candidate addresses
are covered in both selector branches by TZ-owned broad policies with no HLOS
read/write grant; the tested narrow instance-0 policy is likewise branch
invariant.  `SUPPORTED`: the tested known-aperture Normal-World route is
strongly constrained by those policies and the fixed-load/read-failure
observations.

`UNKNOWN`: global Normal-World reachability, alternate or undiscovered
apertures, final runtime policy/register values, exact watchdog causality,
enforcement ordering relative to final DRAM transformation, transform
mutability, physical mapping, aliases, and bypasses.  Static policy coverage
must not be restated as global writer absence or global reachability absence.

The result remains `CLASS C (TRANSFORM ONLY)` and `NOT_ELIGIBLE`.  It does not
authorize a live action, reopen a controller-write path, or promote a
protected-memory claim.  Verification 020K remains a separate future task.

## Validation and artifact

Implementation: `tools/sm8150_1b_reachability_checkpoint.py`.

Focused tests: `tests/test_sm8150_1b_reachability_checkpoint.py`.

The generated public manifest is
`evidence/manifests/verification-1b-known-aperture-reachability-20260827-01.manifest.json`.
Python byte-compilation, focused parser/semantic mutation tests, exact input
hash drift tests, `O_NOFOLLOW`/regular-file checks, redaction, deterministic
encoding, and no-clobber publication all pass.  Runtime repetitions,
rollback, recovery, and target-health receipts are `NOT_APPLICABLE` because
this checkpoint performs no device action.

After the checkpoint files and integration documentation were present, the
repository discovery suite ran once serially: **1,275/1,275 PASS**,
`skipped=1`, elapsed 156.785 s, maximum RSS 357,788 KiB, swap 0, exit status 0.
No device, USB, reboot, MMIO, SMC, SCM, ownership or protected-memory action
occurred.
