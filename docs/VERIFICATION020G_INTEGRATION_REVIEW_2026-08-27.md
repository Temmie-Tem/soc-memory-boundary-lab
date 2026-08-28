# Verification 020G static-slot pointer/object integration review — 2026-08-27

## Boundary and exact inputs

This iteration is host-only and read-only.  No device, ADB, SMC, MMIO,
normal-RAM, protected-memory, partition, or firmware-write operation occurred.
The exact XBL is 4,194,304 bytes with SHA-256
`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.
The public 020F manifest dependency is opened with `O_NOFOLLOW`, checked as a
regular file, parsed, and pinned to SHA-256
`d19687581d046c7b05841aef6340e9a1e3664c69e19903689d1c583aee5b9764`.

## Static checks and result

The tool re-derives the exact 020F event set and re-decodes only the 12
address-use instruction VAs.  Strict unsigned scalar `LDR`/`STR` forms are
classified as immediate object-field-shaped accesses; strict `UXTX`
register-offset forms are classified as array-element-shaped accesses.  The
result is 10 immediate witnesses (7 loads, 3 stores) and 2 register-offset
load witnesses, with 11 unique access VAs and one duplicate witness from two
distinct 020F seeds.  Runtime base values and all physical/MMIO/DRAM meaning
remain unknown.

`PROVED`: exact pins and bounded instruction-shape census.  `SUPPORTED`: the
shape is consistent with local pointer/object or array state and is not a
direct controller-register identity.  `HYPOTHESIS`: the static slots may hold
local configuration pointers.  `UNKNOWN`: runtime execution/currentness and
values, object semantics, global writer/consumer absence, ABI effects,
MMIO/physical/DRAM identity, mutability/locking, protected reach, aliasing,
and bypass.

Classification remains `CLASS C (TRANSFORM ONLY)` and eligibility remains
`NOT_ELIGIBLE`; no live authority is implied.

## Validation

Python byte-compilation passed for the tool and focused test module.  The
focused suite is 10/10 PASS.  The full repository suite was run serially to
avoid memory pressure: 1,205/1,205 tests PASS (`skipped=1`) in 134.596
seconds, maximum RSS 347,740 KiB, zero swap, exit status 0.  Deterministic
regeneration produced a 7,218-byte mode-`0644` manifest with SHA-256
`f534efeee1e12f18d3af40c107dbc6fbe938eae16d9013aa088d22d7c880af3e`, byte
identical to the retained public artifact.  Public JSON parsing, private-path
redaction scan, no-clobber publication, exact event/shape/unique-VA counts,
strict operation/register mutation negatives, and `git diff --check` passed.

The implementation and focused-test hashes at review time are:

| Artifact | SHA-256 |
|---|---|
| `tools/sm8150_xbl_static_slot_pointer_object_census_020g.py` | `d95ea0577e80fc49497be3074ea14ed2451a43a4ce52dceb1783008289baad69` |
| `tests/test_sm8150_xbl_static_slot_pointer_object_census_020g.py` | `fd58978ff6f21b0d4af17686ac6aa23ba35e6d706f0aa7a3bed28438e9dd6056` |
| `experiments/verification-020G-static-slot-pointer-object-census/README.md` | `d4f7b56a115564c35a6a444c398ae170eda56e7863a9122c155ae6d4f2a1285f` |
| `evidence/manifests/020G-static-slot-pointer-object-census-20260827-01.manifest.json` | `f534efeee1e12f18d3af40c107dbc6fbe938eae16d9013aa088d22d7c880af3e` |

Live repetitions, rollback, recovery, and target-health receipts are
`NOT_APPLICABLE` because this iteration performed no device action.

## Independent hostile review

`PASS` after the aggregate-guard repair.  The reviewer independently confirmed
the exact XBL and 020F dependency pins, `O_NOFOLLOW` handling, decoder option
mask, strict operation/register re-decode, 12-event accounting (10 immediate
with 7 `LDR`/3 `STR`, 2 register-offset `LDR`), 11 unique VAs with ten
singletons and one duplicate backed by two distinct seeds, synthetic mutation
negatives, public redaction, Class C/`UNKNOWN` boundaries, and no-device scope.
The initial review's missing aggregate guards and stale pending record were
fixed before this PASS; no P0/P1/P2 issue remains.
