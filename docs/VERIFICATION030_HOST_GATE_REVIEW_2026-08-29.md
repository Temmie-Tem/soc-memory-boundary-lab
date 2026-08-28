# Verification 030 host-gate review — 2026-08-29

## Disposition

`PASS_HOST_INTEGRATED / LIVE_NOT_YET_EXECUTED / CLASS C UNCHANGED`.

The fixed V030 implementation is promoted to `main` and passed the canonical
repository-wide suite.  This does not claim a live allocation, a physical
address result, aliasing, transform mutability, protected reach or bypass.

## Exact reviewed snapshot

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| coordinator | 127,254 | `6f8970a05caf2a214a9976c3e213d942414d5a136feb7b9e21a4a51fac152424` |
| native source | 70,971 | `cee8f32b432e2e62e3169d06f6cd95419df16cb55096b61790595580f30a019e` |
| focused tests | 68,018 | `e5df04fbe2aa7dd88fb227c43e5727b05735d4a677112be3440ab36a4afbb2c2` |
| deterministic static probe | 777,200 | `f12959b5772d8b89ebe5abb15505a0ee2662864f6847189f77c101834337159e` |
| resolved compiler `/usr/bin/aarch64-linux-gnu-gcc-15` | 2,137,240 | `50d0961827e521a7c06d7794d4b15282559a117d365a149aaca5726917ab1603` |

## Host verification

- `30/30` focused tests passed under `ulimit -v 4194304`.
- Python bytecode compilation and `git diff --check` passed.
- Strict AArch64 syntax validation passed.
- Two independent static builds were byte-identical to the pinned probe.
- Host-only preflight passed with `device_contact:false`.
- No device, bridge, USB, ADB, ACM, allocation, MMIO, partition, SMC or
  protected-memory action occurred.

## Independent hostile review

Four bounded repair/review rounds tested the real producer and authority
paths, not only their success fixtures.  The final reviewer found no P0/P1
defect and rechecked:

1. the three CMA calibration records survive the source reset and are used by
   both output accounting and emission;
2. exactly one canonical terminal PASS line is authoritative and is
   cross-bound to target, boot, remote bytes, cleanup, final health and every
   retained artifact;
3. exact field declarations, widths and signedness reject `__data_loc` and
   other type drift;
4. builds invoke the hashed resolved compiler and accept only the pinned
   static `ET_EXEC` image with an executable entry in a `PT_LOAD` segment and
   no `PT_DYNAMIC` or `PT_INTERP`;
5. dangling symlinks and create-then-error remote paths cannot evade scoped
   cleanup and absence checks;
6. boot IDs before and after the delegated boot attestation match;
7. output accounting includes retained calibration rows, and ordering uses a
   subtraction-free comparator.

The reviewer found one P2 test-fidelity defect: the synthetic CMA fixture had
reversed `pfn` and `page` offsets.  The fixture now follows the pinned Samsung
source order `pfn@8,page@16,count@24,align@28`, and a raw source-order record
must reproduce affine slope 64 and `first_pa=0xc2000000`.

## Repository-suite boundary

Two attempted suite runs in the isolated worktree are not PASS evidence.  The
first reached 1,802 tests with 191 errors and two failures because ignored
private fixtures were absent.  After copying those fixtures and normalizing
their local modes, a 2,007-test run had one remaining error because the V024
flash journal is deliberately pinned to the canonical repository path.

The valid repository-wide run was then made serially from
`/home/temmie/dev/soc-memory-boundary-lab` under `ulimit -v 4194304`:

- `Ran 2027 tests in 220.219s`
- `OK (skipped=1)`
- exit status 0;
- maximum RSS 708,576 KiB;
- zero swaps;
- private log: 8,997 bytes, SHA-256
  `dd4d30735b1b5fba210a03bd0971d6f098a522ebd2fe16456e4eba99fcf6c427`.

This closes the host-integration gate.  V030 remains unexecuted on the device.
