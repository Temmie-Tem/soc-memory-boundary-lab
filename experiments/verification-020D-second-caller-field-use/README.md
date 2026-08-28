# Verification 020D — second helper-caller field use (2026-08-27)

This host-only, read-only experiment follows the second direct caller of the
020C return helper at `0x9fc26e2c`.  It asks which fields of the shared static
object are used and where the caller stores those symbolic values.  Static ELF
addresses are not promoted to runtime physical, MMIO, or DRAM destinations.

## Exact scope and pins

The retained A90 XBL `xbl--sdb1.bin` is bound by size 4,194,304 and SHA-256
`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.
The helper `[0x9fc160b8,0x9fc160c4)` is pinned to
`aa23cc5c16d3e14a931184f48199c3891359b3074b3433e0b8a82901bc619ff9`.
The exact second caller `[0x9fc26e24,0x9fc26e78)` is 84 bytes with SHA-256
`4c3100f3dff6b8684aa17fc616f6737b283484bb92199dbe98b747a8ab85721d`.
The object range needed by this caller, `[0x9fc362c0,0x9fc36300)`, is 64
bytes with SHA-256
`07f284b58048d944e3d6ef2e19438d9d1e04bde32eafb5541f2eabe294af8277`.
Raw object bytes/values are not published.

## Result

`PROVED` within the finite model:

- the second caller loads object fields `+0x28`, `+0x30`, `+0x38`, `+0x0c`,
  `+0x18`, and `+0x20` (the latter two through an exact `LDP`);
- six corresponding symbolic stores reach static ELF slots
  `0x9fc3e138`, `0x9fc3e140`, `0x9fc3e148`, `0x9fc3e150`, `0x9fc3e158`, and
  `0x9fc3e160`.

The manifest retains every field value as `UNKNOWN` with static object-field
provenance.  The destination VAs are static code/data addresses only; no
runtime currentness, writability, MMIO identity, physical address, DRAM
coordinate, or controller meaning is asserted.

`SUPPORTED`: this is a second static field-use edge from the shared 020C object
and cross-checks that the object is consumed by more than one XBL path.

`HYPOTHESIS`: the shared object and slots may be configuration state.

`UNKNOWN`: runtime values/type/currentness, slot semantics, writer timing,
mutability/locking, indirect paths, physical-to-DRAM mapping, protected reach,
aliasing, and boundary bypass.

Classification remains `CLASS C (TRANSFORM ONLY)` and eligibility remains
`NOT_ELIGIBLE`.  No device, ADB, SMC, MMIO, normal-RAM, protected-memory, or
partition action was performed.

## Artifacts and validation

The sanitized manifest is
`evidence/manifests/020D-second-caller-field-use-20260827-01.manifest.json`,
10,181 bytes, mode `0644`, SHA-256
`9aa50ba0d1389584bb6b32435ff68b176d60aad9e822aabd6c503be21741b223`.
Focused tests are 6/6 PASS and the full serial repository suite is 1,179/1,179
PASS (`skipped=1`) in 117.908 seconds, maximum RSS 297,080 KiB, with zero swap.
Python byte-compilation, deterministic regeneration/byte identity, public JSON
parse, private-path scan, mode and no-clobber checks, and independent hostile
review PASS.  Live repetitions, rollback, recovery and target-health receipts
are `NOT_APPLICABLE`.

Reproduction template:

```text
python3 tools/sm8150_xbl_second_caller_field_use_020d.py \
  --output evidence/manifests/020D-second-caller-field-use-20260827-01.manifest.json
python3 -m unittest -v tests.test_sm8150_xbl_second_caller_field_use_020d
```
