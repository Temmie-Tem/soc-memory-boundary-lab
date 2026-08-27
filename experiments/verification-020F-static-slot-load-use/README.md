# Verification 020F — bounded static-slot load-use trace (2026-08-27)

This host-only, read-only experiment follows the twelve direct `LDR` accesses
identified by 020E.  For each seed it scans at most 16 instructions in the
same file-backed executable segment, recording only recognized downstream
uses: address-base/register-offset accesses, arithmetic, register copies,
tainted stores, predicates, returns, and explicit control-flow barriers.
Unknown instructions, unsupported forms, indirect paths, and caller-saved
calls stop the local trace.  Continuation across X19–X29 is conditional on the
same explicit AAPCS64 callee-saved assumption used by 020E.

The trace is a bounded static-use model.  It does not establish global writer
or consumer absence, runtime execution/currentness, values, MMIO identity,
physical/DRAM destination, mutability, protected reach, or alias/bypass.

## Exact scope and pins

The retained A90 XBL `xbl--sdb1.bin` is bound by size 4,194,304 and SHA-256
`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.
The 020E dependency is the sanitized manifest SHA-256
`4c28b0cc0a113e099fe3b0ce2bd16a77ce0c9d9bfc799ca9494c52eed9c349ad` and its
exact six-slot / eighteen-access census.  The twelve seed loads are pinned by
their VA, slot offset, width, and destination register in the tool.

## Result

The twelve seeds yield 16 recognized downstream use events in the finite model:
10 address-base uses, 2 arithmetic uses, 2 register-offset address uses, 1
register copy, and 1 return use.  Eleven barriers are also retained: 4
caller-saved-`BL`, 5 recognized generic control, and 2 unknown-instruction
barriers.  No tainted direct store is reached within the supported windows.
This is a bounded static result, not a claim that no other store or consumer
exists.

`PROVED`: exact XBL and 020E seed-set pins; every reported event is produced by
the strict 16-instruction same-block model.

`SUPPORTED`: several slots feed local address formation and arithmetic in the
bounded paths, while one slot load is returned directly.  These are useful
semantic leads for later source reconstruction.

`HYPOTHESIS`: some slot values may be object pointers or local configuration
fields rather than final controller-register state.

`UNKNOWN`: global writer/consumer absence, ABI compliance and callee effects,
runtime execution/currentness and values, slot semantics, MMIO/physical/DRAM
identity, mutability/locking, protected reach, aliasing and bypass.

Classification remains `CLASS C (TRANSFORM ONLY)` and eligibility remains
`NOT_ELIGIBLE`.  No device, ADB, SMC, MMIO, normal-RAM, protected-memory,
partition, firmware-write, or controller-write action was performed.

## Artifacts and validation

The sanitized manifest is
`evidence/manifests/020F-static-slot-load-use-20260827-01.manifest.json`,
13,069 bytes, mode `0644`, SHA-256
`d19687581d046c7b05841aef6340e9a1e3664c69e19903689d1c583aee5b9764`.
Focused tests are 9/9 PASS and the full serial repository suite is 1,195/1,195
PASS (`skipped=1`) in 123.910 seconds, maximum RSS 342,272 KiB, with zero
swap.  Python byte-compilation, deterministic regeneration/byte identity,
public JSON parse, private-path scan, mode/no-clobber checks, and independent
hostile review are PASS.  The durable record is
`docs/VERIFICATION020F_INTEGRATION_REVIEW_2026-08-27.md`.

Reproduction template:

```text
python3 tools/sm8150_xbl_static_slot_load_use_020f.py \
  --output evidence/manifests/020F-static-slot-load-use-20260827-01.manifest.json
python3 -m unittest -v tests.test_sm8150_xbl_static_slot_load_use_020f
```
