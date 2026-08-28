# Verification 020J caller-context barrier/opcode integration review — 2026-08-27

## Boundary and exact inputs

This iteration is host-only and read-only.  No device, ADB/ACM, SMC, MMIO,
normal-RAM, protected-memory, partition, firmware-write, or controller-write
operation occurred.  The exact XBL is 4,194,304 bytes with SHA-256
`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.
The public 020I dependency is pinned to SHA-256
`03c463f667142a21641264ec2e4080d9d5f963c67776037ca9d6194a8a621608`.

## Static result

The tool re-derives the exact 020I callsite set and inspects only the first
unsupported stop word in each of 12 windows.  All 12 stop VAs are unique.  The
strict family inventory is:

| Family | Count |
|---|---:|
| `B_COND` | 5 |
| `CBZ_CBNZ` | 2 |
| `LDP_STP_PAIR` | 2 |
| `LOGICAL_OR_BITMASK_IMMEDIATE` | 2 |
| `BITFIELD` | 1 |

The pair decoder covers both signed-offset and pre-index scalar GPR forms;
the bitfield row is the 32-bit `BFXIL` encoding.  The fallback
`UNKNOWN_OPCODE` count is zero for this exact set.  No stop was reinterpreted
as a call graph, pointer, PA, MMIO, controller register, DRAM coordinate,
ownership state or bypass primitive.

`PROVED`: exact dependency/XBL pins, 12/12 stop cardinality and the bounded
family split.  `SUPPORTED`: ordinary ARM64 control/prologue/bitfield shape in
the finite inventory.  `HYPOTHESIS`: the barriers may be ABI/prologue/control
artifacts rather than controller programming.  `UNKNOWN`: full instruction
semantics, true function boundaries, runtime execution/currentness/values,
indirect paths, object semantics, global writer/consumer absence,
MMIO/physical/DRAM identity, mutability/locking, protected reach, aliasing and
bypass.

Classification remains `CLASS C (TRANSFORM ONLY)` and eligibility remains
`NOT_ELIGIBLE`.

## Validation

Python byte-compilation passed for the tool and focused test module.  The
focused suite is 7/7 PASS.  The full repository suite was run serially to
avoid memory pressure: 1,234/1,234 tests PASS (`skipped=1`) in 164.114
seconds, maximum RSS 355,764 KiB, zero swap, exit status 0.  Deterministic
regeneration produced the retained public manifest byte-for-byte, mode
`0644`, with no private-path or raw-word leakage.  No-clobber publication and
dependency/stop/family mutation negatives passed.

The implementation and artifact hashes are recorded here after the final
reviewed run:

| Artifact | SHA-256 |
|---|---|
| `tools/sm8150_xbl_caller_context_barrier_opcode_inventory_020j.py` | `4ab87464f17bc8887e62c5bb4eba7c693b2ec299575fc38f8bd9f7847c50dc1b` |
| `tests/test_sm8150_xbl_caller_context_barrier_opcode_inventory_020j.py` | `04c904b45e59e57f610001c939bb089870b6dbda902d3bb70a7969611e9fac3b` |
| `experiments/verification-020J-caller-context-barrier-opcode-inventory/README.md` | `0f832b7256e1f3c3a6e019ea7dec4d79fa5c46cb69598c129c8fe4caafecbbff` |
| `docs/VERIFICATION020J_CONTRACT_2026-08-27.md` | `05c869343fc336b37939e472b9b9f5b7d70a853e1dac4f907109690875e103d1` |
| `evidence/manifests/020J-caller-context-barrier-opcode-inventory-20260827-01.manifest.json` | `1fdb1f4ade702fdb2d6ffdc68669a9710c8152e225f89f02fb65c0d10f4c3d55` |

## Independent hostile review

`PASS`.  The independent reviewer confirmed the current hashes and
byte-identical 7,657-byte regeneration, exact XBL/020I pins, 12 unique stops
and expected family counts, pre-index pair and BFXIL recognition, B/BL/RET
separation, dependency/cardinality/family mutation negatives, raw-word/private
redaction, mode `0644`/no-clobber behavior, non-overlap with 020I,
Class C/`NOT_ELIGIBLE`/`UNKNOWN` boundaries and the no-device scope.  No
P0/P1/P2 issue remains; no edits or device commands were performed by the
reviewer.
