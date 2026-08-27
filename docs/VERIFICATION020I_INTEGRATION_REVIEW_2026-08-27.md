# Verification 020I caller-context/entry-role integration review — 2026-08-27

## Boundary and exact inputs

This iteration is host-only and read-only.  No device, ADB, SMC, MMIO,
normal-RAM, protected-memory, partition, firmware-write, or controller-write
operation occurred.  The exact XBL is 4,194,304 bytes with SHA-256
`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.
The public 020H dependency is pinned to SHA-256
`b306ca67675430314289fd79faa2e53b2d67994807d0b08bd91ced9b625faba2`.

## Static result

The tool re-derives the exact 020H role rows and verifies 20 unique
block-entry direct-BL source/target edges.  Each source receives a bounded
backward window of at most 16 instructions with explicit stop reasons.  The
current exact output has 12 `CALLER_CONTEXT_UNSUPPORTED`, 6
`ARGUMENT_OR_UNKNOWN`, and 2 `ARGUMENT_COPY_OR_CONSTANT` rows.  No source is
promoted to a true function or controller writer; static-slot-origin evidence
is not reached in these bounded windows and remains an unproven possibility
outside the model.

`PROVED`: exact input pins, source/target edges, callsite cardinality and
strict bounded stop/definition records.  `SUPPORTED`: local caller-context
shape only.  `HYPOTHESIS`: some callsites may be initialization/helper paths.
`UNKNOWN`: true function boundaries, runtime execution/values, indirect
calls/callee effects, object semantics, global writer/consumer absence, ABI
effects, MMIO/physical/DRAM identity, mutability/locking, protected reach,
aliasing, and bypass.

Classification remains `CLASS C (TRANSFORM ONLY)` and eligibility remains
`NOT_ELIGIBLE`.

## Validation

Python byte-compilation passed for the tool and focused test module.  The
focused suite is 11/11 PASS.  The full repository suite was run serially to
avoid memory pressure: 1,227/1,227 tests PASS (`skipped=1`) in 151.571
seconds, maximum RSS 356,228 KiB, zero swap, exit status 0.  Deterministic
regeneration produced a 12,472-byte mode-`0644` manifest with SHA-256
`03c463f667142a21641264ec2e4080d9d5f963c67776037ca9d6194a8a621608`, byte
identical to the retained public artifact.  Public JSON parsing, private-path
redaction, no-clobber publication, exact 20/20 callsite cardinality and
classification counts, source/target checks, and synthetic decoder/context/
dependency negatives passed.

The implementation and focused-test hashes at review time are:

| Artifact | SHA-256 |
|---|---|
| `tools/sm8150_xbl_static_slot_caller_context_entry_role_020i.py` | `084afe5b9d177e2fa4be4b24c3c82fbe9060f503e6a14cce95119ab4bcdc0f5d` |
| `tests/test_sm8150_xbl_static_slot_caller_context_entry_role_020i.py` | `90ca9f6c45e4f1637cdc4ed1264345411b1d92f15d1c3e2d06633408f69d8daf` |
| `experiments/verification-020I-static-slot-caller-context-entry-role/README.md` | `e8638b849e1da83b29063da17f1a8598186f3085aee4e9ca371f4565ff771624` |
| `docs/VERIFICATION020I_CONTRACT_2026-08-27.md` | `b30866001969fc1d2e931b0d34f9a302858ed8b0fcbbc08a68256f8ca8e9bb34` |
| `evidence/manifests/020I-static-slot-caller-context-entry-role-20260827-01.manifest.json` | `03c463f667142a21641264ec2e4080d9d5f963c67776037ca9d6194a8a621608` |

## Independent hostile review

`PASS`.  The independent reviewer confirmed exact XBL/020H pins and
`O_NOFOLLOW` handling, strict B/BL/RET discrimination, 20 source/target edges,
at-most-16 stop windows, the exact 12/6/2 classification split, forward
static-page tracking with register-kill semantics, and the synthetic mutation
negatives.  Public redaction, no-clobber, Class C/`UNKNOWN` boundaries,
non-overlap and no-device scope also passed.  No P0/P1/P2 issue remains; no
edits or device commands were performed by the reviewer.
