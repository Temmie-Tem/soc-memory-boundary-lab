# Verification 020I — bounded caller-context/entry-role trace (2026-08-27)

This host-only, read-only experiment follows the exact direct `BL` source VAs
recorded by 020H.  It reopens and hashes the public 020H manifest, re-derives
its role rows from the exact XBL, verifies each source/target edge, and traces
at most 16 preceding instructions at each callsite.  Strict `RET X30`, direct
`B`, direct `BL`, scalar/register-offset memory, `ADRP`, flagless `ADD`/`SUB`,
`MADD`, and register-copy forms are recognized; unsupported or ambiguous forms
stop the local trace fail-closed.

The trace records only caller-context shape.  It does not infer true function
boundaries, runtime values, pointer or physical addresses, MMIO/DRAM identity,
ownership, or a security-boundary primitive.

## Exact scope and pins

The retained A90 XBL `xbl--sdb1.bin` is bound by size 4,194,304 and SHA-256
`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.
The exact public 020H manifest is opened with `O_NOFOLLOW`, checked as a
regular file, parsed as JSON, and bound to SHA-256
`b306ca67675430314289fd79faa2e53b2d67994807d0b08bd91ced9b625faba2`.

## Result

The census contains 20 unique 020H block-entry direct-BL source VAs.  Twelve
windows stop at an unsupported form (`CALLER_CONTEXT_UNSUPPORTED`), six remain
`ARGUMENT_OR_UNKNOWN`, and two contain bounded argument-shaped definitions
(`ARGUMENT_COPY_OR_CONSTANT`).  No source was promoted to a true function or
controller writer.  Static-slot-origin classification was not reached in the
exact bounded windows; this is a negative/unknown result, not proof that no
such caller exists elsewhere.

`PROVED`: exact XBL/020H pins, 20 source/target edges, and the bounded window
stop reasons/definitions.

`SUPPORTED`: the retained direct callers provide only local argument/context
shape evidence.  `HYPOTHESIS`: some callsites may be initialization/helper
paths that prepare local configuration state.

`UNKNOWN`: true function boundaries, runtime execution/currentness/values,
indirect calls/callee effects, object semantics, global writer/consumer
absence, ABI effects, MMIO/physical/DRAM identity, mutability/locking,
protected reach, aliasing, and bypass.

Classification remains `CLASS C (TRANSFORM ONLY)` and eligibility remains
`NOT_ELIGIBLE`.  No device, ADB, SMC, MMIO, normal-RAM, protected-memory,
partition, firmware-write, or controller-write action was performed.

## Artifacts and validation

The sanitized manifest is
`evidence/manifests/020I-static-slot-caller-context-entry-role-20260827-01.manifest.json`.
Focused/full validation, deterministic regeneration, artifact hashes, and
independent hostile-review status are recorded in the integration review.

Reproduction template:

```text
python3 tools/sm8150_xbl_static_slot_caller_context_entry_role_020i.py \
  --output evidence/manifests/020I-static-slot-caller-context-entry-role-20260827-01.manifest.json
python3 -m unittest -v tests.test_sm8150_xbl_static_slot_caller_context_entry_role_020i
```
