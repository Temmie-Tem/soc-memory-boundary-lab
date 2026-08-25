# Experiment 025 — bounded XBL platform-query binding

## Question

Can the intended SM8150 XBL platform-query binding resolve the
Experiment 024 runtime-BSS object through registry/attach, factory, vtable
`+0x48`, and callback—and can that binding write the caller's context `+8`
base field?

## Scope and safety

This is host-only, read-only static analysis of one exact XBL ELF.  It performs
no device, SMC, MMIO-write, protected-memory, runtime-register, or activation
action.  The status-helper's statically visible MMIO read is only decoded from
the firmware; it is never executed.

The public manifest contains addresses, hashes, instruction/data pins, counts,
and classifications only.  It contains no firmware bytes, private absolute
paths, device identifiers, or live values.  Classification is `CLASS C
(TRANSFORM ONLY)`; Experiments 015/016 remain `NOT_ELIGIBLE`, and no boundary
bypass is authorized.

## Exact inputs and dependency

| Input | Size | SHA-256 |
|---|---:|---|
| `xbl--sdb1.bin` | 4,194,304 | `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37` |
| Experiment 024 manifest | 30,400 | `f9ac896d396650075ca9e66d8d805a2deaf40b0207e819cd94f8d638c8121b01` |

The Experiment 024 manifest is parsed before analysis.  Its experiment
identity, `initializer_and_base_audit.base_currentness=UNKNOWN`, unresolved
`BLR X9` at `0x1486ac1c`, and conditional mapping status are all validated;
the dependency is not accepted by hash alone.

## Result

`PROVED`: the exact platform-query helper range
`[0x1486abec,0x1486acac)` (file offset `0x51bec`, hash
`679384b78fab5cf3903f5c7a34e5efa45552c983b4d2bb1fcc8dc12e66d555c2`) has one
pinned direct caller at `0x1486847c`.  That caller passes `X0=SP+0x10`; the
main context is held in `X19` and is not forwarded as the helper argument.
The helper loads and retries runtime slot `0x14890590` at `0x1486ac04` and
`0x1486aca4`, forms the attach output address at `0x1486ac40`, passes
`0x02000139` to registry attach, and dispatches through `BLR X9` at
`0x1486ac1c`.  The callback receives `X0=object` and `X1=SP+0xc` output,
not the caller context.

`PROVED`: the registration data and intended static chain are independently
pinned:

`seed 0x1482ee38 -> wrapper 0x1482e7bc -> record 0x14875590 -> descriptor
0x14824ab8 -> factory 0x1484a880 -> object candidate 0x1488f418 -> inline
vtable 0x14824ad0 + 0x48 -> callback 0x1484a9d4`.

The seed derives `X0=0x14875668` and `X1=0x14875590`; the record has five
entries, and the descriptor's ID table independently yields `0x02000139`.
The factory stores its constructed-object candidate through the registry
output argument, which flows back to the runtime slot.

`PROVED`: the callback itself copies `X1` to `X19` and has one recognized
direct write, `STR W8,[X19]` at `0x1484a9f4`, targeting the helper's output
stack slot.  Its immediate callee `0x1484a730` has no direct store.  The
bounded lazy-init graph is also inspected:

- `[0x1484a824,0x1484a854)` calls lazy bootstrap `0x1484aa30` and sets a
  recursion flag at `0x1488f3f9`.
- `[0x1484aa30,0x1484aa74)` (68 bytes, SHA-256
  `1fb73c03710d2acc52a1330804dcb6605d34f16bf8a84dd49902470b4edd8bf8`)
  recurses through `0x1484a824`, calls status helper `0x1484a854`, writes
  only the pinned status BSS locations `0x14890ba0` and `0x14890b90`, and
  reaches the pinned `RET` at `0x1484aa70`.
- `[0x1484a854,0x1484a880)` performs one decoded read from `0x01fc8004`; no
  MMIO write is present in this bounded range.

Thus the recognized callback write is an output write, while nested lazy-init
state writes are separately accounted for.  No recognized write reaches the
caller context `+8` field.

`PROVED`: an independent census scans all file-backed executable PT_LOAD
words.  It reports exact slot loads/address formation/reload and recognized
registry-list insertion stores in `[0x14890e50,0x14890f50)`.  The decoder
does not claim absence of computed, indirect, unrecognized, or alias-based
writes.

## Taxonomy and boundaries

- `PROVED`: intended static registry → factory → vtable → callback dataflow;
  exact arguments and recognized direct write targets.
- `SUPPORTED`: the intended callback path cannot write caller context `+8`
  through its recognized direct output flow.
- `UNKNOWN`: runtime registration/order, runtime slot value/object identity,
  alternate BSS mutation, global aliases, effects beyond the pinned nested
  graph, and full preservation/currentness of the initialized `0x01d80000`
  base.

The Experiment 024 conditional UFS mapping is not upgraded.  No device
authority or live current-base proof exists.

## Definition-of-done metadata

The public manifest records the exact target (`SM-A908N` / A90 5G,
`SM8150` / Snapdragon 855), exact XBL size/hash binding, firmware build
`UNKNOWN` (not derived by this decoder), and date `2026-08-26`.  Kernel, boot,
DTB, and research-kernel hashes are explicitly `NOT_APPLICABLE` with
host-only-static reasons.  Timestamp, live repetitions, dmesg/log,
rollback, and recovery are also explicitly `NOT_APPLICABLE` because no live
device or persistent state was touched.  The manifest includes the exact
precondition, a path-free reproducible command template, result taxonomy,
negative-control/failure contract, and deterministic validation metadata: two
fresh generations must compare byte-for-byte, across five validation checks.

## Reproduce

```sh
out_dir=$(mktemp -d /tmp/exp025-xbl-platform-query-binding.XXXXXX)
python3 tools/sm8150_xbl_platform_query_binding.py \
  --firmware-dir evidence/private/004-live-firmware-readonly-20260825-01 \
  --output "$out_dir/manifest.json"
python3 -m unittest -v tests.test_sm8150_xbl_platform_query_binding
```

Publication uses `O_EXCL`/`O_NOFOLLOW`, forces mode `0644`, and never
clobbers an existing output.  JSON generation is deterministic and fresh
regeneration is byte-identical.

## Evidence

- `evidence/manifests/025-xbl-platform-query-binding-20260826-01.manifest.json`

## Provenance

- Tool SHA-256: `16e9584a3043d76670c66b6a517e56c87267645506c1f76a040737d731b168b9`
- Focused-test SHA-256: `219227a927acb8a98d8e7294150c154b916795e709ab02bb076b946d8d7bb687`
- Public manifest SHA-256: `d3c405d7c8d23dc1cd65b1c578b4b4ce931d9bdfeb303c892e9c0c145c4c81cc`
- Mode: `HOST_ONLY_READ_ONLY`; no device action
