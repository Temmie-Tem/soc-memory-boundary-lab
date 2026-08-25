# Experiment 024 — exact XBL six-byte walker

## Question

Does the exact false-negative loop recorded by Experiment 020 decode as a
direct six-byte offset/value walker, and do its direct callers select tables
that are resident in XBL rather than the separate 8-byte `xbl_config` DCB
candidate-array representation?

## Scope and safety

This is host-only, read-only static analysis.  It parses the exact XBL ELF64
program headers and aligned words, the pinned public Samsung DTS snapshot, and
the pinned A90 OSRC DTS snapshot.  It performs no device, SMC, MMIO,
protected-memory, normal-RAM, runtime-register, or activation action.

The public manifest contains hashes, addresses, instruction pins, counts and
classifications only.  It contains no firmware/source bytes and no private
absolute paths.  Experiments 015 and 016 remain `NOT_ELIGIBLE`; classification
remains `CLASS C (TRANSFORM ONLY)`.

## Exact inputs

| Input | Size | SHA-256 | Public provenance |
|---|---:|---|---|
| `xbl--sdb1.bin` | 4,194,304 | `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37` | Experiment 004 exact XBL |
| public `sm8150.dtsi` | 101,386 | `38db804d589bb01206adbf2a351c4d074f5c92f7ef351dc3976cbcb846f1a31c` | Roynas `kernel_samsung_r3q` commit `e1d271581eff` |
| OSRC `sm8150.dtsi` | 102,419 | `c0d42e66ddd5640e2dd7b65527c25fb617008d94a6a04062b9e1077f0eb63849` | A908N OSRC `Kernel.tar.gz` SHA `403fdc49f086d238c01a796c390083c3c47c1754c218e228f29b55cc7c35d554`; correspondence to installed config is `SUPPORTED` by A90_SELF_BUILT_KERNEL_H0 report |
| Experiment 019 manifest | 40,368 | `232eb0375fadf96db1fd303d83d707cf47cb668a24129d7e4791b193fb3fc70c` | Repository-relative structural eight-byte pair-array dependency |

The complete adjacent `ufsphy_mem` + `ufshc_mem` source block is 4,464 bytes
with SHA-256
`cea31db3785be5916a1ff08d1c99b92155a7914b07d09ecb6c3638d8c16ff10a` in both
snapshots.  This proves agreement between the two pinned design sources; it
does not prove equality with the live DTB, whose hash/equality is `UNKNOWN`.

The structural comparison dependency is pinned to
`019-dcb-register-programming-20260826-01.manifest.json`, size 40,368, SHA-256
`232eb0375fadf96db1fd303d83d707cf47cb668a24129d7e4791b193fb3fc70c`.  It
records 28 eight-byte `xbl_config` candidate pair arrays; this dependency is
validated before the six-byte/XBL distinction is published.
The tool loads this dependency from its repository-relative manifest path; no
private path is emitted.

## Result

`PROVED`: `[0x148689a0,0x14868a64)` is a 196-byte walker with SHA-256
`08265307d79c5f82b85266613f241ae160151dcfe51b19da108f9ad6c4e15021`.  Its
loop uses `UMADDL` with record stride 6, loads flags at `+0`, offset at `+2`,
and a byte value at `+4`, compares the flags field against the exact
terminator `0x8000`, and `B.EQ 0x14868a60` returns before the store.  Accepted
store-taken nonterminator paths execute conditional `STR W14,[X15,X13]`;
other nonterminator flag combinations can skip the store.  `LDRB`
zero-extends the byte and the conditional store writes a 32-bit word.  No
undocumented flag meaning is assigned.

The known loop subrange `[0x148689c8,0x14868a60)` remains pinned to hash
`02248b786ffb501a5fa9242aa3952e1e4d783f47464952e96ca2704a9f94341e`.

`PROVED`: an independent census over all file-backed executable PT_LOAD words
finds exactly three direct callers: `0x14868640`, `0x1486867c`, and
`0x14868698`.  Each passes the context in `X0`, loads `X1` from the stack slot,
and passes the provider return in `W2`.  Only the five nonzero alternatives
prove that the stack slot contains a provider-written XBL table pointer.  The
provider ranges are independently pinned to the exact hashes in the manifest.

The providers derive five XBL-resident table alternatives (counts include the
exact terminator record):

| Selector condition | Table | Count |
|---|---:|---:|
| `selector == 0xf` | `0x14880bee` | 43 |
| `selector != 0xf` | `0x14880e70` | 90 |
| `selector == 0xf` | `0x14880ba0` | 13 |
| `selector != 0xf` | `0x14880cf0` | 64 |
| `selector != 0xf` | `0x14880b40` | 16 |

Each table ends in exact `0x8000/0/0/0`.  The selector-`0xf` alternatives have
53 unique aligned offsets; selector-not-`0xf` has 127; their cross-alternative
union has 170 spanning `0x7000..0x7de0`.  None is `0x400`, `0x404`, or `0x4d0`.
Provider3 on selector `0xf` writes no pointer and returns count zero; the
pinned walker zero-count control reaches `RET` before any table dereference on
that conditional path.  The direct pointers resolve into file-backed XBL
PT_LOAD storage and the six-byte record shape, independently cross-checked
against Experiment 019's pinned eight-byte pair-array result, is structurally
distinct; semantic DCB identity remains `UNKNOWN`.

The runtime selector at `0x146b3000` is in a memory-only PT_LOAD, so its
current value is `UNKNOWN`.  The initializer range
`[0x1486aafc,0x1486ab04)` is pinned to hash
`40fb695e26eac295c251383a0077146e9dd820231a85feedeb791b456086d8a4` and
returns `0x01d80000`; its caller stores `X0` at `[X19,#8]` at `0x14868468`.
The main init range is pinned to
`28fd589dc6e2d47fdf592b3a08aa8883e9e0d90a648f76733dab5376dfd369da`.

The base audit is deliberately conditional.  The direct local store census
finds no second `[ctx,#8]` store, but success-path helper
`[0x1486abec,0x1486acac)` (hash
`679384b78fab5cf3903f5c7a34e5efa45552c983b4d2bb1fcc8dc12e66d555c2`) executes
an unresolved `BLR X9` at `0x1486ac1c` through a runtime-BSS object.  Therefore
base currentness is `UNKNOWN`, and the destination mapping is conditional on
the initialized base remaining current through all reachable direct callees
and aliases.  The helper loads the runtime-BSS slot through `0x1486ac04`,
forms its attached address at `0x1486ac40`, and reloads it at `0x1486aca4`;
the slot (`0x14890590`) is retained as an explicit pin in the manifest.

Under that condition, all 170 symbolic `BASE+offset` destinations derived from
the cross-alternative syntactic store-operand offset superset lie in the
broader DTS `ufshc` `ufs_phy` resource
`[0x01d87000,0x01d87e00)`.  Destinations corresponding to exactly three
offsets — `0x7dc4`, `0x7dd8`, and `0x7de0` — lie beyond standalone `ufsphy_mem`
`[0x01d87000,0x01d87da8)` while remaining inside the broader resource.
Actual current destinations, reached subsets, and flag semantics remain
`UNKNOWN`.

## Boundaries

The direct-call positive control supports a table-driven path, conditional on
base currentness.  It neither proves nor refutes a ranked DDR/MC/DCB path.
Runtime execution, selector value, flags semantics, postboot mutation,
reached store subsets, indirect callers, other walkers, global DCB
consumer/writer presence, aliases, physical ownership, the GF(2) relation, and
boundary bypass remain `UNKNOWN`.

## Reproduce

Set `ANDROID_NATIVE_INIT_LAB` to the operator's local Android-native-init-lab
root, or pass explicit paths.  Both design snapshots are required inputs to
the proof:

```sh
repro_dir=$(mktemp -d /tmp/exp024-xbl-six-byte-walker.XXXXXX)
python3 tools/sm8150_xbl_six_byte_walker.py \
  --firmware-dir evidence/private/004-live-firmware-readonly-20260825-01 \
  --public-kernel-dtsi "$ANDROID_NATIVE_INIT_LAB/workspace/private/work/public_a90_r3q/kernel_samsung_r3q-e1d271581eff/arch/arm64/boot/dts/qcom/sm8150.dtsi" \
  --osrc-kernel-dtsi "$ANDROID_NATIVE_INIT_LAB/workspace/private/work/a90-stock-mpgen27-20260822/source/arch/arm64/boot/dts/qcom/sm8150.dtsi" \
  --output "$repro_dir/manifest.json"
python3 -m unittest -v tests.test_sm8150_xbl_six_byte_walker
```

The output is created with `O_EXCL`/`O_NOFOLLOW`, mode `0644`, and never
clobbers an existing path.  The manifest is deterministic (`sort_keys=True`);
fresh temporary-directory generation is byte-identical.

## Evidence

- `evidence/manifests/024-xbl-six-byte-walker-20260826-01.manifest.json`

## Provenance

- Tool SHA-256: `f0ccb5648b2cce4ab2b835e23c4658c976df9779b0ae6273767b59cc7b6a58bf`
- Focused-test SHA-256: `97c58a22c5c3e7e6cd5b7bc4f8d181c74050b2b530afac03eba3fbb946577f6d`
- Public manifest SHA-256: `f9ac896d396650075ca9e66d8d805a2deaf40b0207e819cd94f8d638c8121b01`
- Mode: `HOST_ONLY_READ_ONLY`; device, SMC and MMIO access: none.
