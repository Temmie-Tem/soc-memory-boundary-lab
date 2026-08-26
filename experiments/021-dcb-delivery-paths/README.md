# Experiment 021 — Scoped DCB delivery-path audit

## Question

Does DCB section data reach a consumer through the exact bounded-copy routine
identified in Experiment 020, and what do the retained SHRM and ABL bytes
actually establish?

## Scope and eligibility

This is host-only, read-only static evidence over the exact Experiment-004 XBL
and ABL artifacts plus the pinned SHRM Xtensa blob. The delivery conclusion is
limited to one pinned bounded-copy routine at `0x1483ab24` and the exact direct
AArch64 `BL`/`B` encodings that target it. It is not a global call-graph or
all-copy-routine result. Indirect `BLR`/`BR` callers, other copy routines and
runtime paths remain `UNKNOWN`.

No device, SMC, MMIO, normal-RAM, protected-memory or runtime-register access
was used. Conceptual Experiments 015 and 016 remain reserved and
`NOT ELIGIBLE`.

## Result

`PROVED` for the direct census: the exact XBL contains **7 direct `BL`** edges
to the pinned routine and **0 direct `B`** edges. Five of the seven direct
`BL` sites receive a local directory-read label for sections **{0, 1, 2, 15,
16}**, matching the Experiment-004 loader record; two sites remain unlabelled.

For sections **3–14 and 17**, the result is `NOT_OBSERVED` under this local
directory-read label model, not a delivery refutation. Whether either
unlabelled call delivers one of those sections is `UNKNOWN`, as are indirect
callers and other copy routines. The exact `REFUTED` claim is that the local
label model accounts for every direct `BL` site; two are unlabelled, so that
completeness claim is false.

The section observations are retained verbatim in the public manifest:
`call_site_count=7`, `unlabelled_direct_bl_count=2`, five section-labelled
sites, and the locally labelled section set `{0,1,2,15,16}`.

## SHRM literal audit

The pinned Xtensa blob is 23,776 bytes with SHA-256
`421824b417ab28e6c0d1802c05d7ce5422e93b116973ce7f039321fb5a01a1fd`. It has
**116** aligned words in **39** aperture blocks. Ranked-instance-block literal
counts (stored literals within each ranked base block, not runtime reach) are
exact:

| Ranked base | Aligned base-block literals |
|---|---:|
| `0x09260000` | 7 |
| `0x092e0000` | 0 |
| `0x09360000` | 0 |
| `0x093e0000` | 0 |

All 12 ranked target-literal counts (`+0x400`, `+0x404`, `+0x4d0` across
four bases) are exactly **0**. A computed target formed from a retained base
literal remains `UNKNOWN`; literal absence does not refute computed addressing.

## ABL raw observations

The ABL `PT_LOAD` payload is **2,293,760 bytes**. The bytes show `_FVH` at
payload offset `0x28`, measured Shannon entropy **8.000 bits/byte** in the
first 1,048,576 payload bytes, and **0** aligned AArch64 `RET` words. Those
are `PROVED` observations. The result is classified
`UNPARSED_HIGH_ENTROPY_UEFI_FV`; this records marker presence and does not
claim that the full firmware volume was parsed.

The retained ABL artifact is 4,194,304 bytes with SHA-256
`1db19d11a5ce6865e3fbcabadfbdaa9045e75f144b8bc8593a58338c20a3120c`.

The payload’s compression state and whether a literal search would be
meaningful are `UNKNOWN`; the observations only `SUPPORTED` the unparsed
classification. The experiment does not promote the entropy threshold to a
proof of compression or semantic “not searchable”.

## Classification

```text
CLASS C (TRANSFORM ONLY)
NO_BOUNDARY_BYPASS_OBSERVED
```

Register semantics, SHRM computed addressing, ABL consumption of DCB tables,
indirect calls, other copy routines, post-boot writability, aliases and
boundary bypass remain `UNKNOWN`.

## Evidence and reproducibility

- Public manifest: `evidence/manifests/021-dcb-delivery-paths-20260826-01.manifest.json`
- Dependencies are hash-pinned in the manifest:
  - `004-live-firmware-readonly-20260825-01.manifest.json`:
    `1ed4b8b14b2e0ccf2d4ae084ea413e0395d9dc488dd5d2bb1dd872fbe20d9247`
  - `verification-001-independent-claim-audit-20260825-01.manifest.json`:
    `a722f0f66367de300b9a4402002e510a0d457c0250ca1b09f44e964f4914f2e5`

```sh
repro_dir=$(mktemp -d /tmp/021-dcb-delivery-paths.XXXXXX)
python3 tools/sm8150_dcb_delivery_paths.py \
  --output "$repro_dir/manifest.json"
python3 -m unittest -v tests.test_sm8150_dcb_delivery_paths
```

Output creation is `O_EXCL`/`O_NOFOLLOW` by default. Use `--force` only for an
intentional replacement of an existing regular output file.

The manifest contains hashes, addresses, counts and classifications only; it
contains no raw firmware bytes or private paths.

## Provenance

- Tool SHA-256: `180fd7b3eb6f281fa612a31b126dbf474bf99fd775cf6b77ff1d6535d23f133b`
- Focused-test SHA-256: `bd7b07fd1be4c60a74080191a090b3d8fbc0649508bb8ab2767bd36ccbbb526e`
- Public manifest SHA-256: `d85999e644bae1f5bafe683b44b253450d04d1b666c73659d9284c010d32b44a`
- Mode: `HOST_ONLY_READ_ONLY`; device, SMC and MMIO access: none.
