# Experiment 021 — DCB delivery paths, SHRM and abl

## Question

Experiment 020 found no consumer in the exact XBL that programs controller
registers from the DCB base-relative tables, and no reference to the ranked MC
instances in AOP. This asks the prior question: is that data delivered anywhere
at all?

A section reaches a consumer either by being copied out of the DCB or by being
read in place. The copy path is enumerable, and the in-place consumers
Experiment 020 identified are a checksum accumulator over sections 5–10 and a
bounds check on section 10.

## Scope and eligibility

Host-only, read-only static evidence over the exact Experiment-004
`xbl--sdb1.bin` and `abl--sdd8.bin`. No device, SMC, MMIO, normal-RAM,
protected-memory or runtime-register access. Conceptual Experiments 015 and 016
remain reserved and `NOT ELIGIBLE`.

## Result

`PROVED`: the loader's bounded copy at `0x1483ab24` has exactly **seven** call
sites in the exact XBL. Five are the DCB loader, each preceded by a directory
read, and they cover sections **{0, 1, 2, 15, 16}** — matching the set
Experiment 004 records and Experiment 020 re-derived. The other two carry no
directory read within sixteen instructions and are unrelated copies.

`REFUTED`: the DCB base-relative tables are delivered to a consumer by the XBL
bounded copy. Sections 3–14 and 17 — which include every base-relative
programming table, 6, 7, 8, 10, 11 and 12 — have **no** copy path through it.

`PROVED`: the SHRM Xtensa blob embedded in XBL at `0x148bbe98`, 23,776 bytes,
holds 116 aligned words inside the SoC control aperture across 39 blocks.
Seven lie in the first ranked MC instance block:

```text
0x09260000  offset 0x0        0x09265600  offset 0x5600
0x09260200  offset 0x200      0x09265a00  offset 0x5a00
0x09265200  offset 0x5200     0x09266200  offset 0x6200
                              0x09269124  offset 0x9124
```

`PROVED`: **none** of the twelve ranked target addresses appears as a literal
in that blob, and only the first instance is named — `0x092e0000`,
`0x09360000` and `0x093e0000` have no literal at all.

`PROVED`: `abl--sdd8.bin` is a UEFI firmware volume — `_FVH` at payload offset
`0x28` — whose 2,293,760-byte payload has Shannon entropy 8.000 bits per byte
and contains zero AArch64 `RET` instructions. It is **not searchable**.

`UNKNOWN`: whether abl consumes the DCB tables; whether SHRM reaches a ranked
target by computing an offset from the base literal it does hold rather than
storing the target; whether a copy path exists through a routine other than
this one; register semantics; the relation to the Experiment 014 GF(2) bank
relation; post-boot writability; alias; boundary bypass.

Current classification is unchanged:

```text
CLASS C (TRANSFORM ONLY)
NO_BOUNDARY_BYPASS_OBSERVED
```

## A negative and a void are not the same thing

The abl result is recorded as unsearchability, not as an absence count, and the
distinction is load-bearing. A literal search over incompressible bytes returns
nothing whether or not the constant is there, so reporting "no ranked base
literal in abl" alongside the AOP and SHRM results would silently promote a
measurement that cannot fail into evidence.

AOP earns its negative because Cortex-M builds 32-bit constants from literal
pools, so an address it uses must be present as a stored word. SHRM earns its
negative for the same reason under Xtensa `L32R`. abl earns nothing: reaching a
verdict there means parsing the firmware volume and decompressing its sections,
which this experiment does not attempt.

## What the SHRM literals do and do not show

That SHRM names `qhs_mc` instance 0 is a genuine reach into the ranked block,
and it is new: Experiment 018 searched only `xbl--sdb1.bin` for base literals,
and Experiment 014 searched the SHRM dump for the bank relation rather than for
addresses.

It is not evidence about the ranked targets. The seven literals sit at offsets
`0x0`, `0x200`, `0x5200`, `0x5600`, `0x5a00`, `0x6200` and `0x9124`, and none of
`0x400`, `0x404` or `0x4d0` is among them. A base literal plus a computed
displacement would reach any offset without storing it, so this bounds what the
blob names, not what it touches.

The absence of the other three instances is worth recording but not
interpreting. It is equally consistent with SHRM being per-channel, with the
other bases being derived by adding a stride, and with those paths living
outside the 23,776 bytes examined.

## Reading this with Experiment 020

Four facts now hold together. The base-relative tables are never copied out of
the DCB. The in-place consumers XBL does contain compute a checksum and check
bounds. No store in XBL walks a key/value table under either the register-offset
or the computed-address idiom. And AOP names no ranked base.

The economical reading is that the exact XBL does not consume those tables. The
remaining candidates are abl, which is not searchable without decompression,
and a path outside these images entirely.

## Evidence

- `evidence/manifests/021-dcb-delivery-paths-20260826-01.manifest.json`

The manifest contains hashes, addresses, counts and classifications only. It
contains no raw firmware bytes and no private paths.

## Reproduce

```sh
python3 tools/sm8150_dcb_delivery_paths.py \
  --output evidence/manifests/021-dcb-delivery-paths-20260826-01.manifest.json
python3 -m unittest -v tests.test_sm8150_dcb_delivery_paths
```

## Provenance

- Tool SHA-256:
  `e879faad9dbda8297bd99f0b2832881000b209d9c7ec624417cf79d8763ff6d9`.
- Focused-test SHA-256:
  `f092e2f72e6c7d45a0055568f9faedd943bd8461e1ab8338f856fad10ae8b466`.
- Public manifest SHA-256:
  `ccfdce39f17d57ee535ce8406df3b562d1adb669159d9e120f0ac2153b9ebc49`.
- Focused result: 20 tests pass.
- Regeneration is byte-identical; manifest mode is `0644`.
- Date: 2026-08-26 KST.
- Mode: `HOST_ONLY_READ_ONLY`; device, SMC and MMIO access: none.
- Produced on branch `research/xbl-config-cdt` in a separate worktree.
  `STATUS.md`, `docs/EXPERIMENT_MATRIX.md` and `docs/RESEARCH_LOG.md` are
  deliberately untouched here and are reconciled at integration.
