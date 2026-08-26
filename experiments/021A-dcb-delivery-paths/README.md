# Experiment 021A — DCB delivery paths, SHRM and abl

Numbered `021A`, not `021`. This experiment and the concurrent `021-dcb-delivery-paths`
were created independently on 2026-08-26 and given the same number: at the
common ancestor `b78879a` neither existed. They are different investigations,
not two revisions of one. That one is on `main`, integrated across the shared
documents, with Experiments 024-034 built on top of it, so it keeps the bare
number and this one takes the suffix, following the `023R` precedent. Nothing
about this result changed.

## Question

Experiment 020A identified no consumer under its bounded instruction and loop
models that programs controller registers from the DCB base-relative tables,
and no recognized exact-literal/local-reader reference to the ranked MC
instances in AOP. This asks the prior question: is that data delivered
anywhere at all?

A section reaches a consumer either by being copied out of the DCB or by being
read in place. The copy path is enumerable, and the in-place consumers
Experiment 020A identified are a checksum accumulator over sections 5–10 and a
bounds check on section 10.

## Scope and eligibility

Host-only, read-only static evidence over the exact Experiment-004
`xbl--sdb1.bin` and `abl--sdd8.bin`. No device, SMC, MMIO, normal-RAM,
protected-memory or runtime-register access. Conceptual Experiments 015 and 016
remain reserved and `NOT ELIGIBLE`.

## Result

`PROVED` for the direct census: the exact XBL contains **seven direct `BL`**
edges to the pinned routine at `0x1483ab24` and **zero direct `B`** edges. Five
of the seven direct `BL` sites receive a local directory-read label for
sections **{0, 1, 2, 15, 16}**, matching the Experiment-004 loader record; two
sites remain unlabelled (`dcb_section=null`).

For sections 3–14 and 17, the result is `NOT_OBSERVED` under this local
directory-read label model, not a delivery refutation. Whether either
unlabelled call delivers one of those sections is `UNKNOWN`, as are indirect
callers and other copy routines. The exact `REFUTED` claim is that the local
label model accounts for every direct `BL` site; two are unlabelled, so that
completeness claim is false.

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
in that blob, and only the first instance is named — `0x09260000`;
`0x09360000` and `0x093e0000` have no literal at all.

`PROVED`: `abl--sdd8.bin` has an aligned `_FVH` marker at payload offset
`0x28`, measured entropy 8.000 bits per byte in the first 1,048,576 payload
bytes, and zero aligned AArch64 `RET` observations. The payload is
`UNPARSED_HIGH_ENTROPY_UEFI_FV`; its compression and post-parse searchability
are `UNKNOWN`, not a negative.

`UNKNOWN`: whether ABL consumes the DCB tables; whether SHRM reaches a ranked
target by computing an offset from the base literal it does hold rather than
storing the target; whether a copy path exists through a routine other than
this one; register semantics; the relation to the Experiment 014 GF(2) bank
relation; post-boot writability; alias; boundary bypass. Experiment 029A later
parses the retained ABL volume; this A-line observation remains the pre-parse
record and is not a claim that ABL is globally unsearchable.

Current classification is unchanged:

```text
CLASS C (TRANSFORM ONLY)
NO_BOUNDARY_BYPASS_OBSERVED
```

## A negative and a void are not the same thing

The ABL result is recorded as an unparsed high-entropy observation, not as an
absence count, and the distinction is load-bearing. A literal search over
unparsed or compressed bytes returns nothing whether or not the constant is
there, so reporting "no ranked base literal in abl" alongside the AOP and SHRM
results would silently promote a measurement that cannot fail into evidence.

The AOP and SHRM checks are bounded to exact stored literals (and the
recognized local directory-reader form where stated). Computed addresses,
received or cached pointers, and alternate literal-pool/use forms remain
`UNKNOWN`; no negative about all runtime references follows. ABL earns only an
unparsed observation here: reaching a searchability verdict means parsing the
firmware volume and decompressing its sections, which this experiment does not
attempt; Experiment 029A later performs that separate extraction.

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

## Reading this with Experiment 020A

Four facts now hold together. The five sections receive local labels at the
bounded-copy call sites, but two direct calls remain unlabelled. The in-place
consumers XBL does contain compute a checksum and check bounds. No store in XBL
walks a key/value table under either the bounded register-offset or the
computed-address idiom. And AOP has no exact stored ranked-base literal under
the tested literal/local-reader model; computed or received pointers remain
`UNKNOWN`.

`HYPOTHESIS` (bounded to this static evidence): the economical reading is that
the exact XBL does not consume those tables. This is not a delivery conclusion;
the two unlabelled direct calls, indirect callers and other copy routines remain
`UNKNOWN`. The remaining candidates include the then-unparsed ABL path and
paths outside these images; Experiment 029A later covers ABL extraction.

## Evidence

- `evidence/manifests/021A-dcb-delivery-paths-20260826-01.manifest.json`

The manifest contains hashes, addresses, counts and classifications only. It
contains no raw firmware bytes and no private paths.

## Reproduce

```sh
python3 tools/sm8150_dcb_delivery_paths_021a.py \
  --output evidence/manifests/021A-dcb-delivery-paths-20260826-01.manifest.json
python3 -m unittest -v tests.test_sm8150_dcb_delivery_paths_021a
```

The reproduction command is a `REDACTED_REPRODUCTION_TEMPLATE`: private input
and output paths are redacted while exact firmware and dependency hashes are
pinned; it is not an executed-command receipt.

## Provenance

- Historical producer tool SHA-256:
  `e879faad9dbda8297bd99f0b2832881000b209d9c7ec624417cf79d8763ff6d9`.
- Historical producer focused-test SHA-256 (suffix test):
  `0460cc36b83fede10ddc1c7b028d84b793e273625b2988e8578af9982bb20a4f`.
- Historical producer manifest SHA-256 before repair:
  `ccfdce39f17d57ee535ce8406df3b562d1adb669159d9e120f0ac2153b9ebc49`.
- Current verifier tool SHA-256:
  `dfbedee9bd4b96bc523e413c0a651a14c6f6bc33e7d56aac231a85263f26c2ba`.
- Current verifier focused-test SHA-256:
  `1f0858d6d6166bc9f1872e06d6562e8d4425ef4389e3db7d08d3783b18bf0aa1`.
- Repaired public manifest SHA-256: `05ed171f960ea909f71eeea2127e9f26e016e510b4d39dbb390758d3c09b8955`.
- Focused result: 26 tests pass. Full repository discovery is not rerun here.
- The publisher requests mode `0644` for fresh output; its historical producer
  hash remains recorded separately rather than silently repinned.
- Date: 2026-08-26 KST.
- Mode: `HOST_ONLY_READ_ONLY`; device, SMC and MMIO access: none.
- Produced on branch `research/xbl-config-cdt` in a separate worktree.
  `STATUS.md`, `docs/EXPERIMENT_MATRIX.md` and `docs/RESEARCH_LOG.md` are
  deliberately untouched here and are reconciled at integration.
