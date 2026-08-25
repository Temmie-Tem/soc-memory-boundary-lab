# Experiment 020 — XBL DCB consumers and DDR controller bases

## Question

Experiment 018 resolved candidate controller stores through four static models —
direct constant definition, a wide-move extension, a unique-caller retained
table, and a conditional callee-preservation model — and every one returned no
target match. Experiment 019 then showed the boot chain programs registers from
base-relative DCB data rather than from code-resident absolute addresses.

That raises a question about the negative itself. Is Experiment 018 evidence
that no controller writer exists, or is its search shaped so that a writer of
this kind could not appear in it?

## Scope and eligibility

Host-only, read-only static evidence over the exact Experiment-004
`xbl--sdb1.bin`. No device, SMC, MMIO, normal-RAM, protected-memory or
runtime-register access. Conceptual Experiments 015 and 016 remain reserved and
`NOT ELIGIBLE`; this experiment satisfies neither gate.

The ELF walk and every decoder here are written independently of the other
`tools/` modules, for the reason Verification 001 records.

## Result

`PROVED`: the exact XBL contains **719** register-offset stores in executable
segments (RX 453, RWE 266), of which **488** are unscaled and **67** sit inside
a short backward-branch loop.

Experiment 018 Stage 1A states its own census as *"strict scalar AArch64 STR W/X
**unsigned-immediate** recognition"*. A table walker writes through
`STR Wt,[Xn,Xm]`, because its offset is a value loaded from the table at
runtime and cannot be an immediate. That class is therefore outside Stage 1A's
census by construction, and every later stage inherits its candidate list.

`PROVED`: the DDR driver occupies the largest RWE segment, VA `0x9fc00000`,
file offset `0x86fd0`, 2,359,296 bytes. It contains **zero** file-backed 64-bit
values inside the SoC control aperture `0x09000000..0x0a000000`, and **zero**
equal to a ranked MC base.

`PROVED`: the driver's controller base pointers are written by a five-store
setter at `[0x9fc06410,0x9fc0643c)`:

```text
0x9fc06424  STR XZR,[X8,#0x368]   -> 0x9fc38368 = 0
0x9fc06428  STR X0, [X7,#0x360]   -> 0x9fc38360 = argument 0
0x9fc0642c  STR X1, [X6,#0x370]   -> 0x9fc38370 = argument 1
0x9fc06430  STR X2, [X5,#0x378]   -> 0x9fc38378 = argument 2
0x9fc06434  STR W3, [X4,#0x350]   -> 0x9fc38350 = argument 3
```

Every non-zero store takes its value from an incoming argument register. The
setter has exactly one direct `BL` caller, at `0x9fc023f0`, which loads those
arguments from a struct reached through `X0`. Across the whole image, 550
stores into the driver's globals come from a register and 59 write `XZR`.

`REFUTED`: Experiment 018's negative result is evidence that no controller
writer exists. All four of its models terminate in a constant, and the base
values are not constants in this image, so a null result was structurally
guaranteed for those models regardless of whether a writer exists.

`UNKNOWN`: the runtime origin of the base arguments, and therefore the absolute
address any DDR-driver store reaches; which register-offset store, if any,
consumes a DCB table; the implicit base of DCB sections 10, 11 and 12; register
semantics; the relation to the Experiment 014 GF(2) bank relation; post-boot
writability; alias; boundary bypass.

Current classification is unchanged:

```text
CLASS C (TRANSFORM ONLY)
NO_BOUNDARY_BYPASS_OBSERVED
```

## Does any of those stores walk a table?

Counting the class Stage 1A cannot see is only useful if one of its members is
a DCB consumer. A walker reads its store offset out of the table, so the offset
must change on every pass. That is decidable from the last definition of the
offset register inside the loop body, where the body runs from the loop head to
the back edge — a definition placed after the store still applies on the next
pass, and cutting the body at the store misclassifies those.

Two shapes imitate a walker and are excluded on principle rather than by
inspection. A loop-invariant `LDR Xd,[Xn,#imm]` whose base is never modified in
the body loads the same displacement each iteration; that is an array write.
And a body containing `RET` is a function epilogue restoring callee-saved
registers from `SP`, which a backward conditional branch on a return path can
make look like a loop.

Of the 67 looping candidates:

| Offset register definition | Count |
|---|---:|
| induction variable or computed | 37 |
| defined outside the loop | 12 |
| function epilogue, not a loop | 12 |
| loaded, but loop-invariant | 6 |
| **loaded through an advancing pointer** | **0** |

`PROVED`: no register-offset store in the exact XBL walks a key/value table
under this model. Every real loop takes its offset from an induction variable
or from a value that cannot change between passes.

That is a bounded claim. The loop test accepts a backward branch within 24
instructions whose target lies within 64 instructions before the store, so a
walker with a longer back edge, an indirect branch, or a test-before-store
shape falls outside it. A walker would also be missed if a DCB key were a word
index rather than a byte offset, since the scaled store form is excluded — the
keys decoded in Experiment 019 are byte offsets, but not every section was
decoded.

Read with the section-consumer result below, the more economical reading is
that the exact XBL does not consume the DCB base-relative tables at all. The
consumers it does contain compute a checksum and check bounds. `UNKNOWN`:
whether the consumer lives in another image. `aop--sdd7.bin` is not an ELF and
targets a different core, so nothing here covers it.

## The DCB loader, re-derived from code

`tools/xbl_dcb_inventory.py` carries `LOADER_CONSUMED_SECTIONS` as a hardcoded
constant restating a prior finding; nothing in the repository checked it against
the instruction stream. This experiment locates the loader independently, by
the cluster of size constants only it carries, and re-derives the list.

The window is `0x1489f9e8..0x1489fbe8`, holding `0x3404`, `0x77c`, `0x3dc` and
`0x108`. Its structure per section is a directory read followed by a bounded
copy:

```text
0x1489faac  LDRH W9,[X13,#0xc]      section 0 data_offset
0x1489fab0  LDRH W3,[X13,#0xe]      section 0 size
0x1489fab4  ADD  X0,X14,#0x2b0      destination xbl_context+0x2b0
0x1489fabc  BL   0x1483ab24         bounded copy, limit W1 = 0x77c
```

The sections derived this way are `{0, 1, 2, 15, 16}`, which **matches** the
recorded constant exactly. `PROVED`: the recorded loader-consumption value is
correct. This is an independent check of a load-bearing repository constant, not
a new claim about it.

## Other DCB consumers

Every DCB consumer must read a directory slot as a pair of `LDRH` at
`0x0c + index*4` and `+2` from one base register. Scanning for that pair finds a
contiguous run in `xbl--sdb1.bin` at `0x1485f0f8`, `0x1485f13c`, `0x1485f17c`,
`0x1485f1c0`, `0x1485f200` and `0x1485f23c` — sections 5 through 10 in six code
blocks of equal size, reached by a `BR` jump table at `0x1485f0dc`.

Each block calls the same routine at `0x148312b0` and accumulates its result in
`W0`. That shape is a per-section checksum accumulation over the DCB, not a
register programmer. A second section-10 reader at `0x148ab138` compares a value
against the section's offset and size and branches to an error path; it is a
bounds check, also not a programmer.

`UNKNOWN`: no DCB consumer that programs controller registers was identified.
Isolated matches for sections 7, 10, 11 and 12 in `tz--sdd5.bin` and
`hyp--sdd33.bin` are recorded but not promoted: those directory offsets are
common structure offsets, and unlike the XBL run there is no consecutive-index
pattern to separate them from coincidence.

## Why this reframes the search

Three independent facts now line up. The DCB encodes programming data as
base-relative offsets (Experiment 019). A consumer of such data must write
through a register offset, which Stage 1A does not count. And the DDR driver's
bases are runtime arguments held in zero-initialised globals, so they are absent
from the image as constants.

Taken together these do not show that a writer exists. They show that the
Experiment 018 search could not have found one, which is a different statement
and a weaker premise than the accumulated-negative reading the earlier
experiments support. The ranked-candidate negatives from Experiments 014, 017
and 019 are unaffected; what changes is how much additional weight Experiment
018 adds to them, and the answer is less than it appeared.

## Limits

The loop test accepts any backward branch within 24 instructions whose target
lies within 64 instructions before the store. It is a shape filter, not a proof
of iteration, and it neither confirms that any of the 67 sites walks a DCB
table nor excludes a walker outside that window. The setter is pinned by
address after reading its disassembly rather than discovered by a rule, so it
is exact for this image and carries no claim of being the only such setter. The
`0x9fc00000` segment is identified as the DDR driver by size and content, which
is an inference, not a symbol.

## Evidence

- `evidence/manifests/020-xbl-dcb-consumer-xref-20260826-01.manifest.json`

The manifest contains hashes, addresses, counts and classifications only. It
contains no raw firmware bytes and no private paths.

## Reproduce

```sh
python3 tools/sm8150_xbl_dcb_consumer_xref.py \
  --output evidence/manifests/020-xbl-dcb-consumer-xref-20260826-01.manifest.json
python3 -m unittest -v tests.test_sm8150_xbl_dcb_consumer_xref
```

## Provenance

- Tool SHA-256:
  `e1f8e3ae31c583adaaf50a01ad07c7718f3646d8fc6dcb14ba19ff711539b8f0`.
- Focused-test SHA-256:
  `0ac445046bfd26c0045df11dffd419424e44159f8ee6e0557d9ea01e1fd999ea`.
- Public manifest SHA-256:
  `1b5697ff8a56f3c90146793af10fb7c3ca97d59303da76c60af9e19f50884a66`.
- Focused result: 46 tests pass.
- Regeneration is byte-identical; manifest mode is `0644`.
- Date: 2026-08-26 KST.
- Mode: `HOST_ONLY_READ_ONLY`; device, SMC and MMIO access: none.
- Produced on branch `research/xbl-config-cdt` in a separate worktree,
  concurrently with Experiment 018 Stage 2D on `main`. `STATUS.md`,
  `docs/EXPERIMENT_MATRIX.md` and `docs/RESEARCH_LOG.md` are deliberately
  untouched here and are reconciled at integration.
