# Experiment 027 — bounded DCB consumer/writer complement

## Question and safety boundary

Does a bounded, fail-closed CFG/dataflow pass over the exact Experiment 020
register-offset and computed-address site sets recover a DCB consumer or a
controller/SHRM symbolic target that the earlier target-first passes could not
see?

This is a host-only, read-only transform.  It reads the exact pinned XBL and
`xbl_config` ELF files and public dependency manifests only.  It performs no
device, USB, SMC, MMIO, protected-memory, boot, activation, or write action.
The manifest never claims global writer absence.  A symbolic `BASE+offset` is
always represented with `current_destination: UNKNOWN`.

## Exact inputs

| Input | Size | SHA-256 |
|---|---:|---|
| `xbl--sdb1.bin` | 4,194,304 | `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37` |
| `xbl_config--sdb2.bin` | 4,149,248 | `0e9dfac1ddd0f9acc2cc899213e621490308f0cadf329814048edb7712e2484c` |
| Experiment 019 manifest | 40,368 | `232eb0375fadf96db1fd303d83d707cf47cb668a24129d7e4791b193fb3fc70c` |
| Experiment 020 manifest | 23,446 | `31e8dd6791f07d007447600969326a86466f20a0cb263a58885c1489bd284c9a` |
| Experiment 021 manifest | 8,130 | `d85999e644bae1f5bafe683b44b253450d04d1b666c73659d9284c010d32b44a` |
| Experiment 024 manifest | 30,400 | `f9ac896d396650075ca9e66d8d805a2deaf40b0207e819cd94f8d638c8121b01` |
| Experiment 025 manifest | 28,132 | `d3c405d7c8d23dc1cd65b1c578b4b4ce931d9bdfeb303c892e9c0c145c4c81cc` |
| Experiment 026 manifest | 64,027 | `2139b5d230be78d822eda656f2856a229894167938227d34a614dcabf16c7885` |

The six dependencies are validated semantically as well as by size and
SHA-256.  In particular, 019's DCB sections `{6,7,8,10,11,12}` are re-parsed
and section 7's `(0x400, 0x10000000)` and `(0x404, 0x10000000)` pairs are
checked in all four blocks.  The four DCB PT_LOAD file offsets are pinned as
`0x1079c`, `0x13ba0`, `0x16fa4`, and `0x1a3a8`.

## Bounded model

Experiment 020 is the source of the exact site set: 67 register-offset loop
records and eight computed-address idioms (three of those are loop records).
The implementation never scans an arbitrary MMIO aperture or invents a site.
Its instruction subset is limited to:

- `MOVZ`, `MOVK`, `MOVN`, `ORR` copies and valid shifts, and exact logical
  masks;
- `UXTW`, `SXTW`, `UXTX`, and `SXTX` register extensions with exact scale;
- `LDR` taint, `ADD`/`SUB`, `ADRP`, `ADR`, and direct `BL` argument taint;
- unsigned/unscaled/indexed and register-offset loads/stores needed by those
  dependency sites.

The CFG is limited to each dependency-provided loop range.  Direct calls clear
the local taint map; `BLR`, `BR`, atomic/exclusive forms, unsupported aliases,
unmapped words, unresolved computed aliases, and a non-empty worklist at the
state limit fail closed.  Site results use
the following discriminators:

| Discriminator | Meaning |
|---|---|
| `DCB_CONSUMER_PATH` | DCB_DATA provenance from an actual DCB load reaches a usable STR source; runtime pointer/base/semantics remain unresolved. |
| `MC_OR_SHRM_SYMBOLIC_TARGET` | A controller/SHRM-like symbolic base-plus-offset is recognized; it is never a current destination. |
| `NO_TARGET_WITHIN_MODEL` | No target origin was resolved in this bounded model. |
| `INDIRECT_OR_UNSUPPORTED` | An indirect branch, unsupported/atomic form, or required unresolved alias blocked the local claim. |

`DCB_CONSUMER_PATH` is emit-capable only when `DCB_DATA` provenance from an
actual load through a proven DCB section/array address reaches the source of a
usable store; a direct store whose target is a DCB address is not by itself a
consumer.  Section-reader proximity never seeds that origin.  Any unsupported or
unrecognized path within a site invalidates that site's target label and emits
`INDIRECT_OR_UNSUPPORTED`.

The known Experiment 020 false-negative range
`[0x148689c8,0x14868a60)` and store `0x14868a50` are retained as a positive
control only.  Experiment 024 owns the resolved walker
`[0x148689a0,0x14868a64)` and its context, so no new walker semantics are
claimed here.  The three complete Experiment 024 caller-context windows
`[0x14868630,0x14868644)`, `[0x14868668,0x14868680)`, and
`[0x14868684,0x1486869c)` are also recorded as dependency exclusions.  Every
range claimed by Experiments 025 and 026 is excluded and kept dependency-only;
the overlapping 020 site at `0x148688d8` is accounted for but not re-claimed.

The candidate setter `[0x9fc06410,0x9fc0643c)` is independently range-hashed,
and its direct caller at `0x9fc023f0` is resolved only in the bounded caller
window `[0x9fc023e0,0x9fc02430)`.  The caller's runtime object fields remain
unknown.

## Exact result

The public manifest is `CLASS C (TRANSFORM ONLY)`.  It contains 73 analyzed
sites after the two dependency-owned register-site exclusions (65 of the 67
register-offset loop sites and all eight computed-address idioms), plus the
excluded positive-control record.  The exact bounded census is:

| Discriminator | Count |
|---|---:|
| `DCB_CONSUMER_PATH` | 0 |
| `MC_OR_SHRM_SYMBOLIC_TARGET` | 0 |
| `NO_TARGET_WITHIN_MODEL` | 2 |
| `INDIRECT_OR_UNSUPPORTED` | 71 |
| `SECTION_READER_PROXIMITY_ONLY` | 2 hypothesis-level proximity leads |

The prioritized sites are present and remain bounded:

- `0x1484b9a0`: indirect/unsupported because the bounded full-loop path
  reaches an unrecognized form;
- `0x146aea20`: indirect/unsupported for the same fail-closed reason; no
  site-specific SHRM promotion is applied;
- `0x9fc05ef4`: indirect/unsupported because the full loop context reaches an
  unsupported form and fails closed.

The implemented bounded pass produces zero `DCB_CONSUMER_PATH` and zero
`MC_OR_SHRM_SYMBOLIC_TARGET` labels.  This is a bounded result, not a global
absence claim.  The two proximity leads retain their exact reader VA, signed
and absolute distance, `0x1000` threshold, section, and `link_proof: NONE`.

These are static observations only.  Runtime execution, base currentness,
DCB alias identity, register semantics, post-boot mutation, indirect targets,
and any global DCB consumer/writer presence remain `UNKNOWN`.

## Reproduce and validate

```sh
python3 tools/sm8150_dcb_consumer_writer_complement.py \
  --firmware-dir evidence/private/004-live-firmware-readonly-20260825-01 \
  --manifest-dir evidence/manifests \
  --output /tmp/exp027-manifest.json

python3 -m unittest -v tests.test_sm8150_dcb_consumer_writer_complement
python3 -m py_compile tools/sm8150_dcb_consumer_writer_complement.py
```

Publication uses `O_EXCL`, `O_NOFOLLOW` where available, and mode `0644`; an
existing output is never clobbered.  Two fresh generations are byte-identical.
The checked-in public manifest contains no firmware bytes or private absolute
paths.

## Evidence and provenance

- `evidence/manifests/027-dcb-consumer-writer-complement-20260826-01.manifest.json`
- Mode: `HOST_ONLY_READ_ONLY`; device/USB/SMC/MMIO access: none
- Tool SHA-256: `11a4dab37e9a54e74ec93fba7c89524de1e77c7e71b86f105dd167d77780bcb9`
- Focused-test SHA-256: `683da291f4421b3af0c75be21093b2cad3bbb3bf4933e4f2a70910cde4aa1cda`
- Public manifest SHA-256: `d11785969f16ba09155a2305eefd091158abfc515bc64cf94cb34d573a302277`
