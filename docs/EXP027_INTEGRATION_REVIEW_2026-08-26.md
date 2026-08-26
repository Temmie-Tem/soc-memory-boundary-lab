# Experiment 027 integration review — 2026-08-26

## Scope

This review integrates committed host-only Experiment 027 from commit
`7aa1df7` into the common research documents. It is a bounded, fail-closed
CFG/dataflow transform over the exact Experiment 020 register-offset and
computed-address site sets, using the exact XBL, `xbl_config--sdb2.bin`, and
semantically pinned public dependency manifests. It performs no device, USB,
SMC, MMIO, protected-memory, normal-RAM, boot, activation, or write action.
Class C remains `TRANSFORM ONLY`; Experiments 015/016 remain `NOT ELIGIBLE`.

The public artifact is
`evidence/manifests/027-dcb-consumer-writer-complement-20260826-01.manifest.json`,
size 334,847 bytes, mode `0644`, SHA-256
`d11785969f16ba09155a2305eefd091158abfc515bc64cf94cb34d573a302277`.
No private firmware bytes or absolute paths are added to the public
integration.

## Artifact pins

| Artifact | SHA-256 |
|---|---|
| `tools/sm8150_dcb_consumer_writer_complement.py` | `11a4dab37e9a54e74ec93fba7c89524de1e77c7e71b86f105dd167d77780bcb9` |
| `tests/test_sm8150_dcb_consumer_writer_complement.py` | `683da291f4421b3af0c75be21093b2cad3bbb3bf4933e4f2a70910cde4aa1cda` |
| `experiments/027-dcb-consumer-writer-complement/README.md` | `dd722225be2bcc5faf4e0cd08b60b5385d6a9fb9249e5e54d1c2ee6d128cefd0` |
| `evidence/manifests/027-dcb-consumer-writer-complement-20260826-01.manifest.json` | `d11785969f16ba09155a2305eefd091158abfc515bc64cf94cb34d573a302277` |

The exact XBL input is 4,194,304 bytes with SHA-256
`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.
`xbl_config--sdb2.bin` is 4,149,248 bytes with SHA-256
`0e9dfac1ddd0f9acc2cc899213e621490308f0cadf329814048edb7712e2484c`.
The public dependency pins are Experiment 019 manifest
`232eb0375fadf96db1fd303d83d707cf47cb668a24129d7e4791b193fb3fc70c`,
020 manifest `31e8dd6791f07d007447600969326a86466f20a0cb263a58885c1489bd284c9a`,
021 manifest `d85999e644bae1f5bafe683b44b253450d04d1b666c73659d9284c010d32b44a`,
024 manifest `f9ac896d396650075ca9e66d8d805a2deaf40b0207e819cd94f8d638c8121b01`,
025 manifest `d3c405d7c8d23dc1cd65b1c578b4b4ce931d9bdfeb303c892e9c0c145c4c81cc`,
and 026 manifest
`2139b5d230be78d822eda656f2856a229894167938227d34a614dcabf16c7885`.

## Validation

- Focused Experiment 027 unittest suite: **35 PASS**.
- Full repository unittest discovery: **616 PASS** in **86.100 s**.
- Python byte-compilation of the tool and focused test: **PASS**.
- Public JSON safety parse: **PASS** for all 67 public manifests.
- Two fresh Experiment 027 generations: **byte-identical**.
- Public publication safety, no-clobber, and manifest mode `0644`: **PASS**.
- Independent hostile review after fixes: **PASS**.

## Integrated bounded result

`PROVED`: the exact XBL and `xbl_config` inputs are bound before analysis;
Experiment 019 DCB section identities `{6, 7, 8, 10, 11, 12}` and section-7
keys `0x00000400` and `0x00000404`, each with value `0x10000000`, are
revalidated across all four DCB blocks. The blocks are `0x3404` bytes at file
offsets `0x1079c`, `0x13ba0`, `0x16fa4`, and `0x1a3a8`.
The exact-hash-pinned Experiment 020 dependency records XBL loader window
`[0x1489f9e8,0x1489fbe8)` and section-directory reader starts
`0x1485f0f8`, `0x1485f13c`, `0x1485f17c`, `0x1485f1c0`, `0x1485f200`, and
`0x1485f23c`; these are inherited dependency facts, not newly re-derived by
Experiment 027. Section 5's absolute-address table remains a negative control
and is not promoted as a DCB writer target.

`PROVED`: Experiment 020 supplies exactly 67 register-offset loop records and
eight computed-address idioms. The bounded result analyzes all eight computed
idioms, three as complete loop contexts and five as local forms. Two
dependency-owned register sites are excluded, leaving 65 register sites plus
8 computed sites, 73 analyzed sites total. Experiment 024's resolved walker
`[0x148689a0,0x14868a64)` and the overlapping Experiment 020 false-negative
range `[0x148689c8,0x14868a60)` remain excluded positive controls; its
caller-context ranges `[0x14868630,0x14868644)`, `[0x14868668,0x14868680)`,
and `[0x14868684,0x1486869c)` are excluded as well. All Experiment 025/026
claimed ranges remain dependency-only. The candidate setter is
`[0x9fc06410,0x9fc0643c)` (44 bytes, range
SHA-256 `4f90392f2e5c34415ad0bb4709227445f3cad1d2444b57a90fa645f1488e063a`)
with direct caller `0x9fc023f0` in `[0x9fc023e0,0x9fc02430)`; its runtime
object-field arguments and current destination remain `UNKNOWN`.

The exact bounded census is:

| Result label | Count |
|---|---:|
| `INDIRECT_OR_UNSUPPORTED` | 71 |
| `NO_TARGET_WITHIN_MODEL` | 2 |
| `DCB_CONSUMER_PATH` | 0 |
| `MC_OR_SHRM_SYMBOLIC_TARGET` | 0 |

The 71 fail-closed sites include unsupported, indirect, or unrecognized local
forms. The two `NO_TARGET_WITHIN_MODEL` results do not promote a controller or
SHRM destination. All `BASE+offset` observations retain
`current_destination: UNKNOWN`. The result is bounded to the implemented
model and does not claim global DCB consumer or writer absence; writer/global
consumer identity, runtime base, execution/order, register semantics,
computed aliases, indirect targets, and post-boot mutation remain `UNKNOWN`.

Two nonexclusive proximity leads are hypothesis-only
`SECTION_READER_PROXIMITY_ONLY` observations: `0x148aa758` is 2,528 bytes
before reader `0x148ab138` (signed distance `-2528`, absolute distance
`2528`), and `0x148ab4f8` is 960 bytes after the same reader (signed distance
`960`, absolute distance `960`). Both use threshold `0x1000` and
`link_proof: NONE`; neither is a DCB pointer, runtime alias, consumer, or
writer identity.

## Independent hostile review

The independent hostile review returned **PASS** after the committed fixes.
The final boundary keeps section-reader proximity separate from dataflow,
does not promote checksum/bounds-reader candidates as controller writers,
fails closed on unsupported aliases/control or memory forms, and preserves
dependency-owned ranges without re-claiming them. No decoder-extension safety, runtime
reachability, current destination, or writer absence is promoted by this
integration.

## Final disposition

`PASS`: Experiment 027 is integrated as a completed host-only bounded result.
Its 73-site census is evidence about the implemented model only; the zero
`DCB_CONSUMER_PATH` and zero `MC_OR_SHRM_SYMBOLIC_TARGET` labels are not global
absence claims. The next non-overlapping host-only selection is Experiment
029, scored `76/100`: an exact unsupported-frontier inventory over the 71
fail-closed site ranges, with independent unique-VA versus per-site
multiplicity accounting, exact unrecognized-instruction-form classification,
and source-backed ranking of decoder-extension candidates for later semantic
review. Its Stage 1
inventory must not upgrade Experiment 027 or claim decoder safety; only a later
separately reviewed stage may extend an independently reviewed form. It uses the
labels `DECODER_EXTENSION_CANDIDATE`, `FLAG_ONLY_NO_GPR_DEF`,
`TAINT_KILL_REQUIRED`, `CONTROL_OR_MEMORY_UNSUPPORTED`, and
`UNREACHABLE_OR_OVERLAP_UNKNOWN`; unsupported/control/alias `UNKNOWN` remains
preserved, with no device, MMIO, or write action.

Experiment 028 is concurrent work outside this integration (GF(2) row-space
and decoded SHRM register/index-encoding hypotheses). No Experiment 028 result,
score, authority, or review is claimed here.
