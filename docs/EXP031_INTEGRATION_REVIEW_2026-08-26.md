# Experiment 031 integration review — 2026-08-26

## Scope and authority boundary

This review integrates the committed host-only Experiment 031 artifact from
commit `cd9f26e` plus reconciliation repair commit `12a8ebe`. It extends the
exact Experiment 029 frontier only with source-qualified scalar semantics and
a separately counted direct-control CFG repair. It performs no device, USB,
SMC, MMIO, normal-RAM, protected-memory, boot, activation, or write action.
`current_destination` and `writer_absence` remain `UNKNOWN`; Class C remains
`TRANSFORM ONLY`, and Experiments 015/016 remain `NOT ELIGIBLE`.

The exact XBL input is `xbl--sdb1.bin`, 4,194,304 bytes, SHA-256
`e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`.
Experiment 031 analyzes the same 71 Experiment 027 fail-closed site
identities inherited through the pinned Experiment 029 manifest. Range
membership is not CFG reachability, execution, or a current destination.

## Artifact and dependency pins

| Artifact | Size | SHA-256 |
|---|---:|---|
| `tools/sm8150_dcb_consumer_writer_extension.py` | 91,221 | `5263d8975e9d64809aed04763e0c5573458dabcc6ae7432763d2858a36fc267b` |
| `tests/test_sm8150_dcb_consumer_writer_extension.py` | 18,751 | `3a81fb4b4fc3023e70918a1648b6f04bb50e0967d27a8f09dbf939f9b55eff6d` |
| `experiments/031-dcb-scalar-frontier-extension/README.md` | 7,580 | `12924ad1fcfeba580f57447e67f74d14743a5962046941ff3088e1b130d173de` |
| Checked public manifest | 1,327,118 | `51a187195c16eb609d337305540fc6d20a09297f5ab76b054497c5c58c3a2e86` |

The public manifest is
`evidence/manifests/031-dcb-scalar-frontier-extension-20260826-01.manifest.json`,
mode `0644`. It contains no firmware bytes, private path, device identifier,
runtime value, or secret. The exact 027 and 029 dependency pins are retained:

| Dependency | Size | SHA-256 |
|---|---:|---|
| Frozen 027 tool | 86,782 | `11a4dab37e9a54e74ec93fba7c89524de1e77c7e71b86f105dd167d77780bcb9` |
| Frozen 027 manifest | 334,847 | `d11785969f16ba09155a2305eefd091158abfc515bc64cf94cb34d573a302277` |
| Frozen 029 tool | 43,950 | `e5c491deaddafd4c60de7df3bfe0531f38bbd3740fe668942b912466ee86bca0` |
| Frozen 029 manifest | 628,525 | `c6d46c382d7c091fffad137adb9491d107ff823ad6c6221f51eb627cc218f634` |

## Source qualification and bounded model

`PROVED`: instruction masks and scalar operations are qualified against Arm's
primary `Arm A64 Instruction Set for A-profile architecture`, `DDI0602
(ID092025)`, version 2025-09, at
<https://developer.arm.com/documentation/ddi0602/2025-09/>. The downloaded
source is `ISA_A64_xml_A_profile-2025-09_ASL0.pdf`, 25,622,354 bytes, SHA-256
`683025f0460c8af8d6711b764c5c4d51d1b56f38d78b618e6cb27d9abf4c853f`. If the
source identity or an encoding check is unavailable, the form remains
`UNKNOWN` and fail-closed.

The admitted 029 families are flag-only `ADDS/SUBS` aliases, `ANDS/TST`,
`CCMP/CCMN`; valid `SBFM/BFM/UBFM` (`BITFIELD_IMM`); valid shifted-register
`AND` (`AND_SHIFT`); and destination-local conservative kills for arithmetic,
variable shifts, divide, conditional select, and the SP-destination immediate
form (`TAINT_KILL_REQUIRED`). Pair/sign-extending memory, system/control,
three-source, `BIC`/`EOR`, indirect aliases, reserved/unknown encodings, and
all unsafe forms remain fail-closed. W writes do not preserve X-width address
or DCB origins.

`PROVED`: `DIRECT_CONTROL_DISPATCH_REPAIR` separately models direct `B`,
`B.cond`, `CBZ/CBNZ`, and `TBZ/TBNZ` with conservative path splitting. It
corrects the 027 fallback after direct-branch recognition, but grants no
runtime branch-target, execution-order, authority, or absence claim.

## Exact accounting and result

`PROVED`: the 029 frontier contains 352 occurrences. The selected scalar
membership domain is **283 occurrences / 160 unique VAs / 148 unique raw
words** across all 71 sites; 33 selected occurrences are not reached by the
bounded CFG model. The preserved residual syntactic frontier is **69
occurrences / 59 unique VAs / 49 unique raw words** across 20 sites:

| Preserved family | Occurrences |
|---|---:|
| `PAIR_MEMORY` | 48 |
| `THREE_SOURCE_UNVALIDATED` | 11 |
| `SYSTEM_CONTROL` | 4 |
| `BIC_SHIFT` | 2 |
| `EOR_SHIFT` | 2 |
| `SIGN_EXTENDING_MEMORY` | 2 |

`PROVED`: the combined scalar-plus-dispatch v2 model transitions **51** of
the 71 baseline fail-closed sites to bounded `NO_TARGET_WITHIN_MODEL`; 20
remain `INDIRECT_OR_UNSUPPORTED`. This is explicitly `V2_MODEL_ONLY` and
`NO_ABSENCE_CLAIM`, not a scalar-only result. It promotes no
`DCB_CONSUMER_PATH` or `MC_OR_SHRM_SYMBOLIC_TARGET`.

The direct-control repair contributes **143 events across 62 sites**:
`B.cond` 87, `CBZ/CBNZ` 28, `B` 15, and `TBZ/TBNZ` 13. Sites with the repair
split 48 no-target / 14 fail-closed; sites without it split 3 no-target / 6
fail-closed. The manifest records 250 reached selected events, 33 selected-
not-reached occurrences, zero family/label mismatches, zero events outside the
selected domain, exact blocker events, and per-site 027→031 transitions. These
accounting identities are syntactic/bounded-model observations only.

`UNKNOWN`: actual CFG reachability outside the bounded model, runtime
execution/order, current object/base values, destination physical address,
register programming semantics, post-boot writability, global DCB consumer or
writer identity, aliases, and security-boundary effect. No unsupported form is
converted into a writer/consumer absence claim.

## Validation and final disposition

- Focused suite: **19 PASS**.
- Tracked full repository suite: **652 PASS** in **85.226 s**, maximum RSS
  **220,684 KiB**, with no swap activity.
- Python byte-compilation: **PASS**.
- Public JSON parse: **PASS** for 69 public manifests.
- Two fresh manifests: byte-identical to each other and the checked manifest.
- Independent `qemu-aarch64` oracle: **280/280** evaluator results matched.
- Final hostile review: **PASS**.

`PASS`: Experiment 031 is integrated as a deterministic, bounded,
source-qualified v2 transform after the `12a8ebe` reconciliation repair. It
narrows the bounded 027 frontier but does not establish a live consumer,
writer, transform mutation, alias, protected reach, or bypass. The 51-site
result depends on the combined scalar and `DIRECT_CONTROL_DISPATCH_REPAIR`
model; it must never be described as scalar-only closure.

The next non-overlapping host-only selection is Experiment 032, scored
`82/100`: qualify an official source and apply bounded semantics to the exact
reached `MADD/UMADDL` plus `EOR/BIC` arithmetic frontier. Its target blockers
are 10 reached `THREE_SOURCE` events at sites 35/36/37/56, two `EOR` events at
sites 36/37, and two `BIC` events at sites 1/52. Site 35's indirect branch and
site 56's pair form remain fail-closed. This was chosen over pair-memory:
pair-memory has 41 events across 13 sites, but 38 are `LDP` and most of the
remainder are SP epilogues, while arithmetic directly forms indexes/addresses
in the high-value runtime-alias/hash-like contexts. Pair-memory remains a
later candidate. Experiment 032 is host-only and has no device authority.

External Claude Experiments 028 and 030 remain outside this integration and
unreviewed here. No result, score, authority, review, or commit from either is
integrated or claimed.
