# Experiment 031 — bounded DCB scalar-frontier extension

## Question and authority boundary

Can a narrowly qualified, host-only v2 pass reduce the exact 71
`INDIRECT_OR_UNSUPPORTED` sites retained by Experiment 027, using the
highest-value non-control scalar forms inventoried by Experiment 029?

This is a deterministic transform only for the exact A90 5G / SM-A908N /
SM8150 XBL input (`xbl--sdb1.bin`, 4,194,304 bytes,
SHA-256 `e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37`).
It performs no device, USB, SMC, MMIO, protected-memory, boot, activation, or
write action. It never claims global DCB consumer/writer presence or absence;
`current_destination` and `writer_absence` remain `UNKNOWN`.

## Exact dependencies

Both frozen source tools and both public manifests are size- and SHA-256-
checked before the 027 source is imported, followed by semantic validation.
The 029 manifest supplies the exact range membership and frontier classes; no
new site is inferred.

| Input | Size | SHA-256 |
|---|---:|---|
| Frozen 027 tool | 86,782 | `11a4dab37e9a54e74ec93fba7c89524de1e77c7e71b86f105dd167d77780bcb9` |
| Frozen 027 manifest | 334,847 | `d11785969f16ba09155a2305eefd091158abfc515bc64cf94cb34d573a302277` |
| Frozen 029 tool | 43,950 | `e5c491deaddafd4c60de7df3bfe0531f38bbd3740fe668942b912466ee86bca0` |
| Frozen 029 manifest | 628,525 | `c6d46c382d7c091fffad137adb9491d107ff823ad6c6221f51eb627cc218f634` |

## Qualified scalar subset

The v2 pass consumes only source-qualified forms:

- flag-only forms: `ADDS/SUBS` aliases with `Rd=31`, `ANDS/TST`, and
  `CCMP/CCMN`; they write NZCV only and do not define a GPR. Direct
  conditional-control paths are split conservatively.
- `BITFIELD_IMM`: valid `SBFM`, `BFM`, and `UBFM`, including exact
  `DecodeBitMasks`, W/X width checks, `N/sf`, `opc`, `immr`, and `imms`
  validation. `Rd=31` is a discarded ZR destination; `Rn=31` is ZR for these
  scalar forms.
- `AND_SHIFT`: valid AND shifted-register forms, including LSL/LSR/ASR/ROR
  and W/X immediate-width limits. BIC/EOR/other logical families remain
  fail-closed.
- `TAINT_KILL_REQUIRED`: destination-local conservative kills for the 029
  scalar families (`ADDS/SUBS`, variable shifts, divide, conditional select,
  and the SP-destination immediate form). An unknown result kills only its
  destination; it does not erase unrelated origins. W writes do not preserve
  X-width address/DCB origins.

Pair/sign-extending memory, system/control, three-source, BIC/EOR, indirect
aliases, reserved/unknown encodings, and every unsafe or unvalidated form
remain fail-closed. No unsupported semantics are converted into an absence
claim.

The pass also contains a separately bounded `DIRECT_CONTROL_DISPATCH_REPAIR`.
Frozen 027 recognizes direct branches for CFG purposes but then falls through
to its scalar/memory fallback, producing a false unsupported result. The v2
repair stops that fallback for direct `B`, `B.cond`, `CBZ/CBNZ`, and
`TBZ/TBNZ`, while retaining conservative path splitting. It is not part of
the 029 scalar admission set and grants no runtime branch-target authority.

## Architecture provenance

Encoding masks and scalar pseudocode are pinned to Arm's official primary
source, `Arm A64 Instruction Set for A-profile architecture`, `DDI0602
(ID092025)`, version 2025-09:

`https://developer.arm.com/documentation/ddi0602/2025-09/`

The downloaded source identity recorded in the public manifest is
`ISA_A64_xml_A_profile-2025-09_ASL0.pdf`, 25,622,354 bytes,
SHA-256 `683025f0460c8af8d6711b764c5c4d51d1b56f38d78b618e6cb27d9abf4c853f`.
Relevant primary-source pages are AND shifted register 33, ADDS/SUBS
extended/immediate/shifted 25/827, 27/829, 28–29/830–831, ANDS immediate/
shifted 34–35, CCMN 113–114, CCMP 116–117, BFM 59, SBFM 647, UBFM 868,
`DecodeBitMasks` 4519–4520, CSEL/CSINC 325/331,
ASRV/LSLV/LSRV/RORV 39/535/538/640, and SDIV/UDIV 650/872. If this source
identity is unavailable, the implementation must leave the form `UNKNOWN`
and fail closed. The separate direct-control dispatch repair is pinned to B
54, B.cond 55, CBNZ 111, CBZ 112, TBNZ 849, and TBZ 850.

## Exact accounting and result

The 029 frontier contains 352 occurrences. The selected scalar membership
domain is exactly **283 occurrences / 160 unique VAs / 148 unique raw words**
across all 71 sites. The preserved residual syntactic frontier is exactly
**69 occurrences / 59 unique VAs / 49 unique raw words** across 20 sites:

| Preserved family | Occurrences |
|---|---:|
| `PAIR_MEMORY` | 48 |
| `THREE_SOURCE_UNVALIDATED` | 11 |
| `SYSTEM_CONTROL` | 4 |
| `BIC_SHIFT` | 2 |
| `EOR_SHIFT` | 2 |
| `SIGN_EXTENDING_MEMORY` | 2 |

The 51/71 value is published as `all_range_forms_selected`: syntactic range
membership only, neither CFG reachability nor a closure prediction. The
actual bounded CFG/dataflow transition is reported separately. On the exact
XBL input, the combined scalar-plus-dispatch v2 model transitions 51 sites
from the 027 fail-closed label to bounded
`NO_TARGET_WITHIN_MODEL` within the v2 model; 20 remain
`INDIRECT_OR_UNSUPPORTED`. This is explicitly `V2_MODEL_ONLY` and
`NO_ABSENCE_CLAIM`. No
`DCB_CONSUMER_PATH` or `MC_OR_SHRM_SYMBOLIC_TARGET` path is promoted.

The direct-control repair contributes exactly 143 unique events across 62
sites: `B.cond` 87, `CBZ/CBNZ` 28, `B` 15, and `TBZ/TBNZ` 13. Sites with the
repair split 48 no-target / 14 fail-closed; sites without it split 3 no-target
/ 6 fail-closed. Thus the 51-site result is explicitly a combined
scalar-plus-dispatch result, not a scalar-only closure claim.

The manifest also publishes unique reached extension events keyed by
`(site_index, va, raw_word, family, effect)`, exact reached blocker events,
per-site 027→031 transitions, CFG completion/state counts, exact 029
admission (`250` reached selected events, `283` selected occurrences,
`33` selected-not-reached, zero outside/mismatch), and the exact residual form
rows. Range membership is never presented as reachability.

As an independent verification outside the checked manifest, an
`qemu-aarch64` oracle exercised four seeds for each of the 56 unique
`BITFIELD_IMM` VAs and 14 unique `AND_SHIFT` VAs: **280/280** evaluator results
matched. The oracle JSON (`oracle-results.json`) was SHA-256
`ebdac16f2a30356dba93aa7746e71e443fc880d61d9d5c2429a93ed59d35f166`; its
raw `results.bin` (2,240 bytes) was SHA-256
`4eb4b9fe06d73c3015fa1ee391e299b1ce5498992f1bf470259761d0cad15709`. These
temporary oracle artifacts are not Experiment 031 inputs or authority
sources.

## Reproduce and validate

```sh
python3 tools/sm8150_dcb_consumer_writer_extension.py \
  --firmware-dir evidence/private/004-live-firmware-readonly-20260825-01 \
  --manifest-dir evidence/manifests \
  --output /tmp/exp031-manifest.json

python3 -m unittest -v tests.test_sm8150_dcb_consumer_writer_extension
python3 -m py_compile tools/sm8150_dcb_consumer_writer_extension.py
```

Two fresh generations are byte-identical. Publication uses `O_EXCL`,
`O_NOFOLLOW` where available, refuses clobbering, and sets mode `0644`.
The public manifest is deterministic JSON and contains no private path,
firmware bytes, or `xbl_config` artifact.

## Final artifacts

| Artifact | Size | SHA-256 |
|---|---:|---|
| Experiment 031 tool | 91,221 | `5263d8975e9d64809aed04763e0c5573458dabcc6ae7432763d2858a36fc267b` |
| Focused tests | 18,751 | `3a81fb4b4fc3023e70918a1648b6f04bb50e0967d27a8f09dbf939f9b55eff6d` |
| Checked public manifest | 1,327,118 | `51a187195c16eb609d337305540fc6d20a09297f5ab76b054497c5c58c3a2e86` |
