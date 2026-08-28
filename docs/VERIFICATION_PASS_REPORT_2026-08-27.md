# Verification pass report — 2026-08-27

Target `SM-A908N` / `SM8150`, build `A908NKSU5EWA3`, kernel 4.14.190 dated
2023-01-12. Independent adversarial verification pass.

Everything found in this pass was found by checking a sentence this project had
asserted without evidence behind it. Three of them were mine, and all three were
wrong in the direction that made the work look finished.

## State of play

| | |
|---|---|
| Closed | Verification 019's missing raw receipt — recovered as *original bytes*, not reconstructed, and reproduced with a second independent suspend |
| Closed | Reopen condition 2 measured rather than asserted; no non-secure heap reaches 512 MiB |
| Reopened | Route 1 (PA28 and above) — the physical base was published in the device tree the whole time |
| Proposed | One decidable test of the single untested condition the disclosed CVE record points at. **Not executed** |
| Unchanged | Access control. Every protection finding stands; nothing here is an aperture |

Not one of these came from new capability, a new tool, or new privilege.

## 1. Retention — the receipt that was never lost

Verification 019 was published with a manifest but no raw receipt, and the
integration audit labelled it `SUPPORTED_EXTERNAL_MANIFEST_ONLY`, correctly.

The cause was not the experiment.
`evidence/private/verification-019-…-01` was a **symbolic link into a scratch
worktree**; pruning the worktree dangled the link and the receipt left the
repository's view while the manifest stayed behind. The superseded V018
directory had the identical shape.

The target had not rebooted, so the file was still at its device path. Read
back unmodified and re-analysed, it regenerates the published manifest **byte
for byte** (`bf7c66c7…`). The manifest is pinned to its original bytes.

The experiment was then run again from scratch:

| Measure | Run 1 | Run 2 |
|---|---|---|
| Baseline mismatches (instrument gate) | 0 | 0 |
| Suspended | 25.090 s | 25.151 s |
| `suspend_stats/success` | 0 → 1 | 1 → 2 |
| `suspend_stats/fail` | 13, unchanged | 25, unchanged |
| Tags moved | 0 of 4,194,304 | 0 of 4,194,304 |
| Verdict | `MAP_INVARIANT` | `MAP_INVARIANT` |

Run 2 reached suspend on its *first* attempt with `fail` never advancing, so the
blocker diagnosis is not a one-off: `icnss` disabled plus the cable out is
sufficient. A third run with the cable attached is retained as a control —
twelve consecutive `EBUSY` attempts and `SUSPEND_NOT_REACHED` on a clean
baseline, an independent reproduction of the `usb_notify` blocker.

The analyzers already refused to *read* through a symlink (`O_NOFOLLOW`);
nothing refused to *retain* through one.
`tests/test_evidence_private_no_symlinks.py` closes that side, with a negative
control that rebuilds the exact dangling-link shape and requires the guard to
fire.

## 2. Measurement — two of my own numbers, refuted

Reopen condition 2 asks for a non-secure contiguous allocation of at least
512 MiB. Every other reopen condition had been tested directly; this one had
only been asserted. `docs/REMAINING_ROUTES_2026-08-27.md` claimed a prior
experiment tested each ION heap by allocation and found 256 MiB the largest, but
no retained manifest held such a survey.

Measured, with a descending ladder over every enumerated heap:

| Heap | Type | Ceiling | Bracket |
|---|---:|---:|---|
| `camera_preview` | 10 | **320 MiB** | 320 ✓ / 352 ✗ |
| `qsecom` | 4 | 32 MiB | 32 ✓ / 64 ✗ |
| `user_contig` | 4 | 16 MiB | 16 ✓ / 32 ✗ |

Seven further heaps were enumerated but never allocated from. `system` is
page-based and cannot supply a contiguous span by construction; the other six
are secure or remote-processor heaps where an allocation drives `hyp_assign`
and a VMID transition, a mandatory pause gate. Their capacity is `UNKNOWN`, not
zero. Allocation targets are named on the host so that decision stays auditable
off-device.

Two written claims fell at once, in opposite directions:

| Written claim | Status | Actual |
|---|---|---|
| Largest non-secure heap is 256 MiB | `REFUTED` | 320 MiB. 256 was only ever what V016, V018 and V019 *requested* |
| Measuring `f(PA28)` needs a 512 MiB span | `REFUTED` | A pair is `x` and `x + 2^28`, so the span must *exceed* `2^28`, not reach `2^29`. 512 MiB was the base-*independent* bound — the same aligned-versus-arbitrary distinction V017 turned on |

The instrument gate is monotonicity: a success above a failure is memory
pressure, not a ceiling, and the analyzer reports `INSTRUMENT_FAILED` rather
than reducing it to a number. A test drives a synthetic 512 MiB success through
the same reduction and requires the verdict to flip to `MET`, so the negative is
not hardcoded.

Reopen condition 2 is `NOT_MET` as measured.

## 3. Survey — outside the current line

Host-only plus read-only device-tree queries. No register written, no MMIO read,
no allocation made.

### The closest published analogue, and why it does not transfer

`CVE-2022-22063` is the nearest public instance of exactly what this project
hunts: a Qualcomm hardware remapper, mutable at runtime, reachable from the
non-secure OS. `APCS_BOOT_START_ADDR_NSEC` carries `REMAP_EN` and
`BOOT_128KB_EN`, remaps a window to a configurable base, and the window shifts
block by block — giving EL1 full read/write/execute into hypervisor memory.
Qualcomm's fix blocked the remapped *region* via stage 2 and left the
configuration register accessible.

It establishes the shape is real rather than hypothetical. It does not transfer
here. SM8150 has the analogous block — `apcs_glb`,
`qcom,sm8150-apcs-hmss-global` at `0x17c00000` — and one exposed syscon at
`+0x0c` that looked like a candidate. That offset is the SMP2P inter-processor
doorbell on SDM845, SC7180 and SM8150. Not a remapper. `REMAP_EN` and
`BOOT_128KB_EN` appear nowhere in the retained XBL.

What survives: no address inside `0x17c00000..0x17c01000` appears in the
retained 009, 010 or 1b manifests. That is not evidence of absent protection —
those inventories were never complete — but it is squarely the category the 1b
checkpoint named as open, *alternate or undiscovered apertures*.

### "Literature adds nothing" was wrong

That conclusion was reached against the allocation-size problem, where it holds,
then stated generally. Against mapping recovery there is a live and recent line,
now recorded in `docs/PRIOR_ART.md`:

| Work | What it adds |
|---|---|
| **Knock-Knock** (µASC 2025) | The same GF(2) formulation used here, but proves the relation between the bank matrix and an empirically built address matrix, and recovers the bank-mask basis in *polynomial* rather than exponential time; generalises to row mappings and recovers a row basis |
| **Sudoku** (2025) | Decomposes a mapping into channel, rank, bank-group and bank *components*, using refresh intervals and consecutive-access latency rather than one fused relation |
| **DRAM-MaUT** (CASES 2022) | The only ARM-native tool of the set: `DC CIVAC` eviction and `PMCCNTR` timing — the exact primitives available here |

This project's relation is rank 3 over PA13..PA27, bank-selection bits only.
All three attack what is recorded as `UNKNOWN` — complete DRAM coordinates —
and none requires new privilege.

### One found and deliberately not pursued

`CVE-2025-21479` lets the Adreno GPU reload its page tables from an
attacker-chosen physical address via `CP_SMMU_TABLE_UPDATE`, giving DMA that
never passes CPU translation or triggers a stage-2 fault. That defeats the
entire Samsung protection stack, because every layer assumes memory integrity is
enforced by watching the CPU. This build almost certainly predates the fix.

It is not used, for two reasons. It is a privilege-escalation result, and this
project has already judged higher-privilege success uninteresting. And it would
be an aperture to *memory*, not to the transform: the transform's control
registers are protected on the target side against every initiator equally, so
GPU DMA does not reach them.

## 4. Reopening — the base was in the device tree

After the two corrections above, one blocker stood on route 1: the physical base
of an allocation is unknown because `pagemap` is blind for dma-buf. That claim
also had no receipt.

```
/soc/qcom,ion/qcom,ion-heap@30
    reg           = 0x1e          (= heap_id 30, the measured camera_preview)
    memory-region = phandle 0x67a
                       |
/reserved-memory/camera_mem_region
    phandle       = 0x67a
    reg           = base 0xC2000000, size 0x14000000
    properties    = ion,recyclable | name | phandle | reg
    no-map        = absent        (kernel keeps its linear mapping)
    reusable      = absent        (fixed carveout, not CMA)
```

Three independent sources agree on the size: the device-tree `reg` field, the
measured allocation ceiling, and the kernel's own ION debugfs `peak allocated` —
all exactly 335,544,320 bytes.

Span `[0xC2000000, 0xD6000000)`. A pair differing in only bit 28 requires
`x ∈ [0xC2000000, 0xC6000000)`, a 64 MiB window. Across that whole window
`x mod 2^29` stays in `[0x02000000, 0x05FFFFFF]`, below `0x10000000`, so bit 28
of `x` is zero throughout and the addition carries nowhere:

| `x` | `x + 2^28` | XOR | in range |
|---|---|---|---|
| `0xC2000000` | `0xD2000000` | `0x10000000` | yes |
| `0xC3000000` | `0xD3000000` | `0x10000000` | yes |
| `0xC5FFF000` | `0xD5FFF000` | `0x10000000` | yes |

Every offset in 64 MiB of slack yields a clean single-bit-28 pair. There is no
boundary to locate and no phase to infer.

That is the third correction to the same route, and the pattern is worth naming:
**route 1 was never closed by the device — it was closed by three unverified
sentences.**

This does not change access control. It is a measurement capability, not an
aperture: it says where bits land, not who may write the transform.

## 5. Proposal — reading the defenses backwards

*Not executed. This section proposes and does not report.*

The XPU regions around the remapper are not uniform. The middle row does not
belong to its own neighbourhood:

| Region | Size | Read VMID | Write VMID |
|---|---:|---|---|
| `0x09240000..0x09245000` | 20 KiB | `0x40000000` | `0x40000000` |
| **`0x09248000..0x09249000`** | **4 KiB** | **`0x80000000`** | **`0x00000000`** |
| `0x09249000..0x0924c000` | 12 KiB | `0x40000000` | `0x40000000` |
| `0x0924e000..0x09250000` | 8 KiB | `0xf0000000` | `0xf0000000` |

Three things separate that page from its neighbours. Its **write VMID is
`0x00000000`** — not "TZ only" but *no VMID at all*, where both neighbours are
symmetric read/write to one VMID. Its reader is a different VMID again. And its
grant is non-standard: `standard_multi_vmid_permission_words` are both zero
while the permission comes from constructed client bytes `0x11, 0x08`. Identical
in both selector branches.

Broad policies look like floor plans — `MEMNOC_MS_MPU` covers
`0x00000000..0x10000000` wholesale. A single 4 KiB page carved out of a uniform
neighbourhood with a non-standard construction and zero writers looks like a
response.

The disclosed record names what. **`CVE-2020-11252`**, Qualcomm April 2021:
*improper access restrictions during trustzone initialization, as xPU get
disabled when memory dumps are enabled* — Snapdragon Mobile among the affected
families. That is P2 for the *entire* XPU regime, not one register: a
configuration-reachable off switch for the target-side protection this project
has run into on every route. Not an exploit — a setting.

And it has never been tested here. The watchdog bark at `0x09248080` was
recorded **2026-08-24, 20:46–21:40 UTC**; the debug-level transitions were
**2026-08-25, from 12:18 UTC**; the current cmdline is `debug_level=0x4f4c`,
LOW. Every remapper access this project has attempted was made with memory dumps
**disabled** — the state where the protection is expected to be on. The route-2
negative rests entirely on measurements taken in that one state.

The experiment is within precedent: Verification 006 performed `DLOW ↔ DMID`
four times, all `APPLIED_VERIFIED` / `RESTORED_VERIFIED`, with orderly MID
boots, and `param` is outside the forbidden bootloader-class set in
`docs/THREAT_MODEL.md`.

1. Confirm the current state is `DLOW`; re-establish the baseline bark.
2. Apply `DLOW → DMID`; reboot so the level takes effect.
3. Repeat the bounded read at `0x09248080`.
4. Restore `DMID → DLOW`; reboot; verify.

Both branches decide something:

- **The read barks again.** XPU still enforces with memory dumps enabled. The
  route closes on a measurement of the one untested condition instead of on an
  inference, and `CVE-2020-11252` is shown patched on this build.
- **The read returns a value.** A protection was disabled by configuration
  reachable without an exploit. That is P2 and a security-boundary-bypass
  indicator: stop immediately, collect only minimum reproducibility, root-cause
  and affected-range evidence, and move to disclosure mode.

**Expectation, recorded before any run:** this build is `A908NKSU5EWA3`, kernel
2023-01-12, roughly 21 months after the bulletin, so it is expected to be
patched and to bark again. Writing the expectation down first is the point — a
negative is worth having because it was not assumed, and a positive would be
worth stopping for.

## Independent confirmation received during the pass

The concurrent line reviewed this work and returned two results that are
recorded here rather than paraphrased.

`docs/VERIFICATION020_HEAP_CAPACITY_INTEGRATION_REVIEW_2026-08-27.md` upholds
both refutations and confirms the monotonicity gate and the synthetic-`MET`
test. It also found a real gap and repaired it: **the executed probe binary was
not retained by the producer.** The hardened analyzer now pins the checked-in
source by hash, records the executed and reproducible build hashes explicitly
with `retained: false`, and fails closed on source drift. That defect is upheld.

`docs/VERIFICATION020M_INTEGRATION_REVIEW_2026-08-27.md` re-collected the PA28
device-tree chain from the live target under a read-only allowlist and returns
`PROVED` for heap 30's `reg` `0x1e`, its `memory-region` phandle `0x67a`,
`camera_mem_region`'s matching phandle, base `0xc2000000`, size `0x14000000`,
`ion,recyclable` present and `no-map`/`reusable` both `ENOENT`. It calls a
full-size PA28 offset test **feasible**, and holds `UNKNOWN` on *whether a live
320 MiB allocation consumes the whole carveout* — a stricter reading than the
pigeonhole argument in `docs/PA28_UNBLOCKED_2026-08-27.md`, and the correct one
until that allocation is actually made.

## Ledger

| Commit | |
|---|---|
| `1bc494e` | Retain V019's raw receipts and reproduce the suspend independently |
| `78044c2` | Measure heap capacity, and refute two of my own numbers |
| `4d2169d` | Survey outside the current line, and record two dead ends |
| `7f83b9d` | Reopen route 1 — the physical base was in the device tree |
| `0d37ffb` | Read the defenses backwards, and find the one untested condition |

| | |
|---|---|
| Test suite | 1,316 pass, 0 fail, 1 skipped at the last full serial run in this pass |
| Device state | Restored. Wakeup-source set identical to pre-run, every temporary object removed, debugfs mounted read-only and unmounted, no reboot — uptime continuous throughout |
| Boundary | No security-boundary-bypass indicator appeared at any point |
| Classification | `CLASS C (TRANSFORM ONLY)` / `NOT_ELIGIBLE` — unchanged |

## Ranking

`PROVED`: the V019 byte-identical regeneration and the second suspend; the three
measured heap ceilings and their brackets; the device-tree chain to
`camera_mem_region` and the PA28 pair arithmetic; the VMID asymmetry at
`0x09248000`; and the ordering of this project's own experiments from their
retained timestamps.

`REFUTED`: the 256 MiB ceiling; the 512 MiB PA28 span requirement; the unknown
physical base; and "literature adds nothing".

`SUPPORTED`: that the `0x09248000` protection is a targeted lockdown rather than
generic layout, from its contrast with its immediate neighbours.

`UNKNOWN`: whether a live 320 MiB allocation consumes the whole carveout; the
value of `f(PA28)`; the capacity of the seven withheld heaps; whether
`CVE-2020-11252` applies to SM8150 specifically and whether this build carries
the fix; and what the remapper read does at `DMID`.
