# Broad survey: what is outside the current work, 2026-08-27

Scope of this pass: literature and device facts that neither the 020 static line
nor the existing route documents cover. Host-only plus read-only device tree
queries. No register was written, no MMIO was read, and no allocation was made.

Two results are negative and one is a concrete new experiment. All three are
recorded because a lead that was chased and failed is worth as much here as one
that succeeded.

## 1. The closest published analogue to this project's target — and why it does not transfer

`CVE-2022-22063` (msm8916-mainline) is the nearest published thing to the P1/P2
shape this project has been hunting: **a Qualcomm hardware remapper, mutable at
runtime, reachable from the non-secure OS.**

| | |
|---|---|
| Register | `APCS_BOOT_START_ADDR_NSEC`, `0x0b010008` on MSM8916 |
| Control bits | `REMAP_EN`, `BOOT_128KB_EN` |
| What it does | remaps `0x00000..0x20000` to a configurable physical base |
| Why it matters | the window is shiftable block by block, so 64/128 KiB of aperture reaches arbitrary memory |
| Reachable from | EL1, non-secure — stage 2 did not protect the *configuration* register |
| Result | full read/write/execute into hypervisor memory from a modified OS |
| Qualcomm's fix | block the *remapped region* via stage 2; the config register stays accessible |
| Affected | MSM8916/APQ8016; likely MSM8909, MSM8953. **SM8150 is not listed.** |

This is the exact P1 + P2 conjunction: a mutable transform downstream of the
protection boundary, plus a Normal-World path to it. It is worth stating that
such a thing has existed on this vendor's silicon, because it establishes the
shape is real rather than hypothetical.

### Checked on this device — negative

SM8150 has the analogous block:

| Device-tree label | Node | Compatible | Reg |
|---|---|---|---|
| `apcs_glb` | `/soc/mailbox@17c00000` | `qcom,sm8150-apcs-hmss-global` | `0x17c00000`, size `0x1000` |
| `apcs` | `/soc/syscon@17c0000c` | `syscon` | `0x17c0000c`, size `0x4` |

A single 32-bit register at APCS_GLB + `0x0c`, exposed to the kernel as a
syscon, looked like a candidate. **It is not one.** Offset `0x0c` is the
inter-processor-communication doorbell on SDM845, SC7180 and SM8150 — the
register SMP2P kicks to signal another subsystem. Different SoCs place the IPC
register at different offsets in this block (MSM8996 at 16, MSM8998 and IPQ8074
at 8, SDM845/SC7180/SM8150 at 12); this is that register, not a boot remapper.

`REMAP_EN` and `BOOT_128KB_EN` do not appear anywhere in the retained XBL.

### What survives as `UNKNOWN`

> **Resolved 2026-08-27 by Verification 025 — it is protected.** Decoding the
> complete MPU region set instead of the five ranges Verification 009 retained
> shows `0x17c00000` inside `CNOC_AOSS_MPU` region `0x17c00000..0x18200000`,
> TZ-owned, granting no HLOS read or write, identical in both selector branches.
> The absence below was extraction scope: the 009 manifest declares 1,726
> regions and retained decoded ranges for 5. See
> `experiments/verification-025-xpu-region-coverage/README.md`.

The retained XPU policy inventories (009, 010) and the 1b reachability
checkpoint contain **no address inside `0x17c00000..0x17c01000`**. That is not
evidence of absent protection — those inventories were built from XBL
initializers for specific XPU instances and were never a complete enumeration of
SoC protection. It does mean this block sits in the category the 1b checkpoint
explicitly named as open: *alternate or undiscovered apertures, `UNKNOWN`*.

Whether SM8150 carries an `APCS_BOOT_START_ADDR` analogue at some other offset,
and whether it is stage-2 protected, is unresolved. Nothing here justifies a
write; identifying such a register would be 1a, and 1b would still have to be
demonstrated separately.

## 2. Address-mapping recovery literature the project has not used

`docs/PRIOR_ART.md` covers Skitter and the GF(2) model. `docs/REMAINING_ROUTES`
surveyed SPOILER and ρHammer and concluded "literature adds nothing". That
conclusion was too broad — it was reached against the *allocation-size* problem,
where it holds, and then stated generally. Against the *mapping-recovery*
problem there is a live and recent line of work:

| Work | Venue / year | What it gives that this project lacks |
|---|---|---|
| **Knock-Knock** (arXiv 2509.19568) | µASC 2025, Georgia Tech / CentraleSupélec / Inria / CNRS / IRISA | Same GF(2) formulation this project uses, but proves the relation between the bank matrix and an empirically built address matrix, and recovers the bank-mask basis in **polynomial** rather than exponential time. 99% recall, minutes, scales past 500 GB. Also generalises to complex **row** mappings, recovering a row basis. |
| **Sudoku** (arXiv 2506.15918) | 2025 | Decomposes a full mapping into *component* functions — channel, rank, bank group, bank — using refresh intervals and consecutive-access latency, rather than recovering one fused relation. |
| **DRAM-MaUT** (IEEE CASES 2022) | Kaur, Srivastav, Ghoshal | The only **ARM-native** one. `DC CIVAC` for eviction and `PMCCNTR` for timing — the exact primitives available here. |
| **DRAMDig** (arXiv 2004.02354) | 2020 | Knowledge-assisted mapping recovery. |

This project's recovered relation is **rank 3 over PA13..PA27** — bank-selection
bits only. Knock-Knock's row-basis extension and Sudoku's component
decomposition both address what the project currently records as `UNKNOWN`:
complete DRAM coordinates rather than a bank class. Neither requires new
privilege, and both are measurement, not mutation.

`CATTmew` (IEEE TDSC) defeats physical kernel isolation through ION/DMA driver
buffers. It is noted and **not** pursued: it is a privilege-escalation result,
and this project has already decided that succeeding at higher privilege is not
an interesting outcome.

## 3. Skitter, as now publicly described

The motivating work is Christopher Domas's `skitter-creek-bath-salts`, against
AMD Family 16h, targeting the MCT/DCT pipeline — the last stage before physical
addresses become channel/rank/bank/row/column. Reported properties: **no patch
exists and the affected registers cannot be locked**, and the presentation is
slated for Black Hat 2026. The public write-ups assert the same architectural
pattern — channel and rank interleaving, bank swizzling, chip-select mapping —
spans AMD, Intel, ARM and RISC-V.

That last claim is a claim about *structure*, and this project agrees with it:
the transform here is linear over GF(2) and was recovered as such. What this
project has repeatedly failed to find is not the transform but the **aperture**.
Skitter's registers are reachable at ring 0; every A90 equivalent examined so
far is TZ-owned with no HLOS grant. The gap is access control, not architecture,
and none of the new literature narrows it.

## 4. A concrete experiment this survey produces

> **Superseded 2026-08-27, on this heap.** The base does not need inferring:
> the device tree publishes it (`camera_mem_region` @ `0xC2000000`). See
> `docs/PA28_UNBLOCKED_2026-08-27.md`. The lever below stays valid for any heap
> whose base is *not* published, and the derivation is retained for that case.


The heap-capacity measurement showed `camera_preview` reaches **320 MiB**, and
that measuring `f(PA28)` needs a span exceeding `2^28` = 256 MiB rather than the
512 MiB previously asserted. What still blocks PA28 is the unknown physical
base. That base may be measurable rather than read.

**The carry-phase lever.** `f` is linear over GF(2), so two offsets `o` and
`o'` in a contiguous allocation with base `B` land in the same bank exactly when
`f((B+o) ⊕ (B+o')) = 0`. If `B` were zero this would depend only on `o ⊕ o'`.
It does not, and the deviation is the signal:

For `o' = o + 2^k`, the XOR `(B+o) ⊕ (B+o+2^k)` equals `2^k` **exactly when bit
`k` of `B+o` is zero**, and grows to `2^{k+m+1} − 2^k` when a run of `m` ones
carries. So as `o` sweeps, the observed conflict pattern alternates with period
`2^{k+1}`, and **the phase of that alternation is `B mod 2^{k+1}`**.

Sweeping `k = 13..27` — the bits the recovered relation already covers — yields
`B mod 2^28` one bit at a time, from timing alone, with no `pagemap`.

That does not immediately give bit 28 of `B`. It gives something sufficient: it
locates the single `2^28` boundary that can fall inside the 64 MiB of slack in a
320 MiB allocation. On one side of that boundary a pair `(o, o+2^28)` differs in
bit 28 only; on the other it does not. Which side is which is one bit, and it is
decidable by test rather than assumption.

Preconditions, stated honestly: this needs physical contiguity across the whole
allocation, which Verification 016 established behaviourally and not by
construction; it needs `f(2^{k+1}) ≠ 0` for the bits swept, which the rank-3
relation must be checked against per bit; and a 320 MiB allocation may contain
no valid boundary at all, in which case the answer is that this base does not
admit a PA28 pair and a re-allocation is needed. Every one of those is a
measurement, none is a mutation, and the whole thing stays inside `CLASS C`.

## Ranking

`PROVED`: the SM8150 device-tree facts above — labels, compatibles, register
addresses and sizes — read directly from the live target.

`PROVED`: no address in `0x17c00000..0x17c01000` appears in the retained 009,
010 or 1b manifests.

`SUPPORTED`: `syscon@17c0000c` is the SMP2P IPC doorbell rather than a boot
remapper, from the documented per-SoC offset convention.

`REFUTED`: that the literature adds nothing. It adds nothing to the
allocation-size problem and a substantial amount to mapping recovery.

`PROVED` (Verification 025, 2026-08-27): `0x17c00000` **is** protected —
`CNOC_AOSS_MPU` `0x17c00000..0x18200000`, TZ-owned, no HLOS grant, both
selector branches.

`UNKNOWN`: whether SM8150 has an `APCS_BOOT_START_ADDR` analogue anywhere; the
physical base of any allocation; and whether the carry-phase lever survives
contact with real timing noise.

`CLASS C (TRANSFORM ONLY)` and `NOT_ELIGIBLE` are unchanged. Nothing in this
survey is a boundary-bypass indicator, and nothing in it authorises a write.
