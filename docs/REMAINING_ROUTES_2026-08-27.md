# The four remaining routes, and what closes each

> **AUDIT RECONCILIATION — 2026-08-29.** This file remains a route-history
> document. Its current synthesis is
> [FINAL_REPORT_2026-08-29.md](FINAL_REPORT_2026-08-29.md). The two-audit verdict
> reopens route 1 at physical provenance, narrows route 2 to a confirmed
> instance-0 non-return with unknown cause, retains only the signed replacement
> closure of route 3, and closes route 4 only for the exact deep-suspend state.

> Integration note (2026-08-27): the external V019 analyzer/manifest is now
> backed by retained regular-file receipts for the original and an independent
> second deep suspend (`1bc494e`).  Both runs are `MAP_INVARIANT`; the bounded
> deep-suspend candidate is therefore directly negative, while other state
> transitions and global mutability remain `UNKNOWN`.  See
> `docs/VERIFICATION019_INTEGRATION_REVIEW_2026-08-27.md` and
> `docs/EXTERNAL_LINE_INTEGRATION_2026-08-27.md`.

After Verification 019, four routes remain between this project and its
objective. This records what closes each one, what *kind* of thing does the
closing, and what a literature survey adds. The distinction in the middle
column is the load-bearing part: a limit this project chose is not the same
finding as a limit the target enforces.

| Route | Closed by | Kind |
|---|---|---|
| PA28 and above | low-bit/model evidence exists; actual high-bit PFN/SG provenance remains open | conditional model evidence; observer gap |
| Enforcement ordering | one exact instance-0 EL1 load did not return; refusing agent and ordering are unknown | **hardware non-return**, not measured access control |
| DCB topology tampering | replacement path: contract, failure position, and image signature; global runtime writer remains unknown | contract **and** cryptography, plus bounded static negatives |
| Other state changes | two exact deep suspends were negative; other handlers are not subsumed | measurement for deep suspend only |

Only route 3's signed replacement path has a contract closure; the route as a
global writer question is not closed.

## 1. PA28 and above

> **REOPENED 2026-08-27.** This route is not closed.  The strict 020M snapshot
> proves the live DT advertisement for heap 30 and `camera_mem_region` at
> **`0xC2000000`**, size 320 MiB.  The retained 021 receipt supports a
> full-hold/no-residual-probe result, but lacks same-run target attestation, so
> the physical span is only `SUPPORTED_CONDITIONAL_ON_020M_CHAIN`.  A fixed
> 020N normal-RAM timing candidate is implemented but has not yet been run;
> `f(PA28)` and any alias remain `UNKNOWN`.  See
> `docs/PA28_UNBLOCKED_2026-08-27.md` and the 020N contract.  The corrections
> below stand but no longer add up to a closure.


Measuring `f(PA28)` needs two addresses differing in **only** bit 28.

> **Corrected 2026-08-27.** This section previously asserted that the pair
> needs a 512 MiB allocation and that the largest non-secure heap yields 256
> MiB. Both numbers were wrong, and neither was backed by a retained survey.
> The measurement is now `evidence/manifests/verification-020-heap-capacity-20260827-01.manifest.json`;
> the exact raw/probe provenance is reviewed in
> `docs/VERIFICATION020_HEAP_CAPACITY_INTEGRATION_REVIEW_2026-08-27.md`.

Two corrections, of opposite sign:

**The span requirement is 256 MiB, not 512 MiB.** A pair differing in only bit
28 is `x` and `x + 2^28`, so the span must *exceed* `2^28` = 256 MiB — it does
not have to reach `2^29`. The 512 MiB figure was the *base-independent* bound,
the same aligned-versus-arbitrary distinction that Verification 017 turned on:
512 MiB aligned guarantees such a pair exists, while a shorter span only
sometimes contains one.

**The heap ceiling is 320 MiB, not 256 MiB.** 256 MiB is merely what
Verifications 016, 018 and 019 requested. A descending ladder over every
enumerated heap measures `camera_preview` at **320 MiB**, bracketed 320 ✓ /
352 ✗, with `qsecom` at 32 MiB and `user_contig` at 16 MiB. No non-secure heap
comes near 512 MiB, so **reopen condition 2 is `NOT_MET` as measured** — but by
a smaller margin than the old text claimed, and against the wrong threshold.

320 MiB exceeds `2^28`, so PA28 is no longer excluded by span arithmetic. What
still blocks a direct conclusion is allocation identity and placement: a
usable pair exists only if the allocation's physical base modulo `2^29` falls
in the right half, and `pagemap` is `BLIND` for dma-buf.  The 021 result makes
the span conditional on the 020M heap/phandle chain, but does not itself attest
the exact target or physical pages.  The next 020N timing run must therefore
measure the candidate under strict same-run provenance rather than treat the
DT advertisement as a physical-page receipt.
Whether the base can be inferred rather than read — for instance from how the
observed conflict pattern shifts across the 64 MiB of slack — is `UNKNOWN` and
untested.

The seven remaining heaps were enumerated but never allocated from. `system` is
page-based and cannot supply a contiguous span by construction; the other six
are secure or remote-processor heaps, and allocating from one drives
`hyp_assign` and a VMID transition, a mandatory pause gate. Their capacity is
therefore `UNKNOWN`, not zero.

The obvious workaround still does not work. Two allocations cannot be stitched
together, because `pagemap` is `BLIND` for dma-buf and the recovered relation
cannot serve as a ruler for the gap: at rank 3 it pins only three bits of any
difference, never the high part.

**Literature adds nothing.** The one published pagemap-free physical-address
oracle is SPOILER, which exploits speculative load hazards in the x86 memory
disambiguation unit and has no ARM equivalent. The most recent mapping-recovery
work, ρHammer (arXiv 2510.16544, October 2025), recovers mappings "within
seconds" but targets Intel Alder, Comet, Rocket and Raptor Lake; what it
improves is measurement efficiency, not allocation size.

`UNKNOWN`: whether the duplication pattern of PA25..PA27 continues, or whether
the relation changes character at the rank boundary `0x140000000`.

## 2. Enforcement ordering — non-return measured, cause unresolved

Verification 017 closed half of this by granularity: a check reading only
post-decode **bank** coordinates could not separate protected from unprotected
memory, because both occupy all eight classes. What remains is a check on the
complete DRAM coordinate, which is a bijection with the physical address and
therefore carries identical information — indistinguishable by passive
observation, in principle and not merely in practice.

That leaves active observation: change the map and see whether protection
follows. **This is not blocked by the contract.** `docs/THREAT_MODEL.md` binds
on persistence rather than hazard and places "volatile controller/remapper/
MCCC/MC writes" inside the permitted bound, with `docs/WRITE_GATE_<experiment>.md`
as the recording mechanism. An earlier version of Verification 017 said
otherwise and was corrected.

What is measured is narrower than a protection-boundary verdict:

- **The register is not identified.** Experiment 028 found nothing carrying this
  relation among the observed register set, and `docs/PRIOR_ART.md` still lists
  its encoding, writer and lock as unproved.
- **The exact instance-0 direct load is non-returning.** One fixed EL1 load at
  `0x09248080` returned no value and ended in a watchdog reset. `/dev/mem` is
  absent under `CONFIG_DEVMEM=n`. The paired control executed zero MMIO loads,
  so neither the successful-read capability nor XPU causality was established.
- **The static rows are address coverage, not a flat HLOS verdict.** Both TZ
  branches contain broad records covering the eight known addresses and the
  instance-0 narrow raw row. The old bit-3 HLOS predicate does not discriminate
  five HLOS-driver DDRSS pages from the non-return page; client actor, overlap,
  effective instance/path, and final live policy remain `UNKNOWN`.

Qualcomm's public architecture material supports a transaction attribute,
target-policy, and SMMU/XPU stack, but it does not prove that all initiators
take the same exact A90 path or that these static rows equal final live policy.
No published result supplies the missing exact-target cause or ordering.

A second literature result is worth recording for its own sake: **no published
DRAM address-mapping function exists for SM8150/SDM855.** DRAMA, Sudoku
(arXiv 2506.15918), Knock-Knock (arXiv 2509.19568), Barenghi's software-only
reverse engineering and ρHammer are all methodology; none reports this target.
So the register identity is not obtainable from the literature either — and the
rank-3 relation this project recovered appears to be new in the public record.

## 3. DCB topology tampering

This is the one genuine structural transfer from the external memory-aliasing
literature (see `docs/EXTERNAL_REUSE_REVIEW_2026-08-27.md`). BadRAM, DisARMed
and PMPlease all exploit a controller that trusts topology metadata reported by
a DIMM's SPD chip. On this target the metadata is a file in a flash partition:
Experiment 008 `PROVED` that XBL selects DCB `/6003_0200_1_dcb.bin`, reports two
3072-MiB ranks, and that mask `0x3` with total 6144 MiB uniquely chooses
remapper row 7. No physical access is needed — the one thing every external
work requires.

Three independent things close it.

1. **Contract.** `xbl_config` is named in `docs/THREAT_MODEL.md`'s forbidden
   partitions.
2. **Failure position.** A misreported topology fails DDR training inside XBL,
   before ABL, before fastboot, and before any recovery path this project can
   reach. That is the unrecoverable class the standing authorization carves out.
3. **Signature.** New here, and established from the project's own retained
   artifact rather than from the web.

`evidence/private/004-live-firmware-readonly-20260825-01/xbl_config--sdb2.bin`
is an ELF whose program header 1 is a `NULL` segment at file offset `0x1000`,
7000 bytes long — the Qualcomm hash-table segment. It contains an MBN header
declaring **version 6** and a **256-byte (RSA-2048) signature**, followed by a
**three-certificate X.509 DER chain** at offsets `0x1358`, `0x179b` and `0x1c30`
(1091, 1173 and 1165 bytes), with the string `Root CA` appearing five times. The
four `0x3404`-byte `LOAD` segments that Experiment 027 identified as DCB blocks
sit inside that signed container.

`PROVED`: `xbl_config` on this device is a signed image carrying per-segment
hashes and a three-level certificate chain, so any DCB edit invalidates it.

`SUPPORTED`, not `PROVED`: that a modified DCB would therefore fail
authentication at boot. The container proves the image is signed; it does not by
itself prove this device's XBL enforces verification of `xbl_config` under an
unlocked bootloader. Samsung unlock conventionally exempts only
boot/recovery/vbmeta, and the chain is anchored in fuses, so enforcement is
likely — but it is not measured here. A live authentication test is outside the
standing recovery boundary and is not made necessary by this report.

## 4. Other state changes

Verification 019 tested the deepest one available and found the map unchanged
twice: 0 of 4,194,304 tags moved across corroborated 25.090 s and 25.151 s
deep suspends.  Both runs passed the baseline and suspend gates, and the
original run is corroborated by `CLOCK_BOOTTIME` minus `CLOCK_MONOTONIC`,
`suspend_stats/success`, and RPMh `master_stats` recording APSS `Sleep Count:
0x1` for 24.96 s.

The other candidates must be kept separate by handler and state:

| Candidate | Status |
|---|---|
| hibernate | **measured absent** — `/sys/power/state` is `freeze mem`, no `disk` |
| devfreq DDR OPP | **measured vacuous** at the time — `disp_rsc_ebi` held a static 12.8 GB/s vote (see Verification 015's amendment) |
| s2idle (`freeze`) | shallower than `deep`; no power collapse |
| modem SSR | inferred: the DRAM controller is APSS/AOP territory. **Untested** |
| AOP-driven retraining | AOP runtime DDR management is `PROVED`, but no Normal-World trigger is known |

The two retained runs directly close the exact deep-suspend candidate. They do
not close the other rows: physical perturbation magnitude does not order the
set of firmware handlers executed, and OPP/PASR/SSR can follow paths not taken
by suspend/resume. Those mechanisms remain `UNKNOWN`, not negative by
subsumption.

### Post Package Repair — a mechanism this project had not considered

The literature survey turned up one thing that is a *better* fit for the Skitter
premise than the bank-XOR transform: **Post Package Repair**. It is a JEDEC
feature that remaps a faulty row to a spare row **inside the DRAM die**. Soft
PPR is temporary and reverts on power cycle; hard PPR is permanent and
fuse-backed. Vendor and patent material confirms mobile applicability — LPDDR
requires its own PPR sequence and control method.

A row remap inside the die sits downstream of everything the SoC's protection
can observe, so it moves data under any check expressed in physical addresses.
That is the Skitter shape more directly than anything examined here.

It does not open a route:

- PPR is driven by mode-register-set commands from the memory controller. The
  instance-0 APSS non-return does not establish whether an indirect or alternate
  initiator can issue those commands.
- Hard PPR is fuse-backed and **irreversible**, placing it outside the standing
  authorization outright, which binds on persistence.
- Whether SM8150's controller exposes PPR at all, and whether this LPDDR4X part
  supports it, is `UNKNOWN` and untested.

**No published security research on PPR abuse was found** — the material is
patents and vendor documentation. It is an unexplored area in the literature,
and its exact control path remains unresolved with route 2.

## What this adds up to

The audits do not support three route closures. Route 1 retains a strong bounded
low-bit result but is open at high-bit physical provenance. Route 2 proves one
non-return, while its refusing agent, other initiators and ordering remain
unknown. Route 3 strongly closes only the signed replacement path. Route 4 is
negative only for the two deep-suspend acquisitions.

The current one-line result is therefore: **bounded low-bit `C-MAP` strongly
supported; high-bit physical provenance, mutation, reach, final policy/path,
ordering and global alias unresolved; no Class D/E effect observed.**

## Sources consulted

- ρHammer, arXiv [2510.16544](https://arxiv.org/abs/2510.16544) — Intel-only;
  abstract retrieved directly.
- Sudoku, arXiv [2506.15918](https://arxiv.org/pdf/2506.15918); Knock-Knock,
  arXiv [2509.19568](https://arxiv.org/pdf/2509.19568) — already in the record.
- SPOILER, arXiv [1903.00446](https://arxiv.org/pdf/1903.00446) — x86 only.
- Qualcomm security documentation on VMIDMT/XPU/SMMU, and Qualcomm boot
  documentation on QDTE and `xbl_config.elf` signing. **Search-result level
  only**: the QDTE page returned a script shell with no text and the LineageOS
  chain-of-trust page returned HTTP 403, so neither was verified at source. The
  signing claim in route 3 does not rest on them — it rests on the retained
  artifact.
- PPR: USPTO patents and vendor documentation; no security literature found.
