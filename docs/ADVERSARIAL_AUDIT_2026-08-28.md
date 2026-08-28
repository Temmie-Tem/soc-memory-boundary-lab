# Independent adversarial research audit — 2026-08-28

Scope: re-derive the `CLASS C (TRANSFORM ONLY)` conclusion from primary evidence
without inheriting it. Host-only. No device action, no MMIO, no SMC, no
firmware write. Inputs are the retained private artifacts and the public
manifests already in this repository, plus fresh external literature.

This audit deliberately runs in both directions. It looks for what the project
missed **and** it tests whether new hypotheses are actually excluded by the
existing negative evidence. Two of the four routes it reopens; one interface it
closes harder than the project ever did.

---

## 1. Reconstruction of the Class C logic chain

The conclusion is a conjunction of six links. Re-derived from evidence, they are
not the same grade.

| # | Link | Evidence kind | Grade as re-derived |
|---|---|---|---|
| L1 | A non-trivial PA→bank transform exists on this target | **direct measurement**, timing, pre-registered, out-of-sample | `PROVED` |
| L2 | The transform is linear over GF(2), rank ≥ 3 | **direct measurement** (V027/V028/V029: 8/8 out-of-sample, 771/774 corpus) | `PROVED` |
| L3 | The transform's configuration register is not identified | **search exhaustion** ("not found") | `UNKNOWN`, correctly labelled |
| L4 | The known apertures are unreachable from Normal World | **one hung load ×2 configs + static policy tables** | **contested — see §2.1, §2.2** |
| L5 | Nothing else can reach the transform on HLOS's behalf | **not tested** — no interface enumeration was ever performed | **refuted as stated — see §4.1** |
| L6 | The transform is not mutable (P1) | explicitly `UNKNOWN`; no write attempted | `UNKNOWN`, correctly labelled |

L1, L2, L3 and L6 survive the audit unchanged and are well-executed. **L4 and L5
do not.** The report-level sentence "the transform is reachable only from behind
an access-control boundary that held every time it was tested" is a stronger
claim than L4+L5 support, in two specific ways developed below.

### Audit of the eleven propositions named in the audit request

| Proposition | Verdict |
|---|---|
| transform exists but mutation unproved | **upheld** — correctly labelled `UNKNOWN` throughout |
| known apertures unusable from Normal World | **weakened** — rests on an experiment with no positive control (§2.1) |
| XPU policy covers the apertures sufficiently | **argument refuted, conclusion strengthened** — the grant test is wrong; the remapper is nonetheless the one denied page (§2.2) |
| known apertures represent the relevant aperture set | **refuted** — the initiator axis was never considered (§4.1) |
| no complete DRAM coordinate alias | **upheld** |
| protection-ordering reasoning is sufficient | **weakened** — the protection's *identity* is unestablished (§2.3) |
| deep suspend subsumes other transitions | **refuted as stated** (§2.4) |
| DCB/XBL path effectively closed | **upheld** — signature + failure position are independent and sound |
| firmware paths examined represent runtime writers | **weakened** — 5 of 152 SMC records decoded (§2.5) |
| Class C taxonomy divides the problem correctly | **partly** — the label bundles "transform/alias"; only the transform half is evidenced (§9) |
| known XPU policy is the enforced policy | **partly** — it discriminates correctly under the corrected bit, but which MPU is on the access path is unmodelled (§2.2) |

---

## 2. The ten weakest premises

### 2.1 The refusal experiment has no positive control — `HIGH severity`

**CLAIM.** "One fixed EL1 load at `0x09248080` returned no value and ended in a
watchdog reset" ⇒ the read was *refused* by access control.

**EVIDENCE.** `007-inline-remapper-read-watchdog`, `013-shrm-read-watchdog`,
`verification-023-*`. The paired control is recorded verbatim as:
`"fixed __ioremap; immediate __iounmap; return 0xc071; **zero MMIO loads**"`.

**HIDDEN ASSUMPTION.** That a load which does not return is diagnostic of the
*address*. The control establishes that the map/unmap harness is sound. It does
not establish that this harness can complete **any** MMIO load anywhere. Across
every experiment in the repository, `read_success_count` is **0** and
`register_read_success_count` is **0**. The apparatus has a 0-for-N record on
MMIO reads at every address it has ever tried.

**POSSIBLE COUNTEREXAMPLE.** If the inline path cannot complete a load at, say,
a GCC or TLMM register that HLOS demonstrably reads, then the hang at
`0x09248080` is a property of the instrument, not of the target.

**CURRENT CONFIDENCE.** The project's own primary evidence already says this:
`009` records `current_status: "SUPPORTED_NOT_PROVED_CAUSAL"`,
`evidence_against_xpu_denial: ["No decoded XPU syndrome and no post-boot XPU
register readback"]`, and `critical_unknowns` includes **"Sub-aperture clock
state"**. `docs/THREAT_MODEL.md` likewise says the failed load "does not
distinguish access control from clock/power or fabric state."

`docs/FINAL_REPORT_2026-08-27.md` §2 nevertheless labels route 2
"**Measured access control**", and §4 states "`PROVED` … the protected read is
**refused**". **This is a label escalation from `SUPPORTED_NOT_PROVED_CAUSAL` at
the manifest to `PROVED`/"measured" at the report.** The escalation is the
defect; the underlying measurement is fine.

The project's own §5 principle applies exactly: *"A guard that has never fired
is not evidence."* An instrument that has never succeeded is not evidence either.

### 2.2 The HLOS-grant test has no discriminating power, and the VMID bit is wrong — `HIGH severity`

**CLAIM.** Every remapper/BIMC/SHRM aperture is covered by TZ-owned XPU regions
with no HLOS grant, therefore HLOS cannot reach them. `MEMORY_MAP.md`: three
regions "each *independently* covering all eight known remapper/BIMC addresses
with no HLOS VMID grant."

**EVIDENCE.** `verification-025/026`, reproduced byte-for-byte in this audit
(TZ SHA-256 `a5e6c574…`; 109 address regions; 21 reported HLOS-granting, all in
IMEM, AOSS and PMIC_ARB).

**HIDDEN ASSUMPTION.** That HLOS is VMID 3, so `read_vmid & (1<<3)` decides the
grant. `decode_mpu_region_permissions` hardcodes `hlos_vmid = 3`.

**COUNTEREXAMPLE — the test returns `False` for pages HLOS demonstrably drives.**
The retained boot device tree declares these MMIO nodes **inside
`0x09000000..0x09800000`**, the band Route 2 says grants HLOS nothing:

| Live DT node | Address | What drives it |
|---|---|---|
| `syscon@90b0000` (reg `0x090b0000`, size `0x1000`) | `qhs_mccc_master` | a `syscon` regmap consumer |
| `cpu-cpu-llcc-bwmon@90b6400` | `0x090b6400` | bandwidth monitor driver |
| `llcc-pmu@90cc000` | `0x090cc000` | LLCC PMU driver |
| `cpu-llcc-ddr-bwmon@90cd000` | `0x090cd000` | bandwidth monitor driver |
| **`llcc@9200000`** | `0x09200000` | **`llcc-sm8150` — programs LLCC configuration** |

`hlos_present_in_read_mask` is `False` for **all five**, and for the remapper.
A test that returns the same answer for the LLCC controller HLOS programs and
for the page that hung has **no discriminating power**; its agreement with the
truth at `0x09248080` is coincidental.

**THE CORRECTED READING.** Across all 109 regions the low 24 bits of every VMID
word are either `0xffffff` or `0x000000` — never a partial mask — while bits
28–31 vary richly. The field is a **security-class mask**, and **bit 30 is the
non-secure/HLOS class**. Tested against the live evidence, it discriminates
6 for 6:

| Address | HLOS drives it? | nearest-target MPU | `read_vmid` | bit 30 | bit 3 |
|---|---|---|---|---|---|
| `0x090b0000` | yes | `DC_NOC_NON_BROADCAST` | `0x40000000` | **grant** ✓ | deny ✗ |
| `0x090b6400` | yes | `DC_NOC_NON_BROADCAST` | `0x40000000` | **grant** ✓ | deny ✗ |
| `0x090cc000` | yes | `DC_NOC_NON_BROADCAST` | `0x40000000` | **grant** ✓ | deny ✗ |
| `0x090cd000` | yes | `DC_NOC_NON_BROADCAST` | `0x40000000` | **grant** ✓ | deny ✗ |
| `0x09200000` | yes | `DC_NOC_BROADCAST` | `0xc0000000` | **grant** ✓ | deny ✗ |
| **`0x09248080`** | **hung** | `DC_NOC_BROADCAST` | `0x80000000` | **deny** ✓ | deny ✓ |

Under bit 30 the grant counts change from 21/109 read and 15/109 write to
**60/109 and 49/109**.

**CONSEQUENCES — and they cut both ways.**

*Against the project's reasoning:*

- `REFUTED`: "three regions **independently** cover the remapper with no HLOS
  grant." `CNOC_SNOC_MS_MPU` region 5 (`0x9000000..0x9800000`) has
  `read_vmid = 0xf0000000` — bit 30 set — so it **grants**. And
  `MEMNOC_MS_MPU` region 0 (`0x0..0x10000000`) reports `0x80000000` = deny for
  every one of the five pages HLOS demonstrably drives, so it is **not on the
  CPU's config path** and cannot be counted as coverage at all. Three
  independent coverings reduce to **one**.
- `REFUTED`: the count "21 grant HLOS, all in IMEM, AOSS and PMIC_ARB".
- `WEAKENED`: `FINAL_REPORT` §6's "none overlapping the remapper, BIMC, SHRM,
  MCCC, the `0x09000000..0x09800000` band or DRAM" — HLOS-granted regions
  overlap that band extensively.

*For the project's conclusion — this is the stronger half:*

- **`0x09248000` is the only page in its neighbourhood with bit 30 cleared.**
  What `DEFENSE_SHAPE` observed aesthetically ("a response to something") is now
  a **measured discrimination**: the nearest-target MPU grants non-secure access
  to every DDRSS page HLOS actually uses and withholds it from exactly the
  remapper page. The specific conclusion about the remapper **survives and is
  better supported than before**.

**A separate, unresolved case.** `CNOC_AOSS_MPU` region 5 covers
`0x17c00000..0x18200000` with `read_vmid = write_vmid = 0x00000000` — deny under
*either* reading. Yet the retained `last_kmsg` from the boot that produced the
**DMID** route-2 negative — Verification 023, candidate `7ee6a41f…`, whose
`snapshot_physical_address` is the SHRM word `0x0906566c` and **not** the
remapper, an address substitution `FINAL_REPORT` §8 itself lists as open work —
shows, at ~9.5 s intervals from 9.95 s to 85.7 s:
`msm_watchdog 17c10000.qcom,wdt: [pet_watchdog] last_count : …, new_count : …` —
HLOS reading and writing MMIO in that range continuously; the DT also declares
`syscon@17c0000c` bound by `qcom,ipc`/`smp2p`; and `010-xpu-initializer-inventory`
states `PROVED` that the boot loop **does** initialize `CNOC_AOSS_MPU`. TZ's own
SCM allowlist (§6.1) further grants HLOS proxied read/write to
`0x17c000f0..0x17c00150` inside that range.

Best available explanation, `HYPOTHESIS`: different MPU instances filter
different **initiator paths**, and neither `CNOC_AOSS_MPU` nor `MEMNOC_MS_MPU`
sits on the APSS→config-NoC path. If so, "which MPU is on the path" is a
first-class variable the project has never modelled — and it is the variable
that decides every containment answer.

**Net.** The remapper's protection looks *more* real after this correction, not
less. What is refuted is the machinery used to argue it: the grant test, the
independence claim, and the coverage counts. Every document citing them needs
re-grading.

### 2.3 The identity of the refusing protection was never established — `MEDIUM`

The whole route-2 narrative attributes the refusal to **XPU**. The retained
`last_kmsg` says otherwise about what is actually observable:

```
print_noc_info: START      -> tz log is encrypted or not parsed yet!
print_xpu_info: START      -> tz log is encrypted or not parsed yet!
print_smmu_info: START     -> tz log is encrypted or not parsed yet!
```

No NoC, XPU or SMMU syndrome was ever available. But the *same dump* records a
**hypervisor** fault record that nobody has read:

```
log_addr:858df200 log_size:1e00 offset:6b4 wrap:0
add_auto_comment_hyp_log: START
Found[Data abort]!!  Found[Faulting Address]!!  Found[Instruction Executed]!!
Found[ESR_EL2]!!  Found[FAR_EL2]!!  Found[ELR_EL2]!!
```

`PROVED`: a stage-2/EL2 data-abort record with ESR_EL2, FAR_EL2 and ELR_EL2
exists in `hyp_mem` (`0x858df200` is inside the advertised `0x85700000..0x85cfffff`)
and the Samsung Upload parser located all six fields. `UNKNOWN`: their values,
and whether this record corresponds to the probe.

This matters because a **QHEE stage-2 refusal is a different finding from an XPU
refusal**, and it is the one CVE-2022-22063 is about. If the refusal is stage-2,
then Route 2's entire XPU argument is addressing the wrong mechanism.

### 2.4 The deep-suspend subsumption argument is invalid as stated — `MEDIUM`

**CLAIM.** "Deep suspend is a strictly stronger perturbation … A map that
survives losing power does not plausibly move on a frequency change." Used to
close modem SSR, AOP retraining and devfreq **by subsumption**.

**HIDDEN ASSUMPTION.** That physical perturbation magnitude orders *firmware
code-path coverage*. It does not.

**COUNTEREXAMPLE.** Self-refresh exists precisely to **preserve** DRAM contents
and controller configuration across the power collapse; AOP restores saved
controller state verbatim. Map invariance across suspend is a design
*requirement*, so the experiment had near-zero prior probability of a positive
and correspondingly near-zero information gain — it is the *weakest* probe of
the DDR configuration logic, not the strongest. A DDR OPP change, by contrast,
runs the AOP timing/retraining path, which is a genuinely different code path.

Worse, the project's own record shows the one experiment that would have
exercised that path was **vacuous**: `disp_rsc_ebi` held a static 12.8 GB/s vote,
so the frequency never changed (V015 amendment). The gap was then closed by the
subsumption argument rather than by fixing the experiment. The kernel exposes
`ddr_bw_opp_table`, `suspendable_ddr_bw_opp_table`, `bw_ctl_ebi` and
`cpu_llcc_ddr_bwmon` — the surface to force a real OPP change exists.

`0 of 4,194,304 tags moved` is a real measurement and it closes the deep-suspend
candidate. It closes nothing else.

### 2.5 The same "extraction scope" failure that V025 fixed is still live — `HIGH`

V025 was created because V009 decoded **5 of 1,726** XPU region records and
every later "no address appears in the inventory" claim was measured against
0.3% of the policy.

`010-xpu-initializer-inventory` decodes **5** TZ SMC dispatch records, records
the exact record layout (`<u32 reserved, u32 smc_id, u32 param_id, u32 flags,
u64 handler>`, 24 bytes), and the project then reasoned about the secure-monitor
interface from those 5. This audit walked the table: **152 contiguous
well-formed records at `0x1c12a4c8..0x1c12b2f0`** (`PROVED`; a lower bound if the
table continues in another shape). 5 of 152 is 3.3%.

The identical failure signature, one document later, in the neighbouring table.

A second, smaller correction falls out of the walk: the leading record word that
`010` names `reserved` is **`0x64` on one record** (SMC `0x3400fa04`) and zero on
the other 151. It is not a reserved field, and testing it as zero splits the
table into two runs of 117 and 34 — which is how this audit first mis-counted it.

Regenerated by `tools/sm8150_tz_smc_and_io_allowlist.py` into
`evidence/manifests/audit-tz-smc-io-allowlist-20260828-01.manifest.json`.

### 2.6 – 2.10 (compressed)

| # | Premise | Weakness | Confidence |
|---|---|---|---|
| 2.6 | "Undiscovered apertures not excluded" is a sufficient caveat | It is stated, then not acted on. The *address* axis was swept; the **initiator** and **proxy** axes never were (§4.1). A caveat that never changes a plan is decoration. | `LOW` that coverage is adequate |
| 2.7 | `pagemap` is `BLIND`, so physical identity is unobtainable | `BLIND` is a property of the **userspace** probe (`tools/a90_region_probe.c` uses `/dev/ion` + `mmap`). The project already boots custom kernel code with `__ioremap`; a kernel-side `dma_buf`/`sg_table` walk yields the exact PA. The limitation is self-imposed tooling, not platform. | `HIGH` that it is self-imposed |
| 2.8 | The `0x09248000` permission is "a non-standard construction … the shape of a response to something" | `exact_constructed_client_permission_bytes 0x11,0x08` is produced by **hardcoded special cases for bits 28/29/31** inside `decode_mpu_region_permissions`, alongside a fitted `standard_mask = 0x40FFFFFF`. The "non-standard construction" is partly a property of this project's decoder. The *raw* asymmetry survives; the narrative built on it does not. | `MEDIUM` — argument partly circular |
| 2.9 | Route 3 is closed | **Upheld.** MBN v6 + RSA-2048 + three-level X.509 from the retained artifact, plus failure position inside XBL, plus contract. Three independent closures, one cryptographic. No change. | `HIGH` |
| 2.10 | "One load, one address, two debug levels" is bounded honestly | It is — but the bound is severe and under-weighted: **2 addresses probed in 70 experiments**, because each attempt costs a watchdog reset and reboot. The real blocker is not authority, it is the absence of a non-fatal probe (§10). | `HIGH` |

---

## 3. Failure patterns, and which are still live

The project's own reversals, classified:

| Past error | Pattern | Still live? |
|---|---|---|
| PA28 "needs 512 MiB" | **arithmetic asserted without measurement** | no |
| heap ceiling "256 MiB" | **request mistaken for capacity** | no |
| physical base "UNKNOWN" but in the DT | **not-looked-for → not-there** | **yes** — §2.5, §4.1 |
| "literature adds nothing" | **negative-result overgeneralization** (true for allocation size, restated globally) | **yes** — §6 finds two more |
| tautological verifier | **observer defect** | **yes, in new form** — §2.1: an instrument that never succeeds |
| TWRP resets `debuglevel` | **state/provenance mismatch** | no — now pinned |
| 5 of 1,726 XPU regions | **extraction scope mistaken for absence** | **yes** — §2.5, 5 of 152 SMC records |

Three of seven patterns are unrepaired, and the two most consequential —
*extraction scope* and *observer defect* — are the ones that produce §2.1 and
§2.5. The project fixed each **instance** and never generalized the **class**.

---

## 4. Structural blind spots

### 4.1 The search space was swept on one axis only

Every reachability question the project asked has the form *"is address A
readable by the CPU at EL1?"*. Three axes were never enumerated:

| Axis | Question | Coverage |
|---|---|---|
| **Address** | which addresses? | thorough — 8 apertures, both selector branches, complete region walk |
| **Initiator** | *who else* issues bus transactions? | **none** — DCC, SMMU/DMA masters, AOP, modem/DSP never considered |
| **Proxy** | *who will do it on HLOS's behalf?* | **near-none** — 5 of 152 SMC records; `smc_access: false` in every manifest; no SMC was ever executed |
| **Mode** | under which system state? | partial — debug level LOW/MID only |

XPU being "target-side, protecting against all initiators equally" was taken
from Qualcomm marketing documentation and used to retire the initiator axis
without a measurement. That is exactly the kind of vendor-claim-as-evidence the
project rejects elsewhere.

### 4.2 The instrument budget was never treated as the binding constraint

Two addresses in seventy experiments. Every remaining question in §6 of
`FINAL_REPORT` — other dump sinks, other apertures, force-upload states — is
gated on the same fatal-probe cost. The project optimized the *argument* around a
constraint it never tried to remove.

### 4.3 The protection's identity was assumed, not measured

§2.3. Every route-2 document says "XPU". The only fault record actually retained
is an **EL2** one, unread.

---

## 5. Attack/control-surface map, rebuilt independently

Built from the layer × transform × interface axes in the audit request, then
mapped back onto the old routes.

### 5.1 By interface — *who can touch the transform*

| Interface | Present on this target? | Examined? | Status after this audit |
|---|---|---|---|
| Direct MMIO from EL1 | yes | yes | hangs; **uninterpretable without a positive control** (§2.1) |
| `/dev/mem` | no (`CONFIG_DEVMEM` not set) | yes | `REFUTED` |
| **SCM `IO_READ` / `IO_WRITE`** | **yes — SMC `0x02000501`/`0x02000502`** | **never** | **closed by allowlist — §6.1. Measured, exact.** |
| Other SMC services | 152 records, 23 SIP services | 5 records | **`UNKNOWN` — 3.3% decoded** |
| **DCC (Data Capture & Compare)** | **yes — `dcc_v2@10a2000`, 1053 live entries** | **never** | **open, and the highest-value lead — §6.2** |
| SMMU / DMA initiator | yes | no | `UNKNOWN` |
| AOP / RPMh voting | yes (`bw_ctl_ebi`, OPP tables) | vacuously (§2.4) | `UNKNOWN` |
| Modem / DSP remote processors | yes | no (subsumption) | `UNKNOWN` |
| debugfs / sysfs | yes | partially | `UNKNOWN` |
| Crash-dump / Samsung Upload | yes | yes — SHRM export `PROVED` | **under-exploited — §2.3** |
| Bootloader service | yes | route 3 | closed |

### 5.2 By transform kind

The project characterised exactly one transform (bank selection) and treated
"the transform" as singular. The independent enumeration:

| Transform | Who sets it | When | Runtime mutation | Position vs. check |
|---|---|---|---|---|
| bank / bank-group XOR | MC/MCCC or DDRSS | XBL, pre-HLOS | `UNKNOWN` | downstream (assumed) |
| channel selection / interleave | remapper row 7, DCB-selected | XBL | `UNKNOWN` | downstream |
| rank selection | DCB topology (2×3072 MiB) | XBL | `UNKNOWN` | downstream |
| row / column | MC | XBL | `UNKNOWN` | downstream |
| **LLCC / system-cache address transform** | LLCC driver, **HLOS-programmable** | runtime | **likely yes** | **`UNKNOWN` — never considered** |
| NoC target translation | NoC config | XBL | `UNKNOWN` | upstream of MC |
| **PPR (in-die row repair)** | MC via MRS | runtime/fuse | hard PPR irreversible | **fully downstream — best Skitter fit** |
| ECC redirection | MC | boot | `UNKNOWN` | downstream |
| **DDR retraining / OPP reconfiguration** | **AOP** | runtime | **yes, by design** | downstream |

Two rows here were never on any project list: the LLCC transform (HLOS *does*
program LLCC via `llcc-sm8150`) and AOP retraining as a *mutation* path rather
than a perturbation.

### 5.3 Mapping back to the old routes

Route 1 ≈ address axis. Route 2 ≈ address axis + EL1 initiator only. Route 3 ≈
boot-time transform. Route 4 ≈ mode axis, tested at its least informative point.
**The initiator and proxy axes have no route number at all** — which is why they
were never scored, never scheduled, and never closed.

---

## 6. External findings, with provenance

### 6.1 `PRIMARY` — the secure monitor exposes an MMIO proxy, and it is allowlisted

Derived in this audit from the pinned TZ image
(`004-live-firmware-readonly-20260825-01/tz--sdd5.bin`, SHA-256 `a5e6c574…`,
4,194,304 bytes), host-only, no execution.

`PROVED`:

- TZ registers **SMC `0x02000501`** (SIP, service `0x05`, cmd 1 = `SCM_IO_READ`,
  `param_id 0x1`, handler `0x1c03e37c`) and **SMC `0x02000502`**
  (cmd 2 = `SCM_IO_WRITE`, `param_id 0x2`, handler `0x1c03e2e0`).
- The kernel this project boots contains the matching `scm_io_read` /
  `scm_io_write` symbols.
- **Both handlers gate on the same 81-entry address allowlist at `0x1c111238`.**
  A non-matching address returns `-1` before any bus access
  (`cmp w10,wN; b.eq …; cmp x8,#0x50; b.ls loop; → w0 = -1`).
- The 81 entries are all distinct and group as:

  | Block | Entries |
  |---|---:|
  | `0x010a201c … 0x010a239c` (**DCC per-list registers**, stride `0x80`) | 8 |
  | `0x17c000f0 … 0x17c00150` (APCS_GLB) | 25 |
  | `0x18000058 … 0x18070060` (per-core APSS) | 16 |
  | `0x18322934 … 0x183271c8` (APSS cluster) | 24 |
  | `0x17e0041c … 0x17e00434` | 3 |
  | `0x01fd3000`, `0x02ca2204`, `0x02ca24dc`, `0x15002204`, `0x1500251c` | 5 |

- **No entry lies in `0x09000000..0x09800000`.** No remapper, BIMC, SHRM, MCCC,
  MC or DDRSS address is reachable through this interface.

`PROVED`, and independently interesting: the **write** handler special-cases the
DCC range — for `addr − 0x010a201c ≤ 0x380` it clears **bit 3** of the written
value (`and w8, w20, #0xfffffff7`) unless predicate `0x1c054478` returns 1. The
**read** handler conditionally denies 4 of its own allowlisted addresses via a
predicate from the same family (`0x1c03d8cc(1)`).

`SUPPORTED`: `0x1c054478` is a debug/secure-policy evaluator — it queries an
accessor (`0x1c03cf3c`) with small field indices 0/1/4/5 and sits adjacent to the
`security_allows_dump` SMC handler (`0x1c054734`, SMC `0x02000310`).
`UNKNOWN`: the meaning of bit 3 and of the policy fields.

**Two consequences.** (i) The strongest *measured* closure in the project now
belongs to an interface the project never examined — this is a real negative,
obtained host-only, and it is worth more than the contested route-2 negative.
(ii) TZ spends code sanitizing HLOS's DCC configuration **as a function of debug
policy**. That is the CVE-2020-11252 shape, on a block the project has not
looked at, and the project already owns a proven `DLOW ↔ DMID` transition.

### 6.2 `PRIMARY` + `SECONDARY` — DCC is a second bus initiator, present and active

`PROVED` from retained artifacts: the boot DT declares `dcc_v2@10a2000`
(`qcom,dcc-v2`) with `dcc-base`, `dcc-ram-base`, `dcc-ram-offset`, `dcc_timeout`,
and clocks `dcc2_ahb`/`dcc2_apps`. The retained `last_kmsg` shows it **live and
configured**: `dcc_read_config : count: [1053], dcc_offset_addr:[0x10adc0c],
listnr_idx:[451]`. Its config base `0x010a2000` lies in a gap between decoded XPU
regions (`0x800000..0xb00000` and `0x1502000..0x1503000`) — **not covered by any
XPU address region**, and TZ's own SCM allowlist sanctions HLOS access to it.

`SECONDARY` (upstream kernel documentation, LWN/lore, 2022–2023): DCC is *"a DMA
engine designed for debugging"* that *"stores the value at the register
addresses"*, configured from HLOS **debugfs**, and *"the options that the DCC
hardware provides include reading from registers, writing to registers, first
reading and then writing to registers and looping"*. It has a hardware timeout.

This is the missing initiator **and** the missing non-fatal probe in one block.

### 6.3 `PRIMARY` — CVE-2022-22063's mitigation is the opposite of what the project inferred

From the msm8916-mainline advisory: Qualcomm's fix *"disallow[ed] access to the
boot remapper region using the stage 2 translation. The boot remapper
configuration … **is still accessible**, but now both memory regions are
blocked."*

`docs/PRIOR_ART.md` records the fix correctly but does not draw the inference:
**Qualcomm's precedent is to leave a remapper configuration register
Normal-World accessible and mitigate at the destination.** That materially
lowers the prior that SM8150's remapper config *must* be protected, and it
argues for measuring reachability rather than inferring it.

### 6.4 `SECONDARY` — SMEM exposes the DDR address-map parameters directly

Mainline series *"soc: qcom: Expose DDR data from SMEM"* (freedreno list, v2):
platforms **>= SM8150** publish DDR details in **SMEM item 603**, including
`num_channels`, `num_ranks[MAX_CHAN_NUM]`, manufacturer/device type, density,
width, a frequency table, and — critically —
**`highest_bank_addr_bit[MAX_CHAN_NUM][MAX_RANK_NUM]`**, exported to drivers as
`qcom_smem_dram_get_hbb()` and to userspace via `qcom_smem/dram_frequencies`.

HBB is the parameter that fixes the bank/row boundary of the address map. The
project records "rank and channel" as `UNKNOWN` and "no published DRAM
address-mapping function exists for SM8150" — both true of the *literature*, but
the target itself publishes the topology parameters to the Normal World. The
retained kernel contains `ddr_info`, `ddr_type`, `ddr_freq`.

This is a free, read-only, independent cross-check on the DCB-derived
"two 3072 MiB ranks" and on the rank-3 relation.

### 6.5 Re-checked and unchanged

- No published XPU bypass technique found. Upheld.
- No published PPR security research found. Upheld — searched again, still
  patents and vendor material only.
- No published SM8150/SDM855 DRAM address-mapping function. Upheld; the rank-3
  relation still appears new in the public record.

---

## 7. Eight independent perspectives — the surviving objections

Each pass was run against primary evidence, then merged.

1. **SoC / memory-controller architect.** You call `0x09248080` "the remapper"
   on the strength of an XBL ICB writer. LLCC has four instances and its
   registers are HLOS-programmable through `llcc-sm8150`; you never asked
   whether the *system-cache* address transform is separable from the DRAM one.
   Minimum counterexample: an LLCC-visible transform HLOS already configures.

2. **TrustZone / hypervisor / XPU researcher.** You attributed the refusal to
   XPU without a syndrome, and the only fault record you retained is
   **EL2**. Read `hyp_mem` at `0x858df200` before writing another XPU sentence.
   And your HLOS-grant predicate returns the same answer for the LLCC controller
   your own kernel programs and for the page that hung — that is not a predicate,
   it is a constant.

3. **Firmware reverse engineer.** You decoded 5 of 152 SMC records after writing
   a whole verification about decoding 5 of 1,726 XPU records. The layout was
   already in your manifest. This was 20 minutes of work.

4. **DRAM mapping / Rowhammer researcher.** The GF(2) work is the strongest part
   of the project — pre-registered, out-of-sample, 8/8. But you are inferring
   topology from timing while the SoC publishes `num_ranks` and
   `highest_bank_addr_bit` in SMEM. Also: Sudoku's component split is still not
   started, and it is what separates bank from rank from channel.

5. **Kernel / driver researcher.** `CONFIG_DEVMEM=n` closed one door and you
   stopped. `scm_io_read`/`scm_io_write` are in your kernel image. DCC debugfs
   is in your kernel image. Neither appears in any experiment.

6. **Hardware exploit researcher.** Two probe attempts in seventy experiments,
   each costing a reboot, is not a search — it is a sample of size two. Build a
   non-fatal probe before concluding anything about reachability.

7. **Verification / experimental-design reviewer.** The control performs zero
   MMIO loads. The treatment performs one. They differ in the variable under
   test *and* in whether the instrument is exercised at all. That is a
   single-arm study, and the DMID repetition inherits the defect: if the failure
   mode is a hang, disabling XPU produces the same hang, so **the experiment
   cannot detect its own hypothesis**.

8. **Skeptical blue-team reviewer.** Most of this holds up and the discipline is
   unusually good. The honest read is milder than the report's: you have a
   well-characterised transform, no evidence it is mutable, and no evidence
   anyone in the Normal World can reach it — but also no positive evidence that
   the boundary is what stopped you. "Nothing worked" and "it is protected" are
   different findings, and the report merges them.

**Merged.** Seven of eight converge on one thing: *the project's negative
results are real, but their attribution is not.* Perspective 8's counter-point
also holds — nothing found here is a boundary-bypass indicator.

---

## 8. New hypotheses

| # | Hypothesis | Different from prior work because | Discriminator | Cost / risk | If it fails, what closes |
|---|---|---|---|---|---|
| **H1** | DCC can issue MMIO reads to apertures the CPU cannot, as a distinct initiator | The initiator axis has never been touched | Program DCC to read (a) a known-good register, (b) `0x09248080`, (c) an unmapped address; compare stored words and status | low; DCC config volatile, no persistence, **read-only** | if DCC is denied identically, the "target-side, all initiators equal" claim becomes *measured* rather than quoted |
| **H2** | The refusal is a **stage-2/EL2** abort, not an XPU denial | Nobody has read the retained EL2 record | Export `hyp_mem` around `0x858df200` via the already-proven Samsung Upload path; read ESR_EL2/FAR_EL2/ELR_EL2 | low; read-only, path already `PROVED` in V012 | pins the protection identity either way; changes which literature applies |
| **H3** | The hang is bus/clock, not protection | The positive control was never run | Same inline path, one load at an HLOS-mapped register (e.g. GCC), same harness | low; one reboot | **makes every previous refusal interpretable**; without it none are |
| **H4** | SMEM item 603 supplies `num_channels`, `num_ranks`, HBB | Topology has only ever been inferred from DCB or timing | Read SMEM 603 | trivial, read-only | independently validates or refutes the rank-3 model and the 2×3072 MiB claim |
| **H5** | A real DDR OPP change exercises a firmware path deep suspend does not | Subsumption replaced the measurement (§2.4) | Break the static `disp_rsc_ebi` vote (blank display / devfreq), confirm frequency moved, re-run the tag-invariance test | low, reversible | closes the AOP-retraining row by test rather than assertion |
| **H6** | The XPU region tables are not the enforced runtime policy | Falsified prediction already in hand (§2.2) | Static: find where/whether the tables are applied and what overrides them. Live: DCC-read an XPU status register | low, host-only first | re-grades every claim citing those tables |
| **H7** | The remaining 147 SMC records contain a reachable memory/DDR service | 3.3% decoded | Decode all 152; classify by service; disassemble handlers for any touching `0x09xxxxxx` | trivial, host-only | either finds a proxy or produces the project's second exact closure |
| **H8** | *(downgrade)* The transform has no configurable field at all | The project assumes P1 is open; it may be structurally absent | Look for a *write* path to any bank/interleave field in XBL/TZ/AOP, not just a read | host-only | if no writer exists anywhere in the boot chain, Class C should become Class B |

H1–H3 are the ones that change interpretation of existing evidence rather than
adding new evidence. **H3 is a prerequisite for reading H1's result.**

Hypotheses deliberately *not* invented: nothing here proposes a novel exploit
primitive, because the audit found no evidence supporting one. The shortage of
offensive hypotheses is itself a finding — the transform is well-characterised
and no writer has been located in any firmware examined.

---

## 9. Class C stress test, both directions

### A. Could it be higher than Class C?

**No, on current evidence** — but for a weaker reason than the project states.
Class D requires "protected boundary reached but blocked by later enforcement".
Nothing was reached. The `UNKNOWN`s that could connect are H1 (a second
initiator), H2 (a stage-2 rather than XPU boundary) and H7 (an undiscovered
proxy). All three are *reachability* questions, and all three are open. So the
distance to Class D is **not measured**, it is unexplored.

### B. Could it be lower than Class C?

**Plausibly, and this deserves more weight than the project gives it.**

- The class label reads "normal-RAM **transform/alias** only". The project has
  the transform and explicitly **not** the alias. Half the label is unearned.
- Class B is "observable but immutable." The project has never located a *writer*
  for any bank/interleave field — not in XBL, not in TZ, not in AOP. P1 is
  labelled `UNKNOWN` on the grounds that nothing measured it, which is correct;
  but "no writer found anywhere in three firmware images" is at least weak
  evidence *for* immutability, and it is currently recorded as evidence for
  nothing.
- Skitter's premise is a **reprogrammable** transform. A fixed XOR hash burned in
  at DDR training is not a Skitter primitive at all, however well characterised.

`docs/FINAL_REPORT` says "the premise is structurally available." That sentence
is doing real work and is supported only by the *existence* of a transform, not
by any evidence of configurability. **Recommendation: keep `CLASS C` but restate
it as "transform only, alias unobserved", and record the no-writer-found result
as `SUPPORTED` evidence toward Class B rather than as silence.**

Symmetrically: nothing in this audit is a boundary-bypass indicator, and the
stop condition does not fire.

---

## 10. Measurement capability gaps — build these before the next experiment

| Gap | Consequence today | Fix | Unblocks |
|---|---|---|---|
| **No positive control for MMIO reads** | every "unreachable" is uninterpretable | one load at an HLOS-readable register through the identical inline path | H1, H3, and retroactively **all** prior refusals |
| **No non-fatal MMIO probe** | 2 addresses in 70 experiments | **DCC** — hardware timeout, status instead of a hang | H1, H6, large-scale aperture sweeps |
| **No fault-syndrome observer** | protection identity assumed | read the retained EL2 record; decode TZ log if possible | H2 |
| **No physical-address oracle** | `pa_provenance: BLIND`, corpus cannot pool | kernel-side `dma_buf`/`sg_table` walk in the runtime already booted | PA28 provenance, corpus pooling |
| **No topology ground truth** | rank/channel `UNKNOWN` | SMEM item 603 | H4, Sudoku component split |
| **No complete SMC inventory** | proxy axis unassessed | decode all 152 records | H7 |

**One capability dominates: DCC.** It supplies the non-fatal probe *and* the
second initiator *and*, incidentally, a positive control — three gaps with one
build. That is why it ranks first below.

---

## 11. Next experiments, ranked by information gain

| Rank | Experiment | Hypotheses separated | Failure still useful? | Risk | Class |
|---:|---|---|---|---|---|
| **1** | **Decode all 152 TZ SMC records; disassemble any handler touching `0x09xxxxxx` or DDR** | H7, H6 | yes — an exact second closure | none (host-only) | static |
| **2** | **MMIO positive control** — one load at an HLOS-readable register, identical harness | H3 → gates H1 | yes — either way it repairs the record | one reboot; recovery proven | live, read |
| **3** | **Read the retained EL2 fault record** (`hyp_mem` @ `0x858df200`) | H2 | yes — pins protection identity | read-only; V012 path proven | live, read |
| ~~4~~ | ~~**DCC read-only probe**~~ — **WITHDRAWN, see Corrections** | H1, H3, H6 | — | **not read-only**; configuring it resets a live production list | **not eligible** |
| **5** | **SMEM item 603** | H4 | yes | trivial | live, read |
| **6** | **Forced DDR OPP change + tag invariance** | H5 | yes — closes route 4 row by test | reversible | live, read |
| **7** | Re-derive the VMID encoding from TZ's own `tzbsp_mpu_partition_config`, then re-grade every document citing "no HLOS VMID grant" | fixes §2.2 for good | yes | none | static |
| **8** | Sudoku component split (bank vs rank vs channel) | model resolution | yes | none beyond existing | live, read |
| 9 | Carry-phase lever for PA28 base | provenance | yes | none | live, read |

Every one of the top six is **read-only** and inside the standing authorization.
None requires a controller write, a protected-memory operation, or a mandatory
pause gate. Items 1–3 need no new tooling at all.

Note the ordering criterion: items 1–3 change the *interpretation of evidence
already collected*. Item 4 is the first that collects genuinely new evidence, and
it is deliberately placed after its own prerequisite (item 2).

---

## 12. Conclusion

**`CLASS C (TRANSFORM ONLY)` / `NOT_ELIGIBLE` stands, and no boundary-bypass
indicator was found. But it stands on a narrower base than the project's own
final report claims, and two of its four supporting routes must be reopened.**

Specifically:

1. **The positive results are sound and are the best part of the project.** The
   GF(2) bank relation — rank ≥ 3, pre-registered, 8/8 out-of-sample, 771/774
   corpus — survives the audit intact and appears to be new in the public record.
   Route 3 is genuinely closed, three times over.

2. **Route 2 is not closed by "measured access control".** The refusal
   experiment has no positive control, its instrument has never completed an
   MMIO read at any address, and the DMID repetition therefore cannot detect the
   very hypothesis it was designed to test. The manifest label
   `SUPPORTED_NOT_PROVED_CAUSAL` was correct and the report's `PROVED`/"measured"
   is an escalation.

3. **The static XPU argument is right for the wrong reason.** The HLOS-grant
   test keys on VMID bit 3 and returns "denied" for five DDRSS pages the live
   device tree hands to HLOS drivers — including the LLCC controller itself — so
   it has no discriminating power. Under the corrected bit (30 = non-secure) the
   policy discriminates 6 for 6, and `0x09248000` is the **only** page in its
   neighbourhood denied to HLOS: the conclusion is better supported than before,
   while the "three independent coverings" claim collapses to one and the
   published grant counts (21/109) are wrong (60/109).

4. **Route 4 is closed only for deep suspend.** The subsumption argument
   confuses perturbation magnitude with code-path coverage, and the one
   experiment that would have exercised the AOP retraining path was vacuous.

5. **The search space was never swept on the initiator or proxy axes.** Two
   interfaces that exist on this exact target were never examined: the TZ MMIO
   proxy (whose **on-disk** 81-entry allowlist contains no DDRSS address) and
   **DCC**, a live second bus initiator with 1053 configured entries, a hardware
   timeout, and TZ code that sanitizes HLOS's configuration of it as a function
   of debug policy.

6. **The binding constraint was never the authority — it was the instrument.**
   Two probe attempts in seventy experiments, because each costs a reset. A
   non-fatal probe is still the single highest-value capability this project
   could build — but **DCC is not it**, for the reason in Corrections.

The correct form of the conclusion is therefore **not** "the transform is
reachable only from behind an access-control boundary that held every time it was
tested," but:

> The transform is well characterised and no Normal-World path to it has been
> found. Whether the paths tried were *refused* — rather than merely
> unproductive — is not yet established, because the instrument that tried them
> has never succeeded anywhere. Two interfaces that could answer this were never
> examined; one is default-denied by its on-disk table, and the other is open but
> is not the cheap read-only probe this audit first took it for.

Classification unchanged. Stop condition not triggered. No write is authorised
or recommended by this audit; every proposed next step is read-only.

---

## Corrections — 2026-08-29

Four claims in this document were wrong or overstated. All four were caught by
the second adversarial audit
(`docs/INDEPENDENT_ADVERSARIAL_RESEARCH_AUDIT_2026-08-28.md`) and then verified
independently here against the pinned artifacts. They are recorded rather than
quietly amended.

| # | Original claim | Correct form | How it was settled |
|---|---|---|---|
| C1 | "bit 30 **is** the non-secure/HLOS class bit" (§2.2) | bit 30 separates this six-address sample; bit 3 separates none of it. The **actor name is not established** | naming withdrawn; the bit-3 falsification was independently `CONFIRMED` |
| C2 | DCC is a "read-only probe, no `config_write`", ranked 4 and called the highest-value capability (§6.2, §11) | **DCC is not read-only.** Building a read list writes `DCC_LL_CFG/BASE/LOCK/SW_TRIGGER`, and `dcc_enable()` runs `__dcc_config_reset()`, destroying the 1053 entries already configured in production | verified in `dcc_v2.c` of the exact target kernel; row withdrawn |
| C3 | SCM_IO is "closed, exactly, by an 81-entry allowlist" (§6.1, §12) | `PROVED` for the **on-disk image**; `UNKNOWN` at runtime — the table at `0x1c111238` is in LOAD segment 11, flags **RW**, as is the 152-record dispatch table | verified from the TZ ELF program headers |
| C4 | the watchdog pets come from "the same boot that produced the route-2 negative" (§2.2) | that boot is Verification 023, candidate `7ee6a41f…`, reading the **SHRM** word `0x0906566c` — not the remapper. `FINAL_REPORT` §8 lists closing this address substitution as open work | verified from the V023 manifest |

C1, C2 and C3 share one signature, and it is the same defect §2.1 reports
against `FINAL_REPORT`: **a bounded fact about a static artifact stated as a
claim about the live system, one notch too strong.** This audit named that
defect and then committed it three times.

What the corrections do **not** touch: the bit-3 predicate falsification (§2.2),
the `CNOC_AOSS_MPU` live counterexample (§2.2), the missing MMIO positive
control (§2.1), the 152-record dispatch table (§2.5), the deep-suspend
subsumption argument (§2.4), and the retained EL2 fault record (§2.3). Each of
those was put to the second audit and returned `CONFIRMED`, except the *cause*
of the route-2 non-return, which both audits now record as `UNDECIDABLE`.

---

## Provenance and method

### What produced this audit

| | |
|---|---|
| Model | **Claude Opus 5** — exact model ID `claude-opus-5` |
| Reasoning effort | **`xhigh`** — `modelSettings["claude-opus-5"].effortLevel` in `~/.claude/settings.json`, corroborated by `CLAUDE_EFFORT=xhigh` in the environment |
| Extended thinking | enabled (`alwaysThinkingEnabled: true`) |
| Harness | Claude Code CLI, single interactive session, 2026-08-28 |
| Subagents | **none** — see the independence caveat below |
| Role | independent adversarial verification of the concurrent Codex line |

### Exact inputs

Every new result in this document is derived host-only from these pinned
artifacts. No device, MMIO, SMC or firmware write occurred at any point.

| Artifact | SHA-256 | Size | Used for |
|---|---|---:|---|
| Repository state audited | commit `3715135` (*research: close V024 DMID refusal*) | — | the tree every claim is graded against |
| TrustZone image `tz--sdd5.bin` | `a5e6c574e18e2e576a25df6274b20bdb142386811dfda6383f86d7b1b3c102ab` | 4,194,304 | §2.2 XPU regions, §2.5 SMC table, §6.1 allowlist |
| `last_kmsg` at DMID | `fdceab48dc267dd74ec6c70edbec6b51ee13dcd8532cf8b121c4fe93b425c66e` | 2,097,136 | §2.2 watchdog pets, §2.3 EL2 record, §6.2 DCC |
| Boot image `boot_linux_inline_remapper_read_v1.img` | `6fe92825702f304a067fc716c3814a63b2f4e76198a054de4c666cad55a462ed` | — | flattened device tree: DDRSS nodes, `wdt@17c10000`, `dcc_v2@10a2000`, GIC reg |

The boot-image hash equals `read.candidate_sha256` in
`evidence/manifests/007-inline-remapper-read-watchdog-20260825-01.manifest.json`,
so the device tree read here is the same image the route-2 probe ran from.

The XPU region walk reproduces `verification-025/026` exactly (109 address
regions, both selector branches). Regenerating tool:
`tools/sm8150_tz_smc_and_io_allowlist.py`; manifest:
`evidence/manifests/audit-tz-smc-io-allowlist-20260828-01.manifest.json`,
verified byte-identical on regeneration.

### Independence caveat — read this before weighing §7

The eight perspectives in §7 were run **inside one model context, sequentially,
by one model**. They are not independent observers. Each pass could see
everything the previous passes had concluded, and all eight share the same
priors, the same reading of the evidence, and the same blind spots. Convergence
among them is therefore **weak** evidence — it mostly measures internal
consistency, not agreement between separate judgements.

The same limitation applies to the audit as a whole. It was produced by a single
model in a single session, and its most consequential findings (§2.1, §2.2) turn
on interpretation rather than on arithmetic. Where this document says a claim is
`REFUTED`, that verdict deserves an independent check by a different model or
person against the same pinned artifacts above.

A genuinely independent replication should start from commit `3715135` — the
state this audit was written against, and the last commit before it — so that
the replicating agent cannot read these conclusions before forming its own.

### Repair recorded

This provenance section was added after the fact. The original commit pinned the
input artifacts by hash but **did not pin the repository state it audited**,
which is exactly the binding this project requires everywhere else and the same
class of omission the audit criticises in §2.5. It is recorded as a repair
rather than silently amended.

---

*Prepared 2026-08-28 as an independent adversarial audit of the `CLASS C (TRANSFORM ONLY)` conclusion. Inputs, model, effort level and method limitations are pinned in the section above.*
