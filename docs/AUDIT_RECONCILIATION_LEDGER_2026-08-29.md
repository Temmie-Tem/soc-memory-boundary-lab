# Reconciliation ledger — two adversarial audits, 2026-08-29

Two independent-adversarial audits of the same `CLASS C (TRANSFORM ONLY)`
conclusion now exist. This ledger grades one against the other, claim by claim,
against the pinned artifacts both cite.

| | Audit A | Audit B |
|---|---|---|
| Document | `docs/ADVERSARIAL_AUDIT_2026-08-28.md` | `docs/INDEPENDENT_ADVERSARIAL_RESEARCH_AUDIT_2026-08-28.md` |
| Producer | Claude Opus 5 (`claude-opus-5`), effort `xhigh` | `gpt-daybreak-blue-latest`, effort `max`, plus 3 role-separated auditor subagents |
| Tree audited | `3715135` | `4ea9680` (tip `c45d863`) |
| Independence | wrote first, saw nothing of B | **read A** — cites commit `4ba9400` as a cross-check input |

**These are not two independent audits.** B read A and explicitly declined to
inherit its conclusions as authority. So agreement between them is only strong
where B derived the finding from *different evidence*; that distinction is
carried in every row below. A's own §7 carries the mirror-image caveat: its
eight perspectives ran inside one context and are not independent either.

This pass is A grading B. B already graded A. Neither side wrote the merged
verdict alone.

---

## 1. B's claims, graded by A — all CONFIRMED

### 1.1 V016's high-bit conclusion turns on a statistic choice — `CONFIRMED`

B's claim: the probe takes an upper median of an even sample; the two decisive
differences are exact 16/16 mixtures; the lower statistic flips both; there is
no retained preregistration.

Recomputed independently from `pa25-27-heldout.jsonl` (288 retained per-pair
deltas, 9 differences × 32 pairs). **Every number B reports is exact.**

| difference | lower med | upper med | emitted | `> 299` |
|---|---:|---:|---:|---:|
| `0x16000` (control) | 537 | 537 | 537 | 32/32 |
| `0x2000` (control) | 130 | 133 | 133 | 0/32 |
| **`0x6084000`** | **226** | **475** | 475 | **16/32** |
| **`0xc180000`** | **223** | **437** | 437 | **16/32** |
| `0xa202000` | 487 | 509 | 509 | 18/32 |
| `0xa104000` | 490 | 496 | 496 | 18/32 |
| `0x6000000` | 145 | 149 | 149 | 0/32 |
| `0xc000000` | 149 | 149 | 149 | 0/32 |
| `0xa004000` | 152 | 161 | 161 | 6/32 |

`tools/a90_region_probe_r.c:448` emits `deltas[used / 2]` — for `used = 32` that
is index 16, the **upper** median, neither the lower nor the even-N mean.

Only the two differences that carry the high-bit conclusion are perfect 16/16
splits. Every other difference is decisively one-sided. That is a mixture
signature, and it is what B's base-carry hypothesis predicts.

Reconstructing the widest-gap threshold under each statistic:

```
upper (as shipped) : widest gap 161 -> 437,  threshold 299  -> both CONFLICT
lower              : widest gap 226 -> 487,  threshold 356  -> both negative
labels that flip   : exactly 0x6084000 and 0xc180000
```

Agreement falls from 7/7 to **5/7**, matching B exactly.

**Preregistration:** `tools/a90_high_bit_relation_analysis.py` has exactly one
commit in its history — `746def0`, *the commit that integrates the result*. It
hardcodes `EXPECTED_SPLITS`, `EXPECTED_MATCHES`, `EXPECTED_TRIPLETS`,
`EXPECTED_HELDOUT`, `EXPECTED_LOWER_EQUALITIES` and **asserts equality against
them** (lines 1391, 1410, 1426, 1429, 1513, 1527), so a different observation
raises rather than reports. V028 pre-registered at `3799238` and V029 at
`c52f2f5`; V016 did not, and V016 is the one whose verdict moves with the
statistic.

This is the project's own tautological-verifier failure pattern, recurring.
**Audit A did not examine V016 at all.**

### 1.2 The XPU analyzer emits a fixed narrative and discards the evidence — `CONFIRMED`

`sm8150_xpu_policy_inventory.py` sets `static_policy_interpretation` to one
hardcoded sentence — *"TZ-owned; TZ owner read/write; MSA-class read-only; no
standard VMID permission and no HLOS VMID bit"* — for **every** region,
independent of its actual client vector.

`sm8150_xpu_initializer_inventory.py::_format_policy_hit` computes
`decode_mpu_region_permissions(...)` — producing `client_permission_bytes`,
`client_permission_fields`, `multi_vmid_permission_words` — and then returns
only `owner`, `hlos_read`, `hlos_write`. The client vector is computed and
thrown away.

**This is convergence on different evidence.** B found the *formatter* defect;
A found the *predicate* defect (VMID bit 3 has no discriminating power, plus
live device-tree counterexamples). Neither derivation depends on the other, so
this row is strong corroboration despite B having read A.

### 1.3 DCC is not a read-only observer — `CONFIRMED`, and it refutes A

`dcc_v2.c` (2,017 lines, exact target kernel). Building a *read* list is a
sequence of MMIO writes — `DCC_LL_CFG`, `DCC_LL_BASE`, `DCC_FD_BASE`,
`DCC_LL_LOCK`, `DCC_LL_SW_TRIGGER` — and `dcc_enable()` runs
`__dcc_config_reset()`, which destroys the existing configuration. The retained
crash dump shows **1053 entries already configured** in production, so a probe
would wipe Samsung's live crash-capture list.

A's §6.2 and §11 called DCC "read-only, no `config_write`" and ranked it the
single highest-value capability to build. **A was wrong.**

### 1.4 The SCM_IO allowlist is not a closure — `CONFIRMED`, and it bounds A

B: the on-disk allowlist default-denies the DDRSS band, but the table is in an
RW segment, so the runtime value is `UNKNOWN`.

Verified from the TZ ELF program headers: `0x1c111238` falls in LOAD segment 11,
vaddr `0x1c111000`, memsz `0x1a588`, flags **RW**. The 152-record SMC dispatch
table at `0x1c12a4c8` is in the same writable segment — consistent with a table
populated by runtime registration.

So A's §6.1 is correct as a statement about the **image** and overstated as a
statement about the **interface**. Correct form: `PROVED` that the on-disk
initial allowlist has 81 entries with none in `0x09000000..0x09800000`;
`UNKNOWN` whether the runtime table still holds those 81.

---

## 2. Corrections to Audit A, and the pattern behind them

Three of A's claims are corrected above. They share one signature:

> **A converts a bounded fact about a static artifact into a claim about the
> live system, one notch too strong.**

| A's claim | Correct form |
|---|---|
| "bit 30 **is** the non-secure/HLOS class bit" (§2.2) | bit 30 separates the sample 6/6; the actor name is not established. A's own manifest labelled this `SUPPORTED` — the prose was stronger than the artifact |
| "DCC — read-only, no mutation, highest-value" (§6.2, §11) | DCC configuration is an MMIO write sequence that resets a live production list |
| "SCM_IO … closed by an exact allowlist" (§6.1) | on-disk default-deny; runtime table `UNKNOWN` because the segment is RW |

This is the same defect A diagnosed in `FINAL_REPORT` §2.1 — a manifest-level
`SUPPORTED` becoming a report-level `PROVED`. A committed it three times while
naming it. Recorded rather than quietly amended.

---

## 3. Claims A raised that B did not engage — now adjudicated

B's report text still shows **zero** occurrences of `wdt@17c10000`,
`pet_watchdog`, `msm_watchdog`, `llcc@9200000`, `0x40000000`, `CNOC_AOSS`,
`ESR_EL2` and `858df200`. On request, B adjudicated them separately:

| item | B's verdict |
|---|---|
| A1 — the VMID bit-3 predicate does not discriminate | **CONFIRMED**, bounded to this six-address set |
| A2 — `CNOC_AOSS_MPU` live counterexample | **CONFIRMED** |
| B1 — a retained HYP/EL2 fault record exists and is the only structurally recognised one | **CONFIRMED** |
| B2 — the refusing agent is stage-2/QHEE | **UNDECIDABLE** |

B's A2 verification went further than A's: it traced `pet_watchdog()` in
`watchdog_v2.c` and established that the driver reads `WDT0_STS`, writes
`WDT0_RST`, and reads `WDT0_BARK_TIME`/`BITE_TIME` **before** emitting the log
line, so the nine retained log entries prove successful HLOS-issued MMIO reads
*and* writes at `0x17c10000`, not merely that a thread ran.

B2 is correct and A never claimed otherwise — A labelled it `HYPOTHESIS H2`.
Three readings survive: XPU blocked the transaction and QHEE recorded the
resulting external abort; a stage-2 permission fault preceded XPU; or the abort
is unrelated to the probe. `Found[...]` locates field positions, not values, and
the values are not printed in the retained file.

**B also produced a provenance correction that lands on A** — see C4 in A's
Corrections. The V023 run behind the `fdceab48…` dump used candidate
`7ee6a41f…`, whose `snapshot_physical_address` is the SHRM word `0x0906566c`,
not the remapper. Verified here from the V023 manifest, and `FINAL_REPORT` §8
independently lists closing that address substitution as open work. B notes a
separate V024 dump `ee0d2548…`, bound to the remapper candidate `6fe92825…`,
carries the same HYP markers, so remapper relevance survives while causality
does not.

The joint verdict on route 2 is therefore:

> **non-return `CONFIRMED`; the refusing agent — XPU, stage-2/QHEE, or the
> instrument — `UNDECIDABLE`.**

Neither audit defends `FINAL_REPORT`'s "measured access control".

### The original statement of these items

Measured over B's text: `wdt@17c10000`, `pet_watchdog`, `msm_watchdog`,
`llcc@9200000`, `0x40000000`, `CNOC_AOSS`, `ESR_EL2`, `858df200` all return
**zero** occurrences.

1. **The XPU live falsification, as distinct from the naming.** B corrected A's
   *label* for bit 30 but never ruled on A's *fact*: that the shipped
   `hlos_present_in_*_mask` predicate returns `False` for five DDRSS pages the
   live device tree hands to HLOS drivers (`llcc@9200000`, `syscon@90b0000`,
   `llcc-pmu@90cc000`, `cpu-llcc-ddr-bwmon@90cd000`, `cpu-cpu-llcc-bwmon@90b6400`)
   and for the probed remapper word alike — i.e. it does not discriminate. And
   that HLOS reads and writes MMIO inside `CNOC_AOSS_MPU` region 5
   (`0x17c00000..0x18200000`, read and write VMID `0x00000000`) continuously:
   the retained `last_kmsg` records `msm_watchdog 17c10000.qcom,wdt:
   [pet_watchdog]` at ~9.47 s intervals from 9.95 s to 85.7 s.

   B's §1.4 reaches a compatible conclusion from static evidence only. A's live
   counterexample would harden it. **Not mentioned is not agreement.**

2. **The retained EL2 fault record.** The same dump carries
   `log_addr:858df200 log_size:1e00 offset:6b4 wrap:0` followed by the upload
   parser locating `Found[Data abort]`, `Found[Faulting Address]`,
   `Found[ESR_EL2]`, `Found[FAR_EL2]`, `Found[ELR_EL2]`, while
   `print_noc_info`, `print_xpu_info` and `print_smmu_info` all report
   `tz log is encrypted or not parsed yet!`. The only parseable fault record in
   the dump is an **EL2** one and nobody has read it. This bears directly on
   B's own §9.1 chain 4 (QHEE/stage-2) and its §11 rank 3.

---

## 4. Produced during this grading pass

**`camera_preview` is the RBIN heap — `PROVED`, from evidence already retained.**

A had flagged, as an open precondition for the V030 RBIN oracle, that no
retained artifact bound `camera_preview` to the RBIN heap type. It does:

```json
{"type":"ion_heap","name":"camera_preview","heap_type":10,"heap_id":30}
```

— emitted by the V016 probe run, and `include/uapi/linux/msm_ion.h` in the exact
target kernel gives `ION_HEAP_TYPE_MSM_START = 6`, so
`SECURE_DMA=6, SYSTEM_SECURE=7, HYP_CMA=8, SECURE_CARVEOUT=9,`
**`ION_HEAP_TYPE_RBIN = 10`**.

No execution was needed. The precondition closes on retained evidence.

---

## 5. Where each audit is stronger

**B is stronger at:**

- **V016.** An entire experiment A never opened, and the finding stands.
- **External sourcing (§6).** `PRIMARY`/`SECONDARY`/`INFERRED` grading with URLs,
  dates and a per-row "limit for exact A90". Includes material A missed:
  CVE-2019-2274 (secure-processor RPU write access control, SM8150-inclusive),
  the AOP DDR/PASR/mem-offline sources that make A's deep-suspend argument a
  *sourced* one rather than an a-priori one, ZenHammer on allocation-base
  effects, and the Qualcomm access-control whitepaper establishing that XPU is
  the intersection of initiator attribute and target policy.
- **§9.3's 13-axis verdict vector**, which is a better instrument than a single
  ordinal class. A only proposed restating Class C.
- **§9.2-3, check-after-transform**: XPU may sit after SMMU but *before* the MC
  bank/row transform, so the threat model's check-before premise may not hold.
  A did not construct this downgrade argument.

**A is stronger at:**

- **Live falsification.** B's XPU critique is entirely static. A's rests on the
  retained `last_kmsg` and boot device tree from the same boot that produced the
  route-2 negative.
- **The EL2 fault record**, untouched by B.
- **The SCM_IO interface decoded rather than cited**: the 81 entries grouped by
  block, the DCC-range write sanitization (bit 3 cleared unless a debug-policy
  predicate passes), and the read handler's conditional denial of four of its
  own allowlisted addresses.

---

## 6. Standing disagreements

None on fact. Every point of contact above resolved against a pinned artifact by
recomputation, and in each case one side was simply right.

The open items are **interpretive**, and they are not settleable by argument:

| Question | Status | What would decide it |
|---|---|---|
| Is the route-2 non-return a refusal, a stage-2 fault, or an instrument failure? | **jointly `UNDECIDABLE`** — adjudicated, not merely unexamined | MMIO positive control on a known-readable register, then the DC_NOC ladder; and decoding the retained EL2 record |
| Do the XPU region tables describe the enforced runtime policy? | A: falsified as an access-control claim. B: raw fact real, actor/path `UNKNOWN` | full client-vector analyzer repair (B §11 rank 1), plus a live read of an HLOS-granted DDRSS page |
| Is `MAP-HIGH-PA25_28` physical? | B: reopened. A: silent | SG/PFN oracle, then a blinded high-bit OOS with retained preregistration |

Both audits agree on the bottom line, and neither weakened it: **no Class D or E
evidence exists, and the bounded low-bit result is the part that survives.**

---

## 7. Provenance of this ledger

| | |
|---|---|
| Produced by | Claude Opus 5 (`claude-opus-5`), effort `xhigh`, no subagents |
| A graded at | `4ba9400` + the corrections committed alongside this file |
| B graded at | `072cac8e…`, 775 lines |
| B re-checked at finalisation | `d95d2998…`, 780 lines — every claim graded in §1 is present unchanged, with identical numbers (`226/475`, `223/437`, `16/32`, `299`→`356`, `5/7`, `deltas[used/2]`, `0x1c111238`, RW). The grading stands against the current text |
| B's four verdicts in §3 | delivered in review, **not yet written into B's document** |

Everything in §1 was re-derived here from the pinned inputs rather than accepted
from B's text: the V016 recomputation from 288 retained per-pair deltas, the two
analyzer defects from source, `dcc_v2.c`, and the TZ ELF program headers.

---

## 8. Correction to this ledger — verdict pass on final report v2

Produced while adjudicating `docs/FINAL_REPORT_2026-08-29.md` at `791cf5f`.
Two entries above are stale or too strong.

### 8.1 §1.2's second half is narrowed — `C5`

§1.2 graded B's claim `CONFIRMED` in two halves and titled the row *"discards
the evidence."* The first half — the hardcoded `static_policy_interpretation`
narrative, emitted identically for every region — stands unchanged and is the
serious defect. The second half does not.

`client_permission_bytes` is not a retained datum. The MPU region record is
32 bytes, `<IIIIQQ` = `index, flags, read_vmid, write_vmid, start, end`; it
carries **no client-permission field**. `decode_mpu_region_permissions`
synthesises the vector from `flags` plus four hardcoded bit tests on
`read_vmid`/`write_vmid`. For the exact tested DC_NOC region
`0x09248000..0x09249000` (`read_vmid 0x80000000`, `write_vmid 0x00000000`,
owner `TZ`) the whole derivation is two steps:

```text
read_vmid bit 31 set      -> client_byte0 |= 0x10
flags TZ owner branch     -> client_byte0 |= 0x01, client_byte1 |= 0x08
                          => 0x11, 0x08
=> nonsecure_client_ro_vector = (0x11 >> 3) & 7 = 2
```

`nonsecure_client_ro_vector = 2` is therefore a restatement of *one raw bit*,
`read_vmid` bit 31 — not an independent grant to a non-secure client. Because
`flags`, `read_vmid` and `write_vmid` are all retained by
`sm8150_xpu_initializer_inventory.py`, discarding the computed vector loses
**zero** information. "Computed and thrown away" was right; "discards the
evidence" was not.

Audit A §2.8 had already recorded this at `MEDIUM` confidence — *"the
'non-standard construction' is partly a property of this project's decoder …
the raw asymmetry survives; the narrative built on it does not"* — and this
ledger failed to carry it into §1.2. The error is mine, not B's.

Consequences, in scope order:

- B's `POSSIBLE COUNTEREXAMPLE` in §1.4 — *"broad regions have non-owner client
  write bits"* — reduces to "`write_vmid` has bits set." True, but not a
  separate finding, and not evidence about client identity.
- **No verdict changes.** `FINAL-XPU/POLICY-PATH` remains `UNKNOWN`; the
  non-discriminating bit-3 predicate, instance/path/overlap selection and the
  absent live policy readback each carry that axis on their own.
- The correction tally in v2 §6 becomes `A -> B: 1 (narrowing)`,
  `B -> A: 4`. The measured asymmetry stands.

The signature is the same one recorded in §2: **a bounded fact about a static
artifact stated one notch too strong** — here, a decoder output named as
retained evidence. It survived two audits and a reconciliation pass because
both auditors were arguing about whether the vector was *kept*, and neither
re-derived where it came from.

### 8.2 §7's last row is stale

`B's four verdicts in §3` was recorded as *"delivered in review, not yet
written into B's document."* They were written in at `f9ec259`, as
§1.4.1 of `docs/INDEPENDENT_ADVERSARIAL_RESEARCH_AUDIT_2026-08-28.md`
(+27 lines), with the derivations and the V023/V024 provenance split intact.
That row is closed.
