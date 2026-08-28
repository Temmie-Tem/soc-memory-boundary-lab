# Does Skitter apply to SM8150? — final report v2, 2026-08-29

Status: **DRAFT — current successor synthesis on `main`; awaiting the Audit A
author's adjudication pass before final designation.**

Author: **the Audit B author**, Codex Desktop session
`01a048c9-9f97-7f22-b319-46a0d38130d4`; requested model ID
`gpt-daybreak-blue-latest`; reasoning effort `max`. Reviewer: **PENDING**,
Audit A author using `claude-opus-5`, effort `xhigh`.

**Current result: `NO_BOUNDARY_BYPASS_OBSERVED`. The operational label remains
`CLASS C (TRANSFORM ONLY)` / `NOT_ELIGIBLE`, but its precise meaning is
`C-MAP only; C-ALIAS/C-MUTATION/C-REACH/C-ORDER unresolved`.**

The defensible conclusion is:

> A bounded low-bit timing-equivalence transform is strongly supported. The
> high-bit physical relation, transform mutability, alternate-initiator reach,
> final XPU/policy path, protection order, complete global alias, and fault
> enabler remain unresolved. No Class D/E effect has been observed.

This document supersedes [the 2026-08-27 final report](FINAL_REPORT_2026-08-27.md)
as the current synthesis. The older report is retained, apart from a supersede
banner, because both adversarial audits quote its exact sections and sentences.

Exact scope: Samsung Galaxy A90 5G `SM-A908N`, Qualcomm `SM8150`, bootloader
`A908NKSU5EWA3`, kernel `4.14.190-25818860-abA908NKSU5EWA3`. Every verdict is
bounded to the retained artifacts, builds, states, addresses, and observers
named by the linked audits and ledger.

## 1. Classification guardrail

This revision uses the operator-selected option of retaining the existing
`CLASS C` label while replacing its evidentiary explanation with the axis-by-axis
vector below. It does **not** claim that an alias was observed merely because
the historical taxonomy names Class C “transform/alias only.”

Changing from the ordinal taxonomy to the vector as the formal classification
is an operator decision. That transition point is explicit:

1. pause the autonomous loop because the exact `CLASS C (TRANSFORM ONLY)`
   objective and pause/termination conditions would no longer match;
2. rewrite the objective and the mandatory-pause and loop-termination gates in
   `GOAL.md`;
3. update the decision-class definitions and current status atomically; and
4. resume only after the operator accepts the new taxonomy and authority scope.

None of those transition actions is taken in this draft. `GOAL.md` is unchanged.

## 2. The 13-axis verdict vector

This is the load-bearing result. A single ordinal cannot express the different
grades of evidence without converting `UNKNOWN` into agreement.

| Axis | Current verdict | Exact boundary |
|---|---|---|
| `MAP-KERNEL-PA13_23` | **STRONGLY SUPPORTED / bounded timing-equivalence** | Experiment 014, independent V027 recovery, and V029 low-bit 8/8 OOS support the same kernel. This is not yet a semantic channel/rank/bank label. |
| `MODEL-RANK-FLOOR-THROUGH-PA24` | **SUPPORTED / bounded allocation-model coordinates** | The preregistered V028 triple includes PA24 and supports rank at least 3. Physical and semantic DRAM attribution do not follow. |
| `MAP-HIGH-PA25_28` | **MODEL-SUPPORTED / PHYSICAL-PROVENANCE BLIND** | V016's decisive labels depend on an unregistered upper-median choice; V022R improves the acquisition but still lacks observed PFN/SG placement; V029 did not stimulate high bits. V030 passed its host gate but has not run live. |
| `SEMANTIC-COORDINATES` | **UNKNOWN** | No retained observer identifies the recovered outputs as channel, rank, bank group, bank, row, or column. |
| `COMPLETE-COORDINATE-ALIAS` | **NOT OBSERVED IN BOUNDED V018 / GLOBAL UNKNOWN** | A functioning positive control accompanied 176/176 distinct candidate observations in one state over bits 6–27. PA28+, other allocations, other states, and protected destinations were not covered. |
| `MUTABILITY` | **UNKNOWN** | No transform register before/after or controlled transform mutation exists. V015 has four invariant comparisons but retains `v2321-L762 REPEAT_REQUIRED`; V019 closes only its exact deep-suspend state. |
| `APSS-DIRECT-REACH` | **INSTANCE 0 NONRETURNING / CAUSE UNKNOWN** | The exact `0x09248080` load returned no value and the run ended in watchdog/reset. The paired control executed zero MMIO loads, so it is not a positive read control. |
| `OTHER-INITIATOR/PROXY-REACH` | **OPEN** | AOP, DMA, remote processors, and other master/path combinations remain unclosed. SCM_IO is default-denied only in the on-disk table; its runtime RW table is unknown. DCC is not a read-only observer. |
| `FINAL-XPU/POLICY-PATH` | **UNKNOWN** | Raw static policy rows are real, but the existing bit-3 HLOS predicate is non-discriminating on the relevant six-address set, client vectors were discarded, and instance/path/overlap/final-live policy were not established. |
| `PROTECTION-ORDER` | **UNKNOWN** | Check-before, check-after, stage-2-first, and injective complete-map explanations remain compatible with the evidence. The retained EL2 record is relevant but lacks decoded values and incident binding. |
| `PROTECTED-EFFECT/BYPASS` | **NOT OBSERVED** | No transformed transaction has been shown to reach a protected boundary, and no unauthorized protected read/write or isolation bypass exists in the retained evidence. |
| `FAULT-ENABLER` | **STATE/EXPERIMENT NOT CREATED** | Exact PPR/ECC/TRR/Rowhammer identity, observer, activation, and syndrome experiments do not exist. Absence is not claimed. |
| `DDR-INTEGRITY-CONTROL` | **STATIC CANDIDATE SURFACE / DISPATCH AND EFFECT UNPROVED** | Exact QMP sender and AOP vocabulary/partial handler/computed callback facts are not yet joined into a target-bound accepted request and effect. |

The operational `CLASS C` label survives because no D/E evidence appeared, not
because every reachability route or protection-order question was closed.

## 3. The four historical routes, re-graded

| Route | Current bounded result | What is closed | What remains open |
|---:|---|---|---|
| 1 — PA28 and above | **OPEN at physical provenance** | Low-bit `C-MAP` is strong; PA24 model rank floor is supported; V022R supplies a same-run model extension. | V016's high-bit conclusion is statistic-sensitive and not preregistered. Actual V016/V022R PFN/SG placement and a truly high-bit blinded OOS test remain absent. |
| 2 — enforcement/reach | **DIRECT NONRETURN CONFIRMED; REFUSING AGENT UNDECIDABLE** | One exact APSS/EL1 instance-0 load produced no value and ended in a qualified watchdog/reset. | XPU versus QHEE/stage-2 versus fabric/power/instrument cause; a successful same-harness MMIO control; other instances, initiators, proxies, and final policy. |
| 3 — DCB topology tampering | **SIGNED REPLACEMENT PATH STRONGLY CLOSED; GLOBAL WRITER UNKNOWN** | Contract, failure position, signed `xbl_config` container, and bounded XBL models strongly close an unsigned/replaced boot path. | Existing signed code's global runtime writer absence, indirect/computed paths, and other firmware/controller surfaces are not proved. |
| 4 — other state changes | **DEEP SUSPEND ONLY CLOSED** | Two separate same-boot deep-suspend acquisitions retained 0 moved tags out of 4,194,304 each. | OPP/retraining, PASR, modem SSR, recovery/system, crash/upload, and other handlers are not subsumed by physical perturbation magnitude. |

The 2026-08-27 sentence that the transform is reachable only from behind “an
access-control boundary that held every time it was tested” is withdrawn. The
evidence proves a non-returning direct-load path, not the identity of the agent
that refused or stalled it.

## 4. Six conclusions changed by the audits

Each row keeps origin and correction flow instead of flattening the result into
“the two audits agreed.” The section references are the controlling links.

| Claim | v2 disposition and attribution | Audit A | Audit B | Reconciliation ledger |
|---|---|---|---|---|
| **V016 high-bit result** | **Originated in Audit B alone; Audit A had not examined V016.** Audit A's ledger later independently re-derived and confirmed it. From 288 per-pair deltas, the two decisive differences are exact 16/32 mixtures: lower/upper medians `226/475` and `223/437`. Lower median moves the threshold `299 -> 356` and agreement `7/7 -> 5/7`; no preregistration was retained. | [A: not examined; correction context](ADVERSARIAL_AUDIT_2026-08-28.md) | [B §1.1, §2, §9.3, §12](INDEPENDENT_ADVERSARIAL_RESEARCH_AUDIT_2026-08-28.md) | [Ledger §1.1 and §5](AUDIT_RECONCILIATION_LEDGER_2026-08-29.md) |
| **Route 2** | **Narrowed first by Audit A; Audit B accepted the missing-positive-control limitation after reading A, then separately adjudicated the live counterexample/fault items.** Non-return is confirmed; “measured access control,” XPU causality, and the refusing agent are not. The retained EL2 record makes stage-2/QHEE a live alternative, not a verdict. | [A §2.1, §2.3, §12](ADVERSARIAL_AUDIT_2026-08-28.md) | [B §1.3–1.4.1, §9.3, §12](INDEPENDENT_ADVERSARIAL_RESEARCH_AUDIT_2026-08-28.md) | [Ledger §3 and §6](AUDIT_RECONCILIATION_LEDGER_2026-08-29.md) |
| **XPU policy narrative** | **Strong convergence from different evidence.** Audit B found a fixed formatter narrative and discarded client vector; Audit A found that the bit-3 predicate fails to distinguish five live-driver pages from the non-return page. Audit A's later bit30=HLOS naming was withdrawn; the actor remains unknown. | [A §2.2 and Correction C1](ADVERSARIAL_AUDIT_2026-08-28.md) | [B §1.4–1.4.1 and §11](INDEPENDENT_ADVERSARIAL_RESEARCH_AUDIT_2026-08-28.md) | [Ledger §1.2, §2, and §3](AUDIT_RECONCILIATION_LEDGER_2026-08-29.md) |
| **Deep-suspend subsumption** | **Rejected for other code paths.** The two V019 acquisitions remain strong for deep suspend only. Audit B reached this after reading Audit A, so agreement is inherited/shared and weak as replication. | [A §2.4 and §12](ADVERSARIAL_AUDIT_2026-08-28.md) | [B §1.8, H7, §9.3, §12](INDEPENDENT_ADVERSARIAL_RESEARCH_AUDIT_2026-08-28.md) | [Ledger §5–§6](AUDIT_RECONCILIATION_LEDGER_2026-08-29.md) |
| **SCM_IO closure** | **Corrected by Audit B; confirmed by Audit A/ledger.** The 81-entry on-disk table default-denies the known DDRSS band, but the table and 152-record dispatch table occupy an RW segment. Runtime contents and writer are unknown. | [A §6.1 and Correction C3](ADVERSARIAL_AUDIT_2026-08-28.md) | [B §1.10, §9.3, §12](INDEPENDENT_ADVERSARIAL_RESEARCH_AUDIT_2026-08-28.md) | [Ledger §1.4 and §2](AUDIT_RECONCILIATION_LEDGER_2026-08-29.md) |
| **DCC observer** | **Corrected by Audit B; confirmed by Audit A/ledger.** DCC is not read-only: list construction writes MMIO and `dcc_enable()` resets the existing production configuration. It is withdrawn as a live read-only candidate. | [A §6.2, §11, and Correction C2](ADVERSARIAL_AUDIT_2026-08-28.md) | [B H5, §10.1, §11.1, §12](INDEPENDENT_ADVERSARIAL_RESEARCH_AUDIT_2026-08-28.md) | [Ledger §1.3 and §2](AUDIT_RECONCILIATION_LEDGER_2026-08-29.md) |

## 5. What still survives at high confidence

1. The PA13–23 bounded timing-equivalence kernel is supported by direct
   measurements, independent reconstruction, controls, and low-bit OOS data.
2. V028 supports a rank floor of at least 3 in allocation/model coordinates,
   including a PA24 witness, without assigning semantic DRAM names.
3. V018 is a strong bounded negative: its positive control fired and all 176
   one-state candidates were distinct. It is not a global injectivity result.
4. The exact instance-0 load did not return, and the qualified watchdog/reset
   record is real. Only the causal label was overpromoted.
5. The signed `xbl_config` replacement path and each explicitly bounded static
   model are strong within their declared scopes; neither proves global writer
   absence.
6. No Class D or Class E effect, protected-boundary reach, or bypass appears in
   retained evidence.

## 6. What the two-audit comparison actually establishes

The reports are not two independent audits. Audit A was produced first and did
not see Audit B. Audit B later read Audit A, while refusing to inherit it as
authority. Agreement therefore has different weights:

- **Strong, different-evidence convergence:** the XPU narrative defect. Audit B
  found the formatter/client-vector loss; Audit A found the predicate/live
  counterexamples.
- **Weak, shared or inherited convergence:** the missing MMIO positive control,
  152-record SMC surface, deep-suspend non-subsumption, and the unsearched
  initiator/proxy axis. Audit B formed its pass after reading Audit A.
- **One-sided original findings:** V016 was Audit B only. The live XPU
  falsification and retained EL2 fault record were Audit A only; Audit B later
  adjudicated A1/A2/B1 as confirmed and B2 causality as undecidable.
- **Correction direction:** `Audit A -> Audit B: 0`; `Audit B -> Audit A: 4`.
  Audit A recorded C1 bit30 naming, C2 DCC, C3 SCM_IO, and C4 V023 provenance as
  corrections. “Mutual improvement” would erase this measured asymmetry.

The ledger reports no remaining factual disagreement. Three interpretive
questions remain: route-2 cause, whether raw XPU rows describe effective live
policy, and whether the high-bit model has physical provenance.

## 7. Discriminators and current implementation state

| Priority question | Cheapest useful discriminator | Current state |
|---|---|---|
| Are V016/V022R high bits physical? | Exact allocation-local SG/PFN oracle, then preregistered blinded high-bit OOS | [V030](VERIFICATION030_RBIN_PHYSICAL_ORACLE_DESIGN_2026-08-28.md) host gate passed: 30 focused tests, the canonical 2,027-test repository suite, compile/preflight, two byte-identical static AArch64 builds, and independent hostile review pass. **No live effect yet.** |
| Why did route 2 not return? | A successful same-harness MMIO positive control, then raw-set/raw-clear DC_NOC ladder; decode retained ESR/FAR/ELR | [V031](VERIFICATION031_DC_NOC_READ_LADDER_DESIGN_2026-08-28.md) designed and deferred. Its bit30 actor is explicitly `UNKNOWN`. |
| What policy is actually enforced? | Lossless full client-vector/overlap/all-instance decoder plus live path/readback evidence | Not implemented in this revision. |
| Can another master reach the surface? | Complete AOP computed-dataflow and proxy/initiator-specific harmless controls | Static candidates only; no accepted dispatch/effect. |
| Do other transitions change the map? | Separate target-bound receipts for OPP/PASR/SSR/etc. using the same observed physical pairs | Not created; deep suspend is not transferred. |

V030's completion is a measurement-capability milestone, not physical evidence:
no `--execute`, bridge, USB, ADB, ACM, allocation, MMIO, or device command was
issued in its implementation pass.

## 8. Document chain, authorship, model, and independence

| Layer | Producer and reasoning strength | Tree/document binding | Independence and role |
|---|---|---|---|
| Final report v1, 2026-08-27 | **Model and reasoning strength unrecorded** | Evolved from `d373cd2`; pre-banner body at integration has SHA-256 `74d24229b4d5dbc980262d819ffef3172bb322c5f8ddfee3e5352615392a0502` | Historical synthesis. Retained verbatim below its supersede banner so audit citations remain checkable. |
| Audit A | Claude Opus 5 (`claude-opus-5`), effort **`xhigh`**, no subagents | Audited tree `3715135`; original audit `4ba9400`; provenance/corrections through `2055f7f`; current file SHA-256 `5aa0b6fef9972a380b14282348b996b242b3d4184d0584c3e8ea94006745ec22` | Wrote first and did not see Audit B. Its eight roles were one sequential model context, not independent agents. |
| Audit B | `gpt-daybreak-blue-latest`, effort **`max`**, primary author plus three role-separated auditor agents | Evidence tree `4ea9680` (audit-line tip `c45d863`); report `79d5889` plus A1/A2/B1/B2 adjudication `f9ec259`; SHA-256 `de11cf1e79bb142586bd01eef0d2a124e3e99f975256b5055046db5509a5cffc` | Read Audit A. Its agents were separate tasks but shared the same model/effort; B is not an independent replication of A. |
| Reconciliation ledger | Claude Opus 5 (`claude-opus-5`), effort **`xhigh`**, no subagents | Commit `2055f7f`; SHA-256 `ce9d556a3f3d1f38eae04f7098a0e0e0b6802f99877c1959dd63f94173a49fb5` | Audit A graded all four load-bearing Audit B claims against pinned artifacts and confirmed all four. It also records Audit A's four corrections. |
| Final report v2, this document | **Written by the Audit B author:** Codex Desktop session `01a048c9-9f97-7f22-b319-46a0d38130d4`, requested model ID `gpt-daybreak-blue-latest`, reasoning effort **`max`; no new subagents for this synthesis** | Drafted from integrated main tree `2092645`, containing immutable `2055f7f`, `f9ec259`, and V030 `d8286ba`; preserved at `a24d870` and final-draft archive `5b1c4a0`; integrated over V030 host-gate base `434f3f6` | This is an attributed synthesis by B's author, not a neutral third audit and not a claim of two-audit independence. The model ID/effort are recorded task metadata, not cryptographic backend/checkpoint attestation. |
| Reviewed by | **PENDING — Audit A author, Claude Opus 5 (`claude-opus-5`), effort `xhigh`** | No pass has been delivered yet | The draft must not be promoted to `main` as final until this adjudication is supplied and recorded here. |

Primary audit links: [Audit A](ADVERSARIAL_AUDIT_2026-08-28.md),
[Audit B](INDEPENDENT_ADVERSARIAL_RESEARCH_AUDIT_2026-08-28.md), and the
[reconciliation ledger](AUDIT_RECONCILIATION_LEDGER_2026-08-29.md).

Other-branch context was not ignored. Audit B inspected
`research/xbl-config-cdt` at `99eb1dc`, plus
`backup/pre-rebase-20260826` and `remotes/tmpmain`, as history rather than
authority. The research branch is not merged wholesale: its relevant
V015/V016, alias, suspend, and route-2 material was rebuilt or reconciled on
the integrated line, while its superseded HLOS/access-control and subsumption
interpretations do not govern this report.

Integration refreshed two dependent, host-only derived artifacts after the
`MEMORY_MAP.md` interpretation changed. V017's `...20260829-06` manifest only
updates that source pin and leaves its bounded bank-granularity result intact.
The 1b `...20260829-02` manifest uses an audit-corrected v2 schema: it preserves
the exact owner, raw permission words, client vector, and legacy bit-3 result,
but no longer converts the non-discriminating predicate into an HLOS-denial or
refusing-agent claim. Neither refresh adds a device observation.

## 9. Final bounded conclusion

The 2026-08-27 report overstated high-bit physical measurement, route-2
causality, flat HLOS-grant interpretation, and state-transition subsumption.
Those statements are superseded by this vector.

The project has a strong bounded `C-MAP` result and a strong bounded V018
non-alias result. It does not yet have observed high-bit physical provenance,
transform mutation, a complete-coordinate alias, an identified refusing agent,
effective final XPU policy/path, alternate-initiator closure, protection order,
or a protected effect. `CLASS C` remains only as the current operational gate;
no Class D/E evidence exists and the stop condition has not fired.

No new device action, controller write, protected-memory operation, or security
state change was performed to produce this revision.
