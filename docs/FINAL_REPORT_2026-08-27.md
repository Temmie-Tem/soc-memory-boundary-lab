# Does Skitter apply to SM8150? — final report, 2026-08-27

**Result: `NO_BOUNDARY_BYPASS_OBSERVED`.
Class `CLASS C (TRANSFORM ONLY)`, `NOT_ELIGIBLE`.**

The honest form of the conclusion is narrower than "SM8150 is not affected" and
stronger than "we ran out of ideas":

> The premise is structurally available, and the transform is reachable only
> from behind an access-control boundary that held every time it was tested.

This document is the project's conclusion. It states what was asked, what closed
each route and **what kind of thing did the closing**, what was measured, and
what remains `UNKNOWN`. Every claim below is bounded to the exact build,
apertures and configurations named.

## 1. The question, and how it decomposes

The Skitter class depends on a DRAM address transform that is both **mutable**
and **reachable**. If an attacker changes how physical addresses map onto DRAM
coordinates *after* a protection check runs, data moves under the check: the
check validated one location and the hardware reads another.

Two independent conditions, both required:

| | Statement | Result |
|---|---|---|
| **P1** | A mutable address transform exists downstream of the protection check. | `UNKNOWN` — the transform exists and is characterised; mutability was never demonstrated, and no controller write was ever attempted. |
| **P2** | The Normal World can reach it. | `REFUTED` on every aperture tested, in both debug configurations. |

P2 fails, so P1 is moot on this target. P1 is left open rather than claimed
closed, because nothing here measured it.

### Exact target

| | |
|---|---|
| Device | Samsung Galaxy A90 5G — `SM-A908N` |
| SoC | Qualcomm SM8150 (SDM855) |
| Bootloader | `A908NKSU5EWA3` |
| Kernel | `4.14.190-25818860-abA908NKSU5EWA3`, built 2023-01-12 |
| Memory | LPDDR4X, two 3072 MiB ranks, DCB `/6003_0200_1_dcb.bin` |

## 2. The four routes, and what kind of thing closed each

This is the load-bearing distinction in the project. **A limit this project
chose is not the same finding as a limit the target enforces.** A route closed
by a safety contract says nothing about the hardware; a route closed by a
measurement does.

| # | Route | What closes it | **Kind of evidence** |
|---:|---|---|---|
| 1 | PA28 and above | Reopened and measured. The prior closure rested on three unverified sentences, all now refuted. A 320 MiB non-secure carveout exists, its physical base is published in the device tree, and `f(PA28)` was measured directly. | **Measurement** — twice, the second with same-run provenance |
| 2 | Enforcement ordering | Every candidate aperture is TZ-owned with no HLOS grant in both selector branches. Direct EL1 loads end in a watchdog reset — with memory dumps disabled *and* enabled. | **Measured access control** — the substantive route |
| 3 | DCB topology tampering | The one genuine structural transfer from BadRAM/DisARMed/PMPlease. `xbl_config` is a forbidden partition *and* a signed container: MBN v6, 256-byte RSA-2048 signature, three-level X.509 DER chain. | **Contract *and* cryptography** — the only contract-closed route |
| 4 | Other state changes | Deep suspend is a strictly stronger perturbation than the alternatives — DDR self-refresh plus an APSS power collapse. The map did not move: **0 of 4,194,304 tags**, across two corroborated runs. | **Measurement** — closed by subsumption |

Only route 3 is closed by the contract, and it is independently closed by the
image signature as well.

## 3. The positive result — a hidden transform, measured through timing alone

The project never read a single controller register. It characterised the
transform anyway, using row-buffer conflict timing: two addresses in the same
bank but different rows are slow; anything else is fast.

What emerged is a **rank-3 XOR relation over GF(2)**. Selection is a linear
function of physical address bits, and `f(PA13)`, `f(PA14)`, `f(PA15)` =
`001`, `010`, `100` form a basis of GF(2)^3. Any other bit's contribution is
therefore one of exactly eight vectors — which makes it testable rather than
merely describable.

The open question was whether the pattern continued above bit 27. It does.

| Difference tested | Median | Reading |
|---|---:|---|
| `0x16000` (control) | 546 / 543 | `CONFLICT` — same bank, different row |
| `0x2000` (control) | 149 / 145 | `NEGATIVE` — not a same-bank conflict |
| `0x10000000` | 217 / 220 | bit 28 alone is **not** a conflict, so `f(2^28) != 0` |
| **`0x10004000`** (vector `010`) | **540** | `RESOLVED` — the one combination that fires |
| six other combinations | 136 – 218 | all negative |

Testing all seven basis combinations is its own control: none firing would place
bit 28 outside the recovered space; more than one would refute the model.
Exactly one is the only outcome that resolves.

**`f(PA28) = 010 = f(PA14)`.** The separation is not marginal — the gap setting
the threshold is 322 against a runner-up gap of 22, and the winner's minimum
pair delta exceeds every other candidate's maximum, so the sets are disjoint at
pair level.

It was then measured a second time under a provenance-complete acquisition
binding the exact device, bridge, argv and timestamps to the same run. Both
brackets selected only `0x10004000`, at an identical threshold of 369.

**Withheld claim.** `NEGATIVE` means the pair did not present as a same-bank,
different-row conflict. That separates selection bits from row bits; it does
**not** distinguish bank from rank from channel. Calling this "the bank
function" would be an overstatement, so no report in this repository does.

## 4. The wall, and the last untested condition

Route 2 had a genuine hole in its evidence, found by reading the defenses
backwards rather than forwards.

The XPU policy around the remapper does not look like architecture. The page at
`0x09248000..0x09249000` is 4 KiB carved out of a uniform neighbourhood and
given `write_vmid = 0x00000000` — not "TZ only" but *no VMID at all* — while its
neighbours on both sides are symmetric `0x40000000`. Its reader differs
(`0x80000000`), and its permission is built by a non-standard path
(`exact_constructed_client_permission_bytes` `0x11, 0x08` while the standard
multi-VMID permission words are zero). That is the shape of a response to
something, not a floor plan.

The disclosed record names a candidate: **CVE-2020-11252**, "improper access
restrictions during trustzone initialization, as xPU get disabled when memory
dumps are enabled".

And the project's own timestamps showed the gap: **every** protected-read
attempt it had ever made was performed at `androidboot.debug_level=0x4f4c`
(LOW) — memory dumps disabled. The route-2 negative rested on measurements taken
only in the state where the protection is expected to be on.

So the condition was set and the read repeated. The expectation — *patched,
expected to bark again* — was committed to the repository **before the run**
(`e7f3236`), together with the stop condition: a returned value would be treated
as a security-boundary-bypass indicator, ending exploration immediately and
switching to minimum-evidence disclosure.

### What the device recorded

Retained receipt:
`evidence/private/verification-023-last-kmsg-at-mid-20260827-01.last_kmsg.bin`,
2,097,136 bytes, SHA-256
`fdceab48dc267dd74ec6c70edbec6b51ee13dcd8532cf8b121c4fe93b425c66e`.

```text
DebugLevel : 1145654596            <- little-endian "DMID"
Watchdog bark! Now = 69.080467
Watchdog last pet at 58.080193
UploadCause[Non Secure Watchdog Bark], Don't check hangcnt
collect_rr_data : upload_cause = Non Secure Watchdog Bark
collect_rr_data : TZ OEM_RESET_REASON :: TZBSP_ERR_FATAL_NON_SECURE_WDT
```

The bootloader's own crash record carries the debug level. The condition is
attested by the device, not narrated by the investigator.

| Fixed 32-bit load at `0x0906566c` | Dumps disabled (LOW) | Dumps enabled (MID) |
|---|---|---|
| Value returned | none | none |
| Upload cause | `Non Secure Watchdog Bark` | `Non Secure Watchdog Bark` |
| TZ reset reason | `TZBSP_ERR_FATAL_NON_SECURE_WDT` | `TZBSP_ERR_FATAL_NON_SECURE_WDT` |
| Bark − last pet | 11.000279 s | 11.000274 s |

The watchdog timeout agrees to five microseconds. Same refusal path, same
timing, both configurations.

`PROVED` within this build and this one fixed load: the protected read is
refused with memory dumps enabled exactly as with them disabled.

`SUPPORTED`: CVE-2020-11252 does not apply to `A908NKSU5EWA3` — either patched
or never applicable to SM8150. Route 2 now closes on a measurement of the one
untested condition rather than on an inference from measurements taken only at
LOW.

No boundary-bypass indicator appeared, so the stop condition did not fire.

## 5. Method — why the negatives are worth having

A negative result is only worth the discipline that produced it. Three practices
carried the weight.

### Expectations were pre-registered

The DMID prediction was written and committed before the run. A negative is
worth having precisely because it was not assumed, and a positive would have
been worth stopping for. Recording the expectation in advance is what separates
a measurement from a confirmation.

### Every instrument carried a negative control

- The seven-way basis test refutes its own model if more than one candidate
  fires.
- The suspend analyzer has a synthetic positive that flips it to `MAP_CHANGED`.
- The heap-capacity reducer has a synthetic 512 MiB success that flips it to
  `MET`.
- The retention guard rebuilds the exact dangling-symlink defect it exists to
  catch and requires itself to fail.

A guard that has never fired is not evidence.

### The project refuted its own claims

Route 1 was recorded as closed on three sentences that turned out to be wrong: a
256 MiB ceiling that measured 320 MiB, a 512 MiB span requirement that was never
necessary, and an "unknown" physical base that was published in the device tree
the whole time.

An internal audit claim of "3,029 pairs verified, 0 mismatched" was found
tautological — the checker was reading a field the prober had already filtered
on — and was rebuilt to recompute `pa_b` independently from `offset ^ value` and
the pinned base. The verdict never depended on it, but the audit claim did, and
the audit claim was wrong.

Each of these was found by adversarial review and recorded as a refutation, not
quietly amended.

### One constraint discovered the hard way

**A TWRP round trip resets `param.debuglevel` to `DLOW`.** The planned order —
set the debug level, then flash the probe — silently undid itself, and the
candidate booted at LOW. It was caught by a full 10 MiB partition capture rather
than by trusting the earlier write receipt. The repair is to flash first, then
apply the transition, then reboot without re-entering recovery. This binds any
future experiment that needs both a flashed boot image and a non-default debug
level.

## 6. What remains `UNKNOWN`

- **Transform mutability (P1).** Characterised, never shown changeable. No
  controller write was attempted.
- **Physical identity.** `pagemap` is `BLIND` for dma-buf — 0 present pages and
  0 non-zero PFNs over 81,920 pages. Bases come from the device tree and
  allocation-extent measurement, never from the kernel.
- **Rank and channel.** The relation separates selection bits from row bits and
  stops there.
- **Global reachability.** Eight known apertures were covered in both selector
  branches, and Verification 025 decoded the complete MPU region set (164 of 164
  MPU regions, both branches). The 1,465 regions belonging to the 26 non-MPU
  instance classes remain undecoded — their record layout is not established.
  Undiscovered apertures are not excluded; static policy coverage must not be
  restated as global writer absence.
- **Other configurations.** One load, one address, two debug levels. Other dump
  sinks, force-upload states and apertures are untested.
- **Untriggered state changes.** Modem SSR and AOP-driven retraining are closed
  by subsumption, not by test; no Normal-World trigger is known for either.
- **Post Package Repair.** A JEDEC feature that remaps a faulty row *inside the
  DRAM die* — a better fit for the Skitter premise than the bank transform, and
  with **no published security research found**. It needs the same controller
  access route 2 shows to be unreachable, and hard PPR is fuse-backed and
  irreversible, placing it outside the standing authorization outright.

## 7. Provenance and device state

| | |
|---:|---|
| 70 | experiments |
| 118 | public manifests |
| 109 | tools |
| 1,398 | tests passing (0 failing, 1 skipped) |
| 0 | boundary-bypass indicators |

Every live result is pinned to a private raw receipt by size and SHA-256, and
reduced by a host analyzer whose public manifest regenerates byte-identically.

Device writes were bounded to `param` and `boot`, each verified by a complete
partition hash before and after, and each rolled back to a pinned original. No
`xbl`, `xbl_config`, `tz`, `hyp`, `devcfg`, `aop` or `abl` write occurred. No
QFPROM, eFuse, RPMB, anti-rollback counter or partition-table edit occurred. No
XPU, SMMU, EL2, EL3 or protected-memory write occurred. One fixed 32-bit
protected load was attempted, and was refused.

Final device state:

| Asset | State |
|---|---|
| `param`, complete 10 MiB | `1faafee97d08ff93b690dbcffe21d680f20232aa2d3dff5f462b747577bb4345` — byte-identical to the pinned original |
| gate fields | `LOW` / `force_upload=0` / `FMM_lock=0` / `dump_sink=USB_DEFAULT` |
| `boot`, 60,882,944 bytes | `ca978551aabe4b39563abaf529ccf2522054952d8b2ad852e632d26da88168cb` — V2321, readback verified |
| native self-test | `pass=11 warn=1 fail=0 entries=12` |

## 8. Open work

Nothing on this list can change the conclusion; each item either raises evidence
grade or model resolution.

| Item | Nature | State |
|---|---|---|
| Exact remapper read at DMID | Repeats §4 at `0x09248080` instead of the SHRM word, closing the address substitution | in progress |
| `0x17c00000` `apcs_glb` aperture | ~~No address inside the range appears in any retained XPU inventory.~~ Closed by Verification 025: it is covered by `CNOC_AOSS_MPU` `0x17c00000..0x18200000`, TZ-owned, no HLOS grant. The absence was extraction scope — 5 of 1,726 regions decoded. | **done** |
| Knock-Knock / Sudoku method port | Would separate bank from rank from channel | not started |
| Scorecard `LATER` rows | E — capture feasibility; B — base currentness | deferred |

---

*Prepared 2026-08-27. All claims are bounded to the exact build, apertures and
configurations named above.*
