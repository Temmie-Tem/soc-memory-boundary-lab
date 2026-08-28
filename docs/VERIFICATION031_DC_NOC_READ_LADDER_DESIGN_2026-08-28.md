# Verification 031 — same-harness DC_NOC read ladder

Status: `DESIGNED / DEFERRED UNTIL V030 CLOSES / NO LIVE EFFECT`

## Question

Was the fixed EL1 load at `0x09248080` refused in a way that correlates with
that exact `DC_NOC_BROADCAST_MPU` page's raw-bit-30-clear row, or can the same
watchdog result be explained by a broken load instrument or an unreachable,
unclocked DC_NOC/DDRSS path?

A single GIC read alone answers only the first alternative and cannot exclude
a hard-coded returned value.  The tier-0 control therefore reads two distinct
GICD registers.  The decisive policy comparison is then a source-backed
register used by live HLOS software in a raw-bit-30-set
`DC_NOC_BROADCAST_MPU` region followed by the raw-bit-30-clear remapper word
through the same boot, code body and command path.  The bit's actor identity
remains `UNKNOWN`.

## Fixed ladder

| Step | Fixed 32-bit load | Source-backed role | Nearest retained MPU decision | Required observation |
|---:|---|---|---|---|
| 1a | `0x17a00004` | `GICD_TYPER`, read-only | outside the retained relevant XPU rows | returned u32 is nonzero and differs from step 1b |
| 1b | `0x17a00008` | `GICD_IIDR`, read-only | outside the retained relevant XPU rows | returned u32 is nonzero, `(v & 0xfff) == 0x43b`, and differs from step 1a; ProductID is recorded without a hard gate |
| 2a | `0x090cc220` | `llcc-pmu@90cc000`, read-only `MON_CNT(0)` | `DC_NOC_NON_BROADCAST`, read `0x40000000`, raw bit 30 set; actor `UNKNOWN` | one returned u32; source masks the counter to 24 bits |
| 2b | `0x090b0050` | `syscon@90b0000`, MCCC period register read by `clk_debug_read_period()` | `DC_NOC_NON_BROADCAST`, read `0x40000000`, raw bit 30 set; actor `UNKNOWN` | one returned u32; nonzero is the driver-valid form |
| 3 | `0x0923000c` | LLCC `COMMON_STATUS0`, read by both LLCC core/perfmon probes | `DC_NOC_BROADCAST`, read/write `0x40000000`, raw bit 30 set; actor `UNKNOWN` | returned value whose bank-count field agrees with the four DT bank offsets |
| 4 | `0x09248080` | exact qhs_llcc remapper word tested by V007/V024 | `DC_NOC_BROADCAST`, read `0x80000000`, raw bit 30 clear; actor `UNKNOWN` | no value plus the already-qualified watchdog/reset signature |

The two tier-0 reads prove that the load completes, the returned value depends
on the selected address, and the harness is not merely returning a fixed
constant.  The two step-2 reads are parallel rungs, so the ladder has four
semantic levels and six fixed addresses.

`0x17a0ffe8` was not an invalid address: it is `GICD_PIDR2` inside the DT's
`0x17a00000 + 0x10000` distributor resource.  It is deliberately not selected
because reaching offset `0xffe8` would widen the established inline probe from
its fixed `0x5c` mapping to a 64 KiB mapping.  Offsets `0x004` and `0x008`
retain the small known harness and add the stronger two-address control.

## Source and policy pins

The external A90 source corpus is the retained
`a90-stock-mpgen27-20260822/source` tree.  Its enclosing workspace was at
commit `510d909eff0fe10e48f3bfff573bc17f59f0656a`, which records workflow
provenance but does not attest the ignored private source bytes; the
individual SHA-256 pins below bind those bytes.

- `sm8150.dtsi`, SHA-256
  `c0d42e66ddd5640e2dd7b65527c25fb617008d94a6a04062b9e1077f0eb63849`,
  supplies all four live DT resources.
- `irq-gic-v3.c`, SHA-256
  `ed173faf17ae19113fa1c51a19952f080d60dc87885f4d1247c968be81cd0ecc`,
  and `arm-gic-v3.h`, SHA-256
  `fdc8b84b1f473733117fcaeca67b8337a2e48353f389d8f346165bbb8e21d93c`,
  pin the GICD aperture and offset.
- `qcom_llcc_pmu.c`, SHA-256
  `ece25e644723e5fd22491449a469ff9be691413a2c82165c70421ae17c3aee05`,
  reads the LLCC-PMU counters.
- `clk-debug.c`, SHA-256
  `600005ce1d64db5ac3b12c2258f8c180b355ee8871844fff79755700944c5304`,
  reads the MCCC period register at offset `0x50`.
- `llcc-slice.c`, SHA-256
  `508f486ffe243c1e16096df00ec3f35fe5ef42618aebac3c93cfe4c20abb30c9`,
  reads `LLCC_COMMON_STATUS0` at offset `0x3000c`.

The Arm GIC architecture defines `GICD_IIDR` as a 32-bit read-only register at
offset `0x8`; the Arm Implementer field `(v & 0xfff) == 0x43b` is the tier-0
hard assertion.  A GIC-600 ProductID of `0x02` is `SUPPORTED` reference
evidence only: the live DT node is compatible with `arm,gic-v3`, not an exact
GIC-600 identity proof.  ProductID, variant and revision are retained as
observations without being authorization gates.

`PROVED`: the pinned TZ-policy decoder gives step 3's exact address a nearest
`DC_NOC_BROADCAST_MPU` row with raw bit 30 set, and gives step 4's exact page a
nearest row with raw bit 30 clear.  Both embedded selector branches contain
the same local rows.

`UNKNOWN`: the raw bit-30 actor identity, including whether it names HLOS or a
broader non-secure class.  V031 measures only whether the retained raw
set/clear distinction predicts live EL1 behavior; it does not assume an actor
interpretation as its result.

## Same-harness constraint

One fixed boot candidate contains six allowlisted read bodies selected only by
fixed operation numbers.  The host cannot supply an address, width, value or
call target.  Every body uses the V024 sequence:

```text
__ioremap(fixed_pa, fixed_size, PROT_DEVICE_nGnRE)
32-bit load at fixed offset 0
barriers
__iounmap
print operation ID and zero-extended u32
```

Steps 1a, 1b, 2a, 2b and 3 must all return and pass their semantic checks
before step 4 is dispatched.  Either tier-0 value being zero, the two values
being equal, or the IIDR Implementer differing from `0x43b` is a failed
positive control, not a successful zero-valued read.  A failure or hang at
step 3 stops the run; step 4 then has no discriminatory value and is not sent.
Successful steps are never replayed.

The candidate is boot-only and reversible through the exact V2321 image and
the already-proved TWRP/Download recovery path.  The experiment performs no
MMIO store, controller mutation, SCM/SMC, XPU/SMMU mutation, protected-memory
read, firmware change or persistence.  The only durable write is the bounded
candidate boot-prefix transition and its exact rollback.

## Result interpretation

| Tier 0 | Step 3 | Step 4 | Bounded conclusion |
|---|---|---|---|
| both nonzero, distinct, IIDR Implementer exact | correct returned status | watchdog/refusal | `SUPPORTED_MEASURED_DC_NOC_POLICY_DISCRIMINATION`; V024 becomes interpretable as an address-specific access result |
| both nonzero, distinct, IIDR Implementer exact | watchdog/refusal | not dispatched | `DC_NOC_PATH_UNREACHABLE_IN_PROBE_CONTEXT`; V024 cannot be attributed to the remapper or its policy |
| both nonzero, distinct, IIDR Implementer exact | correct returned status | returned u32 | immediate `POTENTIAL_SECURITY_BOUNDARY_BYPASS`; stop broad probing and enter disclosure mode |
| zero/equal/incorrect Implementer | not dispatched | not dispatched | tier-0 address-dependent load control failed; repair the instrument before any DC_NOC inference |
| both nonzero, distinct, IIDR Implementer exact | wrong but returned status | not dispatched | address decode/semantic control failure; repair the instrument or source pin before any raw-clear test |

Even the first row does not prove the exact enforcing silicon block or a
physical-to-DRAM alias.  It proves only that two fixed addresses in the same
retained MPU instance and NoC class behave in accordance with the raw-set and
raw-clear local rows under the tested EL1 path.

V031 is orthogonal to V030.  V030 measures normal-RAM physical provenance;
V031 repairs the causal interpretation of the Route-2 negative.  Neither
supersedes the other.
