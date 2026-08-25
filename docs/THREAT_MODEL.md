# Threat Model

Date: 2026-08-25 KST

Target: Samsung Galaxy A90 5G `SM-A908N`, Qualcomm `SM8150`

Operator authority: owner-controlled research device

## Question

`UNKNOWN`: Can Normal World influence a transform after a protection decision so
that the physical address checked by QHEE/RKP/TrustZone/XPU differs from the DRAM
cell ultimately selected?

The tested property is:

```text
EL1 system PA -> ownership/access decision -> final address transform -> DRAM
                     checked destination       selected destination
```

The attack-class precondition is a state change `S0 -> S1` such that, for two
different system physical addresses `A != B`:

```text
DRAM_S1(A) == DRAM_S0(B)
```

and the relevant protection decision still authorizes `A` rather than the final
destination. A shared cache line, virtual alias, page-table alias, IOMMU alias,
DMA remap, or stale cache observation is not sufficient.

## Capabilities and exclusions

- `PROVED`: The live research runtime provides EL1-mediated, owner-controlled
  read-only access to `/proc` and live DT properties. Evidence:
  `evidence/manifests/001-baseline-live-20260825-01.manifest.json`.
- `PROVED`: A fixed inline map/unmap control returned safely, while its paired
  one-load candidate returned no value and ended in a retained non-secure
  watchdog reset.
- `UNKNOWN`: EL1 read access to the final DDR address-map registers; the failed
  load does not distinguish access control from clock/power or fabric state.
- `UNKNOWN`: EL1 write access to those registers, their lock state, and their
  security owner.
- `PROVED`: a post-reset XBL/Samsung Upload diagnostic path can export the
  protected SHRM snapshot without granting direct EL1 access. One exact dump
  contains coherent set-0 MC/MCCC state; this is observation after reset, not a
  Normal-World runtime primitive.
- `PROVED`: Normal World can behaviorally observe a low-24 XOR bank-selection
  relation through stable non-secure ION PA and write-combine timing. This is
  observation of bank equality, not register access, state mutation, or a
  complete-coordinate alias.
- `UNKNOWN`: Arbitrary read/write access to QHEE private runtime memory.
- `UNKNOWN`: Arbitrary read/write access to TrustZone private runtime memory.
- `REFUTED`: “EL2 interfaces and reserved ranges are mapped, therefore EL2
  private memory is freely readable.” The evidence only establishes an EL1-to-
  secure-monitor call path and advertised ranges.

S20+, S22+, persistence, secret extraction, full secure-memory dumps, and exploit
weaponization are out of scope.

## Gates

The binding constraint for this derived project is persistence, not hazard: any
action that cannot permanently brick the device may be implemented and executed
quickly. Volatile controller/remapper/MCCC/MC writes, watchdog resets, and boot
candidates with verified rollback are inside that bound. Bootloader-class
partitions (`xbl`, `xbl_config`, `tz`, `hyp`, `devcfg`, `aop`, `abl`),
QFPROM/eFuse, RPMB, anti-rollback counters, and partition-table edits are
outside it and stay forbidden. See the Upstream section of `README.md`.

`docs/WRITE_GATE_<experiment>.md` remains the recording mechanism for a
controller/XPU/SCM/EL2/EL3 or protected-memory write: exact register/address,
provenance, expected effect, alternatives, brick/data/boundary risk, rollback
and recovery. It documents a write; it is not an approval ladder, and a write
inside the brick bound is not blocked by its absence.

Data loss is scoped separately from bricking. A remapper write while DRAM
traffic is live can corrupt filesystem write-back. That is recoverable and
therefore permitted, but quiesce and sync first.

If a controlled transform mutation, deterministic protected alias, or normal-PA
blocked/alias-PA-readable result appears, status becomes
`POTENTIAL_SECURITY_BOUNDARY_BYPASS`; collection is minimized and disclosure
notes become active.

## Decision classes

Current class: `CLASS C (TRANSFORM ONLY) — a normal-RAM bank hash is observed;
known direct EL1 register paths are blocked; mutation, complete-coordinate
alias and protected-boundary effect remain unproved`.

- Class A: structurally blocked.
- Class B: observable but immutable.
- Class C: normal-RAM transform/alias only.
- Class D: protected boundary reached but blocked by later enforcement.
- Class E: protected-memory isolation bypass.
