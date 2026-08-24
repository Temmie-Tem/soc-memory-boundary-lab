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
- `SUPPORTED`: The existing research kernel infrastructure is suitable for a
  later, source-backed MMIO read adapter.
- `UNKNOWN`: EL1 read access to the final DDR address-map registers.
- `UNKNOWN`: EL1 write access to those registers, their lock state, and their
  security owner.
- `UNKNOWN`: Arbitrary read/write access to QHEE private runtime memory.
- `UNKNOWN`: Arbitrary read/write access to TrustZone private runtime memory.
- `REFUTED`: “EL2 interfaces and reserved ranges are mapped, therefore EL2
  private memory is freely readable.” The evidence only establishes an EL1-to-
  secure-monitor call path and advertised ranges.

S20+, S22+, persistence, secret extraction, full secure-memory dumps, and exploit
weaponization are out of scope.

## Gates

Phase 0/1 permits host analysis and source-backed read-only device observation.
Before a controller/XPU/SCM/EL2/EL3 or protected-memory write, create
`docs/WRITE_GATE_<experiment>.md` with the exact register/address, provenance,
expected effect, alternatives, brick/data/boundary risk, rollback and recovery.

If a controlled transform mutation, deterministic protected alias, or normal-PA
blocked/alias-PA-readable result appears, status becomes
`POTENTIAL_SECURITY_BOUNDARY_BYPASS`; collection is minimized and disclosure
notes become active.

## Decision classes

Current class: `UNKNOWN — insufficient evidence for Class A–E`.

- Class A: structurally blocked.
- Class B: observable but immutable.
- Class C: normal-RAM transform/alias only.
- Class D: protected boundary reached but blocked by later enforcement.
- Class E: protected-memory isolation bypass.
