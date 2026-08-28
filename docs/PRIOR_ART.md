# Prior Art: Separate Facts from Transfer Hypotheses

## AMD Skitter Creek Bath Salts — demonstrated facts

Primary source pinned during reconnaissance:

- Repository: <https://github.com/xoreaxeaxeax/skitter-creek-bath-salts>
- Observed `main` commit: `6363c2e9721eae82e93ff2e6035e01ee6b01c463`
- Kernel primitive: [`kernel/spaghettify.c`](https://github.com/xoreaxeaxeax/skitter-creek-bath-salts/blob/main/kernel/spaghettify.c)
- Solver: [`unspaghettify.py`](https://github.com/xoreaxeaxeax/skitter-creek-bath-salts/blob/main/unspaghettify.py)
- Usage: <https://github.com/xoreaxeaxeax/skitter-creek-bath-salts/blob/main/USAGE.md>

`PROVED (AMD Family 16h only)`: The PoC reads and temporarily changes
`D18F2x80 DramBankAddrMap`, `D18F2x94[22] BankSwizzleMode`, and
`D18F2xA8[20] BankSwap`. It obtains PCI extended configuration space from MSR
`0xc0010058`. Source anchors: `spaghettify.c:63-84,94-125` at the pinned commit.

`PROVED (AMD Family 16h only)`: The critical sequence restricts execution to one
online CPU, prepares translation/cache state, disables interrupts, flushes the
target, changes controller state, performs one uncacheable access, restores the
state immediately, and fences. The user-space stage records changed-state
aliases and tests them under the normal state. Source anchors:
`spaghettify.c:197-310,451-469`.

`PROVED (AMD Family 16h only)`: The solver models output address bits as XORs of
input bits and solves per-bit constraints with Z3; it also contains a GF(2)
row-mask/pseudoinverse implementation. Source anchors:
`unspaghettify.py:20-26,111-183,220-290`.

`UNKNOWN`: A primary presentation artifact. The repository still marked the
presentation as forthcoming when inspected; this report does not substitute a
secondary summary for it.

## General DRAM/address-transform facts

`SUPPORTED`: Channel, rank, bank-group/bank, row and column selection may be
derived from system address bits with interleaving and XOR hashing. This is not
specific evidence for SM8150. Qualcomm patent filings describe both channel
hashing/local address calculation and bank-group/bank XOR with row bits:

- <https://patents.google.com/patent/US20140310503A1/en>
- <https://patents.google.com/patent/US20210133100A1/en>

Patent text proves that Qualcomm described these designs; it does not prove
that SM8150 implements a cited polynomial, register, or mutability property.

## GF(2) model

Let a mapping state be a binary matrix `M` acting on input physical-address bits
`p`; each output bit is the parity of a subset of input bits:

```text
d = M p  (over GF(2))
```

For firmware state `Mf`, experimental state `Me`, and protected target `t`, an
alias candidate `a` must satisfy:

```text
Me a = Mf t
```

If `Me` is square and invertible, `a = Me^-1 Mf t`. If it is rank-deficient,
there may be no preimage or a coset of multiple preimages. The local
`tools/gf2.py` implementation returns one particular solution plus a nullspace
basis and deliberately encodes no Qualcomm-specific bit assignment.

## Qualcomm-transfer hypotheses

- `PROVED`: exact XBL's Quest DDR reporter models the retained target with a
  direct, bijective rank-relative bit partition and no XOR. This proves the
  firmware diagnostic model. `REFUTED`: it is the complete silicon bank map.
- `PROVED` by live Experiment 014, within rank-relative PA bits `0..23`: SM8150
  has a three-dimensional XOR bank-selection row space containing terms from
  row bits `16..23`. Four held-out kernel relations and four one-bank-bit
  negatives cross-validate it. Qualcomm patent text is no longer the evidence
  for existence on this target; the live timing is.
- `HYPOTHESIS`: the observed hash state is owned by MCCC/MC or closely coupled
  DDRSS logic initialized before HLOS. The exact register, encoding, writer and
  lock remain unproved.
- `PROVED`: selected DCB section-16 base tokens numerically match exact
  SHRM-visible MCCC/MC/MCCC-master/DDRSS pages. `SUPPORTED`: they are register-
  inventory page numbers.
- `PROVED` by Experiment 012: the exact Xtensa SHRM helper computes
  `(base_page << 12) + (offset_token << 2)` and its two direct section-16
  callsites pass direction zero, reading 32-bit words into snapshot buffers.
- `UNKNOWN`: runtime values, reset value, boot value, lock bit, whether any
  token is final-transform state, and whether an indirect reverse-direction
  invocation exists.
- `REFUTED`: apparent raw TrustZone substring matches for recovered row masks
  directly encode the hash. They are unaligned bytes inside monotonic u64
  address tables; encoded, split or computed representations remain possible.
- `UNKNOWN`: Whether any relevant state remains writable from EL1 after boot.
- `UNKNOWN`: Whether security enforcement occurs before or after the final
  transform, or is repeated after it.
- `REFUTED`: AMD register addresses, bit positions, controller names, and Family
  16h access method can be copied to Qualcomm. They are retained only as the
  definition of an attack class.

## Address-mapping recovery: the live literature line

Surveyed 2026-08-27; see `docs/BROAD_SURVEY_2026-08-27.md` for the full pass.

- **Knock-Knock**, arXiv 2509.19568, µASC 2025. Same GF(2) formulation used here,
  but proves the bank-matrix / empirical-address-matrix relation and recovers the
  bank-mask basis in polynomial rather than exponential time; generalises to row
  mappings and recovers a row basis. 99% recall, minutes, >500 GB.
- **Sudoku**, arXiv 2506.15918, 2025. Decomposes a mapping into channel, rank,
  bank-group and bank *components* using refresh intervals and consecutive-access
  latency, rather than one fused relation.
- **DRAM-MaUT**, IEEE CASES 2022. The only ARM-native tool: `DC CIVAC` eviction
  and `PMCCNTR` timing — the primitives available on this target.
- **DRAMDig**, arXiv 2004.02354, 2020. Knowledge-assisted mapping recovery.

This project's relation is rank 3 over PA13..PA27, i.e. bank selection only.
Knock-Knock's row basis and Sudoku's component split both attack what is
recorded here as `UNKNOWN` — complete DRAM coordinates — and neither needs new
privilege.

- **CATTmew**, IEEE TDSC. Defeats physical kernel isolation via ION/DMA driver
  buffers. Noted and not pursued: it is a privilege-escalation result, and
  higher-privilege success is out of scope for this project.

## Qualcomm remapper prior art

- **CVE-2022-22063** (msm8916-mainline). `APCS_BOOT_START_ADDR_NSEC` at
  `0x0b010008` on MSM8916 carries `REMAP_EN` and `BOOT_128KB_EN` and remaps
  `0x00000..0x20000` to a configurable base, shiftable block by block. Reachable
  from non-secure EL1 because stage 2 protected the remapped region and not the
  configuration register; yields full R/W/X into hypervisor memory. Fixed by
  blocking the remapped region. Affected: MSM8916/APQ8016 and likely MSM8909 and
  MSM8953; **SM8150 is not listed**.

  This is the closest published instance of the exact P1 + P2 conjunction this
  project looks for: a mutable transform downstream of the boundary, plus a
  Normal-World path to it. On SM8150 the analogous block exists — `apcs_glb`,
  `qcom,sm8150-apcs-hmss-global` at `0x17c00000` — but its exposed syscon at
  `+0x0c` is the SMP2P IPC doorbell, not a remapper, and `REMAP_EN` /
  `BOOT_128KB_EN` appear nowhere in the retained XBL.
