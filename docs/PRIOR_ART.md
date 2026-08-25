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
  firmware diagnostic model, not necessarily every silicon transform.
- `HYPOTHESIS`: SM8150 has additional final transform state in MCCC/MC or
  closely coupled logic that the diagnostic omits. Prediction: an exact
  consumer or independent coordinate observation requires terms absent from
  the recovered contiguous-bit model.
- `HYPOTHESIS`: any such hidden state may use XOR/hash logic. Qualcomm patent
  text remains design-class evidence only; the exact diagnostic is evidence
  against assuming XOR without another observation.
- `PROVED`: selected DCB section-16 base tokens numerically match exact
  SHRM-visible MCCC/MC/MCCC-master/DDRSS pages. `SUPPORTED`: they are register-
  inventory page numbers.
- `PROVED` by Experiment 012: the exact Xtensa SHRM helper computes
  `(base_page << 12) + (offset_token << 2)` and its two direct section-16
  callsites pass direction zero, reading 32-bit words into snapshot buffers.
- `UNKNOWN`: runtime values, reset value, boot value, lock bit, whether any
  token is final-transform state, and whether an indirect reverse-direction
  invocation exists.
- `UNKNOWN`: Whether any relevant state remains writable from EL1 after boot.
- `UNKNOWN`: Whether security enforcement occurs before or after the final
  transform, or is repeated after it.
- `REFUTED`: AMD register addresses, bit positions, controller names, and Family
  16h access method can be copied to Qualcomm. They are retained only as the
  definition of an attack class.
