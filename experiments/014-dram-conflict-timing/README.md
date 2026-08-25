# Experiment 014 — DRAM Conflict Timing

## Question

Does the real PA-to-bank/channel selection function equal the exact Experiment
011 diagnostic model, or does it contain additional GF(2) terms that no static
firmware artifact represents?

This is the first experiment in this repository to attack the transform side of
the question. Experiments 006–013 and Verification 001 all resolved
*reachability*: whether Normal World can reach the controller apertures. The
answer there is consistently no. Whether a mutable transform sits downstream of
the protection decision has never been tested.

## Why this route exists

Every direct read has been denied. `CONFIG_DEVMEM` is off, the fixed EL1 load in
Experiment 007 ended in a non-secure watchdog, and Experiment 013's fixed SHRM
snapshot load did the same. Verification 001 confirmed why: the target apertures
sit in enabled, TZ-owned XPU regions whose write access word is `0x00000000` and
whose read word grants no ordinary HLOS VMID.

Row-buffer conflict timing needs none of that. Two addresses that select the
same channel, rank and bank but different rows force a precharge and activate,
which is measurably slower than two addresses in different banks. The selection
function is therefore observable through ordinary loads on ordinary RAM, and is
blocked by neither the XPU nor `CONFIG_DEVMEM`.

`docs/EXPERIMENT_MATRIX.md` previously gated this experiment as `NOT ELIGIBLE`
because "a safe independent DRAM-coordinate observation path remains
unresolved." That conflates reading the mapping out of controller registers with
inferring it from timing. Only the first is blocked; the timing *is* the
observation.

## The reduction that makes it cheap

For a linear selection function `f`, two addresses collide exactly when
`f(a) == f(b)`, which is `f(a ^ b) == 0`. The conflict relation depends only on
the XOR difference, so the experiment is not a search over an unstructured
address space — it is the recovery of `ker(f)`, a linear subspace, and the
selection function is that kernel's orthogonal complement.

## Two-phase protocol

Implemented and validated in `tools/dram_conflict_model.py`.

**Phase 1 — one pivot, `WIDTH` probes.** Pick a row bit and confirm it conflicts
with itself alone; that establishes it lies in the kernel. Probe `pivot ^ bit`
for every remaining address bit. Because the pivot is in the kernel, such a
probe conflicts exactly when that bit is also in the kernel, so one sweep
classifies all 32 bits. Bits that do not conflict are *suspects*: they
participate in bank or channel selection.

**Phase 2 — suspect pairs.** A hash such as `bank[0] = PA[13] ^ PA[17]` is
invisible to phase 1, because neither bit is individually in the kernel while
their XOR is. Pairing the suspects exposes it.

For the pure diagnostic model the suspects are exactly `{9, 10, 13, 14, 15}` and
phase 2 costs ten probes. The whole protocol is under 50 measurements.

## Falsifiable predictions

| Outcome | Meaning |
|---|---|
| Suspects are exactly `{9,10,13,14,15}` and no suspect pair conflicts | The diagnostic model is the real selection function. Strong `Class A` evidence: no hidden hash, so no alias can arise from one. |
| Any additional suspect appears, or a suspect pair conflicts | A term exists that the exact diagnostic formula does not represent. First direct evidence on the transform side. |
| Recovered row space differs from the diagnostic row space | `REFUTED`: "the XBL diagnostic formula is the complete PA-to-coordinate model." |

`tools/dram_conflict_model.py` also exposes `distinguishing_differences`, which
returns only those differences where two candidate models disagree. Every other
pair carries no information and does not need to be measured.

## Controls already encoded

- A same-bank, same-row difference is a row *hit*, not a conflict. Probes
  without a row bit are ignored rather than treated as kernel evidence; a naive
  timing test would misread them as "different bank".
- Completeness is checked by probe coverage, not by algebra. Rank-nullity makes
  `kernel_dimension + selection_rank == WIDTH` hold for any span, complete or
  not, so a partial probe set still returns a well-formed but oversized row
  space. `protocol_complete()` checks what was actually measured.
- Contradictory observations for one difference are reported rather than
  silently resolved.
- The XOR-injection negative control is a unit test: an injected
  `bank[0] = PA[13] ^ PA[17]` must be recovered, must separate from the
  diagnostic model, and must make the diagnostic model fail cross-validation.

## Status

`HOST_READY / DEVICE PHASE NOT RUN`.

The model, protocol, recovery and controls are implemented and validated against
synthetic ground truth in both directions. 30 focused tests pass. No device,
SMC, MMIO, partition, EL2, EL3, or protected-memory access has occurred, and
this phase performs none.

## What the device phase still needs

The measurement runs in kernel context, because all four requirements are EL1:

1. **Physical address proof** — allocate from an experiment-owned pool and read
   PFNs from inside the kernel. `docs/NORMAL_RAM_ALIAS_DESIGN.md` step 1 already
   specifies this.
2. **Cache bypass** — `DC CIVAC` between probes, or a Normal-NonCacheable
   mapping. Without it the measurement reports cache behaviour, not DRAM.
3. **A cycle counter** — `PMCCNTR_EL0` or `CNTVCT_EL0`, with user access
   configured.
4. **Determinism** — pin one CPU, bound the critical section, pin DDR frequency.
   AOP DDR frequency messages are visible to Linux and can move the clock under
   the measurement.

Note that `docs/NORMAL_RAM_ALIAS_DESIGN.md` opens its trial procedure with
"read and hash exact pre-state register values". That prerequisite belongs to
the mutation experiment, not to this one. Conflict timing needs no register
access at all, and inheriting that step is what previously made this line of
work look blocked.

## Risk

Normal RAM reads only. No MMIO, SMC, XPU, partition, or persistent state is
touched, so this experiment sits well inside the operating constraint recorded
in `README.md`: it cannot permanently brick the device. The worst realistic
failure is an unstable measurement, not a reset.

## Reproduce

```sh
python3 -m unittest tests.test_dram_conflict_model -v
```
