"""GF(2) model and recovery for the PA-to-bank/channel selection function.

Experiment 011 recovered the exact XBL diagnostic coordinate formula and proved
it is a complete, non-overlapping, invertible bit partition with no XOR. That
settles what the firmware *intends*. It does not settle what the silicon *does*:
a hardware channel/bank hash outside the diagnostic model would be invisible to
every static artifact recovered so far.

Every attempt to read the controller directly has been denied — `CONFIG_DEVMEM`
is off, and the fixed EL1 loads in Experiments 007 and 013 both ended in a
non-secure watchdog because the target apertures sit in TZ-owned XPU regions.
This module takes the other route. DRAM row-buffer conflict timing exposes the
bank/channel selection function without reading any controller register, so it
is blocked by neither the XPU nor `CONFIG_DEVMEM`.

The reduction that makes it tractable: for a *linear* selection function `f`,
two addresses collide exactly when `f(a) == f(b)`, which is `f(a ^ b) == 0`. The
conflict relation therefore depends only on the XOR difference, and the whole
experiment reduces to recovering `ker(f)` — a linear subspace — instead of
probing an unstructured address space.

Host-only. This module models, predicts and recovers; it performs no device,
SMC, MMIO, or memory access and does not itself measure anything.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

from tools import gf2

# Rank-relative offsets are 32 bits wide in the exact Experiment 011 formula.
WIDTH = 32

# Experiment 011, for the retained 3072+3072 MiB topology.
RANK_BASES = (0x80000000, 0x140000000)
RANK_BOUNDARY = 0x140000000

# row=PAoff[31:16], bank=PAoff[15:13], channel=PAoff[10:9],
# column=PAoff[12:11]||PAoff[8:1], byte=PAoff[0]
DIAGNOSTIC_ROW_BITS = tuple(range(16, 32))
DIAGNOSTIC_BANK_BITS = (13, 14, 15)
DIAGNOSTIC_CHANNEL_BITS = (9, 10)

ROW_MASK = sum(1 << bit for bit in DIAGNOSTIC_ROW_BITS)


class ModelError(ValueError):
    """Raised when a model or observation set is structurally inconsistent."""


# --------------------------------------------------------------------------
# selection models
# --------------------------------------------------------------------------


def diagnostic_selection_rows() -> tuple[int, ...]:
    """Return the Experiment 011 bank/channel selection as GF(2) row masks.

    Output bit order is bank[0..2] then channel[0..1]. Each row is a single
    address bit: the diagnostic model contains no XOR term.
    """
    bit_sets = [(bit,) for bit in DIAGNOSTIC_BANK_BITS]
    bit_sets += [(bit,) for bit in DIAGNOSTIC_CHANNEL_BITS]
    return gf2.rows_from_bit_sets(bit_sets, WIDTH)


def with_xor_term(rows: Sequence[int], output_bit: int, address_bit: int) -> tuple[int, ...]:
    """Return ``rows`` with one address bit XORed into one selection output.

    This is the negative control. A real channel/bank hash of the kind Qualcomm
    filings describe as a design class would appear exactly like this, and the
    diagnostic formula would not represent it.
    """
    if not 0 <= output_bit < len(rows):
        raise ModelError("output bit falls outside the selection width")
    if not 0 <= address_bit < WIDTH:
        raise ModelError("address bit falls outside the transform width")
    mutated = list(rows)
    mutated[output_bit] ^= 1 << address_bit
    return tuple(mutated)


def selection_rank(rows: Sequence[int]) -> int:
    return gf2.rank(rows, WIDTH)


# --------------------------------------------------------------------------
# kernel / row-space duality
# --------------------------------------------------------------------------


def kernel_basis(rows: Sequence[int]) -> tuple[int, ...]:
    """Return a basis for ``ker(f)`` — the differences that do not change bank."""
    solution = gf2.solve(rows, 0, WIDTH)
    if solution is None:
        raise ModelError("homogeneous system is unexpectedly inconsistent")
    return solution.nullspace


def orthogonal_complement(basis: Sequence[int]) -> tuple[int, ...]:
    """Return a basis for the space of rows orthogonal to every vector in ``basis``.

    Applied to a kernel basis this reconstructs the selection function's row
    space, which is the recovery direction of the experiment.
    """
    if not basis:
        return gf2.identity(WIDTH)
    solution = gf2.solve(tuple(basis), 0, WIDTH)
    if solution is None:
        raise ModelError("homogeneous system is unexpectedly inconsistent")
    return solution.nullspace


def in_span(basis: Sequence[int], value: int) -> bool:
    """Return whether ``value`` lies in the GF(2) span of ``basis``."""
    if value == 0:
        return True
    if not basis:
        return False
    return gf2.rank(tuple(basis) + (value,), WIDTH) == gf2.rank(tuple(basis), WIDTH)


def same_row_space(left: Sequence[int], right: Sequence[int]) -> bool:
    """Return whether two row sets span the same GF(2) space."""
    if gf2.rank(left, WIDTH) != gf2.rank(right, WIDTH):
        return False
    combined = tuple(left) + tuple(right)
    return gf2.rank(combined, WIDTH) == gf2.rank(left, WIDTH)


# --------------------------------------------------------------------------
# conflict prediction
# --------------------------------------------------------------------------


def same_selection(rows: Sequence[int], difference: int) -> bool:
    """Return whether an XOR difference leaves bank and channel unchanged."""
    if difference < 0 or difference >= (1 << WIDTH):
        raise ModelError("difference falls outside the transform width")
    return gf2.apply(rows, difference, WIDTH) == 0


def predicts_conflict(rows: Sequence[int], difference: int) -> bool:
    """Return whether a difference should produce a row-buffer conflict.

    A conflict needs both conditions: the two addresses select the same bank and
    channel, and they land on different rows. Same bank *and* same row is a row
    hit, which is fast and would be misread as "different bank" by a naive
    timing test.
    """
    return same_selection(rows, difference) and (difference & ROW_MASK) != 0


def distinguishing_differences(
    left: Sequence[int],
    right: Sequence[int],
    candidates: Iterable[int],
) -> tuple[int, ...]:
    """Return candidate differences where two models disagree about conflict.

    These are the only address pairs worth measuring: every other pair produces
    the same prediction under both models and carries no information.
    """
    out = []
    for difference in candidates:
        if predicts_conflict(left, difference) != predicts_conflict(right, difference):
            out.append(difference)
    return tuple(out)


def single_and_pair_differences(bits: Iterable[int] | None = None) -> tuple[int, ...]:
    """Return every single-bit and two-bit difference over the given bits."""
    bit_list = sorted(set(bits)) if bits is not None else list(range(WIDTH))
    for bit in bit_list:
        if not 0 <= bit < WIDTH:
            raise ModelError("bit index falls outside the transform width")
    out = [1 << bit for bit in bit_list]
    for index, low in enumerate(bit_list):
        for high in bit_list[index + 1 :]:
            out.append((1 << low) | (1 << high))
    return tuple(out)


def pivot_probe_set(pivot_bit: int) -> tuple[int, ...]:
    """Phase 1 of the device protocol: ``WIDTH`` probes against one row pivot.

    Every probe carries ``pivot_bit`` so that it differs in row and can register
    as a conflict at all. Given that the pivot itself lies in the kernel, probe
    ``pivot ^ bit`` conflicts exactly when ``bit`` also lies in the kernel, so
    one sweep classifies every individual address bit.

    The pivot must be verified in the kernel first: probe it alone and require a
    conflict. A pivot that does not conflict alone participates in the selection
    function and cannot be used as a reference.
    """
    if pivot_bit not in DIAGNOSTIC_ROW_BITS:
        raise ModelError("pivot must be a row bit or no probe can conflict")
    probes = [1 << pivot_bit]
    probes += [
        (1 << pivot_bit) | (1 << bit) for bit in range(WIDTH) if bit != pivot_bit
    ]
    return tuple(probes)


def suspect_bits(
    observations: Sequence["Observation"], pivot_bit: int
) -> tuple[int, ...]:
    """Return the address bits phase 1 showed are *not* individually in the kernel.

    For the pure diagnostic model these are exactly the bank and channel bits.
    Any additional suspect is the first sign of a term the diagnostic formula
    does not represent.
    """
    pivot = 1 << pivot_bit
    suspects = []
    for observation in observations:
        difference = observation.difference
        if difference == pivot or (difference & pivot) == 0:
            continue
        remainder = difference ^ pivot
        if remainder.bit_count() != 1:
            continue
        if not observation.conflict:
            suspects.append(remainder.bit_length() - 1)
    return tuple(sorted(set(suspects)))


def refinement_probe_set(
    suspects: Iterable[int], pivot_bit: int
) -> tuple[int, ...]:
    """Phase 2: row-qualified pair probes among the phase-1 suspects.

    A hash such as ``bank[0] = PA[13] ^ PA[17]`` hides from phase 1 because
    neither bit is individually in the kernel, but their XOR is. Pairing the
    suspects exposes it.

    Every pair also includes the already-verified row ``pivot_bit``. Without
    that qualifier, a pair made only of bank/channel bits can select the same
    bank *and the same row*. Such a row hit is fast and is observationally
    indistinguishable from a different-bank result in conflict timing. Since
    the pivot is in the kernel, XORing it into the pair does not alter the
    selection test; it only guarantees that a kernel pair changes row.
    """
    if pivot_bit not in DIAGNOSTIC_ROW_BITS:
        raise ModelError("pivot must be a row bit or no probe can conflict")
    bit_list = sorted(set(suspects))
    if pivot_bit in bit_list:
        raise ModelError("verified pivot cannot also be a suspect")
    out = []
    for index, low in enumerate(bit_list):
        for high in bit_list[index + 1 :]:
            out.append((1 << pivot_bit) | (1 << low) | (1 << high))
    return tuple(out)


# --------------------------------------------------------------------------
# recovery from observations
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Observation:
    """One measured XOR difference and whether it produced a conflict."""

    difference: int
    conflict: bool


@dataclass(frozen=True)
class Recovery:
    kernel_basis: tuple[int, ...]
    selection_rows: tuple[int, ...]
    selection_rank: int
    inconsistent: tuple[int, ...]

    @property
    def consistent(self) -> bool:
        return not self.inconsistent

    @property
    def kernel_dimension(self) -> int:
        return len(self.kernel_basis)


def recover(observations: Sequence[Observation]) -> Recovery:
    """Recover the selection function's row space from labelled differences.

    Conflicting differences that carry a row bit lie in ``ker(f)``; the kernel is
    a linear subspace, so its span is accumulated by elimination and the row
    space is its orthogonal complement.

    A conflicting difference with no row bit is a row hit rather than a bank
    collision and carries no kernel information, so it is ignored rather than
    treated as evidence.
    """
    span: list[int] = []
    for observation in observations:
        if not observation.conflict:
            continue
        if (observation.difference & ROW_MASK) == 0:
            continue
        if not in_span(span, observation.difference):
            span.append(observation.difference)

    rows = orthogonal_complement(span)

    # a non-conflicting difference must fall outside the recovered kernel
    inconsistent = []
    for observation in observations:
        if observation.conflict:
            continue
        if (observation.difference & ROW_MASK) == 0:
            continue
        if in_span(span, observation.difference):
            inconsistent.append(observation.difference)

    return Recovery(
        kernel_basis=tuple(span),
        selection_rows=tuple(rows),
        selection_rank=gf2.rank(rows, WIDTH),
        inconsistent=tuple(inconsistent),
    )


def protocol_complete(observations: Sequence[Observation], pivot_bit: int) -> bool:
    """Whether an observation set covers the full two-phase protocol.

    Completeness cannot be read off the recovered algebra. Rank-nullity makes
    ``kernel_dimension + selection_rank == WIDTH`` hold for *any* span, complete
    or not, so a partial probe set still returns a well-formed row space — just
    a larger one than the truth. Coverage is therefore a property of which
    differences were actually measured, and must be checked directly.
    """
    measured = {observation.difference for observation in observations}
    if not set(pivot_probe_set(pivot_bit)) <= measured:
        return False
    suspects = suspect_bits(observations, pivot_bit)
    return set(refinement_probe_set(suspects, pivot_bit)) <= measured


def cross_validate(
    rows: Sequence[int], observations: Sequence[Observation]
) -> tuple[int, int, tuple[int, ...]]:
    """Score a model against held-out observations.

    Returns ``(agreements, total, mismatched_differences)``. A model that
    survives held-out differences is supported; one that mispredicts even a
    single clean difference is refuted for that difference.
    """
    agreements = 0
    mismatched = []
    for observation in observations:
        if predicts_conflict(rows, observation.difference) == observation.conflict:
            agreements += 1
        else:
            mismatched.append(observation.difference)
    return agreements, len(observations), tuple(mismatched)


def synthesize(rows: Sequence[int], differences: Iterable[int]) -> tuple[Observation, ...]:
    """Generate noiseless observations from a known model, for validation only."""
    return tuple(
        Observation(difference, predicts_conflict(rows, difference))
        for difference in differences
    )


# --------------------------------------------------------------------------
# address-pair construction for the device protocol
# --------------------------------------------------------------------------


def rank_relative(physical_address: int) -> tuple[int, int]:
    """Split a physical address into (rank index, rank-relative offset)."""
    for index in reversed(range(len(RANK_BASES))):
        base = RANK_BASES[index]
        if physical_address >= base:
            offset = physical_address - base
            if offset >= (1 << WIDTH):
                raise ModelError("rank-relative offset exceeds the model width")
            return index, offset
    raise ModelError("physical address falls below the first rank base")


def pair_for_difference(base_offset: int, difference: int) -> tuple[int, int]:
    """Return the rank-relative offset pair realising one XOR difference."""
    if base_offset < 0 or base_offset >= (1 << WIDTH):
        raise ModelError("base offset falls outside the transform width")
    if difference < 0 or difference >= (1 << WIDTH):
        raise ModelError("difference falls outside the transform width")
    return base_offset, base_offset ^ difference
