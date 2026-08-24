#!/usr/bin/env python3
"""Small, dependency-free GF(2) helpers for address-transform experiments.

A transform is represented by one integer bit-mask per output bit. Bit j of an
output is the parity of ``rows[j] & input_value``. The helpers intentionally do
not encode any Qualcomm-specific mapping.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence


def _validate(rows: Sequence[int], width: int) -> None:
    if width <= 0:
        raise ValueError("width must be positive")
    limit = 1 << width
    if any(row < 0 or row >= limit for row in rows):
        raise ValueError("row mask falls outside transform width")


def parity(value: int) -> int:
    """Return the parity of a non-negative integer."""
    if value < 0:
        raise ValueError("value must be non-negative")
    return value.bit_count() & 1


def apply(rows: Sequence[int], value: int, width: int) -> int:
    """Apply a row-mask matrix to ``value``."""
    _validate(rows, width)
    if value < 0 or value >= (1 << width):
        raise ValueError("input falls outside transform width")
    output = 0
    for bit, row in enumerate(rows):
        output |= parity(row & value) << bit
    return output


def identity(width: int) -> tuple[int, ...]:
    if width <= 0:
        raise ValueError("width must be positive")
    return tuple(1 << bit for bit in range(width))


def rank(rows: Sequence[int], width: int) -> int:
    """Return the row rank of a GF(2) matrix."""
    _validate(rows, width)
    work = list(rows)
    pivot_row = 0
    for column in range(width):
        selected = next(
            (idx for idx in range(pivot_row, len(work)) if (work[idx] >> column) & 1),
            None,
        )
        if selected is None:
            continue
        work[pivot_row], work[selected] = work[selected], work[pivot_row]
        for idx in range(len(work)):
            if idx != pivot_row and ((work[idx] >> column) & 1):
                work[idx] ^= work[pivot_row]
        pivot_row += 1
        if pivot_row == len(work):
            break
    return pivot_row


@dataclass(frozen=True)
class Solution:
    particular: int
    nullspace: tuple[int, ...]
    pivot_columns: tuple[int, ...]

    def contains(self, value: int) -> bool:
        """Check membership by enumerating the nullspace for small test cases."""
        candidates = {self.particular}
        for basis in self.nullspace:
            candidates |= {candidate ^ basis for candidate in tuple(candidates)}
        return value in candidates


def solve(rows: Sequence[int], target: int, width: int) -> Solution | None:
    """Solve ``rows * x = target`` over GF(2).

    Returns one particular solution and a basis for all homogeneous solutions,
    or ``None`` when the target is inconsistent with the transform.
    """
    _validate(rows, width)
    if target < 0 or target >= (1 << len(rows)):
        raise ValueError("target falls outside output width")

    augmented = [row | (((target >> bit) & 1) << width) for bit, row in enumerate(rows)]
    pivot_columns: list[int] = []
    pivot_row = 0

    for column in range(width):
        selected = next(
            (
                idx
                for idx in range(pivot_row, len(augmented))
                if (augmented[idx] >> column) & 1
            ),
            None,
        )
        if selected is None:
            continue
        augmented[pivot_row], augmented[selected] = augmented[selected], augmented[pivot_row]
        for idx in range(len(augmented)):
            if idx != pivot_row and ((augmented[idx] >> column) & 1):
                augmented[idx] ^= augmented[pivot_row]
        pivot_columns.append(column)
        pivot_row += 1
        if pivot_row == len(augmented):
            break

    variable_mask = (1 << width) - 1
    for row in augmented:
        if (row & variable_mask) == 0 and ((row >> width) & 1):
            return None

    particular = 0
    for row_idx, column in enumerate(pivot_columns):
        if (augmented[row_idx] >> width) & 1:
            particular |= 1 << column

    pivot_set = set(pivot_columns)
    nullspace: list[int] = []
    for free_column in (column for column in range(width) if column not in pivot_set):
        vector = 1 << free_column
        for row_idx, pivot_column in enumerate(pivot_columns):
            if (augmented[row_idx] >> free_column) & 1:
                vector |= 1 << pivot_column
        nullspace.append(vector)

    return Solution(particular, tuple(nullspace), tuple(pivot_columns))


def compose(outer: Sequence[int], inner: Sequence[int], width: int) -> tuple[int, ...]:
    """Return the row masks for ``outer(inner(x))``."""
    _validate(outer, width)
    _validate(inner, width)
    if len(inner) != width:
        raise ValueError("inner transform must have exactly width output rows")
    result = []
    for outer_row in outer:
        row = 0
        for bit in range(width):
            if (outer_row >> bit) & 1:
                row ^= inner[bit]
        result.append(row)
    return tuple(result)


def rows_from_bit_sets(bit_sets: Iterable[Iterable[int]], width: int) -> tuple[int, ...]:
    rows = []
    for bits in bit_sets:
        row = 0
        for bit in bits:
            if bit < 0 or bit >= width:
                raise ValueError("bit index falls outside transform width")
            row ^= 1 << bit
        rows.append(row)
    return tuple(rows)
