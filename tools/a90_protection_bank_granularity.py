#!/usr/bin/env python3
"""Verification 017: can a bank-granular check separate protected memory?

The question this project exists to answer decomposes into two premises.  P1 is
that a mutable address transform sits downstream of the protection check; P2 is
that Normal World can reach the state that changes it.  P2 has been closed on
every route tested.  P1 has always had an unexamined half: *where the check sits
relative to the transform* has been `UNKNOWN` since Experiment 008, and no
experiment proposed a way at it, because observing enforcement ordering in the
data path needs either a controller write or a protected read.

There is one thing about the ordering that can be settled without either, and it
follows from the recovered relation rather than from any new measurement.

The argument
------------
Experiment 023R recovered a rank-3 GF(2) bank-selection relation, and
Verification 016 extended it to PA27 with the rank unchanged.  Rank 3 means
eight bank classes.  The lowest address bit carrying a contribution is PA13, so
the class changes every 8 KiB, and three independent contributions appear by
PA15, so **every region of 64 KiB or more covers all eight classes**.

The protected carveouts on this target are megabytes wide.  So is the
unprotected `System RAM` around them.  Both therefore occupy every bank class,
and a check that saw only a bank index could not tell one from the other.

What this settles, and what it does not
---------------------------------------
It refutes one specific shape of enforcement: a check reading only post-decode
*bank* coordinates.  It does not settle the ordering question.  The full DRAM
coordinate — channel, rank, bank, row, column — is a bijection with the physical
address whenever the map is invertible, so a check on the complete post-decode
coordinate carries exactly the same information as a check on the address and
cannot be distinguished this way.  What is excluded is the *narrow* post-decode
check, which is the only one that would have made the transform irrelevant to
enforcement.

That leaves the Skitter premise standing on this platform for the reason it
stands on AMD: enforcement has to retain address information that the DRAM bank
index does not carry, so a mutable map downstream of it would move data under a
check that could not see the move.  This is a structural argument about
granularity, not an observation of the data path, and it is ranked accordingly.
"""

from __future__ import annotations

import argparse
import json
import pathlib
from collections.abc import Mapping, Sequence

SCHEMA = "a90-protection-bank-granularity-v1"

PAGE_BYTES = 0x1000

#: The rank-3 relation.  PA13..PA23 are Experiment 023R's solved contributions,
#: PA24 is its exhaustively discriminated one, and PA25..PA27 are Verification
#: 016's, each of which duplicates a lower bit's vector rather than adding a
#: dimension.
RELATION: dict[int, int] = {
    13: 0b001, 14: 0b010, 15: 0b100, 16: 0b011, 17: 0b110, 18: 0b111,
    19: 0b101, 20: 0b001, 21: 0b010, 22: 0b100, 23: 0b011, 24: 0b110,
    25: 0b010, 26: 0b101, 27: 0b001,
}

#: Verification 016 determined these by discrimination, independently of the
#: table above.  They must agree with it, and the agreement is checked.
V016_EQUALITIES: dict[int, tuple[int, ...]] = {
    25: (14, 21),
    26: (19,),
    27: (13, 20),
}

#: Carveouts whose live device-tree `reg` is `PROVED` in docs/MEMORY_MAP.md.
PROTECTED_REGIONS: tuple[tuple[str, int, int], ...] = (
    ("hyp_mem",         0x85700000, 0x00600000),
    ("tima_region",     0xB0000000, 0x00200000),
    ("rkp_region",      0xB0200000, 0x00200000),
    ("uh_heap_region",  0xB0400000, 0x01400000),
    ("qseecom_region",  0xA6000000, 0x02400000),
)

#: `System RAM` fragments observed live in /proc/iomem, used as the unprotected
#: comparison.  Only fragments at least a page long are listed.
SYSTEM_RAM: tuple[tuple[int, int], ...] = (
    (0x80002000, 0x856FFFFF),
    (0x85D00000, 0x85DFFFFF),
    (0x9C400000, 0x9FFFFFFF),
    (0xA8400000, 0xAFFFFFFF),
    (0xB0200000, 0xBCBFFFFF),
    (0xC1C01000, 0x1FFFFFFFF),
)


class GranularityError(RuntimeError):
    pass


def bank_class(address: int, relation: Mapping[int, int] = RELATION) -> int:
    """f(address) as a 3-bit bank vector."""
    value = 0
    for bit, contribution in relation.items():
        if (address >> bit) & 1:
            value ^= contribution
    return value


def check_v016_consistency(
    relation: Mapping[int, int] = RELATION,
    equalities: Mapping[int, Sequence[int]] = V016_EQUALITIES,
) -> dict:
    """Verification 016's discrimination must agree with the solved table."""
    rows, disagreements = [], []
    for high, lowers in sorted(equalities.items()):
        for lower in lowers:
            agrees = relation[high] == relation[lower]
            rows.append({
                "high": high, "lower": lower,
                "high_vector": relation[high], "lower_vector": relation[lower],
                "agrees": agrees,
            })
            if not agrees:
                disagreements.append((high, lower))
    return {"rows": rows, "agrees": not disagreements,
            "disagreements": disagreements}


def class_change_granularity(relation: Mapping[int, int] = RELATION) -> int:
    """The smallest span over which the bank class can change."""
    contributing = [bit for bit, vector in relation.items() if vector]
    if not contributing:
        raise GranularityError("the relation has no contributing bit")
    return 1 << min(contributing)


def span_to_cover_all_classes(relation: Mapping[int, int] = RELATION) -> int:
    """Smallest region size guaranteed to cover every class.

    Walking the contributing bits from the bottom, the classes reachable are the
    span of the vectors seen so far.  Once that span is the whole space, a
    region large enough to vary those bits covers every class.
    """
    basis: list[int] = []
    for bit in sorted(bit for bit, vector in relation.items() if vector):
        vector = relation[bit]
        for member in basis:
            vector = min(vector, vector ^ member)
        if vector:
            basis.append(vector)
            basis.sort(reverse=True)
        if len(basis) == 3:
            return 1 << (bit + 1)
    raise GranularityError("the relation never reaches full rank")


def classes_in_range(base: int, size: int,
                     relation: Mapping[int, int] = RELATION,
                     cap_pages: int = 1 << 16) -> dict:
    """Count pages per bank class across a physical range."""
    if size <= 0:
        raise GranularityError("a range needs a positive size")
    pages = size // PAGE_BYTES
    counted = min(pages, cap_pages)
    histogram = {index: 0 for index in range(8)}
    for page in range(counted):
        histogram[bank_class(base + page * PAGE_BYTES, relation)] += 1
    return {
        "base": f"0x{base:x}",
        "size": size,
        "pages": pages,
        "pages_counted": counted,
        "truncated": counted < pages,
        "histogram": histogram,
        "classes_covered": sum(1 for value in histogram.values() if value),
    }


def analyse(relation: Mapping[int, int] = RELATION) -> dict:
    consistency = check_v016_consistency(relation)
    granularity = class_change_granularity(relation)
    covering = span_to_cover_all_classes(relation)

    protected = []
    for name, base, size in PROTECTED_REGIONS:
        entry = classes_in_range(base, size, relation)
        entry["name"] = name
        protected.append(entry)

    unprotected = []
    for start, end in SYSTEM_RAM:
        entry = classes_in_range(start, end - start + 1, relation)
        entry["name"] = f"System RAM 0x{start:x}-0x{end:x}"
        unprotected.append(entry)

    every_protected = all(e["classes_covered"] == 8 for e in protected)
    every_unprotected = all(e["classes_covered"] == 8 for e in unprotected)

    return {
        "schema": SCHEMA,
        "relation": {str(bit): vector for bit, vector in sorted(relation.items())},
        "rank": 3,
        "v016_consistency": consistency,
        "class_change_granularity_bytes": granularity,
        "span_covering_all_classes_bytes": covering,
        "protected_regions": protected,
        "unprotected_ranges": unprotected,
        "all_protected_cover_every_class": every_protected,
        "all_unprotected_cover_every_class": every_unprotected,
        "bank_granular_check_can_separate": not (every_protected and every_unprotected),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)

    result = analyse()
    pathlib.Path(args.output).write_text(json.dumps(result, indent=1) + "\n")

    print(f"relation rank 3, class changes every "
          f"{result['class_change_granularity_bytes']} bytes; "
          f"{result['span_covering_all_classes_bytes']} bytes covers all 8")
    print(f"Verification 016 agrees with the solved table: "
          f"{result['v016_consistency']['agrees']}")
    print()
    for entry in result["protected_regions"] + result["unprotected_ranges"]:
        print(f"  {entry['name']:<34} {entry['pages']:>9} pages  "
              f"classes covered {entry['classes_covered']}/8")
    print()
    print(f"a bank-granular check can separate protected from unprotected: "
          f"{result['bank_granular_check_can_separate']}")
    return 0


if __name__ == "__main__":
    import sys

    raise SystemExit(main(sys.argv[1:]))
