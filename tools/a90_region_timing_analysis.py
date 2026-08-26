#!/usr/bin/env python3
"""Host-only Experiment 023 analysis of second-region DRAM conflict timing.

Experiment 014 recovered a GF(2) bank-selection relation inside one 16 MiB ION
`user_contig` allocation and left PA bits 24 and above `UNKNOWN`. That was a
structural limit, not an omission: the heap is a 16 MiB CMA window, so bit 24
never varied and only one region was ever measured.

This analyses measurements taken in a second carveout. It needs no physical
address. For a linear f a conflict is f(a ^ b) == 0, a function of the
difference alone, so replaying a difference in another contiguous region tests
whether f is the same there.

That shortcut carries one requirement, and the measurements show what happens
when it is not met. The offset difference equals the physical difference only
when the allocation base is aligned to the allocation size; otherwise
``base + offset`` carries into bits the difference does not name. Differences
that stay below the first misaligned base bit remain valid, and the rest must
be excluded rather than read as disagreement.

Mode: HOST_ONLY_READ_ONLY on the analysis side. The measurements it reads were
taken by a probe that allocates, maps, reads and frees, and writes no register,
partition or memory outside its own allocation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Sequence

SCHEMA = "a90-region-timing-analysis-v1"
PROBE_SCHEMA = "a90_region_probe_v1"

# Experiment 014's recovered relation, as the contribution of each PA bit to a
# three-vector bank basis. Bit 13 -> 0b001, bit 14 -> 0b010, bit 15 -> 0b100.
BASE_RELATION = {
    13: 0b001, 14: 0b010, 15: 0b100,
    16: 0b011, 17: 0b110, 18: 0b111, 19: 0b101,
    20: 0b001, 21: 0b010, 22: 0b100, 23: 0b011,
}
# Bits that select a row: a difference must move one, or a same-bank pair is a
# row hit and reads as fast.
ROW_BITS = range(16, 32)

# Region bases taken from the device tree, not from a measurement.
QSECOM_REGION_BASE = 0xA6000000
QSECOM_REGION_SIZE = 0x02400000
# Experiment 014 bound its allocation to this interval.
USER_CONTIG_014_BASE = 0xF0400000
USER_CONTIG_014_SIZE = 0x01000000


class AnalysisError(ValueError):
    """Raised when a measurement set is not internally consistent."""


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_measurements(path: Path) -> dict:
    """Read one probe run: its context, its heap, and its differences."""
    context = None
    heap = None
    differences = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        record = json.loads(line)
        if record.get("schema") != PROBE_SCHEMA:
            continue
        kind = record.get("type")
        if kind == "context":
            context = record
        elif kind == "ion_heap":
            heap = record
        elif kind == "difference" and "p10" in record:
            differences.append(
                {
                    "difference": int(record["value"], 16),
                    "pairs": record["pairs"],
                    "p10": record["p10"],
                    "median": record["median"],
                    "p90": record["p90"],
                }
            )
    if context is None or heap is None:
        raise AnalysisError(f"{path.name} has no context or heap record")
    return {"context": context, "heap": heap, "differences": differences}


def evaluate(relation: dict[int, int], difference: int) -> int:
    """f(difference) over GF(2), as a 3-bit bank-basis vector."""
    output = 0
    for bit, contribution in relation.items():
        if difference >> bit & 1:
            output ^= contribution
    return output


def moves_a_row_bit(difference: int) -> bool:
    return any(difference >> bit & 1 for bit in ROW_BITS)


def predict(relation: dict[int, int], difference: int) -> str:
    """A conflict needs the same bank and a different row."""
    if evaluate(relation, difference) != 0:
        return "NEGATIVE"
    return "KERNEL" if moves_a_row_bit(difference) else "ROW_HIT"


def base_free_valid(difference: int, base: int, size: int) -> bool:
    """Is an offset difference equal to the physical difference here?

    Only when the base is aligned to the allocation size. Otherwise the base's
    own low bits carry, and any difference reaching them is not what it names.
    """
    misaligned = base % size
    if misaligned == 0:
        return True
    return difference < (misaligned & -misaligned)


def classify(differences: list[dict], separation: int) -> dict:
    """Split the measured differences into classes and check they separate.

    A classification is only meaningful if the two groups do not overlap: the
    lowest kernel p10 must exceed the highest negative p90 by the margin.
    """
    kernel = [d for d in differences if d["p10"] > 0 and d["median"] > 0]
    negative = [d for d in differences if d not in kernel]
    lowest_kernel = min((d["p10"] for d in kernel), default=None)
    highest_negative = max((d["p90"] for d in negative), default=None)
    gap = None
    if lowest_kernel is not None and highest_negative is not None:
        gap = lowest_kernel - highest_negative
    return {
        "kernel": sorted(f"0x{d['difference']:x}" for d in kernel),
        "negative": sorted(f"0x{d['difference']:x}" for d in negative),
        "lowest_kernel_p10": lowest_kernel,
        "highest_negative_p90": highest_negative,
        "non_overlap_gap": gap,
        "separated": gap is not None and gap >= separation,
    }


def solve_new_bit(differences: list[dict], relation: dict[int, int], new_bit: int) -> dict:
    """Recover one new bit's contribution from a discrimination sweep.

    Each probe difference is the new bit XOR one known contribution. Exactly
    one lands in the kernel, and it names the new bit's contribution.
    """
    hits = []
    for entry in differences:
        difference = entry["difference"]
        if not difference >> new_bit & 1:
            continue
        if entry["p10"] <= 0:
            continue
        remainder = difference & ~(1 << new_bit)
        hits.append((difference, evaluate(relation, remainder)))
    if len(hits) != 1:
        return {
            "resolved": False,
            "reason": f"expected exactly one kernel difference carrying bit {new_bit}, got {len(hits)}",
            "candidates": [f"0x{d:x}" for d, _ in hits],
        }
    difference, contribution = hits[0]
    return {
        "resolved": True,
        "bit": new_bit,
        "witness": f"0x{difference:x}",
        "contribution_vector": contribution,
        "contribution_basis": "^".join(
            name for index, name in enumerate(("b0", "b1", "b2")) if contribution >> index & 1
        )
        or "0",
    }


def verify(differences: list[dict], relation: dict[int, int]) -> dict:
    """Check the relation predicts every measured classification."""
    rows = []
    agree = 0
    for entry in differences:
        measured = "KERNEL" if entry["p10"] > 0 and entry["median"] > 0 else "NEGATIVE"
        predicted = predict(relation, entry["difference"])
        matched = (predicted == "KERNEL") == (measured == "KERNEL")
        agree += matched
        rows.append(
            {
                "difference": f"0x{entry['difference']:x}",
                "measured": measured,
                "predicted": predicted,
                "agrees": matched,
                "p10": entry["p10"],
                "p90": entry["p90"],
            }
        )
    return {"rows": rows, "agreements": agree, "total": len(rows),
            "all_agree": agree == len(rows)}


def build_manifest(paths: dict[str, Path], separation: int) -> dict:
    runs = {name: parse_measurements(path) for name, path in paths.items()}

    # Phase 1 ran in the Experiment 014 window, whose base is not aligned to a
    # 16 MiB allocation, so only differences below its lowest base bit hold.
    phase1 = runs["validation"]["differences"]
    valid = [d for d in phase1
             if base_free_valid(d["difference"], USER_CONTIG_014_BASE, USER_CONTIG_014_SIZE)]
    excluded = [d for d in phase1 if d not in valid]

    extended = dict(BASE_RELATION)
    solution = solve_new_bit(runs["discriminate"]["differences"], BASE_RELATION, 24)
    if solution["resolved"]:
        extended[24] = solution["contribution_vector"]

    return {
        "schema": SCHEMA,
        "experiment_id": "023-second-region-bank-relation",
        "mode": "HOST_ONLY_READ_ONLY",
        "measurement_context": {
            name: {
                "heap": run["heap"]["name"],
                "heap_type": run["heap"]["heap_type"],
                "heap_id": run["heap"]["heap_id"],
                "mib": run["context"]["mib"],
                "repetitions": run["context"]["repetitions"],
                "pairs": run["context"]["pairs"],
                "cpu": run["context"]["cpu"],
                "cntfrq": run["context"]["cntfrq"],
            }
            for name, run in runs.items()
        },
        "source_sha256": {name: sha256_file(path) for name, path in paths.items()},
        "base_free_method": {
            "requirement": "offset difference equals physical difference only when the "
                           "allocation base is aligned to the allocation size",
            "user_contig_014_base": f"0x{USER_CONTIG_014_BASE:08x}",
            "user_contig_014_misalignment": f"0x{USER_CONTIG_014_BASE % USER_CONTIG_014_SIZE:x}",
            "qsecom_region_base": f"0x{QSECOM_REGION_BASE:08x}",
            "qsecom_region_size": f"0x{QSECOM_REGION_SIZE:x}",
            "qsecom_32mib_aligned": QSECOM_REGION_BASE % 0x2000000 == 0,
            "validation_differences_excluded": sorted(f"0x{d['difference']:x}" for d in excluded),
        },
        "validation_in_014_window": {
            "classification": classify(valid, separation),
            "verification": verify(valid, BASE_RELATION),
        },
        "replay_in_qsecom_region": {
            "classification": classify(runs["replay"]["differences"], separation),
            "verification": verify(runs["replay"]["differences"], BASE_RELATION),
        },
        "pa24_discrimination": {
            "classification": classify(runs["discriminate"]["differences"], separation),
            "solution": solution,
        },
        "held_out_controls": {
            "classification": classify(runs["heldout"]["differences"], separation),
            "verification": verify(runs["heldout"]["differences"], extended),
        },
        "extended_relation": {
            f"PA{bit}": "^".join(
                name for index, name in enumerate(("b0", "b1", "b2")) if vector >> index & 1
            ) or "0"
            for bit, vector in sorted(extended.items())
        },
        "equations": [
            "b0 = " + " xor ".join(f"PA{bit}" for bit, v in sorted(extended.items()) if v & 1),
            "b1 = " + " xor ".join(f"PA{bit}" for bit, v in sorted(extended.items()) if v & 2),
            "b2 = " + " xor ".join(f"PA{bit}" for bit, v in sorted(extended.items()) if v & 4),
        ],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--validation", type=Path, required=True)
    parser.add_argument("--replay", type=Path, required=True)
    parser.add_argument("--discriminate", type=Path, required=True)
    parser.add_argument("--heldout", type=Path, required=True)
    parser.add_argument("--separation", type=int, default=100)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    manifest = build_manifest(
        {
            "validation": args.validation,
            "replay": args.replay,
            "discriminate": args.discriminate,
            "heldout": args.heldout,
        },
        args.separation,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(args.output, 0o644)
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
