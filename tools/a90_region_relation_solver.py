#!/usr/bin/env python3
"""Experiment 023R analysis: base offset, bank relation, and its uniqueness.

Experiment 023 was withheld `NO-GO` for three reasons.  The probe repairs the
protocol defect; this module answers the other two.

Physical-address provenance.  `/proc/self/pagemap` is blind to the dma-buf
mapping, so the allocation's physical base cannot simply be read.  Experiment
023 assumed the allocation began at the carveout base and offered, as
verification, that nine differences classified as Experiment 014 classified
them.  That is not a test of the assumption: a shifted base reproduces those
same labels whenever the shift happens not to carry into the bits the
differences name.  `solve_base_offset` replaces the assumption with a
measurement.  For allocation base ``B = region_base + delta`` and page-aligned
offsets ``a`` and ``a ^ d``, the physical difference is
``(B + a) ^ (B + (a ^ d))``, which equals ``d`` only when adding ``B``
introduces no differing carries.  Sweeping offsets that vary in their low bits
therefore makes ``delta`` observable, and every candidate ``delta`` that
disagrees with even one measured pair is eliminated.  This uses only the
Experiment 014 relation over bits 13..23 and never PA24, so it cannot be
circular with the PA24 claim under test.

Uniqueness.  A conflict measurement observes only whether ``f(d) == 0``, so
what the data can determine is the kernel of ``f``, not ``f`` itself: any
basis change in ``GL(3,2)`` relabels ``b0/b1/b2`` while predicting identical
conflicts, and 168 such relabellings exist.  Reporting a single matrix as
though it were pinned overstates the evidence, which is the defect Experiment
023 had.  `kernel_analysis` states the claim at the level the measurement
supports: it spans the observed conflicting differences, compares that span's
dimension against the dimension a rank-three map forces, and counts how many
kernels remain consistent with every observation.  A count of one is a
uniqueness proof for the relation; a larger count is the honest ambiguity.
"""
from __future__ import annotations

import itertools
import json

SCHEMA = "a90-region-relation-solver-v1"

#: Experiment 014's proved relation over PA13..PA23, as one 3-bit vector per
#: address bit.  Bit 0 of each vector is b0, bit 1 is b1, bit 2 is b2:
#:   b0 = PA13^PA16^PA18^PA19^PA20^PA23
#:   b1 = PA14^PA16^PA17^PA18^PA21^PA23
#:   b2 = PA15^PA17^PA18^PA19^PA22
BASE_RELATION: dict[int, int] = {
    13: 0b001, 14: 0b010, 15: 0b100, 16: 0b011, 17: 0b110, 18: 0b111,
    19: 0b101, 20: 0b001, 21: 0b010, 22: 0b100, 23: 0b011,
}

#: The device-tree declared qseecom carveout: reg = <0x0 0xa6000000 0x0 0x2400000>.
REGION_BASE = 0xA6000000
REGION_SIZE = 0x02400000
ALLOCATION_SIZE = 0x02000000
PAGE_BYTES = 0x1000


def vector(difference: int, relation: dict[int, int]) -> int:
    """f(difference) as a 3-bit bank vector, over the supplied relation."""
    value = 0
    for bit, contribution in relation.items():
        if (difference >> bit) & 1:
            value ^= contribution
    return value


def covered(difference: int, relation: dict[int, int]) -> bool:
    """Does every set bit of the difference have a modelled contribution?

    A difference with a set bit outside the relation is not predictable: the
    model says nothing about that bit, so the prediction would silently treat
    an unmodelled bit as contributing nothing.
    """
    modelled = 0
    for bit in relation:
        modelled |= 1 << bit
    return difference & ~modelled & ~(PAGE_BYTES - 1) == 0


def physical_difference(base: int, offset: int, difference: int) -> int:
    """The physical difference a pair actually realises at a given base.

    Equal to ``difference`` only when adding the base carries identically for
    both members of the pair.
    """
    return (base + offset) ^ (base + (offset ^ difference))


#: Experiment 014's reported bounds, used only to check comparability of this
#: run's separation against it -- never as this run's classifier.
Y014_KERNEL_FLOOR = 536
Y014_NEGATIVE_CEILING = 222


def separation_threshold(values: list[int]) -> dict:
    """Split measured deltas into two classes using only the measurements.

    Importing Experiment 014's numeric floor as this run's classifier would
    make agreement with 014 partly an artefact of the threshold.  The split is
    therefore taken where the sorted deltas have their widest gap, which uses
    no model and no prior run, and the width of that gap is reported so a weak
    separation cannot be mistaken for a clean one.
    """
    if len(values) < 2:
        return {"threshold": None, "gap": 0, "low_max": None, "high_min": None}
    ordered = sorted(values)
    widest = max(range(len(ordered) - 1), key=lambda i: ordered[i + 1] - ordered[i])
    low_max, high_min = ordered[widest], ordered[widest + 1]
    return {
        "threshold": (low_max + high_min) // 2,
        "gap": high_min - low_max,
        "low_max": low_max,
        "high_min": high_min,
    }


def classify(delta: int, kernel_floor: int, negative_ceiling: int) -> str:
    """Label one measured delta against an explicit pair of bounds.

    A delta between the two bounds is reported as ``AMBIGUOUS`` rather than
    forced into whichever class is nearer.
    """
    if delta >= kernel_floor:
        return "KERNEL"
    if delta <= negative_ceiling:
        return "NEGATIVE"
    return "AMBIGUOUS"


def solve_base_offset(
    pairs: list[dict],
    relation: dict[int, int],
    region_base: int = REGION_BASE,
    region_size: int = REGION_SIZE,
    allocation_size: int = ALLOCATION_SIZE,
) -> dict:
    """Which allocation offsets inside the region agree with every pair?

    Each pair carries the offset it used and the class it measured.  For a
    candidate ``delta`` the realised physical difference is recomputed and the
    predicted class compared with the measured one.  Ambiguous pairs
    constrain nothing and are excluded rather than guessed.
    """
    candidates = []
    limit = region_size - allocation_size
    usable = [p for p in pairs if p["label"] in ("KERNEL", "NEGATIVE")]
    for delta in range(0, limit + 1, PAGE_BYTES):
        base = region_base + delta
        for pair in usable:
            realised = physical_difference(base, pair["offset"], pair["difference"])
            if not covered(realised, relation):
                # Carries pushed the difference onto an unmodelled bit; this
                # candidate cannot be scored against this pair either way.
                continue
            predicted = "KERNEL" if vector(realised, relation) == 0 else "NEGATIVE"
            if predicted != pair["label"]:
                break
        else:
            candidates.append(delta)
    return {
        "schema": SCHEMA,
        "constraining_pairs": len(usable),
        "candidate_offsets": [f"0x{value:x}" for value in candidates],
        "candidate_count": len(candidates),
        "resolved": len(candidates) == 1,
        "offset": f"0x{candidates[0]:x}" if len(candidates) == 1 else None,
    }


def discriminate_new_bit(
    measurements: list[dict], relation: dict[int, int], new_bit: int
) -> dict:
    """Which contribution for a new address bit agrees with the measurements?

    Every one of the eight possible 3-bit contributions is scored against all
    measurements naming the new bit, rather than reading a single witness.  A
    single witness identifies a contribution only if the others are assumed
    excluded; scoring all eight makes the exclusion an observation.
    """
    survivors = []
    for candidate in range(8):
        extended = dict(relation)
        extended[new_bit] = candidate
        for entry in measurements:
            if entry["label"] not in ("KERNEL", "NEGATIVE"):
                continue
            if not covered(entry["difference"], extended):
                continue
            predicted = "KERNEL" if vector(entry["difference"], extended) == 0 else "NEGATIVE"
            if predicted != entry["label"]:
                break
        else:
            survivors.append(candidate)
    return {
        "schema": SCHEMA,
        "new_bit": new_bit,
        "surviving_contributions": [f"0b{value:03b}" for value in survivors],
        "survivor_count": len(survivors),
        "resolved": len(survivors) == 1,
        "contribution": f"0b{survivors[0]:03b}" if len(survivors) == 1 else None,
    }


def _span(vectors: list[int]) -> list[int]:
    """A row-reduced basis of the span of the given vectors over GF(2)."""
    basis: list[int] = []
    for value in vectors:
        current = value
        for element in basis:
            current = min(current, current ^ element)
        if current:
            basis.append(current)
            basis.sort(reverse=True)
    return basis


def _in_span(value: int, basis: list[int]) -> bool:
    current = value
    for element in basis:
        current = min(current, current ^ element)
    return current == 0


def _echelon_subspaces(dimension: int, size: int):
    """Yield one basis per `size`-dimensional subspace of GF(2)^dimension.

    Bases are produced in reduced row echelon form, so each subspace is
    yielded exactly once and the enumeration is the Gaussian binomial rather
    than the far larger set of generator tuples.
    """
    if size == 0:
        yield []
        return
    if size > dimension:
        return
    for pivots in itertools.combinations(range(dimension), size):
        free = [c for c in range(dimension) if c not in pivots]
        slots = [[c for c in free if c > pivot] for pivot in pivots]
        counts = [len(s) for s in slots]
        total = 1
        for count in counts:
            total <<= count
        for assignment in range(total):
            rows = []
            cursor = assignment
            for index, pivot in enumerate(pivots):
                row = 1 << pivot
                for column in slots[index]:
                    if cursor & 1:
                        row |= 1 << column
                    cursor >>= 1
                rows.append(row)
            yield rows


def _complete_basis(basis: list[int], bits: list[int]) -> list[int]:
    """Vectors that extend the given basis to the whole space over `bits`."""
    current = list(basis)
    extra: list[int] = []
    for bit in bits:
        candidate = 1 << bit
        if not _in_span(candidate, current):
            current = _span(current + [candidate])
            extra.append(candidate)
    return extra


def kernel_analysis(measurements: list[dict], bits: list[int], rank: int = 3) -> dict:
    """How much of the bank relation do these measurements actually pin down?

    A conflict measurement sees only whether ``f(d) == 0``, so the observable
    object is ``ker f``, not ``f``: any basis change in ``GL(3,2)`` relabels
    b0/b1/b2 and predicts identical conflicts.  Reporting one matrix as though
    the measurement chose it overstates the evidence.

    Under an assumed ``rank`` the kernel has dimension ``len(bits) - rank``.
    The conflicting differences span a subspace of it; if that span is already
    the full kernel dimension and no non-conflicting difference lies inside,
    exactly one kernel is consistent and the relation is pinned.  Otherwise the
    remaining kernels are counted by enumerating every way to extend the span
    inside the quotient space, which is small even when the raw vector count is
    not.  Extension candidates must range over the whole space: no single
    address bit lies in the kernel, so a single-bit pool would find nothing.
    """
    kernel = [m["difference"] for m in measurements if m["label"] == "KERNEL"]
    negative = [m["difference"] for m in measurements if m["label"] == "NEGATIVE"]
    basis = _span(kernel)
    required = len(bits) - rank
    contradictions = [f"0x{d:x}" for d in negative if _in_span(d, basis)]

    consistent = 0
    example = None
    if not contradictions and len(basis) <= required:
        complement = _complete_basis(basis, bits)
        need = required - len(basis)
        # Each extension is a `need`-dimensional subspace of the quotient.
        # Enumerating arbitrary generator tuples revisits the same subspace
        # exponentially often and does not terminate for a wide quotient;
        # enumerating reduced row echelon forms instead visits each subspace
        # exactly once.  Extension candidates must range over the whole
        # quotient: no single address bit lies in the kernel, so a pool built
        # from single bits would find nothing and report a false zero.
        for rows in _echelon_subspaces(len(complement), need):
            lifted = []
            for row in rows:
                value = 0
                for index, element in enumerate(complement):
                    if (row >> index) & 1:
                        value ^= element
                lifted.append(value)
            extended = _span(kernel + lifted)
            if len(extended) != required:
                continue
            if any(_in_span(d, extended) for d in negative):
                continue
            consistent += 1
            if example is None:
                example = [f"0x{v:x}" for v in extended]

    return {
        "schema": SCHEMA,
        "assumed_rank": rank,
        "observed_kernel_differences": len(kernel),
        "observed_negative_differences": len(negative),
        "span_dimension": len(basis),
        "required_kernel_dimension": required,
        "span_basis": [f"0x{v:x}" for v in basis],
        "contradictions": contradictions,
        "consistent_kernel_count": consistent,
        "unique": contradictions == [] and consistent == 1,
        "example_kernel_basis": example,
    }


def load_probe_jsonl(text: str) -> dict:
    """Split probe output into its context, pair, and difference records."""
    records = {"context": [], "ion_heap": [], "pa_provenance": [], "pair": [],
               "difference": []}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        entry = json.loads(line)
        records.setdefault(entry["type"], []).append(entry)
    return records


def rank_analysis(measurements: list[dict], bits: list[int],
                  ranks: tuple[int, ...] = (1, 2, 3, 4, 5)) -> dict:
    """Which ranks survive the measurements?

    Experiment 023 assumed a rank-three model because Experiment 014 used
    three bank vectors.  The assumption is unnecessary: a rank is refuted
    either when the conflicting differences span more dimensions than its
    kernel allows, or when no kernel of its dimension avoids every measured
    non-conflicting difference.  Reporting the surviving ranks turns the model
    order into a measured quantity.
    """
    results = {}
    for rank in ranks:
        analysis = kernel_analysis(measurements, bits, rank=rank)
        if analysis["span_dimension"] > analysis["required_kernel_dimension"]:
            verdict = "REFUTED_SPAN_EXCEEDS_KERNEL"
        elif analysis["contradictions"]:
            verdict = "REFUTED_NEGATIVE_INSIDE_SPAN"
        elif analysis["consistent_kernel_count"] == 0:
            verdict = "REFUTED_NO_KERNEL_AVOIDS_NEGATIVES"
        else:
            verdict = "CONSISTENT"
        results[rank] = {
            "verdict": verdict,
            "kernel_dimension": analysis["required_kernel_dimension"],
            "span_dimension": analysis["span_dimension"],
            "consistent_kernel_count": analysis["consistent_kernel_count"],
        }
    surviving = [r for r, v in results.items() if v["verdict"] == "CONSISTENT"]
    return {
        "schema": SCHEMA,
        "by_rank": results,
        "surviving_ranks": surviving,
        "resolved": len(surviving) == 1,
        "rank": surviving[0] if len(surviving) == 1 else None,
    }


def analyse(phase_text: dict[str, str], new_bit: int = 24,
            discrimination_phase: str = "phaseC",
            stride_phases: tuple[str, ...] = ("phaseA",)) -> dict:
    """Run the whole Experiment 023R analysis over raw probe output."""
    records: dict[str, list] = {}
    for name, text in phase_text.items():
        parsed = load_probe_jsonl(text)
        for key, values in parsed.items():
            records.setdefault(key, []).extend(dict(v, phase=name) for v in values)

    summaries = [r for r in records.get("difference", []) if "median" in r]
    separation = separation_threshold([r["median"] for r in summaries])
    threshold = separation["threshold"]
    differences = [
        {"difference": int(r["value"], 16),
         "label": "KERNEL" if r["median"] >= threshold else "NEGATIVE",
         "median": r["median"], "p10": r["p10"], "p90": r["p90"],
         "phase": r["phase"]}
        for r in summaries
    ]
    kernel = [d for d in differences if d["label"] == "KERNEL"]
    negative = [d for d in differences if d["label"] == "NEGATIVE"]

    # Only offsets that vary in their low bits constrain the base offset; the
    # evenly spaced stride phase is blind to it by construction.
    pairs = [
        {"difference": int(p["value"], 16), "offset": int(p["offset"], 16),
         "label": "KERNEL" if p["delta"] >= threshold else "NEGATIVE"}
        for p in records.get("pair", []) if p["phase"] not in stride_phases
    ]

    bits = sorted(BASE_RELATION) + [new_bit]
    return {
        "schema": SCHEMA,
        "separation": separation,
        "class_bounds": {
            "kernel_min_p10": min((d["p10"] for d in kernel), default=None),
            "negative_max_p90": max((d["p90"] for d in negative), default=None),
            "kernel_count": len(kernel),
            "negative_count": len(negative),
        },
        "comparable_to_014": (
            separation["low_max"] < Y014_NEGATIVE_CEILING < separation["high_min"]
            and separation["low_max"] < Y014_KERNEL_FLOOR < separation["high_min"]
        ),
        "pa_provenance": {
            "pagemap": records.get("pa_provenance", []),
            "base_offset": solve_base_offset(pairs, BASE_RELATION),
        },
        "new_bit": discriminate_new_bit(
            [d for d in differences if d["phase"] == discrimination_phase],
            BASE_RELATION, new_bit),
        "rank": rank_analysis(differences, bits),
        "kernel": kernel_analysis(differences, bits),
        "differences": differences,
    }


def _digest(path) -> str:
    import hashlib
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(argv: list[str]) -> int:
    import argparse
    import pathlib

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", required=True,
                        help="directory of phase*.jsonl probe output")
    parser.add_argument("--output", required=True, help="manifest path")
    parser.add_argument("--probe", help="probe source, hashed into the manifest")
    args = parser.parse_args(argv)

    raw = pathlib.Path(args.raw)
    inputs = sorted(raw.glob("phase*.jsonl"))
    texts = {p.stem: p.read_text() for p in inputs}
    if not texts:
        parser.error(f"no phase*.jsonl under {raw}")
    result = analyse(texts)
    here = pathlib.Path(__file__).resolve()
    result["provenance"] = {
        "mode": "DEVICE_READ_ONLY",
        "device_writes": "none: allocate, map, read, free only",
        "solver_sha256": _digest(here),
        "probe_sha256": _digest(pathlib.Path(args.probe)) if args.probe else None,
        # Raw phase output stays private; only its digest is published.
        "raw_inputs": {p.stem: _digest(p) for p in inputs},
    }
    pathlib.Path(args.output).write_text(json.dumps(result, indent=1) + "\n")
    print(json.dumps({k: result[k] for k in
                      ("separation", "class_bounds", "comparable_to_014")}, indent=1))
    print(json.dumps({"base_offset": result["pa_provenance"]["base_offset"],
                      "new_bit": result["new_bit"],
                      "rank": {"surviving": result["rank"]["surviving_ranks"],
                               "resolved": result["rank"]["resolved"]},
                      "kernel_unique": result["kernel"]["unique"]}, indent=1))
    return 0


if __name__ == "__main__":
    import sys as _sys
    raise SystemExit(main(_sys.argv[1:]))
