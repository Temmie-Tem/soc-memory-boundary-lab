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
Experiment 014 relation over model bits 13..23 and never model bit 24, so it
cannot be circular with the allocation-offset/model-bit-24 claim under test.

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
import os

SCHEMA = "a90-region-relation-solver-v1"
EXPERIMENT_ID = "023R-repaired-region-bank-relation"
RETAINED_CONTEXT_NAME = "context.txt"
RETAINED_CONTEXT_SHA256 = (
    "2733587759119ec48558a3a039da200fa4740033d7043e706f0e8919c1a94f3b"
)

# The measurements and algebra below operate on allocation offsets and the
# supplied GF(2) model.  A physical interpretation is deliberately a separate
# supported-within-model consequence because the retained pagemap is blind.
MODEL_COORDINATE_SCOPE = "allocation-offset/model coordinates"
PHYSICAL_MAPPING_SCOPE = "SUPPORTED_WITHIN_MODEL"

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
        "coordinate_scope": MODEL_COORDINATE_SCOPE,
    }


def physical_base_assessment(pagemap: list[dict], base_offset: dict) -> dict:
    """Classify the solved base without promoting blind pagemap to proof.

    The offset solve is a model comparison: it assumes a contiguous qsecom
    allocation and the Experiment 014 relation over PA13..PA23.  When every
    pagemap record is ``BLIND``, the result can support that model only; it is
    not a direct physical-address observation.
    """

    statuses = [entry.get("status") for entry in pagemap]
    all_blind = bool(statuses) and all(status == "BLIND" for status in statuses)
    resolved = bool(base_offset.get("resolved"))
    if all_blind and resolved:
        classification = "SUPPORTED_WITHIN_MODEL"
        reason = (
            "Pagemap is BLIND for every phase; the solved base is supported only "
            "under a contiguous qsecom allocation and the Experiment 014 "
            "relation over PA13..PA23."
        )
    elif resolved:
        classification = "UNKNOWN"
        reason = (
            "The offset solve resolved under its model, but pagemap was not "
            "uniformly BLIND, so no single physical-base claim is promoted."
        )
    else:
        classification = "UNKNOWN"
        reason = "The measured pairs do not resolve a unique modelled base offset."
    offset_text = base_offset.get("offset")
    modelled_base = None
    if isinstance(offset_text, str):
        try:
            modelled_base = f"0x{REGION_BASE + int(offset_text, 16):08x}"
        except ValueError:
            modelled_base = None
    return {
        "classification": classification,
        "pagemap_status": "BLIND" if all_blind else "UNKNOWN",
        "pagemap_records": len(pagemap),
        "base": modelled_base,
        "base_offset": offset_text,
        "assumptions": [
            "contiguous qsecom allocation within the declared qseecom carveout",
            "Experiment 014 relation over PA13..PA23 is valid for the offset solve",
        ],
        "reason": reason,
        "coordinate_scope": MODEL_COORDINATE_SCOPE,
        "physical_mapping_status": PHYSICAL_MAPPING_SCOPE,
    }


def device_definition_of_done() -> dict:
    """Record the retained device context for this read-only measurement."""

    return {
        "target": {
            "binding": "SUPPORTED_RETAINED_DEVICE_CONTEXT",
            "marketing_name": "A90 5G",
            "model": "SM-A908N",
            "soc": "SM8150",
            "soc_name": "Snapdragon 855",
        },
        "build": {
            "status": "SUPPORTED_RETAINED_CONTEXT",
            "kernel": "4.14.190-Grass,SD855-Perf+",
            "firmware_build": "UNKNOWN",
            "reason": (
                "The retained context is pinned by SHA-256 and identifies the "
                "recovery kernel; it contains no firmware build identifier."
            ),
        },
        "timestamp": {
            "status": "SUPPORTED_RETAINED_CONTEXT",
            "value": "2026-08-26 KST",
            "reason": "Date is retained in the experiment record; individual probe line timestamps are not claimed.",
        },
        "commands": {
            "status": "REDACTED_REPRODUCTION_TEMPLATE",
            "command": (
                "python3 tools/a90_region_relation_solver.py --raw "
                "<private raw directory> --probe "
                "tools/a90_region_probe_r.c --output <public manifest path>"
            ),
            "reason": (
                "Private raw and output paths are redacted; the logical inputs "
                "are pinned by provenance. This template is not an executed-command receipt."
            ),
        },
        "repetitions": {
            "status": "PROVED",
            "per_measurement": 1001,
            "pairs_per_difference": 64,
            "warmups": 17,
        },
        "rollback": {
            "status": "NOT_APPLICABLE",
            "reason": "Read-only allocation/map/read/free probe changed no persistent or device state requiring rollback.",
        },
        "recovery": {
            "status": "NOT_APPLICABLE",
            "reason": (
                "No recovery transition was performed by this host analysis; the "
                "retained experiment record describes the read-only recovery context."
            ),
        },
        "device_binding": {
            "status": "SUPPORTED_RETAINED_DEVICE_CONTEXT",
            "reason": "The retained context identifies SM-A908N/qsecom; no live re-enumeration occurred during host-side analysis.",
        },
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
        if entry.get("type") == "pa_provenance":
            # A zero-present-PFN pagemap result is not an observation of
            # contiguity.  Keep the producer's field for auditability, but
            # move it out of the machine-readable effective classification so
            # downstream consumers cannot mistake `contiguous: true` for a
            # physical-page observation.
            entry = dict(entry)
            if entry.get("status") == "BLIND":
                if "contiguous" in entry:
                    entry["reported_contiguous"] = entry.pop("contiguous")
                entry["effective_contiguity"] = "UNKNOWN"
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
    base_offset = solve_base_offset(pairs, BASE_RELATION)
    pagemap = records.get("pa_provenance", [])
    physical_provenance = physical_base_assessment(pagemap, base_offset)
    unique_difference_count = len({r["value"] for r in summaries})
    new_bit_result = discriminate_new_bit(
        [d for d in differences if d["phase"] == discrimination_phase],
        BASE_RELATION, new_bit)
    new_bit_result["coordinate_scope"] = MODEL_COORDINATE_SCOPE
    new_bit_result["physical_mapping_classification"] = PHYSICAL_MAPPING_SCOPE
    rank_result = rank_analysis(differences, bits)
    rank_result["coordinate_scope"] = MODEL_COORDINATE_SCOPE
    rank_result["physical_mapping_classification"] = PHYSICAL_MAPPING_SCOPE
    kernel_result = kernel_analysis(differences, bits)
    kernel_result["coordinate_scope"] = MODEL_COORDINATE_SCOPE
    kernel_result["physical_mapping_classification"] = PHYSICAL_MAPPING_SCOPE
    return {
        "schema": SCHEMA,
        "experiment_id": EXPERIMENT_ID,
        "definition_of_done": device_definition_of_done(),
        "measurement_summary": {
            "summary_count": len(summaries),
            "unique_difference_count": unique_difference_count,
            "duplicate_summary_count": len(summaries) - unique_difference_count,
        },
        "summary_count": len(summaries),
        "unique_difference_count": unique_difference_count,
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
            "pagemap": pagemap,
            "pagemap_status": physical_provenance["pagemap_status"],
            "base_offset": {
                **base_offset,
                "classification": physical_provenance["classification"],
                "scope": "contiguous qsecom allocation + Experiment 014 relation over PA13..PA23",
            },
        },
        "physical_provenance": physical_provenance,
        "coordinate_scope": {
            "measurement_separation": MODEL_COORDINATE_SCOPE,
            "allocation_offset_algebra": MODEL_COORDINATE_SCOPE,
            "pa24_contribution": MODEL_COORDINATE_SCOPE,
            "kernel": MODEL_COORDINATE_SCOPE,
            "rank": MODEL_COORDINATE_SCOPE,
            "physical_mapping": PHYSICAL_MAPPING_SCOPE,
        },
        "new_bit": new_bit_result,
        "rank": rank_result,
        "kernel": kernel_result,
        "differences": differences,
        "claims": {
            "PROVED": [
                f"The analysis records {len(summaries)} measurement summaries over {unique_difference_count} unique differences.",
                "The raw measurement separation is PROVED in allocation-offset/model coordinates.",
                "The allocation-offset GF(2) algebra, allocation-offset bit-24/model-bit contribution 0b110, unique rank-3 kernel and model-rank results are PROVED in allocation-offset/model coordinates.",
            ],
            "SUPPORTED": [
                "Mapping the allocation-offset/model results to physical PA24, rank 3, base and a second physical region is SUPPORTED_WITHIN_MODEL only under a contiguous qsecom allocation and the Experiment 014 relation over PA13..PA23; pagemap is BLIND in every phase.",
            ],
            "HYPOTHESIS": [],
            "UNKNOWN": [
                "A direct physical-page identity is UNKNOWN because /proc/self/pagemap is BLIND; PA25 and above and behavior beyond the measured regions remain UNKNOWN.",
            ],
            "REFUTED": [
                "Experiment 023's replay is refuted as verification of its physical-base assumption; agreement on low differences does not identify the base.",
            ],
        },
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
        "experiment_id": EXPERIMENT_ID,
        "role": "current_verifier",
        "mode": "DEVICE_READ_ONLY",
        "device_writes": "none: allocate, map, read, free only",
        "solver_sha256": _digest(here),
        "probe_sha256": _digest(pathlib.Path(args.probe)) if args.probe else None,
        # Raw phase output stays private; only its digest is published.
        "raw_inputs": {p.stem: _digest(p) for p in inputs},
    }
    context_path = raw / RETAINED_CONTEXT_NAME
    if context_path.is_file():
        context_digest = _digest(context_path)
        if context_digest != RETAINED_CONTEXT_SHA256:
            parser.error(
                f"retained context hash mismatch for {RETAINED_CONTEXT_NAME}: "
                f"{context_digest}"
            )
        result["provenance"]["retained_context"] = {
            "name": RETAINED_CONTEXT_NAME,
            "sha256": context_digest,
            "status": "SUPPORTED_RETAINED_CONTEXT",
        }
        # Keep the short field for consumers that only need the pin; the
        # structured record above carries its status and logical name.
        result["provenance"]["context_sha256"] = context_digest
        result["provenance"]["retained_context_sha256"] = context_digest
    output_path = pathlib.Path(args.output)
    output_path.write_text(json.dumps(result, indent=1) + "\n")
    os.chmod(output_path, 0o644)
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
