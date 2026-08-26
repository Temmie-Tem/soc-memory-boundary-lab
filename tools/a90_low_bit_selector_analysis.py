#!/usr/bin/env python3
"""Experiment 030: can the reopen delta classify PA bits below the page?

Experiment 014 reported PA9 and PA10 as "two further independent selection
components consistent with channel selection", ranked `SUPPORTED`.  Its
evidence was that adding either to the kernel witness `0x16000` made the result
leave the conflict class.  Experiment 023R's rank-3 result covers PA13..PA24
only, so whether the relation extends downward decides whether the two
statements describe one selector or two different windows.

Reproducing that test shows the observation holds and the inference does not.
A difference leaves the conflict class in two opposite directions, and only one
of them means what the inference assumed:

  - downward, to the non-conflict level, is what a selection component does:
    the two addresses stop landing in the same bank, so nothing interferes;
  - upward, past the conflict level, is not that at all.

PA9 and PA10 leave upward.  The control that separates the two cases is to add
the bit to a difference that is already *non*-conflicting: a selection
component leaves such a difference non-conflicting, whereas PA9 and PA10 raise
it to exactly the value they produce from the conflicting witness.  Their
effect is witness-independent, which means the bank relation is no longer
observable through the metric once they are set, so the measurement is
saturated rather than informative.

That is a statement about the instrument, not a denial that the bits do
something.  A penalty larger than a bank conflict is what a rank or bank-group
change costs, and the boot log's `LPDDR4Y  Enabled = 2` is consistent with a
second rank.  This module reports the levels and the saturation; it does not
assign a DRAM coordinate to either bit.
"""
from __future__ import annotations

import json

SCHEMA = "a90-low-bit-selector-analysis-v1"

#: Bits whose behaviour the analysis reports.  PA13 upward is Experiment 023R's
#: territory and is not re-derived here.
LOW_BITS = tuple(range(13))


def levels(measurements: dict[int, int], kernel_witness: int,
           negative_witness: int, same_row_control: int) -> dict:
    """The three reference levels every low bit is read against.

    Naming them explicitly matters: `leaving the conflict class` is ambiguous
    until the non-conflict level is on the page next to the conflict one.
    """
    return {
        "same_row": measurements.get(same_row_control),
        "non_conflict": measurements.get(negative_witness),
        "conflict": measurements.get(kernel_witness),
    }


def classify_bit(alone: int | None, with_kernel: int | None,
                 with_negative: int | None, reference: dict,
                 tolerance: int = 60) -> str:
    """What does adding this bit do to a conflicting and a non-conflicting pair?

    ``INERT``       both witnesses keep their level: the bit contributes nothing.
    ``SELECTOR``    the conflicting witness falls to the non-conflict level.
    ``SATURATING``  both witnesses move to the same new level, so the bank
                    relation is no longer visible through the metric.
    ``MODULATING``  the levels move but not together and not to non-conflict.
    """
    conflict = reference["conflict"]
    non_conflict = reference["non_conflict"]
    if None in (alone, with_kernel, with_negative, conflict, non_conflict):
        return "INCOMPLETE"
    if (abs(with_kernel - conflict) <= tolerance
            and abs(with_negative - non_conflict) <= tolerance):
        return "INERT"
    if (abs(with_kernel - non_conflict) <= tolerance
            and abs(with_negative - non_conflict) <= tolerance):
        return "SELECTOR"
    if abs(with_kernel - with_negative) <= tolerance:
        return "SATURATING"
    return "MODULATING"


def analyse(measurements: dict[int, int], kernel_witness: int = 0x16000,
            negative_witness: int = 0x2000, same_row_control: int = 0x800,
            tolerance: int = 60) -> dict:
    reference = levels(measurements, kernel_witness, negative_witness,
                       same_row_control)
    bits = {}
    for bit in LOW_BITS:
        value = 1 << bit
        verdict = classify_bit(
            measurements.get(value),
            measurements.get(kernel_witness ^ value),
            measurements.get(negative_witness ^ value),
            reference, tolerance)
        bits[bit] = {
            "alone": measurements.get(value),
            "with_kernel_witness": measurements.get(kernel_witness ^ value),
            "with_negative_witness": measurements.get(negative_witness ^ value),
            "verdict": verdict,
        }
    grouped: dict[str, list[int]] = {}
    for bit, record in bits.items():
        grouped.setdefault(record["verdict"], []).append(bit)
    return {
        "schema": SCHEMA,
        "reference_levels": reference,
        "tolerance": tolerance,
        "witnesses": {"kernel": f"0x{kernel_witness:x}",
                      "negative": f"0x{negative_witness:x}",
                      "same_row_control": f"0x{same_row_control:x}"},
        "bits": bits,
        "by_verdict": grouped,
        "any_selector": bool(grouped.get("SELECTOR")),
        "saturating_bits": grouped.get("SATURATING", []),
    }


def load_medians(text: str) -> dict[int, int]:
    """Difference value to median delta, from probe JSONL."""
    out: dict[int, int] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        entry = json.loads(line)
        if entry.get("type") == "difference" and "median" in entry:
            out[int(entry["value"], 16)] = entry["median"]
    return out


def main(argv: list[str]) -> int:
    import argparse
    import hashlib
    import pathlib

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", required=True, help="directory of phase*.jsonl")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)

    raw = pathlib.Path(args.raw)
    inputs = sorted(raw.glob("phase*.jsonl"))
    if not inputs:
        parser.error(f"no phase*.jsonl under {raw}")
    measurements: dict[int, int] = {}
    for path in inputs:
        measurements.update(load_medians(path.read_text()))

    result = analyse(measurements)
    result["provenance"] = {
        "mode": "DEVICE_READ_ONLY",
        "device_writes": "none: allocate, map, read, free only",
        "analysis_sha256": hashlib.sha256(
            pathlib.Path(__file__).resolve().read_bytes()).hexdigest(),
        "raw_inputs": {p.stem: hashlib.sha256(p.read_bytes()).hexdigest()
                       for p in inputs},
    }
    pathlib.Path(args.output).write_text(json.dumps(result, indent=1) + "\n")
    print(json.dumps({k: result[k] for k in
                      ("reference_levels", "by_verdict", "any_selector",
                       "saturating_bits")}, indent=1))
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(main(sys.argv[1:]))
