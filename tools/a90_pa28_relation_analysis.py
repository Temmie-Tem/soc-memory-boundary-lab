#!/usr/bin/env python3
"""Reduce the Verification 022 receipts to a value for f(PA28).

Verification 016 recovered the bank relation up to model bit PA27 and left
`whether the duplication pattern continues above it` as `UNKNOWN`.  PA28 needs
a span exceeding 2^28, which the 256 MiB allocations of V016, V018 and V019 miss
by exactly one bit.  V020 measured a 320 MiB ceiling, V021 proved a full-size
allocation consumes the whole carveout, and the device tree publishes its base,
so offset differences are physical differences with a known base.

Two questions, in order.  Does flipping PA28 alone leave the conflicting
resource -- that is, is f(2^28) nonzero?  And if so, which element of the rank-3
space is it?  The second is decided by testing 2^28 against every combination of
the basis: exactly one of the seven must conflict, and which one names f(PA28).

Classification follows V016: within each phase the threshold sits in the widest
gap between sorted medians, and the same-phase controls must land on the
expected sides of it.  An aggregate is never substituted for those controls.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import statistics
from pathlib import Path

SCHEMA = "a90_pa28_probe_v1"
PA28 = 1 << 28

# From the recovered relation: f(PA13), f(PA14), f(PA15) are a basis of GF(2)^3.
BASIS = {0x2000: 0b001, 0x4000: 0b010, 0x8000: 0b100}

# Same-phase controls, as V016 used them.  Neither may be inferred from an
# aggregate; each is asserted directly in the phase it was measured in.
CONTROL_CONFLICT = 0x16000
CONTROL_NEGATIVE = 0x2000


def load(path: Path) -> tuple[list[dict], dict]:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        chunks = []
        while True:
            block = os.read(fd, 1 << 20)
            if not block:
                break
            chunks.append(block)
    finally:
        os.close(fd)
    data = b"".join(chunks)
    records = []
    for line in data.decode("utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        record = json.loads(line)
        if record.get("schema") != SCHEMA:
            raise ValueError(f"foreign schema in {path.name}: {record.get('schema')!r}")
        records.append(record)
    if not records:
        raise ValueError(f"{path.name} holds no records")
    return records, {"basename": path.name, "bytes": info.st_size,
                     "sha256": hashlib.sha256(data).hexdigest()}


def verify_pairs(records: list[dict]) -> dict:
    """Every measured pair must have the physical XOR its difference names.

    This is what allows a non-power-of-two span: adding the base can carry, and
    a carried pair would be scored against a bit it does not isolate.  The probe
    rejects those before timing; this re-checks what it emitted.
    """
    checked = 0
    mismatched: list[str] = []
    for record in records:
        if record["type"] != "pair":
            continue
        checked += 1
        if record.get("pa_xor") != record["value"]:
            mismatched.append(f"{record['value']} at offset {record['offset']}")
    return {"pairs_checked": checked, "mismatched": mismatched,
            "all_pairs_isolate_their_difference": not mismatched}


def phase_medians(records: list[dict]) -> dict[int, list[float]]:
    """Per-difference medians, one entry per time the difference was measured."""
    out: dict[int, list[float]] = {}
    current: dict[int, list[int]] = {}
    for record in records:
        if record["type"] == "pair":
            current.setdefault(int(record["value"], 16), []).append(record["delta"])
        elif record["type"] == "difference" and "median" in record:
            value = int(record["value"], 16)
            deltas = current.pop(value, [])
            if deltas:
                out.setdefault(value, []).append(statistics.median(deltas))
    return out


def classify(medians: dict[int, float]) -> dict:
    """V016's rule: the threshold sits in the widest gap between medians."""
    ordered = sorted(medians.items(), key=lambda kv: kv[1])
    if len(ordered) < 2:
        raise ValueError("a phase needs at least two differences to split")
    gaps = [(ordered[i + 1][1] - ordered[i][1], i) for i in range(len(ordered) - 1)]
    widest, index = max(gaps)
    runner_up = max((g for g, i in gaps if i != index), default=0.0)
    threshold = (ordered[index][1] + ordered[index + 1][1]) / 2
    return {
        "threshold": threshold,
        "gap": widest,
        "runner_up_gap": runner_up,
        "conflict": {hex(v): m for v, m in ordered if m > threshold},
        "negative": {hex(v): m for v, m in ordered if m <= threshold},
    }


def analyse(records: list[dict]) -> dict:
    context = next(r for r in records if r["type"] == "context")
    provenance = next((r for r in records if r["type"] == "pa_provenance"), None)
    verification = verify_pairs(records)
    per_difference = phase_medians(records)
    medians = {v: statistics.median(ms) for v, ms in per_difference.items()}
    split = classify(medians)

    controls_present = (CONTROL_CONFLICT in medians and CONTROL_NEGATIVE in medians)
    controls_fired = (
        controls_present
        and medians[CONTROL_CONFLICT] > split["threshold"]
        and medians[CONTROL_NEGATIVE] <= split["threshold"]
    )

    # Candidates: 2^28 XOR each nonempty subset of the basis, plus 2^28 alone.
    candidates: dict[int, int] = {}
    for mask in range(8):
        difference = PA28
        vector = 0
        for bit, value in BASIS.items():
            if mask & value:
                difference ^= bit
                vector ^= value
        candidates[difference] = vector

    measured = {d: medians[d] for d in candidates if d in medians}
    conflicting = [d for d, m in measured.items() if m > split["threshold"]]

    if not controls_fired:
        verdict, resolved = "INSTRUMENT_FAILED", None
    elif not verification["all_pairs_isolate_their_difference"]:
        verdict, resolved = "INSTRUMENT_FAILED", None
    elif len(conflicting) == 1:
        verdict, resolved = "RESOLVED", candidates[conflicting[0]]
    elif not conflicting:
        verdict, resolved = "OUTSIDE_RANK_3_SPACE", None
    else:
        verdict, resolved = "AMBIGUOUS_MULTIPLE_CONFLICTS", None

    return {
        "schema": "a90_pa28_relation_v1",
        "context": {k: context[k] for k in
                    ("heap", "mib", "repetitions", "pairs", "cpu", "warmups",
                     "order", "barrier", "divisor", "offset_mode", "declared_base")
                    if k in context},
        "pagemap_status": provenance.get("status") if provenance else None,
        "pair_verification": verification,
        "medians": {hex(v): m for v, m in sorted(medians.items())},
        "repeats_per_difference": {hex(v): len(ms) for v, ms in sorted(per_difference.items())},
        "phase_split": split,
        "controls": {
            "conflict_difference": hex(CONTROL_CONFLICT),
            "negative_difference": hex(CONTROL_NEGATIVE),
            "controls_present": controls_present,
            "controls_fired": controls_fired,
        },
        "candidates_measured": {hex(d): {"vector": f"{candidates[d]:03b}", "median": m}
                                for d, m in sorted(measured.items())},
        "conflicting_candidates": [hex(d) for d in sorted(conflicting)],
        "verdict": verdict,
        "f_pa28": (f"{resolved:03b}" if resolved is not None else None),
        "f_pa28_equals": (
            next((f"f(PA{bit.bit_length() - 1})" for bit, v in BASIS.items() if v == resolved), None)
            if resolved is not None else None
        ),
        "not_claimed": (
            "NEGATIVE means the pair did not present as a same-bank different-row "
            "conflict. That separates bank, rank and channel selection from row "
            "bits, but does not distinguish among them. No complete DRAM "
            "coordinate, no transform mutability and no access-control "
            "implication follows."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", type=Path, required=True, action="append")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    merged: list[dict] = []
    inputs = []
    for path in args.raw:
        records, source = load(path)
        merged.extend(records)
        inputs.append(source)
    result = analyse(merged)
    result["inputs"] = inputs

    print(f"pairs verified   : {result['pair_verification']['pairs_checked']} "
          f"({len(result['pair_verification']['mismatched'])} mismatched)")
    print(f"pagemap          : {result['pagemap_status']}")
    print(f"threshold        : {result['phase_split']['threshold']:.0f} "
          f"(gap {result['phase_split']['gap']:.0f}, "
          f"runner-up {result['phase_split']['runner_up_gap']:.0f})")
    print(f"controls fired   : {result['controls']['controls_fired']}")
    for d, entry in result["candidates_measured"].items():
        mark = "  <-- CONFLICT" if d in result["conflicting_candidates"] else ""
        print(f"  {d:<12} vector {entry['vector']}  median {entry['median']:.0f}{mark}")
    print(f"verdict          : {result['verdict']}")
    if result["f_pa28"]:
        print(f"f(PA28)          : {result['f_pa28']}  = {result['f_pa28_equals']}")

    if args.output:
        payload = json.dumps(result, indent=1, sort_keys=True).encode() + b"\n"
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        try:
            os.write(fd, payload)
        finally:
            os.close(fd)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
