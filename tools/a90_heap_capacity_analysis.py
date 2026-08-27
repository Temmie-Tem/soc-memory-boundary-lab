#!/usr/bin/env python3
"""Reduce an A90 ION heap-capacity ladder to a measured ceiling per heap.

Reopen condition 2 asks whether a non-secure contiguous allocation of at least
512 MiB is available.  `docs/REMAINING_ROUTES_2026-08-27.md` answered it by
asserting that the largest non-secure heap was `camera_preview` at 256 MiB, but
no retained survey backed that number.  This reduces an actual ladder instead.

The ladder is a descending sequence of requested sizes per heap.  A ceiling is
only meaningful if the outcomes are monotone in size: every size at or below
the ceiling must succeed and every size above it must fail.  A non-monotone
ladder means transient memory pressure, not a capacity boundary, and is
reported as such rather than reduced to a number.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

SCHEMA = "a90_heap_capacity_v1"
MIB = 1 << 20
REOPEN_CONDITION_2_MIB = 512
ION_HEAP_TYPE_SYSTEM = 0  # page-based; never physically contiguous


def load_records(path: Path) -> list[dict]:
    """Read the ladder through a stable, symlink-refusing descriptor."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        data = os.read(fd, 1 << 22)
    finally:
        os.close(fd)
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
    return records


def max_xor_bit(span_bytes: int) -> int | None:
    """Highest bit index k with 2**k strictly inside the span.

    Measuring f(PA_k) needs two addresses differing in only bit k, so the span
    must exceed 2**k -- *not* 2**(k+1).  Whether such a pair actually exists
    also depends on the physical base modulo 2**(k+1), which pagemap does not
    expose for dma-buf; this is an upper bound, never a guarantee.
    """
    if span_bytes <= 1:
        return None
    k = span_bytes.bit_length() - 1
    if (1 << k) >= span_bytes:
        k -= 1
    return k if k >= 0 else None


def analyse(records: list[dict]) -> dict:
    heaps: dict[str, dict] = {}
    order: list[str] = []
    for record in records:
        kind = record.get("type")
        if kind == "heap":
            name = record["name"]
            if name in heaps:
                raise ValueError(f"duplicate heap record: {name}")
            heaps[name] = {
                "heap_type": record["heap_type"],
                "heap_id": record["heap_id"],
                "attempted": bool(record["attempted"]),
                "attempts": [],
            }
            order.append(name)
        elif kind == "attempt":
            name = record["name"]
            if name not in heaps:
                raise ValueError(f"attempt precedes its heap record: {name}")
            if not heaps[name]["attempted"]:
                raise ValueError(f"attempt on a heap marked not attempted: {name}")
            heaps[name]["attempts"].append(
                {"mib": int(record["mib"]), "ok": bool(record["ok"]),
                 "errno": int(record["errno"])}
            )

    results = {}
    for name in order:
        entry = heaps[name]
        attempts = sorted(entry["attempts"], key=lambda a: a["mib"])
        if not entry["attempted"]:
            # Two distinct reasons, and conflating them would misreport the
            # survey: a page-based heap cannot supply a contiguous span at all,
            # while a secure or remote-processor heap could but must not be
            # touched -- allocating from one drives hyp_assign and a VMID
            # transition, a mandatory pause gate.
            page_based = entry["heap_type"] == ION_HEAP_TYPE_SYSTEM
            results[name] = {
                "heap_type": entry["heap_type"], "heap_id": entry["heap_id"],
                "attempted": False, "ceiling_mib": None,
                "reason_not_attempted": (
                    "page-based heap: cannot supply a contiguous span by construction"
                    if page_based
                    else "host withheld: secure or remote-processor heap"
                ),
                "contiguity_possible": not page_based,
            }
            continue
        oks = [a["mib"] for a in attempts if a["ok"]]
        fails = [a["mib"] for a in attempts if not a["ok"]]
        monotone = (not oks or not fails) or max(oks) < min(fails)
        ceiling = max(oks) if oks else None
        smallest_failure = min(fails) if fails else None
        results[name] = {
            "heap_type": entry["heap_type"],
            "heap_id": entry["heap_id"],
            "attempted": True,
            "sizes_tested_mib": [a["mib"] for a in attempts],
            "largest_success_mib": ceiling,
            "smallest_failure_mib": smallest_failure,
            "monotone": monotone,
            "ceiling_mib": ceiling if monotone else None,
            "ceiling_bracket_mib": (
                [ceiling, smallest_failure] if monotone and ceiling and smallest_failure
                else None
            ),
            "meets_reopen_condition_2": bool(
                monotone and ceiling is not None and ceiling >= REOPEN_CONDITION_2_MIB
            ),
            "max_xor_bit_upper_bound": (
                max_xor_bit(ceiling * MIB) if monotone and ceiling else None
            ),
        }

    attempted = {n: r for n, r in results.items() if r["attempted"]}
    any_non_monotone = any(not r["monotone"] for r in attempted.values())
    largest = max(
        (r["ceiling_mib"] for r in attempted.values() if r["ceiling_mib"]),
        default=None,
    )
    return {
        "schema": "a90_heap_capacity_analysis_v1",
        "reopen_condition_2_threshold_mib": REOPEN_CONDITION_2_MIB,
        "heaps": results,
        "attempted_count": len(attempted),
        "enumerated_count": len(results),
        "instrument_ok": not any_non_monotone,
        "largest_non_secure_ceiling_mib": largest,
        "reopen_condition_2": (
            "INSTRUMENT_FAILED" if any_non_monotone
            else "MET" if largest and largest >= REOPEN_CONDITION_2_MIB
            else "NOT_MET"
        ),
        "max_xor_bit_upper_bound": (
            max_xor_bit(largest * MIB) if (not any_non_monotone and largest) else None
        ),
        "scope": (
            "Ceilings are what this device returned at this uptime under this "
            "firmware, for the heaps the host chose to attempt.  Secure and "
            "remote-processor heaps were enumerated but never allocated from, so "
            "their capacity is UNKNOWN, not zero.  max_xor_bit_upper_bound is an "
            "arithmetic bound on span alone: it assumes physical contiguity and "
            "says nothing about the physical base, which pagemap does not expose "
            "for dma-buf, so a usable XOR pair is not implied."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", type=Path, required=True, action="append",
                        help="ladder receipt; repeatable, later files must agree")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    reductions = [analyse(load_records(path)) for path in args.raw]
    first = reductions[0]
    for path, other in zip(args.raw[1:], reductions[1:]):
        for name, result in other["heaps"].items():
            baseline = first["heaps"].get(name)
            if baseline is None or baseline["attempted"] != result["attempted"]:
                raise SystemExit(f"{path.name}: heap set disagrees at {name}")
            if not result["attempted"]:
                continue
            # A coarse and a fine ladder may bracket differently, but neither may
            # succeed at a size the other proved impossible.
            if (baseline["largest_success_mib"] and result["smallest_failure_mib"]
                    and baseline["largest_success_mib"] >= result["smallest_failure_mib"]):
                raise SystemExit(f"{path.name}: ladders contradict at {name}")

    best = max(reductions, key=lambda r: len(next(iter(r["heaps"].values()))["sizes_tested_mib"])
               if r["heaps"] else 0)
    best["ladders_reduced"] = len(reductions)
    best["inputs"] = [p.name for p in args.raw]

    for name, result in best["heaps"].items():
        if not result["attempted"]:
            print(f"{name:16s} not attempted -- {result['reason_not_attempted']}")
            continue
        bracket = result["ceiling_bracket_mib"]
        print(f"{name:16s} ceiling {result['ceiling_mib']} MiB"
              + (f"  (bracket {bracket[0]}..{bracket[1]})" if bracket else "")
              + ("" if result["monotone"] else "  NON-MONOTONE"))
    print(f"\ninstrument_ok: {best['instrument_ok']}")
    print(f"reopen condition 2 (>= {REOPEN_CONDITION_2_MIB} MiB): {best['reopen_condition_2']}")
    print(f"largest non-secure ceiling: {best['largest_non_secure_ceiling_mib']} MiB")
    print(f"max XOR bit upper bound: PA{best['max_xor_bit_upper_bound']}")

    if args.output:
        payload = json.dumps(best, indent=1, sort_keys=True).encode() + b"\n"
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        try:
            os.write(fd, payload)
        finally:
            os.close(fd)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
