#!/usr/bin/env python3
"""Decide whether a full-size ION allocation consumes its whole carveout.

`docs/PA28_UNBLOCKED_2026-08-27.md` argued by pigeonhole that a 320 MiB
allocation from a 320 MiB carveout must start at the region base.  The 020M
review held that `UNKNOWN`, correctly: nothing had shown the allocation spans
the pool rather than the heap over-committing or the pool exceeding what the
device tree declares.

The receipt this reduces answers it directly.  With the full size held, nothing
allocatable may remain -- not one page.  A failure under hold proves nothing on
its own, so it is only admissible when bracketed by two controls: the same
probe sizes succeed before the hold and again after it is released.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

SCHEMA = "a90_heap_exhaustion_v1"
MIB = 1 << 20

# Pinned from the device tree, re-collected live and PROVED by the 020M review.
DT_REGION = {
    "node": "camera_mem_region",
    "base": 0xC2000000,
    "size": 0x14000000,
    "heap_id": 30,
    "heap_name": "camera_preview",
    "memory_region_phandle": 0x67A,
}


def load_records(path: Path) -> tuple[list[dict], dict]:
    """Read the receipt through a stable, symlink-refusing descriptor."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        data = os.read(fd, 1 << 20)
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
    return records, {
        "basename": path.name,
        "bytes": info.st_size,
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def analyse(records: list[dict]) -> dict:
    context = next((r for r in records if r["type"] == "context"), None)
    if context is None:
        raise ValueError("receipt has no context record")
    if any(r["type"] == "abort" for r in records):
        reason = next(r for r in records if r["type"] == "abort").get("reason")
        return {"schema": "a90_carveout_exhaustion_v1", "verdict": "ABORTED",
                "abort_reason": reason, "instrument_ok": False}

    phases: dict[str, list[dict]] = {}
    for record in records:
        if record["type"] == "probe":
            phases.setdefault(record["phase"], []).append(record)

    for required in ("control_before", "under_hold", "control_after"):
        if required not in phases:
            raise ValueError(f"receipt is missing phase {required}")

    sizes = [p["bytes"] for p in phases["control_before"]]
    for name, probes in phases.items():
        if [p["bytes"] for p in probes] != sizes:
            raise ValueError(f"phase {name} probes a different size set")

    hold = next((r for r in records if r["type"] == "hold"), None)
    if hold is None or not hold["ok"]:
        raise ValueError("receipt has no successful full-size hold")

    n = len(sizes)
    before = sum(1 for p in phases["control_before"] if p["ok"])
    under = sum(1 for p in phases["under_hold"] if p["ok"])
    after = sum(1 for p in phases["control_after"] if p["ok"])
    controls_fired = before == n and after == n

    if not controls_fired:
        verdict = "INSTRUMENT_FAILED"
    elif under == 0:
        verdict = "HOLD_CONSUMES_POOL"
    else:
        verdict = "HOLD_LEAVES_ROOM"

    hold_bytes = hold["bytes"]
    exhausted = controls_fired and under == 0
    dt_match = hold_bytes == DT_REGION["size"]

    return {
        "schema": "a90_carveout_exhaustion_v1",
        "heap": {"name": context["heap"], "heap_type": context["heap_type"],
                 "heap_id": context["heap_id"]},
        "hold_bytes": hold_bytes,
        "probe_sizes_bytes": sizes,
        "smallest_probe_bytes": min(sizes),
        "control_before_ok": before,
        "under_hold_ok": under,
        "control_after_ok": after,
        "probe_count": n,
        "controls_fired": controls_fired,
        "instrument_ok": controls_fired,
        "pool_exhausted": exhausted,
        "verdict": verdict,
        "device_tree_region": {k: (hex(v) if isinstance(v, int) and k != "heap_id" else v)
                               for k, v in DT_REGION.items()},
        "hold_equals_declared_region_size": dt_match,
        "implied_pool_bytes": hold_bytes if exhausted else None,
        "implied_physical_span": (
            [hex(DT_REGION["base"]), hex(DT_REGION["base"] + DT_REGION["size"])]
            if exhausted and dt_match else None
        ),
        "residual_assumption": (
            "The pool is proved exactly equal in size to the declared region: "
            "the full size allocates and nothing further fits, so the pool is "
            "neither larger nor smaller. That the pool IS that region -- rather "
            "than an equally sized region elsewhere -- rests on heap 30 naming "
            "camera_mem_region through its memory-region phandle, which the 020M "
            "review PROVED on the live target but which this receipt does not "
            "independently re-derive."
        ),
        "not_claimed": (
            "No physical page identity, no complete DRAM coordinate, no value of "
            "f(PA28), no transform mutability and no access-control implication. "
            "This decides allocation extent only."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    records, source = load_records(args.raw)
    result = analyse(records)
    result["input"] = source

    print(f"heap            : {result['heap']['name']} (id {result['heap']['heap_id']})")
    print(f"hold            : {result['hold_bytes'] // MIB} MiB")
    print(f"controls fired  : {result['controls_fired']} "
          f"({result['control_before_ok']}/{result['probe_count']} before, "
          f"{result['control_after_ok']}/{result['probe_count']} after)")
    print(f"under hold      : {result['under_hold_ok']}/{result['probe_count']} allocatable, "
          f"smallest probe {result['smallest_probe_bytes'] // 1024} KiB")
    print(f"verdict         : {result['verdict']}")
    if result.get("implied_physical_span"):
        lo, hi = result["implied_physical_span"]
        print(f"implied span    : [{lo}, {hi})")

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
