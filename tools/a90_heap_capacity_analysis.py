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
import hashlib
import json
import os
import stat
from pathlib import Path

SCHEMA = "a90_heap_capacity_v1"
MIB = 1 << 20
REOPEN_CONDITION_2_MIB = 512
ION_HEAP_TYPE_SYSTEM = 0  # page-based; never physically contiguous
MAX_INPUT_BYTES = 8 << 20
REPO_ROOT = Path(__file__).resolve().parents[1]
PROBE_SOURCE_NAME = "a90_heap_capacity_probe.c"
PROBE_SOURCE_SIZE = 4_176
PROBE_SOURCE_SHA256 = "26b320115e0a23884e633709a13afa40276c66c0d95c54882bd2399fd31c8876"
PROBE_SOURCE_PATH = REPO_ROOT / "tools" / PROBE_SOURCE_NAME

# The executed static binary was not retained by the producer.  Keep that
# limitation explicit while still pinning the exact bytes reported in the
# retained README and receipt.  The checked-in source is independently read
# and hashed below; a source drift therefore fails closed.
EXECUTED_PROBE = {
    "basename": "heap_cap.c",
    "size": 706_184,
    "sha256": "cf0b3caf834213fd0d8db22f09b85e1a58084c94dc69193b49fe141111390457",
    "retained": False,
}
REPRODUCIBLE_PROBE_BUILD = {
    "basename": "a90_heap_capacity_probe.c",
    "size": 706_192,
    "sha256": "d913d633ed5edea38025318658f61b2175318ec1c18ad3859b616f746723fedf",
    "retained": False,
    "source_basename_difference_only": True,
}


def _read_stable(path: Path) -> tuple[bytes, dict[str, object]]:
    """Read and pin one bounded regular file without following a symlink."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"{path.name} is not a regular file")
        if before.st_size < 0 or before.st_size > MAX_INPUT_BYTES:
            raise ValueError(f"{path.name} exceeds the bounded input size")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(fd, min(1 << 20, remaining))
            if not chunk:
                raise ValueError(f"{path.name} truncated while being read")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    before_key = (before.st_dev, before.st_ino, before.st_size,
                  before.st_mtime_ns, before.st_ctime_ns)
    after_key = (after.st_dev, after.st_ino, after.st_size,
                 after.st_mtime_ns, after.st_ctime_ns)
    if before_key != after_key:
        raise ValueError(f"{path.name} changed while being read")
    data = b"".join(chunks)
    if len(data) != before.st_size:
        raise ValueError(f"{path.name} size changed while being read")
    return data, {
        "filename": path.name,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def probe_provenance() -> dict[str, object]:
    """Return mechanically checked source and explicitly attested binaries."""
    _, source = _read_stable(PROBE_SOURCE_PATH)
    if source["size"] != PROBE_SOURCE_SIZE or source["sha256"] != PROBE_SOURCE_SHA256:
        raise ValueError("probe source size/SHA-256 mismatch")
    return {
        "source": source,
        "executed_binary": dict(EXECUTED_PROBE),
        "reproducible_build": dict(REPRODUCIBLE_PROBE_BUILD),
    }


def load_records_with_pin(path: Path) -> tuple[list[dict], dict[str, object]]:
    """Read a ladder and return its exact public filename/size/SHA pin."""
    data, pin = _read_stable(path)
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
    return records, pin


def load_records(path: Path) -> list[dict]:
    """Read the ladder through a stable, symlink-refusing descriptor."""
    records, _ = load_records_with_pin(path)
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

    loaded = [load_records_with_pin(path) for path in args.raw]
    reductions = [analyse(records) for records, _ in loaded]
    provenance = probe_provenance()
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
    best["inputs"] = {
        "raw_ladders": [pin for _, pin in loaded],
        "probe": provenance,
    }

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
