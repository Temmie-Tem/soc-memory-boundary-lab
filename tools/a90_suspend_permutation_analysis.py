#!/usr/bin/env python3
"""Verification 019: did the address-to-DRAM map survive a suspend/resume?

`tools/a90_suspend_permute_probe.c` tags every 64-byte line of a 256 MiB ION allocation
with a value derived from its own offset, crosses a deep suspend, and reads
every tag back.  This module reads that transcript.

Why a permutation needs two states
----------------------------------
Verification 018 established that a single-state marker sweep is blind to a
permutation by construction: within one state every marker reads back exactly
where it was written.  `docs/PRIOR_ART.md` states the model an alias candidate
must satisfy, `Me a == Mf t` -- a relation between *two* states.  Suspend is the
only state change this project can cause that both takes the DRAM controller
through a real transition and leaves the allocation in place.

Two gates, and why a null needs both
------------------------------------
`moved == 0` means nothing unless the run also shows that the state change
actually happened and that the tags were readable beforehand.  So:

* the baseline pass must have found zero mismatches, and
* the suspend must be corroborated -- CLOCK_BOOTTIME includes time spent
  suspended and CLOCK_MONOTONIC does not, so their difference is the suspended
  interval, and `suspend_stats/success` must also have advanced.

Without both, the verdict is `INSTRUMENT_FAILED` or `SUSPEND_NOT_REACHED`, and
`invariance_is_admissible` stays false.

Decoding a move
---------------
The tag function is splitmix64, which is a bijection, so it inverts exactly.
If a location ever returns another location's tag, `decode_move` names the
offset that tag was written to -- the permutation is read off directly rather
than searched for.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import stat
from collections.abc import Sequence

SCHEMA = "a90-suspend-permutation-analysis-v1"
PROBE_SCHEMA = "a90_suspend_permute_v1"

MASK64 = (1 << 64) - 1
ADD = 0x9E3779B97F4A7C15
MUL1 = 0xBF58476D1CE4E5B9
MUL2 = 0x94D049BB133111EB
MUL1_INV = pow(MUL1, -1, 1 << 64)
MUL2_INV = pow(MUL2, -1, 1 << 64)

#: A suspend shorter than this is not treated as one.
MIN_SUSPENDED_SECONDS = 1.0


class PermutationError(RuntimeError):
    pass


def _read_raw(path: pathlib.Path) -> str:
    """Read a transcript only from a stable regular file, never a symlink."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        raise PermutationError(f"cannot open raw transcript safely: {exc}") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise PermutationError("raw transcript is not a regular file")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise PermutationError("raw transcript changed during read")
        payload = b"".join(chunks)
    finally:
        os.close(fd)
    if len(payload) != before.st_size:
        raise PermutationError("raw transcript size changed during read")
    hashlib.sha256(payload).hexdigest()  # integrity check is deliberately not published
    try:
        return payload.decode()
    except UnicodeDecodeError as exc:
        raise PermutationError("raw transcript is not UTF-8") from exc


def mix(value: int) -> int:
    """splitmix64, matching the probe's `mix` bit for bit."""
    value = (value + ADD) & MASK64
    value = ((value ^ (value >> 30)) * MUL1) & MASK64
    value = ((value ^ (value >> 27)) * MUL2) & MASK64
    return value ^ (value >> 31)


def _unxorshift(value: int, shift: int) -> int:
    result = value
    while shift < 64:
        result ^= value >> shift
        value = result
        shift <<= 1
    return result & MASK64


def unmix(value: int) -> int:
    """The exact inverse of `mix`.  splitmix64 is a bijection."""
    value = _unxorshift(value, 31)
    value = (value * MUL2_INV) & MASK64
    value = _unxorshift(value, 27)
    value = (value * MUL1_INV) & MASK64
    value = _unxorshift(value, 30)
    return (value - ADD) & MASK64


def tag_for(offset: int, seed: int) -> int:
    return mix(offset ^ seed)


def decode_move(observed: int, seed: int) -> int | None:
    """Which offset was this tag written to?  None if it is not a tag."""
    candidate = unmix(observed) ^ seed
    return candidate if tag_for(candidate, seed) == observed else None


def parse(text: str) -> list[dict]:
    records = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("schema") == PROBE_SCHEMA:
            records.append(record)
    return records


def analyse(records: Sequence[dict]) -> dict:
    context = next((r for r in records if r.get("type") == "context"), {})
    baseline = next((r for r in records if r.get("type") == "baseline"), None)
    stats = next((r for r in records if r.get("type") == "suspend_stats"), None)
    summary = next((r for r in records if r.get("type") == "summary"), None)
    attempts = [r for r in records if r.get("type") == "attempt"]
    moves = [r for r in records if r.get("type") == "moved"]

    seed = int(context.get("seed", "0x0"), 16)

    gate_reasons = []
    if baseline is None:
        gate_reasons.append("no baseline pass")
    elif baseline.get("mismatches", 1) != 0:
        gate_reasons.append("tags did not read back before the state change")
    if summary is None:
        gate_reasons.append("run did not reach its summary")

    slept = 0.0
    entered = None
    for attempt in attempts:
        interval = attempt.get("boottime_delta", 0.0) - attempt.get("monotonic_delta", 0.0)
        if interval > MIN_SUSPENDED_SECONDS:
            slept, entered = interval, attempt
            break

    stats_advanced = bool(stats and stats.get("success_after", 0) > stats.get("success_before", 0))
    suspended = entered is not None and stats_advanced

    decoded = []
    for move in moves:
        observed = int(move["observed"], 16)
        source = decode_move(observed, seed)
        decoded.append({
            "offset": move["offset"],
            "observed": move["observed"],
            "source_offset": None if source is None else f"0x{source:x}",
            "delta": None if source is None
                     else f"0x{source ^ int(move['offset'], 16):x}",
        })

    moved = summary.get("moved", 0) if summary else 0

    if gate_reasons:
        verdict = "INSTRUMENT_FAILED"
    elif not suspended:
        verdict = "SUSPEND_NOT_REACHED"
    elif moved:
        verdict = "MAP_CHANGED"
    else:
        verdict = "MAP_INVARIANT"

    return {
        "schema": SCHEMA,
        "instrument_ok": not gate_reasons,
        "gate_reasons": gate_reasons,
        "tags": context.get("tags"),
        "tag_stride": context.get("tag_stride"),
        "mib": context.get("mib"),
        "attempts": len(attempts),
        "suspend_occurred": suspended,
        "suspend_corroborated_by_stats": stats_advanced,
        "suspended_seconds": round(slept, 3),
        "moved": moved,
        "decoded_moves": decoded,
        "verdict": verdict,
        "invariance_is_admissible": verdict == "MAP_INVARIANT",
    }


# --------------------------------------------------------------------------
# Synthetic control: the detector must find a permutation that is really there
# --------------------------------------------------------------------------

def simulate(seed: int, tags: int, stride: int, permuted_bit: int | None,
             suspended_seconds: float = 25.0, baseline_bad: int = 0,
             stats_advance: bool = True, report_cap: int = 4096) -> str:
    """Emit the probe's records for a memory whose map may permute on resume.

    `permuted_bit` models the shape this experiment exists to look for: after
    the state change, a location holds the contents of the location one address
    bit away.
    """
    lines = [json.dumps({
        "schema": PROBE_SCHEMA, "type": "context", "heap": "synthetic",
        "mib": (tags * stride) >> 20, "tag_stride": stride, "tags": tags,
        "seed": f"0x{seed:x}", "wait_seconds": 0, "alarm_seconds": 25,
        "attempts": 1,
    }), json.dumps({
        "schema": PROBE_SCHEMA, "type": "baseline",
        "mismatches": baseline_bad, "instrument_ok": baseline_bad == 0,
    }), json.dumps({
        "schema": PROBE_SCHEMA, "type": "attempt", "n": 0, "write_rc": 3,
        "errno": 0, "error": "", "monotonic_delta": 0.5,
        "boottime_delta": 0.5 + suspended_seconds,
        "suspended_seconds": suspended_seconds,
        "suspended": suspended_seconds > MIN_SUSPENDED_SECONDS,
    })]

    moved = 0
    for index in range(tags):
        offset = index * stride
        source = offset if permuted_bit is None else offset ^ (1 << permuted_bit)
        if source == offset:
            continue
        moved += 1
        if moved <= report_cap:
            lines.append(json.dumps({
                "schema": PROBE_SCHEMA, "type": "moved",
                "offset": f"0x{offset:x}",
                "expected": f"0x{tag_for(offset, seed):x}",
                "observed": f"0x{tag_for(source, seed):x}",
            }))

    lines.append(json.dumps({
        "schema": PROBE_SCHEMA, "type": "suspend_stats",
        "success_before": 0, "success_after": 1 if stats_advance else 0,
        "fail_before": 0, "fail_after": 0,
    }))
    lines.append(json.dumps({
        "schema": PROBE_SCHEMA, "type": "summary",
        "suspend_occurred": suspended_seconds > MIN_SUSPENDED_SECONDS,
        "suspended_seconds": suspended_seconds, "tags": tags, "moved": moved,
        "reported": min(moved, report_cap),
        "verdict": "placeholder",
    }))
    return "\n".join(lines) + "\n"


def self_test(seed: int = 0x5DA9F0E3C17B2846) -> dict:
    tags, stride, bit = 4096, 64, 12
    positive = analyse(parse(simulate(seed, tags, stride, bit)))
    negative = analyse(parse(simulate(seed, tags, stride, None)))
    named = all(move["delta"] == f"0x{1 << bit:x}"
                for move in positive["decoded_moves"])
    return {
        "positive": {"verdict": positive["verdict"], "moved": positive["moved"],
                     "every_move_decoded_to_the_permuted_bit": named},
        "negative": {"verdict": negative["verdict"], "moved": negative["moved"]},
        "passed": (positive["verdict"] == "MAP_CHANGED" and named
                   and negative["verdict"] == "MAP_INVARIANT"),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)

    result: dict = {"schema": SCHEMA, "self_test": self_test()}
    if not result["self_test"]["passed"]:
        raise PermutationError("the synthetic control failed; no device "
                               "transcript may be interpreted by this build")
    if args.raw:
        result["run"] = analyse(parse(_read_raw(pathlib.Path(args.raw))))

    pathlib.Path(args.output).write_text(json.dumps(result, indent=1) + "\n")

    print(f"synthetic control passed: {result['self_test']['passed']}")
    print(f"  positive: {result['self_test']['positive']['verdict']}, "
          f"{result['self_test']['positive']['moved']} moves, all decoded: "
          f"{result['self_test']['positive']['every_move_decoded_to_the_permuted_bit']}")
    print(f"  negative: {result['self_test']['negative']['verdict']}")
    if "run" in result:
        run = result["run"]
        print()
        print(f"instrument ok: {run['instrument_ok']} {run['gate_reasons']}")
        print(f"suspend occurred: {run['suspend_occurred']} "
              f"({run['suspended_seconds']}s, stats corroborate: "
              f"{run['suspend_corroborated_by_stats']})")
        print(f"tags {run['tags']} at stride {run['tag_stride']}, "
              f"moved {run['moved']}")
        print(f"verdict: {run['verdict']}")
    return 0


if __name__ == "__main__":
    import sys

    raise SystemExit(main(sys.argv[1:]))
