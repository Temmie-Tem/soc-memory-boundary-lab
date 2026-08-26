#!/usr/bin/env python3
"""Repair and analyse the retained Verification-016 high-bit transcripts.

The retained acquisition is deliberately kept as five logical parts: three
14-key discrimination sections (PA25, PA26 and PA27), one nine-key held-out
section, and two repeated 14-key three-column sections.  A previous external
implementation flattened those sections with implicit first-value insertion;
this module
never does that.  References and overlapping values remain attached to their
acquisition section, and only the two three-column repeats are combined after
their key sets have been checked.

All classifications are in allocation-offset/model coordinates.  The probe's
``contiguous`` flag is retained as a reported allocation property only.  The
canonical records have BLIND pagemap provenance, so physical PA mapping,
allocation base/alignment, and effective physical contiguity are not inferred.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
import hashlib
import itertools
import json
import math
import os
from pathlib import Path
import stat
import sys

# ``python tools/a90_high_bit_relation_analysis.py`` places only ``tools/``
# on ``sys.path``.  Add the repository root before importing the sibling
# package so the canonical CLI and module invocation use the same code path.
_IMPORT_ROOT = str(Path(__file__).resolve().parents[1])
if _IMPORT_ROOT not in sys.path:
    sys.path.insert(0, _IMPORT_ROOT)

from tools import a90_runtime_invariance_analysis as v015


SCHEMA = "a90-high-bit-relation-analysis-v1"
PROBE_SCHEMA = "a90_region_probe_r_v1"
DEPENDENCY_SCHEMA = "a90-region-relation-solver-v1"
MODEL_COORDINATE_SCOPE = "allocation-offset/model coordinates"
PUBLIC_COORDINATE_SCOPE = "ALLOCATION_OFFSET_MODEL_COORDINATES"
PAGE_BYTES = 4096

KERNEL_REFERENCE = 0x16000
NEGATIVE_REFERENCE = 0x2000
HIGH_BITS = (25, 26, 27)
LOWER_BITS = tuple(range(13, 25))

RAW_BASENAMES = (
    "pa25-27-discriminate.jsonl",
    "pa25-27-heldout.jsonl",
    "pa25-27-three-column.jsonl",
)
RAW_PINS: dict[str, tuple[int, str]] = {
    "pa25-27-discriminate.jsonl": (
        142987,
        "0b269229a1607c6894fea15c21008ed3651b29faf02b9bc6cd851878c6030754",
    ),
    "pa25-27-heldout.jsonl": (
        30770,
        "38649c2d2f73be05ef238c20cdc69880b391547f84fe48cd656fff9343be91b0",
    ),
    "pa25-27-three-column.jsonl": (
        94966,
        "4cea5779ebdace6cc9817de591c8cff81dbd7f029ad78f46d8711708758c950f",
    ),
}

PROBE_SOURCE_SHA256 = (
    "2dbc81ef7595d30f627df8d28d24e21603d8c1c174074e85593b9fe8df5569e9"
)
PROBE_SOURCE_SIZE = 19337
DEPENDENCY_MANIFEST_SHA256 = (
    "5c3e14ff898c109de740d98260d974bca10751000f85977775cd467ac74aac2e"
)
DEPENDENCY_MANIFEST_SIZE = 18040
V015_HELPER_SHA256 = (
    "6fae489d27d03f94e9dcd89086027a4209988a67020620e54f1df7e22ca99e03"
)
V015_HELPER_SIZE = 97572

REPO_ROOT = Path(__file__).resolve().parents[1]
PRIVATE_ROOT = (
    REPO_ROOT / "evidence" / "private" /
    "verification-016-high-bit-relation-20260827-01"
)
PROBE_SOURCE_PATH = REPO_ROOT / "tools" / "a90_region_probe_r.c"
DEPENDENCY_MANIFEST_PATH = (
    REPO_ROOT / "evidence" / "manifests" /
    "023R-repaired-region-bank-relation-20260826-01.manifest.json"
)
V015_HELPER_PATH = REPO_ROOT / "tools" / "a90_runtime_invariance_analysis.py"

EXPECTED_SECTION_COUNTS = {
    "discriminate": (3, 14),
    "heldout": (1, 9),
    "three_column": (2, 14),
}
EXPECTED_SPLITS = {
    "bit25": {
        "threshold": 339,
        "gap": 295,
        "runner_up_gap": 22,
        "band_low": 192,
        "band_high": 487,
        "conflict_count": 3,
    },
    "bit26": {
        "threshold": 325,
        "gap": 273,
        "runner_up_gap": 75,
        "band_low": 189,
        "band_high": 462,
        "conflict_count": 2,
    },
    "bit27": {
        "threshold": 355,
        "gap": 302,
        "runner_up_gap": 25,
        "band_low": 204,
        "band_high": 506,
        "conflict_count": 3,
    },
    "heldout": {
        "threshold": 299,
        "gap": 276,
        "runner_up_gap": 38,
        "band_low": 161,
        "band_high": 437,
        "conflict_count": 5,
    },
    "three_column": {
        "threshold": 358,
        "gap": 304,
        "runner_up_gap": 136,
        "band_low": 206,
        "band_high": 510,
        "conflict_count": 2,
    },
}
EXPECTED_MATCHES = {25: (14, 21), 26: (19,), 27: (13, 20)}
EXPECTED_TRIPLETS = {
    25: (152, 133, 206, "SELECTOR"),
    26: (150, 141, 136, "SELECTOR"),
    27: (131, 148, 510, "SELECTOR_CANCELS_NEGATIVE_WITNESS"),
}
EXPECTED_THREE_PASS_TRIPLETS = {
    0: {
        25: (186, 161, 226, "SELECTOR"),
        26: (161, 161, 149, "SELECTOR"),
        27: (145, 158, 527, "SELECTOR_CANCELS_NEGATIVE_WITNESS"),
    },
    1: {
        25: (118, 105, 186, "SELECTOR"),
        26: (139, 121, 124, "SELECTOR"),
        27: (118, 139, 493, "SELECTOR_CANCELS_NEGATIVE_WITNESS"),
    },
}
EXPECTED_HELDOUT = (
    (0x6084000, "CONFLICT"),
    (0xA202000, "CONFLICT"),
    (0xC180000, "CONFLICT"),
    (0xA104000, "CONFLICT"),
    (0x6000000, "NEGATIVE"),
    (0xC000000, "NEGATIVE"),
    (0xA004000, "NEGATIVE"),
)
EXPECTED_LOWER_EQUALITIES = {
    25: 0x204000,  # PA14 ^ PA21
    27: 0x102000,  # PA13 ^ PA20
}


class HighBitError(v015.InvarianceError):
    """Raised when a retained-input or publication contract fails."""


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _parse_int(value: object, field: str, source: str, *, nonnegative: bool = True) -> int:
    if _is_int(value):
        result = int(value)
    elif isinstance(value, str):
        try:
            result = int(value, 0)
        except ValueError as exc:
            raise HighBitError(f"{source}: {field} is not an integer") from exc
    else:
        raise HighBitError(f"{source}: {field} is not an integer")
    if nonnegative and result < 0:
        raise HighBitError(f"{source}: {field} must be non-negative")
    return result


def _require(record: Mapping[str, object], key: str, source: str) -> object:
    if key not in record:
        raise HighBitError(f"{source}: {record.get('type')!r} lacks {key!r}")
    return record[key]


def _identity(record: Mapping[str, object]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _hex(value: int) -> str:
    return f"0x{value:x}"


def _read_stable_bytes(path: Path, label: str) -> bytes:
    """Use the repaired V015 stable descriptor read, kept behind a local seam."""

    try:
        return v015._read_stable_bytes(Path(path), label)
    except v015.InvarianceError as exc:
        raise HighBitError(str(exc)) from exc


def _stable_snapshot(path: Path, label: str) -> tuple[bytes, dict]:
    """Read/hash a file, then independently re-read and require identical bytes."""

    path = Path(path)
    first = _read_stable_bytes(path, label)
    first_meta = {
        "basename": path.name,
        "size_bytes": len(first),
        "sha256": hashlib.sha256(first).hexdigest(),
    }
    second = _read_stable_bytes(path, f"{label} independent re-read")
    second_meta = {
        "basename": path.name,
        "size_bytes": len(second),
        "sha256": hashlib.sha256(second).hexdigest(),
    }
    if first != second or first_meta != second_meta:
        raise HighBitError(f"{label} {path.name!r} changed between matching reads")
    return first, first_meta


def _check_pin(metadata: Mapping[str, object], pin: tuple[int, str], label: str) -> None:
    if metadata.get("size_bytes") != pin[0] or metadata.get("sha256") != pin[1]:
        raise HighBitError(f"{label} {metadata.get('basename')!r} does not match its pin")


def _validate_context(record: Mapping[str, object], source: str) -> dict:
    if record.get("schema") != PROBE_SCHEMA or record.get("type") != "context":
        raise HighBitError(f"{source}: expected {PROBE_SCHEMA} context record")
    for field in ("heap", "order", "barrier", "divisor", "offset_mode"):
        value = _require(record, field, source)
        if not isinstance(value, str) or not value:
            raise HighBitError(f"{source}: context {field!r} must be nonempty text")
    for field in ("cpu", "cntfrq", "mib", "repetitions", "pairs", "warmups"):
        value = _require(record, field, source)
        if not _is_int(value) or int(value) < 0:
            raise HighBitError(f"{source}: context {field!r} must be a non-negative JSON integer")
        if field in ("cntfrq", "mib", "repetitions", "pairs") and int(value) == 0:
            raise HighBitError(f"{source}: context {field!r} must be positive")
    return dict(record)


def _validate_heap(record: Mapping[str, object], source: str) -> dict:
    if record.get("schema") != PROBE_SCHEMA or record.get("type") != "ion_heap":
        raise HighBitError(f"{source}: expected {PROBE_SCHEMA} ion_heap record")
    name = _require(record, "name", source)
    if not isinstance(name, str) or not name:
        raise HighBitError(f"{source}: ion_heap name must be nonempty text")
    _parse_int(_require(record, "heap_type", source), "heap_type", source)
    _parse_int(_require(record, "heap_id", source), "heap_id", source)
    return dict(record)


def _validate_pa(record: Mapping[str, object], source: str) -> dict:
    if record.get("schema") != PROBE_SCHEMA or record.get("type") != "pa_provenance":
        raise HighBitError(f"{source}: expected {PROBE_SCHEMA} pa_provenance record")
    for field in ("source", "status", "first_pfn", "last_pfn"):
        value = _require(record, field, source)
        if not isinstance(value, str) or not value:
            raise HighBitError(f"{source}: pa_provenance {field!r} must be nonempty text")
    for field in ("pages", "present", "nonzero_pfn"):
        _parse_int(_require(record, field, source), field, source)
    contiguous = _require(record, "contiguous", source)
    if not isinstance(contiguous, bool):
        raise HighBitError(f"{source}: pa_provenance contiguous must be boolean")
    if record.get("source") != "pagemap" or record.get("status") != "BLIND":
        raise HighBitError(
            f"{source}: pa_provenance must be the retained pagemap BLIND record"
        )
    return dict(record)


def _normalise_pa_provenance(record: Mapping[str, object]) -> dict:
    """Keep the producer flag auditable without treating it as physical proof."""

    result = dict(record)
    if "contiguous" in result:
        result["reported_contiguous"] = result.pop("contiguous")
    if result.get("effective_contiguity") not in (None, "UNKNOWN"):
        raise HighBitError("pa_provenance effective contiguity is not UNKNOWN")
    result["effective_contiguity"] = "UNKNOWN"
    return result


def _validate_pair(record: Mapping[str, object], source: str) -> tuple[int, int, int]:
    if record.get("schema") != PROBE_SCHEMA or record.get("type") != "pair":
        raise HighBitError(f"{source}: expected {PROBE_SCHEMA} pair record")
    value = _parse_int(_require(record, "value", source), "value", source)
    offset = _parse_int(_require(record, "offset", source), "offset", source)
    if value == 0:
        raise HighBitError(f"{source}: pair value must be non-zero")
    if offset % PAGE_BYTES != 0:
        raise HighBitError(
            f"{source}: pair offset {_hex(offset)} is not {PAGE_BYTES}-byte aligned"
        )
    delta = _require(record, "delta", source)
    if not _is_int(delta):
        raise HighBitError(f"{source}: pair delta must be a JSON integer")
    return value, offset, int(delta)


def _validate_difference(record: Mapping[str, object], source: str) -> tuple[int, dict]:
    if record.get("schema") != PROBE_SCHEMA or record.get("type") != "difference":
        raise HighBitError(f"{source}: expected {PROBE_SCHEMA} difference record")
    value = _parse_int(_require(record, "value", source), "value", source)
    if value == 0:
        raise HighBitError(f"{source}: difference value must be non-zero")
    pairs = _parse_int(_require(record, "pairs", source), "pairs", source)
    if pairs <= 0:
        raise HighBitError(f"{source}: difference pairs must be positive")
    stats: dict[str, int] = {"pairs": pairs}
    for field in ("p10", "median", "p90"):
        item = _require(record, field, source)
        if not _is_int(item):
            raise HighBitError(f"{source}: difference {field!r} must be a JSON integer")
        stats[field] = int(item)
    if not stats["p10"] <= stats["median"] <= stats["p90"]:
        raise HighBitError(f"{source}: difference quantiles are not ordered")
    return value, stats


def _reject_json_constant(value: str) -> object:
    """Reject non-JSON numeric constants instead of admitting NaN/Infinity."""

    raise HighBitError(f"JSON constant {value!r} is not permitted")


def _json_objects(data: bytes, source: str) -> list[tuple[int, dict]]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HighBitError(f"{source}: transcript is not UTF-8") from exc
    if not text.strip():
        raise HighBitError(f"{source}: transcript is empty")
    objects: list[tuple[int, dict]] = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line, parse_constant=_reject_json_constant)
        except json.JSONDecodeError as exc:
            raise HighBitError(f"{source}:{number}: invalid JSON: {exc.msg}") from exc
        if not isinstance(record, dict):
            raise HighBitError(f"{source}:{number}: JSON record is not an object")
        objects.append((number, record))
    if not objects:
        raise HighBitError(f"{source}: transcript has no records")
    return objects


def _finish_section(section: dict, source: str) -> dict:
    if len(section["heaps"]) != 1:
        raise HighBitError(
            f"{source}: section {section['index']} needs exactly one ion_heap, "
            f"got {len(section['heaps'])}"
        )
    if len(section["pa_records"]) != 1:
        raise HighBitError(
            f"{source}: section {section['index']} needs exactly one pa_provenance, "
            f"got {len(section['pa_records'])}"
        )
    if not section["summaries"]:
        raise HighBitError(f"{source}: section {section['index']} has no differences")
    for difference, records in section["pairs_by_difference"].items():
        if difference not in section["summaries"]:
            raise HighBitError(f"{source}: pair records for {_hex(difference)} lack a summary")
        expected = section["summaries"][difference]["pairs"]
        if len(records) != expected:
            raise HighBitError(
                f"{source}: {_hex(difference)} has {len(records)} pair records, "
                f"summary says {expected}"
            )
    for difference, summary in section["summaries"].items():
        records = section["pairs_by_difference"].get(difference, ())
        if len(records) != summary["pairs"]:
            raise HighBitError(
                f"{source}: {_hex(difference)} summary has {summary['pairs']} "
                f"pairs but only {len(records)} preceding pair records"
            )
        values = sorted(item["delta"] for item in records)
        count = len(values)
        expected_stats = (
            values[count // 10],
            values[count // 2],
            values[count - 1 - count // 10],
        )
        actual_stats = (summary["p10"], summary["median"], summary["p90"])
        if actual_stats != expected_stats:
            raise HighBitError(
                f"{source}: {_hex(difference)} qsort statistics {actual_stats!r} "
                f"!= recomputed {expected_stats!r}"
            )
    section["medians"] = {
        difference: summary["median"]
        for difference, summary in sorted(section["summaries"].items())
    }
    section["summary_count"] = len(section["summaries"])
    section["pair_record_count"] = sum(len(items) for items in section["pairs_by_difference"].values())
    return section


def parse_probe_transcript(data: bytes | str, source: str = "<transcript>") -> dict:
    """Strictly parse a probe transcript while preserving every section."""

    if isinstance(data, str):
        raw = data.encode("utf-8")
    elif isinstance(data, bytes):
        raw = data
    else:
        raise HighBitError(f"{source}: transcript must be bytes or text")
    objects = _json_objects(raw, source)
    contexts: list[dict] = []
    sections: list[dict] = []
    heaps: list[dict] = []
    pa_records: list[dict] = []
    current: dict | None = None

    for line_number, raw_record in objects:
        record = dict(raw_record)
        location = f"{source}:{line_number}"
        kind = record.get("type")
        if kind == "context":
            if current is not None:
                sections.append(_finish_section(current, source))
            context = _validate_context(record, location)
            contexts.append(context)
            current = {
                "index": len(sections),
                "context": context,
                "heaps": [],
                "pa_records": [],
                "pairs_by_difference": {},
                "summaries": {},
                "summarized": set(),
                "pairs_started": False,
            }
            continue
        if current is None:
            raise HighBitError(f"{location}: record precedes the first context")
        if kind == "ion_heap":
            if current["pairs_started"]:
                raise HighBitError(f"{location}: ion_heap record appears after pair records")
            heap = _validate_heap(record, location)
            current["heaps"].append(heap)
            heaps.append(heap)
            continue
        if kind == "pa_provenance":
            if current["pairs_started"]:
                raise HighBitError(
                    f"{location}: pa_provenance record appears after pair records"
                )
            pa = _validate_pa(record, location)
            current["pa_records"].append(pa)
            pa_records.append(pa)
            continue
        if kind == "pair":
            difference, offset, delta = _validate_pair(record, location)
            if not current["heaps"] or not current["pa_records"]:
                raise HighBitError(
                    f"{location}: pair records require ion_heap and pa_provenance first"
                )
            current["pairs_started"] = True
            if difference in current["summarized"]:
                raise HighBitError(
                    f"{location}: pair for {_hex(difference)} appears after its summary"
                )
            limit = int(current["context"]["mib"]) * 1024 * 1024
            if difference >= limit:
                raise HighBitError(
                    f"{location}: pair difference {_hex(difference)} exceeds allocation"
                )
            if (
                offset + PAGE_BYTES > limit
                or (offset ^ difference) + PAGE_BYTES > limit
            ):
                raise HighBitError(
                    f"{location}: pair {_hex(difference)} page endpoint exceeds allocation"
                )
            records = current["pairs_by_difference"].get(difference)
            if records is None:
                records = []
                current["pairs_by_difference"][difference] = records
            if any(item["offset"] == offset for item in records):
                raise HighBitError(
                    f"{location}: duplicate pair offset {_hex(offset)} for {_hex(difference)}"
                )
            records.append({"offset": offset, "delta": delta})
            continue
        if kind == "difference":
            difference, summary = _validate_difference(record, location)
            if difference in current["summaries"]:
                raise HighBitError(f"{location}: duplicate summary for {_hex(difference)}")
            if difference in current["summarized"]:
                raise HighBitError(f"{location}: duplicate summary for {_hex(difference)}")
            records = current["pairs_by_difference"].get(difference, ())
            if summary["pairs"] != current["context"]["pairs"]:
                raise HighBitError(
                    f"{location}: {_hex(difference)} summary pairs "
                    f"{summary['pairs']} does not match context pairs "
                    f"{current['context']['pairs']}"
                )
            limit = int(current["context"]["mib"]) * 1024 * 1024
            if difference >= limit:
                raise HighBitError(
                    f"{location}: difference {_hex(difference)} exceeds allocation"
                )
            if len(records) != summary["pairs"]:
                raise HighBitError(
                    f"{location}: {_hex(difference)} has {len(records)} preceding pairs, "
                    f"summary says {summary['pairs']}"
                )
            current["summaries"][difference] = summary
            current["summarized"].add(difference)
            continue
        raise HighBitError(f"{location}: unrecognized transcript type {kind!r}")
    if current is not None:
        sections.append(_finish_section(current, source))
    if not sections or not contexts:
        raise HighBitError(f"{source}: no context section")
    if len({_identity(item) for item in contexts}) != 1:
        raise HighBitError(f"{source}: context sections are not identical")
    if len({_identity(item) for item in heaps}) != 1:
        raise HighBitError(f"{source}: ion_heap records are not identical")
    if len({_identity(item) for item in pa_records}) != 1:
        raise HighBitError(f"{source}: pa_provenance records are not identical")
    return {
        "context": contexts[0],
        "contexts": contexts,
        "ion_heap": heaps[0],
        "pa_provenance": _normalise_pa_provenance(pa_records[0]),
        "sections": [
            {
                **section,
                "pa_records": [
                    _normalise_pa_provenance(section["pa_records"][0])
                ],
            }
            for section in sections
        ],
        "record_count": len(objects),
        "summary_count": sum(section["summary_count"] for section in sections),
    }


def parse_probe_file(path: Path) -> dict:
    """Stable-read, independently re-read, and parse one JSONL input."""

    data, metadata = _stable_snapshot(Path(path), "probe input")
    parsed = parse_probe_transcript(data, Path(path).name)
    matching, matching_metadata = _stable_snapshot(Path(path), "probe input")
    if data != matching or metadata != matching_metadata:
        raise HighBitError(f"probe input {Path(path).name!r} changed after parsing")
    parsed["artifact"] = metadata
    parsed["path"] = Path(path)
    return parsed


def _section_copy(section: Mapping[str, object]) -> dict:
    heaps = section.get("heaps")
    pa_records = section.get("pa_records")
    summaries = section.get("summaries")
    medians = section.get("medians")
    if (
        not isinstance(heaps, Sequence)
        or isinstance(heaps, (str, bytes))
        or len(heaps) != 1
        or not isinstance(pa_records, Sequence)
        or isinstance(pa_records, (str, bytes))
        or len(pa_records) != 1
        or not isinstance(summaries, Mapping)
        or not isinstance(medians, Mapping)
    ):
        raise HighBitError("parsed section has an invalid retained shape")
    return {
        "index": int(section["index"]),
        "context": dict(section["context"]),
        "ion_heap": dict(heaps[0]),
        "pa_provenance": _normalise_pa_provenance(pa_records[0]),
        "medians": dict(medians),
        "summaries": {
            int(key): dict(value)
            for key, value in summaries.items()
        },
        "summary_count": int(section["summary_count"]),
        "pair_record_count": int(section["pair_record_count"]),
    }


def combine_three_column_passes(sections: Sequence[Mapping[str, object]]) -> tuple[dict[int, int], dict[int, dict]]:
    """Floor-average exactly two same-key passes, retaining both observations."""

    if len(sections) != 2:
        raise HighBitError(f"three-column combination needs exactly two sections, got {len(sections)}")
    first_raw = sections[0].get("medians")
    second_raw = sections[1].get("medians")
    if first_raw is None and "medians" not in sections[0]:
        first_raw = sections[0]
    if second_raw is None and "medians" not in sections[1]:
        second_raw = sections[1]
    if not isinstance(first_raw, Mapping) or not isinstance(second_raw, Mapping):
        raise HighBitError("three-column sections lack median mappings")
    first: dict[int, int] = {}
    second: dict[int, int] = {}
    for name, source, destination in (
        ("first", first_raw, first), ("second", second_raw, second)
    ):
        for key, value in source.items():
            difference = _parse_int(key, f"{name} difference key", "three-column pass")
            if not _is_int(value):
                raise HighBitError(
                    f"three-column {name} median {_hex(difference)} is not an integer"
                )
            if difference in destination:
                raise HighBitError(
                    f"three-column {name} has duplicate difference {_hex(difference)}"
                )
            destination[difference] = int(value)
    first_keys = set(first)
    second_keys = set(second)
    if not first_keys:
        raise HighBitError("three-column passes contain no differences")
    if first_keys != second_keys:
        raise HighBitError(
            f"three-column passes have unequal keys: "
            f"missing={sorted(first_keys - second_keys)}, extra={sorted(second_keys - first_keys)}"
        )
    combined: dict[int, int] = {}
    dispersion: dict[int, dict] = {}
    for difference in sorted(first_keys):
        values = [first[difference], second[difference]]
        mean = sum(values) / len(values)
        variance = sum((value - mean) ** 2 for value in values) / len(values)
        combined[difference] = sum(values) // len(values)
        dispersion[difference] = {
            "observations": 2,
            "values": values,
            "minimum": min(values),
            "maximum": max(values),
            "mean": mean,
            "population_stddev": round(math.sqrt(variance), 6),
            "spread": max(values) - min(values),
        }
    return combined, dispersion


def separation(medians: Mapping[int, int]) -> dict:
    """Return the deterministic widest-gap split and its runner-up."""

    if len(medians) < 2:
        raise HighBitError("separation needs at least two differences")
    ordered = sorted(int(value) for value in medians.values())
    gaps = [high - low for low, high in zip(ordered, ordered[1:])]
    ranked = sorted(enumerate(gaps), key=lambda item: (-item[1], item[0]))
    widest_index, widest_gap = ranked[0]
    runner_up = ranked[1][1] if len(ranked) > 1 else 0
    low = ordered[widest_index]
    high = ordered[widest_index + 1]
    return {
        "threshold": (low + high) // 2,
        "gap": widest_gap,
        "widest_gap": widest_gap,
        "runner_up_gap": runner_up,
        "runner_up_ratio": runner_up / widest_gap if widest_gap else 1.0,
        "band_low": low,
        "band_high": high,
        "value_count": len(ordered),
        "gap_count": len(gaps),
    }


def threshold(medians: Mapping[int, int]) -> int:
    """Return the in-acquisition widest-gap threshold.

    The two named references must be present before a caller can ask for a
    threshold.  Canonical analysis still records the full ``separation``
    object, but this guard prevents a caller from accidentally classifying a
    phase against an unrelated value set.
    """

    if KERNEL_REFERENCE not in medians or NEGATIVE_REFERENCE not in medians:
        raise HighBitError(
            "both in-acquisition references are required before thresholding"
        )
    split = separation(medians)
    if split["gap"] <= 0:
        raise HighBitError("in-acquisition references do not separate")
    return int(split["threshold"])


def classify(median: int, level: int) -> str:
    return "CONFLICT" if int(median) > int(level) else "NEGATIVE"


def labels(medians: Mapping[int, int], split: Mapping[str, object]) -> dict[int, str]:
    level = int(split["threshold"])
    return {int(key): classify(int(value), level) for key, value in medians.items()}


def assert_reference_labels(
    medians: Mapping[int, int],
    split: Mapping[str, object] | int,
    source: str = "<phase>",
) -> dict[str, str]:
    """Require both same-phase reference controls to have their named labels.

    The expected labels are an explicit contract, independent of aggregate
    conflict counts.  Every canonical discrimination section, held-out
    section, three-column pass, and combined three-column result calls this
    helper before publishing its split.
    """

    if isinstance(split, Mapping):
        if "threshold" not in split:
            raise HighBitError(f"{source}: reference split lacks threshold")
        level = int(split["threshold"])
    elif _is_int(split):
        level = int(split)
    else:
        raise HighBitError(f"{source}: reference split must contain a threshold")
    expected = {
        KERNEL_REFERENCE: "CONFLICT",
        NEGATIVE_REFERENCE: "NEGATIVE",
    }
    observed: dict[str, str] = {}
    for difference, expected_label in expected.items():
        if difference not in medians:
            raise HighBitError(
                f"{source}: required reference {_hex(difference)} is missing"
            )
        observed_label = classify(int(medians[difference]), level)
        observed[_hex(difference)] = observed_label
        if observed_label != expected_label:
            raise HighBitError(
                f"{source}: reference {_hex(difference)} classified as "
                f"{observed_label}, expected {expected_label}"
            )
    return observed


def assert_reference_controls(
    medians: Mapping[int, int],
    split: Mapping[str, object] | int,
    source: str = "<phase>",
) -> dict[str, str]:
    """Compatibility alias for the explicit same-phase control assertion."""

    return assert_reference_labels(medians, split, source)


def direction(
    alone: int,
    with_conflict: int,
    with_negative: int,
    level: int,
    conflict_reference: int,
) -> str:
    """Classify the three-column direction, including PA27's cancellation case."""

    del alone  # The alone value is retained in output; direction uses witnesses.
    conflict_falls = int(with_conflict) <= int(level)
    negative_raises = int(with_negative) > int(level)
    if conflict_falls and negative_raises:
        return "SELECTOR_CANCELS_NEGATIVE_WITNESS"
    if conflict_falls:
        return "SELECTOR"
    if negative_raises:
        together_tolerance = max(1, (int(conflict_reference) - int(level)) // 4)
        return (
            "SATURATING"
            if abs(int(with_conflict) - int(with_negative)) <= together_tolerance
            else "AMBIGUOUS"
        )
    return "INERT"


def analyse_high_bit(bit: int, medians: Mapping[int, int], level: int) -> dict:
    high = 1 << int(bit)
    alone = medians.get(high)
    with_conflict = medians.get(high ^ KERNEL_REFERENCE)
    with_negative = medians.get(high ^ NEGATIVE_REFERENCE)
    result = {
        "bit": int(bit),
        "alone": alone,
        "with_conflict": with_conflict,
        "with_negative": with_negative,
    }
    if None in (alone, with_conflict, with_negative) or KERNEL_REFERENCE not in medians:
        result["verdict"] = "INCOMPLETE"
        return result
    result["verdict"] = direction(
        int(alone), int(with_conflict), int(with_negative), int(level),
        int(medians[KERNEL_REFERENCE]),
    )
    result["alone_class"] = classify(int(alone), int(level))
    result["with_conflict_class"] = classify(int(with_conflict), int(level))
    result["with_negative_class"] = classify(int(with_negative), int(level))
    return result


def assert_three_column_verdict_consistency(
    pass_triplets: Sequence[Sequence[Mapping[str, object]]],
    combined_triplets: Sequence[Mapping[str, object]],
) -> dict:
    """Require each pass and the combined result to retain the same verdict.

    The means are only a representation of two already-analysed passes.  A
    mean cannot vote away a pass-level disagreement, so this gate runs after
    both pass-level triplet analyses and before a combined result is
    published.
    """

    if len(pass_triplets) != 2:
        raise HighBitError(
            f"three-column verdict check needs two passes, got {len(pass_triplets)}"
        )
    expected_bits = tuple(HIGH_BITS)
    pass_by_bit: list[dict[int, Mapping[str, object]]] = []
    for index, triplets in enumerate(pass_triplets):
        by_bit: dict[int, Mapping[str, object]] = {}
        for triplet in triplets:
            if not isinstance(triplet, Mapping):
                raise HighBitError(f"three-column pass {index} triplet is not an object")
            bit = triplet.get("bit")
            if not _is_int(bit) or int(bit) not in expected_bits or int(bit) in by_bit:
                raise HighBitError(f"three-column pass {index} has an invalid triplet bit")
            verdict = triplet.get("verdict")
            if not isinstance(verdict, str) or not verdict:
                raise HighBitError(f"three-column pass {index} triplet lacks verdict")
            by_bit[int(bit)] = triplet
        if tuple(sorted(by_bit)) != expected_bits:
            raise HighBitError(
                f"three-column pass {index} triplet bits do not cover PA25..PA27"
            )
        pass_by_bit.append(by_bit)

    combined_by_bit: dict[int, Mapping[str, object]] = {}
    for triplet in combined_triplets:
        if not isinstance(triplet, Mapping):
            raise HighBitError("combined three-column triplet is not an object")
        bit = triplet.get("bit")
        if not _is_int(bit) or int(bit) not in expected_bits or int(bit) in combined_by_bit:
            raise HighBitError("combined three-column triplet has an invalid bit")
        verdict = triplet.get("verdict")
        if not isinstance(verdict, str) or not verdict:
            raise HighBitError("combined three-column triplet lacks verdict")
        combined_by_bit[int(bit)] = triplet
    if tuple(sorted(combined_by_bit)) != expected_bits:
        raise HighBitError("combined three-column triplets do not cover PA25..PA27")

    by_bit: dict[str, dict] = {}
    for bit in expected_bits:
        verdicts = [str(pass_by_bit[index][bit]["verdict"]) for index in range(2)]
        combined_verdict = str(combined_by_bit[bit]["verdict"])
        all_verdicts = [*verdicts, combined_verdict]
        if len(set(all_verdicts)) != 1:
            raise HighBitError(
                f"three-column PA{bit} verdict mismatch: {all_verdicts!r}"
            )
        by_bit[str(bit)] = {
            "pass_verdicts": verdicts,
            "combined_verdict": combined_verdict,
            "consistent": True,
        }
    return {
        "all_consistent": True,
        "passes_checked": 2,
        "combined_checked": True,
        "by_bit": by_bit,
    }


def discriminate(bit: int, medians: Mapping[int, int], level: int) -> dict:
    """Find all lower bits whose single-bit combinations classify as conflict."""

    high = 1 << int(bit)
    tested: dict[str, int] = {}
    tested_bits: list[dict] = []
    matches: list[int] = []
    for lower in LOWER_BITS:
        difference = high ^ (1 << lower)
        if difference not in medians:
            continue
        value = int(medians[difference])
        label = classify(value, int(level))
        tested[_hex(difference)] = value
        tested_bits.append({
            "lower_bit": lower,
            "difference": _hex(difference),
            "median": value,
            "label": label,
        })
        if label == "CONFLICT":
            matches.append(lower)
    return {
        "bit": int(bit),
        "tested": tested,
        "tested_bits": tested_bits,
        "tested_count": len(tested_bits),
        "equal_contribution_bits": matches,
        "resolved": bool(matches),
    }


def check_predictions(
    predictions: Sequence[tuple[int, str]], medians: Mapping[int, int], level: int
) -> dict:
    checked: list[dict] = []
    agreements = 0
    for difference, expected in predictions:
        median = medians.get(int(difference))
        observed = None if median is None else classify(int(median), int(level))
        agrees = observed == expected
        if agrees:
            agreements += 1
        row = {
            "difference": _hex(int(difference)),
            "expected": expected,
            "observed": observed,
            "agrees": agrees,
        }
        if median is not None:
            row["median"] = int(median)
        checked.append(row)
    return {
        "checked": checked,
        "agreements": agreements,
        "total": len(predictions),
        "all_agree": agreements == len(predictions),
    }


def contiguity_check(
    medians: Mapping[int, int],
    level: int,
    known_kernel: Sequence[int],
    known_negative: Sequence[int],
) -> dict:
    """Compare retained model labels without promoting BLIND pagemap.

    This compatibility helper reports whether the supplied reference labels
    were reproduced in the current allocation-offset measurement.  That is a
    useful model-consistency check, but it is deliberately *not* physical
    contiguity evidence: callers must use ``effective_contiguity`` below as
    the authoritative physical status.
    """

    rows: list[dict] = []
    agreements = 0
    seen: set[int] = set()
    for difference, expected in (
        *((int(value), "CONFLICT") for value in known_kernel),
        *((int(value), "NEGATIVE") for value in known_negative),
    ):
        if difference in seen:
            raise HighBitError(
                f"contiguity references repeat difference {_hex(difference)}"
            )
        seen.add(difference)
        median = medians.get(difference)
        observed = None if median is None else classify(int(median), int(level))
        agrees = observed == expected
        if agrees:
            agreements += 1
        rows.append({
            "difference": _hex(difference),
            "median": median,
            "expected": expected,
            "observed": observed,
            "agrees": agrees,
        })
    total = len(rows)
    return {
        "rows": rows,
        "agreements": agreements,
        "total": total,
        # This is retained for callers of the original helper name only.  It
        # means reproduced model labels, never effective physical contiguity.
        "supports_contiguity": total > 0 and agreements == total,
        "effective_contiguity": "UNKNOWN",
        "coordinate_scope": PUBLIC_COORDINATE_SCOPE,
    }


def _parse_expected_sections(parsed: Mapping[str, object], role: str) -> list[dict]:
    sections = parsed.get("sections")
    if not isinstance(sections, Sequence) or isinstance(sections, (str, bytes)):
        raise HighBitError(f"{role}: parsed transcript has no sections")
    expected_section_count, expected_difference_count = EXPECTED_SECTION_COUNTS[role]
    if len(sections) != expected_section_count:
        raise HighBitError(
            f"{role}: expected {expected_section_count} sections, got {len(sections)}"
        )
    copied = [_section_copy(section) for section in sections]
    for section in copied:
        if section["summary_count"] != expected_difference_count:
            raise HighBitError(
                f"{role}: section {section['index']} expected {expected_difference_count} "
                f"differences, got {section['summary_count']}"
            )
        if int(section["context"].get("pairs", 0)) != 32:
            raise HighBitError(f"{role}: canonical context pairs must be 32")
        if section["pa_provenance"].get("status") != "BLIND":
            raise HighBitError(f"{role}: canonical pagemap status must be BLIND")
    return copied


def _canonical_context(parsed_by_role: Mapping[str, Mapping[str, object]]) -> dict:
    contexts = [parsed["context"] for parsed in parsed_by_role.values()]
    if len({_identity(context) for context in contexts}) != 1:
        raise HighBitError("canonical contexts differ across retained transcripts")
    context = dict(contexts[0])
    expected = {
        "schema": PROBE_SCHEMA,
        "type": "context",
        "cpu": 7,
        "cntfrq": 19200000,
        "heap": "camera_preview",
        "mib": 256,
        "repetitions": 201,
        "pairs": 32,
        "warmups": 17,
        "order": "alternating",
        "barrier": "dsb_ld",
        "divisor": "kept_times_two",
        "offset_mode": "spread",
    }
    if context != expected:
        raise HighBitError("canonical context does not match the retained camera-preview context")
    heaps = [parsed["ion_heap"] for parsed in parsed_by_role.values()]
    pa_records = [parsed["pa_provenance"] for parsed in parsed_by_role.values()]
    if len({_identity(item) for item in heaps}) != 1:
        raise HighBitError("canonical ion_heap records differ")
    if len({_identity(item) for item in pa_records}) != 1:
        raise HighBitError("canonical pa_provenance records differ")
    heap = dict(heaps[0])
    pa = dict(pa_records[0])
    if heap != {
        "schema": PROBE_SCHEMA, "type": "ion_heap", "name": "camera_preview",
        "heap_type": 10, "heap_id": 30,
    }:
        raise HighBitError("canonical ion_heap does not match camera_preview heap 10/id 30")
    if pa.get("source") != "pagemap" or pa.get("status") != "BLIND":
        raise HighBitError("canonical pa provenance is not pagemap BLIND")
    pa = _normalise_pa_provenance(pa)
    return {"context": context, "ion_heap": heap, "pa_provenance": pa}


def _validate_split(name: str, split: Mapping[str, object]) -> None:
    expected = EXPECTED_SPLITS[name]
    for key in (
        "threshold",
        "gap",
        "runner_up_gap",
        "band_low",
        "band_high",
        "conflict_count",
    ):
        if split.get(key) != expected[key]:
            raise HighBitError(
                f"{name}: {key}={split.get(key)!r}, expected {expected[key]!r}"
            )


def _validate_difference_shape(
    section: Mapping[str, object], expected: set[int], role: str
) -> None:
    actual = {int(key) for key in section["medians"]}
    if actual != expected:
        raise HighBitError(
            f"{role}: section {section['index']} keys differ; "
            f"missing={sorted(expected - actual)}, extra={sorted(actual - expected)}"
        )
    references = {KERNEL_REFERENCE, NEGATIVE_REFERENCE}
    if not references <= actual:
        raise HighBitError(f"{role}: section {section['index']} lacks both reference differences")


def _dependency_cross_check(
    dependency: Mapping[str, object], matches: Mapping[int, Sequence[int]]
) -> dict:
    if dependency.get("schema") != DEPENDENCY_SCHEMA:
        raise HighBitError("023R dependency has the wrong schema")
    kernel = dependency.get("kernel")
    if not isinstance(kernel, Mapping):
        raise HighBitError("023R dependency lacks kernel object")
    rank = dependency.get("rank")
    if not isinstance(rank, Mapping):
        raise HighBitError("023R dependency lacks rank object")
    if (
        rank.get("resolved") is not True
        or rank.get("rank") != 3
        or rank.get("surviving_ranks") != [3]
        or rank.get("coordinate_scope") != MODEL_COORDINATE_SCOPE
        or rank.get("physical_mapping_classification") != "SUPPORTED_WITHIN_MODEL"
    ):
        raise HighBitError("023R dependency rank semantics are not the pinned rank-3 model")
    new_bit = dependency.get("new_bit")
    if not isinstance(new_bit, Mapping):
        raise HighBitError("023R dependency lacks new_bit object")
    if (
        new_bit.get("new_bit") != 24
        or new_bit.get("resolved") is not True
        or new_bit.get("contribution") != "0b110"
        or new_bit.get("surviving_contributions") != ["0b110"]
        or new_bit.get("survivor_count") != 1
        or new_bit.get("coordinate_scope") != MODEL_COORDINATE_SCOPE
        or new_bit.get("physical_mapping_classification") != "SUPPORTED_WITHIN_MODEL"
    ):
        raise HighBitError("023R dependency new-bit semantics are not the pinned PA24 model")
    if (
        kernel.get("assumed_rank") != 3
        or kernel.get("span_dimension") != 9
        or kernel.get("required_kernel_dimension") != 9
        or kernel.get("consistent_kernel_count") != 1
        or kernel.get("unique") is not True
        or kernel.get("example_kernel_basis") != kernel.get("span_basis")
        or kernel.get("coordinate_scope") != MODEL_COORDINATE_SCOPE
        or kernel.get("physical_mapping_classification") != "SUPPORTED_WITHIN_MODEL"
    ):
        raise HighBitError("023R dependency kernel semantics are not the pinned unique rank-3 model")
    coordinate_scope = dependency.get("coordinate_scope")
    if not isinstance(coordinate_scope, Mapping):
        raise HighBitError("023R dependency lacks coordinate_scope object")
    if (
        coordinate_scope.get("kernel") != MODEL_COORDINATE_SCOPE
        or coordinate_scope.get("rank") != MODEL_COORDINATE_SCOPE
        or coordinate_scope.get("pa24_contribution") != MODEL_COORDINATE_SCOPE
        or coordinate_scope.get("physical_mapping") != "SUPPORTED_WITHIN_MODEL"
    ):
        raise HighBitError("023R dependency coordinate scopes are not model-scoped")
    values: set[int] = set()
    kernel_values: set[int] = set()
    basis = kernel.get("span_basis")
    if not isinstance(basis, Sequence) or isinstance(basis, (str, bytes)):
        raise HighBitError("023R dependency kernel lacks span_basis")
    for item in basis:
        value = _parse_int(item, "kernel span_basis", "023R dependency")
        values.add(value)
        kernel_values.add(value)
    differences = dependency.get("differences")
    if not isinstance(differences, Sequence) or isinstance(differences, (str, bytes)):
        raise HighBitError("023R dependency lacks differences")
    for item in differences:
        if not isinstance(item, Mapping):
            raise HighBitError("023R dependency difference is not an object")
        if "difference" in item:
            value = _parse_int(item["difference"], "difference", "023R dependency")
        elif "value" in item:
            value = _parse_int(item["value"], "value", "023R dependency")
        else:
            raise HighBitError("023R dependency difference lacks difference/value")
        values.add(value)
        label = item.get("label")
        if label == "KERNEL":
            kernel_values.add(value)
        elif label is not None and label != "NEGATIVE":
            raise HighBitError("023R dependency difference has an unknown label")
    rows: list[dict] = []
    for bit in HIGH_BITS:
        if bit not in matches:
            raise HighBitError(f"high-bit match set lacks PA{bit}")
        lower_values = matches[bit]
        if not isinstance(lower_values, Sequence) or isinstance(lower_values, (str, bytes)):
            raise HighBitError(f"PA{bit} match set is not a sequence")
        lower = tuple(_parse_int(value, f"PA{bit} match", "high-bit match") for value in lower_values)
        if any(value not in LOWER_BITS for value in lower) or len(set(lower)) != len(lower):
            raise HighBitError(f"PA{bit} match set has invalid or duplicate lower bits")
        pairwise: list[dict] = []
        for left, right in itertools.combinations(lower, 2):
            difference = (1 << left) ^ (1 << right)
            pairwise.append({
                "lower_bits": [left, right],
                "difference": _hex(difference),
                "present_in_023R_kernel_or_differences": difference in values,
            })
        rows.append({
            "bit": bit,
            "pairwise_equalities": pairwise,
            "pairwise_equalities_checked": len(pairwise),
        })
    for bit, difference in EXPECTED_LOWER_EQUALITIES.items():
        if difference not in kernel_values:
            raise HighBitError(
                f"023R dependency does not retain expected lower-kernel equality {_hex(difference)} as KERNEL"
            )
    return {
        "schema": dependency.get("schema"),
        "coordinate_scope": MODEL_COORDINATE_SCOPE,
        "physical_mapping_classification": "SUPPORTED_WITHIN_MODEL",
        "rank": rank["rank"],
        "new_bit": new_bit["new_bit"],
        "new_bit_contribution": new_bit["contribution"],
        "kernel_span_dimension": kernel["span_dimension"],
        "kernel_consistent_count": kernel["consistent_kernel_count"],
        "lower_kernel_equalities": rows,
        "retained_kernel_values_checked": sorted(_hex(value) for value in values),
    }


def _load_dependency(path: Path) -> tuple[dict, dict]:
    data, metadata = _stable_snapshot(Path(path), "023R dependency manifest")
    _check_pin(metadata, (DEPENDENCY_MANIFEST_SIZE, DEPENDENCY_MANIFEST_SHA256), "dependency manifest")
    try:
        dependency = json.loads(
            data.decode("utf-8"), parse_constant=_reject_json_constant
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HighBitError("023R dependency manifest is not valid JSON") from exc
    if not isinstance(dependency, dict) or dependency.get("schema") != DEPENDENCY_SCHEMA:
        raise HighBitError("023R dependency manifest has the wrong schema")
    rank = dependency.get("rank")
    new_bit = dependency.get("new_bit")
    if (
        not isinstance(rank, Mapping)
        or rank.get("resolved") is not True
        or rank.get("rank") != 3
        or rank.get("surviving_ranks") != [3]
        or rank.get("coordinate_scope") != MODEL_COORDINATE_SCOPE
        or rank.get("physical_mapping_classification") != "SUPPORTED_WITHIN_MODEL"
    ):
        raise HighBitError("023R dependency does not prove resolved rank 3")
    if (
        not isinstance(new_bit, Mapping)
        or new_bit.get("new_bit") != 24
        or new_bit.get("resolved") is not True
        or new_bit.get("contribution") != "0b110"
        or new_bit.get("surviving_contributions") != ["0b110"]
        or new_bit.get("survivor_count") != 1
        or new_bit.get("coordinate_scope") != MODEL_COORDINATE_SCOPE
        or new_bit.get("physical_mapping_classification") != "SUPPORTED_WITHIN_MODEL"
    ):
        raise HighBitError("023R dependency does not retain new bit 24")
    kernel = dependency.get("kernel")
    if (
        not isinstance(kernel, Mapping)
        or kernel.get("assumed_rank") != 3
        or kernel.get("span_dimension") != 9
        or kernel.get("required_kernel_dimension") != 9
        or kernel.get("consistent_kernel_count") != 1
        or kernel.get("unique") is not True
        or kernel.get("example_kernel_basis") != kernel.get("span_basis")
        or kernel.get("coordinate_scope") != MODEL_COORDINATE_SCOPE
        or kernel.get("physical_mapping_classification") != "SUPPORTED_WITHIN_MODEL"
    ):
        raise HighBitError("023R dependency does not retain the unique rank-3 kernel")
    return dependency, metadata


def _load_pinned_artifact(path: Path, pin: tuple[int, str], label: str) -> dict:
    _data, metadata = _stable_snapshot(Path(path), label)
    _check_pin(metadata, pin, label)
    return metadata


def _input_metadata(raw_dir: Path, paths: Mapping[str, Path]) -> dict[str, dict]:
    if raw_dir.is_symlink() or not raw_dir.is_dir():
        raise HighBitError("canonical raw directory is unavailable or symlinked")
    try:
        names = {item.name for item in raw_dir.iterdir()}
    except OSError as exc:
        raise HighBitError("canonical raw directory cannot be enumerated") from exc
    if names != set(RAW_BASENAMES):
        raise HighBitError(
            f"canonical raw directory must contain exactly {RAW_BASENAMES!r}, got {sorted(names)!r}"
        )
    identities: set[tuple[int, int]] = set()
    hashes: set[str] = set()
    metadata: dict[str, dict] = {}
    for name in RAW_BASENAMES:
        path = Path(paths[name])
        if path.is_symlink():
            raise HighBitError(f"raw input {name!r} must not be a symlink")
        try:
            mode = path.stat().st_mode
        except OSError as exc:
            raise HighBitError(f"raw input {name!r} is unreadable") from exc
        if not stat.S_ISREG(mode):
            raise HighBitError(f"raw input {name!r} is not a regular file")
        try:
            file_stat = path.stat()
            identity = (int(file_stat.st_dev), int(file_stat.st_ino))
        except OSError as exc:
            raise HighBitError(f"raw input {name!r} cannot be resolved") from exc
        if identity in identities:
            raise HighBitError(f"raw input path alias for {name!r}")
        identities.add(identity)
        metadata[name] = _load_pinned_artifact(path, RAW_PINS[name], "raw input")
        digest = metadata[name]["sha256"]
        if digest in hashes:
            raise HighBitError(f"raw input hash alias for {name!r}")
        hashes.add(digest)
    return metadata


def _prediction_label(difference: int, matches: Mapping[int, Sequence[int]]) -> str:
    """Evaluate a held-out difference from only measured equal-contribution classes."""

    if not _is_int(difference) or int(difference) < 0:
        raise HighBitError("held-out difference must be a non-negative integer")
    classes: dict[int, int] = {}
    for bit, lower_bits in sorted(matches.items()):
        if not _is_int(bit) or int(bit) not in HIGH_BITS:
            raise HighBitError("held-out match set has an unknown high bit")
        if not isinstance(lower_bits, Sequence) or isinstance(lower_bits, (str, bytes)):
            raise HighBitError("held-out match set is not a sequence")
        lower = tuple(_parse_int(value, "held-out lower bit", "held-out match") for value in lower_bits)
        if (
            not lower
            or any(value not in LOWER_BITS for value in lower)
            or len(set(lower)) != len(lower)
        ):
            raise HighBitError("held-out match set has an invalid lower bit")
        representative = min((int(bit), *lower))
        for item in (int(bit), *lower):
            prior = classes.get(item)
            if prior is not None and prior != representative:
                raise HighBitError("held-out match sets overlap inconsistently")
            classes[item] = representative
    parity: dict[int, int] = {}
    remaining = int(difference)
    bit = 0
    while remaining:
        if remaining & 1:
            representative = classes.get(bit, bit)
            parity[representative] = 1 - parity.get(representative, 0)
        remaining >>= 1
        bit += 1
    return "CONFLICT" if not any(parity.values()) else "NEGATIVE"


def analyse_canonical(raw_dir: Path = PRIVATE_ROOT, *, probe_source_path: Path = PROBE_SOURCE_PATH,
                      dependency_manifest_path: Path = DEPENDENCY_MANIFEST_PATH) -> dict:
    """Build the in-memory canonical analysis; publication is a separate step."""

    raw_dir = Path(raw_dir)
    paths = {name: raw_dir / name for name in RAW_BASENAMES}
    metadata = _input_metadata(raw_dir, paths)
    parsed = {
        "discriminate": parse_probe_file(paths["pa25-27-discriminate.jsonl"]),
        "heldout": parse_probe_file(paths["pa25-27-heldout.jsonl"]),
        "three_column": parse_probe_file(paths["pa25-27-three-column.jsonl"]),
    }
    # Rebind metadata from the parse path and require it to match the initial
    # stable/hash snapshot.  This is intentionally separate from parser reads.
    for name, path in paths.items():
        if parsed["discriminate" if "discriminate" in name else "heldout" if "heldout" in name else "three_column"]["artifact"] != metadata[name]:
            raise HighBitError(f"raw input {name!r} changed during analysis")
    sections = {
        role: _parse_expected_sections(parsed[role], role)
        for role in parsed
    }
    acquisition = _canonical_context(parsed)
    discrimination: list[dict] = []
    matches: dict[int, tuple[int, ...]] = {}
    phase_medians: dict[str, dict] = {}
    for bit, section in zip(HIGH_BITS, sections["discriminate"]):
        expected_keys = {KERNEL_REFERENCE, NEGATIVE_REFERENCE}
        expected_keys.update((1 << bit) ^ (1 << lower) for lower in LOWER_BITS)
        _validate_difference_shape(section, expected_keys, f"bit{bit}")
        split = separation(section["medians"])
        phase_labels = labels(section["medians"], split)
        reference_labels = assert_reference_labels(
            section["medians"], split, f"bit{bit} discrimination"
        )
        conflict_count = sum(value == "CONFLICT" for value in phase_labels.values())
        _validate_split(f"bit{bit}", {**split, "conflict_count": conflict_count})
        if conflict_count != EXPECTED_SPLITS[f"bit{bit}"]["conflict_count"]:
            raise HighBitError(f"bit{bit}: unexpected conflict count {conflict_count}")
        phase_medians[f"bit{bit}"] = {
            "bit": bit,
            "model_bit": bit,
            "section_index": section["index"],
            "context": dict(section["context"]),
            "ion_heap": dict(section["ion_heap"]),
            "pa_provenance": _normalise_pa_provenance(section["pa_provenance"]),
            "references": [_hex(KERNEL_REFERENCE), _hex(NEGATIVE_REFERENCE)],
            "reference_count": 2,
            "reference_labels": reference_labels,
            "summary_count": section["summary_count"],
            "pair_record_count": section["pair_record_count"],
            "medians": {_hex(key): value for key, value in sorted(section["medians"].items())},
            "labels": {_hex(key): phase_labels[key] for key in sorted(phase_labels)},
            "separation": {**split, "conflict_count": conflict_count},
        }
        result = discriminate(bit, section["medians"], split["threshold"])
        if tuple(result["equal_contribution_bits"]) != EXPECTED_MATCHES[bit] or result["tested_count"] != 12:
            raise HighBitError(f"bit{bit}: equal-contribution discrimination mismatch")
        matches[bit] = tuple(result["equal_contribution_bits"])
        result["section_index"] = section["index"]
        result["threshold"] = split["threshold"]
        discrimination.append(result)

    heldout_section = sections["heldout"][0]
    _validate_difference_shape(heldout_section, {KERNEL_REFERENCE, NEGATIVE_REFERENCE, *(difference for difference, _ in EXPECTED_HELDOUT)}, "heldout")
    heldout_split = separation(heldout_section["medians"])
    heldout_labels = labels(heldout_section["medians"], heldout_split)
    heldout_reference_labels = assert_reference_labels(
        heldout_section["medians"], heldout_split, "held-out section"
    )
    heldout_conflicts = sum(value == "CONFLICT" for value in heldout_labels.values())
    _validate_split("heldout", {**heldout_split, "conflict_count": heldout_conflicts})
    if heldout_conflicts != EXPECTED_SPLITS["heldout"]["conflict_count"]:
        raise HighBitError(f"heldout: unexpected conflict count {heldout_conflicts}")
    predictions = []
    for difference, expected in EXPECTED_HELDOUT:
        derived = _prediction_label(difference, matches)
        if derived != expected:
            raise HighBitError(f"heldout {_hex(difference)} has an inconsistent derived prediction")
        predictions.append((difference, expected))
    heldout_result = {
        "section_index": heldout_section["index"],
        "context": dict(heldout_section["context"]),
        "ion_heap": dict(heldout_section["ion_heap"]),
        "pa_provenance": _normalise_pa_provenance(heldout_section["pa_provenance"]),
        "references": [_hex(KERNEL_REFERENCE), _hex(NEGATIVE_REFERENCE)],
        "reference_count": 2,
        "reference_labels": heldout_reference_labels,
        "agreement_scope": "OUT_OF_SAMPLE_MODEL_DERIVED_AGREEMENT",
        "preregistration_status": "UNKNOWN_UNRETAINED",
        "acquisition_order_timestamp_status": "UNKNOWN_UNRETAINED",
        "summary_count": heldout_section["summary_count"],
        "pair_record_count": heldout_section["pair_record_count"],
        "medians": {_hex(key): value for key, value in sorted(heldout_section["medians"].items())},
        "labels": {_hex(key): heldout_labels[key] for key in sorted(heldout_labels)},
        "separation": {**heldout_split, "conflict_count": heldout_conflicts},
        "predictions": check_predictions(predictions, heldout_section["medians"], heldout_split["threshold"]),
    }
    if heldout_result["predictions"]["agreements"] != 7:
        raise HighBitError("heldout predictions are not exact 7/7")

    combined, dispersion = combine_three_column_passes(sections["three_column"])
    _validate_difference_shape(sections["three_column"][0], {KERNEL_REFERENCE, NEGATIVE_REFERENCE, 0x800, 0x2000000, 0x4000000, 0x8000000, 0x2016000, 0x4016000, 0x8016000, 0x2002000, 0x4002000, 0x8002000, 0x202C000, 0x2102000}, "three_column")
    three_passes: list[dict] = []
    pass_triplets: list[list[dict]] = []
    for pass_index, section in enumerate(sections["three_column"]):
        pass_split = separation(section["medians"])
        pass_labels = labels(section["medians"], pass_split)
        pass_reference_labels = assert_reference_labels(
            section["medians"], pass_split,
            f"three-column pass {section['index']}",
        )
        current_triplets: list[dict] = []
        for bit in HIGH_BITS:
            triplet = analyse_high_bit(bit, section["medians"], pass_split["threshold"])
            expected = EXPECTED_THREE_PASS_TRIPLETS[pass_index][bit]
            observed = (
                int(triplet["alone"]),
                int(triplet["with_conflict"]),
                int(triplet["with_negative"]),
                triplet["verdict"],
            )
            if observed != expected:
                raise HighBitError(
                    f"three-column pass {pass_index} PA{bit} triplet mismatch"
                )
            current_triplets.append(triplet)
        pass_triplets.append(current_triplets)
        three_passes.append({
            "section_index": section["index"],
            "context": dict(section["context"]),
            "ion_heap": dict(section["ion_heap"]),
            "pa_provenance": _normalise_pa_provenance(section["pa_provenance"]),
            "references": [_hex(KERNEL_REFERENCE), _hex(NEGATIVE_REFERENCE)],
            "reference_count": 2,
            "reference_labels": pass_reference_labels,
            "summary_count": section["summary_count"],
            "pair_record_count": section["pair_record_count"],
            "medians": {
                _hex(key): value for key, value in sorted(section["medians"].items())
            },
            "labels": {
                _hex(key): pass_labels[key] for key in sorted(pass_labels)
            },
            "triplets": current_triplets,
            "separation": {
                **pass_split,
                "conflict_count": sum(
                    value == "CONFLICT" for value in pass_labels.values()
                ),
            },
        })
    three_split = separation(combined)
    three_labels = labels(combined, three_split)
    three_reference_labels = assert_reference_labels(
        combined, three_split, "combined three-column passes"
    )
    three_conflicts = sum(value == "CONFLICT" for value in three_labels.values())
    _validate_split("three_column", {**three_split, "conflict_count": three_conflicts})
    if three_conflicts != EXPECTED_SPLITS["three_column"]["conflict_count"]:
        raise HighBitError(f"three_column: unexpected conflict count {three_conflicts}")
    triplets: list[dict] = []
    three_by_bit: dict[int, dict] = {}
    for bit in HIGH_BITS:
        high = 1 << bit
        item = {
            "bit": bit,
            "model_bit": bit,
            "alone": combined[high],
            "with_conflict": combined[high ^ KERNEL_REFERENCE],
            "with_negative": combined[high ^ NEGATIVE_REFERENCE],
        }
        item.update(analyse_high_bit(bit, combined, three_split["threshold"]))
        expected = EXPECTED_TRIPLETS[bit]
        if (item["alone"], item["with_conflict"], item["with_negative"], item["verdict"]) != expected:
            raise HighBitError(f"bit{bit}: three-column triplet mismatch")
        item["dispersion"] = {
            "alone": dispersion[high],
            "with_conflict": dispersion[high ^ KERNEL_REFERENCE],
            "with_negative": dispersion[high ^ NEGATIVE_REFERENCE],
        }
        triplets.append(item)
        three_by_bit[bit] = item
    three_verdict_consistency = assert_three_column_verdict_consistency(
        pass_triplets, triplets
    )
    three_result = {
        "pass_count": 2,
        "pass_section_indices": [section["index"] for section in sections["three_column"]],
        "passes": three_passes,
        "difference_count": len(combined),
        "medians": {_hex(key): value for key, value in sorted(combined.items())},
        "dispersion": {_hex(key): dispersion[key] for key in sorted(dispersion)},
        "labels": {_hex(key): three_labels[key] for key in sorted(three_labels)},
        "separation": {**three_split, "conflict_count": three_conflicts},
        "reference_labels": three_reference_labels,
        "verdict_consistency": three_verdict_consistency,
        "triplets": triplets,
    }
    dependency, dependency_metadata = _load_dependency(Path(dependency_manifest_path))
    probe_metadata = _load_pinned_artifact(Path(probe_source_path), (PROBE_SOURCE_SIZE, PROBE_SOURCE_SHA256), "probe source")
    helper_metadata = _load_pinned_artifact(V015_HELPER_PATH, (V015_HELPER_SIZE, V015_HELPER_SHA256), "V015 helper")
    dependency_cross_check = _dependency_cross_check(dependency, matches)
    manifest = {
        "schema": SCHEMA,
        "experiment_id": "verification-016-high-bit-relation",
        "mode": "HOST_ONLY_READ_ONLY_ANALYSIS",
        "eligibility": "NOT_ELIGIBLE",
        "classification": "Class C: TRANSFORM ONLY",
        "class_c": "TRANSFORM ONLY",
        "coordinate_scope": PUBLIC_COORDINATE_SCOPE,
        "references": {
            "kernel": _hex(KERNEL_REFERENCE),
            "negative": _hex(NEGATIVE_REFERENCE),
            "unique_count": 2,
        },
        "acquisition_context": acquisition,
        "sources": [
            {"file": name, "sections": len(sections[role]), "differences_per_section": EXPECTED_SECTION_COUNTS[role][1]}
            for name, role in (("pa25-27-discriminate.jsonl", "discriminate"), ("pa25-27-heldout.jsonl", "heldout"), ("pa25-27-three-column.jsonl", "three_column"))
        ],
        "phase_results": phase_medians,
        "phases": {
            "discriminate": [phase_medians[f"bit{bit}"] for bit in HIGH_BITS],
            "heldout": [heldout_result],
            "three_column": three_passes,
        },
        "discrimination": discrimination,
        "matches": {
            f"PA{bit}": list(matches[bit]) for bit in HIGH_BITS
        },
        "model_assessment": {
            "status": "SUPPORTED_WITHIN_MODEL",
            "coordinate_scope": PUBLIC_COORDINATE_SCOPE,
            "rank": dependency_cross_check["rank"],
            "duplicate_existing_contributions": True,
            "bits": {
                f"PA{bit}": {
                    "matching_lower_bits": list(matches[bit]),
                    "status": "SUPPORTED_WITHIN_MODEL",
                }
                for bit in HIGH_BITS
            },
        },
        "heldout": heldout_result,
        "heldout_predictions": heldout_result["predictions"],
        "historical_17_of_17": {
            "retained_evidence_status": "REFUTED_AS_RETAINED_EVIDENCE",
            "retained_reference_count_per_phase": 2,
            "separate_unretained_run_occurrence": "UNKNOWN",
            "separate_unretained_run_result": "UNKNOWN",
            "prediction_preregistration": "UNKNOWN_UNRETAINED",
            "acquisition_order_timestamp": "UNKNOWN_UNRETAINED",
        },
        "three_column": three_result,
        "dependency_cross_check": dependency_cross_check,
        "dependencies": {
            "probe_source": dict(probe_metadata),
            "dependency_manifest": dict(dependency_metadata),
            "v015_helper": dict(helper_metadata),
            "dependency_semantics": dict(dependency_cross_check),
        },
        "inputs": {
            "raw": [metadata[name] for name in RAW_BASENAMES],
            "probe_source": probe_metadata,
            "dependency_manifest": dependency_metadata,
            "v015_helper": helper_metadata,
        },
        "pins": {
            "raw": {name: {"size_bytes": pin[0], "sha256": pin[1]} for name, pin in sorted(RAW_PINS.items())},
            "probe_source": {"size_bytes": PROBE_SOURCE_SIZE, "sha256": PROBE_SOURCE_SHA256},
            "dependency_manifest": {"size_bytes": DEPENDENCY_MANIFEST_SIZE, "sha256": DEPENDENCY_MANIFEST_SHA256},
            "v015_helper": {"size_bytes": V015_HELPER_SIZE, "sha256": V015_HELPER_SHA256},
        },
        "raw_structure": {
            "discrimination_sections": 3,
            "discrimination_differences_per_section": 14,
            "heldout_sections": 1,
            "heldout_differences": 9,
            "three_column_sections": 2,
            "three_column_differences_per_section": 14,
            "unique_reference_differences_per_section": [_hex(KERNEL_REFERENCE), _hex(NEGATIVE_REFERENCE)],
            "reference_count": 2,
            "pair_count_per_difference": 32,
            "summary_statistics": "recomputed C qsort p10/median/p90",
        },
        "claims": {
            "PROVED": [
                "The retained discrimination transcript preserves three 14-key sections mapped in order to model bits 25, 26 and 27.",
                "The retained held-out transcript preserves one nine-key section and the retained three-column transcript preserves two identical-key 14-key passes.",
                "Every retained pair and qsort p10/median/p90 summary passed strict validation, including pair-before-summary, bounds and per-difference offset uniqueness.",
                "The canonical widest-gap splits, three-column floor-mean triplets and discrimination matches are exactly reproduced from the retained bytes.",
                "The separate held-out file has seven observed labels agreeing 7/7 with model-derived predictions from the discrimination matches; this is OUT_OF_SAMPLE_MODEL_DERIVED_AGREEMENT only.",
                "Each retained phase contains exactly the two reference differences 0x16000 and 0x2000; this proves the retained reference count, not a historical 17/17 run.",
            ],
            "SUPPORTED": [
                "In allocation-offset/model coordinates, model bits 25, 26 and 27 duplicate existing contribution vectors; this is SUPPORTED_WITHIN_MODEL and the supported model rank remains 3.",
            ],
            "HYPOTHESIS": [
                "The observed high-bit duplication may represent folding of high allocation-offset bits into the same model output space; physical controller semantics are not established.",
            ],
            "UNKNOWN": [
                "Physical PA25/PA26/PA27 mapping, allocation base and alignment, and effective physical contiguity remain unknown because pagemap is BLIND.",
                "Target, build, acquisition timestamp/order, prediction preregistration, historical device action, cleanup and final state are not attested by these raw transcripts.",
                "Whether a separate unretained 17-difference run occurred, and what result it produced, is UNKNOWN.",
                "The historical producer or cause of the external 192/170/506 tuple is UNKNOWN because that integration evidence is not retained in the canonical inputs.",
                "Filesystem inode provenance is UNKNOWN and not claimed; this analysis pins exact input bytes and content stability.",
                "Verification 017 is not promoted and requires a separate audit; no device authority, alias, mutation, protected reach or boundary bypass follows from this host analysis.",
            ],
            "REFUTED": [
                "REFUTED_AS_RETAINED_EVIDENCE: the external 192/170/506 tuple is not coherent with either retained three-column pass or their two-pass combine; the retained means are 152/133/206, 150/141/136 and 131/148/510.",
                "REFUTED_AS_RETAINED_EVIDENCE: the retained V016 bytes do not establish the historical 17/17 claim; that separate unretained run's occurrence and result remain UNKNOWN.",
            ],
        },
        "dispositions": {
            "class": "Class C: TRANSFORM ONLY",
            "eligibility": "NOT_ELIGIBLE",
            "numbered_experiments_015_and_016": "NOT_ELIGIBLE",
            "verification_017": "UNBLOCKED_FOR_SEPARATE_AUDIT_NOT_PROMOTED",
            "physical_attribution": "UNKNOWN_PAGEMAP_BLIND",
            "alias_mutation_protected_reach_bypass": "NO_ALIAS_OR_MUTATION_OBSERVED_OR_PROVED",
            "alias_or_mutation_scope": "NO_ALIAS_OR_MUTATION_OBSERVED_OR_TESTED",
            "protected_reach": "UNKNOWN_NOT_TESTED",
            "boundary_bypass": "UNKNOWN_NOT_TESTED",
            "device_action": "NONE_FOR_THIS_HOST_INTEGRATION",
        },
        "provenance_identity": {
            "target": {"status": "SUPPORTED_BY_UNRETAINED_OPERATOR_REPORT", "model": "SM-A908N", "soc": "SM8150", "transcript_attests_identity": False},
            "build": {"status": "SUPPORTED_BY_UNRETAINED_OPERATOR_REPORT", "kernel": "4.14.190-Grass,SD855-Perf+", "transcript_attests_identity": False},
            "timestamp": {"status": "UNKNOWN_UNRETAINED"},
            "commands": {
                "status": "REDACTED_REPRODUCTION_TEMPLATE",
                "template": (
                    "python3 tools/a90_high_bit_relation_analysis.py --raw "
                    "<private-root> --output <public-output>"
                ),
                "executed_receipt": "NOT_RETAINED",
            },
            "historical_action": {"status": "UNKNOWN_INCOMPLETE_RECEIPT"},
            "cleanup": {"status": "UNKNOWN_INCOMPLETE_RECEIPT"},
            "final_state": {"status": "UNKNOWN_INCOMPLETE_RECEIPT"},
        },
        "physical_provenance": {
            "pagemap_status": "BLIND",
            "reported_contiguous": bool(acquisition["pa_provenance"].get("reported_contiguous")),
            "effective_contiguity": "UNKNOWN",
            "physical_pa_mapping": "UNKNOWN",
            "allocation_base": "UNKNOWN",
            "allocation_alignment": "UNKNOWN",
            "coordinate_scope": PUBLIC_COORDINATE_SCOPE,
        },
        "public_private_separation": {
            "private_absolute_paths_in_manifest": False,
            "raw_transcript_bytes_in_manifest": False,
            "raw_sensitive_bytes_in_manifest": False,
            "input_paths_emitted": "BASENAMES_ONLY",
        },
        "input_identity_scope": {
            "contract": "PINNED_EXACT_BYTES_CONTENT_STABILITY",
            "filesystem_inode_provenance": "UNKNOWN_NOT_CLAIMED",
            "same_content_inode_replacement_effect": "NO_ANALYSIS_VALUE_CHANGE",
        },
        "publication": {
            "method": "ATOMIC_NO_CLOBBER_HARDLINK_V015_HELPER",
            "requested_mode": "0644",
            "helper_pin": V015_HELPER_SHA256,
        },
    }
    _assert_public_safety(manifest)
    return manifest


def load_medians(data: bytes | str) -> dict[int, int]:
    """Compatibility helper that refuses to flatten multi-section transcripts."""

    parsed = parse_probe_transcript(data)
    if len(parsed["sections"]) != 1:
        raise HighBitError("load_medians refuses to flatten multiple acquisition sections")
    return dict(parsed["sections"][0]["medians"])


def _assert_public_safety(value: object) -> None:
    try:
        v015._assert_public_safety(value)
    except v015.InvarianceError as exc:
        raise HighBitError(str(exc)) from exc


def encode_manifest(manifest: Mapping[str, object]) -> bytes:
    _assert_public_safety(manifest)
    return (json.dumps(manifest, indent=1, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def write_manifest(path: Path, manifest: Mapping[str, object], *, force: bool = False) -> dict:
    """Use the pinned repaired V015 atomic no-clobber/fresh-0644 publisher."""

    del force
    _load_pinned_artifact(V015_HELPER_PATH, (V015_HELPER_SIZE, V015_HELPER_SHA256), "V015 helper")
    _assert_public_safety(manifest)
    try:
        return v015.write_manifest(Path(path), manifest)
    except v015.InvarianceError as exc:
        raise HighBitError(str(exc)) from exc


def build_manifest(raw_dir: Path = PRIVATE_ROOT, **kwargs: object) -> dict:
    """Compatibility name for the canonical in-memory builder."""

    unknown = set(kwargs) - {"probe_source_path", "dependency_manifest_path"}
    if unknown:
        raise HighBitError(f"canonical builder does not accept {sorted(unknown)!r}")
    return analyse_canonical(Path(raw_dir), **kwargs)  # type: ignore[arg-type]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--raw", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        manifest = analyse_canonical(args.raw)
        publication = write_manifest(args.output, manifest)
        print(json.dumps({
            "triplets": [
                {"bit": item["bit"], "verdict": item["verdict"]}
                for item in manifest["three_column"]["triplets"]
            ],
            "heldout": manifest["heldout"]["predictions"],
            "output": {"size_bytes": publication["size_bytes"], "mode": publication["observed_mode"]},
        }, indent=1, sort_keys=True))
        return 0
    except (HighBitError, OSError) as exc:
        print(f"verification-016: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
