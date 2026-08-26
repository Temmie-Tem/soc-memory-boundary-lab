#!/usr/bin/env python3
"""Strict host-side analysis for the Verification-018 marker probe.

The probe is deliberately a storage-identity oracle, not a timing oracle.  A
marker observed at an offset which was only given a sentinel is evidence of a
non-injective map in the one state which was tested.  A clean run is only
injectivity over the exact allocation offsets and state in the transcript.
It says nothing about physical PA lines which pagemap did not disclose, other
heaps, untested offsets, or a Skitter-style permutation which is injective in
each individual state and can only be compared across states.

The parser is intentionally strict.  The live probe emits one fixed JSONL
record sequence; accepting a malformed, reordered, duplicated, or partially
known sequence would make a negative result impossible to audit.
"""

from __future__ import annotations

import argparse
from collections.abc import Iterable, Mapping, Sequence
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import stat
import sys

_IMPORT_ROOT = str(Path(__file__).resolve().parents[1])
if _IMPORT_ROOT not in sys.path:
    sys.path.insert(0, _IMPORT_ROOT)

from tools import a90_runtime_invariance_analysis as v015
from tools import a90_acm_snapshot as a90_acm


ANALYSIS_SCHEMA = "a90-alias-marker-analysis-v1"
PROBE_SCHEMA = "a90_alias_marker_v1"
LIVE_SCHEMA = "a90_alias_marker_live_v1"
MASK64 = (1 << 64) - 1
PAGE_BYTES = 4096
WORD_BYTES = 8
CACHE_LINE_SHIFT = 6
TOP_BIT = 27
EXPECTED_BITS = tuple(range(CACHE_LINE_SHIFT, TOP_BIT + 1))
EXPECTED_MIB = 256
EXPECTED_BYTES = EXPECTED_MIB * 1024 * 1024
EXPECTED_ANCHORS = (0x0, 0x0410B000, 0x0713A000, 0x0BCC0000)
TRIAL_COUNT = 2
EXPECTED_HEAP = "camera_preview"
EXPECTED_HEAP_TYPE = 10
EXPECTED_HEAP_ID = 30
DEFAULT_SEED = 0x5DA9F0E3C17B2846
CONTROL_LEFT = PAGE_BYTES
CONTROL_RIGHT = PAGE_BYTES * 3 + 8
TRIAL_SALT = 0xA24BAED4963EE407

SENTINEL_SALT = 0x9E3779B97F4A7C15
MARKER_SALT = 0xBF58476D1CE4E5B9
CONTROL_SAME_SALT = 0xD1B54A32D192ED03
CONTROL_DISTINCT_SALT = 0x2545F4914F6CDD1D

V015_HELPER_PATH = Path(__file__).resolve().with_name("a90_runtime_invariance_analysis.py")
V015_HELPER_SIZE = 97572
V015_HELPER_SHA256 = "6fae489d27d03f94e9dcd89086027a4209988a67020620e54f1df7e22ca99e03"
V018_RUNNER_PATH = Path(__file__).resolve().with_name("a90_alias_marker_live.py")
V018_BRIDGE_PATH = Path(__file__).resolve().with_name("a90_acm_snapshot.py")
BUILD_SCHEMA = "a90_alias_marker_build_v1"
RAW_PAYLOAD_BASENAME = "probe-output.bin"
TRANSCRIPT_BASENAME = "transcript.bin"
BUILD_RECEIPT_BASENAME = "build-receipt.json"
MAX_LEGACY_CHUNK = 3500

_HEX_RE = re.compile(r"0[xX][0-9a-fA-F]+\Z")
_SHA256_RE = re.compile(r"[0-9a-fA-F]{64}\Z")
_SAFE_BASENAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_SAFE_NODE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")


class MarkerError(RuntimeError):
    """Raised for any transcript, provenance, or publication contract error."""


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _parse_uint(value: object, field: str, source: str, *, max_value: int = MASK64) -> int:
    if _is_int(value):
        number = int(value)
    elif isinstance(value, str) and _HEX_RE.fullmatch(value):
        try:
            number = int(value, 16)
        except ValueError as exc:  # pragma: no cover - regex already excludes it
            raise MarkerError(f"{source}: {field} is not a hexadecimal integer") from exc
    else:
        raise MarkerError(f"{source}: {field} must be an unsigned integer or 0x string")
    if number < 0 or number > max_value:
        raise MarkerError(f"{source}: {field} is outside the unsigned 64-bit range")
    return number


def _parse_count(value: object, field: str, source: str, *, maximum: int) -> int:
    number = _parse_uint(value, field, source, max_value=maximum)
    return number


def _json_object(pairs: list[tuple[str, object]]) -> dict:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise MarkerError(f"JSON object repeats key {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise MarkerError(f"non-finite JSON number {value!r} is not permitted")


def _decode_transcript(data: bytes | str, source: str) -> list[dict]:
    if isinstance(data, bytes):
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise MarkerError(f"{source}: transcript is not UTF-8") from exc
    elif isinstance(data, str):
        text = data
    else:
        raise MarkerError(f"{source}: transcript must be bytes or text")
    if not text:
        raise MarkerError(f"{source}: transcript is empty")
    records: list[dict] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            raise MarkerError(f"{source}:{line_number}: blank JSONL record")
        try:
            record = json.loads(
                line,
                object_pairs_hook=_json_object,
                parse_constant=_reject_json_constant,
            )
        except MarkerError:
            raise
        except json.JSONDecodeError as exc:
            raise MarkerError(f"{source}:{line_number}: malformed JSON: {exc.msg}") from exc
        if not isinstance(record, dict):
            raise MarkerError(f"{source}:{line_number}: record is not an object")
        records.append(record)
    if not records:
        raise MarkerError(f"{source}: transcript has no records")
    return records


_COMMON_FIELDS = {"schema", "type"}
_FIELDS = {
    "context": _COMMON_FIELDS | {
        "heap", "mib", "anchors", "trials", "seed", "low_bit", "top_bit",
        "algorithm", "mapping", "ion_node",
    },
    "ion_heap": _COMMON_FIELDS | {"name", "heap_type", "heap_id"},
    "pa_provenance": _COMMON_FIELDS | {
        "source", "status", "pages", "present", "nonzero_pfn",
        "first_pfn", "last_pfn", "reported_contiguous",
        "effective_contiguity", "physical_mapping",
    },
    "anchor": _COMMON_FIELDS | {"anchor", "trial", "marker", "readback", "intact"},
    "candidate": _COMMON_FIELDS | {
        "anchor", "trial", "bit", "candidate", "expected", "observed", "verdict",
    },
    "summary": _COMMON_FIELDS | {
        "anchors", "trials", "candidates", "bits", "aliases", "disturbed",
        "clobbered_anchors", "trial_disagreements", "all_anchors_intact", "verdict",
    },
}
_CONTROL_FIELDS = {
    "same_storage_two_mappings": _COMMON_FIELDS | {
        "name", "offset", "different_virtual_addresses", "marker", "observed", "verdict",
    },
    "distinct": _COMMON_FIELDS | {
        "name", "left", "right", "marker", "expected", "observed", "verdict",
    },
}


def _check_record_shape(record: Mapping[str, object], source: str) -> None:
    kind = record.get("type")
    if record.get("schema") != PROBE_SCHEMA:
        raise MarkerError(f"{source}: unknown schema {record.get('schema')!r}")
    if not isinstance(kind, str):
        raise MarkerError(f"{source}: record type is missing or not text")
    if kind == "control":
        name = record.get("name")
        allowed = _CONTROL_FIELDS.get(name) if isinstance(name, str) else None
        if allowed is None:
            raise MarkerError(f"{source}: unknown control {name!r}")
    else:
        allowed = _FIELDS.get(kind)
        if allowed is None:
            raise MarkerError(f"{source}: unknown record type {kind!r}")
    if set(record) != allowed:
        missing = sorted(allowed - set(record))
        extra = sorted(set(record) - allowed)
        raise MarkerError(f"{source}: {kind} fields differ; missing={missing}, extra={extra}")


def _validate_order(records: Sequence[Mapping[str, object]], source: str) -> None:
    if not records or records[0].get("type") != "context":
        raise MarkerError(f"{source}: context must be the first record")
    if [record.get("type") for record in records[1:3]] != ["ion_heap", "pa_provenance"]:
        raise MarkerError(f"{source}: ion_heap and pa_provenance must follow context")
    if len(records) < 6 or any(record.get("type") != "control" for record in records[3:5]):
        raise MarkerError(f"{source}: exactly two controls must precede anchors")
    names = [records[3].get("name"), records[4].get("name")]
    if names != ["same_storage_two_mappings", "distinct"]:
        raise MarkerError(f"{source}: controls must be same_storage_two_mappings then distinct")
    cursor = 5
    for anchor_index in range(len(EXPECTED_ANCHORS)):
        for trial in range(TRIAL_COUNT):
            if cursor >= len(records) or records[cursor].get("type") != "anchor":
                raise MarkerError(f"{source}: anchor {anchor_index}/trial {trial} is missing or out of order")
            cursor += 1
            for bit in EXPECTED_BITS:
                if cursor >= len(records) or records[cursor].get("type") != "candidate":
                    raise MarkerError(
                        f"{source}: candidate for anchor {anchor_index}, trial {trial}, bit {bit} is missing"
                    )
                cursor += 1
    if cursor >= len(records) or records[cursor].get("type") != "summary":
        raise MarkerError(f"{source}: summary must be the final record")
    if cursor + 1 != len(records):
        raise MarkerError(f"{source}: records after summary or duplicate summary")


def parse(data: bytes | str, source: str = "<transcript>") -> list[dict]:
    """Parse one complete probe JSONL transcript without dropping a record."""

    records = _decode_transcript(data, source)
    for index, record in enumerate(records, 1):
        _check_record_shape(record, f"{source}:{index}")
    _validate_order(records, source)
    return [dict(record) for record in records]


def _mix(value: int) -> int:
    value = (value + 0x9E3779B97F4A7C15) & MASK64
    value = ((value ^ (value >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
    value = ((value ^ (value >> 27)) * 0x94D049BB133111EB) & MASK64
    return value ^ (value >> 31)


def sentinel_for(offset: int, seed: int) -> int:
    return _mix(offset ^ seed ^ SENTINEL_SALT)


def marker_for(anchor: int, seed: int) -> int:
    return _mix(anchor ^ seed ^ MARKER_SALT)


def trial_sentinel_for(offset: int, seed: int, trial: int) -> int:
    if trial not in range(TRIAL_COUNT):
        raise MarkerError(f"trial {trial} is outside 0..{TRIAL_COUNT - 1}")
    return _mix(offset ^ seed ^ SENTINEL_SALT ^ (trial * TRIAL_SALT))


def trial_marker_for(anchor: int, seed: int, trial: int) -> int:
    if trial not in range(TRIAL_COUNT):
        raise MarkerError(f"trial {trial} is outside 0..{TRIAL_COUNT - 1}")
    return _mix(anchor ^ seed ^ MARKER_SALT ^ (trial * TRIAL_SALT))


def control_same_marker(seed: int) -> int:
    return _mix(seed ^ CONTROL_SAME_SALT)


def control_distinct_marker(seed: int) -> int:
    return _mix(CONTROL_LEFT ^ seed ^ CONTROL_DISTINCT_SALT)


def deterministic_anchors(seed: int = DEFAULT_SEED) -> tuple[int, ...]:
    """Return the fixed, page-aligned four-anchor layout.

    ``seed`` is accepted to make the call site explicit: the layout is fixed so
    a future transcript can be compared across acquisitions, while markers
    and sentinels remain seed-dependent.  The argument is intentionally not
    used to avoid an acquisition changing its tested offsets unexpectedly.
    """

    del seed
    return EXPECTED_ANCHORS


def _layout_values(seed: int) -> list[tuple[str, int]]:
    values = [
        ("control.same.marker", control_same_marker(seed)),
        ("control.distinct.marker", control_distinct_marker(seed)),
        ("control.distinct.expected", sentinel_for(CONTROL_RIGHT, seed)),
    ]
    for anchor_index, anchor in enumerate(deterministic_anchors(seed)):
        for trial in range(TRIAL_COUNT):
            values.append((f"anchor[{anchor_index}].trial[{trial}].marker", trial_marker_for(anchor, seed, trial)))
            for bit in EXPECTED_BITS:
                candidate = anchor ^ (1 << bit)
                values.append((f"anchor[{anchor_index}].trial[{trial}].bit[{bit}].sentinel", trial_sentinel_for(candidate, seed, trial)))
    seen: dict[int, str] = {}
    for name, value in values:
        previous = seen.get(value)
        if previous is not None:
            raise MarkerError(f"generated marker/sentinel collision: {name} == {previous}")
        seen[value] = name
    return values


def _validate_context(record: Mapping[str, object], source: str) -> dict:
    if record.get("heap") != EXPECTED_HEAP or record.get("mib") != EXPECTED_MIB:
        raise MarkerError(f"{source}: probe must target camera_preview at 256 MiB")
    if record.get("anchors") != len(EXPECTED_ANCHORS) or record.get("trials") != TRIAL_COUNT:
        raise MarkerError(f"{source}: expected exactly four anchors and two trials")
    if record.get("low_bit") != CACHE_LINE_SHIFT or record.get("top_bit") != TOP_BIT:
        raise MarkerError(f"{source}: probe must test exactly bits 6..27")
    if record.get("algorithm") != "pmplease_alg2" or record.get("mapping") not in {
        "write_combine", "synthetic",
    }:
        raise MarkerError(f"{source}: unsupported probe algorithm or mapping")
    seed = _parse_uint(record.get("seed"), "seed", source)
    node = record.get("ion_node")
    if not isinstance(node, str) or not node:
        raise MarkerError(f"{source}: ion_node must be text")
    if node == "synthetic":
        node_basename = node
    elif node == "/dev/ion":
        node_basename = "ion"
    elif node.startswith("/tmp/a90-native/"):
        node_basename = node.rsplit("/", 1)[-1]
        if _SAFE_NODE_RE.fullmatch(node_basename) is None:
            raise MarkerError(f"{source}: ion_node has an unsafe temporary basename")
    else:
        raise MarkerError(f"{source}: ion_node is outside the approved node grammar")
    return {
        "heap": EXPECTED_HEAP,
        "mib": EXPECTED_MIB,
        "allocation_bytes": EXPECTED_BYTES,
        "anchors": len(EXPECTED_ANCHORS),
        "trials": TRIAL_COUNT,
        "seed": f"0x{seed:x}",
        "low_bit": CACHE_LINE_SHIFT,
        "top_bit": TOP_BIT,
        "algorithm": "pmplease_alg2",
        "mapping": record["mapping"],
        "ion_node_basename": node_basename,
    }


def _validate_heap(record: Mapping[str, object], source: str) -> dict:
    if record.get("name") != EXPECTED_HEAP:
        raise MarkerError(f"{source}: heap name is not camera_preview")
    heap_type = _parse_count(record.get("heap_type"), "heap_type", source, maximum=(1 << 32) - 1)
    heap_id = _parse_count(record.get("heap_id"), "heap_id", source, maximum=31)
    if heap_type != EXPECTED_HEAP_TYPE or heap_id != EXPECTED_HEAP_ID:
        raise MarkerError(f"{source}: camera_preview heap is not exact type 10/id 30")
    return {"name": EXPECTED_HEAP, "heap_type": heap_type, "heap_id": heap_id}


def _validate_pagemap(record: Mapping[str, object], source: str) -> dict:
    if record.get("source") != "pagemap":
        raise MarkerError(f"{source}: provenance source must be pagemap")
    if record.get("status") not in {"BLIND", "PARTIAL", "OPEN_FAILED"}:
        raise MarkerError(f"{source}: pagemap status is not a retained blind/partial status")
    pages = _parse_count(record.get("pages"), "pages", source, maximum=EXPECTED_BYTES // PAGE_BYTES)
    present = _parse_count(record.get("present"), "present", source, maximum=pages)
    nonzero = _parse_count(record.get("nonzero_pfn"), "nonzero_pfn", source, maximum=pages)
    if pages != EXPECTED_BYTES // PAGE_BYTES or present > pages or nonzero > pages:
        raise MarkerError(f"{source}: pagemap page counts do not match the allocation")
    for field in ("first_pfn", "last_pfn"):
        value = record.get(field)
        if value != "BLIND":
            _parse_uint(value, field, source)
    if not isinstance(record.get("reported_contiguous"), bool):
        raise MarkerError(f"{source}: reported_contiguous must be boolean")
    if record.get("effective_contiguity") != "UNKNOWN" or record.get("physical_mapping") != "UNKNOWN":
        raise MarkerError(f"{source}: pagemap provenance must remain physically UNKNOWN")
    return {
        "source": "pagemap",
        "status": record["status"],
        "pages": pages,
        "present": present,
        "nonzero_pfn": nonzero,
        "reported_contiguous": record["reported_contiguous"],
        "effective_contiguity": "UNKNOWN",
        "physical_mapping": "UNKNOWN",
    }


def _validate_controls(records: Sequence[Mapping[str, object]], seed: int, source: str) -> dict:
    same, distinct = records
    if same.get("name") != "same_storage_two_mappings" or distinct.get("name") != "distinct":
        raise MarkerError(f"{source}: control names are duplicated or out of order")
    gate_reasons: list[str] = []
    same_marker = control_same_marker(seed)
    same_ok = (
        _parse_uint(same["offset"], "same.offset", source) == 0
        and same["different_virtual_addresses"] is True
        and _parse_uint(same["marker"], "same.marker", source) == same_marker
        and _parse_uint(same["observed"], "same.observed", source) == same_marker
        and same["verdict"] == "ALIAS"
    )
    if not same_ok:
        gate_reasons.append("same_storage_two_mappings control did not fire")
    distinct_marker = control_distinct_marker(seed)
    distinct_expected = sentinel_for(CONTROL_RIGHT, seed)
    distinct_ok = (
        _parse_uint(distinct["left"], "distinct.left", source) == CONTROL_LEFT
        and _parse_uint(distinct["right"], "distinct.right", source) == CONTROL_RIGHT
        and _parse_uint(distinct["marker"], "distinct.marker", source) == distinct_marker
        and _parse_uint(distinct["expected"], "distinct.expected", source) == distinct_expected
        and _parse_uint(distinct["observed"], "distinct.observed", source) == distinct_expected
        and distinct["verdict"] == "DISTINCT"
    )
    if not distinct_ok:
        gate_reasons.append("distinct control reported an alias or changed")
    return {
        "same_storage_two_mappings": {
            "offset": "0x0", "different_virtual_addresses": True, "verdict": "ALIAS",
        },
        "distinct": {
            "left": f"0x{CONTROL_LEFT:x}",
            "right": f"0x{CONTROL_RIGHT:x}",
            "verdict": "DISTINCT",
        },
        "instrument_ok": not gate_reasons,
        "gate_reasons": gate_reasons,
    }


def _verdict(observed: int, expected: int, marker: int) -> str:
    if observed == marker:
        return "ALIAS"
    if observed != expected:
        return "DISTURBED"
    return "DISTINCT"


def _analyse_records(records: Sequence[Mapping[str, object]], source: str) -> dict:
    expected_record_count = 1 + 1 + 1 + 2 + len(EXPECTED_ANCHORS) * TRIAL_COUNT * (1 + len(EXPECTED_BITS)) + 1
    if len(records) != expected_record_count:
        raise MarkerError(f"{source}: transcript has the wrong record count")
    for index, record in enumerate(records, 1):
        _check_record_shape(record, f"{source}:{index}")
    _validate_order(records, source)
    context = _validate_context(records[0], f"{source}:context")
    seed = int(context["seed"], 16)
    heap = _validate_heap(records[1], f"{source}:ion_heap")
    pagemap = _validate_pagemap(records[2], f"{source}:pa_provenance")
    controls = _validate_controls(records[3:5], seed, f"{source}:controls")
    expected_anchors = deterministic_anchors(seed)
    if len(set(expected_anchors)) != len(expected_anchors):
        raise MarkerError(f"{source}: deterministic anchors are not unique")
    expected_words = _layout_values(seed)
    del expected_words  # The helper's collision gate is the source of truth.
    anchor_results: list[dict] = []
    candidate_results: list[dict] = []
    aliases: list[int] = []
    disturbed: list[int] = []
    clobbered: list[str] = []
    cursor = 5
    seen_observations: set[tuple[int, int, int]] = set()
    seen_offsets_by_trial: dict[int, set[int]] = {trial: set() for trial in range(TRIAL_COUNT)}
    trial_verdicts: dict[tuple[int, int], list[str]] = {}
    for anchor_index, expected_anchor in enumerate(expected_anchors):
        for trial in range(TRIAL_COUNT):
            anchor_record = records[cursor]
            cursor += 1
            anchor = _parse_uint(anchor_record["anchor"], "anchor", source)
            if not _is_int(anchor_record["trial"]) or anchor_record["trial"] != trial:
                raise MarkerError(f"{source}: anchor trial sequence is not exactly 0..1")
            if anchor != expected_anchor or anchor % PAGE_BYTES != 0:
                raise MarkerError(f"{source}: anchor {anchor_index} is not the expected page-aligned offset")
            if anchor + WORD_BYTES > EXPECTED_BYTES:
                raise MarkerError(f"{source}: anchor endpoint is outside allocation")
            expected_marker = trial_marker_for(anchor, seed, trial)
            readback = _parse_uint(anchor_record["readback"], "anchor.readback", source)
            intact = anchor_record["intact"]
            if _parse_uint(anchor_record["marker"], "anchor.marker", source) != expected_marker:
                raise MarkerError(f"{source}: anchor marker does not recompute")
            if not isinstance(intact, bool) or intact != (readback == expected_marker):
                raise MarkerError(f"{source}: anchor intact flag does not recompute")
            if not intact:
                clobbered.append(f"0x{anchor:x}/trial{trial}")
            anchor_results.append({
                "index": anchor_index,
                "trial": trial,
                "offset": f"0x{anchor:x}",
                "marker": f"0x{expected_marker:x}",
                "readback": f"0x{readback:x}",
                "intact": intact,
            })
            for expected_bit in EXPECTED_BITS:
                candidate_record = records[cursor]
                cursor += 1
                bit = candidate_record["bit"]
                if (
                    not _is_int(candidate_record["trial"])
                    or candidate_record["trial"] != trial
                    or not _is_int(bit)
                    or bit != expected_bit
                ):
                    raise MarkerError(f"{source}: candidate bit/trial sequence is not exactly 0..1 and 6..27")
                candidate = _parse_uint(candidate_record["candidate"], "candidate", source)
                expected_candidate = anchor ^ (1 << expected_bit)
                if candidate != expected_candidate:
                    raise MarkerError(f"{source}: candidate endpoint does not recompute")
                if candidate + WORD_BYTES > EXPECTED_BYTES:
                    raise MarkerError(f"{source}: candidate endpoint is outside allocation")
                identity = (anchor_index, trial, expected_bit)
                if identity in seen_observations:
                    raise MarkerError(f"{source}: candidate observation is duplicated")
                seen_observations.add(identity)
                if candidate in seen_offsets_by_trial[trial]:
                    raise MarkerError(f"{source}: candidate offset is duplicated within trial")
                seen_offsets_by_trial[trial].add(candidate)
                expected_sentinel = trial_sentinel_for(candidate, seed, trial)
                expected_value = _parse_uint(candidate_record["expected"], "candidate.expected", source)
                observed = _parse_uint(candidate_record["observed"], "candidate.observed", source)
                if expected_value != expected_sentinel:
                    raise MarkerError(f"{source}: candidate sentinel does not recompute")
                observed_verdict = _verdict(observed, expected_sentinel, expected_marker)
                if candidate_record["verdict"] != observed_verdict:
                    raise MarkerError(f"{source}: candidate verdict does not recompute")
                verdicts = trial_verdicts.get((anchor_index, expected_bit))
                if verdicts is None:
                    verdicts = []
                    trial_verdicts[(anchor_index, expected_bit)] = verdicts
                verdicts.append(observed_verdict)
                if observed_verdict == "ALIAS":
                    aliases.append(expected_bit)
                elif observed_verdict == "DISTURBED":
                    disturbed.append(expected_bit)
                candidate_results.append({
                    "anchor_index": anchor_index,
                    "trial": trial,
                    "anchor": f"0x{anchor:x}",
                    "bit": expected_bit,
                    "candidate": f"0x{candidate:x}",
                    "expected": f"0x{expected_sentinel:x}",
                    "observed": f"0x{observed:x}",
                    "verdict": observed_verdict,
                })
    trial_disagreements = sum(
        len(set(verdicts)) > 1 for verdicts in trial_verdicts.values()
    )
    if cursor != len(records) - 1:
        raise MarkerError(f"{source}: parser cursor did not reach summary")
    summary = records[-1]
    aliases_count = len(aliases)
    disturbed_count = len(disturbed)
    clobbered_count = len(clobbered)
    all_intact = clobbered_count == 0
    # The probe summary describes only its observed marker state.  Instrument
    # admissibility is a host-side gate and therefore has a separate verdict.
    probe_verdict = "ALIAS_DETECTED" if aliases_count else (
        "ANCHOR_CLOBBERED" if not all_intact else (
            "DISTURBANCE" if disturbed_count else "NO_ALIAS"
        )
    )
    expected_summary = {
        "anchors": len(expected_anchors),
        "candidates": len(candidate_results),
        "bits": len(EXPECTED_BITS),
        "aliases": aliases_count,
        "disturbed": disturbed_count,
        "trials": TRIAL_COUNT,
        "clobbered_anchors": clobbered_count,
        "trial_disagreements": trial_disagreements,
        "all_anchors_intact": all_intact,
        "verdict": probe_verdict,
    }
    numeric_summary_fields = set(expected_summary) - {"all_anchors_intact", "verdict"}
    for field, expected in expected_summary.items():
        actual = summary[field]
        if field in numeric_summary_fields and not _is_int(actual):
            raise MarkerError(f"{source}: summary {field!r} is not an integer")
        if field == "all_anchors_intact" and not isinstance(actual, bool):
            raise MarkerError(f"{source}: summary all_anchors_intact is not boolean")
        if field == "verdict" and not isinstance(actual, str):
            raise MarkerError(f"{source}: summary verdict is not text")
        if actual != expected:
            raise MarkerError(f"{source}: summary {field!r} is {actual!r}, expected {expected!r}")
    if not controls["instrument_ok"]:
        verdict = "INSTRUMENT_FAILED"
    elif trial_disagreements:
        verdict = "REPEAT_REQUIRED"
    else:
        verdict = probe_verdict
    return {
        "schema": ANALYSIS_SCHEMA,
        "instrument_ok": controls["instrument_ok"],
        "controls": controls,
        "context": context,
        "heap": {**heap, "physical_contiguity": "UNKNOWN"},
        "pagemap": pagemap,
        "anchors": anchor_results,
        "candidates": candidate_results,
        "anchors_tested": len(expected_anchors),
        "anchor_records": len(anchor_results),
        "trials": TRIAL_COUNT,
        "candidates_tested": len(candidate_results),
        "bits_tested": list(EXPECTED_BITS),
        "bit_span": [CACHE_LINE_SHIFT, TOP_BIT],
        "candidate_endpoints": {
            "count": len(seen_observations),
            "unique": len(seen_observations) == len(candidate_results),
            "all_within_allocation": True,
            "distinct_offsets_per_trial": all(
                len(offsets) == len(EXPECTED_ANCHORS) * len(EXPECTED_BITS)
                for offsets in seen_offsets_by_trial.values()
            ),
        },
        "aliased_bits": sorted(set(aliases)),
        "disturbed_bits": sorted(set(disturbed)),
        "clobbered_anchors": clobbered,
        "trial_disagreements": trial_disagreements,
        "probe_verdict": probe_verdict,
        "verdict": verdict,
        "negative_is_admissible": (
            controls["instrument_ok"]
            and trial_disagreements == 0
            and verdict == "NO_ALIAS"
        ),
        "scope": {
            "state": "ONE_TESTED_STATE",
            "offsets": "EXACT_RETAINED_CANDIDATE_PAIRS_ONLY",
            "storage_identity": "SINGLE_STATE_NONINJECTIVE_TEST",
            "physical_pa_mapping": "UNKNOWN_PAGEMAP_BLIND",
            "other_heaps_or_drams": "NOT_TESTED",
            "cross_state_skitter_permutation": "NOT_TESTED",
        },
    }


def analyse(records: Sequence[Mapping[str, object]], source: str = "<records>") -> dict:
    """Recompute every field of a parsed transcript and fail closed."""

    if isinstance(records, (str, bytes)) or not isinstance(records, Sequence):
        raise MarkerError(f"{source}: records must be a parsed sequence")
    return _analyse_records(records, source)


class SyntheticMemory:
    """A single-state memory with an optional dropped address line."""

    def __init__(self, size: int = EXPECTED_BYTES, drop_bit: int | None = None,
                 corrupt: Iterable[int] = ()):
        if size <= 0 or size & (size - 1):
            raise MarkerError("synthetic size must be a positive power of two")
        if size < EXPECTED_BYTES:
            raise MarkerError("synthetic size must cover the exact 256 MiB probe")
        if drop_bit is not None and not CACHE_LINE_SHIFT <= drop_bit <= TOP_BIT:
            raise MarkerError("drop_bit is outside the tested 6..27 range")
        self.size = size
        self.drop_bit = drop_bit
        self.corrupt = {int(offset) for offset in corrupt}
        self.cells: dict[int, int] = {}

    def _cell(self, offset: int) -> int:
        if not 0 <= offset < self.size:
            raise MarkerError(f"synthetic offset 0x{offset:x} is outside memory")
        if self.drop_bit is None:
            return offset
        return offset & ~(1 << self.drop_bit)

    def write(self, offset: int, value: int) -> None:
        self.cells[self._cell(offset)] = value & MASK64

    def read(self, offset: int) -> int:
        if offset in self.corrupt:
            return 0xDEADBEEFDEADBEEF
        return self.cells.get(self._cell(offset), 0)


class SkitterPermutation(SyntheticMemory):
    """Injective one-state permutation used to keep the cross-state limit visible."""

    def __init__(self, size: int = EXPECTED_BYTES, state_mask: int = 0x12345000):
        super().__init__(size)
        self.state_mask = state_mask & (size - 1)

    def _cell(self, offset: int) -> int:
        if not 0 <= offset < self.size:
            raise MarkerError(f"synthetic offset 0x{offset:x} is outside memory")
        return offset ^ self.state_mask


def _hex(value: int) -> str:
    return f"0x{value:x}"


def simulate(memory: SyntheticMemory, seed: int = DEFAULT_SEED) -> str:
    """Emit the same strict record sequence as the C probe for host self-tests."""

    if memory.size < EXPECTED_BYTES:
        raise MarkerError("synthetic memory is too small")
    anchors = deterministic_anchors(seed)
    lines: list[str] = []
    lines.append(json.dumps({
        "schema": PROBE_SCHEMA, "type": "context", "heap": EXPECTED_HEAP,
        "mib": EXPECTED_MIB, "anchors": len(anchors), "trials": TRIAL_COUNT,
        "seed": _hex(seed),
        "low_bit": CACHE_LINE_SHIFT, "top_bit": TOP_BIT,
        "algorithm": "pmplease_alg2", "mapping": "synthetic", "ion_node": "synthetic",
    }, sort_keys=True))
    lines.append(json.dumps({
        "schema": PROBE_SCHEMA, "type": "ion_heap", "name": EXPECTED_HEAP,
        "heap_type": EXPECTED_HEAP_TYPE, "heap_id": EXPECTED_HEAP_ID,
    }, sort_keys=True))
    lines.append(json.dumps({
        "schema": PROBE_SCHEMA, "type": "pa_provenance", "source": "pagemap",
        "status": "BLIND", "pages": EXPECTED_BYTES // PAGE_BYTES, "present": 0,
        "nonzero_pfn": 0, "first_pfn": "BLIND", "last_pfn": "BLIND",
        "reported_contiguous": False, "effective_contiguity": "UNKNOWN",
        "physical_mapping": "UNKNOWN",
    }, sort_keys=True))
    same_marker = control_same_marker(seed)
    memory.write(0, same_marker)
    lines.append(json.dumps({
        "schema": PROBE_SCHEMA, "type": "control", "name": "same_storage_two_mappings",
        "offset": "0x0", "different_virtual_addresses": True,
        "marker": _hex(same_marker), "observed": _hex(memory.read(0)),
        "verdict": "ALIAS" if memory.read(0) == same_marker else "MISSED",
    }, sort_keys=True))
    distinct_marker = control_distinct_marker(seed)
    distinct_expected = sentinel_for(CONTROL_RIGHT, seed)
    memory.write(CONTROL_RIGHT, distinct_expected)
    memory.write(CONTROL_LEFT, distinct_marker)
    observed = memory.read(CONTROL_RIGHT)
    lines.append(json.dumps({
        "schema": PROBE_SCHEMA, "type": "control", "name": "distinct",
        "left": _hex(CONTROL_LEFT), "right": _hex(CONTROL_RIGHT),
        "marker": _hex(distinct_marker), "expected": _hex(distinct_expected),
        "observed": _hex(observed), "verdict": "ALIAS" if observed == distinct_marker else "DISTINCT",
    }, sort_keys=True))
    aliases = 0
    disturbed = 0
    clobbered = 0
    trial_verdicts: dict[tuple[int, int], list[str]] = {}
    for anchor in anchors:
        anchor_index = anchors.index(anchor)
        for trial in range(TRIAL_COUNT):
            marker = trial_marker_for(anchor, seed, trial)
            for bit in EXPECTED_BITS:
                candidate = anchor ^ (1 << bit)
                memory.write(candidate, trial_sentinel_for(candidate, seed, trial))
            memory.write(anchor, marker)
            readback = memory.read(anchor)
            intact = readback == marker
            if not intact:
                clobbered += 1
            lines.append(json.dumps({
                "schema": PROBE_SCHEMA, "type": "anchor", "anchor": _hex(anchor),
                "trial": trial, "marker": _hex(marker), "readback": _hex(readback), "intact": intact,
            }, sort_keys=True))
            for bit in EXPECTED_BITS:
                candidate = anchor ^ (1 << bit)
                expected = trial_sentinel_for(candidate, seed, trial)
                observed = memory.read(candidate)
                verdict = _verdict(observed, expected, marker)
                aliases += verdict == "ALIAS"
                disturbed += verdict == "DISTURBED"
                trial_verdicts.setdefault((anchor_index, bit), []).append(verdict)
                lines.append(json.dumps({
                    "schema": PROBE_SCHEMA, "type": "candidate", "anchor": _hex(anchor),
                    "trial": trial, "bit": bit, "candidate": _hex(candidate), "expected": _hex(expected),
                    "observed": _hex(observed), "verdict": verdict,
                }, sort_keys=True))
    trial_disagreements = sum(len(set(items)) > 1 for items in trial_verdicts.values())
    verdict = "ALIAS_DETECTED" if aliases else (
        "ANCHOR_CLOBBERED" if clobbered else ("DISTURBANCE" if disturbed else "NO_ALIAS")
    )
    lines.append(json.dumps({
        "schema": PROBE_SCHEMA, "type": "summary", "anchors": len(anchors), "trials": TRIAL_COUNT,
        "candidates": len(anchors) * TRIAL_COUNT * len(EXPECTED_BITS), "bits": len(EXPECTED_BITS),
        "aliases": aliases, "disturbed": disturbed, "clobbered_anchors": clobbered,
        "trial_disagreements": trial_disagreements,
        "all_anchors_intact": clobbered == 0, "verdict": verdict,
    }, sort_keys=True))
    return "\n".join(lines) + "\n"


def self_test(seed: int = DEFAULT_SEED) -> dict:
    positives: dict[str, dict] = {}
    for bit in (6, 12, 13, 19, 27):
        result = analyse(parse(simulate(SyntheticMemory(drop_bit=bit), seed), "synthetic-positive"))
        positives[str(bit)] = {
            "dropped_bit": bit,
            "verdict": result["verdict"],
            "aliased_bits": result["aliased_bits"],
            "named_the_bit": result["aliased_bits"] == [bit],
        }
    negative = analyse(parse(simulate(SyntheticMemory(), seed), "synthetic-negative"))
    permutation = analyse(parse(simulate(SkitterPermutation(), seed), "synthetic-permutation"))
    passed = (
        all(item["verdict"] == "ALIAS_DETECTED" and item["named_the_bit"] for item in positives.values())
        and negative["verdict"] == "NO_ALIAS"
        and permutation["verdict"] == "NO_ALIAS"
    )
    return {
        "passed": passed,
        "positive_dropped_lines": positives,
        "injective_negative": {
            "verdict": negative["verdict"],
            "negative_is_admissible": negative["negative_is_admissible"],
        },
        "cross_state_skitter_permutation": {
            "single_state_verdict": permutation["verdict"],
            "status": "NOT_TESTED_BY_SINGLE_STATE_MARKER_SWEEP",
        },
    }


_KIND_ALIASES = {
    "raw": "raw",
    "probe_source": "probe_source",
    "probe-source": "probe_source",
    "probe_binary": "probe_binary",
    "probe-binary": "probe_binary",
    "acquisition_receipt": "acquisition_receipt",
    "acquisition-receipt": "acquisition_receipt",
    "build_receipt": "build_receipt",
    "build-receipt": "build_receipt",
}
_INPUT_KINDS = tuple(_KIND_ALIASES[key] for key in ("raw", "probe_source", "probe_binary", "acquisition_receipt", "build_receipt"))

_LIVE_TARGET = {
    "model": "SM-A908N",
    "soc": "SM8150",
    "runtime_version": "0.9.285",
    "runtime_build": "v2321-usb-clean-identity-rodata",
    "kernel": "Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64",
    "bootloader": "A908NKSU5EWA3",
    "debug_level": "0x4f4c",
    "force_upload": "0x0",
    "dump_sink": "0x0",
}
_LIVE_PROBE_ARGV = [
    "--ion-node", "/tmp/a90-native/v018-ion",
    "--seed", f"0x{DEFAULT_SEED:x}",
]
_LIVE_COMMAND_ARGV = ["run", "/tmp/a90-native/v018-alias-probe", *_LIVE_PROBE_ARGV]


def _normalise_kind(kind: str) -> str:
    try:
        return _KIND_ALIASES[kind]
    except KeyError as exc:
        raise MarkerError(f"unknown input kind {kind!r}") from exc


def _decode_receipt(data: bytes, source: str) -> dict:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MarkerError(f"{source}: receipt is not UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_json_object,
            parse_constant=_reject_json_constant,
        )
    except MarkerError:
        raise
    except json.JSONDecodeError as exc:
        raise MarkerError(f"{source}: malformed receipt JSON: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise MarkerError(f"{source}: receipt is not an object")
    return value


def _receipt_descriptor(value: object, field: str, source: str) -> dict:
    if not isinstance(value, Mapping):
        raise MarkerError(f"{source}: {field} descriptor is not an object")
    if set(value) != {"basename", "size_bytes", "sha256"}:
        raise MarkerError(f"{source}: {field} descriptor fields differ")
    # Descriptor shape is independent of artifact kind; `validate_pin` supplies
    # the shared basename/size/digest checks without inventing a path.
    return validate_pin(value, "raw") | {"basename": value["basename"]}


def _validate_build_receipt(data: bytes, source_artifact: Mapping[str, object], binary_artifact: Mapping[str, object], source: str) -> dict:
    receipt = _decode_receipt(data, source)
    required = {"schema", "source", "binary", "compiler", "reproducible_byte_identical"}
    if set(receipt) != required or receipt.get("schema") != BUILD_SCHEMA:
        raise MarkerError(f"{source}: build receipt schema/fields differ")
    source_desc = _receipt_descriptor(receipt.get("source"), "build.source", source)
    binary_desc = _receipt_descriptor(receipt.get("binary"), "build.binary", source)
    if source_desc != dict(source_artifact) or binary_desc != dict(binary_artifact):
        raise MarkerError(f"{source}: build receipt does not bind source/binary")
    if source_desc.get("basename") != "a90_alias_marker_probe.c" or binary_desc.get("basename") != "v018-alias-probe":
        raise MarkerError(f"{source}: build receipt basenames differ")
    compiler = receipt.get("compiler")
    if not isinstance(compiler, Mapping) or set(compiler) != {"triple", "version", "command", "static"}:
        raise MarkerError(f"{source}: build compiler fields differ")
    if (
        compiler.get("triple") != "aarch64-linux-gnu"
        or not isinstance(compiler.get("version"), str) or not compiler["version"].strip()
        or not isinstance(compiler.get("command"), list) or not compiler["command"]
        or any(not isinstance(item, str) or not item for item in compiler["command"])
        or compiler.get("static") is not True
        or receipt.get("reproducible_byte_identical") is not True
    ):
        raise MarkerError(f"{source}: build receipt lacks reproducibility proof")
    return {
        "schema": BUILD_SCHEMA,
        "compiler_triple": compiler["triple"],
        "compiler_version": compiler["version"],
        "static": True,
        "reproducible_byte_identical": True,
    }


def _parse_utc(value: object, field: str, source: str) -> dt.datetime:
    if not isinstance(value, str):
        raise MarkerError(f"{source}: {field} is not text")
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError as exc:
        raise MarkerError(f"{source}: {field} is not ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != dt.timedelta(0):
        raise MarkerError(f"{source}: {field} is not UTC")
    return parsed


def _expected_live_command_ids(chunk_count: int) -> list[str]:
    if not _is_int(chunk_count) or chunk_count < 1:
        raise MarkerError("live command chunk count is invalid")
    return [
        "version", "cmdline", "ion_dev", "preclean", "envelope_header",
        *[f"payload_{index:04d}" for index in range(chunk_count)],
        "envelope_footer", "decode", "chmod_binary", "remote_hash_before_run",
        "ion_node_create", "ion_node_chmod", "probe", "remote_hash_after_run",
        "cleanup_node", "cleanup_files", "absence_node", "absence_envelope",
        "absence_binary", "final_version", "final_cmdline", "final_selftest",
    ]


def _validate_live_command_list(value: object, chunk_count: int, source: str) -> None:
    if not isinstance(value, list):
        raise MarkerError(f"{source}: command transcript index is not a list")
    expected = _expected_live_command_ids(chunk_count)
    actual = [item.get("evidence_id") for item in value if isinstance(item, Mapping)]
    if actual != expected:
        raise MarkerError(f"{source}: command sequence differs from the fixed runner protocol")
    for index, item in enumerate(value):
        if not isinstance(item, Mapping) or set(item) != {
            "evidence_id", "argv", "extended", "begin", "end",
            "transcript_sha256", "transcript_size",
        }:
            raise MarkerError(f"{source}: command entry {index} fields differ")
        if item["evidence_id"] != expected[index]:
            raise MarkerError(f"{source}: command entry {index} is out of order")
        argv = item["argv"]
        if not isinstance(argv, list) or not argv or any(not isinstance(arg, str) for arg in argv):
            raise MarkerError(f"{source}: command entry {index} argv is invalid")
        begin = item["begin"]
        end = item["end"]
        if not isinstance(begin, Mapping) or not isinstance(end, Mapping):
            raise MarkerError(f"{source}: command entry {index} frame metadata is invalid")
        if begin.get("cmd") != argv[0] or end.get("cmd") != argv[0] or begin.get("seq") != end.get("seq"):
            raise MarkerError(f"{source}: command entry {index} frame identity differs")
        digest = item["transcript_sha256"]
        size = item["transcript_size"]
        if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest) or not _is_int(size) or size <= 0:
            raise MarkerError(f"{source}: command entry {index} transcript pin is invalid")
        if not isinstance(item["extended"], bool):
            raise MarkerError(f"{source}: command entry {index} extended flag is invalid")


def _validate_probe_sidecar(raw: bytes, payload: bytes, source: str) -> None:
    normalized = payload.replace(b"\r\n", b"\n")
    lines = normalized.splitlines()
    if (
        len(lines) < 3
        or re.fullmatch(rb"run: pid=[0-9]+, q/Ctrl-C cancels", lines[0]) is None
        or re.fullmatch(rb"\[exit 0\]", lines[-1]) is None
        or any(not line for line in lines[1:-1])
    ):
        raise MarkerError(f"{source}: framed probe sidecar has invalid transport framing")
    reconstructed = b"\n".join(lines[1:-1]) + b"\n"
    if reconstructed != raw:
        raise MarkerError(f"{source}: raw JSONL differs from the framed probe sidecar")


def _validate_live_transcript(
    data: bytes,
    commands: Sequence[Mapping[str, object]],
    source: str,
) -> None:
    headers = list(re.finditer(rb"(?:^|\n)===== ([a-z0-9_.-]+) =====\n", data))
    if len(headers) != len(commands):
        raise MarkerError(f"{source}: transcript frame/header count differs from command count")
    for index, (header, command) in enumerate(zip(headers, commands)):
        evidence_id = command["evidence_id"]
        if header.group(1).decode("ascii") != evidence_id:
            raise MarkerError(f"{source}: transcript command header {index} is out of order")
        start = header.end()
        end = headers[index + 1].start() if index + 1 < len(headers) else len(data)
        frame_bytes = data[start:end]
        if frame_bytes.count(b"A90P1 BEGIN ") != 1 or frame_bytes.count(b"A90P1 END ") != 1:
            raise MarkerError(f"{source}: transcript entry {evidence_id} is not exactly one frame")
        if hashlib.sha256(frame_bytes).hexdigest() != command["transcript_sha256"] or len(frame_bytes) != command["transcript_size"]:
            raise MarkerError(f"{source}: transcript pin differs for {evidence_id}")
        argv = command["argv"]
        try:
            frame = a90_acm.parse_last_frame(frame_bytes, str(argv[0]))
        except (ValueError, UnicodeError) as exc:
            raise MarkerError(f"{source}: transcript frame {evidence_id} is invalid: {exc}") from exc
        if (
            frame.begin.get("seq") != command["begin"].get("seq")
            or frame.end.get("seq") != command["end"].get("seq")
            or frame.end.get("rc") != "0"
            or frame.end.get("status") != "ok"
        ):
            raise MarkerError(f"{source}: transcript frame {evidence_id} status/sequence differs")


def validate_acquisition_receipt(
    data: bytes,
    *,
    raw: Mapping[str, object],
    source_artifact: Mapping[str, object],
    binary_artifact: Mapping[str, object],
    receipt_artifact: Mapping[str, object],
    build_artifact: Mapping[str, object],
    payload_artifact: Mapping[str, object],
    transcript_artifact: Mapping[str, object],
    runner_artifact: Mapping[str, object],
    bridge_artifact: Mapping[str, object],
    build_data: bytes,
    raw_data: bytes,
    payload_data: bytes,
    transcript_data: bytes,
    source: str = "acquisition receipt",
) -> dict:
    """Validate the live runner's reversible-acquisition and cleanup receipt."""

    receipt = _decode_receipt(data, source)
    required = {
        "schema", "status", "experiment_id", "started_utc", "completed_utc",
        "target_bound", "target", "target_frames", "bridge", "bridge_binding",
        "command_argv", "probe_argv", "command_sequence_validated",
        "probe", "artifacts", "source", "binary", "runner", "bridge_script",
        "build_receipt", "build", "upload", "remote_binary", "ion_device",
        "cleanup", "final_health", "transcript", "commands", "failures",
        "claims", "probe_completion",
    }
    if set(receipt) != required:
        raise MarkerError(f"{source}: top-level receipt fields differ")
    experiment_id = receipt.get("experiment_id")
    if (
        receipt.get("schema") != LIVE_SCHEMA
        or receipt.get("status") != "PASS"
        or receipt.get("target_bound") is not True
        or not isinstance(experiment_id, str)
        or _SAFE_BASENAME_RE.fullmatch(experiment_id) is None
    ):
        raise MarkerError(f"{source}: acquisition did not retain a valid PASS identity")
    started = _parse_utc(receipt.get("started_utc"), "started_utc", source)
    completed = _parse_utc(receipt.get("completed_utc"), "completed_utc", source)
    if completed < started:
        raise MarkerError(f"{source}: completion precedes acquisition start")
    if receipt.get("target") != _LIVE_TARGET:
        raise MarkerError(f"{source}: exact A90/V2321 target binding differs")
    if receipt.get("bridge") != {"host": "127.0.0.1", "port": 54321}:
        raise MarkerError(f"{source}: loopback bridge binding differs")
    if receipt.get("bridge_binding") != {
        "listener": {"host": "127.0.0.1", "port": 54321},
        "serial_device": "/dev/ttyACM0",
        "serial_identity_resolved": True,
        "bridge_process_script": "serial_tcp_bridge.py",
        "unique_process": True,
    }:
        raise MarkerError(f"{source}: exact local A90 bridge binding is absent")
    if receipt.get("probe_argv") != _LIVE_PROBE_ARGV or receipt.get("command_argv") != _LIVE_COMMAND_ARGV:
        raise MarkerError(f"{source}: fixed probe command differs")

    target_frames = receipt.get("target_frames")
    if not isinstance(target_frames, Mapping) or set(target_frames) != {"version", "cmdline"}:
        raise MarkerError(f"{source}: target identity frames are absent")
    for field in ("version", "cmdline"):
        frame = target_frames[field]
        if not isinstance(frame, Mapping) or not {
            "begin", "end", "payload_size", "payload_sha256", "transcript_size", "transcript_sha256",
        }.issubset(frame):
            raise MarkerError(f"{source}: target {field} frame descriptor is incomplete")
        if not _is_int(frame["payload_size"]) or frame["payload_size"] <= 0 or not _SHA256_RE.fullmatch(str(frame["payload_sha256"])):
            raise MarkerError(f"{source}: target {field} frame payload descriptor is invalid")
    probe = receipt.get("probe")
    if not isinstance(probe, Mapping) or probe.get("schema") != PROBE_SCHEMA or probe.get("records") != 190:
        raise MarkerError(f"{source}: probe receipt does not bind 190 exact records")
    if not _is_int(probe.get("child_pid")) or probe.get("child_pid") <= 0:
        raise MarkerError(f"{source}: probe child PID is invalid")
    if probe.get("child_exit_proved") is not True:
        raise MarkerError(f"{source}: probe child completion is not proved")
    completion = receipt.get("probe_completion")
    if (
        not isinstance(completion, Mapping)
        or completion.get("proved") is not True
        or completion.get("method") != "child_exit_receipt"
        or completion.get("pid") != probe.get("child_pid")
        or completion.get("errors") != []
    ):
        raise MarkerError(f"{source}: probe completion receipt is not a clean child-exit proof")
    retained_raw = _receipt_descriptor(probe.get("raw"), "raw", source)
    if retained_raw != dict(raw):
        raise MarkerError(f"{source}: retained raw descriptor differs from analyzed input")
    retained_payload = _receipt_descriptor(probe.get("payload"), "payload", source)
    if retained_payload != dict(payload_artifact):
        raise MarkerError(f"{source}: retained probe payload differs from sidecar input")
    _validate_probe_sidecar(raw_data, payload_data, source)
    retained_source = _receipt_descriptor(receipt.get("source"), "source", source)
    retained_binary = _receipt_descriptor(receipt.get("binary"), "binary", source)
    if retained_source != dict(source_artifact) or retained_binary != dict(binary_artifact):
        raise MarkerError(f"{source}: source/binary descriptor differs from analyzed inputs")
    retained_build = _receipt_descriptor(receipt.get("build_receipt"), "build_receipt", source)
    if retained_build != dict(build_artifact):
        raise MarkerError(f"{source}: build receipt descriptor differs from analyzed input")
    build_summary = _validate_build_receipt(build_data, source_artifact, binary_artifact, source)
    if receipt.get("build") != build_summary:
        raise MarkerError(f"{source}: build summary does not match the pinned build receipt")
    artifacts = receipt.get("artifacts")
    if (
        not isinstance(artifacts, Mapping)
        or artifacts.get("source") != receipt.get("source")
        or artifacts.get("binary") != receipt.get("binary")
        or artifacts.get("runner") != receipt.get("runner")
        or artifacts.get("bridge_script") != receipt.get("bridge_script")
        or artifacts.get("build_receipt") != receipt.get("build_receipt")
    ):
        raise MarkerError(f"{source}: receipt artifact aliases differ")
    if _receipt_descriptor(receipt.get("runner"), "runner", source) != dict(runner_artifact):
        raise MarkerError(f"{source}: runner script changed after acquisition")
    if _receipt_descriptor(receipt.get("bridge_script"), "bridge_script", source) != dict(bridge_artifact):
        raise MarkerError(f"{source}: bridge script changed after acquisition")

    upload = receipt.get("upload")
    remote = receipt.get("remote_binary")
    if not isinstance(upload, Mapping) or not isinstance(remote, Mapping):
        raise MarkerError(f"{source}: upload/remote binary receipt is missing")
    digest = binary_artifact["sha256"]
    if (
        upload.get("binary_size") != binary_artifact["size_bytes"]
        or upload.get("binary_sha256") != digest
        or upload.get("remote_sha256_verified") is not True
        or upload.get("remote_before_run_sha256") != digest
        or remote.get("before_run_sha256") != digest
        or remote.get("after_run_sha256") != digest
        or remote.get("unchanged") is not True
    ):
        raise MarkerError(f"{source}: uploaded binary was not hash-stable across execution")
    ion = receipt.get("ion_device")
    if (
        not isinstance(ion, Mapping)
        or ion.get("sysfs_identity") != "10:94"
        or ion.get("expected_identity") != "10:94"
        or ion.get("node_created") is not True
    ):
        raise MarkerError(f"{source}: fixed temporary ION identity was not retained")
    cleanup = receipt.get("cleanup")
    if (
        not isinstance(cleanup, Mapping)
        or cleanup.get("attempted") is not True
        or cleanup.get("node_removed") is not True
        or cleanup.get("files_removed") is not True
        or cleanup.get("absence_proved") is not True
        or cleanup.get("errors") != []
    ):
        raise MarkerError(f"{source}: cleanup is incomplete")
    health = receipt.get("final_health")
    if (
        not isinstance(health, Mapping)
        or health.get("attempted") is not True
        or health.get("ok") is not True
        or health.get("errors") != []
        or health.get("target") != _LIVE_TARGET
    ):
        raise MarkerError(f"{source}: final health is incomplete")
    selftest = health.get("selftest")
    if not isinstance(selftest, Mapping) or set(selftest) != {
        "passed", "warn", "fail", "duration", "entries",
    }:
        raise MarkerError(f"{source}: final device self-test receipt fields differ")
    if any(not _is_int(selftest[field]) for field in selftest):
        raise MarkerError(f"{source}: final device self-test counts are not integers")
    if (
        selftest["passed"] <= 0
        or selftest["warn"] < 0
        or selftest["fail"] != 0
        or selftest["duration"] < 0
        or selftest["entries"] != selftest["passed"] + selftest["warn"]
    ):
        raise MarkerError(f"{source}: final device self-test did not pass")
    if receipt.get("failures") != []:
        raise MarkerError(f"{source}: receipt retains acquisition failures")
    commands = receipt.get("commands")
    if not isinstance(commands, list) or not commands:
        raise MarkerError(f"{source}: command transcript index is absent")
    transcript = receipt.get("transcript")
    if _receipt_descriptor(transcript, "transcript", source) != dict(transcript_artifact):
        raise MarkerError(f"{source}: transcript descriptor is absent")
    # The receipt is only a summary; the command list is independently checked
    # against the exact upload chunk count and fixed command order below.
    if receipt.get("command_sequence_validated") is not True:
        raise MarkerError(f"{source}: command sequence was not validated at acquisition")
    base64_bytes = ((int(binary_artifact["size_bytes"]) + 2) // 3) * 4
    chunk_count = (base64_bytes + MAX_LEGACY_CHUNK - 1) // MAX_LEGACY_CHUNK
    _validate_live_command_list(receipt.get("commands"), chunk_count, source)
    _validate_live_transcript(transcript_data, receipt["commands"], source)
    claims = receipt.get("claims")
    if not isinstance(claims, Mapping) or claims.get("interpretation") != "DEFERRED_TO_HOST_ANALYZER":
        raise MarkerError(f"{source}: live runner claimed an interpretation")
    return {
        "status": "PASS",
        "experiment_id": experiment_id,
        "started_utc": receipt["started_utc"],
        "completed_utc": receipt["completed_utc"],
        "target": dict(_LIVE_TARGET),
        "loopback_bridge_bound": True,
        "probe_command_bound": True,
        "source_binary_raw_bound": True,
        "remote_binary_hash_stable": True,
        "temporary_ion_node_removed": True,
        "remote_files_removed": True,
        "remote_absence_proved": True,
        "final_health_passed": True,
        "receipt": dict(receipt_artifact),
        "build": _validate_build_receipt(build_data, source_artifact, binary_artifact, source),
    }


def validate_pin(pin: Mapping[str, object], kind: str) -> dict:
    """Validate a future exact-input pin without inventing any hash."""

    normalized = _normalise_kind(kind)
    if not isinstance(pin, Mapping):
        raise MarkerError(f"{normalized} pin must be an object")
    allowed = {"basename", "size_bytes", "sha256"}
    if set(pin) - allowed or not {"size_bytes", "sha256"}.issubset(pin):
        raise MarkerError(f"{normalized} pin must contain only basename/size_bytes/sha256")
    basename = pin.get("basename")
    if basename is not None and (not isinstance(basename, str) or _SAFE_BASENAME_RE.fullmatch(basename) is None):
        raise MarkerError(f"{normalized} pin basename is unsafe")
    size = pin["size_bytes"]
    if not _is_int(size) or int(size) < 0:
        raise MarkerError(f"{normalized} pin size_bytes must be non-negative JSON integer")
    digest = pin["sha256"]
    if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
        raise MarkerError(f"{normalized} pin sha256 must be 64 hexadecimal characters")
    result = {"size_bytes": int(size), "sha256": digest.lower()}
    if basename is not None:
        result["basename"] = basename
    return result


def _stable_artifact(path: Path, kind: str, pin: Mapping[str, object] | None = None) -> tuple[bytes, dict]:
    path = Path(path)
    normalized = _normalise_kind(kind)
    try:
        first = v015._read_stable_bytes(path, f"{normalized} input")
        second = v015._read_stable_bytes(path, f"{normalized} input independent re-read")
    except v015.InvarianceError as exc:
        raise MarkerError(str(exc)) from exc
    if first != second:
        raise MarkerError(f"{normalized} input changed between stable reads")
    metadata = {
        "basename": path.name,
        "size_bytes": len(first),
        "sha256": hashlib.sha256(first).hexdigest(),
    }
    if pin is not None:
        checked = validate_pin(pin, normalized)
        if checked.get("basename", path.name) != path.name or checked["size_bytes"] != metadata["size_bytes"] or checked["sha256"] != metadata["sha256"]:
            raise MarkerError(f"{normalized} input does not match its supplied exact pin")
    return first, metadata


def analyse_raw(
    raw_path: Path,
    *,
    pins: Mapping[str, Mapping[str, object]] | None = None,
    artifacts: Mapping[str, Path] | None = None,
) -> dict:
    """Read and analyse one raw transcript plus optional future input artifacts."""

    pins_normalized: dict[str, Mapping[str, object]] = {}
    for kind, pin in (pins or {}).items():
        normalized = _normalise_kind(kind)
        if normalized in pins_normalized:
            raise MarkerError(f"duplicate pin kind {normalized!r}")
        pins_normalized[normalized] = validate_pin(pin, normalized)
    artifacts_normalized: dict[str, Path] = {}
    for kind, path in (artifacts or {}).items():
        normalized = _normalise_kind(kind)
        if normalized in artifacts_normalized:
            raise MarkerError(f"duplicate artifact kind {normalized!r}")
        artifacts_normalized[normalized] = Path(path)
    if set(artifacts_normalized) - set(_INPUT_KINDS):
        raise MarkerError("unknown future input artifact kind")
    if "raw" in artifacts_normalized:
        raise MarkerError("raw artifact is supplied by raw_path, not artifacts")
    dangling_pins = set(pins_normalized) - {"raw", *artifacts_normalized}
    if dangling_pins:
        raise MarkerError(f"declared pins lack supplied artifacts: {sorted(dangling_pins)}")
    raw_bytes, raw_metadata = _stable_artifact(Path(raw_path), "raw", pins_normalized.get("raw"))
    run = analyse(parse(raw_bytes, Path(raw_path).name), Path(raw_path).name)
    synthetic_self_test = self_test()
    if not synthetic_self_test["passed"]:
        raise MarkerError("host synthetic self-test failed during raw analysis")
    input_metadata: dict[str, dict] = {"raw": raw_metadata}
    artifact_bytes: dict[str, bytes] = {}
    for kind in (
        "probe_source", "probe_binary", "acquisition_receipt", "build_receipt",
    ):
        path = artifacts_normalized.get(kind)
        if path is not None:
            data, metadata = _stable_artifact(path, kind, pins_normalized.get(kind))
            artifact_bytes[kind] = data
            input_metadata[kind] = metadata
    live_kinds = {
        "probe_source", "probe_binary", "acquisition_receipt", "build_receipt",
    }
    supplied_live_kinds = live_kinds & set(artifacts_normalized)
    if supplied_live_kinds and supplied_live_kinds != live_kinds:
        raise MarkerError(
            "device acquisition validation requires probe source, probe binary, "
            "and acquisition receipt together"
        )
    acquisition: dict | None = None
    if supplied_live_kinds == live_kinds:
        if (
            run["context"]["mapping"] != "write_combine"
            or run["context"]["ion_node_basename"] != "v018-ion"
        ):
            raise MarkerError(
                "validated live acquisition requires write_combine and the fixed v018-ion node"
            )
        sidecar_metadata: dict[str, dict] = {}
        sidecar_bytes: dict[str, bytes] = {}
        for basename, key in (
            (RAW_PAYLOAD_BASENAME, "raw_payload"),
            (TRANSCRIPT_BASENAME, "transcript"),
        ):
            sidecar_data, metadata = _stable_artifact(
                Path(raw_path).parent / basename,
                "raw",
            )
            sidecar_bytes[key] = sidecar_data
            sidecar_metadata[key] = metadata
            input_metadata[key] = metadata
        runner_data, runner_metadata = _stable_artifact(V018_RUNNER_PATH, "raw")
        bridge_data, bridge_metadata = _stable_artifact(V018_BRIDGE_PATH, "raw")
        input_metadata["runner"] = runner_metadata
        input_metadata["bridge_script"] = bridge_metadata
        acquisition = validate_acquisition_receipt(
            artifact_bytes["acquisition_receipt"],
            raw=raw_metadata,
            source_artifact=input_metadata["probe_source"],
            binary_artifact=input_metadata["probe_binary"],
            receipt_artifact=input_metadata["acquisition_receipt"],
            build_artifact=input_metadata["build_receipt"],
            payload_artifact=sidecar_metadata["raw_payload"],
            transcript_artifact=sidecar_metadata["transcript"],
            runner_artifact=runner_metadata,
            bridge_artifact=bridge_metadata,
            build_data=artifact_bytes["build_receipt"],
            raw_data=raw_bytes,
            payload_data=sidecar_bytes["raw_payload"],
            transcript_data=sidecar_bytes["transcript"],
        )
    if acquisition is None:
        status = "HOST_TOOL_READY_DEVICE_ACQUISITION_PENDING"
        device_negative_claim = "NOT_PROMOTED"
    elif run["verdict"] == "NO_ALIAS" and run["negative_is_admissible"]:
        status = "DEVICE_ACQUISITION_VALIDATED"
        device_negative_claim = "PROVED_NO_ALIAS_IN_EXACT_TESTED_OFFSET_PAIRS"
    elif run["verdict"] == "ALIAS_DETECTED":
        status = "POTENTIAL_NORMAL_RAM_NONINJECTIVE_ALIAS"
        device_negative_claim = "NOT_APPLICABLE_ALIAS_OBSERVED"
    elif run["verdict"] == "REPEAT_REQUIRED":
        status = "REPEAT_REQUIRED"
        device_negative_claim = "NOT_PROMOTED"
    else:
        status = "DEVICE_ACQUISITION_ANOMALY_REQUIRES_REVIEW"
        device_negative_claim = "NOT_PROMOTED"
    declared_pins = {kind: dict(pin) for kind, pin in sorted(pins_normalized.items())}
    result = {
        "schema": ANALYSIS_SCHEMA,
        "mode": "RAW_TRANSCRIPT_ANALYSIS",
        "status": status,
        "device_negative_claim": device_negative_claim,
        "run": run,
        "self_test": synthetic_self_test,
        "acquisition": acquisition,
        "inputs": input_metadata,
        "declared_pins": declared_pins,
        "public_private_separation": {
            "input_paths_emitted": "BASENAME_SIZE_SHA256_ONLY",
            "raw_transcript_bytes_in_output": False,
        },
        "limits": {
            "physical_pa_mapping": "UNKNOWN_PAGEMAP_BLIND",
            "physical_contiguity": "UNKNOWN_PAGEMAP_BLIND",
            "type_nonzero_is_not_contiguity_proof": True,
            "no_alias_scope": "EXACT_TESTED_OFFSET_PAIRS_IN_ONE_STATE_ONLY",
            "other_physical_bits_heap_dram": "NOT_TESTED",
            "cross_state_skitter_permutation": "NOT_TESTED",
        },
        "publication": {
            "v015_helper": {
                "basename": V015_HELPER_PATH.name,
                "size_bytes": V015_HELPER_SIZE,
                "sha256": V015_HELPER_SHA256,
            },
            "method": "PINNED_V015_ATOMIC_NO_CLOBBER_PUBLIC_SAFE",
        },
    }
    _assert_public_safety(result)
    return result


def build_host_selftest() -> dict:
    """Build a public-safe result for the no-raw host-selftest mode."""

    result = {
        "schema": ANALYSIS_SCHEMA,
        "mode": "HOST_SELFTEST_ONLY",
        "status": "HOST_TOOL_READY_DEVICE_ACQUISITION_PENDING",
        "device_negative_claim": "NONE",
        "negative_is_admissible": False,
        "self_test": self_test(),
        "scope": {
            "synthetic_only": True,
            "device_transcript": "ABSENT",
            "physical_pa_mapping": "UNKNOWN",
            "cross_state_skitter_permutation": "NOT_TESTED_BY_SINGLE_STATE_MARKER_SWEEP",
        },
        "publication": {
            "v015_helper": {
                "basename": V015_HELPER_PATH.name,
                "size_bytes": V015_HELPER_SIZE,
                "sha256": V015_HELPER_SHA256,
            },
            "method": "PINNED_V015_ATOMIC_NO_CLOBBER_PUBLIC_SAFE",
        },
    }
    _assert_public_safety(result)
    return result


def _check_v015_pin() -> None:
    try:
        data = v015._read_stable_bytes(V015_HELPER_PATH, "V015 helper")
    except v015.InvarianceError as exc:
        raise MarkerError(str(exc)) from exc
    if len(data) != V015_HELPER_SIZE or hashlib.sha256(data).hexdigest() != V015_HELPER_SHA256:
        raise MarkerError("pinned V015 helper changed")


def _assert_public_safety(value: object) -> None:
    try:
        v015._assert_public_safety(value)
    except v015.InvarianceError as exc:
        raise MarkerError(str(exc)) from exc
    if isinstance(value, Mapping):
        for key, item in value.items():
            _assert_public_safety(key)
            _assert_public_safety(item)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for item in value:
            _assert_public_safety(item)


def encode_output(result: Mapping[str, object]) -> bytes:
    _assert_public_safety(result)
    return v015.encode_manifest(result)


def write_public_output(path: Path, result: Mapping[str, object]) -> dict:
    """Publish through the pinned V015 helper; existing outputs are never replaced."""

    _check_v015_pin()
    _assert_public_safety(result)
    try:
        return v015.write_manifest(Path(path), result)
    except v015.InvarianceError as exc:
        raise MarkerError(str(exc)) from exc


def _parse_cli_pin(spec: str) -> tuple[str, dict]:
    if "=" not in spec or ":" not in spec:
        raise MarkerError("--pin format is KIND=SIZE:SHA256")
    kind, rest = spec.split("=", 1)
    size_text, digest = rest.split(":", 1)
    try:
        size = int(size_text, 10)
    except ValueError as exc:
        raise MarkerError("--pin size is not decimal") from exc
    return _normalise_kind(kind), validate_pin({"size_bytes": size, "sha256": digest}, kind)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--raw", type=Path, help="exact probe JSONL; omit only for host self-test")
    parser.add_argument("--probe-source", type=Path)
    parser.add_argument("--probe-binary", type=Path)
    parser.add_argument("--build-receipt", type=Path)
    parser.add_argument("--acquisition-receipt", type=Path)
    parser.add_argument("--pin", action="append", default=[], metavar="KIND=SIZE:SHA256")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        pins: dict[str, dict] = {}
        for spec in args.pin:
            kind, pin = _parse_cli_pin(spec)
            if kind in pins:
                raise MarkerError(f"duplicate --pin kind {kind!r}")
            pins[kind] = pin
        artifacts = {
            kind: path for kind, path in (
                ("probe_source", args.probe_source),
                ("probe_binary", args.probe_binary),
                ("build_receipt", args.build_receipt),
                ("acquisition_receipt", args.acquisition_receipt),
            ) if path is not None
        }
        if args.raw is None and artifacts:
            raise MarkerError("future artifacts require --raw")
        result = build_host_selftest() if args.raw is None else analyse_raw(
            args.raw, pins=pins, artifacts=artifacts
        )
        publication = write_public_output(args.output, result)
        print(json.dumps({
            "mode": result["mode"],
            "status": result["status"],
            "output": {
                "size_bytes": publication["size_bytes"],
                "mode": publication["observed_mode"],
            },
        }, sort_keys=True))
        return 0
    except (MarkerError, OSError) as exc:
        print(f"verification-018: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
