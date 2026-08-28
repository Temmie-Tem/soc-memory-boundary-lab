#!/usr/bin/env python3
"""Reduce a bounded 020N normal-RAM PA28 timing receipt.

The reducer is host-only.  It never contacts a device, opens an ACM socket,
allocates ION memory, reads pagemap, or interprets a timing candidate as an
alias.  It accepts only the fixed receipt shape emitted by
``a90_pa28_timing_probe.c`` and first revalidates the independent 020M DT and
021 extent preconditions.  A separated timing class is retained as a
candidate for a separately authorized live review; physical address identity,
complete DRAM coordinates, and ``f(PA28)`` remain outside this reducer's claim
boundary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Mapping, Sequence


REPO_ROOT = Path(__file__).resolve().parents[1]
PROBE_SOURCE_PATH = REPO_ROOT / "tools" / "a90_pa28_timing_probe.c"
DEFAULT_PRECONDITION = (
    REPO_ROOT
    / "evidence/manifests/verification-020m-pa28-dt-20260827-03.manifest.json"
)
DEFAULT_EXTENT = (
    REPO_ROOT
    / "evidence/manifests/verification-021-carveout-exhaustion-20260827-01.manifest.json"
)

SCHEMA = "a90_pa28_timing_analysis_v1"
PROBE_SCHEMA = "a90_pa28_timing_probe_v1"
PRECONDITION_SCHEMA = "a90-pa28-dt-snapshot-v1"
EXTENT_SCHEMA = "a90_carveout_exhaustion_v2"
EXPERIMENT_ID = "verification-020n-pa28-timing"

EXPECTED_HEAP_NAME = "camera_preview"
EXPECTED_HEAP_TYPE = 10
EXPECTED_HEAP_ID = 30
EXPECTED_ALLOCATION_MIB = 320
EXPECTED_ALLOCATION_BYTES = EXPECTED_ALLOCATION_MIB * 1024 * 1024
EXPECTED_PA28_DIFFERENCE = 0x10000000
EXPECTED_NEGATIVE_DIFFERENCES = (0x10002000, 0x10004000)
EXPECTED_CPU = 7
EXPECTED_REPETITIONS = 1001
EXPECTED_WARMUPS = 17
EXPECTED_PAIRS = 8
EXPECTED_CACHE_SAMPLES = 129
MIN_CANDIDATE_P10 = 1
MIN_SEPARATION_MILLI_TICKS = 100
MAX_SAME_OFFSET_ABS_MEDIAN = 100
MAX_INPUT_BYTES = 8 * 1024 * 1024

# These are the exact checked-in 020M and independent 021 public pins present
# in the workspace.  A changed file is an input-integrity failure, not a new
# baseline.  The probe source pin is filled after this new source is finalized.
EXPECTED_020M_MANIFEST = {
    "basename": "verification-020m-pa28-dt-20260827-03.manifest.json",
    "size": 8246,
    "sha256": "69b087bd5a6aa279fff9c943405b46491381f3461c5ea1ac57f4d2f287d8ad9a",
}
EXPECTED_020M_RAW_RECEIPT = {
    "size": 15435,
    "sha256": "40a3207d3f822775c4506415a579e993c07a6a7f9ff998e41a6f76cb6216a2ec",
}
EXPECTED_021_MANIFEST = {
    "basename": "verification-021-carveout-exhaustion-20260827-01.manifest.json",
    "size": 4586,
    "sha256": "82471b458f87e1ed86596ab08c97bab743ee868edf98d7d272c1d131046c168b",
}
EXPECTED_PROBE_SOURCE_SIZE = 18809
EXPECTED_PROBE_SOURCE_SHA256 = "281528d45040bc3174aefc5dba957d74d3a04203c65af4413dc34e695708f167"

SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,95}\Z")
HEX_RE = re.compile(r"0x[0-9a-f]+\Z")


class AnalysisError(ValueError):
    """Raised for any malformed, drifted, or unsafe 020N input."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _reject_symlink_components(path: Path) -> None:
    """Reject a symlink in any existing lexical path component."""

    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor or "/")
    for component in absolute.parts[1:]:
        current /= component
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise AnalysisError(f"cannot inspect path component: {current}") from exc
        if stat.S_ISLNK(info.st_mode):
            raise AnalysisError(f"symlink path component is forbidden: {current}")


def read_stable(path: Path, label: str = "input") -> tuple[bytes, dict[str, object]]:
    """Read one bounded regular file through a stable no-follow descriptor."""

    path = Path(path)
    _reject_symlink_components(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise AnalysisError(f"{label} cannot be opened without following links") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise AnalysisError(f"{label} is not a regular file")
        if before.st_size < 0 or before.st_size > MAX_INPUT_BYTES:
            raise AnalysisError(f"{label} exceeds the bounded input size")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(fd, min(1 << 20, remaining))
            if not chunk:
                raise AnalysisError(f"{label} was truncated while being read")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    before_key = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
        before.st_nlink,
    )
    after_key = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
        after.st_nlink,
    )
    if before_key != after_key:
        raise AnalysisError(f"{label} changed while being read")
    data = b"".join(chunks)
    if len(data) != before.st_size:
        raise AnalysisError(f"{label} size changed while being read")
    return data, {
        "basename": path.name,
        "size": len(data),
        "sha256": sha256(data),
    }


def _json_object(data: bytes, label: str) -> dict[str, object]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AnalysisError(f"{label} is not UTF-8") from exc

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                raise AnalysisError(f"{label} repeats key {key!r}")
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise AnalysisError(f"{label} contains non-finite JSON number {value}")

    try:
        value = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_constant=reject_constant,
        )
    except AnalysisError:
        raise
    except json.JSONDecodeError as exc:
        raise AnalysisError(f"{label} is malformed JSON: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise AnalysisError(f"{label} is not a JSON object")
    return value


def _require_keys(record: Mapping[str, object], keys: set[str], label: str) -> None:
    if set(record) != keys:
        raise AnalysisError(
            f"{label} fields differ: expected {sorted(keys)}, got {sorted(record)}"
        )


def _int(value: object, label: str, *, minimum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AnalysisError(f"{label} is not an integer")
    if minimum is not None and value < minimum:
        raise AnalysisError(f"{label} is below {minimum}")
    return value


def _bool(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise AnalysisError(f"{label} is not boolean")
    return value


def _hex(value: object, label: str) -> int:
    if not isinstance(value, str) or HEX_RE.fullmatch(value) is None:
        raise AnalysisError(f"{label} is not a lowercase hexadecimal value")
    return int(value, 16)


def _range_stats(record: Mapping[str, object], label: str) -> dict[str, int]:
    p10 = _int(record.get("p10"), f"{label}.p10")
    median = _int(record.get("median"), f"{label}.median")
    p90 = _int(record.get("p90"), f"{label}.p90")
    if not p10 <= median <= p90:
        raise AnalysisError(f"{label} percentile order is invalid")
    return {"p10": p10, "median": median, "p90": p90}


def _parse_probe_records(data: bytes) -> dict[str, object]:
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise AnalysisError("probe receipt is not UTF-8") from exc
    if not lines:
        raise AnalysisError("probe receipt is empty")

    records: list[dict[str, object]] = []
    for index, line in enumerate(lines, 1):
        if not line.strip():
            raise AnalysisError(f"probe receipt has blank line {index}")
        record = _json_object(line.encode("utf-8"), f"probe line {index}")
        if record.get("schema") != PROBE_SCHEMA:
            raise AnalysisError(f"probe line {index} has a foreign schema")
        records.append(record)

    by_type: dict[str, list[dict[str, object]]] = {}
    for record in records:
        kind = record.get("type")
        if not isinstance(kind, str):
            raise AnalysisError("probe record lacks a type")
        by_type.setdefault(kind, []).append(record)

    if set(by_type) != {"context", "ion_heap", "allocation", "control", "measurement", "summary"}:
        raise AnalysisError("probe record type surface differs")
    for kind in ("context", "ion_heap", "allocation", "summary"):
        if len(by_type[kind]) != 1:
            raise AnalysisError(f"probe requires exactly one {kind} record")

    context = by_type["context"][0]
    _require_keys(
        context,
        {
            "schema", "type", "heap_name", "heap_id", "heap_type",
            "allocation_mib", "allocation_bytes", "pa28_difference",
            "negative_differences", "cpu", "repetitions_per_pair",
            "warmups_per_pair", "mapping", "barrier", "order", "pagemap",
            "physical_address_provenance", "device_writes", "mmio", "smc",
            "protected_memory",
        },
        "context",
    )
    if (
        context["heap_name"] != EXPECTED_HEAP_NAME
        or _int(context["heap_id"], "context.heap_id") != EXPECTED_HEAP_ID
        or _int(context["heap_type"], "context.heap_type") != EXPECTED_HEAP_TYPE
        or _int(context["allocation_mib"], "context.allocation_mib") != EXPECTED_ALLOCATION_MIB
        or _int(context["allocation_bytes"], "context.allocation_bytes") != EXPECTED_ALLOCATION_BYTES
        or _hex(context["pa28_difference"], "context.pa28_difference") != EXPECTED_PA28_DIFFERENCE
        or _int(context["cpu"], "context.cpu") != EXPECTED_CPU
        or _int(context["repetitions_per_pair"], "context.repetitions_per_pair") != EXPECTED_REPETITIONS
        or _int(context["warmups_per_pair"], "context.warmups_per_pair") != EXPECTED_WARMUPS
        or context["mapping"] != "ion_uncached_writecombine"
        or context["barrier"] != "dsb_ld"
        or context["order"] != "alternating"
        or context["pagemap"] != "NOT_USED"
        or context["physical_address_provenance"] != "NOT_COLLECTED"
        or _bool(context["device_writes"], "context.device_writes")
        or _bool(context["mmio"], "context.mmio")
        or _bool(context["smc"], "context.smc")
        or _bool(context["protected_memory"], "context.protected_memory")
    ):
        raise AnalysisError("probe context does not match the fixed safety/parameter contract")
    negative_values = context["negative_differences"]
    if not isinstance(negative_values, list) or [
        _hex(value, "context.negative_differences") for value in negative_values
    ] != list(EXPECTED_NEGATIVE_DIFFERENCES):
        raise AnalysisError("probe negative-difference set changed")

    heap = by_type["ion_heap"][0]
    _require_keys(heap, {"schema", "type", "name", "heap_type", "heap_id"}, "ion_heap")
    if (
        heap["name"] != EXPECTED_HEAP_NAME
        or _int(heap["heap_type"], "ion_heap.heap_type") != EXPECTED_HEAP_TYPE
        or _int(heap["heap_id"], "ion_heap.heap_id") != EXPECTED_HEAP_ID
    ):
        raise AnalysisError("probe heap identity changed")

    allocation = by_type["allocation"][0]
    _require_keys(
        allocation,
        {"schema", "type", "heap_id", "heap_type", "heap_name", "flags",
         "requested_mib", "mapped_bytes", "status"},
        "allocation",
    )
    if (
        _int(allocation["heap_id"], "allocation.heap_id") != EXPECTED_HEAP_ID
        or _int(allocation["heap_type"], "allocation.heap_type") != EXPECTED_HEAP_TYPE
        or allocation["heap_name"] != EXPECTED_HEAP_NAME
        or _int(allocation["flags"], "allocation.flags") != 0
        or _int(allocation["requested_mib"], "allocation.requested_mib") != EXPECTED_ALLOCATION_MIB
        or _int(allocation["mapped_bytes"], "allocation.mapped_bytes") != EXPECTED_ALLOCATION_BYTES
        or allocation["status"] != "OK"
    ):
        raise AnalysisError("full-size allocation record does not match the contract")

    measurements: dict[str, dict[str, object]] = {}
    measurement_names = {"same_offset", "pa28_candidate", "negative_bank_bit13", "negative_bank_bit14"}
    for record in by_type["measurement"]:
        _require_keys(
            record,
            {
                "schema", "type", "name", "difference", "pairs",
                "repetitions_per_pair", "warmups_per_pair", "trim_percent",
                "p10", "median", "p90", "status",
            },
            "measurement",
        )
        name = record["name"]
        if not isinstance(name, str) or name not in measurement_names or name in measurements:
            raise AnalysisError("measurement name is missing, duplicated, or unsupported")
        expected_difference = {
            "same_offset": 0,
            "pa28_candidate": EXPECTED_PA28_DIFFERENCE,
            "negative_bank_bit13": EXPECTED_NEGATIVE_DIFFERENCES[0],
            "negative_bank_bit14": EXPECTED_NEGATIVE_DIFFERENCES[1],
        }[name]
        if (
            _hex(record["difference"], f"measurement[{name}].difference") != expected_difference
            or _int(record["pairs"], f"measurement[{name}].pairs") != EXPECTED_PAIRS
            or _int(record["repetitions_per_pair"], f"measurement[{name}].repetitions_per_pair") != EXPECTED_REPETITIONS
            or _int(record["warmups_per_pair"], f"measurement[{name}].warmups_per_pair") != EXPECTED_WARMUPS
            or _int(record["trim_percent"], f"measurement[{name}].trim_percent") != 10
            or record["status"] != "OK"
        ):
            raise AnalysisError(f"measurement {name} parameter/status drifted")
        measurements[name] = {**record, "stats": _range_stats(record, f"measurement[{name}]")}
    if set(measurements) != measurement_names:
        raise AnalysisError("probe measurement set is incomplete")

    controls: dict[str, dict[str, object]] = {}
    for record in by_type["control"]:
        name = record.get("name")
        if name == "cache_maintenance":
            _require_keys(
                record,
                {
                    "schema", "type", "name", "mapping", "cache_maintenance",
                    "samples", "min", "median", "p90", "status",
                },
                "cache control",
            )
            if (
                record["mapping"] != "anonymous_cached"
                or record["cache_maintenance"] != "dc_civac"
                or _int(record["samples"], "cache.samples") != EXPECTED_CACHE_SAMPLES
                or record["status"] != "OK"
            ):
                raise AnalysisError("cache control identity/status changed")
            minimum = _int(record["min"], "cache.min", minimum=0)
            median = _int(record["median"], "cache.median", minimum=0)
            p90 = _int(record["p90"], "cache.p90", minimum=0)
            if not minimum <= median <= p90:
                raise AnalysisError("cache control percentile order is invalid")
            controls[name] = {**record, "stats": {"min": minimum, "median": median, "p90": p90}}
        else:
            raise AnalysisError(f"unsupported control name: {name!r}")
    if set(controls) != {"cache_maintenance"}:
        raise AnalysisError("cache control set is incomplete or duplicated")

    summary = by_type["summary"][0]
    _require_keys(
        summary,
        {
            "schema", "type", "candidate", "same_offset", "negative_controls",
            "cache_control", "pagemap", "physical_address_claim",
            "interpretation", "status", "load_sink",
        },
        "summary",
    )
    if (
        summary["candidate"] != "pa28_candidate"
        or summary["same_offset"] != "same_offset"
        or summary["negative_controls"] != ["negative_bank_bit13", "negative_bank_bit14"]
        or summary["cache_control"] != "cache_maintenance"
        or summary["pagemap"] != "NOT_USED"
        or summary["physical_address_claim"] != "NONE"
        or summary["interpretation"] != "HOST_ANALYZER_REQUIRED"
        or summary["status"] != "OK"
    ):
        raise AnalysisError("probe summary does not bind the fixed control surface")
    _int(summary["load_sink"], "summary.load_sink")

    return {
        "context": context,
        "heap": heap,
        "allocation": allocation,
        "measurements": measurements,
        "controls": controls,
        "summary": summary,
    }


def _validate_020m(document: Mapping[str, object]) -> dict[str, object]:
    if document.get("schema") != PRECONDITION_SCHEMA:
        raise AnalysisError("020M dependency schema changed")
    target = document.get("target")
    if not isinstance(target, Mapping) or (
        target.get("model") != "SM-A908N"
        or target.get("soc") != "SM8150"
        or target.get("version") != "A90 Linux init 0.9.285"
        or target.get("build") != "build=v2321-usb-clean-identity-rodata"
        or target.get("kernel") != "Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64"
    ):
        raise AnalysisError("020M exact target identity drifted")
    raw = document.get("raw_receipt")
    if not isinstance(raw, Mapping) or raw.get("size") != EXPECTED_020M_RAW_RECEIPT["size"] or raw.get("sha256") != EXPECTED_020M_RAW_RECEIPT["sha256"]:
        raise AnalysisError("020M raw receipt pin drifted")
    semantic = document.get("semantic")
    if not isinstance(semantic, Mapping):
        raise AnalysisError("020M semantic section is missing")
    heap = semantic.get("ion_heap30")
    region = semantic.get("camera_mem_region")
    if not isinstance(heap, Mapping) or not isinstance(region, Mapping):
        raise AnalysisError("020M heap/region semantic sections are missing")
    if (
        heap.get("reg") != "0x1e"
        or heap.get("memory_region_phandle") != "0x67a"
        or heap.get("name") != "qcom,ion-heap"
        or region.get("name") != "camera_mem_region"
        or region.get("phandle") != "0x67a"
    ):
        raise AnalysisError("020M heap-30/phandle semantic chain changed")
    reg = region.get("reg")
    if not isinstance(reg, Mapping) or (
        reg.get("base") != "0xc2000000"
        or reg.get("size") != "0x14000000"
        or reg.get("end_exclusive") != "0xd6000000"
    ):
        raise AnalysisError("020M camera_mem_region extent changed")
    recyclable = region.get("ion_recyclable")
    optional = region.get("optional_properties")
    if not isinstance(recyclable, Mapping) or recyclable.get("present") is not True:
        raise AnalysisError("020M ion,recyclable presence changed")
    if not isinstance(optional, Mapping):
        raise AnalysisError("020M optional-property observations are missing")
    for key in ("camera_no_map", "camera_reusable"):
        value = optional.get(key)
        if not isinstance(value, Mapping) or value.get("present") is not False or value.get("errno") != 2 or value.get("status") != "error":
            raise AnalysisError(f"020M {key} absence observation changed")
    return {
        "target": dict(target),
        "heap_reg": heap["reg"],
        "memory_region_phandle": heap["memory_region_phandle"],
        "camera_reg": dict(reg),
    }


def _validate_021(document: Mapping[str, object]) -> dict[str, object]:
    if document.get("schema") != EXTENT_SCHEMA:
        raise AnalysisError("021 dependency schema changed")
    heap = document.get("heap")
    region = document.get("device_tree_region")
    if not isinstance(heap, Mapping) or not isinstance(region, Mapping):
        raise AnalysisError("021 heap/DT extent sections are missing")
    if (
        heap.get("name") != EXPECTED_HEAP_NAME
        or heap.get("heap_type") != EXPECTED_HEAP_TYPE
        or heap.get("heap_id") != EXPECTED_HEAP_ID
        or region.get("heap_name") != EXPECTED_HEAP_NAME
        or region.get("heap_id") != EXPECTED_HEAP_ID
        or region.get("memory_region_phandle") != "0x67a"
        or region.get("base") != "0xc2000000"
        or region.get("size") != "0x14000000"
    ):
        raise AnalysisError("021 heap/DT extent identity changed")
    if (
        document.get("hold_bytes") != EXPECTED_ALLOCATION_BYTES
        or document.get("hold_equals_declared_region_size") is not True
        or document.get("instrument_ok") is not True
        or document.get("pool_exhausted") is not True
        or document.get("controls_fired") is not True
        or document.get("control_before_ok") != 5
        or document.get("under_hold_ok") != 0
        or document.get("control_after_ok") != 5
        or document.get("verdict") != "HOLD_CONSUMES_POOL"
    ):
        raise AnalysisError("021 full-size allocation/extent gate did not pass")
    if document.get("implied_physical_span") != ["0xc2000000", "0xd6000000"]:
        raise AnalysisError("021 implied extent changed")
    return {
        "heap": dict(heap),
        "region": dict(region),
        "hold_bytes": document["hold_bytes"],
        "verdict": document["verdict"],
    }


def reduce_measurements(parsed: Mapping[str, object]) -> dict[str, object]:
    measurements = parsed["measurements"]
    assert isinstance(measurements, Mapping)
    same = measurements["same_offset"]["stats"]
    candidate = measurements["pa28_candidate"]["stats"]
    negative13 = measurements["negative_bank_bit13"]["stats"]
    negative14 = measurements["negative_bank_bit14"]["stats"]
    assert isinstance(same, Mapping)
    assert isinstance(candidate, Mapping)
    assert isinstance(negative13, Mapping)
    assert isinstance(negative14, Mapping)
    same_centered = (
        abs(int(same["median"])) <= MAX_SAME_OFFSET_ABS_MEDIAN
        and int(same["p10"]) <= 0 <= int(same["p90"])
    )
    negative_max_p90 = max(int(negative13["p90"]), int(negative14["p90"]))
    candidate_min_p10 = int(candidate["p10"])
    gap = candidate_min_p10 - negative_max_p90
    candidate_separated = (
        candidate_min_p10 >= MIN_CANDIDATE_P10
        and gap >= MIN_SEPARATION_MILLI_TICKS
    )
    controls_pass = same_centered and candidate_separated
    return {
        "same_offset": {
            "stats": dict(same),
            "centered": same_centered,
            "max_abs_median": MAX_SAME_OFFSET_ABS_MEDIAN,
        },
        "negative_controls": {
            "negative_bank_bit13": dict(negative13),
            "negative_bank_bit14": dict(negative14),
            "max_p90": negative_max_p90,
        },
        "pa28_candidate": {
            "stats": dict(candidate),
            "positive_p10": candidate_min_p10 >= MIN_CANDIDATE_P10,
            "separation_milli_ticks": gap,
            "minimum_separation_milli_ticks": MIN_SEPARATION_MILLI_TICKS,
            "separated_from_negatives": candidate_separated,
        },
        "controls_pass": controls_pass,
        "candidate_verdict": (
            "PA28_TIMING_CANDIDATE" if controls_pass else "PA28_UNRESOLVED"
        ),
    }


def _source_pin(path: Path) -> dict[str, object]:
    data, pin = read_stable(path, "probe source")
    if EXPECTED_PROBE_SOURCE_SIZE <= 0 or not EXPECTED_PROBE_SOURCE_SHA256:
        raise AnalysisError("probe source pin is not finalized")
    if pin["size"] != EXPECTED_PROBE_SOURCE_SIZE or pin["sha256"] != EXPECTED_PROBE_SOURCE_SHA256:
        raise AnalysisError("probe source size/SHA-256 drifted")
    del data
    return pin


def analyze(
    raw_path: Path,
    precondition_path: Path = DEFAULT_PRECONDITION,
    extent_path: Path = DEFAULT_EXTENT,
    source_path: Path = PROBE_SOURCE_PATH,
) -> dict[str, object]:
    """Validate a raw probe receipt and return a redacted public reduction."""

    raw_data, raw_pin = read_stable(raw_path, "raw probe receipt")
    precondition_data, precondition_pin = read_stable(
        precondition_path, "020M manifest"
    )
    extent_data, extent_pin = read_stable(extent_path, "021 manifest")
    if precondition_pin != EXPECTED_020M_MANIFEST:
        raise AnalysisError("020M manifest size/SHA-256 drifted")
    if extent_pin != EXPECTED_021_MANIFEST:
        raise AnalysisError("021 manifest size/SHA-256 drifted")
    if Path(precondition_path).name != EXPECTED_020M_MANIFEST["basename"]:
        raise AnalysisError("020M manifest basename is not the pinned artifact")
    if Path(extent_path).name != EXPECTED_021_MANIFEST["basename"]:
        raise AnalysisError("021 manifest basename is not the pinned artifact")

    parsed = _parse_probe_records(raw_data)
    precondition = _validate_020m(_json_object(precondition_data, "020M manifest"))
    extent = _validate_021(_json_object(extent_data, "021 manifest"))
    source_pin = _source_pin(source_path)
    reduction = reduce_measurements(parsed)
    candidate = reduction["candidate_verdict"]

    return {
        "schema": SCHEMA,
        "experiment_id": EXPERIMENT_ID,
        "mode": "HOST_ONLY_REDUCTION",
        "device_access": "none_by_analyzer",
        "classification": "CLASS C (TRANSFORM ONLY)",
        "eligibility": "NOT_ELIGIBLE",
        "target": precondition["target"],
        "preconditions": {
            "verification_020m": {
                "manifest": precondition_pin,
                "raw_receipt": dict(EXPECTED_020M_RAW_RECEIPT),
                "dt_chain": {
                    "heap_id": EXPECTED_HEAP_ID,
                    "heap_name": EXPECTED_HEAP_NAME,
                    "memory_region_phandle": "0x67a",
                    "base": "0xc2000000",
                    "size": "0x14000000",
                },
            },
            "verification_021": {
                "manifest": extent_pin,
                "heap": extent["heap"],
                "region": extent["region"],
                "hold_bytes": EXPECTED_ALLOCATION_BYTES,
                "verdict": "HOLD_CONSUMES_POOL",
            },
        },
        "probe": {
            "source": source_pin,
            "raw_receipt": raw_pin,
            "fixed_heap": {
                "name": EXPECTED_HEAP_NAME,
                "type": EXPECTED_HEAP_TYPE,
                "id": EXPECTED_HEAP_ID,
            },
            "allocation_mib": EXPECTED_ALLOCATION_MIB,
            "allocation_bytes": EXPECTED_ALLOCATION_BYTES,
            "pa28_difference": "0x10000000",
            "negative_differences": ["0x10002000", "0x10004000"],
            "pagemap": "NOT_USED",
            "physical_address_provenance": "NOT_COLLECTED",
        },
        "reduction": reduction,
        "status": candidate,
        "claims": {
            "PROVED": [
                "The fixed probe receipt shape, heap identity, full allocation size, offset set and control surface pass strict host validation.",
                "The independent 020M DT chain and 021 full-size extent gates are hash-pinned and pass before timing reduction.",
            ],
            "SUPPORTED": (
                [
                    "The bounded timing summaries separate the PA28 candidate from the two fixed negative controls with the declared margin; this is a timing candidate only.",
                ]
                if candidate == "PA28_TIMING_CANDIDATE"
                else []
            ),
            "HYPOTHESIS": [],
            "REFUTED": [],
            "UNKNOWN": [
                "Physical page identity and allocation placement beyond the independently retained extent gate.",
                "Complete DRAM coordinates, the silicon value of f(PA28), and any physical-address alias.",
                "Transform mutability, protection ordering, controller ownership, and protected-memory reach.",
            ],
        },
        "safety": {
            "analyzer_contacts_device": False,
            "probe_pagemap": "NOT_USED",
            "mmio": False,
            "smc": False,
            "protected_memory": False,
            "controller_write": False,
            "firmware_write": False,
            "normal_ram_scope": "probe-owned-allocation-only",
        },
        "boundary_bypass": {
            "status": "NOT_AUTHORIZED",
            "reason": "Host-only reduction; a timing candidate never authorizes a follow-up write or alias claim.",
        },
        "recovery": {
            "status": "NOT_APPLICABLE",
            "reason": "No device state was touched by this host-only reducer.",
        },
    }


def write_new(path: Path, data: bytes, mode: int = 0o644) -> None:
    """Publish one artifact atomically enough for this bounded host output."""

    path = Path(path)
    _reject_symlink_components(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    _reject_symlink_components(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, mode)
    try:
        os.fchmod(fd, mode)
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise AnalysisError(f"short write while publishing {path}")
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError as exc:
        raise AnalysisError(f"published parent cannot be fsynced: {path.parent}") from exc
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", type=Path, required=True)
    parser.add_argument("--precondition", type=Path, default=DEFAULT_PRECONDITION)
    parser.add_argument("--extent", type=Path, default=DEFAULT_EXTENT)
    parser.add_argument("--source", type=Path, default=PROBE_SOURCE_PATH)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    manifest = analyze(args.raw, args.precondition, args.extent, args.source)
    write_new(args.output, (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
