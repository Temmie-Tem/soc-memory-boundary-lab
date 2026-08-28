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
import re
import statistics
import stat
from pathlib import Path
from typing import Mapping, Sequence

SCHEMA = "a90_pa28_probe_v1"
MANIFEST_SCHEMA = "a90_pa28_relation_v2"
PA28 = 1 << 28
EXPECTED_BASE = 0xC2000000
EXPECTED_ALLOCATION_MIB = 320
EXPECTED_ALLOCATION_BYTES = EXPECTED_ALLOCATION_MIB << 20
EXPECTED_HEAP = "camera_preview"
EXPECTED_HEAP_TYPE = 10
EXPECTED_HEAP_ID = 30
EXPECTED_CPU = 7
EXPECTED_CNTFRQ = 19_200_000
EXPECTED_REPETITIONS = 201
EXPECTED_PAIRS = 256
EXPECTED_WARMUPS = 17
EXPECTED_OFFSET_MODE = "spread"
EXPECTED_ORDER = "alternating"
EXPECTED_BARRIER = "dsb_ld"
EXPECTED_DIVISOR = "kept_times_two"
MAX_RAW_BYTES = 8 * 1024 * 1024

REPO_ROOT = Path(__file__).resolve().parents[1]
DEPENDENCY_020M_PATH = REPO_ROOT / (
    "evidence/manifests/verification-020m-pa28-dt-20260827-03.manifest.json"
)
DEPENDENCY_020M_PIN = {
    "basename": DEPENDENCY_020M_PATH.name,
    "size_bytes": 8246,
    "sha256": "69b087bd5a6aa279fff9c943405b46491381f3461c5ea1ac57f4d2f287d8ad9a",
}
DEPENDENCY_021_PATH = REPO_ROOT / (
    "evidence/manifests/verification-021-carveout-exhaustion-20260827-01.manifest.json"
)
DEPENDENCY_021_PIN = {
    "basename": DEPENDENCY_021_PATH.name,
    "size_bytes": 4586,
    "sha256": "82471b458f87e1ed86596ab08c97bab743ee868edf98d7d272c1d131046c168b",
}
PROBE_SOURCE_PATH = REPO_ROOT / "tools/a90_pa28_probe.c"
PROBE_SOURCE_PIN = {
    "basename": PROBE_SOURCE_PATH.name,
    "size_bytes": 25030,
    "sha256": "b324c1c3332c61b00f6d6e5c75891721be4a5fb2a998c7f0222900d4eba5e199",
    "status": "RETAINED_REPAIRED_SOURCE_NOT_EXECUTED",
}
PROBE_BINARY_PIN = {
    "basename": "a90_pa28_probe",
    "size_bytes": 776256,
    "sha256": "9959674add623891a80be57d1f139d6af1cc622359e4972a08b61133500afa51",
    "status": "NOT_RETAINED",
}
RAW_INPUT_PINS = {
    "pa28-existence.jsonl": {
        "basename": "pa28-existence.jsonl",
        "size_bytes": 194481,
        "sha256": "d0136222fe6b9d211c6f073fec6844b3817c92e25b6e5a00d15cb9b3787ec49b",
    },
    "pa28-identification.jsonl": {
        "basename": "pa28-identification.jsonl",
        "size_bytes": 283197,
        "sha256": "12cd383679524978b4beff7801816e5a4dc8fa9852972701c1395b50f205fa79",
    },
}
HEX_RE = re.compile(r"0x[0-9a-f]+\Z")


def _reject_symlink_parents(path: Path) -> None:
    """Reject symlinked parent components before using a pathname."""
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor or "/")
    for component in absolute.parts[1:-1]:
        current /= component
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise ValueError(f"cannot inspect path component {current}") from exc
        if stat.S_ISLNK(mode):
            raise ValueError(f"symlinked path component is forbidden: {current}")

# From the recovered relation: f(PA13), f(PA14), f(PA15) are a basis of GF(2)^3.
BASIS = {0x2000: 0b001, 0x4000: 0b010, 0x8000: 0b100}

# Same-phase controls, as V016 used them.  Neither may be inferred from an
# aggregate; each is asserted directly in the phase it was measured in.
CONTROL_CONFLICT = 0x16000
CONTROL_NEGATIVE = 0x2000


def _json_object(data: bytes, label: str) -> dict:
    """Decode one JSON object while rejecting duplicate/non-finite fields."""
    def pairs(items: list[tuple[str, object]]) -> dict:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                raise ValueError(f"{label} repeats key {key!r}")
            result[key] = value
        return result

    def reject(value: str) -> object:
        raise ValueError(f"{label} contains non-finite JSON number {value}")

    try:
        value = json.loads(
            data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=reject
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is malformed UTF-8/JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} is not an object")
    return value


def _read_stable(path: Path, label: str = "input") -> tuple[bytes, dict]:
    """Read a bounded regular file through an O_NOFOLLOW stable descriptor."""
    _reject_symlink_parents(path)
    fd = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0),
    )
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"{label} is not a regular file")
        if before.st_size <= 0 or before.st_size > MAX_RAW_BYTES:
            raise ValueError(f"{label} has invalid size {before.st_size}")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            block = os.read(fd, min(1 << 20, remaining))
            if not block:
                raise ValueError(f"{label} truncated while being read")
            chunks.append(block)
            remaining -= len(block)
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
        raise ValueError(f"{label} changed while being read")
    data = b"".join(chunks)
    if len(data) != before.st_size:
        raise ValueError(f"{label} size changed while being read")
    return data, {
        "basename": path.name,
        "bytes": len(data),
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _require_pin(actual: Mapping, expected: Mapping, label: str) -> None:
    expected_size = expected.get("size_bytes", expected.get("bytes"))
    actual_size = actual.get("size_bytes", actual.get("bytes"))
    if (
        actual.get("basename") != expected.get("basename")
        or actual_size != expected_size
        or actual.get("sha256") != expected.get("sha256")
    ):
        raise ValueError(f"{label} does not match its canonical pin")


def load(
    path: Path,
    *,
    phase: str | None = None,
    expected_pin: Mapping | None = None,
    canonical: bool = False,
) -> tuple[list[dict], dict]:
    data, metadata = _read_stable(path, f"receipt {path.name}")
    if expected_pin is not None:
        _require_pin(metadata, expected_pin, f"receipt {path.name}")
    elif canonical:
        expected = RAW_INPUT_PINS.get(path.name)
        if expected is None:
            raise ValueError(f"{path.name} is not a canonical 022 raw input")
        _require_pin(metadata, expected, f"receipt {path.name}")
    records: list[dict] = []
    for index, raw_line in enumerate(data.splitlines(), 1):
        if not raw_line.strip():
            raise ValueError(f"{path.name} has blank record line {index}")
        record = _json_object(raw_line, f"{path.name}:{index}")
        if record.get("schema") != SCHEMA:
            raise ValueError(f"foreign schema in {path.name}: {record.get('schema')!r}")
        if phase is not None:
            record = dict(record)
            record["_phase"] = phase
        records.append(record)
    if not records:
        raise ValueError(f"{path.name} holds no records")
    metadata["status"] = "RETAINED_PRIVATE_RECEIPT"
    if phase is not None:
        metadata["phase"] = phase
    return records, metadata


RECORD_FIELDS = {
    "context": {
        "schema", "type", "cpu", "cntfrq", "heap", "mib", "repetitions",
        "pairs", "warmups", "order", "barrier", "divisor", "offset_mode",
        "declared_base",
    },
    "ion_heap": {"schema", "type", "name", "heap_type", "heap_id"},
    "pa_provenance": {
        "schema", "type", "source", "pages", "present", "nonzero_pfn",
        "first_pfn", "last_pfn", "contiguous", "status",
    },
    "pair": {
        "schema", "type", "value", "offset", "pa_a", "pa_b", "pa_xor",
        "delta",
    },
    "difference": {
        "schema", "type", "value", "pairs", "rejected_range",
        "rejected_carry", "p10", "median", "p90",
    },
    "abort": {"schema", "type", "reason"},
}
EXPECTED_PHASES = {
    "existence": {CONTROL_CONFLICT, CONTROL_NEGATIVE, PA28},
    "identification": {
        CONTROL_CONFLICT,
        CONTROL_NEGATIVE,
        PA28 ^ 0x2000,
        PA28 ^ 0x4000,
        PA28 ^ 0x6000,
        PA28 ^ 0x8000,
        PA28 ^ 0xA000,
        PA28 ^ 0xC000,
        PA28 ^ 0xE000,
    },
}
EXPECTED_PHASE_COUNTS = {
    "existence": {CONTROL_CONFLICT: 2, CONTROL_NEGATIVE: 2, PA28: 2},
    "identification": {
        CONTROL_CONFLICT: 2,
        CONTROL_NEGATIVE: 2,
        PA28 ^ 0x2000: 1,
        PA28 ^ 0x4000: 1,
        PA28 ^ 0x6000: 1,
        PA28 ^ 0x8000: 1,
        PA28 ^ 0xA000: 1,
        PA28 ^ 0xC000: 1,
        PA28 ^ 0xE000: 1,
    },
}


def _hex(value: object, label: str) -> int:
    if not isinstance(value, str) or HEX_RE.fullmatch(value) is None:
        raise ValueError(f"{label} is not lowercase hexadecimal")
    parsed = int(value, 16)
    if value != hex(parsed):
        raise ValueError(f"{label} is not canonically formatted")
    return parsed


def _integer(value: object, label: str, minimum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{label} is not an integer")
    if minimum is not None and value < minimum:
        raise ValueError(f"{label} is below {minimum}")
    return value


def _strict_record_shape(record: Mapping, label: str) -> None:
    kind = record.get("type")
    if not isinstance(kind, str) or kind not in RECORD_FIELDS:
        raise ValueError(f"{label} has unsupported record type")
    keys = set(record) - {"_phase"}
    if keys != RECORD_FIELDS[kind]:
        raise ValueError(f"{label} fields differ for {kind}")
    if record.get("schema") != SCHEMA:
        raise ValueError(f"{label} has a foreign schema")


def validate_phase_records(records: Sequence[Mapping], phase: str) -> dict:
    """Validate one canonical 022 phase and return bounded phase metadata."""
    if phase not in EXPECTED_PHASES:
        raise ValueError(f"unknown 022 phase: {phase}")
    if not records:
        raise ValueError(f"{phase} phase is empty")
    for index, record in enumerate(records, 1):
        _strict_record_shape(record, f"{phase} record {index}")
        if record.get("_phase", phase) != phase:
            raise ValueError(f"record has the wrong phase: {phase}")
    contexts = [r for r in records if r["type"] == "context"]
    heaps = [r for r in records if r["type"] == "ion_heap"]
    provenance = [r for r in records if r["type"] == "pa_provenance"]
    differences = [r for r in records if r["type"] == "difference"]
    if len(contexts) != 1 or len(heaps) != 1 or len(provenance) != 1:
        raise ValueError(f"{phase} requires one context, heap, and pagemap status")
    context = contexts[0]
    if (
        context["heap"] != EXPECTED_HEAP
        or _integer(context["mib"], f"{phase}.mib") != EXPECTED_ALLOCATION_MIB
        or _integer(context["cpu"], f"{phase}.cpu") != EXPECTED_CPU
        or _integer(context["cntfrq"], f"{phase}.cntfrq") != EXPECTED_CNTFRQ
        or _integer(context["repetitions"], f"{phase}.repetitions") != EXPECTED_REPETITIONS
        or _integer(context["pairs"], f"{phase}.pairs") != EXPECTED_PAIRS
        or _integer(context["warmups"], f"{phase}.warmups") != EXPECTED_WARMUPS
        or context["order"] != EXPECTED_ORDER
        or context["barrier"] != EXPECTED_BARRIER
        or context["divisor"] != EXPECTED_DIVISOR
        or context["offset_mode"] != EXPECTED_OFFSET_MODE
        or _hex(context["declared_base"], f"{phase}.declared_base") != EXPECTED_BASE
    ):
        raise ValueError(f"{phase} context target/measurement fields drifted")
    heap = heaps[0]
    if (
        heap["name"] != EXPECTED_HEAP
        or _integer(heap["heap_type"], f"{phase}.heap_type") != EXPECTED_HEAP_TYPE
        or _integer(heap["heap_id"], f"{phase}.heap_id") != EXPECTED_HEAP_ID
    ):
        raise ValueError(f"{phase} heap identity drifted")
    pagemap = provenance[0]
    if (
        pagemap["source"] != "pagemap"
        or pagemap["status"] != "BLIND"
        or _integer(pagemap["pages"], f"{phase}.pagemap.pages") != EXPECTED_ALLOCATION_BYTES // 4096
        or _integer(pagemap["present"], f"{phase}.pagemap.present") != 0
        or _integer(pagemap["nonzero_pfn"], f"{phase}.pagemap.nonzero_pfn") != 0
        or pagemap["first_pfn"] != "0x0"
        or pagemap["last_pfn"] != "0x0"
        or pagemap["contiguous"] is not True
    ):
        raise ValueError(f"{phase} pagemap provenance is not the retained blind result")
    if len(differences) != sum(EXPECTED_PHASE_COUNTS[phase].values()):
        raise ValueError(f"{phase} difference cardinality changed")
    values: list[int] = []
    difference_counts: dict[int, int] = {}
    pair_count_by_difference: dict[int, int] = {}
    for difference in differences:
        value = _hex(difference["value"], f"{phase}.difference.value")
        if value not in EXPECTED_PHASES[phase]:
            raise ValueError(f"{phase} difference identity/cardinality changed")
        difference_counts[value] = difference_counts.get(value, 0) + 1
        if difference_counts[value] > EXPECTED_PHASE_COUNTS[phase][value]:
            raise ValueError(f"{phase} difference identity/cardinality changed")
        pairs = _integer(difference["pairs"], f"{phase}.{value:x}.pairs", minimum=1)
        rejected_range = _integer(difference["rejected_range"], f"{phase}.{value:x}.rejected_range", minimum=0)
        rejected_carry = _integer(difference["rejected_carry"], f"{phase}.{value:x}.rejected_carry", minimum=0)
        p10 = _integer(difference["p10"], f"{phase}.{value:x}.p10")
        median = _integer(difference["median"], f"{phase}.{value:x}.median")
        p90 = _integer(difference["p90"], f"{phase}.{value:x}.p90")
        if p10 > median or median > p90 or pairs > EXPECTED_PAIRS:
            raise ValueError(f"{phase}.{value:x} summary is malformed")
        if pairs + rejected_range + rejected_carry != EXPECTED_PAIRS:
            raise ValueError(f"{phase}.{value:x} rejected-pair accounting is invalid")
        pair_count_by_difference[value] = pairs
        values.append(value)
    if set(values) != EXPECTED_PHASES[phase]:
        raise ValueError(f"{phase} difference set changed")
    if difference_counts != EXPECTED_PHASE_COUNTS[phase]:
        raise ValueError(f"{phase} difference repeat/cardinality changed")

    # Pair rows must occur immediately before their summary and exactly match
    # its count.  Recompute all three arithmetic fields instead of trusting
    # the probe's pa_xor string (the old analyzer's tautological check).
    pending: dict[int, int] = {}
    for index, record in enumerate(records):
        if record["type"] == "pair":
            value = _hex(record["value"], f"{phase} pair value")
            offset = _hex(record["offset"], f"{phase} pair offset")
            pa_a = _hex(record["pa_a"], f"{phase} pair pa_a")
            pa_b = _hex(record["pa_b"], f"{phase} pair pa_b")
            pa_xor = _hex(record["pa_xor"], f"{phase} pair pa_xor")
            _integer(record["delta"], f"{phase} pair delta")
            if value not in EXPECTED_PHASES[phase] or offset % 4096:
                raise ValueError(f"{phase} pair offset/difference is invalid")
            if offset + 4096 > EXPECTED_ALLOCATION_BYTES:
                raise ValueError(f"{phase} pair a offset is outside allocation")
            if pa_a != EXPECTED_BASE + offset:
                raise ValueError(f"{phase} pair pa_a does not match base+offset")
            other_offset = offset ^ value
            if other_offset < 0 or other_offset + 4096 > EXPECTED_ALLOCATION_BYTES:
                raise ValueError(f"{phase} pair b offset is outside allocation")
            if pa_b != EXPECTED_BASE + other_offset:
                raise ValueError(f"{phase} pair pa_b does not match base+b offset")
            if (pa_a ^ pa_b) != value or pa_xor != (pa_a ^ pa_b):
                raise ValueError(f"{phase} pair physical-XOR arithmetic is inconsistent")
            pending[value] = pending.get(value, 0) + 1
        elif record["type"] == "difference":
            value = _hex(record["value"], f"{phase} summary value")
            if pending.get(value, 0) != pair_count_by_difference[value]:
                raise ValueError(f"{phase}.{value:x} pair count does not match summary")
            pending.pop(value)
        elif record["type"] not in {"context", "ion_heap", "pa_provenance"}:
            raise ValueError(f"{phase} has an unsupported ordering record at {index}")
    if pending:
        raise ValueError(f"{phase} has unclosed pair groups")
    return {
        "phase": phase,
        "context": dict(context),
        "heap": dict(heap),
        "pagemap": dict(pagemap),
        "differences": {value: next(r for r in differences if _hex(r["value"], "difference") == value) for value in values},
        "pair_counts": pair_count_by_difference,
    }


def verify_pairs(records: list[dict]) -> dict:
    """Every measured pair must have the physical XOR its difference names.

    This is what allows a non-power-of-two span: adding the base can carry, and
    a carried pair would be scored against a bit it does not isolate.  The probe
    rejects those before timing; this re-checks what it emitted.
    """
    checked = 0
    mismatched: list[str] = []
    for record in records:
        if record.get("type") != "pair":
            continue
        checked += 1
        try:
            value = _hex(record["value"], "pair value")
            offset = _hex(record["offset"], "pair offset")
            pa_a = _hex(record["pa_a"], "pair pa_a")
            pa_b = _hex(record["pa_b"], "pair pa_b")
            pa_xor = _hex(record["pa_xor"], "pair pa_xor")
        except (KeyError, ValueError) as exc:
            mismatched.append(f"malformed pair: {exc}")
            continue
        if (
            pa_xor != (pa_a ^ pa_b)
            or (pa_a ^ pa_b) != value
            or pa_a != EXPECTED_BASE + offset
            or pa_b != EXPECTED_BASE + (offset ^ value)
        ):
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


def _validate_020m_manifest(document: Mapping) -> dict:
    if document.get("schema") != "a90-pa28-dt-snapshot-v1":
        raise ValueError("020M dependency schema changed")
    if document.get("experiment_id") != "verification-020m-pa28-dt-20260827-03":
        raise ValueError("020M dependency experiment identity changed")
    target = document.get("target")
    if not isinstance(target, Mapping) or (
        target.get("model") != "SM-A908N"
        or target.get("soc") != "SM8150"
        or target.get("version") != "A90 Linux init 0.9.285"
        or target.get("build") != "build=v2321-usb-clean-identity-rodata"
        or target.get("kernel") != "Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64"
    ):
        raise ValueError("020M dependency target identity changed")
    bridge = document.get("bridge")
    if not isinstance(bridge, Mapping) or (
        bridge.get("serial_device") != "/dev/ttyACM0"
        or bridge.get("serial_realpath") != "/dev/ttyACM0"
        or bridge.get("strict_expect_realpath_option") is not True
        or bridge.get("strict_device_glob_option") is not True
    ):
        raise ValueError("020M dependency bridge binding changed")
    raw_receipt = document.get("raw_receipt")
    if not isinstance(raw_receipt, Mapping) or (
        raw_receipt.get("size") != 15435
        or raw_receipt.get("sha256") != "40a3207d3f822775c4506415a579e993c07a6a7f9ff998e41a6f76cb6216a2ec"
    ):
        raise ValueError("020M dependency raw receipt pin changed")
    semantic = document.get("semantic")
    if not isinstance(semantic, Mapping):
        raise ValueError("020M dependency semantic DT section is missing")
    heap = semantic.get("ion_heap30")
    region = semantic.get("camera_mem_region")
    if not isinstance(heap, Mapping) or not isinstance(region, Mapping):
        raise ValueError("020M dependency heap/region section is missing")
    if (
        heap.get("reg") != "0x1e"
        or heap.get("memory_region_phandle") != "0x67a"
        or heap.get("name") != "qcom,ion-heap"
        or region.get("name") != "camera_mem_region"
        or region.get("phandle") != "0x67a"
    ):
        raise ValueError("020M dependency heap/phandle chain changed")
    reg = region.get("reg")
    optional = region.get("optional_properties")
    if not isinstance(reg, Mapping) or (
        reg.get("base") != "0xc2000000"
        or reg.get("size") != "0x14000000"
        or reg.get("end_exclusive") != "0xd6000000"
    ):
        raise ValueError("020M dependency camera extent changed")
    if not isinstance(optional, Mapping):
        raise ValueError("020M dependency optional-property records are missing")
    for key in ("camera_no_map", "camera_reusable"):
        value = optional.get(key)
        if not isinstance(value, Mapping) or value.get("present") is not False or value.get("errno") != 2 or value.get("status") != "error":
            raise ValueError(f"020M dependency {key} absence changed")
    recyclable = region.get("ion_recyclable")
    if not isinstance(recyclable, Mapping) or recyclable.get("present") is not True:
        raise ValueError("020M dependency ion,recyclable presence changed")
    return {
        "experiment_id": document["experiment_id"],
        "schema": document["schema"],
        "target": {key: target[key] for key in ("model", "soc", "version")},
        "bridge": {
            key: bridge[key]
            for key in (
                "serial_device", "serial_realpath", "strict_expect_realpath_option",
                "strict_device_glob_option",
            )
        },
        "semantic": {
            "heap30_reg": heap["reg"],
            "heap30_memory_region_phandle": heap["memory_region_phandle"],
            "camera_phandle": region["phandle"],
            "camera_base": reg["base"],
            "camera_size": reg["size"],
            "camera_end_exclusive": reg["end_exclusive"],
        },
    }


def _validate_021_manifest(document: Mapping, dependency_020m_pin: Mapping) -> dict:
    if document.get("schema") != "a90_carveout_exhaustion_v2":
        raise ValueError("021 dependency schema changed")
    heap = document.get("heap")
    region = document.get("device_tree_region")
    if not isinstance(heap, Mapping) or not isinstance(region, Mapping) or (
        heap.get("name") != EXPECTED_HEAP
        or heap.get("heap_type") != EXPECTED_HEAP_TYPE
        or heap.get("heap_id") != EXPECTED_HEAP_ID
        or region.get("heap_name") != EXPECTED_HEAP
        or region.get("heap_id") != EXPECTED_HEAP_ID
        or region.get("memory_region_phandle") != "0x67a"
        or region.get("base") != "0xc2000000"
        or region.get("size") != "0x14000000"
    ):
        raise ValueError("021 dependency heap/DT identity changed")
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
        or document.get("implied_physical_span") != ["0xc2000000", "0xd6000000"]
    ):
        raise ValueError("021 dependency full-size extent gate changed")
    provenance = document.get("provenance")
    if not isinstance(provenance, Mapping):
        raise ValueError("021 dependency provenance section is missing")
    dependency = provenance.get("dependency_020m")
    if not isinstance(dependency, Mapping) or dependency.get("sha256") != dependency_020m_pin["sha256"] or dependency.get("size_bytes") != dependency_020m_pin["size_bytes"]:
        raise ValueError("021 dependency does not bind the canonical 020M manifest")
    target = provenance.get("target")
    bridge = provenance.get("bridge")
    commands = provenance.get("commands")
    if not isinstance(target, Mapping) or target.get("status") != "UNKNOWN_UNRETAINED" or target.get("same_run_attested") is not False:
        raise ValueError("021 same-run target provenance was unexpectedly promoted")
    if not isinstance(bridge, Mapping) or bridge.get("status") != "UNKNOWN_UNRETAINED" or bridge.get("same_run_attested") is not False:
        raise ValueError("021 same-run bridge provenance was unexpectedly promoted")
    if not isinstance(commands, Mapping) or commands.get("status") != "UNKNOWN_UNRETAINED" or commands.get("same_run_attested") is not False:
        raise ValueError("021 same-run command provenance was unexpectedly promoted")
    return {"heap": dict(heap), "region": dict(region), "hold_bytes": document["hold_bytes"]}


def load_dependency(path: Path, expected_pin: Mapping, label: str) -> tuple[dict, dict]:
    data, metadata = _read_stable(path, label)
    _require_pin(metadata, expected_pin, label)
    return _json_object(data, label), metadata


def provenance(input_metadata: Sequence[Mapping], *, same_run_receipt: Mapping | None = None) -> dict:
    """Keep target/bridge provenance UNKNOWN unless a same-run receipt exists."""
    if same_run_receipt is None:
        return {
            "status": "UNKNOWN_UNRETAINED",
            "same_run_attested": False,
            "target": {
                "status": "UNKNOWN_UNRETAINED",
                "same_run_attested": False,
                "intended_model": "SM-A908N",
                "intended_soc": "SM8150",
                "reason": "022 raw receipts have no same-run target preflight",
            },
            "bridge": {
                "status": "UNKNOWN_UNRETAINED",
                "same_run_attested": False,
                "serial_device": "UNKNOWN_UNRETAINED",
                "serial_id": "UNKNOWN_UNRETAINED",
                "reason": "022 raw receipts have no same-run bridge binding",
            },
            "commands": {
                "status": "UNKNOWN_UNRETAINED",
                "same_run_attested": False,
                "argv_recorded": False,
                "reason": "022 raw receipts have no same-run command receipt",
            },
            "timestamp": {"status": "UNKNOWN_UNRETAINED"},
        }
    # A future fixed runner may pass a validated receipt here.  Do not accept
    # arbitrary dictionaries as target authority in the current reducer.
    raise ValueError("same-run acquisition receipt validation is not implemented")


def analyse(
    records: list[dict],
    *,
    strict: bool = False,
    phases: Mapping[str, Sequence[Mapping]] | None = None,
    dependency_020m: Mapping | None = None,
    dependency_021: Mapping | None = None,
    input_metadata: Sequence[Mapping] | None = None,
) -> dict:
    """Reduce retained records while keeping model and provenance claims separate."""
    if strict:
        for index, record in enumerate(records, 1):
            _strict_record_shape(record, f"merged record {index}")
        if phases is None or set(phases) != set(EXPECTED_PHASES):
            raise ValueError("strict reduction requires existence and identification phases")
        phase_results = {
            phase: validate_phase_records(phase_records, phase)
            for phase, phase_records in phases.items()
        }
        expected_records = [
            *phases["existence"],
            *phases["identification"],
        ]
        if records != expected_records:
            raise ValueError("strict reduction records do not match validated phases")
        if dependency_020m is None or dependency_021 is None:
            raise ValueError("strict reduction requires pinned 020M and 021 dependencies")
        _require_pin(dependency_020m, DEPENDENCY_020M_PIN, "020M dependency")
        _require_pin(dependency_021, DEPENDENCY_021_PIN, "021 dependency")
        if not isinstance(dependency_020m.get("semantic_attestation"), Mapping) or not isinstance(dependency_021.get("semantic_attestation"), Mapping):
            raise ValueError("strict reduction requires semantic dependency attestations")
    else:
        phase_results = {}

    context = next((r for r in records if r.get("type") == "context"), None)
    if context is None:
        raise ValueError("receipt has no context record")
    provenance_record = next((r for r in records if r.get("type") == "pa_provenance"), None)
    verification = verify_pairs(records)
    per_difference = phase_medians(records)
    medians = {v: statistics.median(ms) for v, ms in per_difference.items()}
    split = classify(medians)

    controls_present = CONTROL_CONFLICT in medians and CONTROL_NEGATIVE in medians
    controls_fired = (
        controls_present
        and medians[CONTROL_CONFLICT] > split["threshold"]
        and medians[CONTROL_NEGATIVE] <= split["threshold"]
    )
    phase_controls: dict[str, dict[str, object]] = {}
    for phase in phase_results:
        phase_medians_value = phase_medians(list(phases[phase]))
        phase_values = {value: statistics.median(values) for value, values in phase_medians_value.items()}
        phase_split = classify(phase_values)
        phase_present = CONTROL_CONFLICT in phase_values and CONTROL_NEGATIVE in phase_values
        phase_controls[phase] = {
            "differences": sorted(hex(value) for value in phase_values),
            "controls_present": phase_present,
            "controls_fired": (
                phase_present
                and phase_values[CONTROL_CONFLICT] > phase_split["threshold"]
                and phase_values[CONTROL_NEGATIVE] <= phase_split["threshold"]
            ),
            "threshold": phase_split["threshold"],
        }
        if strict and not phase_controls[phase]["controls_fired"]:
            controls_fired = False

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

    measured = {difference: medians[difference] for difference in candidates if difference in medians}
    conflicting = [difference for difference, median in measured.items() if median > split["threshold"]]

    if not controls_fired:
        verdict, resolved = "INSTRUMENT_FAILED", None
    elif not verification["all_pairs_isolate_their_difference"]:
        verdict, resolved = "INSTRUMENT_FAILED", None
    elif strict and len(measured) != 8:
        verdict, resolved = "INSTRUMENT_FAILED", None
    elif len(conflicting) == 1:
        verdict, resolved = "RESOLVED", candidates[conflicting[0]]
    elif not conflicting:
        verdict, resolved = "OUTSIDE_RANK_3_SPACE", None
    else:
        verdict, resolved = "AMBIGUOUS_MULTIPLE_CONFLICTS", None

    model_status = "SUPPORTED_MODEL_EXTENSION" if verdict == "RESOLVED" else "NOT_RESOLVED"
    result = {
        "schema": MANIFEST_SCHEMA,
        "context": {
            key: context[key]
            for key in (
                "heap", "mib", "repetitions", "pairs", "cpu", "warmups",
                "order", "barrier", "divisor", "offset_mode", "declared_base",
            )
            if key in context
        },
        "pagemap_status": provenance_record.get("status") if provenance_record else None,
        "pair_verification": verification,
        "medians": {hex(value): median for value, median in sorted(medians.items())},
        "repeats_per_difference": {
            hex(value): len(values) for value, values in sorted(per_difference.items())
        },
        "phase_split": split,
        "phase_controls": phase_controls,
        "controls": {
            "conflict_difference": hex(CONTROL_CONFLICT),
            "negative_difference": hex(CONTROL_NEGATIVE),
            "controls_present": controls_present,
            "controls_fired": controls_fired,
        },
        "candidates_measured": {
            hex(difference): {"vector": f"{candidates[difference]:03b}", "median": median}
            for difference, median in sorted(measured.items())
        },
        "conflicting_candidates": [hex(difference) for difference in sorted(conflicting)],
        "verdict": verdict,
        "result_disposition": model_status,
        "f_pa28": f"{resolved:03b}" if resolved is not None else None,
        "f_pa28_equals": (
            next(
                (f"f(PA{bit.bit_length() - 1})" for bit, vector in BASIS.items() if vector == resolved),
                None,
            )
            if resolved is not None
            else None
        ),
        "claim_disposition": {
            "model_extension": "SUPPORTED" if resolved is not None else "UNKNOWN",
            "alias": "UNKNOWN_NOT_TESTED",
            "physical_mapping": "UNKNOWN",
            "bypass": "NOT_AUTHORIZED",
            "classification": "CLASS C (TRANSFORM ONLY)",
            "eligibility": "NOT_ELIGIBLE",
        },
        "provenance": provenance(input_metadata or []),
        "not_claimed": (
            "The timing classification is a supported model extension only. "
            "A negative or resolved selection result does not establish a complete "
            "DRAM coordinate, physical alias, transform mutability, or access-control implication."
        ),
    }
    if dependency_020m is not None:
        result["dependencies"] = {
            "verification_020m": dict(dependency_020m),
            "verification_021": dict(dependency_021 or {}),
        }
    return result


def _write_new(path: Path, payload: bytes) -> None:
    _reject_symlink_parents(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    _reject_symlink_parents(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o644)
    try:
        os.fchmod(fd, 0o644)
        view = memoryview(payload)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise ValueError("short public-manifest write")
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        directory_fd = os.open(
            path.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as exc:
        raise ValueError(f"manifest parent cannot be fsynced: {path.parent}") from exc
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def build_public_manifest(
    raw_paths: Sequence[Path],
    *,
    precondition_path: Path = DEPENDENCY_020M_PATH,
    extent_path: Path = DEPENDENCY_021_PATH,
    source_path: Path = PROBE_SOURCE_PATH,
) -> dict:
    """Load canonical inputs, pin dependencies, and produce redacted JSON."""
    if len(raw_paths) != 2:
        raise ValueError("022 requires exactly existence and identification raw inputs")
    phase_names = ("existence", "identification")
    merged: list[dict] = []
    phase_records: dict[str, list[dict]] = {}
    input_metadata: list[dict] = []
    for path, phase in zip(raw_paths, phase_names):
        expected = RAW_INPUT_PINS.get(path.name)
        if expected is None:
            raise ValueError(f"{path.name} is not a canonical 022 raw input")
        records, metadata = load(path, phase=phase, expected_pin=expected, canonical=True)
        validate_phase_records(records, phase)
        phase_records[phase] = records
        merged.extend(records)
        input_metadata.append(metadata)
    pre_doc, pre_metadata = load_dependency(
        precondition_path, DEPENDENCY_020M_PIN, "020M dependency manifest"
    )
    pre_semantic = _validate_020m_manifest(pre_doc)
    ext_doc, ext_metadata = load_dependency(
        extent_path, DEPENDENCY_021_PIN, "021 dependency manifest"
    )
    ext_semantic = _validate_021_manifest(ext_doc, pre_metadata)
    source_data, source_metadata = _read_stable(source_path, "022 probe source")
    _require_pin(source_metadata, PROBE_SOURCE_PIN, "022 probe source")
    del source_data
    result = analyse(
        merged,
        strict=True,
        phases=phase_records,
        dependency_020m={**pre_metadata, "semantic_attestation": pre_semantic},
        dependency_021={**ext_metadata, "semantic_attestation": ext_semantic},
        input_metadata=input_metadata,
    )
    result["inputs"] = {
        "raw": input_metadata,
        "probe_source": {**source_metadata, "status": PROBE_SOURCE_PIN["status"]},
        "probe_binary": dict(PROBE_BINARY_PIN),
        "dependency_020m": pre_metadata,
        "dependency_021": ext_metadata,
    }
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", type=Path, required=True, action="append")
    parser.add_argument("--precondition", type=Path, default=DEPENDENCY_020M_PATH)
    parser.add_argument("--extent", type=Path, default=DEPENDENCY_021_PATH)
    parser.add_argument("--source", type=Path, default=PROBE_SOURCE_PATH)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)

    result = build_public_manifest(
        args.raw,
        precondition_path=args.precondition,
        extent_path=args.extent,
        source_path=args.source,
    )
    print(f"pairs verified   : {result['pair_verification']['pairs_checked']} "
          f"({len(result['pair_verification']['mismatched'])} mismatched)")
    print(f"pagemap          : {result['pagemap_status']}")
    print(f"threshold        : {result['phase_split']['threshold']:.0f} "
          f"(gap {result['phase_split']['gap']:.0f}, "
          f"runner-up {result['phase_split']['runner_up_gap']:.0f})")
    print(f"controls fired   : {result['controls']['controls_fired']}")
    print(f"verdict          : {result['verdict']}")
    if result["f_pa28"]:
        print(f"f(PA28)          : {result['f_pa28']}  = {result['f_pa28_equals']}")
    if args.output:
        _write_new(args.output, (json.dumps(result, indent=1, sort_keys=True) + "\n").encode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
