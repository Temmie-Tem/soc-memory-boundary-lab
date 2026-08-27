#!/usr/bin/env python3
"""Host-only reducer for the provenance-complete Verification 022R run.

This module consumes exactly one *private* acquisition directory.  It never
opens a bridge, invokes a compiler, contacts a device, or treats a runner
``public_status`` string as authority.  The runner receipt, its raw JSONL,
and the pinned 020M/021 public dependencies are independently re-read and
checked before timing data is reduced.

The timing rule is deliberately conservative.  The seven candidate medians
are classified twice: once with the two leading controls and once with the
two trailing controls.  Each bracket uses the unique widest gap in its full
nine-value median set.  Both brackets must put 0x16000 above the threshold,
0x2000 at or below it, agree on every candidate label, have the same unique
winner, and have threshold/control drift no larger than one quarter of the
smaller bracket gap.  A tied widest gap, failed control, excessive drift, or
candidate disagreement is ``INCONCLUSIVE``; it is never coerced into a
winner.

The terminal JSONL cleanup record is required.  The C probe's final record is
accepted only when it reports successful release of all process-owned
resources, using the finalized v022r field set exactly.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
from collections.abc import Mapping, Sequence
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]

ANALYSIS_SCHEMA = "a90_pa28_live_analysis_v1"
SCHEMA = ANALYSIS_SCHEMA
RECEIPT_SCHEMA = "a90_pa28_live_v1"
PROBE_SCHEMA = "a90_pa28_probe_v022r_v1"
BUILD_SCHEMA = "a90_pa28_build_v1"
EXPERIMENT_ID = "verification-022r-pa28-live"

EXPECTED_MODEL = "SM-A908N"
EXPECTED_SOC = "SM8150"
EXPECTED_RUNTIME_VERSION = "0.9.285"
EXPECTED_RUNTIME_BUILD = "v2321-usb-clean-identity-rodata"
EXPECTED_KERNEL = "Linux 4.14.190-25818860-abA908NKSU5EWA3 aarch64"
EXPECTED_BOOTLOADER = "A908NKSU5EWA3"
EXPECTED_TARGET = {
    "model": EXPECTED_MODEL,
    "soc": EXPECTED_SOC,
    "runtime_version": EXPECTED_RUNTIME_VERSION,
    "runtime_build": EXPECTED_RUNTIME_BUILD,
    "kernel": EXPECTED_KERNEL,
    "bootloader": EXPECTED_BOOTLOADER,
    "debug_level": "0x4f4c",
    "force_upload": "0x0",
    "dump_sink": "0x0",
}

BRIDGE_HOST = "127.0.0.1"
BRIDGE_PORT = 54321
BRIDGE_PROCESS_SCRIPT = "serial_tcp_bridge.py"
BRIDGE_SCRIPT_PATH = Path(
    "/home/temmie/dev/android-native-init-lab/workspace/public/src/scripts/"
    "revalidation/serial_tcp_bridge.py"
)
BRIDGE_SERIAL_DEVICE = "/dev/ttyACM0"
BRIDGE_SERIAL_ID = (
    "/dev/serial/by-id/usb-A90-LNX_A90_Linux_ARM64_A90NATIVE001-if00"
)
BRIDGE_SERIAL_GLOB_TOKEN = "usb-A90-LNX_A90_Linux_ARM64_A90NATIVE001-if00"

REMOTE_ROOT = "/tmp/a90-native"
REMOTE_BINARY = f"{REMOTE_ROOT}/v022r-pa28-probe"
REMOTE_ENVELOPE = f"{REMOTE_ROOT}/v022r-pa28-probe.b64u"
REMOTE_ION = f"{REMOTE_ROOT}/v022r-ion"
ION_DEV_PATH = "/sys/class/misc/ion/dev"
TOYBOX = "/bin/toybox"
EXPECTED_ION_DEV = "10:94"

EXPECTED_HEAP = "camera_preview"
EXPECTED_HEAP_TYPE = 10
EXPECTED_HEAP_ID = 30
EXPECTED_MIB = 320
EXPECTED_ALLOCATION_BYTES = EXPECTED_MIB * 1024 * 1024
EXPECTED_REPETITIONS = 201
EXPECTED_PAIRS = 256
EXPECTED_CPU = 7
EXPECTED_CNTFRQ = 19_200_000
EXPECTED_WARMUPS = 17
EXPECTED_OFFSET_MODE = "spread"
EXPECTED_ORDER = "alternating"
EXPECTED_BARRIER = "dsb_ld"
EXPECTED_DIVISOR = "kept_times_two"
EXPECTED_BASE = 0xC2000000
EXPECTED_BASE_TEXT = "0xc2000000"
EXPECTED_PAGE_COUNT = EXPECTED_ALLOCATION_BYTES // 4096

CONTROL_CONFLICT = 0x16000
CONTROL_NON_CONFLICT = 0x2000
PA28 = 1 << 28
BASIS = {0x2000: 0b001, 0x4000: 0b010, 0x8000: 0b100}
CANDIDATE_VALUES = (
    0x10002000,
    0x10004000,
    0x10006000,
    0x10008000,
    0x1000A000,
    0x1000C000,
    0x1000E000,
)
CANDIDATE_VECTORS = {
    0x10002000: "001",
    0x10004000: "010",
    0x10006000: "011",
    0x10008000: "100",
    0x1000A000: "101",
    0x1000C000: "110",
    0x1000E000: "111",
}
FIXED_DIFFERENCES = (
    CONTROL_CONFLICT,
    CONTROL_NON_CONFLICT,
    *CANDIDATE_VALUES,
    CONTROL_CONFLICT,
    CONTROL_NON_CONFLICT,
)
FIXED_DIFFERENCE_TEXT = tuple(hex(value) for value in FIXED_DIFFERENCES)
PROBE_CLI_ARGS = (
    EXPECTED_HEAP,
    str(EXPECTED_MIB),
    str(EXPECTED_REPETITIONS),
    str(EXPECTED_PAIRS),
    str(EXPECTED_CPU),
    EXPECTED_OFFSET_MODE,
    EXPECTED_BASE_TEXT,
    REMOTE_ION,
    *FIXED_DIFFERENCE_TEXT,
)
PROBE_ARGV = ("run", REMOTE_BINARY, *PROBE_CLI_ARGS)

RAW_BASENAME = "pa28-identification.jsonl"
RECEIPT_BASENAME = "receipt.json"
RAW_PAYLOAD_BASENAME = "probe-output.bin"
TRANSCRIPT_BASENAME = "transcript.bin"
EXPECTED_SOURCE_BASENAME = "a90_pa28_probe_v022r.c"
EXPECTED_BINARY_BASENAME = "v022r-pa28-probe"
EXPECTED_RUNNER_BASENAME = "a90_pa28_live.py"
EXPECTED_BRIDGE_BASENAME = "serial_tcp_bridge.py"
EXPECTED_BUILD_BASENAME = "build-receipt.json"
EXPECTED_SOURCE_SIZE = 27415
EXPECTED_SOURCE_SHA256 = "d66e8930fdf8456cb99ee6d4e6d9b8386d3f645d3a902091c39b814b3f73b315"
EXPECTED_BINARY_SIZE = 776408
EXPECTED_BINARY_SHA256 = "ed826cc75dee1eafad3b1b1ea4b0b779147364a330201e284b9e24c92adf1b92"
EXPECTED_BRIDGE_SIZE = 21170
EXPECTED_BRIDGE_SHA256 = "febfb95f408f62f516c2e4f6c25f5da61535f7b75366c3f73cc47bfd91fba077"
EXPECTED_COMPILER_TRIPLE = "aarch64-linux-gnu"
EXPECTED_COMPILER_VERSION = "aarch64-linux-gnu-gcc (Ubuntu 15.2.0-16ubuntu1) 15.2.0"
# Exact bytes observed after the runner's raw Ctrl-C and dual-binding pass.
EXPECTED_RUNNER_SIZE = 150104
EXPECTED_RUNNER_SHA256 = "0f50a20453f00a6f647d52cc2c3cd10ba52f8869d6b9264d5b9c47671197bc66"

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

MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_RECORDS = 100_000
MAX_UINT64 = (1 << 64) - 1
MAX_I64 = (1 << 63) - 1
MIN_I64 = -(1 << 63)
MAX_LEGACY_CHUNK = 3500
THRESHOLD_DRIFT_FRACTION = 0.25
SAFE_BASENAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,95}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
HEX_RE = re.compile(r"0x[0-9a-f]+\Z")


class AnalysisError(ValueError):
    """Raised for malformed, mutated, unsafe, or non-admissible evidence."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _reject_symlink_components(path: Path) -> None:
    """Reject symlinks in every existing lexical path component."""

    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor or "/")
    for component in absolute.parts[1:]:
        current /= component
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise AnalysisError(f"cannot inspect path component {current}") from exc
        if stat.S_ISLNK(info.st_mode):
            raise AnalysisError(f"symlink path component is forbidden: {current}")


def read_stable(path: Path, label: str = "input") -> tuple[bytes, dict[str, object]]:
    """Read one bounded regular file through an O_NOFOLLOW descriptor."""

    path = Path(path)
    _reject_symlink_components(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise AnalysisError(f"{label} cannot be opened without following links") from exc
    before: os.stat_result
    after: os.stat_result
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise AnalysisError(f"{label} is not a regular file")
        if before.st_size <= 0 or before.st_size > MAX_INPUT_BYTES:
            raise AnalysisError(f"{label} has an invalid bounded size")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            block = os.read(fd, min(1 << 20, remaining))
            if not block:
                raise AnalysisError(f"{label} was truncated while being read")
            chunks.append(block)
            remaining -= len(block)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    before_key = (
        before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
        before.st_ctime_ns, before.st_nlink,
    )
    after_key = (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
        after.st_ctime_ns, after.st_nlink,
    )
    if before_key != after_key:
        raise AnalysisError(f"{label} changed while being read")
    data = b"".join(chunks)
    if len(data) != before.st_size:
        raise AnalysisError(f"{label} size changed while being read")
    return data, {
        "basename": path.name,
        "size_bytes": len(data),
        "sha256": sha256(data),
    }


def write_new(path: Path, data: bytes, mode: int = 0o644) -> Path:
    """Publish one new regular file with O_EXCL/O_NOFOLLOW and fsync."""

    path = Path(path)
    _reject_symlink_components(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, mode)
    except OSError as exc:
        raise AnalysisError(f"refusing to clobber output {path}") from exc
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
    return path


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

    def reject(value: str) -> object:
        raise AnalysisError(f"{label} contains non-finite JSON number {value!r}")

    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_constant=reject)
    except AnalysisError:
        raise
    except json.JSONDecodeError as exc:
        raise AnalysisError(f"{label} is malformed JSON: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise AnalysisError(f"{label} is not a JSON object")
    return value


def _json_line(line: bytes, label: str) -> dict[str, object]:
    if not line or line.strip() != line:
        raise AnalysisError(f"{label} is blank or has surrounding whitespace")
    return _json_object(line, label)


def _int(value: object, label: str, *, minimum: int | None = None,
         maximum: int | None = None) -> int:
    if not _is_int(value):
        raise AnalysisError(f"{label} is not an integer")
    number = int(value)
    if minimum is not None and number < minimum:
        raise AnalysisError(f"{label} is below {minimum}")
    if maximum is not None and number > maximum:
        raise AnalysisError(f"{label} is above {maximum}")
    return number


def _hex(value: object, label: str) -> int:
    if not isinstance(value, str) or HEX_RE.fullmatch(value) is None:
        raise AnalysisError(f"{label} is not canonical lowercase hexadecimal")
    parsed = int(value, 16)
    if value != hex(parsed):
        raise AnalysisError(f"{label} is not canonically formatted")
    return parsed


def _bool(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise AnalysisError(f"{label} is not boolean")
    return value


def _required_keys(record: Mapping[str, object], wanted: set[str], label: str) -> None:
    if set(record) != wanted:
        raise AnalysisError(
            f"{label} fields differ: expected {sorted(wanted)}, got {sorted(record)}"
        )


def _descriptor(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != {"basename", "size_bytes", "sha256"}:
        raise AnalysisError(f"{label} descriptor fields differ")
    basename = value.get("basename")
    if not isinstance(basename, str) or SAFE_BASENAME_RE.fullmatch(basename) is None:
        raise AnalysisError(f"{label} descriptor basename is unsafe")
    size = _int(value.get("size_bytes"), f"{label}.size_bytes", minimum=1,
                maximum=MAX_INPUT_BYTES)
    digest = value.get("sha256")
    if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
        raise AnalysisError(f"{label} descriptor hash is not lowercase SHA-256")
    return {"basename": basename, "size_bytes": size, "sha256": digest}


def _same_descriptor(left: Mapping[str, object], right: Mapping[str, object], label: str) -> None:
    if dict(left) != dict(right):
        raise AnalysisError(f"{label} descriptor differs")


def _parse_utc(value: object, label: str) -> dt.datetime:
    if not isinstance(value, str):
        raise AnalysisError(f"{label} is not a timestamp string")
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError as exc:
        raise AnalysisError(f"{label} is not RFC3339/ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != dt.timedelta(0):
        raise AnalysisError(f"{label} is not UTC")
    return parsed


def parse_jsonl(data: bytes, label: str = RAW_BASENAME) -> list[dict[str, object]]:
    """Parse strict LF-delimited JSONL without dropping malformed records."""

    if not data or not data.endswith(b"\n") or b"\r" in data:
        raise AnalysisError(f"{label} is not canonical LF JSONL")
    lines = data.split(b"\n")[:-1]
    if not lines or len(lines) > MAX_RECORDS:
        raise AnalysisError(f"{label} has an invalid record count")
    return [_json_line(line, f"{label}:{index}") for index, line in enumerate(lines, 1)]


CLEANUP_FIELDS = frozenset({
    "schema", "type", "attempted", "released", "ion_fd_closed",
    "allocation_fd_closed", "map_unmapped", "eviction_unmapped",
    "heaps_freed", "sample_buffers_freed", "status",
})

RECORD_FIELDS = {
    "context": frozenset({
        "schema", "type", "cpu", "cntfrq", "heap", "mib", "repetitions",
        "pairs", "warmups", "order", "barrier", "divisor", "offset_mode",
        "declared_base",
    }),
    "ion_heap": frozenset({"schema", "type", "name", "heap_type", "heap_id"}),
    "pa_provenance": frozenset({
        "schema", "type", "source", "pages", "present", "nonzero_pfn",
        "first_pfn", "last_pfn", "contiguous", "status",
    }),
    "pair": frozenset({
        "schema", "type", "value", "offset", "pa_a", "pa_b", "pa_xor", "delta",
    }),
    "difference": frozenset({
        "schema", "type", "value", "pairs", "rejected_range", "rejected_carry",
        "p10", "median", "p90",
    }),
}


def _check_record_shape(record: Mapping[str, object], label: str) -> None:
    kind = record.get("type")
    if record.get("schema") != PROBE_SCHEMA:
        raise AnalysisError(f"{label} has a foreign probe schema")
    if kind == "cleanup":
        if set(record) != CLEANUP_FIELDS:
            raise AnalysisError(f"{label} cleanup fields differ")
        return
    if not isinstance(kind, str) or kind not in RECORD_FIELDS:
        raise AnalysisError(f"{label} has an unsupported record type")
    if set(record) != RECORD_FIELDS[kind]:
        raise AnalysisError(f"{label} fields differ for {kind}")


def _validate_cleanup_record(record: Mapping[str, object], label: str) -> dict[str, object]:
    _check_record_shape(record, label)
    if record.get("status") not in {"OK", "PASS"}:
        raise AnalysisError(f"{label} does not attest successful cleanup")
    out = dict(record)
    for key, value in record.items():
        if key in {"schema", "type", "status"}:
            continue
        if value is not True:
            raise AnalysisError(f"{label}.{key} is not true")
    return out


def _summary_stats(deltas: Sequence[int]) -> dict[str, int]:
    if not deltas:
        raise AnalysisError("difference has no accepted timing pairs")
    ordered = sorted(deltas)
    trim = len(ordered) // 10
    return {
        # These indices match the C probe exactly, including its upper-middle
        # choice for an even number of samples.
        "p10": ordered[trim],
        "median": ordered[len(ordered) // 2],
        "p90": ordered[len(ordered) - 1 - trim],
    }


def validate_probe_records(records: Sequence[Mapping[str, object]]) -> dict[str, object]:
    """Validate complete 022R JSONL order, pair arithmetic, and summaries."""

    if not isinstance(records, Sequence) or isinstance(records, (str, bytes)):
        raise AnalysisError("probe records are not a sequence")
    if not records or len(records) > MAX_RECORDS:
        raise AnalysisError("probe records are empty or too numerous")
    normalized: list[Mapping[str, object]] = []
    for index, record in enumerate(records, 1):
        if not isinstance(record, Mapping):
            raise AnalysisError(f"probe record {index} is not an object")
        _check_record_shape(record, f"probe record {index}")
        normalized.append(record)

    if len(normalized) < 5 or [item.get("type") for item in normalized[:3]] != [
        "context", "ion_heap", "pa_provenance"
    ]:
        raise AnalysisError("probe metadata prefix is not in fixed order")
    if normalized[-1].get("type") != "cleanup":
        raise AnalysisError("probe lacks its terminal cleanup record")
    cleanup = _validate_cleanup_record(normalized[-1], "probe cleanup")
    body = normalized[:-1]
    if any(item.get("type") == "cleanup" for item in body):
        raise AnalysisError("probe contains an early or duplicate cleanup record")

    contexts = [item for item in body if item.get("type") == "context"]
    heaps = [item for item in body if item.get("type") == "ion_heap"]
    pagemaps = [item for item in body if item.get("type") == "pa_provenance"]
    if len(contexts) != 1 or len(heaps) != 1 or len(pagemaps) != 1:
        raise AnalysisError("probe requires one context, heap, and pagemap record")
    context = contexts[0]
    expected_context: dict[str, object] = {
        "cpu": EXPECTED_CPU,
        "cntfrq": EXPECTED_CNTFRQ,
        "heap": EXPECTED_HEAP,
        "mib": EXPECTED_MIB,
        "repetitions": EXPECTED_REPETITIONS,
        "pairs": EXPECTED_PAIRS,
        "warmups": EXPECTED_WARMUPS,
        "order": EXPECTED_ORDER,
        "barrier": EXPECTED_BARRIER,
        "divisor": EXPECTED_DIVISOR,
        "offset_mode": EXPECTED_OFFSET_MODE,
        "declared_base": EXPECTED_BASE_TEXT,
    }
    for key, wanted in expected_context.items():
        if key in {"cpu", "cntfrq", "mib", "repetitions", "pairs", "warmups"}:
            _int(context.get(key), f"context.{key}", minimum=0)
        if context.get(key) != wanted:
            raise AnalysisError(f"context.{key} differs from fixed 022R value")
    if _hex(context.get("declared_base"), "context.declared_base") != EXPECTED_BASE:
        raise AnalysisError("context declared base differs")

    heap = heaps[0]
    if (
        heap.get("name") != EXPECTED_HEAP
        or _int(heap.get("heap_type"), "ion_heap.heap_type") != EXPECTED_HEAP_TYPE
        or _int(heap.get("heap_id"), "ion_heap.heap_id") != EXPECTED_HEAP_ID
    ):
        raise AnalysisError("probe heap identity differs")
    pagemap = pagemaps[0]
    if (
        pagemap.get("source") != "pagemap"
        or pagemap.get("status") != "BLIND"
        or _int(pagemap.get("pages"), "pa_provenance.pages") != EXPECTED_PAGE_COUNT
        or _int(pagemap.get("present"), "pa_provenance.present", minimum=0) != 0
        or _int(pagemap.get("nonzero_pfn"), "pa_provenance.nonzero_pfn", minimum=0) != 0
        or pagemap.get("first_pfn") != "0x0"
        or pagemap.get("last_pfn") != "0x0"
        or pagemap.get("contiguous") is not True
    ):
        raise AnalysisError("pagemap is not the fixed blind observation")

    summaries: list[dict[str, object]] = []
    cursor = 3
    for occurrence, expected_value in enumerate(FIXED_DIFFERENCES):
        deltas: list[int] = []
        while cursor < len(body) and body[cursor].get("type") == "pair":
            pair = body[cursor]
            value = _hex(pair.get("value"), f"pair {cursor + 1}.value")
            if value != expected_value:
                raise AnalysisError("pair/difference interleaving or value order differs")
            offset = _hex(pair.get("offset"), f"pair {cursor + 1}.offset")
            pa_a = _hex(pair.get("pa_a"), f"pair {cursor + 1}.pa_a")
            pa_b = _hex(pair.get("pa_b"), f"pair {cursor + 1}.pa_b")
            pa_xor = _hex(pair.get("pa_xor"), f"pair {cursor + 1}.pa_xor")
            delta = _int(pair.get("delta"), f"pair {cursor + 1}.delta",
                         minimum=MIN_I64, maximum=MAX_I64)
            if offset % 4096 or offset + 4096 > EXPECTED_ALLOCATION_BYTES:
                raise AnalysisError("pair offset is outside the allocation")
            other = offset ^ value
            if other + 4096 > EXPECTED_ALLOCATION_BYTES:
                raise AnalysisError("pair counterpart offset is outside allocation")
            if EXPECTED_BASE + offset > MAX_UINT64 or EXPECTED_BASE + other > MAX_UINT64:
                raise AnalysisError("pair base addition overflows")
            expected_pa_a = EXPECTED_BASE + offset
            expected_pa_b = EXPECTED_BASE + other
            if pa_a != expected_pa_a or pa_b != expected_pa_b:
                raise AnalysisError("pair physical address arithmetic is forged")
            if pa_xor != (pa_a ^ pa_b) or (pa_a ^ pa_b) != value:
                raise AnalysisError("pair physical XOR arithmetic is inconsistent")
            deltas.append(delta)
            cursor += 1
        if cursor >= len(body) or body[cursor].get("type") != "difference":
            raise AnalysisError("difference summary is missing or interleaved")
        summary = body[cursor]
        value = _hex(summary.get("value"), f"difference {occurrence}.value")
        if value != expected_value:
            raise AnalysisError("difference summary value/order differs")
        pairs = _int(summary.get("pairs"), f"difference {occurrence}.pairs", minimum=1,
                     maximum=EXPECTED_PAIRS)
        rejected_range = _int(summary.get("rejected_range"),
                              f"difference {occurrence}.rejected_range", minimum=0)
        rejected_carry = _int(summary.get("rejected_carry"),
                              f"difference {occurrence}.rejected_carry", minimum=0)
        if pairs != len(deltas) or pairs + rejected_range + rejected_carry != EXPECTED_PAIRS:
            raise AnalysisError("difference pair/rejection accounting is invalid")
        recomputed = _summary_stats(deltas)
        for key, wanted in recomputed.items():
            if _int(summary.get(key), f"difference {occurrence}.{key}") != wanted:
                raise AnalysisError(f"difference {occurrence} summary {key} is forged")
        summaries.append({
            "occurrence": occurrence,
            "value": value,
            "value_text": hex(value),
            "pairs": pairs,
            "rejected_range": rejected_range,
            "rejected_carry": rejected_carry,
            **recomputed,
            "deltas": tuple(deltas),
        })
        cursor += 1
    if cursor != len(body):
        raise AnalysisError("probe contains extra, omitted, or reordered records")

    return {
        "schema": PROBE_SCHEMA,
        "records": len(normalized),
        "context": dict(context),
        "ion_heap": dict(heap),
        "pagemap": dict(pagemap),
        "cleanup": cleanup,
        "summaries": summaries,
        "records_data": [dict(item) for item in normalized],
    }


def validate_probe_jsonl(data: bytes, label: str = RAW_BASENAME) -> dict[str, object]:
    records = parse_jsonl(data, label)
    return validate_probe_records(records)


# Compatibility names used by adjacent host analyzers.
parse = parse_jsonl
validate_records = validate_probe_records


def _classify_medians(medians: Mapping[int, int], label: str) -> dict[str, object]:
    if len(medians) < 2:
        return {"status": "INCONCLUSIVE", "reason": f"{label} has fewer than two medians"}
    ordered = sorted(medians.items(), key=lambda item: (item[1], item[0]))
    gaps = [ordered[index + 1][1] - ordered[index][1] for index in range(len(ordered) - 1)]
    widest = max(gaps)
    winners = [index for index, gap in enumerate(gaps) if gap == widest]
    if widest <= 0 or len(winners) != 1:
        return {
            "status": "INCONCLUSIVE",
            "reason": f"{label} widest gap is non-positive or tied",
            "ordered": [(hex(value), median) for value, median in ordered],
            "gaps": gaps,
        }
    split = winners[0]
    threshold = (ordered[split][1] + ordered[split + 1][1]) / 2.0
    labels = {
        value: ("CONFLICT" if median > threshold else "NON_CONFLICT")
        for value, median in medians.items()
    }
    return {
        "status": "OK",
        "threshold": threshold,
        "widest_gap": widest,
        "runner_up_gap": max((gap for index, gap in enumerate(gaps) if index != split), default=0),
        "split_index": split,
        "ordered": [(hex(value), median) for value, median in ordered],
        "labels": {hex(value): labels[value] for value in sorted(labels)},
        "medians": {hex(value): median for value, median in sorted(medians.items())},
    }


def classify(medians: Mapping[int, int]) -> dict[str, object]:
    """Public widest-gap classifier; ambiguous splits return INCONCLUSIVE."""

    return _classify_medians(medians, "median set")


def reduce_measurements(parsed: Mapping[str, object]) -> dict[str, object]:
    """Classify both control brackets and derive a bounded PA28 result."""

    summaries_value = parsed.get("summaries") if isinstance(parsed, Mapping) else None
    if not isinstance(summaries_value, Sequence) or len(summaries_value) != 11:
        raise AnalysisError("validated probe summaries are missing")
    summaries = [item for item in summaries_value if isinstance(item, Mapping)]
    if len(summaries) != 11:
        raise AnalysisError("validated probe summaries are malformed")
    before = list(summaries[:9])
    after = list(summaries[2:])
    before_medians = {int(item["value"]): int(item["median"]) for item in before}
    after_medians = {int(item["value"]): int(item["median"]) for item in after}
    bracket_before = _classify_medians(before_medians, "leading control bracket")
    bracket_after = _classify_medians(after_medians, "trailing control bracket")
    inconclusive_reasons: list[str] = []
    for name, bracket in (("leading", bracket_before), ("trailing", bracket_after)):
        if bracket.get("status") != "OK":
            inconclusive_reasons.append(f"{name} bracket: {bracket.get('reason', 'invalid')}")
    controls_ok = False
    if not inconclusive_reasons:
        for name, bracket in (("leading", bracket_before), ("trailing", bracket_after)):
            labels = bracket["labels"]
            if (
                labels.get(hex(CONTROL_CONFLICT)) != "CONFLICT"
                or labels.get(hex(CONTROL_NON_CONFLICT)) != "NON_CONFLICT"
            ):
                inconclusive_reasons.append(f"{name} controls do not bracket the threshold")
        controls_ok = not inconclusive_reasons

    threshold_drift: float | None = None
    control_drift: dict[str, int] = {}
    drift_limit: float | None = None
    if controls_ok:
        threshold_drift = abs(float(bracket_before["threshold"]) - float(bracket_after["threshold"]))
        drift_limit = min(float(bracket_before["widest_gap"]), float(bracket_after["widest_gap"])) * THRESHOLD_DRIFT_FRACTION
        for value in (CONTROL_CONFLICT, CONTROL_NON_CONFLICT):
            control_drift[hex(value)] = abs(
                int(before_medians[value]) - int(after_medians[value])
            )
        if threshold_drift > drift_limit or any(value > drift_limit for value in control_drift.values()):
            inconclusive_reasons.append("leading/trailing control threshold drift is excessive")

    candidate_labels_before: dict[str, str] = {}
    candidate_labels_after: dict[str, str] = {}
    winner_before: list[int] = []
    winner_after: list[int] = []
    if not inconclusive_reasons:
        labels_before = bracket_before["labels"]
        labels_after = bracket_after["labels"]
        for value in CANDIDATE_VALUES:
            text = hex(value)
            left = labels_before.get(text)
            right = labels_after.get(text)
            if left not in {"CONFLICT", "NON_CONFLICT"} or right not in {"CONFLICT", "NON_CONFLICT"}:
                inconclusive_reasons.append(f"candidate {text} lacks a bracket label")
                continue
            candidate_labels_before[text] = left
            candidate_labels_after[text] = right
            if left == "CONFLICT":
                winner_before.append(value)
            if right == "CONFLICT":
                winner_after.append(value)
        if candidate_labels_before != candidate_labels_after:
            inconclusive_reasons.append("leading/trailing candidate labels disagree")
        if len(winner_before) != 1 or len(winner_after) != 1:
            inconclusive_reasons.append("candidate conflict winner is not unique")
        elif winner_before != winner_after:
            inconclusive_reasons.append("leading/trailing winner differs")

    winner = winner_before[0] if len(winner_before) == 1 and winner_before == winner_after else None
    status = "SUPPORTED_MODEL_EXTENSION" if not inconclusive_reasons and winner is not None else "INCONCLUSIVE"
    result: dict[str, object] = {
        "schema": ANALYSIS_SCHEMA,
        "status": status,
        "verdict": status,
        "controls_pass": controls_ok and not inconclusive_reasons,
        "inconclusive_reasons": inconclusive_reasons,
        "candidate_labels": {
            text: {
                "vector": CANDIDATE_VECTORS[value],
                "leading": candidate_labels_before.get(text),
                "trailing": candidate_labels_after.get(text),
                "median": next(int(item["median"]) for item in summaries if int(item["value"]) == value),
            }
            for value, text in ((value, hex(value)) for value in CANDIDATE_VALUES)
        },
        "brackets": {"leading": bracket_before, "trailing": bracket_after},
        "threshold_drift": threshold_drift,
        "control_drift": control_drift,
        "drift_limit": drift_limit,
        "summaries": [
            {
                key: value
                for key, value in item.items()
                if key != "deltas"
            }
            for item in summaries
        ],
        "candidate_winner": (
            {
                "difference": hex(winner),
                "vector": CANDIDATE_VECTORS[winner],
                "f_pa28": CANDIDATE_VECTORS[winner],
            }
            if winner is not None else None
        ),
        "f_pa28": CANDIDATE_VECTORS[winner] if winner is not None else None,
        "candidate_verdict": (
            "PA28_SUPPORTED_MODEL_EXTENSION" if winner is not None
            else "PA28_UNRESOLVED"
        ),
        "bounded_interpretation": (
            "one exact normal-RAM timing/model candidate supports the recovered rank-3 extension"
            if winner is not None else "timing/model candidate remains unresolved"
        ),
    }
    return result


def _validate_020m(document: Mapping[str, object]) -> dict[str, object]:
    if document.get("schema") != "a90-pa28-dt-snapshot-v1":
        raise AnalysisError("020M dependency schema changed")
    if document.get("experiment_id") != "verification-020m-pa28-dt-20260827-03":
        raise AnalysisError("020M dependency experiment identity changed")
    target = document.get("target")
    if not isinstance(target, Mapping) or {
        target.get("model"), target.get("soc"), target.get("version")
    } != {EXPECTED_MODEL, EXPECTED_SOC, "A90 Linux init 0.9.285"}:
        raise AnalysisError("020M dependency target changed")
    bridge = document.get("bridge")
    if not isinstance(bridge, Mapping) or (
        bridge.get("serial_device") != BRIDGE_SERIAL_DEVICE
        or bridge.get("serial_realpath") != BRIDGE_SERIAL_DEVICE
        or bridge.get("strict_device_glob_option") is not True
        or bridge.get("strict_expect_realpath_option") is not True
    ):
        raise AnalysisError("020M dependency bridge semantics changed")
    semantic = document.get("semantic")
    if not isinstance(semantic, Mapping):
        raise AnalysisError("020M dependency semantic chain is missing")
    heap = semantic.get("ion_heap30")
    region = semantic.get("camera_mem_region")
    if not isinstance(heap, Mapping) or not isinstance(region, Mapping):
        raise AnalysisError("020M dependency lacks heap/region semantics")
    if (
        heap.get("reg"), heap.get("memory_region_phandle"), heap.get("name")
    ) != ("0x1e", "0x67a", "qcom,ion-heap"):
        raise AnalysisError("020M heap-30 semantics changed")
    reg = region.get("reg")
    optional = region.get("optional_properties")
    if not isinstance(reg, Mapping) or not isinstance(optional, Mapping):
        raise AnalysisError("020M camera region semantics are incomplete")
    if (
        region.get("name"), region.get("phandle"), reg.get("base"),
        reg.get("size"), reg.get("end_exclusive")
    ) != (
        "camera_mem_region", "0x67a", "0xc2000000", "0x14000000", "0xd6000000"
    ):
        raise AnalysisError("020M camera region values changed")
    no_map = optional.get("camera_no_map")
    reusable = optional.get("camera_reusable")
    if (
        not isinstance(no_map, Mapping) or not isinstance(reusable, Mapping)
        or no_map.get("present") is not False or no_map.get("errno") != 2
        or reusable.get("present") is not False or reusable.get("errno") != 2
        or not isinstance(region.get("ion_recyclable"), Mapping)
        or region["ion_recyclable"].get("present") is not True
    ):
        raise AnalysisError("020M optional-property semantics changed")
    raw = document.get("raw_receipt")
    if not isinstance(raw, Mapping) or raw.get("size") != 15435 or raw.get(
        "sha256"
    ) != "40a3207d3f822775c4506415a579e993c07a6a7f9ff998e41a6f76cb6216a2ec":
        raise AnalysisError("020M raw receipt pin changed")
    return {
        "schema": document["schema"],
        "experiment_id": document["experiment_id"],
        "target": {"model": target["model"], "soc": target["soc"], "version": target["version"]},
        "semantic": {
            "heap30_reg": heap["reg"],
            "heap30_memory_region_phandle": heap["memory_region_phandle"],
            "camera_phandle": region["phandle"],
            "camera_base": reg["base"],
            "camera_size": reg["size"],
            "camera_end_exclusive": reg["end_exclusive"],
        },
    }


def _validate_021(document: Mapping[str, object], dep020: Mapping[str, object]) -> dict[str, object]:
    if document.get("schema") != "a90_carveout_exhaustion_v2":
        raise AnalysisError("021 dependency schema changed")
    heap = document.get("heap")
    region = document.get("device_tree_region")
    if not isinstance(heap, Mapping) or not isinstance(region, Mapping):
        raise AnalysisError("021 dependency heap/region semantics are missing")
    if (
        heap.get("name"), heap.get("heap_type"), heap.get("heap_id")
    ) != (EXPECTED_HEAP, EXPECTED_HEAP_TYPE, EXPECTED_HEAP_ID):
        raise AnalysisError("021 heap identity changed")
    if (
        region.get("heap_name"), region.get("heap_id"), region.get("memory_region_phandle"),
        region.get("base"), region.get("size")
    ) != (EXPECTED_HEAP, EXPECTED_HEAP_ID, "0x67a", "0xc2000000", "0x14000000"):
        raise AnalysisError("021 device-tree region changed")
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
        raise AnalysisError("021 full-size carveout gate changed")
    dep = document.get("provenance")
    dep_info = dep.get("dependency_020m") if isinstance(dep, Mapping) else None
    if not isinstance(dep_info, Mapping) or (
        dep_info.get("basename") != DEPENDENCY_020M_PIN["basename"]
        or dep_info.get("size_bytes") != DEPENDENCY_020M_PIN["size_bytes"]
        or dep_info.get("sha256") != DEPENDENCY_020M_PIN["sha256"]
        or dep_info.get("status") != "RETAINED_PUBLIC_DEPENDENCY"
    ):
        raise AnalysisError("021 dependency does not bind the canonical 020M pin")
    return {
        "schema": document["schema"],
        "heap": dict(heap),
        "device_tree_region": dict(region),
        "hold_bytes": document["hold_bytes"],
        "pool_exhausted": True,
        "controls_fired": True,
        "verdict": document["verdict"],
    }


def load_dependency(path: Path, expected_pin: Mapping[str, object], label: str) -> dict[str, object]:
    data, metadata = read_stable(path, label)
    if metadata != dict(expected_pin):
        raise AnalysisError(f"{label} does not match its canonical pin")
    return {"metadata": metadata, "document": _json_object(data, label)}


def load_dependencies(
    path_020m: Path | None = None, path_021: Path | None = None
) -> dict[str, object]:
    path_020m = DEPENDENCY_020M_PATH if path_020m is None else Path(path_020m)
    path_021 = DEPENDENCY_021_PATH if path_021 is None else Path(path_021)
    dep020 = load_dependency(path_020m, DEPENDENCY_020M_PIN, "020M dependency")
    sem020 = _validate_020m(dep020["document"])
    dep021 = load_dependency(path_021, DEPENDENCY_021_PIN, "021 dependency")
    sem021 = _validate_021(dep021["document"], sem020)
    return {
        "020m": {"metadata": dep020["metadata"], "semantic": sem020},
        "021": {"metadata": dep021["metadata"], "semantic": sem021},
    }


def _validate_bridge_binding(binding: object) -> dict[str, object]:
    if not isinstance(binding, Mapping):
        raise AnalysisError("private receipt lacks bridge binding")
    required = {
        "listener", "serial_device", "serial_identity", "serial_realpath",
        "serial_stat", "validated_utc", "process_pid", "process_argv",
        "bridge_process_script", "bridge_process_script_path",
        "bridge_process_script_descriptor", "unique_process",
    }
    if set(binding) != required:
        raise AnalysisError("bridge binding fields are incomplete")
    listener = binding.get("listener")
    if listener != {"host": BRIDGE_HOST, "port": BRIDGE_PORT}:
        raise AnalysisError("bridge listener binding differs")
    serial_identity = binding.get("serial_identity", binding.get("serial_id"))
    if (
        binding.get("serial_device") != BRIDGE_SERIAL_DEVICE
        or serial_identity != BRIDGE_SERIAL_ID
        or binding.get("serial_realpath") != BRIDGE_SERIAL_DEVICE
        or binding.get("bridge_process_script") != BRIDGE_PROCESS_SCRIPT
        or binding.get("bridge_process_script_path") != str(BRIDGE_SCRIPT_PATH)
        or binding.get("unique_process") is not True
    ):
        raise AnalysisError("bridge serial/process binding differs")
    pid = _int(binding.get("process_pid"), "bridge_binding.process_pid", minimum=1)
    argv = binding.get("process_argv")
    if not isinstance(argv, list) or not argv or any(not isinstance(item, str) for item in argv):
        raise AnalysisError("bridge process argv is invalid")
    if not any(Path(item).name == BRIDGE_PROCESS_SCRIPT for item in argv):
        raise AnalysisError("bridge process argv lacks serial_tcp_bridge.py")
    if _option_values(argv, "--host") != [BRIDGE_HOST]:
        raise AnalysisError("bridge process host option differs")
    if _option_values(argv, "--port") != [str(BRIDGE_PORT)]:
        raise AnalysisError("bridge process port option differs")
    if _option_values(argv, "--device") != [BRIDGE_SERIAL_DEVICE]:
        raise AnalysisError("bridge process device option differs")
    if _option_values(argv, "--expect-realpath") != [BRIDGE_SERIAL_DEVICE]:
        raise AnalysisError("bridge process realpath option differs")
    glob_values = _option_values(argv, "--device-glob")
    if len(glob_values) != 1 or BRIDGE_SERIAL_GLOB_TOKEN not in glob_values[0]:
        raise AnalysisError("bridge process device-glob option differs")
    serial_stat = binding.get("serial_stat")
    if not isinstance(serial_stat, Mapping) or set(serial_stat) != {
        "st_dev", "st_ino", "st_rdev", "mode", "character_device"
    } or serial_stat.get("character_device") is not True:
        raise AnalysisError("bridge serial stat does not attest a character device")
    for key in ("st_dev", "st_ino", "st_rdev", "mode"):
        _int(serial_stat.get(key), f"bridge_binding.serial_stat.{key}", minimum=0)
    _parse_utc(binding.get("validated_utc"), "bridge_binding.validated_utc")
    script_descriptor = _descriptor(
        binding.get("bridge_process_script_descriptor"),
        "bridge process script",
    )
    if script_descriptor != {
        "basename": EXPECTED_BRIDGE_BASENAME,
        "size_bytes": EXPECTED_BRIDGE_SIZE,
        "sha256": EXPECTED_BRIDGE_SHA256,
    }:
        raise AnalysisError("bridge process script descriptor differs")
    if Path(binding["bridge_process_script_path"]).name != EXPECTED_BRIDGE_BASENAME:
        raise AnalysisError("bridge process script path basename differs")
    return {"process_pid": pid, "validated": True}


def _option_values(argv: Sequence[str], option: str) -> list[str]:
    return [argv[index + 1] for index, item in enumerate(argv[:-1]) if item == option]


def _frame_descriptor(value: object, label: str, expected_cmd: str) -> None:
    if not isinstance(value, Mapping):
        raise AnalysisError(f"{label} frame descriptor is missing")
    for key in ("begin", "end"):
        if not isinstance(value.get(key), Mapping):
            raise AnalysisError(f"{label} frame {key} is missing")
    begin = value["begin"]
    end = value["end"]
    if begin.get("cmd") != expected_cmd or end.get("cmd") != expected_cmd:
        raise AnalysisError(f"{label} frame command differs")
    if begin.get("seq") != end.get("seq"):
        raise AnalysisError(f"{label} frame sequence differs")
    _int(value.get("payload_size"), f"{label}.payload_size", minimum=1)
    _int(value.get("transcript_size"), f"{label}.transcript_size", minimum=1)
    for key in ("payload_sha256", "transcript_sha256"):
        if not isinstance(value.get(key), str) or SHA256_RE.fullmatch(value[key]) is None:
            raise AnalysisError(f"{label}.{key} is not lowercase SHA-256")


def _expected_command_ids(chunk_count: int) -> list[str]:
    if not _is_int(chunk_count) or chunk_count < 1:
        raise AnalysisError("invalid upload chunk count")
    return [
        "version", "cmdline", "ion_dev", "preclean", "envelope_header",
        *[f"payload_{index:04d}" for index in range(chunk_count)],
        "envelope_footer", "decode", "chmod_binary", "remote_hash_before_run",
        "ion_node_create", "ion_node_chmod", "probe", "remote_hash_after_run",
        "cleanup_node", "cleanup_files", "absence_node", "absence_envelope",
        "absence_binary", "final_version", "final_cmdline", "final_selftest",
    ]


def _validate_command_entry(item: Mapping[str, object], expected_id: str, index: int) -> None:
    evidence_id = item.get("evidence_id")
    if evidence_id != expected_id:
        raise AnalysisError(f"command {index} evidence ID differs")
    argv = item.get("argv")
    if not isinstance(argv, list) or not argv or any(not isinstance(arg, str) for arg in argv):
        raise AnalysisError(f"command {expected_id} argv is invalid")
    begin = item.get("begin")
    end = item.get("end")
    if not isinstance(begin, Mapping) or not isinstance(end, Mapping):
        raise AnalysisError(f"command {expected_id} frame metadata is missing")
    if begin.get("cmd") != argv[0] or end.get("cmd") != argv[0] or begin.get("seq") != end.get("seq"):
        raise AnalysisError(f"command {expected_id} frame identity differs")
    if end.get("status") != "ok" or str(end.get("rc")) not in {"0"}:
        raise AnalysisError(f"command {expected_id} frame is not successful")
    if not isinstance(item.get("extended"), bool):
        raise AnalysisError(f"command {expected_id} extended flag is invalid")
    _parse_utc(item.get("started_utc"), f"command {expected_id}.started_utc")
    _parse_utc(item.get("completed_utc"), f"command {expected_id}.completed_utc")
    if float(item.get("duration_monotonic_s", -1)) < 0 or not math.isfinite(float(item.get("duration_monotonic_s", -1))):
        raise AnalysisError(f"command {expected_id} duration is invalid")
    if not isinstance(item.get("transcript_sha256"), str) or SHA256_RE.fullmatch(item["transcript_sha256"]) is None:
        raise AnalysisError(f"command {expected_id} transcript hash is invalid")
    _int(item.get("transcript_size"), f"command {expected_id}.transcript_size", minimum=1)
    child = item.get("child_exit_code")
    if argv[0] == "run":
        if _int(child, f"command {expected_id}.child_exit_code") != 0:
            raise AnalysisError(f"command {expected_id} child did not exit zero")
    elif child != "NOT_APPLICABLE":
        raise AnalysisError(f"command {expected_id} child-exit marker differs")


def _validate_exact_command_argv(commands: Sequence[Mapping[str, object]], binary_size: int) -> None:
    base64_bytes = ((binary_size + 2) // 3) * 4
    chunk_count = (base64_bytes + MAX_LEGACY_CHUNK - 1) // MAX_LEGACY_CHUNK
    expected_ids = _expected_command_ids(chunk_count)
    actual_ids = [item.get("evidence_id") for item in commands if isinstance(item, Mapping)]
    if actual_ids != expected_ids:
        raise AnalysisError("command sequence differs from fixed runner protocol")
    for index, (item, evidence_id) in enumerate(zip(commands, expected_ids)):
        if not isinstance(item, Mapping):
            raise AnalysisError(f"command {index} is not an object")
        if "error" in item:
            raise AnalysisError(f"command {evidence_id} retains an error")
        _validate_command_entry(item, evidence_id, index)
        argv = item["argv"]
        if evidence_id == "probe" and argv != list(PROBE_ARGV):
            raise AnalysisError("probe command argv differs from fixed 022R argv")
        if evidence_id in {"version", "final_version"} and argv != ["version"]:
            raise AnalysisError(f"{evidence_id} argv differs")
        if evidence_id in {"cmdline", "final_cmdline"} and argv != ["run", TOYBOX, "cat", "/proc/cmdline"]:
            raise AnalysisError(f"{evidence_id} argv differs")
        if evidence_id == "ion_dev" and argv != ["run", TOYBOX, "cat", ION_DEV_PATH]:
            raise AnalysisError("ion_dev argv differs")
        if evidence_id == "preclean" and argv != ["run", TOYBOX, "rm", "-f", REMOTE_ENVELOPE, REMOTE_BINARY, REMOTE_ION]:
            raise AnalysisError("preclean argv differs")
        if evidence_id == "decode" and argv != ["run", TOYBOX, "uudecode", "-o", REMOTE_BINARY, REMOTE_ENVELOPE]:
            raise AnalysisError("decode argv differs")
        if evidence_id == "chmod_binary" and argv != ["run", TOYBOX, "chmod", "700", REMOTE_BINARY]:
            raise AnalysisError("chmod argv differs")
        if evidence_id in {"remote_hash_before_run", "remote_hash_after_run"} and argv != ["run", TOYBOX, "sha256sum", REMOTE_BINARY]:
            raise AnalysisError(f"{evidence_id} argv differs")
        if evidence_id == "ion_node_create" and argv != ["run", TOYBOX, "mknod", REMOTE_ION, "c", "10", "94"]:
            raise AnalysisError("ION create argv differs")
        if evidence_id == "ion_node_chmod" and argv != ["run", TOYBOX, "chmod", "600", REMOTE_ION]:
            raise AnalysisError("ION chmod argv differs")
        if evidence_id == "cleanup_node" and argv != ["run", TOYBOX, "rm", "-f", REMOTE_ION]:
            raise AnalysisError("cleanup node argv differs")
        if evidence_id == "cleanup_files" and argv != ["run", TOYBOX, "rm", "-f", REMOTE_ENVELOPE, REMOTE_BINARY]:
            raise AnalysisError("cleanup files argv differs")
        if evidence_id in {"absence_node", "absence_envelope", "absence_binary"}:
            wanted = {
                "absence_node": REMOTE_ION,
                "absence_envelope": REMOTE_ENVELOPE,
                "absence_binary": REMOTE_BINARY,
            }[evidence_id]
            if argv != ["run", TOYBOX, "test", "!", "-e", wanted]:
                raise AnalysisError(f"{evidence_id} argv differs")
        if evidence_id == "final_selftest" and argv != ["selftest", "status"]:
            raise AnalysisError("final_selftest argv differs")
        if evidence_id == "envelope_header":
            if argv[0] != "appendfile" or argv[1] != REMOTE_ENVELOPE or not argv[2].startswith("begin-base64 700 "):
                raise AnalysisError("envelope header argv differs")
        elif evidence_id == "envelope_footer":
            if argv != ["appendfile", REMOTE_ENVELOPE, "\n====\n"]:
                raise AnalysisError("envelope footer argv differs")
        elif evidence_id.startswith("payload_"):
            if argv[0] != "appendfile" or argv[1] != REMOTE_ENVELOPE or len(argv) != 3:
                raise AnalysisError("envelope payload argv differs")
            payload = argv[2]
            if len(payload) > MAX_LEGACY_CHUNK or not re.fullmatch(r"[A-Za-z0-9+/=]+", payload):
                raise AnalysisError("envelope payload chunk is invalid")


def _validate_lifecycle(lifecycle: object) -> None:
    if not isinstance(lifecycle, Mapping):
        raise AnalysisError("receipt lifecycle is missing")
    timestamps = (
        "acquisition_started_utc", "bridge_validation_started_utc",
        "bridge_validation_completed_utc", "target_preflight_started_utc",
        "target_preflight_completed_utc", "ion_identity_started_utc",
        "ion_identity_completed_utc", "preclean_started_utc", "preclean_completed_utc",
        "upload_started_utc", "upload_completed_utc", "remote_hash_before_started_utc",
        "remote_hash_before_completed_utc", "ion_node_creation_started_utc",
        "ion_node_creation_completed_utc", "probe_dispatch_utc", "probe_child_exit_utc",
        "remote_hash_after_started_utc", "remote_hash_after_completed_utc",
        "cleanup_started_utc", "cleanup_completed_utc", "final_health_started_utc",
        "final_health_completed_utc", "acquisition_completed_utc",
        "receipt_publication_prewrite_utc",
    )
    previous: dt.datetime | None = None
    for key in timestamps:
        stamp = _parse_utc(lifecycle.get(key), f"lifecycle.{key}")
        if previous is not None and stamp < previous:
            raise AnalysisError("lifecycle timestamps are not monotonic")
        previous = stamp
    duration = lifecycle.get("duration_monotonic_s")
    if not _is_int(duration) and not isinstance(duration, (float, int)):
        raise AnalysisError("lifecycle duration is invalid")
    if not math.isfinite(float(duration)) or float(duration) < 0:
        raise AnalysisError("lifecycle duration is invalid")
    absence = lifecycle.get("absence_checks")
    if not isinstance(absence, Mapping):
        raise AnalysisError("lifecycle absence checks are missing")
    for name in ("absence_node", "absence_envelope", "absence_binary"):
        entry = absence.get(name)
        if not isinstance(entry, Mapping) or entry.get("ok") is not True:
            raise AnalysisError(f"lifecycle {name} absence is not proved")
        start = _parse_utc(entry.get("started_utc"), f"lifecycle.{name}.started_utc")
        end = _parse_utc(entry.get("completed_utc"), f"lifecycle.{name}.completed_utc")
        if end < start:
            raise AnalysisError(f"lifecycle {name} timestamps are reversed")


def _validate_pre_dispatch(
    receipt: Mapping[str, object],
    bridge_binding: Mapping[str, object],
) -> None:
    """Require the runner's explicit final revalidation attestation.

    This is intentionally separate from the initial target preflight.  A
    receipt that predates the field, or that merely repeats ``target_bound``,
    is not accepted because it cannot prove the bridge/device identity was
    still bound immediately before dispatch.
    """

    candidate = receipt.get("pre_dispatch_revalidation")
    if not isinstance(candidate, Mapping):
        raise AnalysisError("receipt lacks explicit pre-dispatch revalidation")
    required = {
        "status", "validated_utc", "bridge_binding", "target", "ion_identity",
        "command_argv",
    }
    if set(candidate) != required:
        raise AnalysisError("pre-dispatch revalidation fields are incomplete")
    if candidate.get("status") != "PASS":
        raise AnalysisError("pre-dispatch revalidation status is not PASS")
    final_binding = candidate.get("bridge_binding")
    if not isinstance(final_binding, Mapping):
        raise AnalysisError("pre-dispatch revalidation bridge binding is missing")
    if not isinstance(bridge_binding, Mapping):
        raise AnalysisError("initial bridge binding is missing")
    identity_keys = set(bridge_binding) | set(final_binding)
    if identity_keys - {"validated_utc"} != set(bridge_binding) - {"validated_utc"} or identity_keys - {"validated_utc"} != set(final_binding) - {"validated_utc"}:
        raise AnalysisError("pre-dispatch bridge binding fields differ")
    for key in identity_keys - {"validated_utc"}:
        if final_binding.get(key) != bridge_binding.get(key):
            raise AnalysisError(f"pre-dispatch bridge binding drifted at {key}")
    initial_time = _parse_utc(bridge_binding.get("validated_utc"), "bridge_binding.validated_utc")
    final_time = _parse_utc(final_binding.get("validated_utc"), "pre_dispatch_revalidation.bridge_binding.validated_utc")
    if final_time < initial_time:
        raise AnalysisError("pre-dispatch bridge validation precedes initial validation")
    if final_binding.get("unique_process") is not True:
        raise AnalysisError("pre-dispatch bridge is not uniquely bound")
    candidate_time = candidate.get("validated_utc")
    if _parse_utc(candidate_time, "pre_dispatch_revalidation.validated_utc") != final_time:
        raise AnalysisError("pre-dispatch validation timestamp differs from final bridge binding")
    if candidate.get("target") != EXPECTED_TARGET:
        raise AnalysisError("pre-dispatch revalidation target differs")
    ion_identity = candidate.get("ion_identity")
    if ion_identity != EXPECTED_ION_DEV and not (
        isinstance(ion_identity, Mapping)
        and ion_identity.get("sysfs_identity") == EXPECTED_ION_DEV
        and ion_identity.get("expected_identity") == EXPECTED_ION_DEV
    ):
        raise AnalysisError("pre-dispatch revalidation ION identity differs")
    if candidate.get("command_argv") != list(PROBE_ARGV):
        raise AnalysisError("pre-dispatch revalidation command differs")


def validate_receipt(
    receipt: Mapping[str, object],
    raw_metadata: Mapping[str, object],
    probe: Mapping[str, object],
    sidecars: Mapping[str, Mapping[str, object]] | None = None,
) -> dict[str, object]:
    """Fully validate one PASS private runner receipt against parsed raw data."""

    if not isinstance(receipt, Mapping):
        raise AnalysisError("private receipt is not an object")
    if not isinstance(sidecars, Mapping):
        raise AnalysisError("retained private sidecars are required")
    for key in ("payload", "transcript", "build_receipt"):
        entry = sidecars.get(key)
        if not isinstance(entry, Mapping) or not isinstance(entry.get("data"), bytes) or not isinstance(entry.get("metadata"), Mapping):
            raise AnalysisError(f"retained private {key} sidecar is incomplete")
    required = {
        "schema", "status", "experiment_id", "started_utc", "completed_utc",
        "target_bound", "target", "target_frames", "bridge", "bridge_binding",
        "command_argv", "probe_argv", "dispatch_count", "command_sequence_validated", "probe",
        "probe_completion", "artifacts", "source", "binary", "runner",
        "bridge_script", "build_receipt", "build_receipt_copy", "build", "upload", "remote_binary",
        "ion_device", "cleanup", "final_health", "transcript", "commands",
        "failures", "claims", "scope", "lifecycle",
    }
    required.add("pre_dispatch_revalidation")
    optional: set[str] = set()
    if not required.issubset(receipt) or set(receipt) - required - optional:
        raise AnalysisError("private receipt top-level fields differ")
    if receipt.get("schema") != RECEIPT_SCHEMA or receipt.get("status") != "PASS":
        raise AnalysisError("private receipt is not a PASS of the fixed schema")
    experiment_id = receipt.get("experiment_id")
    if not isinstance(experiment_id, str) or SAFE_ID_RE.fullmatch(experiment_id) is None:
        raise AnalysisError("receipt experiment identity is unsafe")
    started = _parse_utc(receipt.get("started_utc"), "started_utc")
    completed = _parse_utc(receipt.get("completed_utc"), "completed_utc")
    if completed < started:
        raise AnalysisError("receipt completion precedes start")
    if receipt.get("target_bound") is not True or receipt.get("target") != EXPECTED_TARGET:
        raise AnalysisError("exact A908N/SM8150 V2321 target binding is absent")
    if receipt.get("bridge") != {"host": BRIDGE_HOST, "port": BRIDGE_PORT}:
        raise AnalysisError("receipt bridge listener differs")
    bridge_binding = receipt.get("bridge_binding")
    _validate_bridge_binding(bridge_binding)
    if not isinstance(bridge_binding, Mapping):  # guarded above; keeps type narrowing explicit
        raise AnalysisError("bridge binding is not an object")
    _validate_pre_dispatch(receipt, bridge_binding)
    frames = receipt.get("target_frames")
    if not isinstance(frames, Mapping) or set(frames) != {"version", "cmdline"}:
        raise AnalysisError("target preflight frame descriptors are missing")
    _frame_descriptor(frames["version"], "target version", "version")
    _frame_descriptor(frames["cmdline"], "target cmdline", "run")
    if receipt.get("command_argv") != list(PROBE_ARGV) or receipt.get("probe_argv") != list(PROBE_CLI_ARGS):
        raise AnalysisError("private receipt fixed probe argv differs")
    if receipt.get("dispatch_count") != 1:
        raise AnalysisError("private receipt dispatch count is not one")
    if receipt.get("command_sequence_validated") is not True:
        raise AnalysisError("private receipt command sequence was not validated")

    probe_receipt = receipt.get("probe")
    if not isinstance(probe_receipt, Mapping):
        raise AnalysisError("private receipt probe summary is missing")
    if (
        probe_receipt.get("schema") != PROBE_SCHEMA
        or probe_receipt.get("records") != probe.get("records")
        or not _is_int(probe_receipt.get("child_pid"))
        or probe_receipt.get("child_pid") <= 0
        or probe_receipt.get("child_exit_proved") is not True
    ):
        raise AnalysisError("private receipt probe completion/record binding differs")
    retained_raw = _descriptor(probe_receipt.get("raw"), "probe.raw")
    _same_descriptor(retained_raw, raw_metadata, "probe raw input")
    if raw_metadata.get("basename") != RAW_BASENAME:
        raise AnalysisError("raw input basename differs")
    nested_cleanup = probe_receipt.get("cleanup")
    raw_cleanup = probe.get("cleanup")
    if not isinstance(nested_cleanup, Mapping) or not isinstance(raw_cleanup, Mapping):
        raise AnalysisError("private receipt does not retain the probe cleanup record")
    _validate_cleanup_record(nested_cleanup, "private receipt probe cleanup")
    if dict(nested_cleanup) != dict(raw_cleanup):
        raise AnalysisError("private receipt probe cleanup differs from raw JSONL")
    payload_metadata = sidecars["payload"]["metadata"]
    transcript_metadata = sidecars["transcript"]["metadata"]
    build_receipt_metadata = sidecars["build_receipt"]["metadata"]
    payload_descriptor = _descriptor(payload_metadata, "probe payload sidecar")
    transcript_descriptor = _descriptor(transcript_metadata, "transcript sidecar")
    build_receipt_descriptor = _descriptor(build_receipt_metadata, "build receipt sidecar")
    if payload_descriptor["basename"] != RAW_PAYLOAD_BASENAME or transcript_descriptor["basename"] != TRANSCRIPT_BASENAME or build_receipt_descriptor["basename"] != EXPECTED_BUILD_BASENAME:
        raise AnalysisError("private sidecar basenames differ")
    if probe_receipt.get("payload") is None or _descriptor(probe_receipt.get("payload"), "probe.payload") != payload_descriptor:
        raise AnalysisError("probe payload descriptor does not match retained sidecar")
    if _descriptor(receipt.get("transcript"), "receipt transcript") != transcript_descriptor:
        raise AnalysisError("transcript descriptor does not match retained sidecar")
    completion = receipt.get("probe_completion")
    if not isinstance(completion, Mapping) or (
        completion.get("proved") is not True
        or completion.get("method") != "child_exit_receipt"
        or completion.get("pid") != probe_receipt.get("child_pid")
        or completion.get("child_exit_code") != 0
        or completion.get("errors") != []
    ):
        raise AnalysisError("child exit proof is incomplete")

    artifacts = receipt.get("artifacts")
    if not isinstance(artifacts, Mapping):
        raise AnalysisError("receipt artifacts are missing")
    artifact_names = ("source", "binary", "runner", "bridge_script", "build_receipt")
    artifact_values: dict[str, dict[str, object]] = {}
    for name in artifact_names:
        artifact_values[name] = _descriptor(artifacts.get(name), f"artifact {name}")
    if artifact_values["source"]["basename"] != EXPECTED_SOURCE_BASENAME:
        raise AnalysisError("receipt source is not the new v022r source")
    if (
        artifact_values["source"]["size_bytes"] != EXPECTED_SOURCE_SIZE
        or artifact_values["source"]["sha256"] != EXPECTED_SOURCE_SHA256
    ):
        raise AnalysisError("receipt source does not match finalized v022r source pin")
    if artifact_values["binary"]["basename"] != EXPECTED_BINARY_BASENAME:
        raise AnalysisError("receipt binary basename differs")
    if (
        artifact_values["binary"]["size_bytes"] != EXPECTED_BINARY_SIZE
        or artifact_values["binary"]["sha256"] != EXPECTED_BINARY_SHA256
    ):
        raise AnalysisError("receipt binary does not match finalized v022r binary pin")
    if artifact_values["runner"]["basename"] != EXPECTED_RUNNER_BASENAME:
        raise AnalysisError("receipt runner basename differs")
    if not _is_int(EXPECTED_RUNNER_SIZE) or not isinstance(EXPECTED_RUNNER_SHA256, str) or SHA256_RE.fullmatch(EXPECTED_RUNNER_SHA256) is None:
        raise AnalysisError("runner byte pin is pending final pre-dispatch receipt schema")
    if (
        artifact_values["runner"]["size_bytes"] != EXPECTED_RUNNER_SIZE
        or artifact_values["runner"]["sha256"] != EXPECTED_RUNNER_SHA256
    ):
        raise AnalysisError("receipt runner does not match the current pinned runner bytes")
    if artifact_values["bridge_script"]["basename"] != EXPECTED_BRIDGE_BASENAME:
        raise AnalysisError("receipt bridge script basename differs")
    if (
        artifact_values["bridge_script"]["size_bytes"] != EXPECTED_BRIDGE_SIZE
        or artifact_values["bridge_script"]["sha256"] != EXPECTED_BRIDGE_SHA256
    ):
        raise AnalysisError("receipt bridge script does not match finalized bridge pin")
    if isinstance(bridge_binding, Mapping):
        bound_script = bridge_binding.get("bridge_process_script_descriptor")
        if bound_script is None or _descriptor(bound_script, "bridge process script") != artifact_values["bridge_script"]:
            raise AnalysisError("bridge process script descriptor is not artifact-bound")
    if artifact_values["build_receipt"]["basename"] != EXPECTED_BUILD_BASENAME:
        raise AnalysisError("receipt build receipt basename differs")
    for name in artifact_names:
        alias = receipt.get(name)
        _same_descriptor(_descriptor(alias, f"receipt {name}"), artifact_values[name], f"receipt {name} alias")
    build_copy = _descriptor(receipt.get("build_receipt_copy"), "build receipt copy")
    _same_descriptor(build_copy, artifact_values["build_receipt"], "build receipt copy")
    _same_descriptor(build_copy, build_receipt_descriptor, "retained build receipt")
    build = receipt.get("build")
    if not isinstance(build, Mapping) or set(build) != {
        "schema", "compiler_triple", "compiler_version", "compiler_command",
        "static", "reproducible_byte_identical"
    } or build.get("schema") != BUILD_SCHEMA or build.get("compiler_triple") != EXPECTED_COMPILER_TRIPLE or build.get("compiler_version") != EXPECTED_COMPILER_VERSION or not isinstance(build.get("compiler_command"), list) or not build["compiler_command"] or any(not isinstance(item, str) or not item for item in build["compiler_command"]) or Path(build["compiler_command"][0]).name != "aarch64-linux-gnu-gcc" or build.get("static") is not True or build.get("reproducible_byte_identical") is not True:
        raise AnalysisError("build reproducibility summary is incomplete")
    command = build["compiler_command"]
    if (
        len(command) != 9
        or command[1:6] != ["-O2", "-static", "-Wall", "-Wextra", "-Werror"]
        or command[6] != "-o"
        or Path(command[0]).name != "aarch64-linux-gnu-gcc"
        or Path(command[7]).name != EXPECTED_BINARY_BASENAME
        or Path(command[8]).name != EXPECTED_SOURCE_BASENAME
    ):
        raise AnalysisError("build compiler command is not the fixed static build")
    build_document = _json_object(sidecars["build_receipt"]["data"], "retained build receipt")
    build_required = {"schema", "source", "binary", "compiler", "reproducible_byte_identical"}
    if set(build_document) != build_required or build_document.get("schema") != BUILD_SCHEMA:
        raise AnalysisError("retained build receipt schema/fields differ")
    build_source = _descriptor(build_document.get("source"), "retained build source")
    build_binary = _descriptor(build_document.get("binary"), "retained build binary")
    if build_source != artifact_values["source"] or build_binary != artifact_values["binary"]:
        raise AnalysisError("retained build receipt source/binary differs")
    compiler = build_document.get("compiler")
    if not isinstance(compiler, Mapping) or set(compiler) != {"triple", "version", "command", "static"}:
        raise AnalysisError("retained build compiler fields differ")
    compiler_command = compiler.get("command")
    if (
        compiler.get("triple") != EXPECTED_COMPILER_TRIPLE
        or compiler.get("version") != EXPECTED_COMPILER_VERSION
        or compiler.get("static") is not True
        or build_document.get("reproducible_byte_identical") is not True
        or compiler_command != build.get("compiler_command")
    ):
        raise AnalysisError("retained build compiler proof differs")
    upload = receipt.get("upload")
    if not isinstance(upload, Mapping):
        raise AnalysisError("upload receipt is missing")
    binary = artifact_values["binary"]
    if (
        upload.get("binary_size") != binary["size_bytes"]
        or upload.get("binary_sha256") != binary["sha256"]
        or upload.get("base64_bytes") != ((int(binary["size_bytes"]) + 2) // 3) * 4
        or upload.get("chunk_bytes") != MAX_LEGACY_CHUNK
        or upload.get("remote_sha256_verified") is not True
        or upload.get("remote_before_run_sha256") != binary["sha256"]
        or upload.get("remote_path") != REMOTE_BINARY
    ):
        raise AnalysisError("local/upload binary hash binding differs")
    expected_chunks = (((int(binary["size_bytes"]) + 2) // 3) * 4 + MAX_LEGACY_CHUNK - 1) // MAX_LEGACY_CHUNK
    if upload.get("chunk_count") != expected_chunks:
        raise AnalysisError("upload chunk count does not match the pinned binary")
    remote = receipt.get("remote_binary")
    if not isinstance(remote, Mapping) or (
        remote.get("path") != REMOTE_BINARY
        or remote.get("before_run_sha256") != binary["sha256"]
        or remote.get("after_run_sha256") != binary["sha256"]
        or remote.get("unchanged") is not True
    ):
        raise AnalysisError("remote binary hash stability is absent")
    if receipt.get("ion_device") != {
        "sysfs_path": ION_DEV_PATH,
        "sysfs_identity": EXPECTED_ION_DEV,
        "expected_identity": EXPECTED_ION_DEV,
        "temporary_node": REMOTE_ION,
        "node_created": True,
    }:
        raise AnalysisError("same-run ION identity/node binding differs")
    cleanup = receipt.get("cleanup")
    if not isinstance(cleanup, Mapping) or (
        cleanup.get("attempted") is not True
        or cleanup.get("node_removed") is not True
        or cleanup.get("files_removed") is not True
        or cleanup.get("absence_proved") is not True
        or cleanup.get("errors") != []
    ):
        raise AnalysisError("remote cleanup/absence is incomplete")
    health = receipt.get("final_health")
    if not isinstance(health, Mapping) or health.get("attempted") is not True or health.get("ok") is not True or health.get("errors") != [] or health.get("target") != EXPECTED_TARGET:
        raise AnalysisError("final health is incomplete or drifted")
    selftest = health.get("selftest")
    if not isinstance(selftest, Mapping) or set(selftest) != {"passed", "warn", "fail", "duration", "entries"} or any(not _is_int(selftest.get(key)) for key in selftest) or selftest.get("passed") != 11 or selftest.get("warn") != 1 or selftest.get("fail") != 0 or selftest.get("entries") != 12:
        raise AnalysisError("final self-test does not match healthy baseline")
    if receipt.get("failures") != []:
        raise AnalysisError("private receipt retains failures")
    transcript = _descriptor(receipt.get("transcript"), "transcript")
    commands = receipt.get("commands")
    if not isinstance(commands, list) or not commands:
        raise AnalysisError("private command receipt is missing")
    _validate_exact_command_argv(commands, int(binary["size_bytes"]))
    claims = receipt.get("claims")
    if not isinstance(claims, Mapping) or claims.get("interpretation") != "DEFERRED_TO_HOST_ANALYZER" or claims.get("physical_alias") != "NOT_ESTABLISHED":
        raise AnalysisError("runner claims exceed deferred interpretation")
    scope = receipt.get("scope")
    if not isinstance(scope, Mapping) or (
        scope.get("normal_ram_only") is not True
        or scope.get("write_combine_mapping") is not True
        or scope.get("mmio") is not False
        or scope.get("smc") is not False
        or scope.get("protected_memory") is not False
        or scope.get("partition_write") is not False
        or scope.get("automatic_retries") is not False
    ):
        raise AnalysisError("receipt scope is not the fixed normal-RAM boundary")
    _validate_lifecycle(receipt.get("lifecycle"))
    return {
        "schema": RECEIPT_SCHEMA,
        "experiment_id": experiment_id,
        "target": dict(EXPECTED_TARGET),
        "artifacts": artifact_values,
        "binary_sha256": binary["sha256"],
        "binary_size_bytes": binary["size_bytes"],
        "transcript": transcript,
        "records": probe["records"],
        "raw": dict(raw_metadata),
    }


def _load_acquisition(directory: Path) -> dict[str, object]:
    directory = Path(directory)
    _reject_symlink_components(directory)
    try:
        info = directory.lstat()
    except OSError as exc:
        raise AnalysisError("private acquisition directory is unavailable") from exc
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
        raise AnalysisError("private acquisition directory must be a real 0700 directory")
    receipt_data, receipt_metadata = read_stable(directory / RECEIPT_BASENAME, "private receipt")
    raw_data, raw_metadata = read_stable(directory / RAW_BASENAME, "raw JSONL")
    sidecars: dict[str, dict[str, object]] = {}
    for key, filename in (
        ("payload", RAW_PAYLOAD_BASENAME),
        ("transcript", TRANSCRIPT_BASENAME),
        ("build_receipt", EXPECTED_BUILD_BASENAME),
    ):
        data, metadata = read_stable(directory / filename, f"private {key} sidecar")
        sidecars[key] = {"data": data, "metadata": metadata}
    receipt = _json_object(receipt_data, "private receipt")
    probe = validate_probe_jsonl(raw_data)
    validated_receipt = validate_receipt(receipt, raw_metadata, probe, sidecars)
    return {
        "directory": directory,
        "receipt": receipt,
        "receipt_metadata": receipt_metadata,
        "raw_metadata": raw_metadata,
        "raw_data": raw_data,
        "sidecars": sidecars,
        "probe": probe,
        "validated_receipt": validated_receipt,
    }


def reduce_directory(
    directory: Path,
    *,
    dependency_020m: Path | None = None,
    dependency_021: Path | None = None,
) -> dict[str, object]:
    """Load one private run, validate dependencies, and reduce its timing."""

    acquisition = _load_acquisition(Path(directory))
    dependencies = load_dependencies(dependency_020m, dependency_021)
    reduction = reduce_measurements(acquisition["probe"])
    return {**acquisition, "dependencies": dependencies, "reduction": reduction}


def analyse(directory: Path, **kwargs: object) -> dict[str, object]:
    if isinstance(directory, Sequence) and not isinstance(directory, (str, bytes, Path)):
        return reduce_measurements(validate_probe_records(directory))
    return reduce_directory(directory, **kwargs)


analyze = analyse
reduce = reduce_directory
reduce_private_directory = reduce_directory
validate_private_receipt = validate_receipt


def _public_descriptor(value: Mapping[str, object]) -> dict[str, object]:
    return {"basename": value["basename"], "size_bytes": value["size_bytes"], "sha256": value["sha256"]}


def _make_public_manifest_from_result(result: Mapping[str, object]) -> dict[str, object]:
    """Build a redacted manifest from an already validated internal result."""

    if "reduction" not in result or "validated_receipt" not in result or "dependencies" not in result:
        raise AnalysisError("public manifest requires a validated reduction")
    reduction = result["reduction"]
    receipt = result["validated_receipt"]
    dependencies = result["dependencies"]
    if not isinstance(reduction, Mapping) or not isinstance(receipt, Mapping) or not isinstance(dependencies, Mapping):
        raise AnalysisError("validated reduction shape is invalid")
    artifacts = receipt.get("artifacts")
    if not isinstance(artifacts, Mapping):
        raise AnalysisError("validated artifacts are missing")
    winner = reduction.get("candidate_winner")
    public: dict[str, object] = {
        "schema": ANALYSIS_SCHEMA,
        "status": reduction.get("status"),
        "verdict": reduction.get("verdict"),
        "experiment_id": EXPERIMENT_ID,
        "acquisition": {
            "receipt": _public_descriptor(result["receipt_metadata"]),
            "raw": _public_descriptor(receipt["raw"]),
            "record_count": receipt.get("records"),
        },
        "dependencies": {
            "020m": {
                **dependencies["020m"]["metadata"],
                "semantic": dependencies["020m"]["semantic"],
            },
            "021": {
                **dependencies["021"]["metadata"],
                "semantic": dependencies["021"]["semantic"],
            },
        },
        # Keep a compact, analyzer-friendly input index alongside the more
        # descriptive dependency sections.  Every entry is a basename/hash
        # descriptor only; no private path is propagated.
        "inputs": {
            "receipt": _public_descriptor(result["receipt_metadata"]),
            "raw": _public_descriptor(receipt["raw"]),
            "dependency_020m": _public_descriptor(dependencies["020m"]["metadata"]),
            "dependency_021": _public_descriptor(dependencies["021"]["metadata"]),
        },
        "artifacts": {
            name: _public_descriptor(value)
            for name, value in artifacts.items()
            if isinstance(value, Mapping)
        },
        "measurement": {
            "fixed_difference_order": [hex(value) for value in FIXED_DIFFERENCES],
            "allocation_mib": EXPECTED_MIB,
            "requested_pairs": EXPECTED_PAIRS,
            "repetitions": EXPECTED_REPETITIONS,
            "cpu": EXPECTED_CPU,
            "declared_base": EXPECTED_BASE_TEXT,
            "summaries": reduction.get("summaries"),
            "brackets": reduction.get("brackets"),
            "threshold_drift": reduction.get("threshold_drift"),
            "control_drift": reduction.get("control_drift"),
            "drift_limit": reduction.get("drift_limit"),
            "candidate_labels": reduction.get("candidate_labels"),
        },
        "winner": winner,
        "result_disposition": reduction.get("status"),
        "claim_disposition": {
            "model_extension": "SUPPORTED" if winner is not None else "INCONCLUSIVE",
            "alias": "UNKNOWN_NOT_TESTED",
            "physical_page_identity": "UNKNOWN_NOT_TESTED",
            "transform_mutability": "UNKNOWN_NOT_TESTED",
            "protected_boundary": "UNKNOWN_NOT_TESTED",
        },
        "claims": {
            "timing_model_surface": "SUPPORTED" if winner is not None else "INCONCLUSIVE",
            "normal_ram_only": True,
            "physical_page_identity": "UNKNOWN",
            "complete_dram_coordinates": "UNKNOWN",
            "physical_alias": "UNKNOWN",
            "transform_mutability": "UNKNOWN",
            "protected_memory_reach": "UNKNOWN",
            "access_control_bypass": "UNKNOWN",
            "device_authority": "NONE",
        },
        "classification": "CLASS C (TRANSFORM ONLY)",
        "eligibility": "NOT_ELIGIBLE",
        "publication": "REDACTED_FROM_VALIDATED_PRIVATE_RECEIPT",
    }
    return public


def make_public_manifest(
    private_directory: Path,
    *,
    dependency_020m: Path | None = None,
    dependency_021: Path | None = None,
) -> dict[str, object]:
    """Revalidate one private directory and return its redacted manifest."""

    if not isinstance(private_directory, Path):
        raise AnalysisError("public manifest requires a private directory Path")
    result = reduce_directory(
        private_directory,
        dependency_020m=dependency_020m,
        dependency_021=dependency_021,
    )
    return _make_public_manifest_from_result(result)


redacted_public_manifest = make_public_manifest
build_manifest = make_public_manifest


def write_public_manifest(
    path: Path,
    private_directory: Path,
    *,
    dependency_020m: Path | None = None,
    dependency_021: Path | None = None,
) -> Path:
    """Revalidate a private directory and write one fresh public manifest."""

    path = Path(path)
    _reject_symlink_components(path)
    resolved = Path(os.path.abspath(path))
    parts = resolved.parts
    for index in range(len(parts) - 1):
        if parts[index] == "evidence" and parts[index + 1] == "private":
            raise AnalysisError("public manifest cannot be below evidence/private")
    if not isinstance(private_directory, Path):
        raise AnalysisError("public publication requires a private directory Path")
    manifest = make_public_manifest(
        private_directory,
        dependency_020m=dependency_020m,
        dependency_021=dependency_021,
    )
    payload = (json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()
    if b"/tmp/a90-native" in payload or b"/evidence/private" in payload or b'"argv"' in payload or b'"pid"' in payload:
        raise AnalysisError("public manifest contains private paths, argv, or PID material")
    return write_new(resolved, payload, 0o644)


def build_public_manifest(
    directory: Path,
    output: Path | None = None,
    **kwargs: object,
) -> dict[str, object]:
    manifest = make_public_manifest(directory, **kwargs)
    if output is not None:
        write_public_manifest(output, directory, **kwargs)
    return manifest


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        manifest = build_public_manifest(args.directory, args.output)
    except AnalysisError as exc:
        print(f"verification-022r-analysis: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
