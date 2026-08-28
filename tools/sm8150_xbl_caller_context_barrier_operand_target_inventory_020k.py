#!/usr/bin/env python3
"""Inventory operands and local targets for the exact 020J stop words.

This pass is deliberately one-word and fail-closed: it reads the exact public
020J manifest, re-derives that manifest from the pinned XBL, and decodes only
the first stop word in each of its twelve unsupported rows.  It does not
continue a path, infer a function, or promote any value to runtime/MMIO/PA or
DRAM meaning.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import struct
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Sequence

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tools.sm8150_xbl_second_caller_field_use_020d import (  # noqa: E402
    FIRMWARE_DIR,
    Image,
    TraceError,
    load_exact,
    write_no_clobber,
)
from tools import sm8150_xbl_caller_context_barrier_opcode_inventory_020j as inventory_020j  # noqa: E402


SCHEMA = "sm8150-xbl-caller-context-barrier-operand-target-inventory-v1"
EXPERIMENT_ID = "020K-caller-context-barrier-operand-target-inventory"
MODE = "HOST_ONLY_READ_ONLY"
XBL_NAME = "xbl--sdb1.bin"
XBL_SIZE = 4_194_304
XBL_SHA256 = "e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37"
DEPENDENCY_020J_MANIFEST_NAME = "020J-caller-context-barrier-opcode-inventory-20260827-01.manifest.json"
DEPENDENCY_020J_MANIFEST_SIZE = 7_657
DEPENDENCY_020J_MANIFEST_SHA256 = "1fdb1f4ade702fdb2d6ffdc68669a9710c8152e225f89f02fb65c0d10f4c3d55"
DEPENDENCY_020J_TOOL_NAME = "sm8150_xbl_caller_context_barrier_opcode_inventory_020j.py"
DEPENDENCY_020J_TOOL_SIZE = 13_337
DEPENDENCY_020J_TOOL_SHA256 = "4ab87464f17bc8887e62c5bb4eba7c693b2ec299575fc38f8bd9f7847c50dc1b"
DEPENDENCY_020J_MANIFEST_PATH = _REPO_ROOT / "evidence/manifests" / DEPENDENCY_020J_MANIFEST_NAME
DEPENDENCY_020J_TOOL_PATH = _REPO_ROOT / "tools" / DEPENDENCY_020J_TOOL_NAME
EXPECTED_STOP_COUNT = 12
EXPECTED_FAMILY_COUNTS = {
    "B_COND": 5,
    "BITFIELD": 1,
    "CBZ_CBNZ": 2,
    "LDP_STP_PAIR": 2,
    "LOGICAL_OR_BITMASK_IMMEDIATE": 2,
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fmt(value: int) -> str:
    return f"0x{value:08x}"


def _sign_extend(value: int, bits: int) -> int:
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def _read_pinned(path: Path, size: int, digest: str, label: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise TraceError(f"cannot open exact {label}: {exc}") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size != size:
            raise TraceError(f"exact {label} size/type mismatch")
        chunks: list[bytes] = []
        remaining = size
        while remaining:
            chunk = os.read(fd, min(1 << 20, remaining))
            if not chunk:
                raise TraceError(f"exact {label} truncated during read")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise TraceError(f"exact {label} changed during read")
        payload = b"".join(chunks)
    finally:
        os.close(fd)
    if len(payload) != size or _sha256(payload) != digest:
        raise TraceError(f"exact {label} SHA-256 mismatch")
    return payload


def _load_dependency() -> dict[str, Any]:
    payload = _read_pinned(
        DEPENDENCY_020J_MANIFEST_PATH,
        DEPENDENCY_020J_MANIFEST_SIZE,
        DEPENDENCY_020J_MANIFEST_SHA256,
        "020J manifest",
    )
    if b"evidence/private" in payload:
        raise TraceError("020J manifest contains a private path")
    try:
        manifest = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise TraceError("020J manifest is not valid JSON") from exc
    if not isinstance(manifest, dict) or manifest.get("schema") != inventory_020j.SCHEMA:
        raise TraceError("020J manifest identity changed")
    if manifest.get("classification") != "CLASS C (TRANSFORM ONLY)" or manifest.get("eligibility") != "NOT_ELIGIBLE":
        raise TraceError("020J class/eligibility boundary changed")
    census = manifest.get("census")
    if not isinstance(census, dict) or census.get("unsupported_stop_count") != EXPECTED_STOP_COUNT:
        raise TraceError("020J stop cardinality changed")
    stops = census.get("stops")
    if not isinstance(stops, list) or len(stops) != EXPECTED_STOP_COUNT:
        raise TraceError("020J stop rows are malformed")
    return {
        "filename": DEPENDENCY_020J_MANIFEST_NAME,
        "size": len(payload),
        "sha256": DEPENDENCY_020J_MANIFEST_SHA256,
        "experiment_id": manifest.get("experiment_id"),
        "manifest": manifest,
    }


def decode_b_cond(word: int, va: int) -> dict[str, Any] | None:
    """Decode B.cond, including its signed imm19 target arithmetic."""

    if not isinstance(word, int) or not 0 <= word <= 0xFFFFFFFF or word & 0xFF000010 != 0x54000000:
        return None
    imm19_raw = (word >> 5) & 0x7FFFF
    imm19 = _sign_extend(imm19_raw, 19)
    return {
        "family": "B_COND",
        "condition": word & 0xF,
        "imm19": imm19,
        "imm19_raw": imm19_raw,
        "target_va": va + (imm19 << 2),
    }


def decode_cbz_cbnz(word: int, va: int) -> dict[str, Any] | None:
    """Decode CBZ/CBNZ scalar GPR form and its signed imm19 target."""

    if not isinstance(word, int) or not 0 <= word <= 0xFFFFFFFF:
        return None
    if word & 0x7F000000 not in (0x34000000, 0x35000000):
        return None
    sf = (word >> 31) & 1
    op = (word >> 24) & 1
    imm19_raw = (word >> 5) & 0x7FFFF
    imm19 = _sign_extend(imm19_raw, 19)
    return {
        "family": "CBZ_CBNZ",
        "sf": sf,
        "width_bits": 64 if sf else 32,
        "op": op,
        "operation": "CBNZ" if op else "CBZ",
        "rt": word & 0x1F,
        "imm19": imm19,
        "imm19_raw": imm19_raw,
        "target_va": va + (imm19 << 2),
    }


def decode_pair_memory(word: int) -> dict[str, Any] | None:
    """Decode scalar GPR LDP/STP offset, pre-index, or post-index forms."""

    if not isinstance(word, int) or not 0 <= word <= 0xFFFFFFFF:
        return None
    # Scalar pair: bits 29:27=101 and V=0.  The mode and L fields are
    # validated below; this mask excludes SIMD/FP vector pairs.
    if word & 0x3E000000 != 0x28000000 or word & (1 << 26):
        return None
    opc = (word >> 30) & 0x3
    load = (word >> 22) & 1
    sign_mode = (word >> 23) & 1
    index_mode = (word >> 24) & 1
    # For scalar GPR pairs, opc selects the element width (00=W, 10=X);
    # L independently selects load versus store.  opc=01/11 are not scalar
    # GPR pair encodings here and must not be admitted by the broad family
    # mask.
    if opc not in (0, 2):
        return None
    mode_bits = (word >> 23) & 0x3
    mode = {1: "POST_INDEX", 2: "OFFSET", 3: "PRE_INDEX"}.get(mode_bits)
    if mode is None:
        return None
    width_bits = 64 if opc >= 2 else 32
    scale = 8 if width_bits == 64 else 4
    imm7_raw = (word >> 15) & 0x7F
    imm7 = _sign_extend(imm7_raw, 7)
    return {
        "family": "LDP_STP_PAIR",
        "opc": opc,
        "L": load,
        "S": sign_mode,
        "index": index_mode,
        "V": 0,
        "operation": "LDP" if load else "STP",
        "width_bits": width_bits,
        "addressing_mode": mode,
        "imm7": imm7,
        "imm7_raw": imm7_raw,
        "offset_bytes": imm7 * scale,
        "rt": word & 0x1F,
        "rt2": (word >> 10) & 0x1F,
        "rn": (word >> 5) & 0x1F,
    }


def decode_logical_immediate(word: int) -> dict[str, Any] | None:
    """Decode strict scalar logical-immediate fields."""

    if not isinstance(word, int) or not 0 <= word <= 0xFFFFFFFF or word & 0x1F800000 != 0x12000000:
        return None
    sf = (word >> 31) & 1
    op = (word >> 30) & 1
    set_flags = (word >> 29) & 1
    n = (word >> 22) & 1
    immr = (word >> 16) & 0x3F
    imms = (word >> 10) & 0x3F
    if n != sf or (not sf and imms == 0x3F):
        return None
    return {
        "family": "LOGICAL_OR_BITMASK_IMMEDIATE",
        "sf": sf,
        "width_bits": 64 if sf else 32,
        "op": op,
        "S": set_flags,
        "N": n,
        "immr": immr,
        "imms": imms,
        "rn": (word >> 5) & 0x1F,
        "rd": word & 0x1F,
    }


def decode_bitfield(word: int) -> dict[str, Any] | None:
    """Decode strict scalar bitfield-immediate/BFXIL fields."""

    if not isinstance(word, int) or not 0 <= word <= 0xFFFFFFFF or word & 0x1F800000 != 0x13000000:
        return None
    sf = (word >> 31) & 1
    opc = (word >> 29) & 0x3
    n = (word >> 22) & 1
    immr = (word >> 16) & 0x3F
    imms = (word >> 10) & 0x3F
    if word & (1 << 26) or opc == 3 or n != sf:
        return None
    if not sf and (immr >= 32 or imms >= 32):
        return None
    operation = {0: "SBFM", 1: "BFM", 2: "UBFM"}[opc]
    result: dict[str, Any] = {
        "family": "BITFIELD",
        "sf": sf,
        "width_bits": 64 if sf else 32,
        "opc": opc,
        "operation": operation,
        "N": n,
        "immr": immr,
        "imms": imms,
        "rn": (word >> 5) & 0x1F,
        "rd": word & 0x1F,
    }
    if opc == 1 and immr <= imms:
        result["alias"] = "BFXIL"
    return result


def _target_in_segment(image: Image, stop_va: int, target_va: int) -> dict[str, Any]:
    if stop_va % 4 or target_va % 4:
        raise TraceError(f"unaligned branch stop/target at {_fmt(stop_va)}")
    segment = image.segment_for(stop_va, 4)
    target_segment = image.segment_for(target_va, 4)
    if segment is None or not segment.executable or target_segment != segment:
        raise TraceError(f"branch target escaped executable segment at {_fmt(stop_va)}")
    return {"target_va": _fmt(target_va), "target_in_same_executable_segment": True}


def decode_stop(image: Image, stop_va: int, expected_family: str) -> dict[str, Any]:
    if stop_va % 4:
        raise TraceError(f"stop VA is not instruction-aligned: {_fmt(stop_va)}")
    segment = image.segment_for(stop_va, 4)
    if segment is None or not segment.executable:
        raise TraceError(f"stop is not an executable file-backed word: {_fmt(stop_va)}")
    word = image.word(stop_va)
    decoded: dict[str, Any] | None
    if expected_family == "B_COND":
        decoded = decode_b_cond(word, stop_va)
    elif expected_family == "CBZ_CBNZ":
        decoded = decode_cbz_cbnz(word, stop_va)
    elif expected_family == "LDP_STP_PAIR":
        decoded = decode_pair_memory(word)
    elif expected_family == "LOGICAL_OR_BITMASK_IMMEDIATE":
        decoded = decode_logical_immediate(word)
    elif expected_family == "BITFIELD":
        decoded = decode_bitfield(word)
    else:
        decoded = None
    if decoded is None or decoded.get("family") != expected_family:
        raise TraceError(f"020K family/word mismatch at {_fmt(stop_va)}")
    if "target_va" in decoded:
        decoded.update(_target_in_segment(image, stop_va, int(decoded.pop("target_va"))))
    return decoded


def _rederive_stops(image: Image, dependency: dict[str, Any], firmware_dir: Path) -> list[dict[str, Any]]:
    expected = dependency["manifest"]["census"]["stops"]
    rederived = inventory_020j.build_manifest(firmware_dir)
    if rederived.get("census", {}).get("stops") != expected:
        raise TraceError("020J stop rows changed during re-decode")
    if len(expected) != EXPECTED_STOP_COUNT or len({row.get("stop_va") for row in expected}) != EXPECTED_STOP_COUNT:
        raise TraceError("020J stop cardinality/uniqueness changed")
    counts = Counter(row.get("family", {}).get("family") for row in expected)
    if dict(sorted(counts.items())) != EXPECTED_FAMILY_COUNTS:
        raise TraceError("020J family counts changed")
    for row in expected:
        if row.get("stop_reason") != "UNSUPPORTED" or not isinstance(row.get("stop_va"), str):
            raise TraceError("020J row is not an unsupported stop")
        stop_va = int(row["stop_va"], 16)
        word = image.word(stop_va)
        if _sha256(struct.pack("<I", word)) != row.get("word_sha256"):
            raise TraceError(f"020J stop-word hash changed at {_fmt(stop_va)}")
    return expected


def build_manifest(firmware_dir: Path = FIRMWARE_DIR) -> dict[str, Any]:
    # Pin the producer source before relying on its re-derived output.
    _read_pinned(DEPENDENCY_020J_TOOL_PATH, DEPENDENCY_020J_TOOL_SIZE, DEPENDENCY_020J_TOOL_SHA256, "020J tool source")
    dependency = _load_dependency()
    # Bind the exact firmware locally as part of this tool's contract.  The
    # imported 020D loader has the same checks, but relying on its constants
    # would make these 020K pins metadata-only and mutation-unverifiable.
    image = Image(_read_pinned(firmware_dir / XBL_NAME, XBL_SIZE, XBL_SHA256, "XBL firmware"))
    stops = _rederive_stops(image, dependency, firmware_dir)
    rows: list[dict[str, Any]] = []
    for stop in sorted(stops, key=lambda row: int(row["stop_va"], 16)):
        stop_va = int(stop["stop_va"], 16)
        expected_family = stop["family"]["family"]
        word = image.word(stop_va)
        operands = decode_stop(image, stop_va, expected_family)
        rows.append(
            {
                "source_va": stop["source_va"],
                "target_va": stop["target_va"],
                "stop_va": stop["stop_va"],
                "stop_reason": stop["stop_reason"],
                "family": expected_family,
                "operands": operands,
                "word_sha256": _sha256(struct.pack("<I", word)),
            }
        )
    counts = Counter(row["family"] for row in rows)
    if len(rows) != EXPECTED_STOP_COUNT or len({row["stop_va"] for row in rows}) != EXPECTED_STOP_COUNT:
        raise TraceError("020K stop cardinality changed")
    if dict(sorted(counts.items())) != EXPECTED_FAMILY_COUNTS:
        raise TraceError("020K family counts changed")
    return {
        "schema": SCHEMA,
        "experiment_id": EXPERIMENT_ID,
        "mode": MODE,
        "device_access": "none",
        "classification": "CLASS C (TRANSFORM ONLY)",
        "eligibility": "NOT_ELIGIBLE",
        "inputs": {
            "firmware": {"filename": XBL_NAME, "size": XBL_SIZE, "sha256": XBL_SHA256},
            "dependency_020j_manifest": {key: value for key, value in dependency.items() if key != "manifest"},
            "dependency_020j_tool": {"filename": DEPENDENCY_020J_TOOL_NAME, "size": DEPENDENCY_020J_TOOL_SIZE, "sha256": DEPENDENCY_020J_TOOL_SHA256},
        },
        "census": {
            "stop_count": len(rows),
            "unique_stop_va_count": len({row["stop_va"] for row in rows}),
            "family_counts": dict(sorted(counts.items())),
            "stops": rows,
            "status": "SUPPORTED_BOUNDED_STOP_OPERAND_TARGET_INVENTORY",
        },
        "scope": {
            "model": "EXACT_020J_STOP_WORD_OPERANDS_AND_LOCAL_BRANCH_TARGETS_ONLY",
            "decode_one_word_per_stop": True,
            "no_trace_past_barrier": True,
            "raw_word_values": "REDACTED_HASH_ONLY",
            "branch_target_scope": "SAME_EXECUTABLE_FILE_BACKED_SEGMENT",
            "runtime_execution": "UNKNOWN",
            "true_function_boundaries": "UNKNOWN",
            "runtime_pointer_or_pa": "UNKNOWN",
            "mmio_or_dram_identity": "UNKNOWN",
            "never_scan_arbitrary_ranges": True,
        },
        "claims": {
            "PROVED": [
                "The exact XBL, 020J producer source, and public 020J stop manifest are bound by size and SHA-256 before decoding.",
                "Only the first stop word for each of the 12 exact 020J unsupported rows is decoded; branch targets are checked to remain in the same executable file-backed segment.",
                "The exact family split is B_COND=5, CBZ_CBNZ=2, LDP_STP_PAIR=2, LOGICAL_OR_BITMASK_IMMEDIATE=2, and BITFIELD=1.",
            ],
            "SUPPORTED": [
                "The bounded operands and local branch-target arithmetic distinguish control/prologue and bitfield/logical shapes without extending the caller trace."
            ],
            "HYPOTHESIS": [],
            "REFUTED": [],
            "UNKNOWN": [
                "Instruction effects beyond decoded fields, branch execution/order, true function boundaries, runtime values/currentness, indirect paths, physical/MMIO/DRAM identity, mutability, protected reach, aliasing, and bypass."
            ],
        },
        "boundary_bypass": {
            "status": "NOT_AUTHORIZED",
            "device": "none",
            "smc": "none",
            "mmio": "none",
            "protected_memory": "none",
            "reason": "Host-only one-word operand inventory; no activation or live state was accessed.",
        },
        "definition_of_done": {
            "target": {"binding": "PROVED_EXACT_XBL_INPUT_HASH", "marketing_name": "A90 5G", "model": "SM-A908N", "soc": "SM8150", "soc_name": "Snapdragon 855"},
            "build": {"status": "NOT_APPLICABLE", "reason": "Interpreted host Python; no device/kernel build."},
            "timestamp": {"status": "NOT_APPLICABLE", "reason": "Deterministic publication does not embed a wall-clock timestamp."},
            "commands": {"status": "REDACTED_REPRODUCTION_TEMPLATE", "command": "python3 tools/sm8150_xbl_caller_context_barrier_operand_target_inventory_020k.py --output <public-manifest-path>", "reason": "Private input paths are redacted; exact hashes are pinned."},
            "repetitions": {"status": "NOT_APPLICABLE", "reason": "Host-only static inventory; no runtime repetitions."},
            "rollback": {"status": "NOT_APPLICABLE", "reason": "Host-only static inventory; no device state."},
            "recovery": {"status": "NOT_APPLICABLE", "reason": "Host-only static inventory; no device state."},
            "device_binding": {"status": "NOT_APPLICABLE", "reason": "No device contact."},
            "tool_and_build": {"tool": f"{Path(__file__).name} schema {SCHEMA}", "build": "NOT_APPLICABLE"},
        },
    }


def encode_manifest(manifest: dict[str, Any]) -> bytes:
    return (json.dumps(manifest, indent=1, sort_keys=True) + "\n").encode()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--firmware-dir", type=Path, default=FIRMWARE_DIR)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        publication = write_no_clobber(args.output, encode_manifest(build_manifest(args.firmware_dir)))
    except (TraceError, OSError) as exc:
        print(f"020K: {exc}", file=sys.stderr)
        return 2
    print(f"wrote {publication['basename']} {publication['size_bytes']} bytes sha256={publication['sha256']} mode={publication['mode']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
