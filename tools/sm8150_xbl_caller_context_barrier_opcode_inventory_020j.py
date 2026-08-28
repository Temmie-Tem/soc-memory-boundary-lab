#!/usr/bin/env python3
"""Inventory the first unsupported opcode at each exact 020I stop."""

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
    decode_adrp,
    decode_bl_target,
    decode_ldr_unsigned,
    decode_str_unsigned,
    load_exact,
    write_no_clobber,
)
from tools.sm8150_xbl_static_slot_load_use_020f import (  # noqa: E402
    decode_add_sub_immediate,
    decode_add_sub_register,
    decode_cmp_immediate,
    decode_cmp_register,
    decode_madd,
    decode_mov_register,
    decode_move_wide,
)
from tools.sm8150_xbl_static_slot_function_role_base_origin_020h import (  # noqa: E402
    XBL_NAME,
    XBL_SHA256,
    XBL_SIZE,
    decode_direct_branch,
    decode_ret,
)
from tools.sm8150_xbl_static_slot_caller_context_entry_role_020i import (  # noqa: E402
    build_manifest as build_020i_manifest,
)


SCHEMA = "sm8150-xbl-caller-context-barrier-opcode-inventory-v1"
EXPERIMENT_ID = "020J-caller-context-barrier-opcode-inventory"
MODE = "HOST_ONLY_READ_ONLY"
DEPENDENCY_020I_MANIFEST_NAME = "020I-static-slot-caller-context-entry-role-20260827-01.manifest.json"
DEPENDENCY_020I_MANIFEST_SHA256 = "03c463f667142a21641264ec2e4080d9d5f963c67776037ca9d6194a8a621608"
DEPENDENCY_020I_MANIFEST_PATH = _REPO_ROOT / "evidence/manifests" / DEPENDENCY_020I_MANIFEST_NAME
EXPECTED_UNSUPPORTED_COUNT = 12
EXPECTED_FAMILY_COUNTS = {
    "B_COND": 5,
    "BITFIELD": 1,
    "CBZ_CBNZ": 2,
    "LDP_STP_PAIR": 2,
    "LOGICAL_OR_BITMASK_IMMEDIATE": 2,
}


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _fmt(value: int) -> str:
    return f"0x{value:08x}"


def _load_public_dependency() -> dict[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(DEPENDENCY_020I_MANIFEST_PATH, flags)
    except OSError as exc:
        raise TraceError(f"cannot open exact 020I manifest: {exc}") from exc
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0:
            raise TraceError("020I dependency manifest is not a regular non-empty file")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(fd, min(1 << 20, remaining))
            if not chunk:
                raise TraceError("020I dependency manifest truncated during read")
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
    finally:
        os.close(fd)
    digest = _sha256(payload)
    if digest != DEPENDENCY_020I_MANIFEST_SHA256:
        raise TraceError("020I dependency manifest SHA-256 mismatch")
    if b"evidence/private" in payload:
        raise TraceError("020I dependency manifest contains a private path")
    try:
        manifest = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise TraceError("020I dependency manifest is not valid JSON") from exc
    if not isinstance(manifest, dict) or manifest.get("schema") != "sm8150-xbl-static-slot-caller-context-entry-role-v1" or manifest.get("classification") != "CLASS C (TRANSFORM ONLY)":
        raise TraceError("020I dependency manifest identity changed")
    return {"filename": DEPENDENCY_020I_MANIFEST_NAME, "size": len(payload), "sha256": digest, "experiment_id": manifest.get("experiment_id"), "manifest": manifest}


def _decode_conditional_branch(word: int) -> dict[str, Any] | None:
    if word & 0xFF000010 != 0x54000000:
        return None
    return {"family": "B_COND", "condition": _fmt(word & 0xF)}


def _decode_compare_branch(word: int) -> dict[str, Any] | None:
    if word & 0x7F000000 in (0x34000000, 0x35000000):
        return {"family": "CBZ_CBNZ", "register": _fmt(word & 0x1F)}
    if word & 0x7F000000 in (0x36000000, 0x37000000):
        return {"family": "TBZ_TBNZ", "register": _fmt(word & 0x1F), "bit": (word >> 19) & 0x3F}
    return None


def _decode_pair_memory(word: int) -> dict[str, Any] | None:
    # Scalar GPR LDP/STP uses the 0b10100 family with offset, pre-index or
    # post-index addressing.  Keep the V-bit excluded by the mask; do not
    # infer a mnemonic beyond the proven pair family.
    if word & 0x3E000000 != 0x28000000:
        return None
    return {"family": "LDP_STP_PAIR", "width_bits": 64 if word & (1 << 31) else 32, "rt": word & 0x1F, "rt2": (word >> 10) & 0x1F, "rn": (word >> 5) & 0x1F}


def _decode_bitfield_or_logical(word: int) -> dict[str, Any] | None:
    # ARM64 requires the N bit to agree with the operand width for both
    # bitfield-immediate and logical-immediate forms (N=0 for W, N=1 for X).
    # Reject reserved width/operand combinations instead of broad-mask
    # labelling them as a valid family.
    if ((word >> 22) & 1) != ((word >> 31) & 1):
        return None
    if word & 0x7F800000 in (0x13000000, 0x33000000, 0x53000000):
        return {"family": "BITFIELD", "width_bits": 64 if word & (1 << 31) else 32, "rd": word & 0x1F, "rn": (word >> 5) & 0x1F}
    if word & 0x1F000000 == 0x12000000:
        return {"family": "LOGICAL_OR_BITMASK_IMMEDIATE", "width_bits": 64 if word & (1 << 31) else 32, "rd": word & 0x1F, "rn": (word >> 5) & 0x1F}
    return None


def decode_opcode_family(word: int, va: int = 0) -> dict[str, Any]:
    """Return a strict family label, never a guessed instruction mnemonic."""

    if decode_ret(word) is not None:
        return {"family": "RET_X30"}
    if decode_direct_branch(word, va) is not None:
        return {"family": "DIRECT_B"}
    if decode_bl_target(word, va) is not None:
        return {"family": "DIRECT_BL"}
    result = _decode_conditional_branch(word)
    if result is not None:
        return result
    result = _decode_compare_branch(word)
    if result is not None:
        return result
    if decode_cmp_register(word) is not None or decode_cmp_immediate(word) is not None:
        return {"family": "CMP_SUBS"}
    result = decode_move_wide(word)
    if result is not None:
        operation, width, destination, halfword = result
        return {"family": operation, "width_bits": width, "rd": destination, "halfword": halfword}
    result = _decode_pair_memory(word)
    if result is not None:
        return result
    result = _decode_bitfield_or_logical(word)
    if result is not None:
        return result
    if decode_adrp(word, va) is not None:
        return {"family": "ADRP"}
    if decode_ldr_unsigned(word) is not None:
        return {"family": "LDR_UNSIGNED"}
    if decode_str_unsigned(word) is not None:
        return {"family": "STR_UNSIGNED"}
    if word & 0x3FE00C00 in (0x38600800, 0x38200800) and ((word >> 13) & 0x7) == 0x3 and ((word >> 30) & 0x3) in (0x2, 0x3):
        return {"family": "LDR_STR_REGISTER_OFFSET_UXTX"}
    if decode_add_sub_immediate(word) is not None or decode_add_sub_register(word) is not None:
        return {"family": "ADD_SUB"}
    if decode_madd(word) is not None:
        return {"family": "MADD"}
    if decode_mov_register(word) is not None:
        return {"family": "MOV_REGISTER"}
    return {"family": "UNKNOWN_OPCODE"}


def _rederive_stops(image: Image, dependency: dict[str, Any], firmware_dir: Path) -> list[dict[str, Any]]:
    expected = dependency["manifest"]["census"]["callsites"]
    rederived = build_020i_manifest(firmware_dir)
    if rederived["census"]["callsites"] != expected:
        raise TraceError("020I callsite set changed during re-decode")
    rows = [row for row in expected if row.get("stop_reason") == "UNSUPPORTED"]
    if len(rows) != EXPECTED_UNSUPPORTED_COUNT:
        raise TraceError("020I unsupported-stop cardinality changed")
    for row in rows:
        if row.get("stop_va") is None:
            raise TraceError("020I unsupported row has no stop VA")
    return rows


def build_manifest(firmware_dir: Path = FIRMWARE_DIR) -> dict[str, Any]:
    dependency = _load_public_dependency()
    image = Image(load_exact(firmware_dir / XBL_NAME))
    stops = _rederive_stops(image, dependency, firmware_dir)
    rows: list[dict[str, Any]] = []
    for stop in sorted(stops, key=lambda row: int(row["stop_va"], 16)):
        stop_va = int(stop["stop_va"], 16)
        word = image.word(stop_va)
        family = decode_opcode_family(word, stop_va)
        rows.append({"source_va": stop["source_va"], "target_va": stop["target_va"], "stop_va": stop["stop_va"], "stop_reason": stop["stop_reason"], "family": family, "word_sha256": _sha256(struct.pack("<I", word))})
    counts = Counter(row["family"]["family"] for row in rows)
    if len(rows) != EXPECTED_UNSUPPORTED_COUNT or sum(counts.values()) != EXPECTED_UNSUPPORTED_COUNT:
        raise TraceError("020J inventory cardinality changed")
    if len({row["stop_va"] for row in rows}) != EXPECTED_UNSUPPORTED_COUNT:
        raise TraceError("020J stop VA uniqueness changed")
    if dict(sorted(counts.items())) != EXPECTED_FAMILY_COUNTS:
        raise TraceError("020J opcode-family inventory changed")
    return {"schema": SCHEMA, "experiment_id": EXPERIMENT_ID, "mode": MODE, "device_access": "none", "classification": "CLASS C (TRANSFORM ONLY)", "eligibility": "NOT_ELIGIBLE", "inputs": {"firmware": {"filename": XBL_NAME, "size": XBL_SIZE, "sha256": XBL_SHA256}, "dependency_020i": {key: value for key, value in dependency.items() if key != "manifest"}}, "census": {"unsupported_stop_count": len(rows), "unique_stop_va_count": len({row["stop_va"] for row in rows}), "family_counts": dict(sorted(counts.items())), "stops": rows, "status": "SUPPORTED_BOUNDED_BARRIER_OPCODE_INVENTORY"}, "scope": {"model": "EXACT_020I_UNSUPPORTED_STOP_WORD_ONLY", "no_trace_past_barrier": True, "raw_word_values": "REDACTED_HASH_ONLY", "runtime_base": "UNKNOWN", "physical_to_dram": "UNKNOWN", "mmio_identity": "UNKNOWN", "global_writer_consumer_absence": "UNKNOWN", "never_scan_arbitrary_ranges": True}, "claims": {"PROVED": ["The exact retained A90 XBL and public 020I manifest are bound by size/SHA-256 before analysis.", "Only the first unsupported stop word for each of the 12 exact 020I unsupported windows is classified by strict opcode-family rules; no trace continues past a barrier."], "SUPPORTED": ["Most retained barriers can be separated into ordinary conditional/prologue/bitfield families or remain explicitly unknown within this bounded inventory."], "HYPOTHESIS": ["The unsupported barriers may be ABI/prologue/control artifacts rather than controller programming, but this inventory does not prove that interpretation."], "REFUTED": [], "UNKNOWN": ["Instruction semantics beyond family labels, true function boundaries, runtime execution/currentness/values, indirect paths, object semantics, MMIO/physical/DRAM identity, mutability/locking, protected reach, aliasing and bypass."]}, "boundary_bypass": {"status": "NOT_AUTHORIZED", "device": "none", "smc": "none", "mmio": "none", "protected_memory": "none", "reason": "Host-only stop-word inventory; no activation or live state was accessed."}, "definition_of_done": {"target": {"binding": "PROVED_EXACT_XBL_INPUT_HASH", "marketing_name": "A90 5G", "model": "SM-A908N", "soc": "SM8150", "soc_name": "Snapdragon 855"}, "build": {"status": "NOT_APPLICABLE", "reason": "Interpreted host Python; no device/kernel build."}, "timestamp": {"status": "NOT_APPLICABLE", "reason": "Deterministic publication does not embed a wall-clock timestamp."}, "commands": {"status": "REDACTED_REPRODUCTION_TEMPLATE", "command": "python3 tools/sm8150_xbl_caller_context_barrier_opcode_inventory_020j.py --output <public-manifest-path>", "reason": "Private input paths are redacted; exact hashes are pinned."}, "repetitions": {"status": "NOT_APPLICABLE", "reason": "Host-only static trace; no runtime repetitions."}, "rollback": {"status": "NOT_APPLICABLE", "reason": "Host-only static trace; no device state."}, "recovery": {"status": "NOT_APPLICABLE", "reason": "Host-only static trace; no device state."}, "device_binding": {"status": "NOT_APPLICABLE", "reason": "Host-only static trace; no device contact."}, "tool_and_build": {"tool": f"sm8150_xbl_caller_context_barrier_opcode_inventory_020j.py schema {SCHEMA}", "build": "NOT_APPLICABLE"}}}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--firmware-dir", type=Path, default=FIRMWARE_DIR)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        payload = (json.dumps(build_manifest(args.firmware_dir), indent=1, sort_keys=True) + "\n").encode()
        publication = write_no_clobber(args.output, payload)
    except (TraceError, OSError) as exc:
        print(f"020J: {exc}", file=sys.stderr)
        return 2
    print(f"wrote {publication['basename']} {publication['size_bytes']} bytes sha256={publication['sha256']} mode={publication['mode']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
