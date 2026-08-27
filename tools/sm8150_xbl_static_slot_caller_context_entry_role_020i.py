#!/usr/bin/env python3
"""Bounded caller-context census for the exact 020H block-entry BL sources.

The pass follows only a short backward window before each direct BL source
reported by 020H.  It records strict argument/static-slot definitions and
stops at direct control-flow or unsupported instructions.  It does not infer
true functions, runtime values, physical addresses, MMIO, DRAM, or ownership.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
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
    decode_madd,
    decode_mov_register,
)
from tools.sm8150_xbl_static_slot_function_role_base_origin_020h import (  # noqa: E402
    ROLE_REGION_START,
    ROLE_REGION_END,
    XBL_NAME,
    XBL_SHA256,
    XBL_SIZE,
    build_manifest as build_020h_manifest,
    decode_direct_branch,
    decode_ret,
)


SCHEMA = "sm8150-xbl-static-slot-caller-context-entry-role-v1"
EXPERIMENT_ID = "020I-static-slot-caller-context-entry-role"
MODE = "HOST_ONLY_READ_ONLY"
DEPENDENCY_020H_MANIFEST_NAME = "020H-static-slot-function-role-base-origin-20260827-01.manifest.json"
DEPENDENCY_020H_MANIFEST_SHA256 = "b306ca67675430314289fd79faa2e53b2d67994807d0b08bd91ced9b625faba2"
DEPENDENCY_020H_MANIFEST_PATH = _REPO_ROOT / "evidence/manifests" / DEPENDENCY_020H_MANIFEST_NAME
CALLER_WINDOW_INSTRUCTIONS = 16
STATIC_SLOT_PAGE = 0x9FC3E000
ARGUMENT_REGISTERS = frozenset(range(4))
XZR = 31


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _fmt(value: int) -> str:
    return f"0x{value:08x}"


def _reg_name(register: int, width: int = 64) -> str:
    if register == XZR:
        return "WZR" if width == 32 else "XZR"
    return f"{'W' if width == 32 else 'X'}{register}"


def _register_offset_decoder(word: int) -> tuple[str, int, int, int, int] | None:
    family = word & 0x3FE00C00
    if family not in (0x38600800, 0x38200800) or ((word >> 13) & 0x7) != 0x3:
        return None
    width_code = (word >> 30) & 0x3
    width = 64 if width_code == 0x3 else 32 if width_code == 0x2 else 0
    if not width:
        return None
    return ("LDR" if family == 0x38600800 else "STR", width, word & 0x1F, (word >> 5) & 0x1F, (word >> 16) & 0x1F)


def _strict_recognized(word: int, va: int) -> bool:
    if decode_ret(word) is not None or decode_direct_branch(word, va) is not None or decode_bl_target(word, va) is not None:
        return True
    if decode_ldr_unsigned(word) is not None or decode_str_unsigned(word) is not None or _register_offset_decoder(word) is not None:
        return True
    return any(result is not None for result in (decode_adrp(word, va), decode_add_sub_immediate(word), decode_add_sub_register(word), decode_madd(word), decode_mov_register(word)))


def _load_public_dependency() -> dict[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(DEPENDENCY_020H_MANIFEST_PATH, flags)
    except OSError as exc:
        raise TraceError(f"cannot open exact 020H manifest: {exc}") from exc
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0:
            raise TraceError("020H dependency manifest is not a regular non-empty file")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(fd, min(1 << 20, remaining))
            if not chunk:
                raise TraceError("020H dependency manifest truncated during read")
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
    finally:
        os.close(fd)
    digest = _sha256(payload)
    if digest != DEPENDENCY_020H_MANIFEST_SHA256:
        raise TraceError("020H dependency manifest SHA-256 mismatch")
    if b"evidence/private" in payload:
        raise TraceError("020H dependency manifest contains a private path")
    try:
        manifest = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise TraceError("020H dependency manifest is not valid JSON") from exc
    if not isinstance(manifest, dict) or manifest.get("schema") != "sm8150-xbl-static-slot-function-role-base-origin-v1" or manifest.get("classification") != "CLASS C (TRANSFORM ONLY)":
        raise TraceError("020H dependency manifest identity changed")
    census = manifest.get("census")
    if not isinstance(census, dict) or census.get("role_row_count") != 11 or census.get("unique_access_va_count") != 11:
        raise TraceError("020H dependency census cardinality changed")
    return {"filename": DEPENDENCY_020H_MANIFEST_NAME, "size": len(payload), "sha256": digest, "experiment_id": manifest.get("experiment_id"), "manifest": manifest}


def _rederive_sources(image: Image, dependency: dict[str, Any], firmware_dir: Path) -> list[dict[str, str]]:
    expected_roles = dependency["manifest"]["census"]["roles"]
    rederived = build_020h_manifest(firmware_dir)
    if rederived["census"]["roles"] != expected_roles:
        raise TraceError("020H role rows changed during re-decode")
    sources: dict[str, dict[str, str]] = {}
    for role in expected_roles:
        block = role["block_role"]["block"]
        for source_va in role["block_entry_direct_bl_sources"]:
            row = {"source_va": source_va, "target_block_start": block["start"], "target_block_end_exclusive": block["end_exclusive"], "target_block_terminator": block["terminator"]}
            prior = sources.setdefault(source_va, row)
            if prior != row:
                raise TraceError(f"020H source maps to multiple block entries: {source_va}")
    rows = [sources[key] for key in sorted(sources, key=lambda value: int(value, 16))]
    if len(rows) != 20 or len({row["source_va"] for row in rows}) != 20:
        raise TraceError("020H direct-BL source cardinality changed")
    for row in rows:
        source_va = int(row["source_va"], 16)
        target = int(row["target_block_start"], 16)
        if decode_bl_target(image.word(source_va), source_va) != target:
            raise TraceError(f"020H source/target BL edge changed: {row['source_va']}")
        if not ROLE_REGION_START <= target < ROLE_REGION_END:
            raise TraceError("020I target block escaped the pinned role region")
    return rows


def trace_callsite(image: Image, source_va: int, target_va: int) -> dict[str, Any]:
    segment = image.segment_for(source_va, 4)
    if segment is None or not segment.executable:
        raise TraceError(f"020I source is not executable: {_fmt(source_va)}")
    if decode_bl_target(image.word(source_va), source_va) != target_va:
        raise TraceError(f"020I source is not the expected direct BL: {_fmt(source_va)}")
    definitions: list[dict[str, Any]] = []
    static_page_registers: set[int] = set()
    visited: list[tuple[int, int]] = []
    stop_reason = "WINDOW_LIMIT"
    stop_va: int | None = None
    first_va = source_va

    def clear_register_definition(register: int) -> None:
        definitions[:] = [item for item in definitions if not item.get("register", "").startswith(("X", "W")) or int(item["register"][1:]) != register]
        static_page_registers.discard(register)

    for step in range(1, CALLER_WINDOW_INSTRUCTIONS + 1):
        va = source_va - step * 4
        if image.segment_for(va, 4) != segment:
            stop_reason = "SEGMENT_BOUNDARY"
            stop_va = va
            break
        word = image.word(va)
        if decode_ret(word) is not None:
            stop_reason = "RET"
            stop_va = va
            break
        if decode_direct_branch(word, va) is not None:
            stop_reason = "DIRECT_B"
            stop_va = va
            break
        if decode_bl_target(word, va) is not None:
            stop_reason = "DIRECT_BL"
            stop_va = va
            break
        if not _strict_recognized(word, va):
            stop_reason = "UNSUPPORTED"
            stop_va = va
            break
        visited.append((va, word))
        first_va = va
    for va, word in reversed(visited):
        adrp = decode_adrp(word, va)
        if adrp is not None:
            register, page = adrp
            clear_register_definition(register)
            if register in ARGUMENT_REGISTERS:
                kind = "STATIC_SLOT_ORIGIN" if page == STATIC_SLOT_PAGE else "ARGUMENT_COPY_OR_CONSTANT"
                definitions.append({"kind": kind, "va": _fmt(va), "register": _reg_name(register), "page": _fmt(page)})
            if page == STATIC_SLOT_PAGE:
                static_page_registers.add(register)
            continue
        ldr = decode_ldr_unsigned(word)
        if ldr is not None:
            width, register, base, offset = ldr
            static_base = base in static_page_registers
            clear_register_definition(register)
            if register in ARGUMENT_REGISTERS:
                kind = "STATIC_SLOT_ORIGIN" if static_base else "ARGUMENT_COPY_OR_CONSTANT"
                definitions.append({"kind": kind, "va": _fmt(va), "register": _reg_name(register, width), "address_base": _reg_name(base), "offset": _fmt(offset)})
            static_page_registers.discard(register)
            continue
        str_decoded = decode_str_unsigned(word)
        if str_decoded is not None:
            width, source, base, offset = str_decoded
            if source in ARGUMENT_REGISTERS and base in static_page_registers:
                definitions.append({"kind": "STATIC_SLOT_ORIGIN", "va": _fmt(va), "register": _reg_name(source, width), "address_base": _reg_name(base), "offset": _fmt(offset), "operation": "STR"})
            continue
        register_memory = _register_offset_decoder(word)
        if register_memory is not None:
            operation, width, register, base, index = register_memory
            static_base = base in static_page_registers or index in static_page_registers
            if operation == "LDR":
                clear_register_definition(register)
            if register in ARGUMENT_REGISTERS and static_base:
                definitions.append({"kind": "STATIC_SLOT_ORIGIN", "va": _fmt(va), "register": _reg_name(register, width), "address_base": _reg_name(base), "index_register": _reg_name(index), "operation": operation})
            continue
        arithmetic = decode_add_sub_immediate(word) or decode_add_sub_register(word)
        if arithmetic is not None:
            _operation, destination, source, _value, width = arithmetic
            clear_register_definition(destination)
            if destination in ARGUMENT_REGISTERS:
                definitions.append({"kind": "ARGUMENT_COPY_OR_CONSTANT", "va": _fmt(va), "register": _reg_name(destination, width), "source": _reg_name(source, width)})
            static_page_registers.discard(destination)
            continue
        madd = decode_madd(word)
        if madd is not None:
            width, destination, rn, rm, ra = madd
            clear_register_definition(destination)
            if destination in ARGUMENT_REGISTERS:
                definitions.append({"kind": "ARGUMENT_COPY_OR_CONSTANT", "va": _fmt(va), "register": _reg_name(destination, width), "sources": [_reg_name(rn), _reg_name(rm), _reg_name(ra)]})
            static_page_registers.discard(destination)
            continue
        mov = decode_mov_register(word)
        if mov is not None:
            width, source, destination = mov
            clear_register_definition(destination)
            if destination in ARGUMENT_REGISTERS:
                definitions.append({"kind": "ARGUMENT_COPY_OR_CONSTANT", "va": _fmt(va), "register": _reg_name(destination, width), "source": _reg_name(source, width)})
            static_page_registers.discard(destination)
            continue
        stop_reason = "UNSUPPORTED"
        stop_va = va
        break
    if stop_reason == "UNSUPPORTED":
        classification = "CALLER_CONTEXT_UNSUPPORTED"
    elif any(item["kind"] == "STATIC_SLOT_ORIGIN" for item in definitions):
        classification = "STATIC_SLOT_ORIGIN"
    elif any(item["kind"] == "ARGUMENT_COPY_OR_CONSTANT" for item in definitions):
        classification = "ARGUMENT_COPY_OR_CONSTANT"
    else:
        classification = "ARGUMENT_OR_UNKNOWN"
    return {"source_va": _fmt(source_va), "target_va": _fmt(target_va), "window_start": _fmt(first_va), "window_end_exclusive": _fmt(source_va), "window_instructions": CALLER_WINDOW_INSTRUCTIONS, "stop_reason": stop_reason, "stop_va": None if stop_va is None else _fmt(stop_va), "classification": classification, "definitions": sorted(definitions, key=lambda item: int(item["va"], 16))}


def build_manifest(firmware_dir: Path = FIRMWARE_DIR) -> dict[str, Any]:
    dependency = _load_public_dependency()
    image = Image(load_exact(firmware_dir / XBL_NAME))
    source_rows = _rederive_sources(image, dependency, firmware_dir)
    callsites = [trace_callsite(image, int(row["source_va"], 16), int(row["target_block_start"], 16)) | {"target_block_end_exclusive": row["target_block_end_exclusive"], "target_block_terminator": row["target_block_terminator"]} for row in source_rows]
    if len(callsites) != 20 or len({row["source_va"] for row in callsites}) != 20:
        raise TraceError("020I callsite result cardinality changed")
    classifications = Counter(row["classification"] for row in callsites)
    if classifications != Counter({"CALLER_CONTEXT_UNSUPPORTED": 12, "ARGUMENT_OR_UNKNOWN": 6, "ARGUMENT_COPY_OR_CONSTANT": 2}):
        raise TraceError("020I caller-context classification split changed")
    return {"schema": SCHEMA, "experiment_id": EXPERIMENT_ID, "mode": MODE, "device_access": "none", "classification": "CLASS C (TRANSFORM ONLY)", "eligibility": "NOT_ELIGIBLE", "inputs": {"firmware": {"filename": XBL_NAME, "size": XBL_SIZE, "sha256": XBL_SHA256}, "dependency_020h": {key: value for key, value in dependency.items() if key != "manifest"}}, "census": {"callsite_count": len(callsites), "unique_callsite_va_count": len({row["source_va"] for row in callsites}), "classification_counts": dict(sorted(classifications.items())), "callsites": callsites, "status": "SUPPORTED_BOUNDED_CALLER_CONTEXT_CENSUS"}, "scope": {"model": "EXACT_020H_BLOCK_ENTRY_DIRECT_BL_SOURCES_BACKWARD_16_INSTRUCTIONS", "backward_window_instructions": CALLER_WINDOW_INSTRUCTIONS, "recognized_forms": ["RET_X30", "DIRECT_B", "DIRECT_BL", "LDR_STR_UNSIGNED", "LDR_STR_REGISTER_OFFSET_UXTX", "ADRP", "ADD_SUB", "MADD", "MOV_REGISTER"], "true_function_boundaries": "UNKNOWN", "runtime_base": "UNKNOWN", "physical_to_dram": "UNKNOWN", "mmio_identity": "UNKNOWN", "global_writer_consumer_absence": "UNKNOWN", "never_scan_arbitrary_ranges": True}, "claims": {"PROVED": ["The exact retained A90 XBL and public 020H role manifest are bound by size/SHA-256 before tracing.", "Each of the 20 exact 020H block-entry direct-BL source VAs is checked against its target and traced only within the stated backward window with explicit stop reasons."], "SUPPORTED": ["The bounded caller contexts provide local static-slot or argument-shaped evidence without establishing true functions, runtime pointers, or controller programming."], "HYPOTHESIS": ["Some direct callsites may belong to initialization/helper paths that prepare local configuration state."], "REFUTED": [], "UNKNOWN": ["True function boundaries, runtime execution/currentness/values, indirect calls/callee effects, object semantics, global writer/consumer absence, ABI effects, MMIO/physical/DRAM identity, mutability/locking, protected reach, aliasing and bypass."]}, "boundary_bypass": {"status": "NOT_AUTHORIZED", "device": "none", "smc": "none", "mmio": "none", "protected_memory": "none", "reason": "Host-only static caller-context census; no activation or live state was accessed."}, "definition_of_done": {"target": {"binding": "PROVED_EXACT_XBL_INPUT_HASH", "marketing_name": "A90 5G", "model": "SM-A908N", "soc": "SM8150", "soc_name": "Snapdragon 855"}, "build": {"status": "NOT_APPLICABLE", "reason": "Interpreted host Python; no device/kernel build."}, "timestamp": {"status": "NOT_APPLICABLE", "reason": "Deterministic publication does not embed a wall-clock timestamp."}, "commands": {"status": "REDACTED_REPRODUCTION_TEMPLATE", "command": "python3 tools/sm8150_xbl_static_slot_caller_context_entry_role_020i.py --output <public-manifest-path>", "reason": "Private input paths are redacted; exact hashes are pinned."}, "repetitions": {"status": "NOT_APPLICABLE", "reason": "Host-only static trace; no runtime repetitions."}, "rollback": {"status": "NOT_APPLICABLE", "reason": "Host-only static trace; no device state."}, "recovery": {"status": "NOT_APPLICABLE", "reason": "Host-only static trace; no device state."}, "device_binding": {"status": "NOT_APPLICABLE", "reason": "Host-only static trace; no device contact."}, "tool_and_build": {"tool": f"sm8150_xbl_static_slot_caller_context_entry_role_020i.py schema {SCHEMA}", "build": "NOT_APPLICABLE"}}}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--firmware-dir", type=Path, default=FIRMWARE_DIR)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        payload = (json.dumps(build_manifest(args.firmware_dir), indent=1, sort_keys=True) + "\n").encode()
        publication = write_no_clobber(args.output, payload)
    except (TraceError, OSError) as exc:
        print(f"020I: {exc}", file=sys.stderr)
        return 2
    print(f"wrote {publication['basename']} {publication['size_bytes']} bytes sha256={publication['sha256']} mode={publication['mode']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
