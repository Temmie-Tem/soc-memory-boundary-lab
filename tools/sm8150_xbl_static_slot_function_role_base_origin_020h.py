#!/usr/bin/env python3
"""Bounded role and base-origin census for the exact 020G access witnesses.

This pass identifies only return/direct-branch-delimited local blocks in the
small XBL region containing the 020G witnesses.  It records strict direct-call
edges and a short backward base-register trace.  A block or definition that
cannot be decoded unambiguously is retained as UNKNOWN/unsupported rather than
being promoted to a function, pointer, physical address, or controller.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

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
from tools.sm8150_xbl_static_slot_pointer_object_census_020g import (  # noqa: E402
    XBL_NAME,
    XBL_SHA256,
    XBL_SIZE,
    build_manifest as build_020g_manifest,
)


SCHEMA = "sm8150-xbl-static-slot-function-role-base-origin-v1"
EXPERIMENT_ID = "020H-static-slot-function-role-base-origin"
MODE = "HOST_ONLY_READ_ONLY"
DEPENDENCY_020G_MANIFEST_NAME = "020G-static-slot-pointer-object-census-20260827-01.manifest.json"
DEPENDENCY_020G_MANIFEST_SHA256 = "f534efeee1e12f18d3af40c107dbc6fbe938eae16d9013aa088d22d7c880af3e"
DEPENDENCY_020G_MANIFEST_PATH = _REPO_ROOT / "evidence/manifests" / DEPENDENCY_020G_MANIFEST_NAME
ROLE_REGION_START = 0x9FC26E84
ROLE_REGION_END = 0x9FC26F60
ROLE_REGION_SIZE = ROLE_REGION_END - ROLE_REGION_START
ROLE_REGION_SHA256 = "f73b378e946379833124c814ad280086c7666123bd9d70985963ca6e1071eaba"
BACKWARD_WINDOW_INSTRUCTIONS = 16
XZR = 31


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _fmt(value: int) -> str:
    return f"0x{value:08x}"


def _reg_name(register: int, width: int = 64) -> str:
    if register == XZR:
        return "WZR" if width == 32 else "XZR"
    return f"{'W' if width == 32 else 'X'}{register}"


def _load_public_dependency() -> dict[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(DEPENDENCY_020G_MANIFEST_PATH, flags)
    except OSError as exc:
        raise TraceError(f"cannot open exact 020G manifest: {exc}") from exc
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0:
            raise TraceError("020G dependency manifest is not a regular non-empty file")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(fd, min(1 << 20, remaining))
            if not chunk:
                raise TraceError("020G dependency manifest truncated during read")
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
    finally:
        os.close(fd)
    digest = _sha256(payload)
    if digest != DEPENDENCY_020G_MANIFEST_SHA256:
        raise TraceError("020G dependency manifest SHA-256 mismatch")
    if b"evidence/private" in payload:
        raise TraceError("020G dependency manifest contains a private path")
    try:
        manifest = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise TraceError("020G dependency manifest is not valid JSON") from exc
    if not isinstance(manifest, dict) or manifest.get("schema") != "sm8150-xbl-static-slot-pointer-object-census-v1" or manifest.get("classification") != "CLASS C (TRANSFORM ONLY)":
        raise TraceError("020G dependency manifest identity changed")
    if manifest.get("census", {}).get("event_count") != 12 or manifest.get("census", {}).get("unique_access_va_count") != 11:
        raise TraceError("020G dependency census cardinality changed")
    return {"filename": DEPENDENCY_020G_MANIFEST_NAME, "size": len(payload), "sha256": digest, "experiment_id": manifest.get("experiment_id"), "manifest": manifest}


def decode_ret(word: int) -> int | None:
    """Decode only the ordinary RET X30 form."""

    if not isinstance(word, int) or not 0 <= word <= 0xFFFFFFFF:
        return None
    if word & 0xFFFFFC1F != 0xD65F0000:
        return None
    link_register = (word >> 5) & 0x1F
    return link_register if link_register == 30 else None


def decode_direct_branch(word: int, va: int) -> int | None:
    """Decode an unconditional direct B and compute its target."""

    if not isinstance(word, int) or not 0 <= word <= 0xFFFFFFFF or word & 0xFC000000 != 0x14000000:
        return None
    immediate = word & 0x03FFFFFF
    if immediate & (1 << 25):
        immediate -= 1 << 26
    return va + (immediate << 2)


def _words_in_region(image: Image) -> dict[int, int]:
    segment = image.segment_for(ROLE_REGION_START, ROLE_REGION_SIZE)
    if segment is None or not segment.executable:
        raise TraceError("020H role region is not a single executable file-backed range")
    payload = image.read(ROLE_REGION_START, ROLE_REGION_SIZE)
    if _sha256(payload) != ROLE_REGION_SHA256:
        raise TraceError("020H role region SHA-256 mismatch")
    return {va: image.word(va) for va in range(ROLE_REGION_START, ROLE_REGION_END, 4)}


@dataclass(frozen=True)
class Block:
    start: int
    end: int
    terminator: str

    def record(self) -> dict[str, Any]:
        return {"start": _fmt(self.start), "end_exclusive": _fmt(self.end), "size": self.end - self.start, "terminator": self.terminator}


def recover_blocks(image: Image, words: dict[int, int]) -> list[Block]:
    blocks: list[Block] = []
    start = ROLE_REGION_START
    for va in range(ROLE_REGION_START, ROLE_REGION_END, 4):
        word = words[va]
        if decode_ret(word) is not None:
            blocks.append(Block(start, va + 4, "RET"))
            start = va + 4
            continue
        if decode_direct_branch(word, va) is not None:
            blocks.append(Block(start, va + 4, "DIRECT_BRANCH"))
            start = va + 4
    if start < ROLE_REGION_END:
        blocks.append(Block(start, ROLE_REGION_END, "REGION_END"))
    if not blocks or blocks[0].start != ROLE_REGION_START or blocks[-1].end != ROLE_REGION_END:
        raise TraceError("020H block partition does not cover the pinned role region")
    return blocks


def _block_for(blocks: Sequence[Block], va: int) -> Block:
    matches = [block for block in blocks if block.start <= va < block.end]
    if len(matches) != 1:
        raise TraceError(f"020H access is not in one bounded block: {_fmt(va)}")
    return matches[0]


def _strict_recognized(word: int, va: int = 0) -> bool:
    if decode_ret(word) is not None or decode_direct_branch(word, 0) is not None or decode_bl_target(word, 0) is not None:
        return True
    if decode_ldr_unsigned(word) is not None or decode_str_unsigned(word) is not None:
        return True
    if word & 0x3FE00C00 in (0x38600800, 0x38200800):
        option = (word >> 13) & 0x7
        width_code = (word >> 30) & 0x3
        if option == 0x3 and width_code in (0x2, 0x3):
            return True
    return any(result is not None for result in (decode_adrp(word, va), decode_add_sub_immediate(word), decode_add_sub_register(word), decode_madd(word), decode_mov_register(word)))


def _block_role(image: Image, block: Block) -> dict[str, Any]:
    instruction_count = (block.end - block.start) // 4
    unknown_vas: list[str] = []
    scalar_loads = scalar_stores = register_offset = direct_calls = 0
    for va in range(block.start, block.end, 4):
        word = image.word(va)
        if decode_bl_target(word, va) is not None:
            direct_calls += 1
        if decode_ldr_unsigned(word) is not None:
            scalar_loads += 1
        elif decode_str_unsigned(word) is not None:
            scalar_stores += 1
        elif word & 0x3FE00C00 in (0x38600800, 0x38200800) and ((word >> 13) & 0x7) == 0x3 and ((word >> 30) & 0x3) in (0x2, 0x3):
            register_offset += 1
        elif not _strict_recognized(word, va):
            unknown_vas.append(_fmt(va))
    if unknown_vas:
        role = "UNKNOWN_ROLE_UNSUPPORTED_FORM"
    elif direct_calls:
        role = "CALLING_BLOCK"
    elif scalar_stores:
        role = "LOCAL_WRITE_SHAPED_BLOCK"
    elif register_offset:
        role = "INDEXED_READ_SHAPED_BLOCK"
    elif scalar_loads:
        role = "LOCAL_READ_SHAPED_BLOCK"
    else:
        role = "CONTROL_OR_ADDRESS_BLOCK"
    return {"block": block.record(), "role": role, "instruction_count": instruction_count, "scalar_load_count": scalar_loads, "scalar_store_count": scalar_stores, "register_offset_count": register_offset, "direct_call_count": direct_calls, "unsupported_vas": unknown_vas}


def direct_callers(image: Image, target: int) -> list[str]:
    result: list[str] = []
    for va, word in image.executable_words():
        if decode_bl_target(word, va) == target:
            result.append(_fmt(va))
    return result


def _register_offset_decoder(word: int) -> tuple[str, int, int, int, int] | None:
    family = word & 0x3FE00C00
    if family not in (0x38600800, 0x38200800) or ((word >> 13) & 0x7) != 0x3:
        return None
    width_code = (word >> 30) & 0x3
    width = 64 if width_code == 0x3 else 32 if width_code == 0x2 else 0
    if not width:
        return None
    return ("LDR" if family == 0x38600800 else "STR", width, word & 0x1F, (word >> 5) & 0x1F, (word >> 16) & 0x1F)


def trace_base_origin(image: Image, block: Block, access_va: int, base_register: str, seed_va: str, seed_slot_va: str) -> dict[str, Any]:
    if not base_register.startswith("X") or not base_register[1:].isdigit():
        raise TraceError("020H base register is malformed")
    base = int(base_register[1:])
    if not 0 <= base <= 31:
        raise TraceError("020H base register is out of range")
    access_index = (access_va - block.start) // 4
    if access_va < block.start or access_va >= block.end or access_index < 0:
        raise TraceError("020H access is outside its block")
    definitions: list[dict[str, Any]] = []
    unsupported_boundary = False
    start_index = max(0, access_index - BACKWARD_WINDOW_INSTRUCTIONS)
    for index in range(access_index - 1, start_index - 1, -1):
        va = block.start + index * 4
        word = image.word(va)
        if decode_ret(word) is not None or decode_direct_branch(word, va) is not None or decode_bl_target(word, va) is not None:
            unsupported_boundary = True
            break
        ldr = decode_ldr_unsigned(word)
        if ldr is not None:
            width, register, source_base, offset = ldr
            if register == base:
                definitions.append({"kind": "STATIC_SLOT_SEED" if _fmt(va) == seed_va else "MEMORY_LOAD_DEFINITION", "va": _fmt(va), "register": _reg_name(register, width), "address_base": _reg_name(source_base), "offset": _fmt(offset), "seed_slot_va": seed_slot_va})
                break
            continue
        if decode_str_unsigned(word) is not None:
            continue
        regmem = _register_offset_decoder(word)
        if regmem is not None:
            operation, width, register, source_base, index_register = regmem
            if operation == "LDR" and register == base:
                definitions.append({"kind": "MEMORY_LOAD_DEFINITION", "va": _fmt(va), "register": _reg_name(register, width), "address_base": _reg_name(source_base), "index_register": _reg_name(index_register), "seed_slot_va": seed_slot_va})
                break
            continue
        madd = decode_madd(word)
        if madd is not None:
            width, destination, rn, rm, ra = madd
            if destination == base:
                definitions.append({"kind": "ARITHMETIC_DERIVED", "va": _fmt(va), "register": _reg_name(destination, width), "sources": [_reg_name(rn), _reg_name(rm), _reg_name(ra)], "seed_slot_va": seed_slot_va})
                break
            continue
        mov = decode_mov_register(word)
        if mov is not None:
            width, source, destination = mov
            if destination == base:
                definitions.append({"kind": "REGISTER_COPY", "va": _fmt(va), "register": _reg_name(destination, width), "source": _reg_name(source, width), "seed_slot_va": seed_slot_va})
                break
            continue
        add = decode_add_sub_immediate(word) or decode_add_sub_register(word)
        if add is not None:
            _operation, destination, source, _value, width = add
            if destination == base:
                definitions.append({"kind": "ARITHMETIC_DERIVED", "va": _fmt(va), "register": _reg_name(destination, width), "sources": [_reg_name(source, width)], "seed_slot_va": seed_slot_va})
                break
            continue
        if decode_adrp(word, va) is not None:
            destination, _page = decode_adrp(word, va)  # type: ignore[misc]
            if destination == base:
                definitions.append({"kind": "ARITHMETIC_DERIVED", "va": _fmt(va), "register": _reg_name(destination), "sources": [], "seed_slot_va": seed_slot_va})
                break
            continue
        if not _strict_recognized(word, va):
            unsupported_boundary = True
            break
    if definitions:
        classification = definitions[0]["kind"]
    elif unsupported_boundary:
        classification = "UNSUPPORTED_BOUNDARY"
    else:
        classification = "ARGUMENT_OR_UNKNOWN"
    return {"classification": classification, "base_register": base_register, "seed_va": seed_va, "seed_slot_va": seed_slot_va, "backward_window_instructions": BACKWARD_WINDOW_INSTRUCTIONS, "definitions": definitions}


def _rederive_accesses(image: Image, dependency: dict[str, Any], firmware_dir: Path) -> list[dict[str, Any]]:
    expected = dependency["manifest"]["census"]["accesses"]
    rederived = build_020g_manifest(firmware_dir)
    if rederived["census"]["accesses"] != expected:
        raise TraceError("020G access witness set changed during re-decode")
    if len(expected) != 12 or len({row["access_va"] for row in expected}) != 11:
        raise TraceError("020G unique access set cardinality changed")
    if Counter((row.get("shape"), row.get("kind")) for row in expected) != Counter({("IMMEDIATE_OBJECT_FIELD", "LDR"): 7, ("IMMEDIATE_OBJECT_FIELD", "STR"): 3, ("REGISTER_OFFSET_ARRAY_ELEMENT", "LDR"): 2}):
        raise TraceError("020G access shape/operation split changed")
    access_counts = Counter(row["access_va"] for row in expected)
    duplicate_vas = [access_va for access_va, count in access_counts.items() if count == 2]
    if sorted(access_counts.values()) != [1] * 10 + [2] or len(duplicate_vas) != 1:
        raise TraceError("020G duplicate witness structure changed")
    duplicate_rows = [row for row in expected if row["access_va"] == duplicate_vas[0]]
    if len({row["seed_slot_va"] for row in duplicate_rows}) != 2:
        raise TraceError("020G duplicate witness seeds changed")
    for row in expected:
        for field in ("access_va", "seed_va"):
            value = int(row[field], 16)
            if not ROLE_REGION_START <= value < ROLE_REGION_END:
                raise TraceError(f"020G {field} escaped the pinned role region")
    return expected


def build_manifest(firmware_dir: Path = FIRMWARE_DIR) -> dict[str, Any]:
    dependency = _load_public_dependency()
    image = Image(load_exact(firmware_dir / XBL_NAME))
    region_words = _words_in_region(image)
    blocks = recover_blocks(image, region_words)
    accesses = _rederive_accesses(image, dependency, firmware_dir)
    unique: dict[str, dict[str, Any]] = {}
    for row in accesses:
        unique.setdefault(row["access_va"], row)
    rows: list[dict[str, Any]] = []
    role_rows: list[dict[str, Any]] = []
    for access_va_text, row in sorted(unique.items(), key=lambda item: int(item[0], 16)):
        access_va = int(access_va_text, 16)
        block = _block_for(blocks, access_va)
        role = _block_role(image, block)
        callers = direct_callers(image, block.start)
        base_origin = trace_base_origin(image, block, access_va, row["base_register"], row["seed_va"], row["seed_slot_va"])
        role_rows.append({"access_va": access_va_text, "shape": row["shape"], "kind": row["kind"], "witness_count": sum(1 for item in accesses if item["access_va"] == access_va_text), "block_role": role, "block_entry_direct_bl_sources": callers, "base_origin": base_origin})
    block_records = [_block_role(image, block) for block in blocks]
    role_counts = Counter(item["block_role"]["role"] for item in role_rows)
    return {
        "schema": SCHEMA,
        "experiment_id": EXPERIMENT_ID,
        "mode": MODE,
        "device_access": "none",
        "classification": "CLASS C (TRANSFORM ONLY)",
        "eligibility": "NOT_ELIGIBLE",
        "inputs": {"firmware": {"filename": XBL_NAME, "size": XBL_SIZE, "sha256": XBL_SHA256}, "dependency_020g": {key: value for key, value in dependency.items() if key != "manifest"}, "role_region": {"start": _fmt(ROLE_REGION_START), "end_exclusive": _fmt(ROLE_REGION_END), "size": ROLE_REGION_SIZE, "sha256": ROLE_REGION_SHA256}},
        "census": {"access_witness_count": len(accesses), "unique_access_va_count": len(unique), "role_row_count": len(role_rows), "block_count": len(blocks), "role_counts": dict(sorted(role_counts.items())), "blocks": block_records, "roles": role_rows, "status": "SUPPORTED_BOUNDED_FUNCTION_ROLE_BASE_ORIGIN_CENSUS"},
        "scope": {"model": "EXACT_020G_UNIQUE_ACCESS_VA_RET_OR_DIRECT_BRANCH_DELIMITED_LOCAL_BLOCK", "backward_window_instructions": BACKWARD_WINDOW_INSTRUCTIONS, "recognized_forms": ["RET", "DIRECT_B", "DIRECT_BL", "LDR_STR_UNSIGNED", "LDR_STR_REGISTER_OFFSET_UXTX", "ADRP", "ADD_SUB", "MADD", "MOV_REGISTER"], "runtime_base": "UNKNOWN", "physical_to_dram": "UNKNOWN", "mmio_identity": "UNKNOWN", "global_writer_consumer_absence": "UNKNOWN", "function_boundary_proof": "UNKNOWN_FOR_LEAF_BLOCKS", "never_scan_arbitrary_ranges": True},
        "claims": {"PROVED": ["The exact retained A90 XBL, pinned 020G dependency, and 220-byte role region are bound by size/SHA-256 before analysis.", "Each of the 11 unique 020G access VAs is assigned only to a bounded return/direct-branch-delimited local block, with strict direct-call and backward base-origin records."], "SUPPORTED": ["The bounded access family is consistent with local helper/object roles and static-slot-derived or arithmetic-derived bases; this does not establish a runtime function identity or controller register."], "HYPOTHESIS": ["The access family may be a local configuration/helper cluster rather than final DRAM-controller programming."], "REFUTED": [], "UNKNOWN": ["True function boundaries for leaf blocks, runtime execution/currentness/values, indirect callers/callee effects, object semantics, global writer/consumer absence, ABI effects, MMIO/physical/DRAM identity, mutability/locking, protected reach, aliasing and bypass."]},
        "boundary_bypass": {"status": "NOT_AUTHORIZED", "device": "none", "smc": "none", "mmio": "none", "protected_memory": "none", "reason": "Host-only static role/base-origin census; no activation or live state was accessed."},
        "definition_of_done": {"target": {"binding": "PROVED_EXACT_XBL_INPUT_HASH", "marketing_name": "A90 5G", "model": "SM-A908N", "soc": "SM8150", "soc_name": "Snapdragon 855"}, "build": {"status": "NOT_APPLICABLE", "reason": "Interpreted host Python; no device/kernel build."}, "timestamp": {"status": "NOT_APPLICABLE", "reason": "Deterministic publication does not embed a wall-clock timestamp."}, "commands": {"status": "REDACTED_REPRODUCTION_TEMPLATE", "command": "python3 tools/sm8150_xbl_static_slot_function_role_base_origin_020h.py --output <public-manifest-path>", "reason": "Private input paths are redacted; exact hashes are pinned."}, "repetitions": {"status": "NOT_APPLICABLE", "reason": "Host-only static trace; no runtime repetitions."}, "rollback": {"status": "NOT_APPLICABLE", "reason": "Host-only static trace; no device state."}, "recovery": {"status": "NOT_APPLICABLE", "reason": "Host-only static trace; no device state."}, "device_binding": {"status": "NOT_APPLICABLE", "reason": "Host-only static trace; no device contact."}, "tool_and_build": {"tool": f"sm8150_xbl_static_slot_function_role_base_origin_020h.py schema {SCHEMA}", "build": "NOT_APPLICABLE"}},
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--firmware-dir", type=Path, default=FIRMWARE_DIR)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        payload = (json.dumps(build_manifest(args.firmware_dir), indent=1, sort_keys=True) + "\n").encode()
        publication = write_no_clobber(args.output, payload)
    except (TraceError, OSError) as exc:
        print(f"020H: {exc}", file=sys.stderr)
        return 2
    print(f"wrote {publication['basename']} {publication['size_bytes']} bytes sha256={publication['sha256']} mode={publication['mode']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
