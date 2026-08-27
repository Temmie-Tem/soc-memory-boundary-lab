#!/usr/bin/env python3
"""Bounded forward use-trace for the twelve 020E slot loads.

The trace starts from the exact direct scalar loads retained by 020E and
follows only a small same-block instruction window.  It records direct uses
of a slot-derived value (arithmetic, address-base, stores, predicates and
returns) and stops at unsupported forms.  It is not a whole-program data-flow
or writer/consumer-absence proof.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any, Sequence

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tools.sm8150_xbl_second_caller_field_use_020d import (
    FIRMWARE_DIR,
    Image,
    TraceError,
    decode_bl_target,
    decode_ldr_unsigned,
    decode_str_unsigned,
    fmt,
    load_exact,
    write_no_clobber,
)
from tools.sm8150_xbl_static_slot_census_020e import (
    CALLEE_SAVED_REGISTERS,
    SLOT_OFFSETS,
    STATIC_SLOT_PAGE,
    XBL_NAME,
    XBL_SHA256,
    XBL_SIZE,
    census_slots,
)


SCHEMA = "sm8150-xbl-static-slot-load-use-v1"
EXPERIMENT_ID = "020F-static-slot-load-use"
MODE = "HOST_ONLY_READ_ONLY"
DEPENDENCY_020E_MANIFEST_SHA256 = "4c28b0cc0a113e099fe3b0ce2bd16a77ce0c9d9bfc799ca9494c52eed9c349ad"
DEPENDENCY_020E_MANIFEST_NAME = "020E-static-slot-census-20260827-01.manifest.json"
DEPENDENCY_020E_MANIFEST_PATH = _REPO_ROOT / "evidence/manifests" / DEPENDENCY_020E_MANIFEST_NAME
WINDOW_INSTRUCTIONS = 16
# X0-X18 and X30 are caller-saved under AAPCS64; X19-X29 are the explicitly
# conditional callee-saved set inherited from 020E.
CALLER_SAVED_REGISTERS = frozenset(range(0, 19)) | {30}
XZR = 31

# Exact 020E load rows.  The scanner re-derives these from the pinned XBL and
# rejects any drift before the forward slice starts.
EXPECTED_LOADS = (
    (0x9FC26E7C, 0x148, 64, 0),
    (0x9FC26E90, 0x158, 64, 8),
    (0x9FC26E98, 0x160, 64, 9),
    (0x9FC26EAC, 0x150, 64, 9),
    (0x9FC26EC4, 0x138, 64, 9),
    (0x9FC26EE8, 0x138, 64, 9),
    (0x9FC26F0C, 0x138, 64, 8),
    (0x9FC26F18, 0x138, 64, 9),
    (0x9FC26F3C, 0x138, 64, 9),
    (0x9FC26F54, 0x138, 64, 9),
    (0x9FC26FB8, 0x140, 32, 0),
    (0x9FC26FE0, 0x140, 32, 8),
)


def _load_public_dependency_pin() -> dict[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(DEPENDENCY_020E_MANIFEST_PATH, flags)
    except OSError as exc:
        raise TraceError(f"cannot open exact 020E manifest: {exc}") from exc
    try:
        stat_result = os.fstat(fd)
        if not stat.S_ISREG(stat_result.st_mode) or stat_result.st_size <= 0:
            raise TraceError("020E dependency manifest is not a regular non-empty file")
        chunks: list[bytes] = []
        remaining = stat_result.st_size
        while remaining:
            chunk = os.read(fd, min(1 << 20, remaining))
            if not chunk:
                raise TraceError("020E dependency manifest truncated during read")
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) != stat_result.st_size:
            raise TraceError("020E dependency manifest truncated during read")
    finally:
        os.close(fd)
    digest = hashlib.sha256(payload).hexdigest()
    if digest != DEPENDENCY_020E_MANIFEST_SHA256:
        raise TraceError("020E dependency manifest SHA-256 mismatch")
    return {"filename": DEPENDENCY_020E_MANIFEST_NAME, "size": len(payload), "sha256": digest, "manifest_sha256": digest, "access_count": 18, "load_count": 12, "slot_page": fmt(STATIC_SLOT_PAGE), "slot_offsets": [fmt(offset) for offset in SLOT_OFFSETS]}


def _reg_name(register: int, width: int = 64) -> str:
    if register == XZR:
        return "WZR" if width == 32 else "XZR"
    return f"{'W' if width == 32 else 'X'}{register}"


def decode_add_sub_immediate(word: int) -> tuple[str, int, int, int, int] | None:
    """Decode flagless ADD/SUB (W/X) immediate forms."""

    if not isinstance(word, int) or not 0 <= word <= 0xFFFFFFFF:
        return None
    if word & 0x1F000000 != 0x11000000:
        return None
    sf = (word >> 31) & 1
    op = (word >> 30) & 1
    set_flags = (word >> 29) & 1
    if set_flags or ((word >> 23) & 1):
        return None
    shift = (word >> 22) & 1
    immediate = ((word >> 10) & 0xFFF) << (12 if shift else 0)
    return ("SUB" if op else "ADD", word & 0x1F, (word >> 5) & 0x1F, immediate, 64 if sf else 32)


def decode_add_sub_register(word: int) -> tuple[str, int, int, int, int] | None:
    """Decode only flagless ADD/SUB (W/X) shifted-register LSL#0."""

    if not isinstance(word, int) or not 0 <= word <= 0xFFFFFFFF:
        return None
    if word & 0x1F200000 != 0x0B000000 or word & (1 << 29):
        return None
    if ((word >> 22) & 0x3) != 0 or ((word >> 10) & 0x3F) != 0:
        return None
    sf = 64 if word & (1 << 31) else 32
    return ("SUB" if word & (1 << 30) else "ADD", word & 0x1F, (word >> 5) & 0x1F, (word >> 16) & 0x1F, sf)


def decode_madd(word: int) -> tuple[int, int, int, int, int] | None:
    """Decode flagless MADD W/X and return width, rd, rn, rm, ra."""

    if not isinstance(word, int) or not 0 <= word <= 0xFFFFFFFF:
        return None
    if (word & 0x7F000000) != 0x1B000000 or (word & 0x7FE08000) != 0x1B000000:
        return None
    return (64 if word & (1 << 31) else 32, word & 0x1F, (word >> 5) & 0x1F, (word >> 16) & 0x1F, (word >> 10) & 0x1F)


def decode_mov_register(word: int) -> tuple[int, int, int] | None:
    """Decode ORR X/W register MOV aliases with LSL #0."""

    if not isinstance(word, int) or not 0 <= word <= 0xFFFFFFFF:
        return None
    if word & 0xFFE0FC00 in (0xAA000000, 0x2A000000):
        if ((word >> 5) & 0x1F) != XZR or ((word >> 10) & 0x3F):
            return None
        width = 64 if word & (1 << 31) else 32
        return width, (word >> 16) & 0x1F, word & 0x1F
    return None


def decode_move_wide(word: int) -> tuple[str, int, int, int] | None:
    """Decode MOVZ/MOVK/MOVN only for kill/partial-kill accounting."""

    if not isinstance(word, int) or not 0 <= word <= 0xFFFFFFFF:
        return None
    base = word & 0x7F800000
    if base not in (0x12800000, 0x52800000, 0x72800000):
        return None
    width = 64 if word & (1 << 31) else 32
    halfword = (word >> 21) & 0x3
    if width == 32 and halfword > 1:
        return None
    return ("MOVN" if base == 0x12800000 else "MOVZ" if base == 0x52800000 else "MOVK", width, word & 0x1F, halfword)


def decode_cmp_register(word: int) -> tuple[int, int, int] | None:
    """Decode CMP W/X register (SUBS ...,ZR)."""

    if word & 0xFFE0FC1F in (0x6B00001F, 0xEB00001F):
        return (64 if word & (1 << 31) else 32, (word >> 5) & 0x1F, (word >> 16) & 0x1F)
    return None


def decode_cmp_immediate(word: int) -> tuple[int, int] | None:
    """Decode CMP W/X immediate (SUBS ...,ZR)."""

    if word & 0x1F000000 != 0x11000000 or not (word & (1 << 29)) or word & (1 << 23):
        return None
    if (word & 0x1F) != XZR:
        return None
    sf = 64 if word & (1 << 31) else 32
    immediate = ((word >> 10) & 0xFFF) << (12 if (word >> 22) & 1 else 0)
    return sf, (word >> 5) & 0x1F


def decode_cbz(word: int) -> tuple[int, int] | None:
    if word & 0x7F000000 not in (0x34000000, 0x35000000):
        return None
    return (64 if word & (1 << 31) else 32, word & 0x1F)


def decode_tbz(word: int) -> int | None:
    if word & 0x7F000000 not in (0x36000000, 0x37000000):
        return None
    return word & 0x1F


def decode_direct_b(word: int, va: int) -> int | None:
    if word & 0x7C000000 != 0x14000000:
        return None
    immediate = word & 0x03FFFFFF
    if immediate & (1 << 25):
        immediate -= 1 << 26
    return va + (immediate << 2)


def decode_conditional_b(word: int, va: int) -> int | None:
    """Decode B.cond and compute its target without interpreting condition."""

    if not isinstance(word, int) or not 0 <= word <= 0xFFFFFFFF or word & 0xFF000010 != 0x54000000:
        return None
    immediate = (word >> 5) & 0x7FFFF
    if immediate & (1 << 18):
        immediate -= 1 << 19
    return va + (immediate << 2)


def decode_indirect_control(word: int) -> tuple[str, int | None] | None:
    masked = word & 0xFFFFFC1F
    if masked == 0xD61F0000:
        return "BR", (word >> 5) & 0x1F
    if masked == 0xD63F0000:
        return "BLR", (word >> 5) & 0x1F
    if masked == 0xD65F0000:
        return "RET", (word >> 5) & 0x1F
    return None


def decode_register_offset_memory(word: int) -> tuple[str, int, int, int, int] | None:
    """Decode LDR/STR W/X [Xn,Xm,UXTX] with optional scale."""

    family = word & 0x3FE00C00
    if family not in (0x38600800, 0x38200800):
        return None
    option = (word >> 13) & 0x7
    if option != 0x3:
        return None
    width = 64 if (word >> 30) & 0x3 == 0x3 else 32 if (word >> 30) & 0x3 == 0x2 else 0
    if not width:
        return None
    return ("LDR" if family == 0x38600800 else "STR", width, word & 0x1F, (word >> 5) & 0x1F, (word >> 16) & 0x1F)


def _slot_load_rows(image: Image) -> list[dict[str, Any]]:
    census = census_slots(image)
    rows = [row for row in census["accesses"] if row["kind"] == "LDR"]
    normalized = [(int(row["va"], 16), int(row["slot_offset"], 16), row["width_bits"], int(row["register"][1:])) for row in rows]
    if normalized != list(EXPECTED_LOADS):
        raise TraceError("020E load set changed")
    return rows


def _event(va: int, kind: str, **details: Any) -> dict[str, Any]:
    result = {"va": fmt(va), "kind": kind}
    result.update(details)
    return result


def trace_load(image: Image, row: dict[str, Any]) -> dict[str, Any]:
    seed_va = int(row["va"], 16)
    seed_register = int(row["register"][1:])
    seed_width = int(row["width_bits"])
    segment = image.segment_for(seed_va, 4)
    if segment is None or not segment.executable:
        raise TraceError(f"load is not in an executable segment: {fmt(seed_va)}")
    words = {va: word for va, word in image.executable_words()}
    tainted: set[int] = set() if seed_register == XZR else {seed_register}
    events: list[dict[str, Any]] = []
    for step in range(1, WINDOW_INSTRUCTIONS + 1):
        va = seed_va + step * 4
        if image.segment_for(va, 4) != segment or va not in words:
            events.append(_event(va, "BOUNDARY"))
            break
        word = words[va]
        direct_target = decode_bl_target(word, va)
        if direct_target is not None:
            if tainted & CALLER_SAVED_REGISTERS:
                events.append(_event(va, "CALLER_SAVED_BL_BARRIER", target=fmt(direct_target), registers=[_reg_name(reg) for reg in sorted(tainted & CALLER_SAVED_REGISTERS)]))
                break
            events.append(_event(va, "CALLEE_SAVED_BL_CONDITIONAL", target=fmt(direct_target), registers=[_reg_name(reg) for reg in sorted(tainted & CALLEE_SAVED_REGISTERS)]))
            continue
        control = decode_indirect_control(word)
        if control is not None:
            kind, register = control
            if kind == "RET" and 0 in tainted:
                events.append(_event(va, "RETURN_USE", register=_reg_name(0, seed_width)))
            elif register is not None and register in tainted:
                events.append(_event(va, "INDIRECT_CONTROL_USE", control=kind, register=_reg_name(register)))
            else:
                events.append(_event(va, "CONTROL_BARRIER", control=kind))
            break
        direct_branch = decode_direct_b(word, va)
        if direct_branch is not None:
            events.append(_event(va, "DIRECT_BRANCH_BARRIER", target=fmt(direct_branch)))
            break
        conditional_branch = decode_conditional_b(word, va)
        if conditional_branch is not None:
            events.append(_event(va, "CONTROL_BARRIER", control="B_COND", target=fmt(conditional_branch)))
            break
        cbz = decode_cbz(word)
        if cbz is not None:
            _width, register = cbz
            if register in tainted:
                events.append(_event(va, "PREDICATE_USE", predicate="CBZ_CBNZ", register=_reg_name(register, _width)))
            else:
                events.append(_event(va, "CONTROL_BARRIER", control="CBZ_CBNZ"))
            break
        tbz = decode_tbz(word)
        if tbz is not None:
            if tbz in tainted:
                events.append(_event(va, "PREDICATE_USE", predicate="TBZ_TBNZ", register=_reg_name(tbz)))
            else:
                events.append(_event(va, "CONTROL_BARRIER", control="TBZ_TBNZ"))
            break
        cmp_reg = decode_cmp_register(word)
        if cmp_reg is not None:
            width, rn, rm = cmp_reg
            if rn in tainted or rm in tainted:
                events.append(_event(va, "PREDICATE_USE", predicate="CMP_REGISTER", registers=[_reg_name(reg, width) for reg in (rn, rm) if reg in tainted]))
            continue
        cmp_imm = decode_cmp_immediate(word)
        if cmp_imm is not None:
            width, rn = cmp_imm
            if rn in tainted:
                events.append(_event(va, "PREDICATE_USE", predicate="CMP_IMMEDIATE", register=_reg_name(rn, width)))
            continue
        ldr = decode_ldr_unsigned(word)
        if ldr is not None:
            width, target, base, offset = ldr
            if base in tainted:
                events.append(_event(va, "ADDRESS_BASE_USE", operation="LDR", width_bits=width, base=_reg_name(base), offset=fmt(offset), destination=_reg_name(target, width)))
            if target in tainted:
                events.append(_event(va, "KILL", register=_reg_name(target, width), operation="LDR"))
                tainted.discard(target)
            continue
        str_decoded = decode_str_unsigned(word)
        if str_decoded is not None:
            width, source, base, offset = str_decoded
            if base in tainted:
                events.append(_event(va, "ADDRESS_BASE_USE", operation="STR", width_bits=width, base=_reg_name(base), offset=fmt(offset), source=_reg_name(source, width)))
            if source in tainted:
                events.append(_event(va, "DIRECT_TAINTED_STORE", width_bits=width, source=_reg_name(source, width), base=_reg_name(base), offset=fmt(offset)))
            continue
        register_memory = decode_register_offset_memory(word)
        if register_memory is not None:
            operation, width, target, base, index = register_memory
            used = []
            if base in tainted:
                used.append(_reg_name(base))
            if index in tainted:
                used.append(_reg_name(index))
            if used:
                events.append(_event(va, "REGISTER_OFFSET_ADDRESS_USE", operation=operation, width_bits=width, registers=used, destination_or_source=_reg_name(target, width)))
            if operation == "STR" and target in tainted:
                events.append(_event(va, "DIRECT_TAINTED_STORE", width_bits=width, source=_reg_name(target, width), address_mode="REGISTER_OFFSET"))
            if operation == "LDR" and target in tainted:
                events.append(_event(va, "KILL", register=_reg_name(target, width), operation="LDR_REGISTER_OFFSET"))
                tainted.discard(target)
            continue
        arithmetic = decode_add_sub_immediate(word)
        if arithmetic is None:
            arithmetic = decode_add_sub_register(word)
        if arithmetic is not None:
            operation, rd, rn, immediate_or_rm, width = arithmetic
            sources = [rn]
            if decode_add_sub_register(word) is not None:
                sources.append(immediate_or_rm)
            if rn in tainted or (len(sources) > 1 and immediate_or_rm in tainted):
                events.append(_event(va, "ARITHMETIC_USE", operation=operation, width_bits=width, destination=_reg_name(rd, width), sources=[_reg_name(reg, width) for reg in sources if reg in tainted]))
                if rd != XZR:
                    tainted.add(rd)
            elif rd in tainted:
                events.append(_event(va, "KILL", register=_reg_name(rd, width), operation=operation))
                tainted.discard(rd)
            continue
        madd = decode_madd(word)
        if madd is not None:
            width, rd, rn, rm, ra = madd
            sources = [rn, rm, ra]
            if any(reg in tainted for reg in sources):
                events.append(_event(va, "ARITHMETIC_USE", operation="MADD", width_bits=width, destination=_reg_name(rd, width), sources=[_reg_name(reg, width) for reg in sources if reg in tainted]))
                if rd != XZR:
                    tainted.add(rd)
            elif rd in tainted:
                events.append(_event(va, "KILL", register=_reg_name(rd, width), operation="MADD"))
                tainted.discard(rd)
            continue
        mov = decode_mov_register(word)
        if mov is not None:
            width, source, destination = mov
            if source in tainted:
                events.append(_event(va, "REGISTER_COPY", width_bits=width, source=_reg_name(source, width), destination=_reg_name(destination, width)))
                if destination != XZR:
                    tainted.add(destination)
            elif destination in tainted:
                events.append(_event(va, "KILL", register=_reg_name(destination, width), operation="MOV"))
                tainted.discard(destination)
            continue
        move_wide = decode_move_wide(word)
        if move_wide is not None:
            operation, width, destination, _halfword = move_wide
            if destination in tainted:
                events.append(_event(va, "PARTIAL_KILL", register=_reg_name(destination, width), operation=operation))
                # MOVK preserves some old bits.  Without a bit-level lattice,
                # stop here rather than silently dropping residual taint.
                break
            continue
        # A recognized BFI/UBFM/SBFM form is a value use and destination
        # definition.  Other logical forms remain an explicit barrier.
        if word & 0x7F800000 in (0x13000000, 0x53000000):
            source = (word >> 5) & 0x1F
            destination = word & 0x1F
            width = 64 if word & (1 << 31) else 32
            if source in tainted:
                events.append(_event(va, "BITFIELD_USE", width_bits=width, source=_reg_name(source, width), destination=_reg_name(destination, width)))
                if destination != XZR:
                    tainted.add(destination)
            elif destination in tainted:
                events.append(_event(va, "KILL", register=_reg_name(destination, width), operation="BITFIELD"))
                tainted.discard(destination)
            continue
        events.append(_event(va, "UNKNOWN_BARRIER", word=fmt(word)))
        break
    return {
        "seed": row,
        "window_instructions": WINDOW_INSTRUCTIONS,
        "events": events,
        "remaining_tainted_registers": [_reg_name(reg) for reg in sorted(tainted)],
        "status": "SUPPORTED_BOUNDED_FORWARD_USE_TRACE",
    }


def build_manifest(firmware_dir: Path = FIRMWARE_DIR) -> dict[str, Any]:
    image = Image(load_exact(firmware_dir / XBL_NAME))
    firmware = {"filename": XBL_NAME, "size": XBL_SIZE, "sha256": XBL_SHA256}
    dependency = _load_public_dependency_pin()
    rows = _slot_load_rows(image)
    traces = [trace_load(image, row) for row in rows]
    event_counts: dict[str, int] = {}
    for trace in traces:
        for event in trace["events"]:
            event_counts[event["kind"]] = event_counts.get(event["kind"], 0) + 1
    return {
        "schema": SCHEMA,
        "experiment_id": EXPERIMENT_ID,
        "mode": MODE,
        "device_access": "none",
        "classification": "CLASS C (TRANSFORM ONLY)",
        "eligibility": "NOT_ELIGIBLE",
        "inputs": {"firmware": firmware, "dependency_020e": dependency},
        "traces": traces,
        "summary": {"seed_load_count": len(traces), "event_counts": dict(sorted(event_counts.items())), "global_writer_absence": "UNKNOWN", "global_consumer_absence": "UNKNOWN", "runtime_values": "UNKNOWN", "status": "SUPPORTED_BOUNDED_FORWARD_USE_TRACE"},
        "scope": {"model": "EACH_020E_LOAD_FORWARD_SAME_EXECUTABLE_BLOCK_16_INSTRUCTIONS", "recognized_forms": ["LDR_STR_UNSIGNED", "LDR_STR_REGISTER_OFFSET_UXTX", "ADD_SUB_IMMEDIATE", "ADD_SUB_REGISTER_LSL0", "MADD", "MOV_REGISTER", "MOVZ_MOVK_MOVN_KILL", "CMP", "CBZ_CBNZ", "TBZ_TBNZ", "B_COND", "DIRECT_BL_IF_CALLEE_SAVED_PAGE_OR_TAINT_REGISTER"], "runtime_values": "UNKNOWN", "physical_to_dram": "UNKNOWN", "indirect_paths": "UNKNOWN", "never_scan_arbitrary_ranges": True},
        "claims": {"PROVED": ["The exact retained A90 XBL and the 020E-derived twelve-load seed set are bound before tracing.", "Each reported event is a recognized use or fail-closed boundary within the stated 16-instruction same-block model."], "SUPPORTED": ["The twelve slot loads have bounded direct downstream uses recorded in the trace; these static uses do not identify runtime MMIO or DRAM state."], "HYPOTHESIS": ["Some slot-derived values may be configuration fields used for local object access or arithmetic rather than final controller programming."], "REFUTED": [], "UNKNOWN": ["Global writer/consumer absence, ABI compliance and callee effects, runtime execution/currentness and values, slot semantics, MMIO/physical/DRAM identity, mutability/locking, protected reach, aliasing and bypass."]},
        "boundary_bypass": {"status": "NOT_AUTHORIZED", "device": "none", "smc": "none", "mmio": "none", "protected_memory": "none", "reason": "Host-only static load-use trace; no activation or live state was accessed."},
        "definition_of_done": {"target": {"binding": "PROVED_EXACT_XBL_INPUT_HASH", "marketing_name": "A90 5G", "model": "SM-A908N", "soc": "SM8150", "soc_name": "Snapdragon 855"}, "build": {"status": "NOT_APPLICABLE", "reason": "Interpreted host Python; no device/kernel build."}, "timestamp": {"status": "NOT_APPLICABLE", "reason": "Deterministic publication does not embed a wall-clock timestamp."}, "commands": {"status": "REDACTED_REPRODUCTION_TEMPLATE", "command": "python3 tools/sm8150_xbl_static_slot_load_use_020f.py --output <public-manifest-path>", "reason": "Private input paths are redacted; exact hashes are pinned."}, "repetitions": {"status": "NOT_APPLICABLE", "reason": "Host-only static trace; no runtime repetitions."}, "rollback": {"status": "NOT_APPLICABLE", "reason": "Host-only static trace; no device state."}, "recovery": {"status": "NOT_APPLICABLE", "reason": "Host-only static trace; no device state."}, "device_binding": {"status": "NOT_APPLICABLE", "reason": "Host-only static trace; no device contact."}, "tool_and_build": {"tool": f"sm8150_xbl_static_slot_load_use_020f.py schema {SCHEMA}", "build": "NOT_APPLICABLE"}},
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
        print(f"020F: {exc}", file=sys.stderr)
        return 2
    print(f"wrote {publication['basename']} {publication['size_bytes']} bytes sha256={publication['sha256']} mode={publication['mode']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
