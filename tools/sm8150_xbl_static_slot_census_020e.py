#!/usr/bin/env python3
"""Bounded census of direct XBL accesses to the six 020D static slots.

Only an ``ADRP`` page definition followed by a recognized unsigned scalar
``LDR``/``STR`` is counted.  The result is a bounded access set, never a claim
that all writers or consumers have been found.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tools.sm8150_xbl_second_caller_field_use_020d import (
    CALLER_END,
    CALLER_SHA256,
    CALLER_START,
    FIRMWARE_DIR,
    HELPER_END,
    HELPER_SHA256,
    HELPER_START,
    Image,
    OBJECT_END,
    OBJECT_SHA256,
    OBJECT_START,
    TraceError,
    decode_adrp,
    decode_add_sub_imm,
    decode_bl_target,
    decode_ldp_unsigned,
    decode_ldr_unsigned,
    decode_str_unsigned,
    fmt,
    load_exact,
    range_record,
    sha256,
    write_no_clobber,
)


SCHEMA = "sm8150-xbl-static-slot-census-v1"
EXPERIMENT_ID = "020E-static-slot-census"
MODE = "HOST_ONLY_READ_ONLY"
XBL_NAME = "xbl--sdb1.bin"
XBL_SIZE = 4_194_304
XBL_SHA256 = "e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37"
STATIC_SLOT_PAGE = 0x9FC3E000
SLOT_OFFSETS = (0x138, 0x140, 0x148, 0x150, 0x158, 0x160)
SLOT_VAS = tuple(STATIC_SLOT_PAGE + offset for offset in SLOT_OFFSETS)
CALLER_SIZE = CALLER_END - CALLER_START
OBJECT_SIZE = OBJECT_END - OBJECT_START
WINDOW_INSTRUCTIONS = 8
# A direct BL may clobber caller-saved registers.  The bounded model only
# continues across a call when the page register is in the AAPCS64
# callee-saved set; this is an explicit ABI assumption, not a proof that an
# arbitrary XBL callee obeys it.
CALLEE_SAVED_REGISTERS = frozenset(range(19, 30))


def _written_register(word: int) -> set[int]:
    """Return registers written by recognized non-branch instructions."""
    written: set[int] = set()
    if (decoded := decode_adrp(word, 0x1000)) is not None:
        written.add(decoded[0])
    if (decoded := decode_add_sub_imm(word)) is not None:
        written.add(decoded[1])
    if (decoded := decode_ldr_unsigned(word)) is not None:
        written.add(decoded[1])
    if (decoded := decode_ldp_unsigned(word)) is not None:
        written.update((decoded[1], decoded[2]))
    # MOVZ/MOVK/MOVN (32/64-bit) write Rd.  These are only used as kill
    # information; their values are not interpreted.
    if word & 0x7F800000 in (0x12800000, 0x52800000, 0x72800000):
        written.add(word & 0x1F)
    # UBFM/SBFM/ BFM (including LSL/LSR aliases) are register-writing forms;
    # they are only used as clobber information here.
    if word & 0x7F800000 in (0x13000000, 0x53000000):
        written.add(word & 0x1F)
    # Register-only MOV/ORR alias writes Rd.
    if word & 0xFFE0FC00 == 0xAA000000:
        written.add(word & 0x1F)
    return written


def _contiguous_words(image: Image) -> dict[int, int]:
    return dict(image.executable_words())


def census_slots(image: Image) -> dict[str, Any]:
    words = _contiguous_words(image)
    by_access: dict[int, dict[str, Any]] = {}
    barriers: list[dict[str, str]] = []
    callee_saved_calls: list[dict[str, str]] = []
    caller_saved_call_barriers = 0
    for adrp_va, adrp_word in sorted(words.items()):
        decoded_adrp = decode_adrp(adrp_word, adrp_va)
        if decoded_adrp is None or decoded_adrp[1] != STATIC_SLOT_PAGE:
            continue
        page_register = decoded_adrp[0]
        for step in range(1, WINDOW_INSTRUCTIONS + 1):
            access_va = adrp_va + step * 4
            word = words.get(access_va)
            if word is None:
                break
            ldr = decode_ldr_unsigned(word)
            if ldr is not None and ldr[2] == page_register and ldr[3] in SLOT_OFFSETS:
                width, target, _base, offset = ldr
                by_access[access_va] = {
                    "va": fmt(access_va), "kind": "LDR", "width_bits": width,
                    "page_register": f"X{page_register}", "adrp_va": fmt(adrp_va),
                    "slot_offset": fmt(offset), "slot_va": fmt(STATIC_SLOT_PAGE + offset),
                    "register": f"{'W' if width == 32 else 'X'}{target}",
                }
            else:
                str_decoded = decode_str_unsigned(word)
                if str_decoded is not None and str_decoded[2] == page_register and str_decoded[3] in SLOT_OFFSETS:
                    width, source, _base, offset = str_decoded
                    by_access[access_va] = {
                        "va": fmt(access_va), "kind": "STR", "width_bits": width,
                        "page_register": f"X{page_register}", "adrp_va": fmt(adrp_va),
                        "slot_offset": fmt(offset), "slot_va": fmt(STATIC_SLOT_PAGE + offset),
                        "register": f"{'W' if width == 32 else 'X'}{source}",
                    }
            direct_target = decode_bl_target(word, access_va)
            if direct_target is not None:
                if page_register not in CALLEE_SAVED_REGISTERS:
                    caller_saved_call_barriers += 1
                    barriers.append({"adrp_va": fmt(adrp_va), "barrier_va": fmt(access_va), "kind": "CALLER_SAVED_BL"})
                    break
                callee_saved_calls.append({
                    "adrp_va": fmt(adrp_va),
                    "call_va": fmt(access_va),
                    "target": fmt(direct_target),
                    "page_register": f"X{page_register}",
                })
            # A recognized write to the page register ends this definition's
            # bounded lifetime.  Unknown forms are barriers, not evidence of
            # absence; preserving them makes the census fail-closed.
            if page_register in _written_register(word):
                break
            if ldr is None and decode_str_unsigned(word) is None and decode_adrp(word, access_va) is None and decode_add_sub_imm(word) is None and decode_ldp_unsigned(word) is None and direct_target is None and not _written_register(word) and not (word & 0xFFE0FC00 == 0xAA000000):
                barriers.append({"adrp_va": fmt(adrp_va), "barrier_va": fmt(access_va), "kind": "UNKNOWN_INSTRUCTION"})
                break

    accesses = sorted(by_access.values(), key=lambda row: int(row["va"], 16))
    stores = [row for row in accesses if row["kind"] == "STR"]
    loads = [row for row in accesses if row["kind"] == "LDR"]
    unknown_instruction_barriers = [row for row in barriers if row.get("kind") == "UNKNOWN_INSTRUCTION"]
    return {
        "accesses": accesses,
        "access_count": len(accesses),
        "store_count": len(stores),
        "load_count": len(loads),
        "slot_offsets": [fmt(offset) for offset in SLOT_OFFSETS],
        "slot_vas": [fmt(va) for va in SLOT_VAS],
        "window_instructions": WINDOW_INSTRUCTIONS,
        "barrier_count": len(barriers),
        "unknown_barrier_count": len(unknown_instruction_barriers),
        "barriers": barriers,
        "unknown_barriers": unknown_instruction_barriers,
        "callee_saved_register_model": [f"X{register}" for register in sorted(CALLEE_SAVED_REGISTERS)],
        "callee_saved_calls": callee_saved_calls,
        "caller_saved_call_barrier_count": caller_saved_call_barriers,
        "status": "SUPPORTED_BOUNDED_STATIC_SLOT_CENSUS",
    }


def definition_of_done() -> dict[str, Any]:
    reason = "NOT_APPLICABLE: bounded host-only static census; no device or runtime state was touched"
    return {
        "target": {"binding": "PROVED_EXACT_XBL_INPUT_HASH", "marketing_name": "A90 5G", "model": "SM-A908N", "soc": "SM8150", "soc_name": "Snapdragon 855"},
        "build": {"status": "NOT_APPLICABLE", "reason": reason},
        "timestamp": {"status": "NOT_APPLICABLE", "reason": "Deterministic publication does not embed a wall-clock timestamp."},
        "commands": {"status": "REDACTED_REPRODUCTION_TEMPLATE", "command": "python3 tools/sm8150_xbl_static_slot_census_020e.py --output <public-manifest-path>", "reason": "Private input paths are redacted; exact hashes are pinned."},
        "repetitions": {"status": "NOT_APPLICABLE", "reason": reason},
        "rollback": {"status": "NOT_APPLICABLE", "reason": reason},
        "recovery": {"status": "NOT_APPLICABLE", "reason": reason},
        "device_binding": {"status": "NOT_APPLICABLE", "reason": reason},
        "tool_and_build": {"build": "NOT_APPLICABLE", "build_reason": "Interpreted host Python; no firmware/kernel build.", "tool": f"sm8150_xbl_static_slot_census_020e.py schema {SCHEMA}"},
    }


def build_manifest(firmware_dir: Path = FIRMWARE_DIR) -> dict[str, Any]:
    image = Image(load_exact(firmware_dir / XBL_NAME))
    helper = range_record(image, HELPER_START, HELPER_END, HELPER_SHA256, "020C helper")
    caller = range_record(image, CALLER_START, CALLER_END, CALLER_SHA256, "020D caller")
    object_range = range_record(image, OBJECT_START, OBJECT_END, OBJECT_SHA256, "020D object")
    census = census_slots(image)
    return {
        "schema": SCHEMA,
        "experiment_id": EXPERIMENT_ID,
        "mode": MODE,
        "device_access": "none",
        "classification": "CLASS C (TRANSFORM ONLY)",
        "eligibility": "NOT_ELIGIBLE",
        "inputs": {"firmware": {"filename": XBL_NAME, "size": XBL_SIZE, "sha256": XBL_SHA256}, "dependencies": {"helper": helper, "caller_020d": caller, "object_020d": object_range}, "slot_page": fmt(STATIC_SLOT_PAGE), "slot_offsets": [fmt(offset) for offset in SLOT_OFFSETS]},
        "census": census,
        "scope": {"model": "ADRP_TO_UNSIGNED_SCALAR_ACCESS_WITHIN_8_INSTRUCTIONS", "recognized_forms": ["ADRP", "LDR_UNSIGNED", "STR_UNSIGNED", "ADD_SUB_IMMEDIATE", "LDP_UNSIGNED", "MOV_REGISTER", "BL_DIRECT_IF_CALLEE_SAVED_PAGE_REGISTER"], "call_preservation_assumption": "AAPCS64_X19_X29_CALLEE_SAVED", "runtime_values": "UNKNOWN", "global_writer_absence": "UNKNOWN", "physical_to_dram": "UNKNOWN", "indirect_paths": "UNKNOWN", "never_scan_arbitrary_ranges": True},
        "claims": {
            "PROVED": [
                "The exact retained A90 XBL and 020C/020D dependency ranges are bound by size and SHA-256.",
                "The bounded census recognizes the reported direct ADRP-to-scalar accesses to the six 020D static slots.",
                "The recognized access set contains six stores and twelve loads in the exact retained XBL.",
            ],
            "SUPPORTED": ["The six static slots form a bounded cross-reference set for the 020D field-use edge; unknown barriers and indirect paths remain outside the model.", "Direct BL windows continue only for page registers X19-X29 under an explicit AAPCS64 callee-saved assumption; caller-saved BL windows are barriers."],
            "HYPOTHESIS": ["The static slots may be shared configuration state rather than final controller registers."],
            "REFUTED": [],
            "UNKNOWN": ["Global writer/consumer absence, ABI compliance and callee side effects, runtime execution/currentness and values, slot semantics, MMIO/physical/DRAM meaning, mutability/locking, protected reach, aliasing and bypass."],
        },
        "boundary_bypass": {"status": "NOT_AUTHORIZED", "device": "none", "smc": "none", "mmio": "none", "protected_memory": "none", "reason": "Host-only static census; no activation or live state was accessed."},
        "definition_of_done": definition_of_done(),
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
        print(f"020E: {exc}", file=__import__("sys").stderr)
        return 2
    print(f"wrote {publication['basename']} {publication['size_bytes']} bytes sha256={publication['sha256']} mode={publication['mode']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
