#!/usr/bin/env python3
"""Host-only Experiment 018 Stage 2A direct-definition discriminator.

This deliberately small analyzer examines only the four non-SP RX candidates
from the Stage 1A census.  It resolves same-basic-block MOVZ/MOVK or ADRP plus
64-bit ADD-immediate definitions through a bounded backward slice.  Everything
else is fail-closed and remains unknown; no writer-absence claim is made.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
from pathlib import Path
from typing import Iterable

try:
    from tools.sm8150_xbl_mc_writer_xref import (
        DEFAULT_XBL,
        ElfImage,
        TARGETS,
        XBL_SHA256,
        XBL_SIZE,
        _decode_str_unsigned_immediate,
        _hex,
        _iter_segment_words,
        _segment_class,
        analyze as analyze_stage1a,
    )
except ModuleNotFoundError as error:  # direct ``python tools/...`` invocation
    if error.name != "tools":
        raise
    from sm8150_xbl_mc_writer_xref import (
        DEFAULT_XBL,
        ElfImage,
        TARGETS,
        XBL_SHA256,
        XBL_SIZE,
        _decode_str_unsigned_immediate,
        _hex,
        _iter_segment_words,
        _segment_class,
        analyze as analyze_stage1a,
    )


WINDOW_MAX_INSTRUCTIONS = 128
STAGE2A_CLASSIFICATION = (
    "NO_RESOLVED_TARGET_STORE_WITHIN_STAGE2A_DIRECT_DEFINITION_RX_MODEL"
)

# These are the four non-SP RX rows from the exact Stage 1A census.  Keeping
# them as an explicit pin prevents this stage from silently broadening scope.
EXACT_RX_CANDIDATES: tuple[dict[str, object], ...] = (
    {
        "virtual_address": 0x14844B20,
        "file_offset": 0x2BB20,
        "base_register": 8,
        "byte_offset": 0x400,
        "width_bytes": 8,
    },
    {
        "virtual_address": 0x14844C78,
        "file_offset": 0x2BC78,
        "base_register": 8,
        "byte_offset": 0x4D0,
        "width_bytes": 8,
    },
    {
        "virtual_address": 0x146A70C0,
        "file_offset": 0x2D6090,
        "base_register": 8,
        "byte_offset": 0x400,
        "width_bytes": 4,
    },
    {
        "virtual_address": 0x14935BF4,
        "file_offset": 0x312BC4,
        "base_register": 19,
        "byte_offset": 0x400,
        "width_bytes": 8,
    },
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _decode_mov_wide(word: int) -> dict[str, object] | None:
    """Decode MOVN/MOVZ/MOVK, retaining MOVN for fail-closed handling."""

    opcode = word & 0x7F800000
    operation = {
        0x12800000: "MOVN",
        0x52800000: "MOVZ",
        0x72800000: "MOVK",
    }.get(opcode)
    if operation is None:
        return None
    width_bits = 64 if (word >> 31) & 1 else 32
    halfword = (word >> 21) & 0x3
    if width_bits == 32 and halfword > 1:
        return None
    return {
        "kind": operation,
        "width_bits": width_bits,
        "destination": word & 0x1F,
        "immediate": (word >> 5) & 0xFFFF,
        "shift": halfword * 16,
    }


def _decode_adr_or_adrp(word: int, pc: int) -> dict[str, object] | None:
    if word & 0x9F000000 == 0x90000000:
        immlo = (word >> 29) & 0x3
        immhi = (word >> 5) & 0x7FFFF
        immediate = (immhi << 2) | immlo
        sign = 1 << 20
        immediate = (immediate ^ sign) - sign
        return {
            "kind": "ADRP",
            "destination": word & 0x1F,
            "value": (pc & ~0xFFF) + (immediate << 12),
        }
    if word & 0x9F000000 == 0x10000000:
        immlo = (word >> 29) & 0x3
        immhi = (word >> 5) & 0x7FFFF
        immediate = (immhi << 2) | immlo
        sign = 1 << 20
        immediate = (immediate ^ sign) - sign
        return {
            "kind": "ADR",
            "destination": word & 0x1F,
            "value": pc + immediate,
        }
    return None


def _decode_add_immediate_64(word: int) -> dict[str, object] | None:
    # ADD (immediate), sf=1, S=0, op=0.  Bit 23 is reserved and bit 22 is
    # the optional 12-bit left shift.
    if word & 0x1F000000 != 0x11000000:
        return None
    if not ((word >> 31) & 1):
        return None
    if (word >> 30) & 1 or (word >> 29) & 1 or (word >> 23) & 1:
        return None
    immediate = (word >> 10) & 0xFFF
    if (word >> 22) & 1:
        immediate <<= 12
    return {
        "kind": "ADD_IMMEDIATE_64",
        "destination": word & 0x1F,
        "source": (word >> 5) & 0x1F,
        "immediate": immediate,
    }


def _decode_mov_alias(word: int) -> dict[str, object] | None:
    for width_bits, opcode in ((32, 0x2A0003E0), (64, 0xAA0003E0)):
        if word & 0xFFE0FFE0 == opcode:
            return {
                "kind": "MOV_ALIAS",
                "width_bits": width_bits,
                "destination": word & 0x1F,
                "source": (word >> 16) & 0x1F,
            }
    return None


def _decode_scalar_load(word: int) -> dict[str, object] | None:
    # LDR W/X unsigned immediate.  This is sufficient to classify the exact
    # memory-derived X8 definition; unmodeled loads remain conservative below.
    if word & 0x3FC00000 != 0x39400000:
        return None
    size = (word >> 30) & 0x3
    if size not in (2, 3):
        return None
    return {
        "kind": "LDR_UNSIGNED_IMMEDIATE",
        "destination": word & 0x1F,
    }


def _decode_pair_load(word: int) -> dict[str, object] | None:
    """Decode scalar/vector LDP destinations for conservative failure."""

    scalar = word & 0x3E000000 == 0x28000000
    vector = word & 0x3E000000 == 0x2C000000
    if not (scalar or vector) or not (word & 0x00400000):
        return None
    return {
        "kind": "LDP_UNSUPPORTED",
        "destination": word & 0x1F,
        "second_destination": (word >> 10) & 0x1F,
    }


def _decode_madd(word: int) -> dict[str, object] | None:
    # MADD/MSUB W/X share this destination-bearing class.  Treating both as
    # unsupported definitions is intentionally conservative.
    if word & 0xFFE00000 not in (0x1B000000, 0x9B000000):
        return None
    return {"kind": "MADD_OR_MSUB", "destination": word & 0x1F}


def _decode_direct_branch_target(word: int, pc: int) -> int | None:
    if word & 0xFC000000 in (0x14000000, 0x94000000):
        immediate = word & 0x03FFFFFF
        immediate = (immediate ^ (1 << 25)) - (1 << 25)
        return pc + (immediate << 2)
    if word & 0xFF000010 == 0x54000000:
        immediate = (word >> 5) & 0x7FFFF
        immediate = (immediate ^ (1 << 18)) - (1 << 18)
        return pc + (immediate << 2)
    if word & 0x7E000000 == 0x34000000:
        immediate = (word >> 5) & 0x7FFFF
        immediate = (immediate ^ (1 << 18)) - (1 << 18)
        return pc + (immediate << 2)
    if word & 0x7E000000 == 0x36000000:
        immediate = (word >> 5) & 0x3FFF
        immediate = (immediate ^ (1 << 13)) - (1 << 13)
        return pc + (immediate << 2)
    return None


def _is_indirect_branch_or_return(word: int) -> bool:
    return (word & 0xFFFFFC1F) in {
        0xD61F0000,  # BR
        0xD63F0000,  # BLR
        0xD65F0000,  # RET
        0xD69F0000,  # ERET
    }


def _is_control_transfer(word: int, pc: int) -> bool:
    return _decode_direct_branch_target(word, pc) is not None or _is_indirect_branch_or_return(word)


def _is_store_form(word: int) -> bool:
    if word & 0x3FC00000 == 0x39000000:
        return True
    # Scalar unscaled/pre/post-index store class with opc=00.
    if word & 0x3B000000 == 0x38000000 and ((word >> 22) & 0x3) == 0:
        return True
    # Scalar/vector pair stores with L=0; the source registers are not
    # definitions.  LDP is deliberately excluded and classified below.
    scalar_pair = word & 0x3E000000 == 0x28000000
    vector_pair = word & 0x3E000000 == 0x2C000000
    return (scalar_pair or vector_pair) and not (word & 0x00400000)


def _definition_for_register(word: int, pc: int, register: int) -> dict[str, object] | None:
    """Return a destination-bearing instruction only when it may define reg."""

    if _is_store_form(word) or _is_control_transfer(word, pc):
        return None
    for decoder in (
        _decode_mov_wide,
        lambda value: _decode_adr_or_adrp(value, pc),
        _decode_add_immediate_64,
        _decode_mov_alias,
        _decode_scalar_load,
        _decode_pair_load,
        _decode_madd,
    ):
        decoded = decoder(word)
        if decoded is not None:
            if (
                decoded["destination"] == register
                or decoded.get("second_destination") == register
            ):
                return decoded
            return None
    # Unknown non-store instruction with matching Rd/Rt bits: fail closed.
    # This may conservatively classify an operand-bearing instruction, which
    # is preferable to skipping a possible definition.
    if (word & 0x1F) == register:
        return {"kind": "UNSUPPORTED_INSTRUCTION", "destination": register}
    return None


def _rx_word_map(image: ElfImage) -> tuple[dict[int, int], set[int]]:
    words: dict[int, int] = {}
    boundaries: set[int] = set()
    for segment in image.segments:
        if _segment_class(segment) != "RX":
            continue
        segment_words = list(_iter_segment_words(image, segment))
        if segment_words:
            boundaries.add(segment_words[0][0])
        for virtual_address, _file_offset, word in segment_words:
            words[virtual_address] = word
            target = _decode_direct_branch_target(word, virtual_address)
            if target is not None:
                boundaries.add(target)
    return words, boundaries


def _candidate_pin(image: ElfImage, candidate: dict[str, object]) -> dict[str, object]:
    file_offset = int(candidate["file_offset"])
    virtual_address = int(candidate["virtual_address"])
    width = int(candidate["width_bytes"])
    mapped_offset = image.vaddr_to_offset(virtual_address, 4)
    if mapped_offset != file_offset:
        raise ValueError(
            f"candidate {_hex(virtual_address)} maps to {_hex(mapped_offset)}, "
            f"expected {_hex(file_offset)}"
        )
    word = image.u32(virtual_address)
    decoded = _decode_str_unsigned_immediate(word)
    if decoded is None:
        raise ValueError(f"candidate {_hex(virtual_address)} is not a strict STR W/X")
    if (
        decoded["base_register"] != candidate["base_register"]
        or decoded["byte_offset"] != candidate["byte_offset"]
        or decoded["width_bytes"] != width
    ):
        raise ValueError(f"candidate {_hex(virtual_address)} does not match the pinned form")
    if _segment_class(image.segment_for_vaddr(virtual_address, 4)) != "RX":
        raise ValueError(f"candidate {_hex(virtual_address)} is not RX")
    return {
        "virtual_address": _hex(virtual_address),
        "file_offset": _hex(file_offset),
        "segment_class": "RX",
        "base_register": f"X{candidate['base_register']}",
        "byte_offset": _hex(int(candidate["byte_offset"])),
        "width_bytes": width,
    }


def _as_int(value: object) -> int:
    if isinstance(value, int):
        return value
    return int(str(value), 0)


def _no_direct_result(candidate: dict[str, object], stop_reason: str) -> dict[str, object]:
    return {
        **candidate,
        "status": "UNRESOLVED_NO_DIRECT_CONSTANT_DEFINITION",
        "reason": "NO_DIRECT_CONSTANT_DEFINITION",
        "stop_reason": stop_reason,
        "resolved": False,
        "base_value": None,
        "effective_address": None,
        "target_match": None,
        "slice": [],
    }


def _slice_candidate(
    image: ElfImage,
    words: dict[int, int],
    boundaries: set[int],
    candidate: dict[str, object],
) -> dict[str, object]:
    pc = _as_int(candidate["virtual_address"])
    if str(candidate["base_register"]) == "SP":
        return {
            **candidate,
            "status": "UNRESOLVED_RUNTIME_SP",
            "reason": "UNRESOLVED_RUNTIME_SP",
            "stop_reason": "SP_BASE_NOT_MODELED",
            "resolved": False,
            "base_value": None,
            "effective_address": None,
            "target_match": None,
            "slice": [],
        }
    register = int(str(candidate["base_register"])[1:])
    scanned = 0
    current = pc - 4
    state: str | None = None
    operations: list[dict[str, object]] = []
    boundary_kind: str | None = None

    if pc in boundaries and pc != min(words):
        return {
            **candidate,
            "status": "UNRESOLVED_INBOUND_BLOCK_ENTRY",
            "reason": "INBOUND_DIRECT_BRANCH_BLOCK_ENTRY",
            "stop_reason": "INBOUND_DIRECT_BRANCH_BLOCK_ENTRY",
            "resolved": False,
            "base_value": None,
            "effective_address": None,
            "target_match": None,
            "slice": [],
        }

    while scanned < WINDOW_MAX_INSTRUCTIONS:
        if current not in words:
            boundary_kind = "SEGMENT_OR_MAPPING_EDGE"
            break
        # Every predecessor word inspected consumes one window slot,
        # including a supported definition.  This makes the 128th predecessor
        # eligible for resolution while excluding the 129th.
        scanned += 1
        at_block_entry = current in boundaries
        if at_block_entry:
            # A direct branch target is a basic-block entry.  Inspect the
            # entry instruction.  An unsupported definition fails closed;
            # supported direct definitions at the entry may terminate a
            # complete same-block chain, but no earlier instruction is read.
            entry_definition = _definition_for_register(words[current], current, register)
            if entry_definition is not None and str(entry_definition["kind"]) not in {
                "MOVZ",
                "MOVK",
                "ADRP",
                "ADD_IMMEDIATE_64",
            }:
                return _unsupported_result(candidate, current, str(entry_definition["kind"]))
            if entry_definition is None:
                boundary_kind = "INBOUND_DIRECT_BRANCH_BLOCK_ENTRY"
                break
        word = words[current]
        if _is_control_transfer(word, current):
            boundary_kind = "CONTROL_TRANSFER"
            break

        definition = _definition_for_register(word, current, register)
        if definition is not None:
            kind = str(definition["kind"])
            destination = int(definition["destination"])
            if state is None:
                if kind == "MOVK":
                    if int(definition["width_bits"]) != 64:
                        return _unsupported_result(candidate, current, "MOVK_32_UNSUPPORTED")
                    state = "MOVZ_MOVK"
                    operations.append({"pc": current, "kind": kind, **definition})
                    if at_block_entry:
                        return _no_direct_result(candidate, "INBOUND_DIRECT_BRANCH_BLOCK_ENTRY")
                elif (
                    kind == "ADD_IMMEDIATE_64"
                    and int(definition["source"]) == register
                ):
                    state = "ADRP_ADD"
                    operations.append({"pc": current, "kind": kind, **definition})
                    if at_block_entry:
                        return _no_direct_result(candidate, "INBOUND_DIRECT_BRANCH_BLOCK_ENTRY")
                elif kind == "MOVZ":
                    if int(definition["width_bits"]) != 64:
                        return _unsupported_result(candidate, current, "MOVZ_32_UNSUPPORTED")
                    operations.reverse()
                    value = (int(definition["immediate"]) << int(definition["shift"])) & ((1 << int(definition["width_bits"])) - 1)
                    for operation in operations:
                        shift = int(operation["shift"])
                        value = (value & ~(0xFFFF << shift)) | (int(operation["immediate"]) << shift)
                    value &= (1 << int(definition["width_bits"])) - 1
                    effective = value + _as_int(candidate["byte_offset"])
                    chain = [
                        {"virtual_address": _hex(current), "kind": "MOVZ", "provenance": "DIRECT_CONSTANT"}
                    ] + [
                        {"virtual_address": _hex(int(operation["pc"])), "kind": str(operation["kind"]), "provenance": "DIRECT_CONSTANT"}
                        for operation in operations
                    ]
                    return {
                        **candidate,
                        "status": "RESOLVED_DIRECT_CONSTANT",
                        "reason": "RESOLVED_MOVZ_MOVK_CHAIN",
                        "stop_reason": "SUPPORTED_DIRECT_DEFINITION",
                        "resolved": True,
                        "base_value": _hex(value, 8),
                        "effective_address": _hex(effective, 8),
                        "target_match": effective in TARGETS,
                        "slice": chain,
                    }
                else:
                    return _unsupported_result(candidate, current, kind)
            elif state == "MOVZ_MOVK":
                if kind == "MOVK":
                    if int(definition["width_bits"]) != 64:
                        return _unsupported_result(candidate, current, "MOVK_32_UNSUPPORTED")
                    operations.append({"pc": current, "kind": kind, **definition})
                    if at_block_entry:
                        return _no_direct_result(candidate, "INBOUND_DIRECT_BRANCH_BLOCK_ENTRY")
                elif kind == "MOVZ":
                    if int(definition["width_bits"]) != 64:
                        return _unsupported_result(candidate, current, "MOVZ_32_UNSUPPORTED")
                    operations.reverse()
                    value = (int(definition["immediate"]) << int(definition["shift"])) & ((1 << int(definition["width_bits"])) - 1)
                    for operation in operations:
                        shift = int(operation["shift"])
                        value = (value & ~(0xFFFF << shift)) | (int(operation["immediate"]) << shift)
                    value &= (1 << int(definition["width_bits"])) - 1
                    effective = value + _as_int(candidate["byte_offset"])
                    chain = [
                        {"virtual_address": _hex(current), "kind": "MOVZ", "provenance": "DIRECT_CONSTANT"}
                    ] + [
                        {"virtual_address": _hex(int(operation["pc"])), "kind": str(operation["kind"]), "provenance": "DIRECT_CONSTANT"}
                        for operation in operations
                    ]
                    return {
                        **candidate,
                        "status": "RESOLVED_DIRECT_CONSTANT",
                        "reason": "RESOLVED_MOVZ_MOVK_CHAIN",
                        "stop_reason": "SUPPORTED_DIRECT_DEFINITION",
                        "resolved": True,
                        "base_value": _hex(value, 8),
                        "effective_address": _hex(effective, 8),
                        "target_match": effective in TARGETS,
                        "slice": chain,
                    }
                else:
                    return _unsupported_result(candidate, current, kind)
            elif state == "ADRP_ADD":
                if kind == "ADRP":
                    value = int(definition["value"]) + int(operations[0]["immediate"])
                    effective = value + _as_int(candidate["byte_offset"])
                    chain = [
                        {"virtual_address": _hex(current), "kind": "ADRP", "provenance": "DIRECT_CONSTANT"},
                        {"virtual_address": _hex(int(operations[0]["pc"])), "kind": "ADD_IMMEDIATE_64", "provenance": "DIRECT_CONSTANT"},
                    ]
                    return {
                        **candidate,
                        "status": "RESOLVED_DIRECT_CONSTANT",
                        "reason": "RESOLVED_ADRP_ADD_CHAIN",
                        "stop_reason": "SUPPORTED_DIRECT_DEFINITION",
                        "resolved": True,
                        "base_value": _hex(value, 8),
                        "effective_address": _hex(effective, 8),
                        "target_match": effective in TARGETS,
                        "slice": chain,
                    }
                return _unsupported_result(candidate, current, kind)
            else:
                return _unsupported_result(candidate, current, kind)

        # This instruction neither defines the tracked register nor crosses a
        # control boundary, so it is safe to move one instruction backward.
        current -= 4

    if scanned >= WINDOW_MAX_INSTRUCTIONS:
        boundary_kind = "WINDOW_LIMIT"
    return {
        **candidate,
        "status": "UNRESOLVED_NO_DIRECT_CONSTANT_DEFINITION",
        "reason": "NO_DIRECT_CONSTANT_DEFINITION",
        "stop_reason": boundary_kind or "NO_DEFINITION",
        "resolved": False,
        "base_value": None,
        "effective_address": None,
        "target_match": None,
        "slice": [],
    }


def _unsupported_result(candidate: dict[str, object], pc: int, kind: str) -> dict[str, object]:
    return {
        **candidate,
        "status": "UNSUPPORTED_REGISTER_DEFINITION",
        "reason": "UNSUPPORTED_REGISTER_DEFINITION",
        "stop_reason": "UNSUPPORTED_REGISTER_DEFINITION",
        "resolved": False,
        "base_value": None,
        "effective_address": None,
        "target_match": None,
        "slice": [
            {
                "virtual_address": _hex(pc),
                "kind": kind,
                "provenance": "FAIL_CLOSED_UNSUPPORTED_DEFINITION",
            }
        ],
    }


def stage2a_model(image: ElfImage, stage1a: dict[str, object]) -> dict[str, object]:
    words, boundaries = _rx_word_map(image)
    candidates = [_candidate_pin(image, candidate) for candidate in EXACT_RX_CANDIDATES]
    results = [_slice_candidate(image, words, boundaries, candidate) for candidate in candidates]
    resolved = [result for result in results if result["resolved"]]
    hits = [result for result in resolved if result["target_match"]]
    reasons: dict[str, int] = {}
    for result in results:
        reason = str(result["reason"])
        reasons[reason] = reasons.get(reason, 0) + 1
    return {
        "scope": "FOUR_NON_SP_RX_CANDIDATES_ONLY",
        "window_max_instructions": WINDOW_MAX_INSTRUCTIONS,
        "rx_candidate_count": 11,
        "analyzed_rx_candidate_count": len(results),
        "excluded_rx_sp_candidate_count": 7,
        "excluded_rx_sp_status": "UNRESOLVED_RUNTIME_SP",
        "excluded_rwe_candidate_count": 3,
        "excluded_rwe_status": "NOT_ATTEMPTED_RWE_AMBIGUOUS",
        "resolved_base_count": len(resolved),
        "resolved_target_hit_count": len(hits),
        "unresolved_count": len(results) - len(resolved),
        "reason_counts": reasons,
        "candidates": results,
        "limitations": [
            "Only the four pinned non-SP RX candidates are analyzed.",
            "No SP, RWE, memory-load, table, argument, wrapper, cross-block, or cross-call provenance is resolved.",
            "Only 64-bit MOVZ/MOVK and ADRP Xn followed by ADD Xn,Xn,#imm definitions are supported; 32-bit wide-move chains are rejected.",
            "MOVN, MOV aliases, arithmetic other than the exact ADRP+ADD form, and unsupported definitions fail closed.",
            "A direct branch target or basic-block entry is never crossed backward; runtime execution and writer identity remain UNKNOWN.",
        ],
    }


def analyze(data: bytes) -> dict[str, object]:
    if len(data) != XBL_SIZE:
        raise ValueError(f"XBL size is {len(data)}, expected {XBL_SIZE}")
    image_hash = sha256(data)
    if image_hash != XBL_SHA256:
        raise ValueError(f"XBL SHA-256 mismatch: {image_hash}")
    image = ElfImage(data)
    stage1a = analyze_stage1a(data)
    stage2a = stage2a_model(image, stage1a)
    hit_count = int(stage2a["resolved_target_hit_count"])
    classification = (
        STAGE2A_CLASSIFICATION
        if hit_count == 0
        else "RESOLVED_TARGET_STORE_WITHIN_STAGE2A_DIRECT_DEFINITION_RX_MODEL"
    )
    claims = {
        "PROVED": [
            "The exact XBL size and SHA-256 pin are verified.",
            "The Stage 1A 14-candidate census is preserved; Stage 2A analyzes exactly the four pinned non-SP RX candidates.",
            "The bounded Stage 2A model outcome, per-candidate reasons and supported direct-definition counts are deterministic.",
        ],
        "REFUTED": [],
        "UNKNOWN": [
            "Any writer outside the supported Stage 2A direct-definition path, including unsupported, dynamic, memory/table, argument, wrapper, cross-block, cross-call and other-firmware paths.",
            "Runtime execution, register semantics, mutability/lock state, GF(2) relation, alias, bypass and protected reach.",
            "The seven SP candidates and three RWE candidates, which remain runtime-derived or ambiguous.",
        ],
    }
    if hit_count == 0:
        claims["REFUTED"].append(
            "The supported Stage 2A direct-definition path resolves none of the four analyzed RX candidate stores to an exact target."
        )
    stage1a_summary = {
        "schema": stage1a["schema"],
        "stage": stage1a["stage"],
        "classification": stage1a["classification"],
        "target_count": stage1a["target_set"]["target_count"],
        "matching_offset_candidate_count": stage1a["pt_load_census"]["matching_offset_candidate_count"],
        "matching_offset_candidate_count_by_segment": stage1a["pt_load_census"]["matching_offset_candidate_count_by_segment"],
        "resolved_target_hit_count": stage1a["model"]["resolved_target_hit_count"],
    }
    # Preserve all Stage 1A public fields at top level while carrying only a
    # concise Stage 1A pin/summary rather than duplicating the full manifest.
    result = dict(stage1a)
    result.update(
        {
            "schema": "sdm855-xbl-mc-writer-xref-stage2a-public-v1",
            "stage": "STAGE2A_DIRECT_DEFINITION_RX_MODEL",
            "model": stage2a,
            "stage1a_summary": stage1a_summary,
            "stage2a_model": stage2a,
            "claims": claims,
            "classification": classification,
        }
    )
    return result


def analyze_path(path: Path) -> dict[str, object]:
    result = analyze(path.read_bytes())
    result["input"] = {**result["input"], "filename": path.name}
    return result


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_no_clobber(path: Path, data: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags, mode)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xbl", type=Path, default=DEFAULT_XBL)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    write_no_clobber(args.output, _json_bytes(analyze_path(args.xbl)))
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
