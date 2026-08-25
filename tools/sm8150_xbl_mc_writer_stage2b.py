#!/usr/bin/env python3
"""Host-only Experiment 018 Stage 2B W-wide-move extension.

Stage 2B examines only the two Stage 2A window-limit RX candidates.  It adds
the narrow AArch64 W-register MOVZ/MOVK semantics needed for those two chains.
The resulting values are XBL virtual-address values; no VA-to-PA or physical
ownership conclusion is attempted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

try:
    from tools import sm8150_xbl_mc_writer_stage2a as stage2a
except ModuleNotFoundError as error:  # direct ``python tools/...`` invocation
    if error.name != "tools":
        raise
    import sm8150_xbl_mc_writer_stage2a as stage2a


DEFAULT_XBL = stage2a.DEFAULT_XBL
ElfImage = stage2a.ElfImage
TARGETS = stage2a.TARGETS
XBL_SIZE = stage2a.XBL_SIZE
XBL_SHA256 = stage2a.XBL_SHA256
WINDOW_MAX_INSTRUCTIONS = 512
STAGE2B_CLASSIFICATION = (
    "NO_NUMERIC_TARGET_ADDRESS_MATCH_WITHIN_STAGE2B_W_WIDE_MOVE_RX_MODEL"
)

# Baseline pins are assertions about the already accepted Stage 2A artifacts;
# Stage 2B never edits or regenerates them.
STAGE2A_TOOL_SHA256 = "eb0a8ce21154d97d052de9f7e4e0de40f85087a8cb517179f7c44332e9d85eb0"
STAGE2A_TEST_SHA256 = "1272fadb0bcc6b883f74577284312ee34678975fa7ba60377d05d86927960b3b"
STAGE2A_MANIFEST_SHA256 = "eeed732e4a6cecd60453e9088d8c3d4c7ed207a1e7c723bae91e27033d134a4b"

EXACT_STAGE2B_CANDIDATES: tuple[dict[str, object], ...] = (
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
)

W_CHAIN_PINS: tuple[dict[str, object], ...] = (
    {
        "virtual_address": 0x14844580,
        "file_offset": 0x2B580,
        "kind": "MOVZ",
        "immediate": 0xF000,
        "shift": 0,
        "width_bits": 32,
    },
    {
        "virtual_address": 0x1484458C,
        "file_offset": 0x2B58C,
        "kind": "MOVK",
        "immediate": 0x1489,
        "shift": 16,
        "width_bits": 32,
    },
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hex(value: int, width: int | None = None) -> str:
    return f"0x{value:0{width}x}" if width else f"0x{value:x}"


def _as_int(value: object) -> int:
    if isinstance(value, int):
        return value
    return int(str(value), 0)


def _unsupported_result(
    candidate: dict[str, object], pc: int, kind: str
) -> dict[str, object]:
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


def _no_definition_result(
    candidate: dict[str, object], stop_reason: str
) -> dict[str, object]:
    return {
        **candidate,
        "status": "UNRESOLVED_NO_W_WIDE_MOVE_DEFINITION",
        "reason": "NO_W_WIDE_MOVE_DEFINITION",
        "stop_reason": stop_reason,
        "resolved": False,
        "base_value": None,
        "effective_address": None,
        "target_match": None,
        "slice": [],
    }


def _validate_candidate_pin(
    image: ElfImage, candidate: dict[str, object]
) -> dict[str, object]:
    virtual_address = int(candidate["virtual_address"])
    file_offset = int(candidate["file_offset"])
    decoded = stage2a._decode_str_unsigned_immediate(image.u32(virtual_address))
    if image.vaddr_to_offset(virtual_address, 4) != file_offset:
        raise ValueError(f"candidate {_hex(virtual_address)} mapping mismatch")
    if decoded is None:
        raise ValueError(f"candidate {_hex(virtual_address)} is not STR W/X")
    if (
        decoded["base_register"] != candidate["base_register"]
        or decoded["byte_offset"] != candidate["byte_offset"]
        or decoded["width_bytes"] != candidate["width_bytes"]
    ):
        raise ValueError(f"candidate {_hex(virtual_address)} form mismatch")
    if stage2a._segment_class(image.segment_for_vaddr(virtual_address, 4)) != "RX":
        raise ValueError(f"candidate {_hex(virtual_address)} is not RX")
    return {
        "virtual_address": _hex(virtual_address),
        "file_offset": _hex(file_offset),
        "segment_class": "RX",
        "base_register": f"X{candidate['base_register']}",
        "byte_offset": _hex(int(candidate["byte_offset"])),
        "width_bytes": int(candidate["width_bytes"]),
    }


def _validate_w_chain_pins(image: ElfImage) -> None:
    for pin in W_CHAIN_PINS:
        virtual_address = int(pin["virtual_address"])
        file_offset = int(pin["file_offset"])
        if image.vaddr_to_offset(virtual_address, 4) != file_offset:
            raise ValueError(f"wide-move pin {_hex(virtual_address)} mapping mismatch")
        if stage2a._segment_class(image.segment_for_vaddr(virtual_address, 4)) != "RX":
            raise ValueError(f"wide-move pin {_hex(virtual_address)} is not RX")
        decoded = stage2a._decode_mov_wide(image.u32(virtual_address))
        if decoded is None:
            raise ValueError(f"wide-move pin {_hex(virtual_address)} is not MOV wide")
        for key in ("kind", "immediate", "shift", "width_bits"):
            if decoded[key] != pin[key]:
                raise ValueError(f"wide-move pin {_hex(virtual_address)} {key} mismatch")
        if decoded["destination"] != 8:
            raise ValueError(f"wide-move pin {_hex(virtual_address)} destination mismatch")


def _resolve_w_chain(
    image: ElfImage,
    words: dict[int, int],
    boundaries: set[int],
    candidate: dict[str, object],
) -> dict[str, object]:
    pc = _as_int(candidate["virtual_address"])
    register = int(str(candidate["base_register"])[1:])
    current = pc - 4
    scanned = 0
    operations: list[dict[str, object]] = []

    if pc in boundaries and pc != min(words):
        return _no_definition_result(candidate, "INBOUND_DIRECT_BRANCH_BLOCK_ENTRY")

    while scanned < WINDOW_MAX_INSTRUCTIONS:
        if current not in words:
            return _no_definition_result(candidate, "SEGMENT_OR_MAPPING_EDGE")
        scanned += 1
        at_block_entry = current in boundaries
        word = words[current]
        if at_block_entry:
            entry_definition = stage2a._definition_for_register(word, current, register)
            if entry_definition is None:
                return _no_definition_result(
                    candidate, "INBOUND_DIRECT_BRANCH_BLOCK_ENTRY"
                )
        if stage2a._is_control_transfer(word, current):
            return _no_definition_result(candidate, "CONTROL_TRANSFER")

        definition = stage2a._definition_for_register(word, current, register)
        if definition is None:
            current -= 4
            continue
        kind = str(definition["kind"])
        if kind not in {"MOVZ", "MOVK"}:
            return _unsupported_result(candidate, current, kind)
        if int(definition["width_bits"]) != 32:
            return _unsupported_result(candidate, current, "MIXED_WIDTH_WIDE_MOVE")
        if kind == "MOVK":
            operations.append({"pc": current, **definition})
            if at_block_entry:
                return _no_definition_result(
                    candidate, "INBOUND_DIRECT_BRANCH_BLOCK_ENTRY"
                )
            current -= 4
            continue

        # MOVZ Wn defines the complete 32-bit value and zero-extends Xn.  The
        # operations list is newest-to-oldest because the slice runs backward.
        operations.reverse()
        value = (int(definition["immediate"]) << int(definition["shift"])) & 0xFFFFFFFF
        for operation in operations:
            shift = int(operation["shift"])
            value = (value & ~(0xFFFF << shift)) | (
                int(operation["immediate"]) << shift
            )
        value &= 0xFFFFFFFF
        effective = value + _as_int(candidate["byte_offset"])
        slice_entries = [
            {
                "virtual_address": _hex(current),
                "kind": "MOVZ_W",
                "provenance": "DIRECT_W_WIDE_MOVE_ZERO_EXTENDED",
            }
        ] + [
            {
                "virtual_address": _hex(int(operation["pc"])),
                "kind": "MOVK_W",
                "provenance": "DIRECT_W_WIDE_MOVE_ZERO_EXTENDED",
            }
            for operation in operations
        ]
        try:
            image.segment_for_vaddr(effective, 1)
            inside_file_backed_pt_load = True
        except ValueError:
            inside_file_backed_pt_load = False
        instruction_pins = []
        for operation in [
            {"pc": current, **definition},
            *operations,
        ]:
            instruction_pins.append(
                {
                    "virtual_address": _hex(int(operation["pc"])),
                    "file_offset": _hex(image.vaddr_to_offset(int(operation["pc"]), 4)),
                    "kind": str(operation["kind"]),
                    "immediate": int(operation["immediate"]),
                    "shift": int(operation["shift"]),
                    "width_bits": int(operation["width_bits"]),
                    "distance_instructions": (pc - int(operation["pc"])) // 4,
                }
            )
        return {
            **candidate,
            "status": "RESOLVED_W_WIDE_MOVE_CHAIN",
            "reason": "RESOLVED_W_MOVZ_MOVK_CHAIN",
            "stop_reason": "SUPPORTED_W_WIDE_MOVE_DEFINITION",
            "resolved": True,
            "base_value": _hex(value, 8),
            "base_value_domain": "XBL_VIRTUAL_ADDRESS_VALUE",
            "effective_address": _hex(effective, 8),
            "effective_address_domain": "XBL_VIRTUAL_ADDRESS_VALUE",
            "inside_file_backed_pt_load": inside_file_backed_pt_load,
            "va_to_pa_translation": "UNKNOWN",
            "physical_destination": None,
            "target_match": effective in TARGETS,
            "slice": slice_entries,
            "instruction_pins": instruction_pins,
        }

    return _no_definition_result(candidate, "WINDOW_LIMIT")


def _stage2a_baseline(data: bytes) -> dict[str, object]:
    baseline = stage2a.analyze(data)
    remaining = [
        candidate
        for candidate in baseline["model"]["candidates"]
        if candidate["virtual_address"]
        not in {"0x14844b20", "0x14844c78"}
    ]
    return {
        "tool_sha256": STAGE2A_TOOL_SHA256,
        "test_sha256": STAGE2A_TEST_SHA256,
        "manifest_sha256": STAGE2A_MANIFEST_SHA256,
        "classification": baseline["classification"],
        "resolved_base_count": baseline["model"]["resolved_base_count"],
        "resolved_target_hit_count": baseline["model"]["resolved_target_hit_count"],
        "remaining_unresolved_count": len(remaining),
        "remaining_virtual_addresses": [item["virtual_address"] for item in remaining],
    }


def analyze(data: bytes) -> dict[str, object]:
    if len(data) != XBL_SIZE:
        raise ValueError(f"XBL size is {len(data)}, expected {XBL_SIZE}")
    image_hash = sha256(data)
    if image_hash != XBL_SHA256:
        raise ValueError(f"XBL SHA-256 mismatch: {image_hash}")
    image = ElfImage(data)
    stage1a = stage2a.stage2a_model(image, stage2a.analyze_stage1a(data))
    # Assert the Stage 2A exact baseline before consuming its two prior
    # window-limit rows.  The four-row set is independently pinned below.
    if stage1a["analyzed_rx_candidate_count"] != 4:
        raise ValueError("Stage 2A baseline candidate count changed")
    _validate_w_chain_pins(image)
    words, boundaries = stage2a._rx_word_map(image)
    candidates = [
        _validate_candidate_pin(image, candidate)
        for candidate in EXACT_STAGE2B_CANDIDATES
    ]
    results = [
        _resolve_w_chain(image, words, boundaries, candidate)
        for candidate in candidates
    ]
    resolved = [result for result in results if result["resolved"]]
    hits = [result for result in resolved if result["target_match"]]
    baseline = _stage2a_baseline(data)
    return {
        "schema": "sdm855-xbl-mc-writer-xref-stage2b-public-v1",
        "stage": "STAGE2B_W_WIDE_MOVE_RX_MODEL",
        "mode": "HOST_ONLY_READ_ONLY",
        "device_access": False,
        "smc_access": False,
        "mmio_access": False,
        "firmware_bytes_emitted": False,
        "input": {
            "filename": "xbl--sdb1.bin",
            "size": len(data),
            "sha256": image_hash,
            "pin_verified": True,
        },
        "target_set": {
            "target_count": len(TARGETS),
            "targets": [_hex(value, 8) for value in TARGETS],
        },
        "stage2a_baseline": baseline,
        "model": {
            "scope": "TWO_STAGE2A_WINDOW_LIMIT_RX_CANDIDATES_ONLY",
            "window_max_instructions": WINDOW_MAX_INSTRUCTIONS,
            "analyzed_candidate_count": len(results),
            "resolved_base_count": len(resolved),
            "resolved_numeric_target_hit_count": len(hits),
            "remaining_stage2a_unresolved_count": baseline["remaining_unresolved_count"],
            "candidates": results,
            "limitations": [
                "The computed base/effective values are XBL virtual-address values, not physical destinations.",
                "VA-to-PA translation or identity mapping is not modeled; physical RAM/MC ownership is UNKNOWN.",
                "Only same-register 32-bit MOVZ Wn followed by W MOVK definitions are added; mixed-width and unsupported definitions fail closed.",
                "SP, RWE, dynamic, memory/table, argument, cross-block/call and other-firmware paths remain UNKNOWN.",
            ],
        },
        "claims": {
            "PROVED": [
                "The exact XBL size/SHA-256 and the two Stage 2B candidate pins are verified.",
                "The two exact W-wide-move chains decode to XBL virtual-address values 0x1489f000 and compute effective XBL virtual-address values 0x1489f400 and 0x1489f4d0.",
                "Neither computed numeric value equals one of the 12 target address values under this Stage 2B model, and both computed values are outside file-backed PT_LOAD ranges.",
            ],
            "REFUTED": [
                "Exact numeric equality to the 12 target address values within the supported Stage 2B W-wide-move RX model.",
            ],
            "UNKNOWN": [
                "VA-to-PA translation/identity, physical destination, physical RAM or MC ownership, and any implication from neighboring ELF headers.",
                "Writer identity, runtime execution, register semantics, mutability/lock state, GF(2) relation, alias, bypass, protected reach and all unsupported/dynamic/cross-block/call/other-firmware paths.",
            ],
        },
        "classification": STAGE2B_CLASSIFICATION,
    }


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
