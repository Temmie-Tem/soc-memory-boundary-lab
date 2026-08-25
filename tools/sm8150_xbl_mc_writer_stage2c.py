#!/usr/bin/env python3
"""Host-only Experiment 018 Stage 2C retained-table writer discriminator.

This stage covers only the remaining RX writer candidate at 0x146a70c0.  It
validates the retained direct caller, its success-path wrapper/lookup data
flow, and the 48-entry table feeding the writer descriptor.  The table-derived
``base + 0x400`` values are a conservative possible-value superset: the
descriptor's +0x20 eligibility field is populated at runtime and is not
modeled here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
from pathlib import Path

try:
    from tools import sm8150_xbl_mc_snapshot_xref as snapshot
    from tools import sm8150_xbl_mc_writer_stage2a as stage2a
    from tools import sm8150_xbl_mc_writer_stage2b as stage2b
except ModuleNotFoundError as error:  # direct ``python tools/...`` invocation
    if error.name != "tools":
        raise
    import sm8150_xbl_mc_snapshot_xref as snapshot
    import sm8150_xbl_mc_writer_stage2a as stage2a
    import sm8150_xbl_mc_writer_stage2b as stage2b


DEFAULT_XBL = stage2b.DEFAULT_XBL
ElfImage = snapshot.ElfImage
TARGETS = stage2a.TARGETS
XBL_SIZE = stage2b.XBL_SIZE
XBL_SHA256 = stage2b.XBL_SHA256
STAGE2C_CLASSIFICATION = (
    "NO_NUMERIC_TARGET_ADDRESS_MATCH_WITHIN_STAGE2C_UNIQUE_DIRECT_CALLER_TABLE_MODEL"
)

WRITER_VA = 0x146A70A4
WRITER_END_VA = 0x146A70DC
WRITER_FILE_OFFSET = 0x2D6074
WRITER_SIZE = 56
WRITER_SHA256 = "a50aaeb45c498a63e91704fc0ec4550b120ca0c1b691c238736b0532136dad6c"

WRAPPER_VA = 0x146A6744
WRAPPER_END_VA = 0x146A67B0
WRAPPER_FILE_OFFSET = 0x2D5714
WRAPPER_SIZE = 108
WRAPPER_SHA256 = "24008bb23f54ed515774f020ac62cb3973b74dc57a41acd2bd358567863ad436"

LOOKUP_VA = 0x146A7A08
LOOKUP_END_VA = 0x146A7B18
LOOKUP_FILE_OFFSET = 0x2D69D8
LOOKUP_SIZE = 272
LOOKUP_SHA256 = "9e54cfe4e5e2fad580b92c0853513f1be25046abeb00ff76db83d87ad3036046"

TABLE_VA = 0x146AA4D0
TABLE_FILE_OFFSET = 0x2D94A0
TABLE_ENTRY_COUNT = 48
TABLE_ENTRY_SIZE = 16
TABLE_SIZE = TABLE_ENTRY_COUNT * TABLE_ENTRY_SIZE
TABLE_END_VA = TABLE_VA + TABLE_SIZE
TABLE_COUNT_VA = TABLE_END_VA
TABLE_SHA256 = "47a7f6195703f2f4d27cbe1e8bd0cc976600453a3ba4aebba98736ef8e03906e"

WRITER_CALLER_VA = 0x146A67A4
WRITER_CALLER_FILE_OFFSET = 0x2D5774
WRITER_CALLER_TARGET = WRITER_VA
EXPECTED_DIRECT_CALLER_COUNT = 1

# Accepted prior-stage artifact pins.  Stage 2C only reads these files/results.
STAGE2A_TOOL_SHA256 = "eb0a8ce21154d97d052de9f7e4e0de40f85087a8cb517179f7c44332e9d85eb0"
STAGE2A_TEST_SHA256 = "1272fadb0bcc6b883f74577284312ee34678975fa7ba60377d05d86927960b3b"
STAGE2A_MANIFEST_SHA256 = "eeed732e4a6cecd60453e9088d8c3d4c7ed207a1e7c723bae91e27033d134a4b"
STAGE2B_TOOL_SHA256 = "aa35d8b303a7ea32a086d601b1f08390b1cad0932f105209ac337f394813dbcb"
STAGE2B_TEST_SHA256 = "af7ca7b46550dda13e85e517c0c1c1df19b6414549d06415316b6d428e020fc9"
STAGE2B_MANIFEST_SHA256 = "a4715112e27c74e5548ecb49f09106c236146c8a0216c87446ddbd3c355ccca6"

REMAINING_NON_SP_RX_CANDIDATE = {
    "virtual_address": 0x14935BF4,
    "file_offset": 0x312BC4,
    "base_register": "X19",
    "byte_offset": 0x400,
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hex(value: int, width: int | None = None) -> str:
    return f"0x{value:0{width}x}" if width else f"0x{value:x}"


def _sign_extend(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def _decode_bl(word: int, pc: int) -> dict[str, object] | None:
    if word & 0xFC000000 != 0x94000000:
        return None
    return {
        "kind": "BL",
        "target": pc + (_sign_extend(word & 0x03FFFFFF, 26) << 2),
    }


def _decode_cbz(word: int, pc: int) -> dict[str, object] | None:
    if word & 0x7F000000 != 0x34000000:
        return None
    return {
        "kind": "CBZ",
        "width_bits": 64 if (word >> 31) & 1 else 32,
        "register": word & 0x1F,
        "target": pc + (_sign_extend((word >> 5) & 0x7FFFF, 19) << 2),
    }


def _decode_add_x_immediate(word: int) -> dict[str, object] | None:
    if word & 0x7F000000 != 0x11000000:
        return None
    if (
        not (word >> 31) & 1
        or (word >> 30) & 1
        or (word >> 29) & 1
        or (word >> 23) & 1
    ):
        return None
    return {
        "kind": "ADD_IMMEDIATE_X",
        "destination": word & 0x1F,
        "source": (word >> 5) & 0x1F,
        "immediate": ((word >> 10) & 0xFFF) << (12 if (word >> 22) & 1 else 0),
    }


def _decode_mov_x(word: int) -> dict[str, object] | None:
    if word & 0xFFE0FFE0 != 0xAA0003E0:
        return None
    return {
        "kind": "MOV_REGISTER_X",
        "destination": word & 0x1F,
        "source": (word >> 16) & 0x1F,
    }


def _decode_mov_w(word: int) -> dict[str, object] | None:
    if word & 0xFFE0FFE0 != 0x2A0003E0:
        return None
    return {
        "kind": "MOV_REGISTER_W",
        "destination": word & 0x1F,
        "source": (word >> 16) & 0x1F,
    }


def _decode_add_w_immediate(word: int) -> dict[str, object] | None:
    if word & 0x7F000000 != 0x11000000:
        return None
    if (
        (word >> 31) & 1
        or (word >> 30) & 1
        or (word >> 29) & 1
        or (word >> 23) & 1
        or (word >> 22) & 1
    ):
        return None
    return {
        "kind": "ADD_IMMEDIATE_W",
        "destination": word & 0x1F,
        "source": (word >> 5) & 0x1F,
        "immediate": (word >> 10) & 0xFFF,
    }


def _decode_cmp_w_register(word: int) -> dict[str, object] | None:
    if word & 0xFFE0FC1F != 0x6B00001F:
        return None
    return {
        "kind": "CMP_REGISTER_W",
        "left": (word >> 5) & 0x1F,
        "right": (word >> 16) & 0x1F,
    }


def _decode_b(word: int, pc: int) -> dict[str, object] | None:
    if word & 0xFC000000 != 0x14000000:
        return None
    return {"kind": "B", "target": pc + (_sign_extend(word & 0x03FFFFFF, 26) << 2)}


def _decode_ldr_unsigned(word: int) -> dict[str, object] | None:
    if word & 0x3FC00000 != 0x39400000:
        return None
    size = (word >> 30) & 0x3
    if size not in (2, 3):
        return None
    return {
        "kind": "LDR_UNSIGNED_IMMEDIATE",
        "width_bits": 64 if size == 3 else 32,
        "destination": word & 0x1F,
        "base_register": (word >> 5) & 0x1F,
        "byte_offset": ((word >> 10) & 0xFFF) * (8 if size == 3 else 4),
    }


def _decode_ldr_register_offset_w(word: int) -> dict[str, object] | None:
    if word & 0xFFE0FC00 != 0xB8606800:
        return None
    if (word >> 13) & 0x7 != 0x3 or (word >> 12) & 1:
        return None
    return {
        "kind": "LDR_REGISTER_OFFSET",
        "width_bits": 32,
        "destination": word & 0x1F,
        "base_register": (word >> 5) & 0x1F,
        "index_register": (word >> 16) & 0x1F,
        "index_width": 64,
        "extend": "UXTX",
        "scale": 0,
    }


def _decode_b_cond(word: int, pc: int) -> dict[str, object] | None:
    if word & 0xFF000010 != 0x54000000:
        return None
    return {
        "kind": "B_COND",
        "condition": word & 0xF,
        "target": pc + (_sign_extend((word >> 5) & 0x7FFFF, 19) << 2),
    }


def _decode_str_unsigned(word: int) -> dict[str, object] | None:
    if word & 0x3FC00000 != 0x39000000:
        return None
    size = (word >> 30) & 0x3
    if size not in (2, 3):
        return None
    return {
        "kind": "STR_UNSIGNED_IMMEDIATE",
        "width_bits": 64 if size == 3 else 32,
        "source_register": word & 0x1F,
        "base_register": (word >> 5) & 0x1F,
        "byte_offset": ((word >> 10) & 0xFFF) * (8 if size == 3 else 4),
    }


def _decode_add_register_lsl(word: int) -> dict[str, object] | None:
    if word & 0xFF200000 != 0x8B000000:
        return None
    if (word >> 22) & 0x3 or (word >> 31) & 1 == 0:
        return None
    return {
        "kind": "ADD_REGISTER_LSL",
        "destination": word & 0x1F,
        "source": (word >> 5) & 0x1F,
        "index": (word >> 16) & 0x1F,
        "shift": (word >> 10) & 0x3F,
    }


def _decode_lsl_x(word: int) -> dict[str, object] | None:
    """Decode the 64-bit LSL alias used for the table-entry byte stride."""

    if word & 0x7F800000 != 0x53000000 or not (word >> 31) & 1:
        return None
    if (word >> 22) & 1 != 1:
        return None
    immr = (word >> 16) & 0x3F
    imms = (word >> 10) & 0x3F
    shift = (64 - immr) & 0x3F
    if shift == 0 or imms != 63 - shift:
        return None
    return {
        "kind": "LSL_IMMEDIATE_X",
        "destination": word & 0x1F,
        "source": (word >> 5) & 0x1F,
        "shift": shift,
    }


def _read_code_range(image: ElfImage, start: int, end: int, expected_offset: int,
                     expected_size: int, expected_hash: str) -> dict[str, object]:
    if end <= start or end - start != expected_size:
        raise ValueError("code range size pin is malformed")
    file_offset = image.vaddr_to_offset(start, end - start)
    if file_offset != expected_offset:
        raise ValueError(f"code range {_hex(start)} mapping mismatch")
    segment = image.segment_for_vaddr(start, end - start)
    if not segment.executable:
        raise ValueError(f"code range {_hex(start)} is not executable")
    digest = sha256(image.read_vaddr(start, end - start))
    if digest != expected_hash:
        raise ValueError(f"code range {_hex(start)} SHA-256 mismatch: {digest}")
    return {
        "virtual_address": _hex(start),
        "end_exclusive": _hex(end),
        "file_offset": _hex(file_offset),
        "byte_length": end - start,
        "sha256": digest,
        "segment_class": "RX" if not (segment.flags & 2) else "RWE",
    }


def _validate_code_ranges(image: ElfImage) -> dict[str, dict[str, object]]:
    return {
        "wrapper": _read_code_range(
            image, WRAPPER_VA, WRAPPER_END_VA, WRAPPER_FILE_OFFSET,
            WRAPPER_SIZE, WRAPPER_SHA256,
        ),
        "writer": _read_code_range(
            image, WRITER_VA, WRITER_END_VA, WRITER_FILE_OFFSET,
            WRITER_SIZE, WRITER_SHA256,
        ),
        "lookup": _read_code_range(
            image, LOOKUP_VA, LOOKUP_END_VA, LOOKUP_FILE_OFFSET,
            LOOKUP_SIZE, LOOKUP_SHA256,
        ),
    }


def scan_direct_callers(image: ElfImage, target: int) -> list[dict[str, object]]:
    hits: list[dict[str, object]] = []
    for va, file_offset, word in image.executable_words():
        decoded = _decode_bl(word, va)
        if decoded is not None and decoded["target"] == target:
            hits.append({
                "virtual_address": _hex(va),
                "file_offset": _hex(file_offset),
                "target": _hex(target),
                "segment_class": "RX" if not (image.segment_for_vaddr(va, 4).flags & 2) else "RWE",
            })
    return hits


def _word(image: ElfImage, address: int) -> int:
    return image.u32(address)


def _validate_success_path(image: ElfImage) -> dict[str, object]:
    # Wrapper: x1=SP, lookup BL, return-value branch, x0=SP, writer BL.
    add_lookup_arg = _decode_add_x_immediate(_word(image, 0x146A6770))
    lookup_call = _decode_bl(_word(image, 0x146A6774), 0x146A6774)
    lookup_branch = _decode_cbz(_word(image, 0x146A6778), 0x146A6778)
    add_writer_arg = _decode_add_x_immediate(_word(image, 0x146A67A0))
    writer_call = _decode_bl(_word(image, WRITER_CALLER_VA), WRITER_CALLER_VA)
    if add_lookup_arg != {
        "kind": "ADD_IMMEDIATE_X", "destination": 1, "source": 31, "immediate": 0,
    }:
        raise ValueError("wrapper does not pass SP in X1")
    if lookup_call != {"kind": "BL", "target": LOOKUP_VA}:
        raise ValueError("wrapper lookup BL does not target pinned lookup")
    if lookup_branch != {
        "kind": "CBZ", "width_bits": 32, "register": 0, "target": 0x146A67A0,
    }:
        raise ValueError("wrapper lookup-result branch is unexpected")
    if add_writer_arg != {
        "kind": "ADD_IMMEDIATE_X", "destination": 0, "source": 31, "immediate": 0,
    }:
        raise ValueError("wrapper does not pass SP in X0")
    if writer_call != {"kind": "BL", "target": WRITER_VA}:
        raise ValueError("wrapper writer BL does not target pinned writer")

    # Lookup: X19 derives from X1; table base is ADRP+ADD; matched pointer is
    # loaded from entry +8 and copied to [X19].
    mov_x19 = _decode_mov_x(_word(image, 0x146A7A14))
    input_id = _decode_mov_w(_word(image, 0x146A7A18))
    index_zero = _decode_mov_w(_word(image, 0x146A7A44))
    index_copy = _decode_mov_w(_word(image, 0x146A7A4C))
    index_increment = _decode_add_w_immediate(_word(image, 0x146A7A60))
    index_compare = _decode_cmp_w_register(_word(image, 0x146A7A64))
    index_loop = _decode_b_cond(_word(image, 0x146A7A68), 0x146A7A68)
    adrp = snapshot._decode_aarch64_adrp(_word(image, 0x146A7A40), 0x146A7A40)
    add_table = snapshot._decode_aarch64_add_immediate(_word(image, 0x146A7A48))
    count_page = snapshot._decode_aarch64_adrp(_word(image, 0x146A7A30), 0x146A7A30)
    count_load = _decode_ldr_unsigned(_word(image, 0x146A7A34))
    id_load = _decode_ldr_register_offset_w(_word(image, 0x146A7A54))
    index_shift = _decode_lsl_x(_word(image, 0x146A7A50))
    id_compare = _word(image, 0x146A7A58)
    id_branch = _decode_b_cond(_word(image, 0x146A7A5C), 0x146A7A5C)
    add_entry = _decode_add_register_lsl(_word(image, 0x146A7A84))
    load_pointer = _decode_ldr_unsigned(_word(image, 0x146A7A88))
    store_pointer = _decode_str_unsigned(_word(image, 0x146A7A8C))
    if mov_x19 != {"kind": "MOV_REGISTER_X", "destination": 19, "source": 1}:
        raise ValueError("lookup output register does not derive from X1")
    if input_id != {"kind": "MOV_REGISTER_W", "destination": 20, "source": 0}:
        raise ValueError("lookup ID comparison input does not derive from W0")
    if index_zero != {"kind": "MOV_REGISTER_W", "destination": 10, "source": 31}:
        raise ValueError("lookup loop index is not initialized to zero")
    if index_copy != {"kind": "MOV_REGISTER_W", "destination": 11, "source": 10}:
        raise ValueError("lookup entry index does not derive from W10")
    if count_page != (10, 0x146AA000):
        raise ValueError("lookup count ADRP is unexpected")
    if count_load != {
        "kind": "LDR_UNSIGNED_IMMEDIATE", "width_bits": 32,
        "destination": 8, "base_register": 10, "byte_offset": 0x7D0,
    }:
        raise ValueError("lookup count load is unexpected")
    if id_load != {
        "kind": "LDR_REGISTER_OFFSET", "width_bits": 32,
        "destination": 12, "base_register": 9, "index_register": 12,
        "index_width": 64, "extend": "UXTX", "scale": 0,
    }:
        raise ValueError("lookup ID load is unexpected")
    if index_shift != {
        "kind": "LSL_IMMEDIATE_X", "destination": 12, "source": 11, "shift": 4,
    }:
        raise ValueError("lookup table index shift is unexpected")
    if id_compare != 0x6B14019F:
        raise ValueError("lookup ID comparison is unexpected")
    if id_branch != {
        "kind": "B_COND", "condition": 0, "target": 0x146A7A84,
    }:
        raise ValueError("lookup ID match branch is unexpected")
    if index_increment != {
        "kind": "ADD_IMMEDIATE_W", "destination": 10, "source": 10, "immediate": 1,
    }:
        raise ValueError("lookup loop index increment is unexpected")
    if index_compare != {"kind": "CMP_REGISTER_W", "left": 10, "right": 8}:
        raise ValueError("lookup loop index/count comparison is unexpected")
    if index_loop != {"kind": "B_COND", "condition": 3, "target": 0x146A7A4C}:
        raise ValueError("lookup loop bound branch is unexpected")
    if adrp != (9, 0x146AA000):
        raise ValueError("lookup table ADRP is unexpected")
    if add_table != (9, 9, 0x4D0):
        raise ValueError("lookup table ADD is unexpected")
    if add_entry != {
        "kind": "ADD_REGISTER_LSL", "destination": 11, "source": 9,
        "index": 11, "shift": 4,
    }:
        raise ValueError("lookup entry-address formation is unexpected")
    if load_pointer != {
        "kind": "LDR_UNSIGNED_IMMEDIATE", "width_bits": 64,
        "destination": 8, "base_register": 11, "byte_offset": 8,
    }:
        raise ValueError("lookup does not load the table pointer at +8")
    if store_pointer != {
        "kind": "STR_UNSIGNED_IMMEDIATE", "width_bits": 64,
        "source_register": 8, "base_register": 19, "byte_offset": 0,
    }:
        raise ValueError("lookup does not copy the pointer through X19")
    pointer_guard = _decode_cbz(_word(image, 0x146A7A90), 0x146A7A90)
    if pointer_guard != {
        "kind": "CBZ", "width_bits": 64, "register": 8, "target": 0x146A7A70,
    }:
        raise ValueError("lookup pointer success guard is unexpected")
    success_return = _decode_mov_w(_word(image, 0x146A7B10))
    if success_return != {"kind": "MOV_REGISTER_W", "destination": 0, "source": 31}:
        raise ValueError("lookup success return-zero instruction is unexpected")
    epilogue_branch = _decode_b(_word(image, 0x146A7B14), 0x146A7B14)
    if epilogue_branch != {"kind": "B", "target": 0x146A7A78}:
        raise ValueError("lookup epilogue branch is unexpected")

    # Writer: descriptor +0x20 controls eligibility; the success fall-through
    # loads X8 from descriptor +0 and stores W9 at X8+0x400.
    descriptor_flag = _decode_ldr_unsigned(_word(image, WRITER_VA))
    descriptor_base = _decode_ldr_unsigned(_word(image, WRITER_VA + 0x10))
    writer_store = _decode_str_unsigned(_word(image, WRITER_VA + 0x1C))
    if descriptor_flag != {
        "kind": "LDR_UNSIGNED_IMMEDIATE", "width_bits": 32,
        "destination": 8, "base_register": 0, "byte_offset": 0x20,
    }:
        raise ValueError("writer eligibility load is unexpected")
    if descriptor_base != {
        "kind": "LDR_UNSIGNED_IMMEDIATE", "width_bits": 64,
        "destination": 8, "base_register": 0, "byte_offset": 0,
    }:
        raise ValueError("writer does not load X8 from descriptor X0")
    if writer_store != {
        "kind": "STR_UNSIGNED_IMMEDIATE", "width_bits": 32,
        "source_register": 9, "base_register": 8, "byte_offset": 0x400,
    }:
        raise ValueError("writer store is not W9,[X8,#0x400]")
    return {
        "wrapper": {
            "x1_setup_site": _hex(0x146A6770),
            "lookup_call_site": _hex(0x146A6774),
            "x1_source": "SP",
            "lookup_result_branch_site": _hex(0x146A6778),
            "lookup_call": _hex(LOOKUP_VA),
            "lookup_result_branch": _hex(lookup_branch["target"]),
            "x0_setup_site": _hex(0x146A67A0),
            "x0_source": "SP",
            "writer_call_site": _hex(WRITER_CALLER_VA),
            "writer_call": _hex(WRITER_VA),
        },
        "lookup": {
            "input_id_move_site": _hex(0x146A7A18),
            "count_adrp_site": _hex(0x146A7A30),
            "count_load_site": _hex(0x146A7A34),
            "count_source": {
                "register": "W8",
                "base_register": "X10",
                "byte_offset": _hex(0x7D0),
            },
            "id_compare_branch": _hex(id_branch["target"]),
            "index_zero_site": _hex(0x146A7A44),
            "index_copy_site": _hex(0x146A7A4C),
            "index_shift_site": _hex(0x146A7A50),
            "id_load_site": _hex(0x146A7A54),
            "id_compare_site": _hex(0x146A7A58),
            "id_match_branch_site": _hex(0x146A7A5C),
            "index_increment_site": _hex(0x146A7A60),
            "index_compare_site": _hex(0x146A7A64),
            "index_loop_branch_site": _hex(0x146A7A68),
            "input_id_register": "W20",
            "input_id_source": "W0",
            "index_register": "W10",
            "entry_index_register": "X11",
            "index_initial_value": 0,
            "index_increment": 1,
            "loop_bound_register": "W8",
            "loop_back_target": _hex(index_loop["target"]),
            "success_return": 0,
            "success_return_site": _hex(0x146A7B10),
            "success_epilogue_branch_site": _hex(0x146A7B14),
            "success_epilogue_branch_target": _hex(epilogue_branch["target"]),
            "output_register": "X19",
            "output_source": "X1",
            "table_base": _hex(TABLE_VA),
            "entry_stride": 16,
            "pointer_entry_offset": 8,
            "pointer_load_site": _hex(0x146A7A88),
            "pointer_store_site": _hex(0x146A7A8C),
            "pointer_output": "[X19]",
            "pointer_guard_site": _hex(0x146A7A90),
        },
        "writer": {
            "eligibility_load_site": _hex(WRITER_VA),
            "eligibility_field_offset": _hex(0x20),
            "descriptor_pointer_load_site": _hex(WRITER_VA + 0x10),
            "descriptor_pointer_load": "X8=[X0]",
            "store_source": "W9",
            "store_base": "X8",
            "store_offset": _hex(0x400),
            "store_site": _hex(0x146A70C0),
        },
        "critical_instruction_pins_verified": True,
    }


def parse_retained_table(
    image: ElfImage,
    *,
    table_va: int = TABLE_VA,
    table_file_offset: int = TABLE_FILE_OFFSET,
    entry_count: int = TABLE_ENTRY_COUNT,
    expected_hash: str | None = TABLE_SHA256,
    count_va: int | None = None,
) -> dict[str, object]:
    if entry_count <= 0:
        raise ValueError("retained table entry count must be positive")
    table_size = entry_count * TABLE_ENTRY_SIZE
    if count_va is None:
        count_va = table_va + table_size
    file_offset = image.vaddr_to_offset(table_va, table_size)
    if file_offset != table_file_offset:
        raise ValueError("retained table mapping mismatch")
    table_segment = image.segment_for_vaddr(table_va, table_size)
    digest = sha256(image.read_vaddr(table_va, table_size))
    if expected_hash is not None and digest != expected_hash:
        raise ValueError(f"retained table SHA-256 mismatch: {digest}")
    rows: list[dict[str, object]] = []
    ids: list[int] = []
    pointers: list[int] = []
    for index in range(entry_count):
        entry_va = table_va + index * TABLE_ENTRY_SIZE
        entry_offset = image.vaddr_to_offset(entry_va, TABLE_ENTRY_SIZE)
        entry_id = image.u32(entry_va)
        middle = image.u32(entry_va + 4)
        pointer = image.u64(entry_va + 8)
        if entry_id == 0:
            raise ValueError(f"retained table ID {index} is zero")
        if pointer == 0:
            raise ValueError(f"retained table pointer {index} is zero")
        if entry_id in ids:
            raise ValueError(f"retained table duplicate ID at {index}")
        if pointer in pointers:
            raise ValueError(f"retained table duplicate pointer at {index}")
        ids.append(entry_id)
        pointers.append(pointer)
        effective = pointer + 0x400
        rows.append({
            "entry_index": index,
            "entry_virtual_address": _hex(entry_va),
            "entry_file_offset": _hex(entry_offset),
            "id": _hex(entry_id),
            "base_value": _hex(pointer),
            "base_value_domain": "XBL_VIRTUAL_ADDRESS_VALUE",
            "table_derived_possible_effective_address": _hex(effective),
            "effective_address_domain": "XBL_VIRTUAL_ADDRESS_VALUE",
            "numeric_target_match": effective in TARGETS,
        })
        if middle != 0:
            raise ValueError(f"retained table reserved u32 is nonzero at {index}")
    count = image.u32(count_va)
    if count != entry_count:
        raise ValueError(f"retained table count is {count}, expected {entry_count}")
    target_bases = {0x09260000, 0x092E0000, 0x09360000, 0x093E0000}
    possible_matches = [row for row in rows if row["numeric_target_match"]]
    return {
        "virtual_address": _hex(table_va),
        "file_offset": _hex(file_offset),
        "byte_length": table_size,
        "entry_count": entry_count,
        "entry_size": TABLE_ENTRY_SIZE,
        "sha256": digest,
        "count_u32_virtual_address": _hex(count_va),
        "count_u32_file_offset": _hex(image.vaddr_to_offset(count_va, 4)),
        "count_u32": count,
        "reserved_u32_zero_count": entry_count,
        "unique_id_count": len(set(ids)),
        "unique_nonzero_pointer_count": len(set(pointers)),
        "exact_target_base_pointer_match_count": sum(pointer in target_bases for pointer in pointers),
        "possible_effective_numeric_target_match_count": len(possible_matches),
        "value_domain": "XBL_VIRTUAL_ADDRESS_VALUE",
        "va_to_pa_translation": "UNKNOWN",
        "physical_destination": None,
        "source_pt_load_pf_w": bool(table_segment.flags & 2),
        "rows": rows,
    }


def _baseline(data: bytes) -> dict[str, object]:
    prior = stage2b.analyze(data)
    return {
        "stage2a_tool_sha256": STAGE2A_TOOL_SHA256,
        "stage2a_test_sha256": STAGE2A_TEST_SHA256,
        "stage2a_manifest_sha256": STAGE2A_MANIFEST_SHA256,
        "stage2b_tool_sha256": STAGE2B_TOOL_SHA256,
        "stage2b_test_sha256": STAGE2B_TEST_SHA256,
        "stage2b_manifest_sha256": STAGE2B_MANIFEST_SHA256,
        "stage2b_classification": prior["classification"],
        "stage2b_resolved_base_count": prior["model"]["resolved_base_count"],
        "stage2b_resolved_numeric_target_hit_count": prior["model"]["resolved_numeric_target_hit_count"],
    }


def analyze(data: bytes) -> dict[str, object]:
    if len(data) != XBL_SIZE:
        raise ValueError(f"XBL size is {len(data)}, expected {XBL_SIZE}")
    digest = sha256(data)
    if digest != XBL_SHA256:
        raise ValueError(f"XBL SHA-256 mismatch: {digest}")
    image = ElfImage(data)
    ranges = _validate_code_ranges(image)
    callers = scan_direct_callers(image, WRITER_VA)
    if len(callers) != EXPECTED_DIRECT_CALLER_COUNT:
        raise ValueError(f"writer direct caller count is {len(callers)}, expected 1")
    if callers[0]["virtual_address"] != _hex(WRITER_CALLER_VA) or callers[0]["file_offset"] != _hex(WRITER_CALLER_FILE_OFFSET):
        raise ValueError("writer direct caller pin mismatch")
    flow = _validate_success_path(image)
    table = parse_retained_table(image)
    return {
        "schema": "sdm855-xbl-mc-writer-xref-stage2c-public-v1",
        "stage": "STAGE2C_UNIQUE_DIRECT_CALLER_TABLE_MODEL",
        "mode": "HOST_ONLY_READ_ONLY",
        "device_access": False,
        "smc_access": False,
        "mmio_access": False,
        "firmware_bytes_emitted": False,
        "input": {
            "filename": "xbl--sdb1.bin",
            "size": len(data),
            "sha256": digest,
            "pin_verified": True,
        },
        "scope": {
            "writer_store": {
                "virtual_address": _hex(0x146A70C0),
                "file_offset": _hex(0x2D6090),
                "source_register": "W9",
                "base_register": "X8",
                "byte_offset": _hex(0x400),
            },
            "remaining_non_sp_rx_static_candidate_count": 1,
            "remaining_non_sp_rx_static_candidate": {
                "virtual_address": _hex(REMAINING_NON_SP_RX_CANDIDATE["virtual_address"]),
                "file_offset": _hex(REMAINING_NON_SP_RX_CANDIDATE["file_offset"]),
                "base_register": REMAINING_NON_SP_RX_CANDIDATE["base_register"],
                "byte_offset": _hex(REMAINING_NON_SP_RX_CANDIDATE["byte_offset"]),
            },
            "table_derived_possible_effective_values_count": len(table["rows"]),
        },
        "code_ranges": ranges,
        "direct_callers": {
            "target": _hex(WRITER_VA),
            "count": len(callers),
            "callers": callers,
            "direct_file_backed_executable_pt_loads_only": True,
        },
        "success_path": flow,
        "retained_table": table,
        "baseline": _baseline(data),
        "claims": {
            "PROVED": [
                "The exact XBL, wrapper/writer/lookup ranges and retained 48-entry table hashes and mappings are verified.",
                "Exactly one direct BL in file-backed executable PT_LOADs targets the writer; the wrapper success path passes SP through lookup and then to that writer.",
                "The lookup success path derives X19 from X1, loads a matched table-entry pointer at +8, and copies it to [X19]; the writer success path loads X8 from [X0] and has STR W9,[X8,#0x400].",
                "The 48 table-derived base+0x400 values are a conservative possible-effective-value superset; none numerically matches the 12 targets.",
            ],
            "REFUTED": [
                "Numeric equality to one of the 12 target values within this exact unique-direct-caller retained-table model.",
            ],
            "UNKNOWN": [
                "Descriptor +0x20 eligibility for each entry, per-entry success, runtime table mutation/currentness, runtime execution, and coherent/current output.",
                "VA-to-PA translation/identity, physical destination/ownership, indirect callers, writer identity outside this direct path, register semantics, mutability/lock, GF(2), alias, bypass and other firmware paths.",
            ],
        },
        "classification": STAGE2C_CLASSIFICATION,
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
