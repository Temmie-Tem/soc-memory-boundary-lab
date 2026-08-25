#!/usr/bin/env python3
"""Host-only Experiment 018 Stage 2E SP-frame store discriminator.

This stage examines only the seven RX candidates whose encoded base register is
SP.  It proves the exact instruction forms and frame-relative bounds while
keeping the absolute runtime stack address, physical destination, execution,
and stack-integrity premises unknown.
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
except ModuleNotFoundError as error:  # direct ``python tools/...`` invocation
    if error.name != "tools":
        raise
    import sm8150_xbl_mc_snapshot_xref as snapshot
    import sm8150_xbl_mc_writer_stage2a as stage2a


DEFAULT_XBL = stage2a.DEFAULT_XBL
ElfImage = snapshot.ElfImage
XBL_SIZE = stage2a.XBL_SIZE
XBL_SHA256 = stage2a.XBL_SHA256
STAGE2E_CLASSIFICATION = (
    "SEVEN_RX_SP_CANDIDATES_ARE_PINNED_STACK_FRAME_STORES_RUNTIME_STACK_ADDRESS_UNKNOWN"
)

F1 = {
    "name": "F1",
    "virtual_address": 0x1492DF68,
    "end_exclusive": 0x1492E718,
    "file_offset": 0x30AF38,
    "size": 0x7B0,
    "sha256": "941753add8e6b033096df1bce4b0950ed2ebaec8625e3147e0ba457279325e3b",
    "caller_va": 0x1492ED64,
    "caller_file_offset": 0x30BD34,
    "caller_word": 0x97FFFC81,
    "allocation_sub_site": 0x1492DF88,
    "allocation_size": 0x5A0,
    "allocation_word": 0xD11683FF,
    "prologue_site": 0x1492DF68,
    "prologue_word": 0x6DB923E9,
    "deallocation_site": 0x1492E6F4,
    "deallocation_word": 0x911683FF,
    "epilogue_pair_site": 0x1492E710,
    "epilogue_pair_word": 0x6CC723E9,
    "ret_site": 0x1492E714,
    "ret_word": 0xD65F03C0,
    "sp_base_memory_accesses_without_writeback": 134,
    "non_sp_writeback_sites": ((0x1492DFE8, "X27"), (0x1492E4F8, "X20")),
    "non_sp_writeback_words": (0xF8428769, 0xF8408E80),
}
F2 = {
    "name": "F2",
    "virtual_address": 0x14936AE0,
    "end_exclusive": 0x14937C18,
    "file_offset": 0x313AB0,
    "size": 0x1138,
    "sha256": "861cf19f8c6c27e4be5f1dfa8b662d0723ed5b1d02a115266c00ab4165bf058e",
    "caller_va": 0x14936050,
    "caller_file_offset": 0x313020,
    "caller_word": 0x940002A4,
    "allocation_sub_site": 0x14936B08,
    "allocation_size": 0x490,
    "allocation_word": 0xD11243FF,
    "prologue_site": 0x14936AE0,
    "prologue_word": 0x6DB733ED,
    "deallocation_site": 0x14936BAC,
    "deallocation_word": 0x911243FF,
    "epilogue_pair_site": 0x14936BD0,
    "epilogue_pair_word": 0x6CC933ED,
    "ret_site": 0x14936BD4,
    "ret_word": 0xD65F03C0,
    "sp_base_memory_accesses_without_writeback": 168,
    "non_sp_writeback_sites": ((0x14936D14, "X12"), (0x14936D94, "X22")),
    "non_sp_writeback_words": (0xB801858F, 0xB84F4ECA),
}
FUNCTIONS = (F1, F2)

CANDIDATES = (
    {"virtual_address": 0x1492E3E0, "file_offset": 0x30B3B0, "function": "F1", "source_register": 8, "width_bits": 32, "byte_offset": 0x4D0, "word": 0xB904D3E8},
    {"virtual_address": 0x1492E4EC, "file_offset": 0x30B4BC, "function": "F1", "source_register": 12, "width_bits": 64, "byte_offset": 0x400, "word": 0xF90203EC},
    {"virtual_address": 0x14936EC0, "file_offset": 0x313E90, "function": "F2", "source_register": 17, "width_bits": 32, "byte_offset": 0x404, "word": 0xB90407F1},
    {"virtual_address": 0x14936EC8, "file_offset": 0x313E98, "function": "F2", "source_register": 4, "width_bits": 32, "byte_offset": 0x400, "word": 0xB90403E4},
    {"virtual_address": 0x14936EF8, "file_offset": 0x313EC8, "function": "F2", "source_register": 4, "width_bits": 32, "byte_offset": 0x400, "word": 0xB90403E4},
    {"virtual_address": 0x14936EFC, "file_offset": 0x313ECC, "function": "F2", "source_register": 17, "width_bits": 32, "byte_offset": 0x404, "word": 0xB90407F1},
    {"virtual_address": 0x149377C0, "file_offset": 0x314790, "function": "F2", "source_register": 7, "width_bits": 64, "byte_offset": 0x400, "word": 0xF90203E7},
)

RECOGNIZED_SP_WRITE_CLASSES = (
    "ADD_SUB_IMMEDIATE_TARGETING_SP",
    "ADD_SUB_EXTENDED_REGISTER_TARGETING_SP",
    "SINGLE_SCALAR_OR_VECTOR_PRE_POST_INDEX_WITH_SP_BASE",
    "PAIR_SCALAR_OR_VECTOR_PRE_POST_INDEX_WITH_SP_BASE",
)


def _sp_cfg_model() -> dict[str, object]:
    return {
        "scope": "SAME_FUNCTION_IMMEDIATE_CONTROL_CFG",
        "recognized_sp_write_classes": list(RECOGNIZED_SP_WRITE_CLASSES),
        "direct_call_handling": "BL_FALLTHROUGH",
        "unsupported_instruction_effects": "UNKNOWN",
        "normal_return_callee_sp_restoration": "SUPPORTED_SEPARATE_PREMISE",
    }


def _independent_sp_access_census(function: dict[str, object]) -> dict[str, object]:
    return {
        "count": function["sp_base_memory_accesses_without_writeback"],
        "source": "INDEPENDENT_GNU_OBJDUMP_2.46_DISASSEMBLY_CENSUS",
        "range_hash_pinned": True,
        "recomputed_by_this_tool": False,
    }

STAGE2A_TOOL_SHA256 = "eb0a8ce21154d97d052de9f7e4e0de40f85087a8cb517179f7c44332e9d85eb0"
STAGE2A_TEST_SHA256 = "1272fadb0bcc6b883f74577284312ee34678975fa7ba60377d05d86927960b3b"
STAGE2A_MANIFEST_SHA256 = "eeed732e4a6cecd60453e9088d8c3d4c7ed207a1e7c723bae91e27033d134a4b"
STAGE2B_TOOL_SHA256 = "aa35d8b303a7ea32a086d601b1f08390b1cad0932f105209ac337f394813dbcb"
STAGE2B_TEST_SHA256 = "af7ca7b46550dda13e85e517c0c1c1df19b6414549d06415316b6d428e020fc9"
STAGE2B_MANIFEST_SHA256 = "a4715112e27c74e5548ecb49f09106c236146c8a0216c87446ddbd3c355ccca6"
STAGE2C_TOOL_SHA256 = "d53d820eb8d10e8417247fabbc0e3196f73c73584a6b7d79d583a96834c34d53"
STAGE2C_TEST_SHA256 = "92c95472940937a7001fe48dd055b4c598fd290c28a1e15757d1c297ebf5f526"
STAGE2C_MANIFEST_SHA256 = "e096562a35da93a1dac10a1651fc7eff08eecf05dafca4a789bae2fd50540c01"
STAGE2D_TOOL_SHA256 = "95e53e25f288ba1ef09996ff73919c2ad1dd4186c4fec41dc84216d715ee8b26"
STAGE2D_TEST_SHA256 = "23c91a14c16706b920b4c3556e85844543dc99545a2b7b6d864a8c09d35f6136"
STAGE2D_MANIFEST_SHA256 = "48c7aa83d30844f1d42094fcb0f8d7dd13cf44265f9961167912792d014661c4"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hex(value: int) -> str:
    return f"0x{value:x}"


def _signed_hex(value: int) -> str:
    return f"-0x{-value:x}" if value < 0 else _hex(value)


def _sign_extend(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


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


def _decode_add_sub_immediate_sp(word: int) -> dict[str, object] | None:
    if word & 0x1F000000 != 0x11000000:
        return None
    if (word >> 29) & 1 or (word >> 23) & 1 or (word & 0x1F) != 31:
        return None
    operation = "SUB" if (word >> 30) & 1 else "ADD"
    return {
        "kind": f"{operation}_IMMEDIATE_SP",
        "width_bits": 64 if (word >> 31) & 1 else 32,
        "source_register": (word >> 5) & 0x1F,
        "destination_register": 31,
        "immediate": ((word >> 10) & 0xFFF) << (12 if (word >> 22) & 1 else 0),
        "shift": 12 if (word >> 22) & 1 else 0,
    }


def _decode_add_sub_register_sp(word: int) -> dict[str, object] | None:
    # ADD/SUB (extended register): retain sf/op/S and the fixed 23:21 bits.
    # The prior 0x7F... mask dropped sf, making every 64-bit form look like
    # its unreachable 32-bit key and also consumed option bits as shift.
    opcode = word & 0xFFE00000
    operations = {
        0x0B200000: ("ADD", 32), 0x4B200000: ("SUB", 32),
        0x8B200000: ("ADD", 64), 0xCB200000: ("SUB", 64),
    }
    if opcode not in operations or (word >> 29) & 1 or (word & 0x1F) != 31:
        return None
    shift = (word >> 10) & 0x7
    if shift > 4:
        return None
    operation, width_bits = operations[opcode]
    return {
        "kind": f"{operation}_REGISTER_SP",
        "width_bits": width_bits,
        "source_register": (word >> 5) & 0x1F,
        "operand_register": (word >> 16) & 0x1F,
        "destination_register": 31,
        "shift": shift,
        "extension": (word >> 13) & 0x7,
    }


_SINGLE_WRITEBACK_CLASSES = {
    0x38000400: ("POST", "STORE"), 0x38000C00: ("PRE", "STORE"),
    0x38400400: ("POST", "LOAD"), 0x38400C00: ("PRE", "LOAD"),
    0x3C000400: ("POST", "STORE"), 0x3C000C00: ("PRE", "STORE"),
    0x3C400400: ("POST", "LOAD"), 0x3C400C00: ("PRE", "LOAD"),
}


def _decode_single_writeback(word: int) -> dict[str, object] | None:
    decoded = _SINGLE_WRITEBACK_CLASSES.get(word & 0x3F600C00)
    if decoded is None:
        return None
    mode, access = decoded
    return {
        "kind": f"SINGLE_{mode}_INDEX_{access}",
        "base_register": (word >> 5) & 0x1F,
        "source_or_destination_register": word & 0x1F,
        "byte_immediate": _sign_extend((word >> 12) & 0x1FF, 9),
        "writeback": True,
    }


_PAIR_WRITEBACK_CLASSES = {
    0x28800000: ("POST", "STORE", "SCALAR"), 0x28C00000: ("POST", "LOAD", "SCALAR"),
    0x29800000: ("PRE", "STORE", "SCALAR"), 0x29C00000: ("PRE", "LOAD", "SCALAR"),
    0x2C800000: ("POST", "STORE", "VECTOR"), 0x2CC00000: ("POST", "LOAD", "VECTOR"),
    0x2D800000: ("PRE", "STORE", "VECTOR"), 0x2DC00000: ("PRE", "LOAD", "VECTOR"),
}


def _decode_pair_writeback(word: int) -> dict[str, object] | None:
    decoded = _PAIR_WRITEBACK_CLASSES.get(word & 0x3FC00000)
    if decoded is None:
        return None
    mode, access, register_class = decoded
    vector = register_class == "VECTOR"
    width_code = (word >> 30) & 0x3
    if vector:
        # S/D/Q use width codes 0/1/2; code 3 is reserved.
        element_class = {0: "S", 1: "D", 2: "Q"}.get(width_code)
        scale = {0: 4, 1: 8, 2: 16}.get(width_code)
    else:
        # W/LDPSW/X use width codes 0/1/2; code 3 is reserved.
        element_class = {0: "W", 1: "LDPSW", 2: "X"}.get(width_code)
        scale = {0: 4, 1: 4, 2: 8}.get(width_code)
        # LDPSW is a load-only encoding.  The otherwise identical scalar
        # pair-store opcode with width code 1 is reserved and must not be
        # accepted as a writeback site.
        if access == "STORE" and width_code == 1:
            return None
    if element_class is None or scale is None:
        return None
    return {
        "kind": f"PAIR_{register_class}_{mode}_INDEX_{access}",
        "mode": mode,
        "access": access,
        "register_class": register_class,
        "element_class": element_class,
        "scale": scale,
        "base_register": (word >> 5) & 0x1F,
        "first_register": word & 0x1F,
        "second_register": (word >> 10) & 0x1F,
        "byte_immediate": _sign_extend((word >> 15) & 0x7F, 7) * scale,
        "writeback": True,
    }


def _decode_ret(word: int) -> dict[str, object] | None:
    if word & 0xFFFFFC1F != 0xD65F0000:
        return None
    return {"kind": "RET", "register": (word >> 5) & 0x1F}


def _decode_indirect_branch(word: int) -> dict[str, object] | None:
    # Authenticated BR*/BLR* encodings are intentionally not claimed here;
    # any such unsupported mutation is rejected by the exact range hash.
    if word & 0xFFFFFC1F == 0xD61F0000:
        return {"kind": "BR", "register": (word >> 5) & 0x1F}
    if word & 0xFFFFFC1F == 0xD63F0000:
        return {"kind": "BLR", "register": (word >> 5) & 0x1F}
    return None


def _decode_sp_write(word: int) -> dict[str, object] | None:
    for decoder in (_decode_add_sub_immediate_sp, _decode_add_sub_register_sp):
        decoded = decoder(word)
        if decoded is not None:
            return decoded
    for decoder in (_decode_single_writeback, _decode_pair_writeback):
        decoded = decoder(word)
        if decoded is not None and decoded["base_register"] == 31:
            return decoded
    return None


def _decode_direct_branch(word: int, pc: int) -> dict[str, object] | None:
    if word & 0xFC000000 == 0x14000000:
        return {"kind": "B", "target": pc + (_sign_extend(word & 0x03FFFFFF, 26) << 2), "conditional": False}
    if word & 0xFC000000 == 0x94000000:
        return {"kind": "BL", "target": pc + (_sign_extend(word & 0x03FFFFFF, 26) << 2), "conditional": True}
    if word & 0xFF000010 == 0x54000000:
        return {"kind": "B_COND", "target": pc + (_sign_extend((word >> 5) & 0x7FFFF, 19) << 2), "conditional": True}
    if word & 0x7F000000 in (0x34000000, 0x35000000):
        return {"kind": "CBZ_CBNZ", "target": pc + (_sign_extend((word >> 5) & 0x7FFFF, 19) << 2), "conditional": True}
    if word & 0x7F000000 in (0x36000000, 0x37000000):
        return {"kind": "TBZ_TBNZ", "target": pc + (_sign_extend((word >> 5) & 0x3FFF, 14) << 2), "conditional": True}
    return None


def _read_code_range(image: ElfImage, function: dict[str, object]) -> dict[str, object]:
    start = function["virtual_address"]
    size = function["size"]
    offset = image.vaddr_to_offset(start, size)
    if offset != function["file_offset"]:
        raise ValueError(f"{function['name']} file mapping mismatch")
    segment = image.segment_for_vaddr(start, size)
    if not segment.executable:
        raise ValueError(f"{function['name']} is not executable")
    digest = sha256(image.read_vaddr(start, size))
    if digest != function["sha256"]:
        raise ValueError(f"{function['name']} SHA-256 mismatch: {digest}")
    return {
        "virtual_address": _hex(start),
        "end_exclusive": _hex(function["end_exclusive"]),
        "file_offset": _hex(offset),
        "byte_length": size,
        "sha256": digest,
        "segment_class": "RX" if not (segment.flags & 2) else "RWE",
    }


def _function_words(image: ElfImage, function: dict[str, object]) -> dict[int, int]:
    return {
        va: image.u32(va)
        for va in range(function["virtual_address"], function["end_exclusive"], 4)
    }


def _sp_manifest(function: dict[str, object]) -> dict[int, dict[str, object]]:
    if function["name"] == "F1":
        rows = (
            (function["prologue_site"], function["prologue_word"], "PAIR_VECTOR_PRE_INDEX_STORE", -0x70),
            (function["allocation_sub_site"], function["allocation_word"], "SUB_IMMEDIATE_SP", -0x5A0),
            (function["deallocation_site"], function["deallocation_word"], "ADD_IMMEDIATE_SP", 0x5A0),
            (function["epilogue_pair_site"], function["epilogue_pair_word"], "PAIR_VECTOR_POST_INDEX_LOAD", 0x70),
        )
    else:
        rows = (
            (function["prologue_site"], function["prologue_word"], "PAIR_VECTOR_PRE_INDEX_STORE", -0x90),
            (function["allocation_sub_site"], function["allocation_word"], "SUB_IMMEDIATE_SP", -0x490),
            (function["deallocation_site"], function["deallocation_word"], "ADD_IMMEDIATE_SP", 0x490),
            (function["epilogue_pair_site"], function["epilogue_pair_word"], "PAIR_VECTOR_POST_INDEX_LOAD", 0x90),
        )
    return {
        va: {"word": word, "kind": kind, "immediate": immediate, "writes_sp": True}
        for va, word, kind, immediate in rows
    }


def _memory_writeback_manifest(function: dict[str, object]) -> dict[int, dict[str, object]]:
    sp_rows = _sp_manifest(function)
    non_sp = function["non_sp_writeback_sites"]
    non_sp_words = function["non_sp_writeback_words"]
    rows = {
        va: {"word": row["word"], "kind": row["kind"], "base_register": 31}
        for va, row in sp_rows.items()
        if row["kind"].startswith("PAIR_")
    }
    for (va, register), word in zip(non_sp, non_sp_words):
        rows[va] = {
            "word": word,
            "base_register": int(register[1:]),
        }
    return rows


def _decode_explicit_memory_writeback(word: int) -> dict[str, object] | None:
    decoded = _decode_single_writeback(word)
    if decoded is not None:
        return decoded
    return _decode_pair_writeback(word)


def _public_writeback_site(va: int, decoded: dict[str, object]) -> dict[str, object]:
    base = decoded["base_register"]
    return {
        "virtual_address": _hex(va),
        "kind": decoded["kind"],
        "base_register": "SP" if base == 31 else f"X{base}",
        "byte_immediate": _signed_hex(decoded["byte_immediate"]),
        "writes_sp": base == 31,
    }


def _audit_sp_write_words(
    function: dict[str, object], words: dict[int, int],
) -> dict[str, object]:
    expected = _sp_manifest(function)
    expected_writebacks = _memory_writeback_manifest(function)
    if set(words) != set(range(function["virtual_address"], function["end_exclusive"], 4)):
        raise ValueError(f"{function['name']} word address set mismatch")
    observed: dict[int, dict[str, object]] = {}
    observed_writebacks: dict[int, dict[str, object]] = {}
    for va, word in words.items():
        decoded = _decode_sp_write(word)
        if decoded is not None:
            observed[va] = decoded
            if va not in expected:
                raise ValueError(f"unexpected SP write at {_hex(va)}")
        decoded_writeback = _decode_explicit_memory_writeback(word)
        if decoded_writeback is not None:
            observed_writebacks[va] = decoded_writeback
            expected_writeback = expected_writebacks.get(va)
            if expected_writeback is None:
                raise ValueError(f"unexpected explicit memory writeback at {_hex(va)}")
            if decoded_writeback["base_register"] != expected_writeback["base_register"]:
                raise ValueError(f"explicit memory writeback base mismatch at {_hex(va)}")
            if words[va] != expected_writeback["word"]:
                raise ValueError(f"explicit memory writeback instruction mismatch at {_hex(va)}")
    for va, row in expected.items():
        if words[va] != row["word"]:
            raise ValueError(f"audited SP-write instruction mismatch at {_hex(va)}")
        decoded = _decode_sp_write(words[va])
        if decoded is None or decoded["kind"] != row["kind"]:
            raise ValueError(f"audited SP-write class mismatch at {_hex(va)}")
    if set(observed_writebacks) != set(expected_writebacks):
        raise ValueError(f"explicit memory writeback site census mismatch for {function['name']}")
    digest = sha256(b"".join(struct.pack("<I", words[va]) for va in sorted(words)))
    if digest != function["sha256"]:
        raise ValueError(f"{function['name']} exact SP-write manifest hash mismatch: {digest}")
    return {
        "count": len(observed),
        "sites": [
            {
                "virtual_address": _hex(va),
                "kind": expected[va]["kind"],
                "immediate": _signed_hex(expected[va]["immediate"]),
                "base_register": "SP",
                "writes_sp": True,
            }
            for va in sorted(expected)
        ],
        "unexpected_count": 0,
        "recognized_sp_write_scope": list(RECOGNIZED_SP_WRITE_CLASSES),
        "unsupported_possible_sp_write_handling": "UNKNOWN_UNSUPPORTED_INSTRUCTION_EFFECTS_HASH_PINS_BYTES_ONLY",
        "range_hash_bound": True,
        "explicit_memory_writeback_audit": {
            "recognized_count": len(observed_writebacks),
            "count": len(observed_writebacks),
            "expected_count": len(expected_writebacks),
            "all_recognized_sites_accounted": set(observed_writebacks) == set(expected_writebacks),
            "sites": [
                _public_writeback_site(va, observed_writebacks[va])
                for va in sorted(observed_writebacks)
            ],
            "unexpected_count": 0,
            "missing_count": 0,
            "range_hash_bound": True,
        },
    }


def _decode_function_pins(image: ElfImage, function: dict[str, object]) -> dict[str, object]:
    words = _function_words(image, function)
    prologue = _decode_pair_writeback(words[function["prologue_site"]])
    allocation = _decode_add_sub_immediate_sp(words[function["allocation_sub_site"]])
    deallocation = _decode_add_sub_immediate_sp(words[function["deallocation_site"]])
    epilogue = _decode_pair_writeback(words[function["epilogue_pair_site"]])
    ret = _decode_ret(words[function["ret_site"]])
    if prologue != {
        "kind": "PAIR_VECTOR_PRE_INDEX_STORE", "mode": "PRE", "access": "STORE",
        "register_class": "VECTOR", "element_class": "D", "scale": 8,
        "base_register": 31, "first_register": 9 if function["name"] == "F1" else 13,
        "second_register": 8 if function["name"] == "F1" else 12,
        "byte_immediate": -0x70 if function["name"] == "F1" else -0x90, "writeback": True,
    }:
        raise ValueError(f"{function['name']} prologue pin mismatch")
    allocation_expected = {"kind": "SUB_IMMEDIATE_SP", "width_bits": 64, "source_register": 31, "destination_register": 31, "immediate": function["allocation_size"], "shift": 0}
    if allocation != allocation_expected:
        raise ValueError(f"{function['name']} local SUB pin mismatch")
    deallocation_expected = {"kind": "ADD_IMMEDIATE_SP", "width_bits": 64, "source_register": 31, "destination_register": 31, "immediate": function["allocation_size"], "shift": 0}
    if deallocation != deallocation_expected:
        raise ValueError(f"{function['name']} local ADD pin mismatch")
    if epilogue != {
        "kind": "PAIR_VECTOR_POST_INDEX_LOAD", "mode": "POST", "access": "LOAD",
        "register_class": "VECTOR", "element_class": "D", "scale": 8,
        "base_register": 31, "first_register": 9 if function["name"] == "F1" else 13,
        "second_register": 8 if function["name"] == "F1" else 12,
        "byte_immediate": 0x70 if function["name"] == "F1" else 0x90, "writeback": True,
    } or ret != {"kind": "RET", "register": 30}:
        raise ValueError(f"{function['name']} epilogue pin mismatch")
    return {
        "prologue": {"site": _hex(function["prologue_site"]), "form": "STP D9,D8,[SP,#-0x70]!" if function["name"] == "F1" else "STP D13,D12,[SP,#-0x90]!"},
        "local_allocation": {"sub_site": _hex(function["allocation_sub_site"]), "size": _hex(function["allocation_size"]), "form": f"SUB SP,SP,#{_hex(function['allocation_size'])}"},
        "epilogue": {"add_site": _hex(function["deallocation_site"]), "pair_site": _hex(function["epilogue_pair_site"]), "ret_site": _hex(function["ret_site"]), "form": "ADD SP,SP,#allocation; LDP saved D registers,[SP],#frame"},
        "pins_verified": True,
    }


def _scan_transfers(image: ElfImage, target: int) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    bl_hits = []
    b_hits = []
    for va, file_offset, word in image.executable_words():
        decoded = _decode_direct_branch(word, va)
        if decoded is None:
            continue
        record = {"virtual_address": _hex(va), "file_offset": _hex(file_offset), "target": _hex(target), "segment_class": "RX" if not (image.segment_for_vaddr(va, 4).flags & 2) else "RWE"}
        if decoded["kind"] == "BL" and decoded["target"] == target:
            bl_hits.append(record)
        if decoded["kind"] == "B" and decoded["target"] == target:
            b_hits.append(record)
    return bl_hits, b_hits


def _audit_indirect_branch_census(function: dict[str, object], words: dict[int, int]) -> dict[str, object]:
    sites = []
    for va, word in words.items():
        decoded = _decode_indirect_branch(word)
        if decoded is not None:
            sites.append({"virtual_address": _hex(va), "kind": decoded["kind"]})
    if sites:
        raise ValueError(f"recognized indirect branch in {function['name']} range")
    return {
        "recognized_kinds": ["BR", "BLR"],
        "recognized_count": len(sites),
        "count": 0,
        "sites": [],
        "range_hash_bound": True,
        "authenticated_branch_forms": "NOT_CLAIMED",
        "cfg_fails_closed_on_recognized": True,
    }


def _audit_external_direct_entries(image: ElfImage, function: dict[str, object]) -> dict[str, object]:
    start = function["virtual_address"]
    end = function["end_exclusive"]
    external = []
    internal = []
    kinds = {"B", "BL", "B_COND", "CBZ_CBNZ", "TBZ_TBNZ"}
    for va, file_offset, word in image.executable_words():
        decoded = _decode_direct_branch(word, va)
        if decoded is None or decoded["kind"] not in kinds:
            continue
        target = decoded["target"]
        if not (start <= target < end):
            continue
        record = {
            "virtual_address": _hex(va),
            "file_offset": _hex(file_offset),
            "kind": decoded["kind"],
            "target": _hex(target),
            "segment_class": "RX" if not (image.segment_for_vaddr(va, 4).flags & 2) else "RWE",
        }
        if start <= va < end:
            internal.append(record)
        else:
            external.append(record)
    external_to_interior = [row for row in external if row["target"] != _hex(start)]
    expected = external == [{
        "virtual_address": _hex(function["caller_va"]),
        "file_offset": _hex(function["caller_file_offset"]),
        "kind": "BL",
        "target": _hex(start),
        "segment_class": "RX",
    }]
    if not expected or external_to_interior:
        raise ValueError(f"{function['name']} external direct-entry census mismatch")
    return {
        "recognized_kinds": sorted(kinds),
        "external_direct_entry_count": len(external),
        "external_direct_entries": external,
        "external_direct_entry_to_interior_count": len(external_to_interior),
        "internal_direct_target_count": len(internal),
        "range_hash_bound": True,
        "indirect_callers": "UNKNOWN",
    }


def _path_sp_write_status(
    function: dict[str, object], words: dict[int, int], candidate_va: int, sp_sites: set[int],
) -> tuple[bool, bool]:
    start = function["allocation_sub_site"] + 4
    end = function["end_exclusive"]
    pending = [(start, False)]
    visited: set[tuple[int, bool]] = set()
    reached = False
    while pending:
        va, seen_write = pending.pop()
        state = (va, seen_write)
        if state in visited:
            continue
        visited.add(state)
        if va == candidate_va:
            reached = True
            if seen_write:
                return True, True
            continue
        if not (function["virtual_address"] <= va < end):
            continue
        next_seen = seen_write or va in sp_sites
        word = words[va]
        if _decode_indirect_branch(word) is not None:
            raise ValueError(f"indirect branch prevents static CFG proof at {_hex(va)}")
        if _decode_ret(word) is not None:
            continue
        branch = _decode_direct_branch(word, va)
        successors: list[int] = []
        if branch is None:
            successors = [va + 4]
        elif branch["kind"] == "BL":
            successors = [va + 4]
        elif branch["conditional"]:
            successors = [va + 4, branch["target"]]
        else:
            successors = [branch["target"]]
        for successor in successors:
            if function["virtual_address"] <= successor < end:
                pending.append((successor, next_seen))
    return reached, False


def _path_has_sp_write(function: dict[str, object], words: dict[int, int], candidate_va: int, sp_sites: set[int]) -> bool:
    reached, has_write = _path_sp_write_status(function, words, candidate_va, sp_sites)
    if not reached:
        raise ValueError(f"candidate is not reachable in static function CFG at {_hex(candidate_va)}")
    return has_write


def _frame_bounds(byte_offset: int, width_bits: int, allocation_size: int) -> dict[str, object]:
    if width_bits not in (32, 64):
        raise ValueError("unsupported frame-store width")
    width_bytes = width_bits // 8
    end_offset = byte_offset + width_bytes
    if byte_offset < 0 or end_offset > allocation_size:
        raise ValueError("frame-store access exceeds local allocation")
    return {
        "access_start_offset": _hex(byte_offset),
        "access_end_offset_exclusive": _hex(end_offset),
        "remaining_allocation_after_access": _hex(allocation_size - end_offset),
        "within_allocation": True,
    }


def _candidate_record(image: ElfImage, candidate: dict[str, object], function: dict[str, object], words: dict[int, int], sp_audit: dict[str, object]) -> dict[str, object]:
    word = words[candidate["virtual_address"]]
    decoded = _decode_str_unsigned(word)
    expected = {
        "kind": "STR_UNSIGNED_IMMEDIATE", "width_bits": candidate["width_bits"],
        "source_register": candidate["source_register"], "base_register": 31,
        "byte_offset": candidate["byte_offset"],
    }
    if image.vaddr_to_offset(candidate["virtual_address"], 4) != candidate["file_offset"] or word != candidate["word"] or decoded != expected:
        raise ValueError(f"candidate pin mismatch at {_hex(candidate['virtual_address'])}")
    bounds = _frame_bounds(candidate["byte_offset"], candidate["width_bits"], function["allocation_size"])
    sp_sites = {int(site["virtual_address"], 0) for site in sp_audit["sites"]}
    path_write = _path_has_sp_write(function, words, candidate["virtual_address"], sp_sites)
    if path_write:
        raise ValueError(f"SP write reaches candidate path at {_hex(candidate['virtual_address'])}")
    source_name = ("X" if candidate["width_bits"] == 64 else "W") + str(candidate["source_register"])
    return {
        "virtual_address": _hex(candidate["virtual_address"]),
        "file_offset": _hex(candidate["file_offset"]),
        "form": f"STR {source_name},[SP,#{_hex(candidate['byte_offset'])}]",
        "source_register": source_name,
        "base_register": "SP",
        "width_bits": candidate["width_bits"],
        "byte_offset": _hex(candidate["byte_offset"]),
        "local_frame_bounds": {
            "allocation_sub_site": _hex(function["allocation_sub_site"]),
            "allocation_size": _hex(function["allocation_size"]),
            **bounds,
        },
        "recognized_sp_write_sites_on_same_function_immediate_control_cfg_path": 0,
        "sp_write_cfg_model": _sp_cfg_model(),
        "runtime_absolute_stack_address": "UNKNOWN",
    }


def _baseline() -> dict[str, str]:
    return {
        "stage2a_tool_sha256": STAGE2A_TOOL_SHA256,
        "stage2a_test_sha256": STAGE2A_TEST_SHA256,
        "stage2a_manifest_sha256": STAGE2A_MANIFEST_SHA256,
        "stage2b_tool_sha256": STAGE2B_TOOL_SHA256,
        "stage2b_test_sha256": STAGE2B_TEST_SHA256,
        "stage2b_manifest_sha256": STAGE2B_MANIFEST_SHA256,
        "stage2c_tool_sha256": STAGE2C_TOOL_SHA256,
        "stage2c_test_sha256": STAGE2C_TEST_SHA256,
        "stage2c_manifest_sha256": STAGE2C_MANIFEST_SHA256,
        "stage2d_tool_sha256": STAGE2D_TOOL_SHA256,
        "stage2d_test_sha256": STAGE2D_TEST_SHA256,
        "stage2d_manifest_sha256": STAGE2D_MANIFEST_SHA256,
    }


def analyze(data: bytes) -> dict[str, object]:
    if len(data) != XBL_SIZE:
        raise ValueError(f"XBL size is {len(data)}, expected {XBL_SIZE}")
    digest = sha256(data)
    if digest != XBL_SHA256:
        raise ValueError(f"XBL SHA-256 mismatch: {digest}")
    image = ElfImage(data)
    function_results = {}
    candidate_by_function = {name: [] for name in ("F1", "F2")}
    for candidate in CANDIDATES:
        candidate_by_function[candidate["function"]].append(candidate)
    all_candidates = []
    for function in FUNCTIONS:
        code = _read_code_range(image, function)
        words = _function_words(image, function)
        pins = _decode_function_pins(image, function)
        audit = _audit_sp_write_words(function, words)
        indirect_census = _audit_indirect_branch_census(function, words)
        external_entries = _audit_external_direct_entries(image, function)
        callers, branches = _scan_transfers(image, function["virtual_address"])
        if len(callers) != 1 or callers[0]["virtual_address"] != _hex(function["caller_va"]):
            raise ValueError(f"{function['name']} direct-BL caller census mismatch")
        if branches:
            raise ValueError(f"{function['name']} has an unexpected direct-B caller")
        if image.vaddr_to_offset(function["caller_va"], 4) != function["caller_file_offset"] or image.u32(function["caller_va"]) != function["caller_word"]:
            raise ValueError(f"{function['name']} caller pin mismatch")
        candidates = [_candidate_record(image, candidate, function, words, audit) for candidate in candidate_by_function[function["name"]]]
        all_candidates.extend(candidates)
        function_results[function["name"]] = {
            "range": code,
            "direct_bl_count": len(callers),
            "direct_bl_callers": callers,
            "direct_b_count": len(branches),
            "direct_b_callers": branches,
            "frame_pins": pins,
            "sp_write_census": audit,
            "indirect_branch_census": indirect_census,
            "external_direct_entry_census": external_entries,
            "instruction_count": function["size"] // 4,
            "sp_base_memory_access_census": _independent_sp_access_census(function),
            "non_sp_writeback_sites": [
                site for site in audit["explicit_memory_writeback_audit"]["sites"]
                if not site["writes_sp"]
            ],
            "candidate_count": len(candidates),
        }
    return {
        "schema": "sdm855-xbl-mc-writer-xref-stage2e-public-v1",
        "stage": "STAGE2E_RX_SP_FRAME_STORE_MODEL",
        "mode": "HOST_ONLY_READ_ONLY",
        "device_access": False,
        "smc_access": False,
        "mmio_access": False,
        "firmware_bytes_emitted": False,
        "input": {"filename": "xbl--sdb1.bin", "size": len(data), "sha256": digest, "pin_verified": True},
        "accounting": {
            "rx_candidate_count_examined": 11,
            "rx_non_sp_candidate_count_examined_prior_stage2a_to_2d": 4,
            "rx_sp_candidate_count_examined": len(all_candidates),
            "rwe_candidate_count_outside_scope_unknown": 3,
            "all_eleven_rx_candidates_examined": True,
            "stage2e_candidate_count": len(all_candidates),
        },
        "functions": function_results,
        "candidates": all_candidates,
        "baseline": _baseline(),
        "claims": {
            "PROVED": [
                "All seven scoped RX candidates decode as STR W/X unsigned-immediate stores with architectural base register SP and the pinned mappings, widths, offsets and source registers.",
                "Both exact function ranges, unique direct-BL callers, prologues, local SUB allocations, epilogues and RET pins are verified.",
                "Each candidate access lies fully within its function's local SUB allocation.",
                "The same-function immediate-control CFG (with BL modeled as fallthrough) has no recognized SP-write-class instruction after allocation on a path to each candidate; the recognized scope is ADD/SUB immediate or extended targeting SP plus scalar/vector single/pair pre/post-index forms with SP base.",
                "The explicit memory-writeback audit recognizes and accounts for exactly four writeback sites in each function (two SP frame sites and two non-SP sites), with base registers mechanically checked.",
                "A scan of all file-backed executable PT_LOAD words finds exactly one external direct BL to each function start and no external direct entry to either function interior; recognized BR/BLR counts inside both ranges are zero.",
            ],
            "SUPPORTED": [
                "A normally conforming stack frame and normal-return/callee SP restoration support treating the pinned SP-relative accesses as local-frame stores; this is a separate premise and runtime stack integrity is not established.",
            ],
            "HYPOTHESIS": [
                "Under a well-formed, normally executing stack frame, these seven stores write stack-resident state rather than a statically materialized controller base.",
            ],
            "REFUTED": [
                "Within the pinned normal stack-frame model, these seven encodings are not static absolute target writers or controller-base-GPR stores.",
            ],
            "UNKNOWN": [
                "Absolute runtime stack address, VA-to-PA translation, physical destination/ownership, stack corruption or rebasing, unsupported instruction-class SP effects/semantics, execution, indirect callers, callee behavior, runtime semantics, mutability/lock, alias, bypass and writer identity remain UNKNOWN.",
                "The three RWE candidates are explicitly outside this RX-only stage and remain UNKNOWN.",
            ],
        },
        "classification": STAGE2E_CLASSIFICATION,
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
