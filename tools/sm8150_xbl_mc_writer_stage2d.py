#!/usr/bin/env python3
"""Host-only Experiment 018 Stage 2D conditional X19 writer analysis.

The exact XBL contains one remaining non-SP RX candidate after Stage 2C.  This
stage pins its direct caller and the local code/data path, while keeping final
numeric-address claims conditional on runtime success, import-slot currentness,
and explicitly stated callee-preservation premises.
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
    from tools import sm8150_xbl_mc_writer_stage2c as stage2c
except ModuleNotFoundError as error:  # direct ``python tools/...`` invocation
    if error.name != "tools":
        raise
    import sm8150_xbl_mc_snapshot_xref as snapshot
    import sm8150_xbl_mc_writer_stage2a as stage2a
    import sm8150_xbl_mc_writer_stage2c as stage2c


DEFAULT_XBL = stage2c.DEFAULT_XBL
ElfImage = snapshot.ElfImage
TARGETS = stage2a.TARGETS
XBL_SIZE = stage2c.XBL_SIZE
XBL_SHA256 = stage2c.XBL_SHA256
STAGE2D_CLASSIFICATION = (
    "NO_NUMERIC_TARGET_ADDRESS_MATCH_WITHIN_STAGE2D_UNIQUE_DIRECT_CALLER_CONDITIONAL_CALLEE_SAVED_PRESERVATION_MODEL"
)

FUNCTION_VA = 0x14935960
FUNCTION_END_VA = 0x14935EDC
FUNCTION_FILE_OFFSET = 0x312930
FUNCTION_SIZE = FUNCTION_END_VA - FUNCTION_VA
FUNCTION_SHA256 = "68739df6f843f790376eb0af47da22f0af5ebeb2421f05d29c3b5a8673983fd9"

INITIALIZER_VA = 0x14844580
INITIALIZER_END_VA = 0x14844DAC
INITIALIZER_FILE_OFFSET = 0x2B580
INITIALIZER_SIZE = INITIALIZER_END_VA - INITIALIZER_VA
INITIALIZER_SHA256 = "65e117b99fd109cbb01531bd70fc2befe70c0b672a01afe6dd523bbebf1486cb"
INITIALIZER_CALLER_VA = 0x14828270
INITIALIZER_CALLER_FILE_OFFSET = 0xF270
BOOT_ENTRY_CALL_SITE = 0x1481C9B4
BOOT_ENTRY_CALL_TARGET = 0x14828198
BOOT_ENTRY_SKIP_SITE = 0x148281C0
BOOT_ENTRY_SKIP_TARGET = 0x148282C8

TARGET_CALLEE_VA = 0x1483C904
TARGET_CALLEE_END_VA = 0x1483C9E8
TARGET_CALLEE_FILE_OFFSET = 0x23904
TARGET_CALLEE_SIZE = TARGET_CALLEE_END_VA - TARGET_CALLEE_VA
TARGET_CALLEE_SHA256 = "5c979955c6d1cdfd541766ca3ea6964460803d61aa3d07bed0c74f60d3eec34e"
PRE_MADD_DIRECT_CALLEE_VA = 0x1493641C
PRE_MADD_DIRECT_CALLEE_END_VA = 0x1493697C
PRE_MADD_DIRECT_CALLEE_FILE_OFFSET = 0x3133EC
PRE_MADD_DIRECT_CALLEE_SIZE = PRE_MADD_DIRECT_CALLEE_END_VA - PRE_MADD_DIRECT_CALLEE_VA
PRE_MADD_DIRECT_CALLEE_SHA256 = "43fa9c70453b7ad1d8ff88d4ca07b375d2dc6b3b06e805339b2ad1927e4487e0"
PRE_MADD_SAVE_SITE = 0x14936428
PRE_MADD_RESTORE_SITE = 0x149365A8
PRE_MADD_RET_SITE = 0x149365B4

CANDIDATE_VA = 0x14935BF4
CANDIDATE_FILE_OFFSET = 0x312BC4
CANDIDATE_WORD = 0xF9020269
POST_CALL_X9_RANGE_VA = 0x14935BA0
POST_CALL_X9_RANGE_END_VA = CANDIDATE_VA
POST_CALL_X9_RANGE_FILE_OFFSET = 0x312B70
POST_CALL_X9_RANGE_SIZE = POST_CALL_X9_RANGE_END_VA - POST_CALL_X9_RANGE_VA
POST_CALL_X9_RANGE_SHA256 = "94e85068fba48edb7f799e0ab51fb8e3f9e4ffd8c8d7b5d2a4f10705ed8e8318"

CALLER_VA = 0x14949EEC
CALLER_FILE_OFFSET = 0x326EBC
CALLER_TARGET = FUNCTION_VA
CALLER_WORD = 0x97FFAE9D
EXPECTED_DIRECT_CALLER_COUNT = 1

CALLER_ZERO_SITE = 0x14949EC8
CALLER_LOOKUP_CALL_SITE = 0x14949ED0
CALLER_LOOKUP_TARGET = 0x14935868
CALLER_BRANCH_SITE = 0x14949ED4
CALLER_BRANCH_TARGET = 0x14949EE4
CALLER_X1_SETUP_SITE = 0x14949EE4
CALLER_W2_ZERO_SITE = 0x14949EE8

CALLEE_DISPATCH_SUB_SITE = 0x149359C4
CALLEE_DISPATCH_CMP_SITE = 0x149359C8
CALLEE_DISPATCH_BRANCH_SITE = 0x149359CC
CALLEE_DISPATCH_TARGET = 0x14935AAC
PRE_MADD_RESULT_BRANCH_SITE = 0x14935AC0
PRE_MADD_RESULT_BRANCH_TARGET = 0x14935CE8

WRAPPER_VA = 0x149396F4
WRAPPER_END_VA = 0x14939704
WRAPPER_FILE_OFFSET = 0x3166C4
WRAPPER_SIZE = 16
WRAPPER_SHA256 = "bdacf0c0105dcf377f9f0a431bae20513fdf216669a69c35ad34a141186e1ac4"

THUNK_VA = 0x14900254
THUNK_END_VA = 0x14900264
THUNK_FILE_OFFSET = 0x2DD224
THUNK_SIZE = 16
THUNK_SHA256 = "85978d37e0b5ccb6ee6ecc601e21cb4901a5953382872ac9e928c0476c8a2493"

IMPORT_SLOT_VA = 0x1489F3B0
IMPORT_SEGMENT_START = 0x14882800
IMPORT_SEGMENT_END = 0x1489F400

EFFECTIVE_SEGMENT_START = 0x85E44000
EFFECTIVE_SEGMENT_FILE_SIZE = 0x43620
EFFECTIVE_SEGMENT_MEMORY_SIZE = 0x66038
EFFECTIVE_SEGMENT_FILE_END = EFFECTIVE_SEGMENT_START + EFFECTIVE_SEGMENT_FILE_SIZE
EFFECTIVE_SEGMENT_MEMORY_END = EFFECTIVE_SEGMENT_START + EFFECTIVE_SEGMENT_MEMORY_SIZE

STAGE2A_TOOL_SHA256 = "eb0a8ce21154d97d052de9f7e4e0de40f85087a8cb517179f7c44332e9d85eb0"
STAGE2A_TEST_SHA256 = "1272fadb0bcc6b883f74577284312ee34678975fa7ba60377d05d86927960b3b"
STAGE2A_MANIFEST_SHA256 = "eeed732e4a6cecd60453e9088d8c3d4c7ed207a1e7c723bae91e27033d134a4b"
STAGE2B_TOOL_SHA256 = "aa35d8b303a7ea32a086d601b1f08390b1cad0932f105209ac337f394813dbcb"
STAGE2B_TEST_SHA256 = "af7ca7b46550dda13e85e517c0c1c1df19b6414549d06415316b6d428e020fc9"
STAGE2B_MANIFEST_SHA256 = "a4715112e27c74e5548ecb49f09106c236146c8a0216c87446ddbd3c355ccca6"
STAGE2C_TOOL_SHA256 = "d53d820eb8d10e8417247fabbc0e3196f73c73584a6b7d79d583a96834c34d53"
STAGE2C_TEST_SHA256 = "92c95472940937a7001fe48dd055b4c598fd290c28a1e15757d1c297ebf5f526"
STAGE2C_MANIFEST_SHA256 = "e096562a35da93a1dac10a1651fc7eff08eecf05dafca4a789bae2fd50540c01"


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
    return {"kind": "BL", "target": pc + (_sign_extend(word & 0x03FFFFFF, 26) << 2)}


def _decode_b(word: int, pc: int) -> dict[str, object] | None:
    if word & 0xFC000000 != 0x14000000:
        return None
    return {"kind": "B", "target": pc + (_sign_extend(word & 0x03FFFFFF, 26) << 2)}


def _decode_cbz(word: int, pc: int) -> dict[str, object] | None:
    if word & 0x7F000000 != 0x34000000:
        return None
    return {
        "kind": "CBZ",
        "width_bits": 64 if (word >> 31) & 1 else 32,
        "register": word & 0x1F,
        "target": pc + (_sign_extend((word >> 5) & 0x7FFFF, 19) << 2),
    }


def _decode_cbnz(word: int, pc: int) -> dict[str, object] | None:
    if word & 0x7F000000 != 0x35000000:
        return None
    return {
        "kind": "CBNZ",
        "width_bits": 64 if (word >> 31) & 1 else 32,
        "register": word & 0x1F,
        "target": pc + (_sign_extend((word >> 5) & 0x7FFFF, 19) << 2),
    }


def _decode_blr(word: int) -> dict[str, object] | None:
    if word & 0xFFFFFC1F != 0xD63F0000:
        return None
    return {"kind": "BLR", "register": (word >> 5) & 0x1F}


def _decode_ret(word: int) -> dict[str, object] | None:
    if word & 0xFFFFFC1F != 0xD65F0000:
        return None
    return {"kind": "RET", "register": (word >> 5) & 0x1F}


def _decode_sub_w_immediate(word: int) -> dict[str, object] | None:
    if word & 0x7F000000 != 0x51000000:
        return None
    if not (word >> 30) & 1 or (word >> 29) & 1 or (word >> 23) & 1:
        return None
    return {
        "kind": "SUB_IMMEDIATE_W",
        "destination": word & 0x1F,
        "source": (word >> 5) & 0x1F,
        "immediate": (word >> 10) & 0xFFF,
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


def _decode_cmp_w_immediate(word: int) -> dict[str, object] | None:
    if word & 0x7F00001F != 0x7100001F:
        return None
    return {
        "kind": "CMP_IMMEDIATE_W",
        "source": (word >> 5) & 0x1F,
        "immediate": (word >> 10) & 0xFFF,
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


def _decode_str_post_index(word: int) -> dict[str, object] | None:
    """Decode scalar W/X STR post-index and its architectural base writeback."""
    if word & 0x3F600C00 != 0x38000400:
        return None
    size = (word >> 30) & 0x3
    width_bits = (8, 16, 32, 64)[size]
    immediate = _sign_extend((word >> 12) & 0x1FF, 9)
    return {
        "kind": "STR_POST_INDEX",
        "width_bits": width_bits,
        "source_register": word & 0x1F,
        "base_register": (word >> 5) & 0x1F,
        "byte_offset": immediate,
        "base_writeback_register": (word >> 5) & 0x1F,
    }


def _decode_ldp_signed_offset(word: int) -> dict[str, object] | None:
    """Decode scalar W/X LDP signed-offset and extract both destinations."""
    if word & 0x3FC00000 != 0x29400000:
        return None
    width_bits = 64 if (word >> 31) & 1 else 32
    scale = 8 if width_bits == 64 else 4
    immediate = _sign_extend((word >> 15) & 0x7F, 7) * scale
    return {
        "kind": "LDP_SIGNED_OFFSET",
        "width_bits": width_bits,
        "first_destination": word & 0x1F,
        "second_destination": (word >> 10) & 0x1F,
        "base_register": (word >> 5) & 0x1F,
        "byte_offset": immediate,
    }


def _decode_madd_x(word: int) -> dict[str, object] | None:
    if word & 0xFFE00000 != 0x9B000000:
        return None
    return {
        "kind": "MADD_X",
        "destination": word & 0x1F,
        "left": (word >> 5) & 0x1F,
        "right": (word >> 16) & 0x1F,
        "accumulator": (word >> 10) & 0x1F,
    }


def _decode_orr_w_logical_immediate(word: int) -> dict[str, object] | None:
    # The exact aliases below are pinned as logical-immediate constants.  The
    # decoder is deliberately narrow: unsupported encodings fail closed.
    constants = {
        0x321707E8: (8, 0x600),
        0x321707E9: (9, 0x600),
        0x321707ED: (13, 0x600),
    }
    if word not in constants:
        return None
    destination, immediate = constants[word]
    return {"kind": "ORR_W_IMMEDIATE", "destination": destination, "immediate": immediate}


# This is an audited, exact instruction-class/write-set manifest for the
# 228-byte target range.  It is deliberately source-private: public output
# carries only the range hash and the resulting census, never these words.
# The manifest is bound to TARGET_CALLEE_SHA256 below and is checked word for
# word before any register-preservation conclusion is emitted.  A small exact
# allowlist is preferable here to pretending that bits [4:0] are a universal
# architectural destination field.
_TARGET_CALLEE_AUDIT_ROWS = (
    (0x1483C904, 0x9240080C, "ALU", (12,)),
    (0x1483C908, 0xB500034C, "CBNZ", ()),
    (0x1483C90C, 0x7100205F, "COMPARE", ()),
    (0x1483C910, 0x54000303, "B_COND", ()),
    (0x1483C914, 0x2A2203EC, "ALU", (12,)),
    (0x1483C918, 0x3100219F, "COMPARE", ()),
    (0x1483C91C, 0x321D73EB, "ALU", (11,)),
    (0x1483C920, 0x2A014029, "ALU", (9,)),
    (0x1483C924, 0x5A82916C, "ALU", (12,)),
    (0x1483C928, 0x2A01612A, "ALU", (10,)),
    (0x1483C92C, 0x0B02018D, "ALU", (13,)),
    (0x1483C930, 0x2A012149, "ALU", (9,)),
    (0x1483C934, 0x110021AE, "ALU", (14,)),
    (0x1483C938, 0x121D71CB, "ALU", (11,)),
    (0x1483C93C, 0x8B0B0008, "ALU", (8,)),
    (0x1483C940, 0x2A0203EA, "ALU", (10,)),
    (0x1483C944, 0xB3607D29, "ALU", (9,)),
    (0x1483C948, 0x14000002, "B", ()),
    (0x1483C94C, 0xF8008409, "STORE_POST_INDEX", (0,)),
    (0x1483C950, 0x7100214A, "ALU", (10,)),
    (0x1483C954, 0x54FFFFC2, "B_COND", ()),
    (0x1483C958, 0x4B0B0049, "ALU", (9,)),
    (0x1483C95C, 0x14000003, "B", ()),
    (0x1483C960, 0x38001501, "STORE_POST_INDEX", (8,)),
    (0x1483C964, 0x51000529, "ALU", (9,)),
    (0x1483C968, 0x35FFFFC9, "CBNZ", ()),
    (0x1483C96C, 0x1400001E, "B", ()),
    (0x1483C970, 0x9240040D, "ALU", (13,)),
    (0x1483C974, 0xB500024D, "CBNZ", ()),
    (0x1483C978, 0x71000C5F, "COMPARE", ()),
    (0x1483C97C, 0x54000209, "B_COND", ()),
    (0x1483C980, 0x2A2203EF, "ALU", (15,)),
    (0x1483C984, 0x310011FF, "COMPARE", ()),
    (0x1483C988, 0x321E77EF, "ALU", (15,)),
    (0x1483C98C, 0x5A8291F0, "ALU", (16,)),
    (0x1483C990, 0x0B020210, "ALU", (16,)),
    (0x1483C994, 0x2A01402D, "ALU", (13,)),
    (0x1483C998, 0x11001211, "ALU", (17,)),
    (0x1483C99C, 0x2A0161AE, "ALU", (14,)),
    (0x1483C9A0, 0x121E762A, "ALU", (10,)),
    (0x1483C9A4, 0x2A0121C8, "ALU", (8,)),
    (0x1483C9A8, 0x8B0A0009, "ALU", (9,)),
    (0x1483C9AC, 0x2A0203EB, "ALU", (11,)),
    (0x1483C9B0, 0x14000006, "B", ()),
    (0x1483C9B4, 0x38001401, "STORE_POST_INDEX", (0,)),
    (0x1483C9B8, 0x51000442, "ALU", (2,)),
    (0x1483C9BC, 0x35FFFFC2, "CBNZ", ()),
    (0x1483C9C0, 0x14000009, "B", ()),
    (0x1483C9C4, 0xB8004408, "STORE_POST_INDEX", (0,)),
    (0x1483C9C8, 0x7100116B, "ALU", (11,)),
    (0x1483C9CC, 0x54FFFFC2, "B_COND", ()),
    (0x1483C9D0, 0x4B0A0048, "ALU", (8,)),
    (0x1483C9D4, 0x14000003, "B", ()),
    (0x1483C9D8, 0x38001521, "STORE_POST_INDEX", (9,)),
    (0x1483C9DC, 0x51000508, "ALU", (8,)),
    (0x1483C9E0, 0x35FFFFC8, "CBNZ", ()),
    (0x1483C9E4, 0xD65F03C0, "RET", ()),
)
_TARGET_CALLEE_AUDIT = {
    va: {"word": word, "kind": kind, "writes_gpr": frozenset(writes)}
    for va, word, kind, writes in _TARGET_CALLEE_AUDIT_ROWS
}


def _known_forbidden_control(word: int, pc: int) -> dict[str, object] | None:
    """Return a forbidden/control decode used by exact-range audits."""
    for decoder in (_decode_bl, _decode_blr, _decode_br, _decode_b, _decode_b_cond,
                    _decode_cbz, _decode_cbnz, _decode_ret):
        decoded = decoder(word, pc) if decoder in (_decode_bl, _decode_b, _decode_b_cond, _decode_cbz, _decode_cbnz) else decoder(word)
        if decoded is not None:
            return decoded
    return None


def _audit_target_callee_words(words: dict[int, int] | list[tuple[int, int]]) -> dict[str, object]:
    """Audit exact target words and their explicit architectural write sets."""
    actual = dict(words)
    if set(actual) != set(_TARGET_CALLEE_AUDIT):
        raise ValueError("target callee audit address set mismatch")
    direct_b = 0
    controls = 0
    ret_count = 0
    for va, spec in _TARGET_CALLEE_AUDIT.items():
        word = actual[va]
        if spec["kind"] not in {"ALU", "COMPARE", "STORE_POST_INDEX", "B", "B_COND", "CBZ", "CBNZ", "RET"}:
            raise ValueError(f"target callee unsupported audited class at {_hex(va)}")
        # Detect the two safety-critical mutation classes before exact-word
        # comparison, so tests and callers get a semantic fail-closed reason,
        # not merely a range-hash mismatch.
        if _decode_br(word) is not None or _decode_blr(word) is not None:
            raise ValueError(f"target callee indirect control transfer at {_hex(va)}")
        if _decode_bl(word, va) is not None:
            raise ValueError(f"target callee BL at {_hex(va)}")
        for decoder in (_decode_b, _decode_b_cond, _decode_cbz, _decode_cbnz):
            decoded = decoder(word, va)
            if decoded is not None and decoded["target"] not in range(TARGET_CALLEE_VA, TARGET_CALLEE_END_VA, 4):
                raise ValueError(f"target callee branch escapes range at {_hex(va)}")
        if _decode_ret(word) is not None:
            ret_count += 1
        expected_word = spec["word"]
        if word != expected_word:
            decoded_x = _decode_mov_x(word)
            decoded_w = _decode_mov_w(word)
            decoded_store = _decode_str_post_index(word)
            if decoded_store is not None and 19 <= decoded_store["base_register"] <= 29:
                raise ValueError(f"target callee saved-register writeback at {_hex(va)}")
            if (decoded_x is not None and 19 <= decoded_x["destination"] <= 29) or (
                decoded_w is not None and 19 <= decoded_w["destination"] <= 29
            ):
                raise ValueError(f"target callee saved-register definition at {_hex(va)}")
            raise ValueError(f"target callee audited instruction mismatch at {_hex(va)}")
        kind = spec["kind"]
        decoded_control = _known_forbidden_control(word, va)
        if kind in {"B", "B_COND", "CBZ", "CBNZ"}:
            if decoded_control is None or decoded_control["kind"] != kind:
                raise ValueError(f"target callee control class mismatch at {_hex(va)}")
            controls += 1
            if kind == "B":
                direct_b += 1
        elif kind == "RET":
            if decoded_control is None or decoded_control["kind"] != "RET":
                raise ValueError("target callee RET class mismatch")
        elif decoded_control is not None:
            raise ValueError(f"unexpected control class at {_hex(va)}")
        if kind == "STORE_POST_INDEX":
            decoded_store = _decode_str_post_index(word)
            if decoded_store is None or decoded_store["base_writeback_register"] not in spec["writes_gpr"]:
                raise ValueError(f"target callee post-index writeback mismatch at {_hex(va)}")
            if set(spec["writes_gpr"]) != {decoded_store["base_writeback_register"]}:
                raise ValueError(f"target callee post-index write-set mismatch at {_hex(va)}")
        if any(19 <= register <= 29 for register in spec["writes_gpr"]):
            raise ValueError(f"target callee audited saved-register write at {_hex(va)}")
    if ret_count != 1:
        raise ValueError(f"target callee RET count is {ret_count}, expected 1")
    return {"direct_b_count": direct_b, "control_transfer_count": controls + ret_count, "ret_count": ret_count}


_POST_CALL_X9_AUDIT_ROWS = (
    (0x14935BA4, 0xB9439668, "LOAD", (8,)),
    (0x14935BA8, 0xF9400602, "LOAD", (2,)),
    (0x14935BAC, 0x39400211, "LOAD", (17,)),
    (0x14935BB0, 0xF9400A03, "LOAD", (3,)),
    (0x14935BB4, 0xB9042A61, "STORE", ()),
    (0x14935BB8, 0x910F2261, "ALU", (1,)),
    (0x14935BBC, 0xF901D662, "STORE", ()),
    (0x14935BC0, 0xB9401A02, "LOAD", (2,)),
    (0x14935BC4, 0x2943C206, "LOAD_PAIR", (6, 16)),
    (0x14935BC8, 0xB903BE71, "STORE", ()),
    (0x14935BCC, 0xB9039E62, "STORE", ()),
    (0x14935BD0, 0xF9021264, "STORE", ()),
    (0x14935BD4, 0xB903A266, "STORE", ()),
    (0x14935BD8, 0xB9039270, "STORE", ()),
    (0x14935BDC, 0xB9042E67, "STORE", ()),
    (0x14935BE0, 0xB9043275, "STORE", ()),
    (0x14935BE4, 0xF901DA63, "STORE", ()),
    (0x14935BE8, 0xF9020E69, "STORE", ()),
    (0x14935BEC, 0xF9000FE1, "STORE", ()),
    (0x14935BF0, 0xB903D270, "STORE", ()),
)
_POST_CALL_X9_AUDIT = {
    va: {"word": word, "kind": kind, "writes_gpr": frozenset(writes)}
    for va, word, kind, writes in _POST_CALL_X9_AUDIT_ROWS
}


def _audit_post_call_x9_words(words: dict[int, int] | list[tuple[int, int]]) -> dict[str, object]:
    actual = dict(words)
    if set(actual) != set(_POST_CALL_X9_AUDIT):
        raise ValueError("post-call X9 audit address set mismatch")
    for va, spec in _POST_CALL_X9_AUDIT.items():
        word = actual[va]
        if spec["kind"] not in {"ALU", "LOAD", "LOAD_PAIR", "STORE"}:
            raise ValueError(f"post-call X9 unsupported audited class at {_hex(va)}")
        if _decode_bl(word, va) is not None or _decode_blr(word) is not None or _decode_br(word) is not None:
            raise ValueError(f"post-call X9 control transfer at {_hex(va)}")
        if (_decode_b(word, va) is not None or _decode_b_cond(word, va) is not None or
                _decode_cbz(word, va) is not None or _decode_cbnz(word, va) is not None or
                _decode_ret(word) is not None):
            raise ValueError(f"post-call X9 branch/return at {_hex(va)}")
        if word != spec["word"]:
            decoded_x = _decode_mov_x(word)
            decoded_w = _decode_mov_w(word)
            decoded_pair = _decode_ldp_signed_offset(word)
            if decoded_pair is not None and 9 in {
                decoded_pair["first_destination"], decoded_pair["second_destination"],
            }:
                raise ValueError(f"post-call X9 LDP redefinition at {_hex(va)}")
            if (decoded_x is not None and decoded_x["destination"] == 9) or (
                decoded_w is not None and decoded_w["destination"] == 9
            ):
                raise ValueError(f"post-call X9 redefinition at {_hex(va)}")
            raise ValueError(f"post-call X9 audited instruction mismatch at {_hex(va)}")
        if spec["kind"] == "LOAD_PAIR":
            decoded_pair = _decode_ldp_signed_offset(word)
            if decoded_pair is None:
                raise ValueError(f"post-call X9 LDP class mismatch at {_hex(va)}")
            if {
                decoded_pair["first_destination"], decoded_pair["second_destination"],
            } != set(spec["writes_gpr"]):
                raise ValueError(f"post-call X9 LDP write-set mismatch at {_hex(va)}")
        if any(register == 9 for register in spec["writes_gpr"]):
            raise ValueError(f"post-call X9 audited redefinition at {_hex(va)}")
    return {"instruction_count": len(_POST_CALL_X9_AUDIT)}


def _read_code_range(
    image: ElfImage,
    start: int,
    end: int,
    expected_offset: int,
    expected_size: int,
    expected_hash: str,
) -> dict[str, object]:
    if end - start != expected_size:
        raise ValueError("code range size pin mismatch")
    file_offset = image.vaddr_to_offset(start, expected_size)
    if file_offset != expected_offset:
        raise ValueError(f"code range {_hex(start)} mapping mismatch")
    segment = image.segment_for_vaddr(start, expected_size)
    if not segment.executable:
        raise ValueError(f"code range {_hex(start)} is not executable")
    digest = sha256(image.read_vaddr(start, expected_size))
    if digest != expected_hash:
        raise ValueError(f"code range {_hex(start)} SHA-256 mismatch: {digest}")
    return {
        "virtual_address": _hex(start),
        "end_exclusive": _hex(end),
        "file_offset": _hex(file_offset),
        "byte_length": expected_size,
        "sha256": digest,
        "segment_class": "RX" if not (segment.flags & 2) else "RWE",
    }


def _transfer_census(image: ElfImage, target: int) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    bl_hits: list[dict[str, object]] = []
    b_hits: list[dict[str, object]] = []
    for va, file_offset, word in image.executable_words():
        segment = image.segment_for_vaddr(va, 4)
        record = {
            "virtual_address": _hex(va),
            "file_offset": _hex(file_offset),
            "target": _hex(target),
            "segment_class": "RX" if not (segment.flags & 2) else "RWE",
        }
        decoded_bl = _decode_bl(word, va)
        decoded_b = _decode_b(word, va)
        if decoded_bl is not None and decoded_bl["target"] == target:
            bl_hits.append(record)
        if decoded_b is not None and decoded_b["target"] == target:
            b_hits.append(record)
    return bl_hits, b_hits


def _audit_initializer_control_words(words: dict[int, int] | list[tuple[int, int]]) -> list[dict[str, str]]:
    controls = []
    for va in sorted(dict(words)):
        word = dict(words)[va]
        if _decode_ret(word) is not None:
            controls.append({"virtual_address": _hex(va), "kind": "RET"})
        elif (_decode_bl(word, va) is not None or _decode_blr(word) is not None or
              _decode_br(word) is not None or _decode_b(word, va) is not None or
              _decode_cbz(word, va) is not None or _decode_cbnz(word, va) is not None or
              _decode_b_cond(word, va) is not None):
            raise ValueError(f"unexpected initializer control transfer at {_hex(va)}")
    if controls != [{"virtual_address": _hex(0x14844DA8), "kind": "RET"}]:
        raise ValueError("initializer control-transfer census mismatch")
    return controls


def _validate_initializer(image: ElfImage) -> dict[str, object]:
    code = _read_code_range(
        image, INITIALIZER_VA, INITIALIZER_END_VA, INITIALIZER_FILE_OFFSET,
        INITIALIZER_SIZE, INITIALIZER_SHA256,
    )
    movz = stage2a._decode_mov_wide(_word(image, INITIALIZER_VA))
    movk = stage2a._decode_mov_wide(_word(image, INITIALIZER_VA + 0x0C))
    adrp = snapshot._decode_aarch64_adrp(_word(image, 0x14844A84), 0x14844A84)
    add = snapshot._decode_aarch64_add_immediate(_word(image, 0x14844AC8))
    store = stage2a._decode_str_unsigned_immediate(_word(image, 0x14844AE0))
    if movz != {"kind": "MOVZ", "width_bits": 32, "destination": 8, "immediate": 0xF000, "shift": 0}:
        raise ValueError("initializer X8 MOVZ mismatch")
    if movk != {"kind": "MOVK", "width_bits": 32, "destination": 8, "immediate": 0x1489, "shift": 16}:
        raise ValueError("initializer X8 MOVK mismatch")
    if adrp != (5, 0x1483C000):
        raise ValueError("initializer X5 ADRP mismatch")
    if add != (5, 5, 0x904):
        raise ValueError("initializer X5 ADD mismatch")
    if store != {
        "form": "STR_UNSIGNED_IMMEDIATE", "width_bytes": 8,
        "byte_offset": 0x3B0, "base_register": 8, "source_register": 5,
        "base_is_sp": False,
    }:
        raise ValueError("initializer import-slot store mismatch")
    bl_hits, b_hits = _transfer_census(image, INITIALIZER_VA)
    if len(bl_hits) != 1 or bl_hits[0]["virtual_address"] != _hex(INITIALIZER_CALLER_VA):
        raise ValueError("initializer direct-BL caller census mismatch")
    if b_hits:
        raise ValueError("initializer has an unexpected direct-B caller")
    controls = _audit_initializer_control_words({
        va: _word(image, va) for va in range(INITIALIZER_VA, INITIALIZER_END_VA, 4)
    })
    boot_call = _decode_bl(_word(image, BOOT_ENTRY_CALL_SITE), BOOT_ENTRY_CALL_SITE)
    boot_skip = _decode_cbz(_word(image, BOOT_ENTRY_SKIP_SITE), BOOT_ENTRY_SKIP_SITE)
    if boot_call != {"kind": "BL", "target": BOOT_ENTRY_CALL_TARGET}:
        raise ValueError("initializer boot-entry call pin mismatch")
    if boot_skip != {
        "kind": "CBZ", "width_bits": 64, "register": 20, "target": BOOT_ENTRY_SKIP_TARGET,
    }:
        raise ValueError("initializer boot-entry skip pin mismatch")
    return {
        "range": code,
        "x8_value": _hex(0x1489F000),
        "x5_value": _hex(0x1483C904),
        "store_site": _hex(0x14844AE0),
        "store_offset": _hex(0x3B0),
        "resolved_import_slot": _hex(IMPORT_SLOT_VA),
        "direct_bl_caller_count": len(bl_hits),
        "direct_bl_callers": bl_hits,
        "direct_b_caller_count": len(b_hits),
        "control_transfer_census": controls,
        "boot_entry_call_site": _hex(BOOT_ENTRY_CALL_SITE),
        "boot_entry_call_target": _hex(BOOT_ENTRY_CALL_TARGET),
        "boot_entry_skip_site": _hex(BOOT_ENTRY_SKIP_SITE),
        "boot_entry_skip_target": _hex(BOOT_ENTRY_SKIP_TARGET),
        "runtime_execution": "UNKNOWN",
        "later_slot_mutation": "UNKNOWN",
        "critical_pins_verified": True,
    }


def _target_callee_register_census(image: ElfImage) -> dict[str, object]:
    code = _read_code_range(
        image, TARGET_CALLEE_VA, TARGET_CALLEE_END_VA,
        TARGET_CALLEE_FILE_OFFSET, TARGET_CALLEE_SIZE, TARGET_CALLEE_SHA256,
    )
    words = {va: _word(image, va) for va in range(TARGET_CALLEE_VA, TARGET_CALLEE_END_VA, 4)}
    audit = _audit_target_callee_words(words)
    return {
        "range": code,
        "direct_bl_count": 0,
        "direct_blr_count": 0,
        "direct_br_count": 0,
        "direct_b_count": audit["direct_b_count"],
        "control_transfer_count": audit["control_transfer_count"],
        "ret_count": audit["ret_count"],
        "callee_saved_registers": ["X19", "X20", "X21", "X22", "X23", "X24", "X25", "X26", "X27", "X28", "X29"],
        "callee_saved_write_count": 0,
        "callee_saved_write_virtual_addresses": [],
        "exact_instruction_class_manifest": True,
        "semantic_name": "UNKNOWN",
        "critical_pins_verified": True,
    }


def _direct_transfer_census_to(
    image: ElfImage, target: int,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    bl_hits = []
    b_hits = []
    for va, file_offset, word in image.executable_words():
        decoded_bl = _decode_bl(word, va)
        decoded_b = _decode_b(word, va)
        segment = image.segment_for_vaddr(va, 4)
        segment_class = "RX" if not (segment.flags & 2) else "RWE"
        if decoded_bl is not None and decoded_bl["target"] == target:
            bl_hits.append({
                "virtual_address": _hex(va),
                "file_offset": _hex(file_offset),
                "target": _hex(target),
                "segment_class": segment_class,
            })
        if decoded_b is not None and decoded_b["target"] == target:
            b_hits.append({
                "virtual_address": _hex(va),
                "file_offset": _hex(file_offset),
                "target": _hex(target),
                "segment_class": segment_class,
            })
    return bl_hits, b_hits


def _validate_pre_madd_direct_callee(image: ElfImage) -> dict[str, object]:
    code = _read_code_range(
        image, PRE_MADD_DIRECT_CALLEE_VA, PRE_MADD_DIRECT_CALLEE_END_VA,
        PRE_MADD_DIRECT_CALLEE_FILE_OFFSET, PRE_MADD_DIRECT_CALLEE_SIZE,
        PRE_MADD_DIRECT_CALLEE_SHA256,
    )
    callers, branches = _direct_transfer_census_to(image, PRE_MADD_DIRECT_CALLEE_VA)
    if len(callers) != 1 or callers[0]["virtual_address"] != _hex(0x14935ABC):
        raise ValueError("pre-MADD direct callee caller census mismatch")
    if branches:
        raise ValueError("pre-MADD direct callee direct-B caller mismatch")
    save_word = _word(image, PRE_MADD_SAVE_SITE)
    restore_word = _word(image, PRE_MADD_RESTORE_SITE)
    ret_word = _word(image, PRE_MADD_RET_SITE)
    # Exact STP/LDP pair encodings save and restore X24,X23 around the normal
    # return.  The surrounding range hash and unique RET pin bind this
    # preservation observation to the retained function, without assuming
    # that an indirect runtime callee or execution actually occurred.
    if save_word != 0xA90C5FF8:
        raise ValueError("pre-MADD direct callee X24/X23 save mismatch")
    if restore_word != 0xA94C5FF8:
        raise ValueError("pre-MADD direct callee X24/X23 restore mismatch")
    if _decode_ret(ret_word) != {"kind": "RET", "register": 30}:
        raise ValueError("pre-MADD direct callee RET mismatch")
    ret_sites = [
        va for va in range(PRE_MADD_DIRECT_CALLEE_VA, PRE_MADD_DIRECT_CALLEE_END_VA, 4)
        if _decode_ret(_word(image, va)) is not None
    ]
    if ret_sites != [PRE_MADD_RET_SITE]:
        raise ValueError("pre-MADD direct callee RET census mismatch")
    return {
        "range": code,
        "direct_bl_caller_count": len(callers),
        "direct_bl_callers": callers,
        "direct_b_caller_count": len(branches),
        "saved_registers": ["X23", "X24"],
        "save_site": _hex(PRE_MADD_SAVE_SITE),
        "restore_site": _hex(PRE_MADD_RESTORE_SITE),
        "ret_site": _hex(PRE_MADD_RET_SITE),
        "unique_ret_count": len(ret_sites),
        "normal_return_preserves_x23_x24": True,
        "runtime_execution_and_nonreturning_paths": "UNKNOWN",
    }


def _word(image: ElfImage, address: int) -> int:
    return image.u32(address)


def _decode_direct_caller_path(image: ElfImage) -> dict[str, object]:
    zero_word = _word(image, CALLER_ZERO_SITE)
    lookup_call = _decode_bl(_word(image, CALLER_LOOKUP_CALL_SITE), CALLER_LOOKUP_CALL_SITE)
    branch = _decode_cbz(_word(image, CALLER_BRANCH_SITE), CALLER_BRANCH_SITE)
    x1_setup = _decode_add_x_immediate(_word(image, CALLER_X1_SETUP_SITE))
    w2_zero = _decode_mov_w(_word(image, CALLER_W2_ZERO_SITE))
    writer_call = _decode_bl(_word(image, CALLER_VA), CALLER_VA)
    if zero_word != 0x2A1F03E0:
        raise ValueError("direct caller does not zero W0")
    if lookup_call != {"kind": "BL", "target": CALLER_LOOKUP_TARGET}:
        raise ValueError("direct caller lookup BL mismatch")
    if branch != {
        "kind": "CBZ", "width_bits": 32, "register": 0, "target": CALLER_BRANCH_TARGET,
    }:
        raise ValueError("direct caller W0 branch mismatch")
    if x1_setup != {
        "kind": "ADD_IMMEDIATE_X", "destination": 1, "source": 31, "immediate": 0xE0,
    }:
        raise ValueError("direct caller X1 setup mismatch")
    if w2_zero != {"kind": "MOV_REGISTER_W", "destination": 2, "source": 31}:
        raise ValueError("direct caller W2 setup mismatch")
    if writer_call != {"kind": "BL", "target": FUNCTION_VA}:
        raise ValueError("direct caller BL target mismatch")
    return {
        "zero_site": _hex(CALLER_ZERO_SITE),
        "lookup_call_site": _hex(CALLER_LOOKUP_CALL_SITE),
        "lookup_call_target": _hex(CALLER_LOOKUP_TARGET),
        "lookup_result_branch_site": _hex(CALLER_BRANCH_SITE),
        "lookup_result_branch_target": _hex(CALLER_BRANCH_TARGET),
        "x1_setup_site": _hex(CALLER_X1_SETUP_SITE),
        "x1_source": "SP",
        "x1_immediate": _hex(0xE0),
        "w2_zero_site": _hex(CALLER_W2_ZERO_SITE),
        "writer_call_site": _hex(CALLER_VA),
        "writer_call_target": _hex(FUNCTION_VA),
        "writer_call_w0_domain": ["0x0"],
        "critical_pins_verified": True,
    }


def _decode_callee_path(image: ElfImage) -> dict[str, object]:
    mov_x19 = _decode_mov_x(_word(image, 0x14935988))
    mov_w20 = _decode_mov_w(_word(image, 0x14935990))
    cmp_w7 = _decode_cmp_w_immediate(_word(image, 0x14935998))
    upper_branch = _decode_b_cond(_word(image, 0x149359A0), 0x149359A0)
    nonzero_gate = _decode_cbz(_word(image, 0x149359A4), 0x149359A4)
    mov_w25 = _decode_mov_w(_word(image, 0x149359A8))
    cmp_w8 = _decode_cmp_w_immediate(_word(image, 0x149359AC))
    csel_x23 = _word(image, 0x149359B0)
    orr_w13 = _decode_orr_w_logical_immediate(_word(image, 0x14935B58))
    adrp_x24 = snapshot._decode_aarch64_adrp(_word(image, 0x149359B8), 0x149359B8)
    add_x24 = snapshot._decode_aarch64_add_immediate(_word(image, 0x149359BC))
    dispatch_sub = _decode_sub_w_immediate(_word(image, CALLEE_DISPATCH_SUB_SITE))
    dispatch_cmp = _decode_cmp_w_immediate(_word(image, CALLEE_DISPATCH_CMP_SITE))
    dispatch_branch = _decode_b_cond(_word(image, CALLEE_DISPATCH_BRANCH_SITE), CALLEE_DISPATCH_BRANCH_SITE)
    cmp_w1 = _decode_cmp_w_immediate(_word(image, 0x14935AAC))
    w1_branch = _decode_b_cond(_word(image, 0x14935AB0), 0x14935AB0)
    result_branch = _decode_cbnz(_word(image, PRE_MADD_RESULT_BRANCH_SITE), PRE_MADD_RESULT_BRANCH_SITE)
    madd = _decode_madd_x(_word(image, 0x14935B60))
    if mov_x19 != {"kind": "MOV_REGISTER_X", "destination": 19, "source": 1}:
        raise ValueError("callee X19 input copy mismatch")
    if mov_w20 != {"kind": "MOV_REGISTER_W", "destination": 20, "source": 0}:
        raise ValueError("callee W20 input copy mismatch")
    if cmp_w7 != {"kind": "CMP_IMMEDIATE_W", "source": 20, "immediate": 7}:
        raise ValueError("callee W0<=7 guard mismatch")
    if upper_branch != {
        "kind": "B_COND", "condition": 8, "target": 0x14935CEC,
    }:
        raise ValueError("callee W0<=7 failure branch mismatch")
    if nonzero_gate != {
        "kind": "CBZ", "width_bits": 64, "register": 19, "target": 0x14935CEC,
    }:
        raise ValueError("callee X1 nonzero gate mismatch")
    if mov_w25 != {"kind": "MOV_REGISTER_W", "destination": 25, "source": 20}:
        raise ValueError("callee X23 selection source mismatch")
    if cmp_w8 != {"kind": "CMP_IMMEDIATE_W", "source": 20, "immediate": 8}:
        raise ValueError("callee X23 selection compare mismatch")
    if csel_x23 != 0x9A9F3337:
        raise ValueError("callee X23 CSEL encoding mismatch")
    if orr_w13 != {"kind": "ORR_W_IMMEDIATE", "destination": 13, "immediate": 0x600}:
        raise ValueError("callee MADD multiplier constant mismatch")
    if adrp_x24 != (24, 0x85E9E000):
        raise ValueError("callee X24 ADRP mismatch")
    if add_x24 != (24, 24, 0x570):
        raise ValueError("callee X24 ADD mismatch")
    if dispatch_sub != {
        "kind": "SUB_IMMEDIATE_W", "destination": 12, "source": 20, "immediate": 2,
    }:
        raise ValueError("callee W20 dispatch SUB mismatch")
    if dispatch_cmp != {"kind": "CMP_IMMEDIATE_W", "source": 12, "immediate": 3}:
        raise ValueError("callee W20 dispatch CMP mismatch")
    if dispatch_branch != {
        "kind": "B_COND", "condition": 2, "target": CALLEE_DISPATCH_TARGET,
    }:
        raise ValueError("callee W20 dispatch branch mismatch")
    if cmp_w1 != {"kind": "CMP_IMMEDIATE_W", "source": 20, "immediate": 1}:
        raise ValueError("callee W0<=1 path compare mismatch")
    if w1_branch != {
        "kind": "B_COND", "condition": 8, "target": 0x14935D20,
    }:
        raise ValueError("callee W0<=1 path branch mismatch")
    if result_branch != {
        "kind": "CBNZ", "width_bits": 32, "register": 0,
        "target": PRE_MADD_RESULT_BRANCH_TARGET,
    }:
        raise ValueError("pre-MADD helper result branch mismatch")
    if madd != {
        "kind": "MADD_X", "destination": 19, "left": 23,
        "right": 13, "accumulator": 24,
    }:
        raise ValueError("callee X19 MADD mismatch")
    return {
        "input_w20_source": "W0",
        "w0_guard_domain": ["0x0", "0x1"],
        "x1_nonzero_required": True,
        "x23_selection": "CSEL X23,W20-or-zero under W20<8",
        "x24_value": _hex(0x85E9E570),
        "madd_site": _hex(0x14935B60),
        "madd_multiplier_register": "X13",
        "madd_multiplier_value": _hex(0x600),
        "w0_le_one_branch_site": _hex(0x14935AB0),
        "w0_le_one_branch_target": _hex(0x14935D20),
        "w20_dispatch": {
            "sub_site": _hex(CALLEE_DISPATCH_SUB_SITE),
            "sub": "SUB W12,W20,#2",
            "compare_site": _hex(CALLEE_DISPATCH_CMP_SITE),
            "compare": "CMP W12,#3",
            "branch_site": _hex(CALLEE_DISPATCH_BRANCH_SITE),
            "branch_target": _hex(CALLEE_DISPATCH_TARGET),
            "condition": "CS",
            "w0_le_one_path_reaches_dispatch_target": True,
        },
        "pre_madd_result_gate": {
            "branch_site": _hex(PRE_MADD_RESULT_BRANCH_SITE),
            "kind": "CBNZ W0",
            "nonzero_target": _hex(PRE_MADD_RESULT_BRANCH_TARGET),
            "requires_w0_zero_to_reach_madd": True,
            "result_of_pre_madd_direct_callee": "UNKNOWN",
        },
        "intrinsic_w0_domain": ["0x0", "0x1"],
        "intrinsic_pre_call_x19_base_values": [_hex(0x85E9E570), _hex(0x85E9EB70)],
        "critical_pins_verified": True,
    }


def _decode_intervening_calls(image: ElfImage) -> list[dict[str, object]]:
    sites = (
        (0x14935ABC, 0x1493641C, "PRE_MADD"),
        (0x14935B48, WRAPPER_VA, "PRE_MADD"),
        (0x14935B54, WRAPPER_VA, "PRE_MADD"),
        (0x14935B68, WRAPPER_VA, "POST_MADD_X19"),
    )
    result = []
    for site, target, phase in sites:
        decoded = _decode_bl(_word(image, site), site)
        if decoded != {"kind": "BL", "target": target}:
            raise ValueError(f"intervening call {_hex(site)} mismatch")
        result.append({"call_site": _hex(site), "target": _hex(target), "phase": phase})
    return result


def _validate_post_call_x9(image: ElfImage) -> dict[str, object]:
    code = _read_code_range(
        image, POST_CALL_X9_RANGE_VA, POST_CALL_X9_RANGE_END_VA,
        POST_CALL_X9_RANGE_FILE_OFFSET, POST_CALL_X9_RANGE_SIZE,
        POST_CALL_X9_RANGE_SHA256,
    )
    add_x9 = snapshot._decode_aarch64_add_immediate(_word(image, 0x14935BA0))
    candidate_store = stage2a._decode_str_unsigned_immediate(_word(image, CANDIDATE_VA))
    if add_x9 != (9, 19, 0x428):
        raise ValueError("post-call X9 construction mismatch")
    if candidate_store is None or candidate_store["source_register"] != 9:
        raise ValueError("candidate does not consume X9")
    words = {va: _word(image, va) for va in range(0x14935BA4, CANDIDATE_VA, 4)}
    audit = _audit_post_call_x9_words(words)
    return {
        "range": code,
        "add_site": _hex(0x14935BA0),
        "source_register": "X19",
        "offset": _hex(0x428),
        "candidate_store_site": _hex(CANDIDATE_VA),
        "candidate_source_register": "X9",
        "no_intervening_direct_bl": True,
        "no_intervening_indirect_control_transfer": True,
        "exact_instruction_class_manifest": True,
        "audited_instruction_count": audit["instruction_count"],
        "conditional_on_post_madd_X19": True,
    }


def _validate_wrapper_thunk(image: ElfImage) -> dict[str, object]:
    wrapper_range = _read_code_range(
        image, WRAPPER_VA, WRAPPER_END_VA, WRAPPER_FILE_OFFSET, WRAPPER_SIZE, WRAPPER_SHA256,
    )
    thunk_range = _read_code_range(
        image, THUNK_VA, THUNK_END_VA, THUNK_FILE_OFFSET, THUNK_SIZE, THUNK_SHA256,
    )
    wrapper = {
        "move_x8": _decode_mov_x(_word(image, WRAPPER_VA)),
        "zero_w1": _decode_mov_w(_word(image, WRAPPER_VA + 4)),
        "move_x2": _decode_mov_x(_word(image, WRAPPER_VA + 8)),
        "tail": _decode_b(_word(image, WRAPPER_VA + 12), WRAPPER_VA + 12),
    }
    if wrapper != {
        "move_x8": {"kind": "MOV_REGISTER_X", "destination": 8, "source": 1},
        "zero_w1": {"kind": "MOV_REGISTER_W", "destination": 1, "source": 31},
        "move_x2": {"kind": "MOV_REGISTER_X", "destination": 2, "source": 8},
        "tail": {"kind": "B", "target": THUNK_VA},
    }:
        raise ValueError("runtime-import wrapper pin mismatch")
    thunk_movz = stage2a._decode_mov_wide(_word(image, THUNK_VA))
    thunk_movk = stage2a._decode_mov_wide(_word(image, THUNK_VA + 4))
    thunk_ldr = _decode_ldr_x(_word(image, THUNK_VA + 8))
    thunk_br = _decode_br(_word(image, THUNK_VA + 12))
    if thunk_movz != {"kind": "MOVZ", "width_bits": 32, "destination": 8, "immediate": 0xF3B0, "shift": 0}:
        raise ValueError("import thunk MOVZ mismatch")
    if thunk_movk != {"kind": "MOVK", "width_bits": 32, "destination": 8, "immediate": 0x1489, "shift": 16}:
        raise ValueError("import thunk MOVK mismatch")
    if thunk_ldr != {"kind": "LDR_X_UNSIGNED", "destination": 3, "base_register": 8, "byte_offset": 0}:
        raise ValueError("import thunk pointer load mismatch")
    if thunk_br != {"kind": "BR", "register": 3}:
        raise ValueError("import thunk BR mismatch")
    return {
        "wrapper_range": wrapper_range,
        "thunk_range": thunk_range,
        "wrapper_x8_source": "X1",
        "wrapper_x2_source": "X8",
        "tail_target": _hex(THUNK_VA),
        "thunk_import_slot": _hex(IMPORT_SLOT_VA),
        "thunk_runtime_target": "UNKNOWN",
        "current_runtime_import_slot_target": "UNKNOWN",
        "direct_bl_link_register": "X30",
        "x19_defined_by_wrapper_or_thunk": False,
        "critical_pins_verified": True,
    }


def _decode_ldr_x(word: int) -> dict[str, object] | None:
    if word & 0x3FC00000 != 0x39400000 or (word >> 30) & 0x3 != 3:
        return None
    return {
        "kind": "LDR_X_UNSIGNED",
        "destination": word & 0x1F,
        "base_register": (word >> 5) & 0x1F,
        "byte_offset": ((word >> 10) & 0xFFF) * 8,
    }


def _decode_br(word: int) -> dict[str, object] | None:
    if word & 0xFFFFFC1F != 0xD61F0000:
        return None
    return {"kind": "BR", "register": (word >> 5) & 0x1F}


def _all_phdrs(image: ElfImage) -> list[dict[str, int]]:
    data = image.data
    phoff = struct.unpack_from("<Q", data, 0x20)[0]
    phentsize = struct.unpack_from("<H", data, 0x36)[0]
    phnum = struct.unpack_from("<H", data, 0x38)[0]
    records = []
    for index in range(phnum):
        base = phoff + index * phentsize
        p_type, flags = struct.unpack_from("<II", data, base)
        p_offset, vaddr, paddr, filesz, memsz, align = struct.unpack_from("<QQQQQQ", data, base + 8)
        if p_type == 1:
            records.append({
                "index": index, "flags": flags, "offset": p_offset,
                "vaddr": vaddr, "paddr": paddr, "filesz": filesz,
                "memsz": memsz, "align": align,
            })
    return records


def _validate_memory_segments(image: ElfImage, effective_values: set[int]) -> dict[str, object]:
    records = _all_phdrs(image)
    import_matches = [
        record for record in records
        if record["vaddr"] == IMPORT_SEGMENT_START
        and record["vaddr"] + record["memsz"] == IMPORT_SEGMENT_END
        and record["filesz"] == 0
        and record["flags"] == 6
    ]
    if len(import_matches) != 1:
        raise ValueError("memory-only RW import segment pin mismatch")
    effective_matches = [
        record for record in records
        if record["vaddr"] == EFFECTIVE_SEGMENT_START
        and record["filesz"] == EFFECTIVE_SEGMENT_FILE_SIZE
        and record["memsz"] == EFFECTIVE_SEGMENT_MEMORY_SIZE
        and record["paddr"] == record["vaddr"]
        and record["flags"] == 6
    ]
    if len(effective_matches) != 1:
        raise ValueError("effective RW PT_LOAD pin mismatch")
    record = effective_matches[0]
    inside_file = {
        value: EFFECTIVE_SEGMENT_START <= value < EFFECTIVE_SEGMENT_FILE_END
        for value in effective_values
    }
    inside_memory = {
        value: EFFECTIVE_SEGMENT_START <= value < EFFECTIVE_SEGMENT_MEMORY_END
        for value in effective_values
    }
    return {
        "import_slot": {
            "virtual_address": _hex(IMPORT_SLOT_VA),
            "memory_only_rw_pt_load_start": _hex(IMPORT_SEGMENT_START),
            "memory_only_rw_pt_load_end": _hex(IMPORT_SEGMENT_END),
            "filesz": 0,
            "runtime_pointer": "UNKNOWN",
        },
        "effective_value_segment": {
            "virtual_address": _hex(EFFECTIVE_SEGMENT_START),
            "file_size": _hex(EFFECTIVE_SEGMENT_FILE_SIZE),
            "memory_size": _hex(EFFECTIVE_SEGMENT_MEMORY_SIZE),
            "file_backed_end": _hex(EFFECTIVE_SEGMENT_FILE_END),
            "memory_end": _hex(EFFECTIVE_SEGMENT_MEMORY_END),
            "p_vaddr_equals_p_paddr": record["paddr"] == record["vaddr"],
            "values_inside_file_backed_range": inside_file,
            "values_inside_pt_load_memory_range": inside_memory,
        },
    }


def _direct_transfer_census(image: ElfImage) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    bl_hits = []
    b_hits = []
    for va, file_offset, word in image.executable_words():
        decoded_bl = _decode_bl(word, va)
        decoded_b = _decode_b(word, va)
        if decoded_bl is not None and decoded_bl["target"] == FUNCTION_VA:
            bl_hits.append({
                "virtual_address": _hex(va),
                "file_offset": _hex(file_offset),
                "target": _hex(FUNCTION_VA),
                "segment_class": "RX" if not (image.segment_for_vaddr(va, 4).flags & 2) else "RWE",
            })
        if decoded_b is not None and decoded_b["target"] == FUNCTION_VA:
            b_hits.append({
                "virtual_address": _hex(va),
                "file_offset": _hex(file_offset),
                "target": _hex(FUNCTION_VA),
                "segment_class": "RX" if not (image.segment_for_vaddr(va, 4).flags & 2) else "RWE",
            })
    return bl_hits, b_hits


def _compute_effective_values(
    x24: int, x23_values: tuple[int, ...] | list[int],
    multiplier: int = 0x600, store_offset: int = 0x400,
) -> tuple[list[int], list[int]]:
    bases = [x24 + multiplier * value for value in x23_values]
    return bases, [value + store_offset for value in bases]


def _conditional_values() -> dict[str, object]:
    x24 = 0x85E9E570
    intrinsic_bases, intrinsic_effective = _compute_effective_values(x24, (0, 1))
    direct_bases, direct_effective = _compute_effective_values(x24, (0,))
    return {
        "intrinsic_pre_call_x19_base_values": [_hex(value) for value in intrinsic_bases],
        "intrinsic_possible_effective_values": [_hex(value) for value in intrinsic_effective],
        "intrinsic_numeric_target_matches": [value in TARGETS for value in intrinsic_effective],
        "unique_direct_caller_w0": _hex(0),
        "conditional_pre_call_x19_base_values": [_hex(value) for value in direct_bases],
        "conditional_effective_values": [_hex(value) for value in direct_effective],
        "conditional_numeric_target_matches": [value in TARGETS for value in direct_effective],
        "numeric_target_match_count": sum(value in TARGETS for value in intrinsic_effective),
    }


def _baseline(data: bytes) -> dict[str, object]:
    prior = stage2c.analyze(data)
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
        "stage2c_classification": prior["classification"],
        "stage2c_direct_caller_count": prior["direct_callers"]["count"],
        "stage2c_table_entry_count": prior["retained_table"]["entry_count"],
    }


def analyze(data: bytes) -> dict[str, object]:
    if len(data) != XBL_SIZE:
        raise ValueError(f"XBL size is {len(data)}, expected {XBL_SIZE}")
    digest = sha256(data)
    if digest != XBL_SHA256:
        raise ValueError(f"XBL SHA-256 mismatch: {digest}")
    image = ElfImage(data)
    function = _read_code_range(
        image, FUNCTION_VA, FUNCTION_END_VA, FUNCTION_FILE_OFFSET,
        FUNCTION_SIZE, FUNCTION_SHA256,
    )
    initializer = _validate_initializer(image)
    target_callee = _target_callee_register_census(image)
    pre_madd_direct_callee = _validate_pre_madd_direct_callee(image)
    candidate = _decode_str_unsigned(_word(image, CANDIDATE_VA))
    if image.vaddr_to_offset(CANDIDATE_VA, 4) != CANDIDATE_FILE_OFFSET:
        raise ValueError("candidate mapping mismatch")
    if _word(image, CANDIDATE_VA) != CANDIDATE_WORD:
        raise ValueError("candidate instruction pin mismatch")
    if candidate != {
        "kind": "STR_UNSIGNED_IMMEDIATE", "width_bits": 64,
        "source_register": 9, "base_register": 19, "byte_offset": 0x400,
    }:
        raise ValueError("candidate store form mismatch")
    callers, direct_branches = _direct_transfer_census(image)
    if len(callers) != EXPECTED_DIRECT_CALLER_COUNT:
        raise ValueError(f"direct BL caller count is {len(callers)}, expected 1")
    if direct_branches:
        raise ValueError("unexpected direct B target to scoped function")
    if callers[0]["virtual_address"] != _hex(CALLER_VA) or callers[0]["file_offset"] != _hex(CALLER_FILE_OFFSET):
        raise ValueError("direct caller pin mismatch")
    caller_path = _decode_direct_caller_path(image)
    callee_path = _decode_callee_path(image)
    calls = _decode_intervening_calls(image)
    post_call_x9 = _validate_post_call_x9(image)
    wrappers = _validate_wrapper_thunk(image)
    values = _conditional_values()
    segments = _validate_memory_segments(image, set(int(value, 0) for value in values["intrinsic_possible_effective_values"]))
    baseline = _baseline(data)
    return {
        "schema": "sdm855-xbl-mc-writer-xref-stage2d-public-v1",
        "stage": "STAGE2D_UNIQUE_DIRECT_CALLER_CONDITIONAL_CALLEE_SAVED_PRESERVATION_MODEL",
        "mode": "HOST_ONLY_READ_ONLY",
        "device_access": False,
        "smc_access": False,
        "mmio_access": False,
        "firmware_bytes_emitted": False,
        "input": {"filename": "xbl--sdb1.bin", "size": len(data), "sha256": digest, "pin_verified": True},
        "accounting": {
            "non_sp_rx_candidate_count": 4,
            "prior_stage2a_candidates": 4,
            "current_candidate": _hex(CANDIDATE_VA),
            "current_candidate_status": "CONDITIONAL_NOT_UNCONDITIONALLY_RESOLVED",
            "all_four_non_sp_rx_candidates_examined": True,
            "remaining_non_sp_rx_static_candidate_count": 0,
            "sp_rx_candidate_count_unknown": 7,
            "rwe_candidate_count_unknown": 3,
        },
        "function": function,
        "initializer": initializer,
        "target_callee": target_callee,
        "pre_madd_direct_callee": pre_madd_direct_callee,
        "candidate": {
            "virtual_address": _hex(CANDIDATE_VA),
            "file_offset": _hex(CANDIDATE_FILE_OFFSET),
            "source_register": "X9",
            "base_register": "X19",
            "byte_offset": _hex(0x400),
            "width_bits": 64,
            "form": "STR X9,[X19,#0x400]",
        },
        "direct_callers": {
            "target": _hex(FUNCTION_VA),
            "direct_bl_count": len(callers),
            "direct_bl_callers": callers,
            "direct_b_count": len(direct_branches),
            "direct_b_callers": direct_branches,
            "file_backed_executable_pt_loads_only": True,
            "indirect_callers": "UNKNOWN",
        },
        "caller_success_path": caller_path,
        "callee_path": callee_path,
        "intervening_calls": calls,
        "post_call_x9": post_call_x9,
        "wrapper_thunk": wrappers,
        "conditional_values": values,
        "static_initialized_slot_model": {
            "model_name": "STATIC_INITIALIZED_SLOT_UNCHANGED",
            "initializer_value": _hex(0x1483C904),
            "slot_runtime_execution": "UNKNOWN",
            "slot_later_mutation": "UNKNOWN",
            "resolved_import_target_static_range": _hex(TARGET_CALLEE_VA),
            "resolved_import_target_has_no_X19_X29_writes": True,
            "pre_madd_direct_callee_normal_return_preservation": [_hex(0x14935ABC)],
            "remaining_pre_madd_import_wrapper_preservation": [_hex(0x14935B48), _hex(0x14935B54)],
            "post_madd_import_target_preserves_X19_under_static_range": True,
            "conditional_effective_value": _hex(0x85E9E970),
            "numeric_target_match": False,
        },
        "elf_memory_facts": segments,
        "baseline": baseline,
        "claims": {
            "PROVED": [
                "The exact XBL size/hash, containing function, candidate store, unique direct-BL caller, initializer, wrapper/thunk ranges, and RW PT_LOAD facts are verified.",
                "The unique direct-BL caller statically zeroes W0, takes the CBZ W0 success edge, sets X1=SP+0xe0 and W2=0, then directly calls the scoped function; therefore W0=0 at that direct callsite in the pinned static path.",
                "The callee pins W20=W0, W0<=7 and X1-nonzero guards, W20<=1 path, X23 selection, X24=0x85e9e570 construction, and MADD X19,X23,0x600,X24.",
                "BL link state is X30; the pinned lookup wrapper/thunk do not define X19. The current runtime import-slot target/currentness is UNKNOWN; the initializer statically assigns 0x1483c904.",
                "The initializer statically stores 0x1483c904 into import slot 0x1489f3b0, and the exact resolved target range has zero BL/BLR/BR transfers, one RET, and zero X19-X29 definitions under its exact audited instruction-class manifest.",
                "The static construction pins and model arithmetic yield intrinsic and unique-direct-caller effective sets with zero numeric matches to the 12 targets; the conditional runtime premises remain separate.",
            ],
            "SUPPORTED": [
                "AAPCS64 conditionally supports preservation of X19, X23 and X24 by a conforming callee; the current runtime import-slot value/target and its conformance/currentness are not established here.",
            ],
            "HYPOTHESIS": [
                "If the scoped direct-BL path executes, the pinned pre-MADD direct callee returns normally, both pre-MADD import wrappers preserve X23/X24, and the post-MADD callee preserves X19, the direct-caller effective store value is 0x85e9e970.",
                "If the initializer executes, the import slot remains unchanged, the pinned pre-MADD direct callee returns normally, and both pre-MADD import wrappers preserve X23/X24, the statically resolved import target supports the same 0x85e9e970 effective value without relying on that target to preserve X19.",
            ],
            "REFUTED": [
                "Within the unique-direct-BL caller plus conforming-AAPCS64-X19/X23/X24-preservation model, the intrinsic two-value and direct-caller effective sets have no numeric equality to the 12 target values.",
                "Within the STATIC_INITIALIZED_SLOT_UNCHANGED model plus normal-return preservation across the pinned pre-MADD direct callee and the two pre-MADD import wrappers, the direct-caller effective value has no numeric equality to the 12 target values.",
            ],
            "UNKNOWN": [
                "Actual initializer execution, later slot mutation, current runtime import-slot target/currentness, indirect callee/target identity and conformance, pre-MADD result success, post-call register values without the stated conditions, VA-to-PA/identity, physical destination/ownership, runtime semantics, mutability/lock, table/state mutation, alias, bypass and other firmware paths.",
                "Seven SP RX candidates and three RWE ambiguous candidates remain outside this static accounting result.",
            ],
        },
        "classification": STAGE2D_CLASSIFICATION,
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
