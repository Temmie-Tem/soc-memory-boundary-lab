#!/usr/bin/env python3
"""Host-only Experiment 026: bounded XBL dispatch/order and slot escape census.

The decoder in this module is intentionally conservative.  It pins one exact
SM8150 XBL ELF and independently records the dispatch/registration ranges that
are new in Experiment 026.  Experiment 025 is read as a semantic dependency;
its already-supported platform-query/registry idioms are excluded from the
complementary census so this experiment cannot silently duplicate their claims.

No device, USB, SMC, MMIO, protected-memory, runtime-register, or activation
action is performed.  A static edge or a pointer escape is not evidence that
the edge executed, that a memory-only value was non-zero, or that an observed
boot order exists.  Runtime order, runtime slot/object identity, BLR targets,
and current base authority remain UNKNOWN unless separately observed (none is
observed here).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


REPO_ROOT = Path(__file__).resolve().parent.parent
FIRMWARE_DIR = REPO_ROOT / "evidence/private/004-live-firmware-readonly-20260825-01"
XBL_NAME = "xbl--sdb1.bin"
XBL_SIZE = 4_194_304
XBL_SHA256 = "e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37"

DEPENDENCY_NAME = "025-xbl-platform-query-binding-20260826-01.manifest.json"
DEPENDENCY_PATH = REPO_ROOT / "evidence/manifests" / DEPENDENCY_NAME
DEPENDENCY_SIZE = 28_132
DEPENDENCY_SHA256 = "d3c405d7c8d23dc1cd65b1c578b4b4ce931d9bdfeb303c892e9c0c145c4c81cc"

SCHEMA = "sm8150-xbl-dispatch-order-slot-escape-v1"

RUNTIME_SLOT = 0x14890590
REGISTRY_START = 0x14890E50
REGISTRY_END = 0x14890F50
REGISTRATION_GLOBALS_START = 0x14890F50
REGISTRATION_GLOBALS_END = 0x14890F68
REGISTRATION_HEAD = 0x14890F60
FACTORY_OBJECT_START = 0x1488F400
FACTORY_OBJECT_END = 0x1488F440
BOOTSTRAP_STATE_A = 0x1488AF30
BOOTSTRAP_STATE_B = 0x1488AF58

REGISTRATION_CORE_START = 0x1482ECB4
REGISTRATION_CORE_END = 0x1482EDA8
REGISTRATION_START = REGISTRATION_CORE_START
REGISTRATION_END = 0x1482EDAC  # includes the RET at 0x1482eda8
REGISTRATION_CORE_SHA256 = "a06e6ddaaab9efa5fa4756926554d7be8824c27a40dff7173011caf08162d34d"
REGISTRATION_SHA256 = "a603e4dbf24dd86e1487695f7adc3ae6dad23da7c091a074119f55c8b66bc9d7"
REGISTRATION_OFFSET = 0x15CB4

INITIALIZER_START = 0x1482EDAC
INITIALIZER_END = 0x1482F0B4
INITIALIZER_SHA256 = "b17d7aeb92f959c8c47bc0d3b1a970c2483d649d29749b1e2fc80a6e1a7b4cbd"
INITIALIZER_OFFSET = 0x15DAC

TABLE_HEADER_START = 0x14875534
TABLE_HEADER_END = 0x14875568
TABLE_HEADER_SHA256 = "472a39ffae4ed0c869c5f39b2bbd6104b6fab39bc12982bc7e848207585b232a"
TABLE_HEADER_OFFSET = 0x54F14
TABLE_COUNT = 2
TABLE_ROW_START = 0x14875538
TABLE_ROW_STRIDE = 0x18
TABLE_ID_FIELD_OFFSET = 0x14
TABLE_KIND_FIELD_OFFSET = 0x10

BOOTSTRAP_CALLER_START = 0x14852CE0
BOOTSTRAP_CALLER_END = 0x14852D70
BOOTSTRAP_CALLER_SHA256 = "0d8fe60229edeeb076d0e1e684356f7b518df766517d9a8ba51fffaff42f48bf"
BOOTSTRAP_CALLER_OFFSET = 0x39CE0

VENEER_START = 0x14843D20
VENEER_END = 0x14843D50
VENEER_SHA256 = "dca21f62f4878aba67add52fcaeef6b04de9f5b3ef1ff6a5f99612e508c76f1f"
VENEER_OFFSET = 0x2AD20

ALTERNATE_ONE_START = 0x14828338
ALTERNATE_ONE_END = 0x14828360
ALTERNATE_ONE_SHA256 = "fc0344cec688fe4cdaa5b0708023ae7a27516ce8c5c5d341e0f8602865103b6d"
ALTERNATE_ONE_OFFSET = 0xF338
ALTERNATE_TWO_START = 0x14828B44
ALTERNATE_TWO_END = 0x14828C80
ALTERNATE_TWO_SHA256 = "b008d12e3f1a8dad8621a057c3e71c543709810375b2c85a1bec82a2440567e4"
ALTERNATE_TWO_OFFSET = 0xFB44

DISPATCHER_START = 0x14864834
DISPATCHER_END = 0x148648C0
DISPATCHER_SHA256 = "519df36f8fd0c91b7b09564254b0e32377dc0f78158f5c7b088a4721e45ab309"
DISPATCHER_OFFSET = 0x4B834
DISPATCHER_POOL_START = 0x146B30C0
DISPATCHER_POOL_END = 0x146B38B0
DISPATCHER_POOL_STRIDE = 0x3F8
DISPATCHER_POOL_ROWS = 2
DISPATCHER_POOL_INDEX_OFFSET = 9

# Descriptive aliases used by the manifest/review vocabulary.
MAIN_DISPATCHER_START = DISPATCHER_START
MAIN_DISPATCHER_END = DISPATCHER_END
INITIALIZER_POOL_START = DISPATCHER_POOL_START
INITIALIZER_POOL_END = DISPATCHER_POOL_END
REGISTRATION_HELPER_START = REGISTRATION_START
REGISTRATION_HELPER_END = REGISTRATION_CORE_END

CALLER_RANGES = (
    ("caller_context_init", 0x148641A4, 0x1486420C, "6bbd29427c6cb5853b47a6d6e529d5cf66207d2873e94042f8688bd790e49429", 0x4B1A4),
    ("caller_dispatch_wrapper", 0x1486420C, 0x1486424C, "2df6fdc5eff88cb71e1df58d7bdc0d9433b97b16d66855f0811ffad956f55eef", 0x4B20C),
    ("caller_service_path", 0x148642DC, 0x148644CC, "de5b437bb270fecfe558b9c0e097ff4eb4566480c177f6b530ee90b0777095cc", 0x4B2DC),
    ("caller_bootstrap_entry", 0x1485A2EC, 0x1485A30C, "0516e6042e3bffa173786336e107925e497ff6fdbcc5467ca0554272cca90124", 0x412EC),
)

# Memory-only PT_LOAD containing the requested pool.  There is deliberately no
# file hash for this range: the ELF has no file-backed bytes at this VA.
POOL_SEGMENT_INDEX = 10
POOL_SEGMENT_VADDR = 0x146B2000
POOL_SEGMENT_MEM_SIZE = 0x3204

# Exact 025-supported code ranges.  The complementary census skips these
# words and reports the exclusion explicitly.  Data ranges are listed for
# documentation but cannot occur in a file-backed executable scan.
EXCLUDED_025_RANGES = (
    (0x1482D7EC, 0x1482D948, "registry_attach"),
    (0x1482E7BC, 0x1482E834, "wrappers"),
    (0x1482EE38, 0x1482EE4C, "seed"),
    (0x1484A730, 0x1484A750, "callback_callee"),
    (0x1484A824, 0x1484A854, "lazy_init"),
    (0x1484A854, 0x1484A880, "lazy_status_helper"),
    (0x1484A880, 0x1484A8FC, "factory"),
    (0x1484A9D4, 0x1484AA0C, "callback"),
    (0x1484AA30, 0x1484AA74, "lazy_bootstrap"),
    (0x14868418, 0x148688F0, "025_main_initializer"),
    (0x148689A0, 0x14868A64, "024_walker"),
    (0x1486ABEC, 0x1486ACAC, "025_platform_query"),
)


class DispatchError(ValueError):
    """Raised on malformed input or an exact/static pin mismatch."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fmt(value: int) -> str:
    return f"0x{value:08x}"


def fmt_offset(value: int) -> str:
    return f"0x{value:x}"


def sign_extend(value: int, bits: int) -> int:
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


@dataclass(frozen=True)
class Segment:
    index: int
    file_offset: int
    vaddr: int
    file_size: int
    mem_size: int
    flags: int

    @property
    def executable(self) -> bool:
        return bool(self.flags & 1)

    @property
    def kind(self) -> str:
        return {1: "X", 2: "W", 3: "WX", 4: "R", 5: "RX", 6: "RW", 7: "RWX"}.get(self.flags, f"F{self.flags}")


class Image:
    """Independent, bounds-checked ELF64 PT_LOAD reader."""

    def __init__(self, data: bytes):
        if len(data) < 64 or data[:4] != b"\x7fELF" or data[4:6] != b"\x02\x01" or data[6] != 1:
            raise DispatchError("not a little-endian ELF64 image")
        phoff = struct.unpack_from("<Q", data, 32)[0]
        phentsize = struct.unpack_from("<H", data, 54)[0]
        phnum = struct.unpack_from("<H", data, 56)[0]
        if phentsize < 56 or phnum > 4096 or phoff > len(data) or phoff + phentsize * phnum > len(data):
            raise DispatchError("invalid program-header shape")
        self.data = data
        self.segments: list[Segment] = []
        for index in range(phnum):
            off = phoff + index * phentsize
            p_type, flags, file_off, va, _pa, file_size, mem_size, _align = struct.unpack_from("<IIQQQQQQ", data, off)
            if p_type != 1:
                continue
            if file_off > len(data) or file_off + file_size > len(data) or mem_size < file_size:
                raise DispatchError(f"PT_LOAD {index} exceeds image or has memsz < filesz")
            self.segments.append(Segment(index, file_off, va, file_size, mem_size, flags))

    def file_backed(self) -> list[Segment]:
        return [s for s in self.segments if s.file_size]

    def executable(self) -> list[Segment]:
        return [s for s in self.file_backed() if s.executable]

    def segment_for(self, va: int, *, file_backed: bool = True) -> Segment | None:
        matches = [
            s for s in self.segments
            if s.vaddr <= va < s.vaddr + (s.file_size if file_backed else s.mem_size)
            and (not file_backed or s.file_size)
        ]
        if len(matches) > 1:
            raise DispatchError(f"ambiguous PT_LOAD mapping at {fmt(va)}")
        return matches[0] if matches else None

    def file_offset(self, va: int) -> int | None:
        s = self.segment_for(va)
        return None if s is None else s.file_offset + va - s.vaddr

    def slice(self, start: int, end: int) -> bytes:
        if end <= start:
            raise DispatchError("empty or reversed range")
        first = self.file_offset(start)
        last = self.file_offset(end - 1)
        if first is None or last is None or last + 1 != first + end - start:
            raise DispatchError(f"range is not one file-backed PT_LOAD: {fmt(start)}..{fmt(end)}")
        return self.data[first:first + end - start]

    def word(self, va: int) -> int | None:
        off = self.file_offset(va)
        if off is None or off % 4 or off + 4 > len(self.data):
            return None
        return struct.unpack_from("<I", self.data, off)[0]

    def qword(self, va: int) -> int | None:
        off = self.file_offset(va)
        if off is None or off + 8 > len(self.data):
            return None
        return struct.unpack_from("<Q", self.data, off)[0]

    def instructions(self, segment: Segment) -> Iterable[tuple[int, int]]:
        for rel in range(0, max(0, segment.file_size - 3), 4):
            yield segment.vaddr + rel, struct.unpack_from("<I", self.data, segment.file_offset + rel)[0]


def decode_bl_target(word: int, va: int) -> int | None:
    if (word & 0xFC000000) != 0x94000000:
        return None
    return va + 4 * sign_extend(word & 0x03FFFFFF, 26)


def decode_b_target(word: int, va: int) -> int | None:
    if (word & 0xFC000000) == 0x14000000:
        return va + 4 * sign_extend(word & 0x03FFFFFF, 26)
    if (word & 0xFF000010) == 0x54000000:
        return va + 4 * sign_extend((word >> 5) & 0x7FFFF, 19)
    if (word & 0x7E000000) == 0x34000000:
        return va + 4 * sign_extend((word >> 5) & 0x7FFFF, 19)
    if (word & 0x7E000000) == 0x36000000:
        return va + 4 * sign_extend((word >> 5) & 0x3FFF, 14)
    return None


def is_blr(word: int) -> int | None:
    return (word >> 5) & 0x1F if (word & 0xFFFFFC1F) == 0xD63F0000 else None


def is_br(word: int) -> int | None:
    return (word >> 5) & 0x1F if (word & 0xFFFFFC1F) == 0xD61F0000 else None


def is_ret(word: int) -> bool:
    return (word & 0xFFFFFC1F) == 0xD65F0000


def is_adr(word: int) -> tuple[int, int] | None:
    if (word & 0x9F000000) != 0x10000000:
        return None
    imm = sign_extend((((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 3), 21)
    return imm, word & 0x1F


def is_adrp(word: int) -> tuple[int, int] | None:
    if (word & 0x9F000000) != 0x90000000:
        return None
    imm = sign_extend((((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 3), 21) << 12
    return imm, word & 0x1F


def adr_target(word: int, va: int) -> tuple[int, int] | None:
    d = is_adr(word)
    return None if d is None else ((va + d[0]) & 0xFFFFFFFFFFFFFFFF, d[1])


def adrp_target(word: int, va: int) -> tuple[int, int] | None:
    d = is_adrp(word)
    return None if d is None else (((va & ~0xFFF) + d[0]) & 0xFFFFFFFFFFFFFFFF, d[1])


def _is_add_sub_imm(word: int) -> tuple[str, str, int, int, int] | None:
    # Reject flag-setting ADDS/SUBS and Rd=ZR/CMP aliases.  They do not create
    # a general-purpose address definition for this census.
    # Bit23 is fixed-zero for ADD/SUB (immediate); ADDG/SUBG (MTE) use the
    # otherwise similar 0x918.../0xd18... encoding and are not this form.
    if (word & 0x1F000000) not in (0x11000000, 0x51000000, 0x91000000, 0xD1000000) or word & 0x20000000 or word & 0x00800000:
        return None
    sf = "X" if word & 0x80000000 else "W"
    op = "SUB" if word & 0x40000000 else "ADD"
    rd, rn = word & 0x1F, (word >> 5) & 0x1F
    if rd == 31:
        return None
    imm = (word >> 10) & 0xFFF
    if word & (1 << 22):
        imm <<= 12
    return op, sf, imm, rn, rd


def is_add_x_imm(word: int) -> tuple[int, int, int, int] | None:
    d = _is_add_sub_imm(word)
    if d is None or d[0] != "ADD" or d[1] != "X" or d[2] >= (1 << 24):
        return None
    return d[4], d[3], d[2] & 0xFFF, 12 if word & (1 << 22) else 0


def is_sub_x_imm(word: int) -> tuple[int, int, int, int] | None:
    d = _is_add_sub_imm(word)
    if d is None or d[0] != "SUB" or d[1] != "X":
        return None
    return d[4], d[3], d[2] & 0xFFF, 12 if word & (1 << 22) else 0


def is_add_sub_reg(word: int) -> tuple[str, str, int, int, int, int, int] | None:
    # ADD/SUB (shifted register).  Return both the shift type and imm6; the
    # shift type is not itself a shift amount (a previous implementation
    # accidentally shifted by 0/1/2 for LSL/LSR/ASR).
    if (word & 0x1F200000) != 0x0B000000 or word & 0x20000000:
        return None
    sf = "X" if word & 0x80000000 else "W"
    op = "SUB" if word & 0x40000000 else "ADD"
    shift_type = (word >> 22) & 3
    if shift_type == 3 or (word & 0x1F) == 31:
        return None
    return op, sf, word & 0x1F, (word >> 5) & 0x1F, (word >> 16) & 0x1F, shift_type, (word >> 10) & 0x3F


def is_add_sub_ext_reg(word: int) -> tuple[str, str, int, int, int, int, int] | None:
    # ADD/SUB (extended register): option encodes UXTW/SXTW/UXTX/SXTX and
    # LSL #0..4.  Keep the option explicit so tests can reject unsupported
    # widths rather than treating all register arithmetic as an address.
    # Bits23:22 are fixed-zero for ADD/SUB (extended register); values 01/10
    # are undefined/reserved encodings, not alternate extension forms.
    if (word & 0x1F200000) != 0x0B200000 or word & 0x20000000 or word & 0x00C00000:
        return None
    sf = "X" if word & 0x80000000 else "W"
    op = "SUB" if word & 0x40000000 else "ADD"
    if (word & 0x1F) == 31:
        return None
    option = (word >> 13) & 7
    if sf == "W" and option in (3, 7):
        # UXTX/SXTX are not valid widening sources for the W form under this
        # bounded model; keep them UNKNOWN rather than truncating implicitly.
        return None
    return op, sf, word & 0x1F, (word >> 5) & 0x1F, (word >> 16) & 0x1F, option, (word >> 10) & 7


def is_movz(word: int) -> tuple[str, int, int, int] | None:
    if (word & 0x7F800000) != 0x52800000:
        return None
    width = "X" if word & 0x80000000 else "W"
    return width, (word >> 5) & 0xFFFF, (word >> 21) & 3, word & 0x1F


def is_movk(word: int) -> tuple[str, int, int, int] | None:
    if (word & 0x7F800000) != 0x72800000:
        return None
    width = "X" if word & 0x80000000 else "W"
    return width, (word >> 5) & 0xFFFF, (word >> 21) & 3, word & 0x1F


def is_movn(word: int) -> tuple[str, int, int, int] | None:
    if (word & 0x7F800000) != 0x12800000:
        return None
    width = "X" if word & 0x80000000 else "W"
    return width, (word >> 5) & 0xFFFF, (word >> 21) & 3, word & 0x1F


def is_orr_reg(word: int) -> tuple[str, int, int, int, int, int] | None:
    # Bits 10..15 hold the optional logical shift and must not participate in
    # the opcode match.
    # 0x0a... is AND (not ORR); only the W/X ORR opcodes are accepted.
    # Bits23:22 are the shift type and must be excluded from the opcode mask;
    # otherwise only LSL (00) would be accepted.  The scanner applies exact
    # LSL/LSR/ASR semantics below.
    if (word & 0xFF200000) not in (0x2A000000, 0xAA000000) or (word & 0x1F) == 31:
        return None
    width = "X" if word & 0x80000000 else "W"
    shift_type = (word >> 22) & 3
    if shift_type == 3:
        return None
    return width, word & 0x1F, (word >> 5) & 0x1F, (word >> 16) & 0x1F, shift_type, (word >> 10) & 0x3F


def is_orr_imm(word: int) -> tuple[str, int, int, int] | None:
    if (word & 0x7F800000) != 0x32000000:
        return None
    # Decode logical immediate (N:immr:imms) for the subset needed by
    # materialized scalar/address constants.  A non-representable encoding is
    # rejected rather than approximated.
    width = 64 if word & 0x80000000 else 32
    n = (word >> 22) & 1
    immr, imms, rd, rn = (word >> 16) & 0x3F, (word >> 10) & 0x3F, word & 0x1F, (word >> 5) & 0x1F
    if width == 32 and n:
        return None
    value = _decode_logical_immediate(n, immr, imms, width)
    if value is None:
        return None
    return "X" if width == 64 else "W", rd, rn, value


def _decode_logical_immediate(n: int, immr: int, imms: int, width: int) -> int | None:
    # ARM ARM DecodeBitMasks, constrained to valid logical-immediate forms.
    combined = (n << 6) | ((~imms) & 0x3F)
    if combined == 0:
        return None
    length = combined.bit_length() - 1
    if length < 1 or (1 << length) > width:
        return None
    levels = (1 << length) - 1
    s = imms & levels
    r = immr & levels
    if s == levels:
        return None
    element = (1 << (s + 1)) - 1
    element = ((element >> r) | (element << ((1 << length) - r))) & ((1 << (1 << length)) - 1)
    repeat = 1 << length
    value = 0
    for bit in range(0, width, repeat):
        value |= element << bit
    return value & ((1 << width) - 1)


def is_extend(word: int) -> tuple[str, int, int] | None:
    """UBFM/SBFM extension aliases are intentionally unsupported.

    Their alias widths/sign behavior are easy to misclassify in a raw-word
    census.  Returning ``None`` makes the scanner clear taint and report the
    form as UNKNOWN instead of manufacturing a fixed address.
    """
    return None


def _mem_size_from_code(size: int) -> tuple[str, int] | None:
    return {0: ("B", 1), 1: ("H", 2), 2: ("W", 4), 3: ("X", 8)}.get(size)


def is_mem_unsigned(word: int) -> tuple[str, str, int, int, int] | None:
    # LDR/STR unsigned immediate for byte/half/word/xword.  SIMD and sign-
    # extending forms are intentionally outside this narrow direct model.
    group = word & 0xFFC00000
    groups = {
        0x39400000: ("LDR", "B", 1), 0xB9400000: ("LDR", "W", 4), 0xF9400000: ("LDR", "X", 8),
        0x39000000: ("STR", "B", 1), 0xB9000000: ("STR", "W", 4), 0xF9000000: ("STR", "X", 8),
        0x79400000: ("LDR", "H", 2), 0x79000000: ("STR", "H", 2),
    }
    if group not in groups:
        return None
    kind, width, scale = groups[group]
    return kind, width, ((word >> 10) & 0xFFF) * scale, (word >> 5) & 0x1F, word & 0x1F


def is_mem_unscaled(word: int) -> tuple[str, str, int, int, int] | None:
    # LDUR/STUR and byte/half variants.  Exclude pair/literal encodings.
    opcode = word & 0xFFE00C00
    shapes = {
        0x38000000: ("B", 1, "STR"), 0x38400000: ("B", 1, "LDR"),
        0x78000000: ("H", 2, "STR"), 0x78400000: ("H", 2, "LDR"),
        0xB8000000: ("W", 4, "STR"), 0xB8400000: ("W", 4, "LDR"),
        0xF8000000: ("X", 8, "STR"), 0xF8400000: ("X", 8, "LDR"),
    }
    shape = shapes.get(opcode)
    if shape is None:
        return None
    width, _scale, kind = shape
    return kind, width, sign_extend((word >> 12) & 0x1FF, 9), (word >> 5) & 0x1F, word & 0x1F


def is_mem_index(word: int) -> tuple[str, str, int, int, int, str] | None:
    # Signed immediate pre/post-index forms.  The low op bits distinguish
    # pre/post; return the mode to update a tracked base only after access.
    opcode = word & 0xFFC00C00
    valid = {
        0x38000400: ("B", "STR"), 0x38000C00: ("B", "STR"),
        0x38400400: ("B", "LDR"), 0x38400C00: ("B", "LDR"),
        0x78000400: ("H", "STR"), 0x78000C00: ("H", "STR"),
        0x78400400: ("H", "LDR"), 0x78400C00: ("H", "LDR"),
        0xB8000400: ("W", "STR"), 0xB8000C00: ("W", "STR"),
        0xB8400400: ("W", "LDR"), 0xB8400C00: ("W", "LDR"),
        0xF8000400: ("X", "STR"), 0xF8000C00: ("X", "STR"),
        0xF8400400: ("X", "LDR"), 0xF8400C00: ("X", "LDR"),
    }
    shape = valid.get(opcode)
    if shape is None:
        return None
    width, kind = shape
    mode = "POSTINDEX" if (word & 0x00000C00) == 0x00000400 else "PREINDEX"
    return kind, width, sign_extend((word >> 12) & 0x1FF, 9), (word >> 5) & 0x1F, word & 0x1F, mode


def is_mem_pair(word: int) -> tuple[str, str, int, int, int, int, str] | None:
    # LDP/STP W/X signed offset, pre-index, post-index.  Pair addressing mode
    # is encoded in bits 24:23; bits 14:10 are Rt2 and must not be mistaken
    # for mode bits.  Return Rt2 so a load kills both destinations.
    # Integer pair opcodes are 0x28 under this mask; 0x2c is SIMD/FP pair.
    if (word & 0x3E000000) != 0x28000000:
        return None
    size = (word >> 30) & 3
    # Pair encodings use size=00 for W and size=10 for X (unlike the
    # unsigned single-register encodings, where size=11 denotes X).
    if size == 0:
        width, scale = "W", 4
    elif size == 2:
        width, scale = "X", 8
    else:
        return None
    kind = "LDP" if word & 0x00400000 else "STP"
    mode_bits = (word >> 23) & 3
    mode = {1: "POSTINDEX", 2: "OFFSET", 3: "PREINDEX"}.get(mode_bits)
    if mode is None:
        return None
    imm = sign_extend((word >> 15) & 0x7F, 7) * scale
    return kind, width, imm, (word >> 5) & 0x1F, word & 0x1F, (word >> 10) & 0x1F, mode


def is_mem_literal(word: int, va: int) -> tuple[str, str, int, int] | None:
    # Keep only LDR W/X literal.  LDRSW and PRFM share the broad literal
    # shape but have different destination/semantics and remain UNKNOWN.
    if (word & 0xFF000000) not in (0x18000000, 0x58000000):
        return None
    width = ("X", 8) if (word & 0xFF000000) == 0x58000000 else ("W", 4)
    target = va + sign_extend((word >> 5) & 0x7FFFF, 19) * 4
    return "LDR", width[0], target, word & 0x1F


def is_mem_reg_offset(word: int) -> tuple[str, str, int, int, int, int, int] | None:
    # Register-offset LDR/STR W/X/B/H.  Option is bits 15:13 and S is bit 12;
    # scale is the access-size shift only when S=1.  Unsupported options are
    # rejected rather than treated as LSL.
    # Masking with 0x3fe... retains the integer size-independent opcode,
    # distinguishes LDR (0x386...) from STR (0x382...), and rejects SIMD/V
    # (bit26) and sign-ext/unprivileged variants (bit23/opcode changes).
    opcode = word & 0x3FE00C00
    if opcode not in (0x38200800, 0x38600800):
        return None
    shape = _mem_size_from_code((word >> 30) & 3)
    if shape is None:
        return None
    kind = "LDR" if opcode == 0x38600800 else "STR"
    width, _ = shape
    option = (word >> 13) & 7
    if option not in (2, 3, 6, 7):
        return None
    scaled = (word >> 12) & 1
    scale = {"B": 0, "H": 1, "W": 2, "X": 3}[width] if scaled else 0
    return kind, width, (word >> 5) & 0x1F, (word >> 16) & 0x1F, option, scale, word & 0x1F


def is_mem_exclusive_atomic(word: int) -> tuple[str, str, int, int] | None:
    # Exclusive/LSE forms have load-vs-store and acquire/release semantics
    # that this bounded taint model does not implement.  Keep the name as a
    # negative decoder hook so callers/tests can assert fail-closed behavior.
    return None


# Familiar names retained for focused reviewers that use the Experiment 025
# decoder vocabulary.  They are aliases only; the complementary scope and
# exclusion policy remain Experiment-026-specific.
is_ldr_str_unsigned = is_mem_unsigned
is_ldr_str_unscaled = is_mem_unscaled


def is_ldr_postindex(word: int) -> tuple[str, str, int, int, int] | None:
    decoded = is_mem_index(word)
    return None if decoded is None or decoded[-1] != "POSTINDEX" else decoded[:-1]


def _u32(image: Image, va: int) -> int:
    value = image.word(va)
    if value is None:
        raise DispatchError(f"unmapped word at {fmt(va)}")
    return value


def assert_words(image: Image, expected: dict[int, int]) -> None:
    for va, expected_word in expected.items():
        if _u32(image, va) != expected_word:
            raise DispatchError(f"instruction/data mismatch at {fmt(va)}")


def range_record(image: Image, start: int, end: int, *, expected_offset: int, expected_hash: str, label: str) -> dict:
    data = image.slice(start, end)
    offset = image.file_offset(start)
    if offset != expected_offset or sha256(data) != expected_hash:
        raise DispatchError(f"{label} exact range pin mismatch")
    return {"start": fmt(start), "end_exclusive": fmt(end), "file_offset": fmt_offset(offset), "size": end - start, "sha256": expected_hash}


def direct_edges(image: Image, start: int, end: int) -> dict:
    calls: list[dict] = []
    branches: list[dict] = []
    indirect: list[dict] = []
    for va in range(start, end, 4):
        word = _u32(image, va)
        target = decode_bl_target(word, va)
        if target is not None:
            calls.append({"va": fmt(va), "word": fmt(word), "target": fmt(target), "kind": "BL"})
            continue
        if is_blr(word) is not None:
            indirect.append({"va": fmt(va), "word": fmt(word), "kind": "BLR", "register": f"X{is_blr(word)}", "target": "UNKNOWN"})
            continue
        if is_br(word) is not None:
            indirect.append({"va": fmt(va), "word": fmt(word), "kind": "BR", "register": f"X{is_br(word)}", "target": "UNKNOWN"})
            continue
        target = decode_b_target(word, va)
        if target is not None:
            # decode_b_target also recognizes conditional branches.  Keep the
            # instruction class visible so local control edges are not turned
            # into calls.
            branches.append({"va": fmt(va), "word": fmt(word), "target": fmt(target), "kind": "B_OR_CONDITIONAL"})
    return {"direct_bl": calls, "branches": branches, "indirect": indirect}


def _is_excluded(va: int) -> str | None:
    for start, end, label in EXCLUDED_025_RANGES:
        if start <= va < end:
            return label
    return None


def _write_kind(kind: str) -> bool:
    return kind in {"STR", "STP", "STUR", "STR_POSTINDEX", "STR_PREINDEX"}


_WIDTH_BYTES = {"B": 1, "H": 2, "W": 4, "X": 8}


def _target_class(address: int, width_bytes: int = 1) -> str | None:
    """Classify an address or memory span by containment/overlap.

    Pointer escapes use the default one-byte span (containment).  Memory
    accesses pass their actual width so a slot+4 W store or slot-4 X store
    overlapping the pointer-sized slot is not misclassified as absent.
    """
    end = address + max(1, width_bytes)
    intervals = (
        (RUNTIME_SLOT, RUNTIME_SLOT + 8, "RUNTIME_SLOT_0x14890590"),
        (REGISTRY_START, REGISTRY_END, "REGISTRY_LIST_0x14890e50_0x14890f50"),
        (REGISTRATION_GLOBALS_START, REGISTRATION_GLOBALS_END, "REGISTRATION_GLOBALS_0x14890f50_0x14890f68"),
        (FACTORY_OBJECT_START, FACTORY_OBJECT_END, "FACTORY_OBJECT_0x1488f400_0x1488f440"),
        (BOOTSTRAP_STATE_A, BOOTSTRAP_STATE_A + 0x10, "BOOTSTRAP_STATE_AROUND_0x1488af30"),
        (BOOTSTRAP_STATE_B, BOOTSTRAP_STATE_B + 0x10, "BOOTSTRAP_STATE_AROUND_0x1488af58"),
    )
    for start, stop, label in intervals:
        if address < stop and start < end:
            return label
    return None


def _record_access(
    accesses: list[dict],
    *,
    va: int,
    word: int,
    kind: str,
    width: str,
    target: int,
    offset: int = 0,
    base_register: int | None = None,
    index_register: int | None = None,
    index_option: int | None = None,
    index_scale: int | None = None,
    source: str = "COMPLEMENTARY_ALL_EXECUTABLE_PT_LOAD_CENSUS",
    excluded: str | None = None,
) -> None:
    width_bytes = _WIDTH_BYTES.get(width)
    if width_bytes is None:
        return
    target_kind = _target_class(target, width_bytes)
    if target_kind is None:
        return
    row = {
            "va": fmt(va),
            "word": fmt(word),
            "kind": kind,
            "width": width,
            "target": fmt(target),
            "access_span": {"start": fmt(target), "end_exclusive": fmt(target + width_bytes)},
            "target_class": target_kind,
            "offset": offset,
            "base_register": None if base_register is None else f"X{base_register}",
            "index_register": None if index_register is None else f"X{index_register}",
            "index_option": index_option,
            "index_scale": index_scale,
            "address_model": source,
            "excluded_025_range": excluded,
        }
    if va == 0x1482ED68 and target == REGISTRATION_HEAD:
        row["target_semantics"] = "global head on empty-list branch; otherwise tail_node+0x10"
        row["control_flow_condition"] = "X20 head node is null versus non-null traversal"
    accesses.append(row)


def _memory_decode(word: int, va: int, image: Image) -> tuple[str, str, int | None, int | None, int, int, str, int | None] | None:
    """Return a normalized memory operation.

    ``(kind,width,base_reg,index_reg,offset,post_delta,form,second_reg)``.  ``base_reg``
    is ``None`` for literal loads.  A pair has two adjacent elements but one
    normalized record is enough for target classification; the caller emits a
    second record when the second element is in a target range.
    """
    literal = is_mem_literal(word, va)
    if literal is not None:
        kind, width, literal_va, rt = literal
        # Literal loads are represented by base_reg=None and offset=literal VA;
        # the scanner may use the literal's value to seed ``rt``.
        return kind, width, None, rt, literal_va, 0, "LITERAL", None
    pair = is_mem_pair(word)
    if pair is not None:
        kind, width, offset, rn, rt, rt2, mode = pair
        delta = offset if mode in ("POSTINDEX", "PREINDEX") else 0
        return kind, width, rn, rt, offset, delta, f"PAIR_{mode}", rt2
    reg = is_mem_reg_offset(word)
    if reg is not None:
        kind, width, rn, rm, option, scale, rt = reg
        # Encode option/scale in the normalized form; the scanner applies
        # UXTW/UXTX/SXTW/SXTX and S-size scaling exactly.
        return kind, width, rn, rm, option, scale, "REGISTER_OFFSET", rt
    indexed = is_mem_index(word)
    if indexed is not None:
        kind, width, offset, rn, rt, mode = indexed
        return kind, width, rn, rt, offset, offset if mode in ("POSTINDEX", "PREINDEX") else 0, mode, None
    unscaled = is_mem_unscaled(word)
    if unscaled is not None:
        kind, width, offset, rn, rt = unscaled
        return kind, width, rn, rt, offset, 0, "UNSCALED", None
    unsigned = is_mem_unsigned(word)
    if unsigned is not None:
        kind, width, offset, rn, rt = unsigned
        return kind, width, rn, rt, offset, 0, "UNSIGNED", None
    return None


def _is_zero_or_nop(word: int) -> bool:
    return word in (0xD503201F, 0xD5033FDF)


def _shift_value(value: int, width: str, shift_type: int, amount: int) -> int | None:
    """Apply AArch64 shifted-register semantics exactly."""
    bits = 64 if width == "X" else 32
    mask = (1 << bits) - 1
    value &= mask
    if amount >= bits or shift_type == 3:
        return None
    if shift_type == 0:  # LSL
        return (value << amount) & mask
    if shift_type == 1:  # LSR
        return value >> amount
    signed = value - (1 << bits) if value & (1 << (bits - 1)) else value
    return (signed >> amount) & mask  # ASR


def _extended_value(value: int, option: int) -> int | None:
    """Decode ADD/SUB extended-register option (UXTW/UXTX/SXTW/SXTX)."""
    if option == 2:  # UXTW
        return value & 0xFFFFFFFF
    if option == 3:  # UXTX
        return value & 0xFFFFFFFFFFFFFFFF
    if option == 6:  # SXTW
        value &= 0xFFFFFFFF
        return value - (1 << 32) if value & 0x80000000 else value
    if option == 7:  # SXTX
        value &= 0xFFFFFFFFFFFFFFFF
        return value - (1 << 64) if value & (1 << 63) else value
    return None


def _set_reg(regs: dict[int, int], register: int, value: int) -> None:
    # Register 31 is XZR in these address-producing instructions.  Treating
    # it as a persistent SP/XZR value would let taint survive an alias that is
    # not modeled; clear it conservatively.
    if register == 31:
        regs.pop(31, None)
    else:
        regs[register] = value


def decode_materialised_addresses(image: Image) -> dict:
    """Complementary fail-closed census over executable file-backed words.

    The scanner carries only concrete register values along the current
    straight-line span.  Any call/branch/unknown write clears the map.  It
    recognizes ADR/ADRP, MOVZ/MOVK/MOVN, ADD/SUB immediate/shifted/
    extended-register arithmetic, exact ORR W/X copies, and direct memory
    forms.  UBFM/SBFM, exclusive/LSE, and other unsupported forms are cleared.
    A direct call records tracked X0..X7 argument escapes, while BLR/BR targets
    remain UNKNOWN.  The result is intentionally an under-approximation: an
    empty recognized list is never a writer-absence claim.
    """
    accesses: list[dict] = []
    escapes: list[dict] = []
    calls: list[dict] = []
    unsupported: set[str] = set()
    word_count = 0
    excluded_word_count = 0
    recognized_word_forms = {
        "ADR", "ADRP", "MOVZ", "MOVK", "MOVN", "ADD_SUB_IMMEDIATE", "ADD_SUB_REGISTER",
        "ADD_SUB_EXTENDED_REGISTER", "ORR_REGISTER_COPY_OR_SHIFT", "ORR_LOGICAL_IMMEDIATE",
        "LDR_STR_UNSIGNED", "LDR_STR_UNSCALED", "LDR_STR_INDEXED", "LDP_STP", "LDR_LITERAL",
        "REGISTER_OFFSET", "DIRECT_BL_ARGUMENT_TAINT",
    }

    for segment in image.executable():
        regs: dict[int, int] = {}
        for va, word in image.instructions(segment):
            word_count += 1
            excluded = _is_excluded(va)
            if excluded is not None:
                excluded_word_count += 1
                # Do not carry an address proof through a dependency range.
                regs.clear()
                continue

            target = decode_bl_target(word, va)
            if target is not None:
                args = []
                for reg in range(8):
                    if reg in regs:
                        args.append({"register": f"X{reg}", "value": fmt(regs[reg])})
                        cls = _target_class(regs[reg])
                        if cls is not None:
                            escapes.append({"va": fmt(va), "word": fmt(word), "kind": "BL_ARGUMENT_ESCAPE", "target": fmt(regs[reg]), "target_class": cls, "argument": f"X{reg}", "callee": fmt(target)})
                calls.append({"va": fmt(va), "word": fmt(word), "kind": "BL", "target": fmt(target), "tracked_arguments": args})
                regs.clear()
                continue
            blr = is_blr(word)
            br = is_br(word)
            if blr is not None or br is not None:
                kind = "BLR" if blr is not None else "BR"
                reg = blr if blr is not None else br
                args = []
                for arg in range(8):
                    if arg in regs:
                        args.append({"register": f"X{arg}", "value": fmt(regs[arg])})
                        cls = _target_class(regs[arg])
                        if cls is not None:
                            escapes.append({"va": fmt(va), "word": fmt(word), "kind": f"{kind}_ARGUMENT_ESCAPE", "target": fmt(regs[arg]), "target_class": cls, "argument": f"X{arg}", "callee": "UNKNOWN"})
                calls.append({"va": fmt(va), "word": fmt(word), "kind": kind, "register": f"X{reg}", "target": "UNKNOWN", "tracked_arguments": args})
                unsupported.add("INDIRECT_BRANCH_TARGET_OR_RUNTIME_ALIAS")
                regs.clear()
                continue
            branch = decode_b_target(word, va)
            if branch is not None or is_ret(word):
                regs.clear()
                continue

            adrp = adrp_target(word, va)
            if adrp is not None:
                _set_reg(regs, adrp[1], adrp[0])
                continue
            adr = adr_target(word, va)
            if adr is not None:
                _set_reg(regs, adr[1], adr[0])
                continue

            movz = is_movz(word)
            movk = is_movk(word)
            movn = is_movn(word)
            if movz is not None:
                width, imm, hw, rd = movz
                if width == "W" and hw > 1:
                    regs.pop(rd, None)
                else:
                    _set_reg(regs, rd, (imm << (16 * hw)) & (0xFFFFFFFF if width == "W" else 0xFFFFFFFFFFFFFFFF))
                continue
            if movn is not None:
                width, imm, hw, rd = movn
                if width == "W" and hw > 1:
                    regs.pop(rd, None)
                else:
                    mask = 0xFFFFFFFF if width == "W" else 0xFFFFFFFFFFFFFFFF
                    _set_reg(regs, rd, (~(imm << (16 * hw))) & mask)
                continue
            if movk is not None:
                width, imm, hw, rd = movk
                mask = 0xFFFFFFFF if width == "W" else 0xFFFFFFFFFFFFFFFF
                old = regs.get(rd)
                if old is None or (width == "W" and hw > 1):
                    regs.pop(rd, None)
                else:
                    half_mask = 0xFFFF << (16 * hw)
                    _set_reg(regs, rd, ((old & ~half_mask) | (imm << (16 * hw))) & mask)
                continue

            logical_imm = is_orr_imm(word)
            if logical_imm is not None:
                width, rd, rn, value = logical_imm
                if rn == 31:
                    _set_reg(regs, rd, value)
                elif rn in regs:
                    _set_reg(regs, rd, regs[rn] | value)
                else:
                    regs.pop(rd, None)
                continue
            logical = is_orr_reg(word)
            if logical is not None:
                width, rd, rn, rm, shift_type, amount = logical
                shifted = _shift_value(regs[rm], width, shift_type, amount) if rm in regs else None
                if rn == 31 and rm in regs:
                    if shifted is None:
                        regs.pop(rd, None)
                    else:
                        _set_reg(regs, rd, shifted)
                elif rm == 31 and rn in regs:
                    # Rm==ZR contributes zero; the shift applies to Rm, not
                    # the first operand Rn.
                    _set_reg(regs, rd, regs[rn])
                elif rn in regs and rm in regs:
                    if shifted is None:
                        regs.pop(rd, None)
                    else:
                        mask = 0xFFFFFFFFFFFFFFFF if width == "X" else 0xFFFFFFFF
                        _set_reg(regs, rd, (regs[rn] | shifted) & mask)
                else:
                    regs.pop(rd, None)
                continue
            ext = is_extend(word)
            if ext is not None:
                _name, rd, rn = ext
                if rn in regs:
                    value = regs[rn] & 0xFFFFFFFF
                    if _name.startswith("SXT") and value & 0x80000000:
                        value -= 1 << 32
                    _set_reg(regs, rd, value & 0xFFFFFFFFFFFFFFFF)
                else:
                    regs.pop(rd, None)
                continue

            add_imm = _is_add_sub_imm(word)
            if add_imm is not None:
                op, width, imm, rn, rd = add_imm
                mask = 0xFFFFFFFF if width == "W" else 0xFFFFFFFFFFFFFFFF
                if rn in regs:
                    _set_reg(regs, rd, ((regs[rn] - imm) if op == "SUB" else (regs[rn] + imm)) & mask)
                else:
                    regs.pop(rd, None)
                continue
            add_reg = is_add_sub_reg(word)
            if add_reg is not None:
                op, width, rd, rn, rm, shift_type, amount = add_reg
                mask = 0xFFFFFFFF if width == "W" else 0xFFFFFFFFFFFFFFFF
                if rn in regs and rm in regs:
                    value = _shift_value(regs[rm], width, shift_type, amount)
                    if value is None:
                        regs.pop(rd, None)
                    else:
                        _set_reg(regs, rd, ((regs[rn] - value) if op == "SUB" else (regs[rn] + value)) & mask)
                else:
                    regs.pop(rd, None)
                continue
            add_ext = is_add_sub_ext_reg(word)
            if add_ext is not None:
                op, width, rd, rn, rm, option, shift = add_ext
                mask = 0xFFFFFFFF if width == "W" else 0xFFFFFFFFFFFFFFFF
                if rn in regs and rm in regs and option in (2, 3, 6, 7) and shift <= 4:
                    extended = _extended_value(regs[rm], option)
                    value = None if extended is None else (extended << shift) & mask
                    if value is None:
                        regs.pop(rd, None)
                    else:
                        _set_reg(regs, rd, ((regs[rn] - value) if op == "SUB" else (regs[rn] + value)) & mask)
                else:
                    regs.pop(rd, None)
                continue

            mem = _memory_decode(word, va, image)
            if mem is not None:
                kind, width, rn, rt_or_rm, offset, post_delta, form, second_reg = mem
                if form == "LITERAL":
                    literal_va = offset
                    value = image.word(literal_va) if width == "W" else image.qword(literal_va)
                    if value is not None:
                        _set_reg(regs, rt_or_rm if rt_or_rm is not None else 0, value)
                    else:
                        if rt_or_rm is not None:
                            regs.pop(rt_or_rm, None)
                        unsupported.add("LITERAL_VALUE_NOT_FILE_BACKED")
                    continue
                if rn is None:
                    regs.clear()
                    unsupported.add("MEMORY_FORM_WITHOUT_REGISTER_BASE")
                    continue
                base = regs.get(rn)
                index = regs.get(rt_or_rm) if form == "REGISTER_OFFSET" and rt_or_rm is not None else None
                is_load = kind.startswith("LDR") or kind == "LDP"
                load_destinations = ({second_reg} if form == "REGISTER_OFFSET" else {rt_or_rm, second_reg}) if is_load else set()
                load_destinations.discard(None)
                base_destination_overlap = is_load and rn in load_destinations
                if base is not None:
                    if form == "REGISTER_OFFSET":
                        # ``offset`` carries the register-offset option and
                        # ``post_delta`` carries the exact S-size shift.
                        transformed = _extended_value(index, offset) if index is not None else None
                        target_addr = None if transformed is None else (base + (transformed << post_delta)) & 0xFFFFFFFFFFFFFFFF
                    elif form in ("POSTINDEX", "PAIR_POSTINDEX"):
                        # Post-index memory uses the old base for the access;
                        # writeback happens only after the load/store.
                        target_addr = base
                    else:
                        target_addr = (base + offset) & 0xFFFFFFFFFFFFFFFF
                    if target_addr is not None:
                        _record_access(
                            accesses,
                            va=va,
                            word=word,
                            kind=kind,
                            width=width,
                            target=target_addr,
                            offset=0 if form == "REGISTER_OFFSET" else offset,
                            base_register=rn,
                            index_register=rt_or_rm if form == "REGISTER_OFFSET" else None,
                            index_option=offset if form == "REGISTER_OFFSET" else None,
                            index_scale=post_delta if form == "REGISTER_OFFSET" else None,
                            source=f"COMPLEMENTARY_{form}",
                        )
                        if kind in ("LDP", "STP"):
                            second = target_addr + (8 if width == "X" else 4)
                            _record_access(accesses, va=va, word=word, kind=kind, width=width, target=second, offset=offset + (8 if width == "X" else 4), base_register=rn, source=f"COMPLEMENTARY_{form}")
                    # LDR/LD* destination is overwritten; stores preserve the
                    # source register.  Pair/atomic forms conservatively kill
                    # the register(s) that may be loaded.
                    if is_load:
                        if form == "REGISTER_OFFSET":
                            regs.pop(second_reg, None)
                        else:
                            regs.pop(rt_or_rm, None)
                            if second_reg is not None:
                                regs.pop(second_reg, None)
                    if post_delta and form in ("POSTINDEX", "PREINDEX", "PAIR_POSTINDEX", "PAIR_PREINDEX"):
                        if base_destination_overlap:
                            # Writeback and a load into the base register are
                            # an overlap whose architectural ordering is not
                            # modeled here; clear the base rather than choose
                            # either the loaded value or writeback value.
                            regs.pop(rn, None)
                        else:
                            _set_reg(regs, rn, (base + post_delta) & 0xFFFFFFFFFFFFFFFF)
                else:
                    if is_load:
                        if form == "REGISTER_OFFSET":
                            regs.pop(second_reg, None)
                        else:
                            regs.pop(rt_or_rm, None)
                            if second_reg is not None:
                                regs.pop(second_reg, None)
                continue

            if _is_zero_or_nop(word):
                continue
            # Unknown instruction or memory form.  It can redefine any tracked
            # register, so clear the map and retain a precise coverage reason.
            unsupported.add("UNRECOGNIZED_AARCH64_INSTRUCTION_OR_MEMORY_FORM")
            regs.clear()

    target_writes = [row for row in accesses if _write_kind(row["kind"])]
    target_reads = [row for row in accesses if not _write_kind(row["kind"])]
    target_values = {row["target"] for row in escapes}
    calls_with_target_arguments = [
        row for row in calls
        if any(argument.get("value") in target_values for argument in row.get("tracked_arguments", []))
    ]
    return {
        "word_count": word_count,
        "excluded_025_word_count": excluded_word_count,
        "scan_scope": "ALL_FILE_BACKED_EXECUTABLE_PT_LOAD_WORDS_EXCLUDING_025_SUPPORTED_RANGES",
        "excluded_ranges": [{"start": fmt(a), "end_exclusive": fmt(b), "label": label} for a, b, label in EXCLUDED_025_RANGES],
        "decoder_coverage": sorted(recognized_word_forms),
        "recognized_direct_accesses": sorted(accesses, key=lambda row: (row["va"], row["kind"], row["target"])),
        "recognized_direct_writes": sorted(target_writes, key=lambda row: (row["va"], row["kind"], row["target"])),
        "recognized_direct_reads": sorted(target_reads, key=lambda row: (row["va"], row["kind"], row["target"])),
        "recognized_pointer_escapes": sorted(escapes, key=lambda row: (row["va"], row["argument"], row["target"])),
        # Keep the public artifact bounded: all direct calls are counted, but
        # only calls carrying tracked arguments (the proof-relevant subset)
        # are expanded.  This preserves exact taint accounting without
        # publishing tens of thousands of unrelated call rows.
        "call_counts": {"direct_bl": sum(row["kind"] == "BL" for row in calls), "indirect_blr_br": sum(row["kind"] in {"BLR", "BR"} for row in calls), "total": len(calls)},
        "recognized_calls": sorted(calls_with_target_arguments, key=lambda row: row["va"]),
        "unsupported_forms": sorted(unsupported | {
            "COMPUTED_RUNTIME_INDEXES_AND_POINTERS",
            "UNRESOLVED_MEMORY_CONTENTS_AND_ALIASES",
            "CONTROL_FLOW_MERGING_AND_LOOP_FIXED_POINTS",
            "UBFM_SBFM_EXTENSIONS_UNSUPPORTED",
            "EXCLUSIVE_AND_LSE_ATOMICS_UNSUPPORTED",
            "LDRSW_AND_PRFM_LITERALS_UNSUPPORTED",
        }),
        "arbitrary_write_absence": "UNKNOWN",
        "writer_absence_claim": False,
    }


def _resolve_adrp_add(image: Image, adrp_va: int, add_va: int) -> int:
    first = adrp_target(_u32(image, adrp_va), adrp_va)
    add = _is_add_sub_imm(_u32(image, add_va))
    if first is None or add is None or add[0] != "ADD" or add[3] != first[1] or add[4] != first[1]:
        raise DispatchError(f"ADRP+ADD pair changed at {fmt(adrp_va)}")
    return (first[0] + add[2]) & 0xFFFFFFFFFFFFFFFF


def analyze_registration_helpers(image: Image) -> dict:
    core_range = range_record(image, REGISTRATION_CORE_START, REGISTRATION_CORE_END, expected_offset=REGISTRATION_OFFSET, expected_hash=REGISTRATION_CORE_SHA256, label="registration helper core")
    full_range = range_record(image, REGISTRATION_START, REGISTRATION_END, expected_offset=REGISTRATION_OFFSET, expected_hash=REGISTRATION_SHA256, label="registration helper enclosure")
    assert_words(
        image,
        {
            0x1482ECC8: 0x321D07E0,
            0x1482ECDC: 0xF9000113,
            0x1482ECE8: 0xB9000808,
            0x1482ED10: 0x97FFFFEA,
            0x1482ED18: 0xF907B100,
            0x1482ED34: 0x2A0103F3,
            0x1482ED38: 0xF947B134,
            0x1482ED44: 0xB9000813,
            0x1482ED54: 0xF8410D14,
            0x1482ED68: 0xF9000100,
            0x1482EDA8: 0xD65F03C0,
        },
    )
    edges = direct_edges(image, REGISTRATION_START, REGISTRATION_END)
    global_head = _resolve_adrp_add(image, 0x1482ED60, 0x1482ED64)
    if global_head != REGISTRATION_HEAD:
        raise DispatchError("registration list-head address changed")
    # The allocator/cell layout is proven only for the exact helper stores;
    # contents and runtime list membership remain runtime-dependent.
    return {
        "ranges": {"requested_core": core_range, "function_enclosure_including_ret": full_range},
        "functions": [
            {"name": "registration_create", "start": fmt(0x1482ECB8), "end_exclusive": fmt(0x1482ED04)},
            {"name": "registration_initialize", "start": fmt(0x1482ED04), "end_exclusive": fmt(0x1482ED24)},
            {"name": "registration_append", "start": fmt(0x1482ED24), "end_exclusive": fmt(0x1482ED78)},
            {"name": "registration_lookup", "start": fmt(0x1482ED78), "end_exclusive": fmt(0x1482EDAC)},
        ],
        "list_head": {
            "address": fmt(global_head),
            "segment_storage": "MEMORY_ONLY_PT_LOAD_ZERO_FILL",
            "segment_index": image.segment_for(global_head, file_backed=False).index if image.segment_for(global_head, file_backed=False) else None,
        },
        "node_layout": {
            "allocation_size": 0x18,
            "object_pointer_offset": 0,
            "service_id_offset": 8,
            "next_pointer_offset": 16,
            "create_store_sites": [
                {"va": fmt(0x1482ECDC), "kind": "STR_X", "target": "new_node+0"},
                {"va": fmt(0x1482ECE8), "kind": "STR_W", "target": "new_node+8"},
                {"va": fmt(0x1482ECEC), "kind": "STR_X_ZERO", "target": "new_node+16"},
            ],
        },
        "global_writes": [
            {"va": fmt(0x1482ED18), "kind": "STR_X", "target": fmt(REGISTRATION_HEAD), "role": "initialize list head"},
            {
                "va": fmt(0x1482ED68),
                "kind": "STR_X",
                "target": fmt(REGISTRATION_HEAD),
                "target_semantics": "global head only on the empty-list branch; otherwise tail_node+0x10 (tail->next)",
                "role": "initialize head or append list tail",
            },
        ],
        "lookup": {
            "entry": fmt(0x1482ED78),
            "compare": {"va": fmt(0x1482ED84), "node_field": 8, "register": "W0"},
            "return_object_load": {"va": fmt(0x1482EDA4), "target": "node+0"},
            "empty_result": "X0=0",
        },
        "edges": edges,
        "status": "PROVED_LOCAL_REGISTRATION_HELPER_SHAPES_ONLY",
        "runtime_status": "UNKNOWN_RUNTIME_LIST_CONTENTS_AND_EXECUTION",
    }


def analyze_table_header(image: Image) -> dict:
    table_range = range_record(image, TABLE_HEADER_START, TABLE_HEADER_END, expected_offset=TABLE_HEADER_OFFSET, expected_hash=TABLE_HEADER_SHA256, label="initializer table header")
    count = _u32(image, TABLE_HEADER_START)
    if count != TABLE_COUNT:
        raise DispatchError("initializer table count changed")
    # The loop's cursor points to row+0x14, and its header counter is the
    # first word.  Two 0x18-byte rows exactly fill the pinned table range.
    if TABLE_ROW_START + count * TABLE_ROW_STRIDE != TABLE_HEADER_END:
        raise DispatchError("initializer table count/stride does not fill the pinned range")
    rows = []
    for index in range(count):
        row = TABLE_ROW_START + index * TABLE_ROW_STRIDE
        rows.append(
            {
                "index": index,
                "start": fmt(row),
                "end_exclusive": fmt(row + TABLE_ROW_STRIDE),
                "kind": _u32(image, row + TABLE_KIND_FIELD_OFFSET),
                "id": _u32(image, row + TABLE_ID_FIELD_OFFSET),
                "id_field": fmt(row + TABLE_ID_FIELD_OFFSET),
                "kind_field": fmt(row + TABLE_KIND_FIELD_OFFSET),
            }
        )
    return {
        "range": table_range,
        "header": {"address": fmt(TABLE_HEADER_START), "count": count, "row_start": fmt(TABLE_ROW_START), "row_stride": TABLE_ROW_STRIDE, "row_stride_hex": fmt(TABLE_ROW_STRIDE), "storage": "FILE_BACKED_RW_PT_LOAD"},
        "cursor": {"initial": fmt(TABLE_ROW_START + TABLE_ID_FIELD_OFFSET), "kind_offset_from_cursor": -4, "id_offset_from_cursor": 0, "advance": TABLE_ROW_STRIDE, "loop_index_register": "X28", "back_edge": fmt(0x1482EE04)},
        "rows": rows,
        "status": "PROVED_TABLE_COUNT_STRIDE_AND_CURSOR_BEHAVIOR",
        "runtime_status": "UNKNOWN_RUNTIME_LOOP_EXECUTION_ORDER",
    }


def analyze_initializer_loop(image: Image, table: dict) -> dict:
    loop_range = range_record(image, INITIALIZER_START, INITIALIZER_END, expected_offset=INITIALIZER_OFFSET, expected_hash=INITIALIZER_SHA256, label="initializer loop")
    assert_words(
        image,
        {
            0x1482EDAC: 0xD102C3FF,
            0x1482EDCC: 0xF0000228,
            0x1482EDE0: 0xAA1F03FC,
            0x1482EE20: 0xB94F5A89,
            0x1482EE34: 0x97FFFFBC,
            0x1482EE48: 0x97FFFE5D,
            0x1482EF28: 0x97FFFF7F,
            0x1482F068: 0x97FFFF2F,
            0x1482F078: 0x91006273,
            0x1482F080: 0xEB09039F,
            0x1482F084: 0x54FFEC0B,
            0x1482F0B0: 0xD65F03C0,
        },
    )
    table_row_cursor = _resolve_adrp_add(image, 0x1482EDCC, 0x1482EDD4) + 0x14
    if table_row_cursor != TABLE_ROW_START + TABLE_ID_FIELD_OFFSET:
        raise DispatchError("initializer table cursor materialization changed")
    state_page = adrp_target(_u32(image, 0x1482EDEC), 0x1482EDEC)
    state_load = is_mem_unsigned(_u32(image, 0x1482EE20))
    if state_page is None or state_load is None or state_load[0] != "LDR" or state_load[3] != state_page[1]:
        raise DispatchError("bootstrap state load materialization changed")
    state = state_page[0] + state_load[2]
    if state != BOOTSTRAP_STATE_B:
        raise DispatchError("bootstrap state address materialization changed")
    # x25 is page 0x14875000 and the ldrsw immediate is 0x534; verify the
    # exact final instruction separately because it is far beyond the pair.
    if _u32(image, 0x1482F07C) != 0xB9853729 or _u32(image, 0x1482F080) != 0xEB09039F:
        raise DispatchError("initializer header load changed")
    header_va = 0x14875534
    if _u32(image, header_va) != TABLE_COUNT:
        raise DispatchError("initializer count header changed")
    call_targets = direct_edges(image, INITIALIZER_START, INITIALIZER_END)["direct_bl"]
    registration_calls = [row for row in call_targets if int(row["target"], 16) == 0x1482ED24]
    if [row["va"] for row in registration_calls] != [fmt(0x1482EE34), fmt(0x1482EF28), fmt(0x1482F068)]:
        raise DispatchError("initializer registration helper call sites changed")
    wrapper_calls = [row for row in call_targets if int(row["target"], 16) == 0x1482E7BC]
    if [row["va"] for row in wrapper_calls] != [fmt(0x1482EE48)]:
        raise DispatchError("initializer wrapper edge changed")
    return {
        "range": loop_range,
        "table_dependency": table["header"],
        "table_cursor": {"va": fmt(0x1482EDD4), "materialized": fmt(table_row_cursor), "row_stride": TABLE_ROW_STRIDE, "advance_va": fmt(0x1482F078), "advance_word": fmt(_u32(image, 0x1482F078))},
        "loop": {"index_register": "X28", "initial_index": 0, "count_load": {"va": fmt(0x1482F07C), "address": fmt(header_va), "word": fmt(_u32(image, 0x1482F07C))}, "back_edge": {"va": fmt(0x1482F084), "target": fmt(0x1482EE04), "word": fmt(_u32(image, 0x1482F084))}},
        "bootstrap_state": {"address": fmt(state), "load_sites": [{"va": fmt(0x1482EE20), "word": fmt(_u32(image, 0x1482EE20)), "offset": 0xF58}]},
        "registration_helper_calls": registration_calls,
        "dependency_wrapper_calls": wrapper_calls,
        "local_data_edges": [
            {"from": fmt(0x1482EF18), "kind": "STP", "to": fmt(REGISTRATION_GLOBALS_START + 0x18), "note": "adjacent global base at 0x14890f68; outside the bounded globals target interval"},
            {"from": fmt(0x1482F034), "kind": "STR", "to": "runtime-derived entry pointer", "note": "not a fixed target; no global write absence claim"},
        ],
        "edges": direct_edges(image, INITIALIZER_START, INITIALIZER_END),
        "status": "PROVED_LOCAL_INITIALIZER_LOOP_AND_DATA_EDGES",
        "runtime_status": "UNKNOWN_RUNTIME_EXECUTION_AND_RELATIVE_BOOT_ORDER",
    }


def analyze_bootstrap_caller(image: Image) -> dict:
    result = range_record(image, BOOTSTRAP_CALLER_START, BOOTSTRAP_CALLER_END, expected_offset=BOOTSTRAP_CALLER_OFFSET, expected_hash=BOOTSTRAP_CALLER_SHA256, label="bootstrap caller")
    assert_words(image, {0x14852D18: 0x97FF6EB1, 0x14852D28: 0x97FF6CF1, 0x14852D44: 0x97FF6D6E, 0x14852D6C: 0xD65F03C0})
    edges = direct_edges(image, BOOTSTRAP_CALLER_START, BOOTSTRAP_CALLER_END)
    return {
        "range": result,
        "edges": edges,
        "static_calls": [
            {"va": fmt(0x14852D18), "target": fmt(0x1482E7DC), "role": "dependency_wrapper_entry"},
            {"va": fmt(0x14852D28), "target": fmt(0x1482E0EC), "role": "bootstrap_local_helper"},
            {"va": fmt(0x14852D44), "target": fmt(0x1482E2FC), "role": "bootstrap_local_helper"},
        ],
        "guard": {"address": fmt(0x1488F700), "load_va": fmt(0x14852D04), "condition": "CBZ W17", "runtime_value": "UNKNOWN"},
        "status": "PROVED_BOOTSTRAP_CALLER_LOCAL_EDGES",
        "runtime_status": "UNKNOWN_EXECUTION_AND_BOOT_ORDER",
    }


def analyze_veneer(image: Image) -> dict:
    result = range_record(image, VENEER_START, VENEER_END, expected_offset=VENEER_OFFSET, expected_hash=VENEER_SHA256, label="dispatch veneer")
    edges = direct_edges(image, VENEER_START, VENEER_END)
    if len(edges["branches"]) != 12:
        raise DispatchError("dispatch veneer branch count changed")
    return {"range": result, "branch_table": edges["branches"], "edges": edges, "status": "PROVED_LOCAL_VENEER_BRANCH_TARGETS", "runtime_status": "UNKNOWN_VENEER_SELECTION_AND_EXECUTION"}


def analyze_alternates(image: Image) -> dict:
    one = range_record(image, ALTERNATE_ONE_START, ALTERNATE_ONE_END, expected_offset=ALTERNATE_ONE_OFFSET, expected_hash=ALTERNATE_ONE_SHA256, label="alternate path one")
    two = range_record(image, ALTERNATE_TWO_START, ALTERNATE_TWO_END, expected_offset=ALTERNATE_TWO_OFFSET, expected_hash=ALTERNATE_TWO_SHA256, label="alternate path two")
    assert_words(image, {0x1482834C: 0x94006E7C, 0x14828354: 0x94006E74, 0x14828B68: 0x94001891, 0x14828BAC: 0xD63F0100, 0x14828BE8: 0xD63F0180, 0x14828C30: 0xD63F0120})
    one_edges = direct_edges(image, ALTERNATE_ONE_START, ALTERNATE_ONE_END)
    two_edges = direct_edges(image, ALTERNATE_TWO_START, ALTERNATE_TWO_END)
    init_calls = [row for row in two_edges["direct_bl"] if int(row["target"], 16) == INITIALIZER_START]
    if [row["va"] for row in init_calls] != [fmt(0x14828B68)]:
        raise DispatchError("alternate initializer edge changed")
    return {
        "alternate_one": {"range": one, "edges": one_edges, "state_pointer": {"va": fmt(0x1482835C), "target": fmt(0x14872438), "storage": "FILE_BACKED_RW_PT_LOAD"}},
        "alternate_two": {"range": two, "edges": two_edges, "initializer_call": init_calls, "indirect_dispatches": two_edges["indirect"]},
        "status": "PROVED_LOCAL_ALTERNATE_EDGES_WITH_UNRESOLVED_INDIRECTS",
        "runtime_status": "UNKNOWN_ALTERNATE_SELECTION_AND_ORDER",
    }


def analyze_pool(image: Image) -> dict:
    segment = image.segment_for(DISPATCHER_POOL_START, file_backed=False)
    if segment is None or segment.index != POOL_SEGMENT_INDEX or segment.file_size != 0 or segment.vaddr != POOL_SEGMENT_VADDR or segment.mem_size != POOL_SEGMENT_MEM_SIZE:
        raise DispatchError("initializer pool memory-only PT_LOAD mapping changed")
    if not (segment.vaddr <= DISPATCHER_POOL_START and DISPATCHER_POOL_END <= segment.vaddr + segment.mem_size):
        raise DispatchError("initializer pool exceeds memory-only segment")
    if image.file_offset(DISPATCHER_POOL_START) is not None:
        raise DispatchError("initializer pool unexpectedly became file-backed")
    return {
        "range": {"start": fmt(DISPATCHER_POOL_START), "end_exclusive": fmt(DISPATCHER_POOL_END), "size": DISPATCHER_POOL_END - DISPATCHER_POOL_START, "file_offset": "NOT_FILE_BACKED", "sha256": "NOT_FILE_BACKED"},
        "storage": {"segment_index": segment.index, "segment_vaddr": fmt(segment.vaddr), "segment_mem_size": segment.mem_size, "file_size": segment.file_size, "kind": segment.kind},
        "rows": {"count": DISPATCHER_POOL_ROWS, "row_stride": DISPATCHER_POOL_STRIDE, "row_stride_hex": fmt(DISPATCHER_POOL_STRIDE), "index_source": "dispatcher X8 = LDRB [X19,#9]", "index_range_guard": "0..1 via CMP X8,#1; B.LS"},
        "contents": "UNKNOWN_MEMORY_ONLY_INITIALIZER_BYTES",
        "status": "SUPPORTED_MEMORY_ONLY_POOL_SHAPE",
    }


def analyze_dispatcher(image: Image, pool: dict) -> dict:
    result = range_record(image, DISPATCHER_START, DISPATCHER_END, expected_offset=DISPATCHER_OFFSET, expected_hash=DISPATCHER_SHA256, label="main dispatcher")
    assert_words(image, {0x1486484C: 0x39402668, 0x14864850: 0xF100051F, 0x14864864: 0xF0FFF26A, 0x14864868: 0x9103014A, 0x1486486C: 0x9B092914, 0x14864874: 0x38401EA8, 0x14864890: 0x97FF5FAB, 0x148648A0: 0x94000EDE, 0x148648AC: 0xF9000274, 0x148648BC: 0xD65F03C0})
    pool_base = _resolve_adrp_add(image, 0x14864864, 0x14864868)
    if pool_base != DISPATCHER_POOL_START:
        raise DispatchError("dispatcher pool base changed")
    edges = direct_edges(image, DISPATCHER_START, DISPATCHER_END)
    init_calls = [row for row in edges["direct_bl"] if int(row["target"], 16) == 0x14868418]
    if [row["va"] for row in init_calls] != [fmt(0x148648A0)]:
        raise DispatchError("dispatcher initializer call edge changed")
    return {
        "range": result,
        "pool": {"range": pool["range"], "base": fmt(pool_base), "stride": DISPATCHER_POOL_STRIDE, "index": {"register": "W8", "source_va": fmt(0x1486484C), "source": "LDRB W8,[X19,#9]", "guard_va": fmt(0x14864850), "guard": "CMP X8,#1; B.LS"}, "rows": DISPATCHER_POOL_ROWS},
        "local_data_edges": [
            {"va": fmt(0x14864890), "kind": "BL_ARGUMENT_X0", "target": f"{fmt(pool_base)} + X8*{fmt(DISPATCHER_POOL_STRIDE)}", "target_base": fmt(pool_base), "index_register": "X8", "argument": "X0=X20 row pointer", "callee": fmt(0x1483C73C), "status": "PROVED_SYMBOLIC_POINTER_ESCAPE"},
            {"va": fmt(0x148648AC), "kind": "STR_X", "target": "context[X19]+0", "value": "X20 row pointer", "status": "PROVED_LOCAL_STORE"},
            {"va": fmt(0x1486489C), "kind": "STRB", "target": "pool row byte 0", "value": "context byte #9"},
            {"va": fmt(0x148648A8), "kind": "STRB", "target": "pool row byte 1 after pre-index", "value": "1"},
        ],
        "initializer_call": init_calls[0],
        "edges": edges,
        "status": "PROVED_DISPATCHER_POOL_INDEX_AND_LOCAL_POINTER_ESCAPE",
        "runtime_status": "UNKNOWN_DISPATCH_EXECUTION_POOL_CONTENTS_AND_ORDER",
    }


def analyze_callers(image: Image) -> dict:
    rows = []
    for name, start, end, digest, offset in CALLER_RANGES:
        record = range_record(image, start, end, expected_offset=offset, expected_hash=digest, label=name)
        edges = direct_edges(image, start, end)
        rows.append({"name": name, "range": record, "edges": edges})
    return {
        "ranges": rows,
        "chain": [
            {"from": fmt(0x1485A2F4), "to": fmt(0x148641A4), "kind": "BL", "status": "PROVED"},
            {"from": fmt(0x148641C8), "to": fmt(0x1486420C), "kind": "BL", "status": "PROVED"},
            {"from": fmt(0x1486421C), "to": fmt(0x14864834), "kind": "BL", "status": "PROVED"},
            {"from": fmt(0x1486430C), "to": fmt(0x1486420C), "kind": "BL", "status": "PROVED"},
        ],
        "status": "PROVED_LOCAL_CALLER_AND_DISPATCH_EDGES",
        "runtime_status": "UNKNOWN_CALLER_SELECTION_AND_BOOT_ORDER",
    }


def analyze_dependency(path: Path = DEPENDENCY_PATH) -> dict:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise DispatchError(f"cannot read Experiment 025 dependency: {exc}") from exc
    if len(data) != DEPENDENCY_SIZE or sha256(data) != DEPENDENCY_SHA256:
        raise DispatchError("Experiment 025 dependency size/hash mismatch")
    try:
        prior = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DispatchError("Experiment 025 dependency is not valid JSON") from exc
    if prior.get("experiment_id") != "025-xbl-platform-query-binding" or prior.get("classification") != "CLASS C (TRANSFORM ONLY)":
        raise DispatchError("Experiment 025 identity/classification changed")
    order = prior.get("order_and_authority")
    platform = prior.get("platform_query")
    base = prior.get("base_audit")
    if not isinstance(order, dict) or order.get("boot_order") != "UNKNOWN" or order.get("status") != "UNKNOWN_RUNTIME_ORDER_AND_GLOBAL_ALIAS":
        raise DispatchError("Experiment 025 runtime order is no longer UNKNOWN")
    if not isinstance(platform, dict) or platform.get("runtime_slot", {}).get("address") != fmt(RUNTIME_SLOT):
        raise DispatchError("Experiment 025 runtime-slot semantic pin changed")
    unresolved = platform.get("helper_arguments", {}).get("indirect_call", {})
    if unresolved.get("va") != fmt(0x1486AC1C) or unresolved.get("target") != "UNKNOWN_UNTIL_RUNTIME_OBJECT_BINDING":
        raise DispatchError("Experiment 025 BLR semantic pin changed")
    if not isinstance(base, dict) or base.get("full_base_preservation") != "UNKNOWN":
        raise DispatchError("Experiment 025 base currentness is no longer UNKNOWN")
    unknown = prior.get("claims", {}).get("UNKNOWN", [])
    if not any("runtime" in str(claim).lower() and "slot" in str(claim).lower() for claim in unknown):
        raise DispatchError("Experiment 025 UNKNOWN claims do not preserve runtime slot boundary")
    return {
        "filename": DEPENDENCY_NAME,
        "size": len(data),
        "sha256": DEPENDENCY_SHA256,
        "experiment_id": prior["experiment_id"],
        "classification": prior["classification"],
        "runtime_order": order["boot_order"],
        "runtime_slot": platform["runtime_slot"]["address"],
        "blr": {"va": unresolved["va"], "target": unresolved["target"]},
        "base_currentness": base["full_base_preservation"],
        "validation": "SEMANTIC_CLASS_C_ORDER_SLOT_BLR_BASE_UNKNOWN",
    }


def derive_order_taxonomy(initializer: dict, bootstrap: dict, alternates: dict, dispatcher: dict, callers: dict) -> dict:
    """Derive ORDER_OPEN from explicit unresolved closure conditions."""
    reasons: list[str] = []
    if initializer.get("runtime_status") != "PROVED_RUNTIME_ORDER":
        reasons.append("initializer loop execution and relative order are not observed")
    if bootstrap.get("runtime_status") != "PROVED_RUNTIME_ORDER":
        reasons.append("bootstrap caller execution/selection is unresolved")
    if alternates.get("runtime_status") != "PROVED_RUNTIME_ORDER":
        reasons.append("alternate paths and indirect dispatch selection are unresolved")
    if dispatcher.get("runtime_status") != "PROVED_RUNTIME_ORDER":
        reasons.append("dispatcher execution and pool contents are unresolved")
    if callers.get("runtime_status") != "PROVED_RUNTIME_ORDER":
        reasons.append("caller selection and a common runtime root are unresolved")
    # There is intentionally no static-only path to ORDER_CLOSED_STATIC in this
    # experiment: closure requires runtime execution/relative-order evidence.
    status = "ORDER_CLOSED_STATIC" if not reasons else "ORDER_OPEN"
    return {"status": status, "closure": not reasons, "reasons": reasons}


def load_xbl(firmware_dir: Path = FIRMWARE_DIR) -> bytes:
    path = firmware_dir / XBL_NAME
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise DispatchError(f"cannot read exact XBL input: {exc}") from exc
    if len(data) != XBL_SIZE or sha256(data) != XBL_SHA256:
        raise DispatchError("exact XBL size/SHA-256 pin mismatch")
    return data


def _elf_summary(image: Image) -> dict:
    return {
        "format": "ELF64_LITTLE_AARCH64",
        "pt_load_count": len(image.segments),
        "file_backed_pt_load_count": len(image.file_backed()),
        "file_backed_executable_pt_load_count": len(image.executable()),
        "pt_loads": [
            {"segment_index": s.index, "file_offset": fmt_offset(s.file_offset), "vaddr": fmt(s.vaddr), "file_size": s.file_size, "mem_size": s.mem_size, "flags": s.flags, "kind": s.kind}
            for s in image.segments
        ],
        "scan_scope": "ALL_FILE_BACKED_EXECUTABLE_PT_LOAD_WORDS",
        "memory_only_pool_segment": {"segment_index": POOL_SEGMENT_INDEX, "vaddr": fmt(POOL_SEGMENT_VADDR), "mem_size": POOL_SEGMENT_MEM_SIZE, "file_size": 0},
    }


def definition_of_done_metadata(dependency: dict) -> dict:
    na = "NOT_APPLICABLE: host-only static analysis; no live device observation or device artifact was used"
    return {
        "date": "2026-08-26",
        "target": {"marketing_name": "A90 5G", "model": "SM-A908N", "soc": "SM8150", "soc_name": "Snapdragon 855", "binding": "PROVED_EXACT_FIRMWARE_INPUT_HASH"},
        "firmware": {"filename": XBL_NAME, "size": XBL_SIZE, "sha256": XBL_SHA256, "build": "UNKNOWN", "binding": "PROVED_EXACT_XBL_SIZE_AND_SHA256", "build_reason": "No firmware build identifier is derived by this bounded decoder."},
        "precondition": {"status": "PROVED", "device_access": "none", "firmware_sha256": XBL_SHA256, "dependency_sha256": DEPENDENCY_SHA256, "exact": "Use only the exact SM-A908N/A90 5G SM8150 XBL input and semantically validated Experiment 025 dependency; perform no device action."},
        "result": {"classification": "CLASS C (TRANSFORM ONLY)", "status": "ORDER_OPEN_STATIC_SLOT_CENSUS_BOUNDED", "proved": "Exact dispatch/order ranges, table count/stride, local data/control edges, and conservative complementary target census are pinned.", "supported": "Recognized direct forms provide a bounded slot/global/escape census; recognized absence is bounded and never global.", "unknown": "Runtime execution/order, runtime slot/object identity, BLR targets, memory-only contents, unsupported/computed aliases, and current base authority remain UNKNOWN."},
        "reproducible_command_template": "python3 tools/sm8150_xbl_dispatch_order_slot_escape.py --firmware-dir <exact-firmware-dir> --output <public-manifest-path>",
        "negative_controls": {"status": "PASS", "description": "Exact image/range/word/dependency mutations, unsupported address forms, semantic dependency mutations, and no-clobber publication fail closed before output."},
        "non_applicable_artifacts": {name: {"sha256": "NOT_APPLICABLE", "reason": na} for name in ("boot", "dtb", "kernel", "research_kernel")},
        "timestamp": {"value": "NOT_APPLICABLE", "reason": "Deterministic host-only publication intentionally does not embed a wall-clock timestamp."},
        "live_repetitions": {"status": "NOT_APPLICABLE", "reason": "No live device execution or observation is part of this host-only static experiment."},
        "dmesg": {"status": "NOT_APPLICABLE", "reason": na},
        "log": {"status": "NOT_APPLICABLE", "reason": na},
        "rollback": {"status": "NOT_APPLICABLE", "reason": "No device or persistent state was changed; there is no effect to roll back."},
        "recovery": {"status": "NOT_APPLICABLE", "reason": "No device, boot, transport, or runtime state was touched."},
        "tool_and_build": {"tool": f"sm8150_xbl_dispatch_order_slot_escape.py schema v1", "build": "NOT_APPLICABLE", "build_reason": "The host-only analyzer is interpreted Python source and has no firmware/kernel build output."},
        "deterministic_repetition_validation": {"repetition_count": 2, "repetition_unit": "fresh host manifest generations", "repetition_result": "BYTE_IDENTICAL", "focused_test_count": 25, "validation_count": 5, "validation_checks": ["exact firmware size/SHA-256 binding", "Experiment 025 size/SHA-256 plus semantic Class C/order/slot/BLR/base validation", "exact range/word/control/data edge and conservative decoder checks", "focused synthetic and exact-image test suite", "public JSON, publication mode, safety scan, and fresh-generation byte comparison"]},
    }


def build_manifest(firmware_dir: Path = FIRMWARE_DIR, dependency_path: Path = DEPENDENCY_PATH) -> dict:
    dependency = analyze_dependency(dependency_path)
    image = Image(load_xbl(firmware_dir))
    table = analyze_table_header(image)
    registration = analyze_registration_helpers(image)
    initializer = analyze_initializer_loop(image, table)
    bootstrap = analyze_bootstrap_caller(image)
    veneer = analyze_veneer(image)
    alternates = analyze_alternates(image)
    pool = analyze_pool(image)
    dispatcher = analyze_dispatcher(image, pool)
    callers = analyze_callers(image)
    census = decode_materialised_addresses(image)
    slot_writes = [row for row in census["recognized_direct_writes"] if row["target_class"] == "RUNTIME_SLOT_0x14890590"]
    slot_status = "SLOT_MUTATION_FOUND" if slot_writes else "PROVED_BOUNDED_NO_RECOGNIZED_SLOT_MUTATION"
    order = derive_order_taxonomy(initializer, bootstrap, alternates, dispatcher, callers)
    ranges = {
        "registration_helpers": registration["ranges"]["function_enclosure_including_ret"],
        "registration_helpers_core": registration["ranges"]["requested_core"],
        "initializer_loop": initializer["range"],
        "table_header": table["range"],
        "bootstrap_caller": bootstrap["range"],
        "veneer": veneer["range"],
        "alternate_one": alternates["alternate_one"]["range"],
        "alternate_two": alternates["alternate_two"]["range"],
        "main_dispatcher": dispatcher["range"],
        "callers": {row["name"]: row["range"] for row in callers["ranges"]},
        "memory_only_initializer_pool": pool["range"],
    }
    claims = {
        "PROVED": [
            "Exact XBL and Experiment 025 dependency size/SHA-256 pins are validated.",
            "Registration helper local node layout, list-head access, and direct helper control edges are pinned.",
            "Initializer table count=2, row stride=0x18, cursor field offsets, local loop edges, and registration helper calls are pinned.",
            "Main dispatcher derives the memory-only pool base 0x146b30c0, stride 0x3f8, byte-index guard 0..1, and a local row-pointer escape to a direct BL argument.",
            "Exact bootstrap, veneer, alternate, dispatcher, and caller ranges/control edges are pinned independently of Experiment 025 ranges.",
        ],
        "SUPPORTED": [
            "The complementary census recognizes only concrete address forms across file-backed executable PT_LOAD words and explicitly excludes Experiment 025-supported direct idioms.",
            "The memory-only initializer pool has two rows of 0x3f8 bytes by exact range geometry; its bytes and runtime values are not file-backed.",
        ],
        "HYPOTHESIS": [],
        "REFUTED": [],
        "UNKNOWN": [
            "Runtime registration execution, relative boot order, caller/path selection, and runtime slot/object identity remain UNKNOWN.",
            "BLR/BR targets, memory-only pool/bootstrap state contents, computed indexes/pointers, aliases, unsupported instruction forms, and writer absence remain UNKNOWN.",
            "Experiment 025 current-base authority and full preservation remain UNKNOWN and are not upgraded by this experiment.",
        ],
    }
    return {
        "schema": SCHEMA,
        "experiment_id": "026-xbl-dispatch-order-slot-escape",
        "mode": "HOST_ONLY_READ_ONLY",
        "device_access": "none",
        "classification": "CLASS C (TRANSFORM ONLY)",
        "boundary_bypass": "NO_BOUNDARY_BYPASS_OBSERVED",
        "inputs": {"firmware": {"filename": XBL_NAME, "size": XBL_SIZE, "sha256": XBL_SHA256}, "experiment_025_dependency": dependency},
        "dependencies": {"experiment_025": dependency},
        "elf": _elf_summary(image),
        "ranges": ranges,
        "registration_helpers": registration,
        "initializer_table": table,
        "initializer_loop": initializer,
        "bootstrap_caller": bootstrap,
        "veneer": veneer,
        "alternates": alternates,
        "dispatcher": dispatcher,
        "callers": callers,
        "initializer_pool": pool,
        "complementary_census": census,
        "slot_escape": {"taxonomy": slot_status, "recognized_runtime_slot_writes": slot_writes, "runtime_slot": fmt(RUNTIME_SLOT), "registry": {"start": fmt(REGISTRY_START), "end_exclusive": fmt(REGISTRY_END)}, "registration_globals": {"start": fmt(REGISTRATION_GLOBALS_START), "end_exclusive": fmt(REGISTRATION_GLOBALS_END)}, "factory_object": {"start": fmt(FACTORY_OBJECT_START), "end_exclusive": fmt(FACTORY_OBJECT_END)}, "bootstrap_state_windows": [{"start": fmt(BOOTSTRAP_STATE_A), "end_exclusive": fmt(BOOTSTRAP_STATE_A + 0x10)}, {"start": fmt(BOOTSTRAP_STATE_B), "end_exclusive": fmt(BOOTSTRAP_STATE_B + 0x10)}], "writer_absence": "UNKNOWN"},
        "order_and_authority": {"taxonomy": order["status"], "closure": order["closure"], "closure_reasons": order["reasons"], "static_order_status": "PROVED_LOCAL_EDGES_ONLY", "runtime_order": "UNKNOWN", "runtime_slot": "UNKNOWN", "runtime_blr": "UNKNOWN", "base_currentness": "UNKNOWN", "reason": "Static local/control/data edges do not close runtime execution or relative boot order."},
        "claims": claims,
        "eligibility": {"class": "C", "device_action": "NONE", "experiments_015_016": "NOT_ELIGIBLE"},
        "definition_of_done": definition_of_done_metadata(dependency),
    }


def dependency_audit(path: Path = DEPENDENCY_PATH) -> dict:
    """Compatibility spelling for the semantic Experiment 025 audit."""
    return analyze_dependency(path)


def analyze_census(image: Image) -> dict:
    """Return the complementary census under the short reviewer name."""
    return decode_materialised_addresses(image)


def analyze_dispatch(image: Image, pool: dict | None = None) -> dict:
    """Analyze the new dispatcher, deriving the memory-only pool when needed."""
    return analyze_dispatcher(image, analyze_pool(image) if pool is None else pool)


def analyze_order(initializer: dict, bootstrap: dict, alternates: dict, dispatcher: dict, callers: dict) -> dict:
    """Expose explicit ORDER_OPEN closure derivation for reviewers/tests."""
    return derive_order_taxonomy(initializer, bootstrap, alternates, dispatcher, callers)


def write_no_clobber(path: Path, data: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = None
    try:
        fd = os.open(path, flags, mode)
        os.fchmod(fd, mode)
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short manifest write")
            view = view[written:]
    except FileExistsError as exc:
        raise DispatchError(f"refusing to clobber existing output: {path}") from exc
    except OSError as exc:
        raise DispatchError(f"manifest publication failed: {exc}") from exc
    finally:
        if fd is not None:
            os.close(fd)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--firmware-dir", type=Path, default=FIRMWARE_DIR)
    parser.add_argument("--dependency", type=Path, default=DEPENDENCY_PATH)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    manifest = build_manifest(args.firmware_dir, args.dependency)
    payload = (json.dumps(manifest, indent=1, sort_keys=True) + "\n").encode("utf-8")
    write_no_clobber(args.output, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
