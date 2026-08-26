#!/usr/bin/env python3
"""Host-only Experiment 027: bounded DCB consumer/writer complement.

This module deliberately works on a *dependency supplied* set of 67
register-offset loop sites and eight computed-address idioms.  It does not
search arbitrary addresses, execute firmware, contact a device, or infer a
writer-absence result.  The static decoder is an under-approximation: any
instruction or control-flow form which is not explicitly implemented clears
the relevant origin and, when it is required for a positive path, produces
``INDIRECT_OR_UNSUPPORTED``.

The public result is a transform-only evidence record.  A symbolic
``BASE+offset`` is intentionally never reported as a current destination.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


REPO_ROOT = Path(__file__).resolve().parent.parent
FIRMWARE_DIR = REPO_ROOT / "evidence/private/004-live-firmware-readonly-20260825-01"
MANIFEST_DIR = REPO_ROOT / "evidence/manifests"

SCHEMA = "sm8150-dcb-consumer-writer-complement-v1"
EXPERIMENT_ID = "027-dcb-consumer-writer-complement"
MODE = "HOST_ONLY_READ_ONLY"

XBL_NAME = "xbl--sdb1.bin"
XBL_SIZE = 4_194_304
XBL_SHA256 = "e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37"
DCB_NAME = "xbl_config--sdb2.bin"
DCB_SIZE = 4_149_248
DCB_SHA256 = "0e9dfac1ddd0f9acc2cc899213e621490308f0cadf329814048edb7712e2484c"

DEPENDENCY_SPECS: dict[str, tuple[int, str]] = {
    "019-dcb-register-programming-20260826-01.manifest.json": (
        40_368,
        "232eb0375fadf96db1fd303d83d707cf47cb668a24129d7e4791b193fb3fc70c",
    ),
    "020-xbl-dcb-consumer-xref-20260826-01.manifest.json": (
        23_446,
        "31e8dd6791f07d007447600969326a86466f20a0cb263a58885c1489bd284c9a",
    ),
    "021-dcb-delivery-paths-20260826-01.manifest.json": (
        8_130,
        "d85999e644bae1f5bafe683b44b253450d04d1b666c73659d9284c010d32b44a",
    ),
    "024-xbl-six-byte-walker-20260826-01.manifest.json": (
        30_400,
        "f9ac896d396650075ca9e66d8d805a2deaf40b0207e819cd94f8d638c8121b01",
    ),
    "025-xbl-platform-query-binding-20260826-01.manifest.json": (
        28_132,
        "d3c405d7c8d23dc1cd65b1c578b4b4ce931d9bdfeb303c892e9c0c145c4c81cc",
    ),
    "026-xbl-dispatch-order-slot-escape-20260826-01.manifest.json": (
        64_027,
        "2139b5d230be78d822eda656f2856a229894167938227d34a614dcabf16c7885",
    ),
}

FALSE_NEGATIVE_START = 0x148689C8
FALSE_NEGATIVE_END = 0x14868A60
WALKER_START = 0x148689A0
WALKER_END = 0x14868A64
# Experiment 024's argument-flow windows are complete caller-context
# exclusions.  They are deliberately kept separate from the walker and from
# the narrower 020 false-negative range: a future site which overlaps one of
# these windows must fail closed rather than silently inherit walker taint.
WALKER_CALLER_CONTEXT_RANGES = (
    (0x14868630, 0x14868644),
    (0x14868668, 0x14868680),
    (0x14868684, 0x1486869C),
)

SETTER_START = 0x9FC06410
SETTER_END = 0x9FC0643C
SETTER_SHA256 = "4f90392f2e5c34415ad0bb4709227445f3cad1d2444b57a90fa645f1488e063a"
SETTER_CALLER = 0x9FC023F0
SETTER_CALLER_RANGE = (0x9FC023E0, 0x9FC02430)

DCB_SECTIONS = (6, 7, 8, 10, 11, 12)
DCB_SECTION7_KEYS = (0x400, 0x404)
DCB_SECTION7_VALUE = 0x10000000
DCB_BLOCK_FILE_OFFSETS = (0x1079C, 0x13BA0, 0x16FA4, 0x1A3A8)
SECTION_READER_PROXIMITY_THRESHOLD = 0x1000

# The 020 target aperture is a syntactic address domain only.  It is not a
# claim that every address in the range is an accessible MMIO destination.
MC_APERTURE_START = 0x09000000
MC_APERTURE_END = 0x0A000000
RANKED_MC_BASES = (0x09260000, 0x092E0000, 0x09360000, 0x093E0000)
RANKED_MC_OFFSETS = (0x400, 0x404, 0x4D0)

RET_WORD = 0xD65F03C0


class ComplementError(ValueError):
    """Raised for a malformed, mismatched, or semantically unsafe input."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fmt(value: int) -> str:
    return f"0x{value:08x}"


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
        return {5: "RX", 6: "RW", 7: "RWE"}.get(self.flags, f"F{self.flags}")


class Image:
    """Independent ELF64 PT_LOAD view used by this experiment."""

    def __init__(self, data: bytes):
        if len(data) < 64 or data[:4] != b"\x7fELF" or data[4:6] != b"\x02\x01":
            raise ComplementError("not a little-endian ELF64 image")
        if data[6] != 1:
            raise ComplementError("unsupported ELF version")
        ph_offset = struct.unpack_from("<Q", data, 32)[0]
        ph_entry = struct.unpack_from("<H", data, 54)[0]
        ph_count = struct.unpack_from("<H", data, 56)[0]
        if ph_entry < 56 or ph_count > 4096:
            raise ComplementError("invalid program-header shape")
        if ph_offset > len(data) or ph_offset + ph_entry * ph_count > len(data):
            raise ComplementError("program headers exceed image")
        self.data = data
        self.segments: list[Segment] = []
        for index in range(ph_count):
            offset = ph_offset + index * ph_entry
            p_type, flags, file_offset, vaddr, _pa, file_size, mem_size, _al = struct.unpack_from(
                "<IIQQQQQQ", data, offset
            )
            if p_type != 1:
                continue
            if file_offset > len(data) or file_offset + file_size > len(data):
                raise ComplementError(f"PT_LOAD {index} exceeds image")
            if mem_size < file_size:
                raise ComplementError(f"PT_LOAD {index} has memsz smaller than filesz")
            self.segments.append(Segment(index, file_offset, vaddr, file_size, mem_size, flags))

    def segment_for(self, vaddr: int, *, file_backed: bool = True) -> Segment | None:
        matches = [
            segment
            for segment in self.segments
            if segment.vaddr <= vaddr < segment.vaddr + (segment.file_size if file_backed else segment.mem_size)
            and (not file_backed or segment.file_size)
        ]
        if len(matches) > 1:
            raise ComplementError(f"ambiguous PT_LOAD mapping at {fmt(vaddr)}")
        return matches[0] if matches else None

    def file_offset(self, vaddr: int) -> int | None:
        segment = self.segment_for(vaddr)
        return None if segment is None else segment.file_offset + vaddr - segment.vaddr

    def word(self, vaddr: int) -> int | None:
        offset = self.file_offset(vaddr)
        if offset is None or offset % 4 or offset + 4 > len(self.data):
            return None
        return struct.unpack_from("<I", self.data, offset)[0]

    def qword(self, vaddr: int) -> int | None:
        offset = self.file_offset(vaddr)
        if offset is None or offset + 8 > len(self.data):
            return None
        return struct.unpack_from("<Q", self.data, offset)[0]

    def slice(self, start: int, end: int) -> bytes:
        if end <= start:
            raise ComplementError("empty or reversed range")
        first = self.file_offset(start)
        last = self.file_offset(end - 1)
        if first is None or last is None or last + 1 != first + end - start:
            raise ComplementError(f"range is not contiguous and file-backed: {fmt(start)}..{fmt(end)}")
        return self.data[first : first + end - start]

    def instructions(self, segment: Segment) -> Iterable[tuple[int, int]]:
        for offset in range(0, max(0, segment.file_size - 3), 4):
            yield segment.vaddr + offset, struct.unpack_from("<I", self.data, segment.file_offset + offset)[0]


# ---------------------------------------------------------------------------
# Explicit AArch64 decoder subset


def decode_bl_target(word: int, va: int) -> int | None:
    if (word & 0xFC000000) != 0x94000000:
        return None
    return va + 4 * sign_extend(word & 0x03FFFFFF, 26)


def decode_b_target(word: int, va: int) -> int | None:
    if (word & 0x7C000000) == 0x14000000:
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
    immediate = sign_extend((((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 3), 21)
    return immediate, word & 0x1F


def is_adrp(word: int) -> tuple[int, int] | None:
    if (word & 0x9F000000) != 0x90000000:
        return None
    immediate = sign_extend((((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 3), 21) << 12
    return immediate, word & 0x1F


def adr_target(word: int, va: int) -> tuple[int, int] | None:
    decoded = is_adr(word)
    return None if decoded is None else ((va + decoded[0]) & 0xFFFFFFFFFFFFFFFF, decoded[1])


def adrp_target(word: int, va: int) -> tuple[int, int] | None:
    decoded = is_adrp(word)
    return None if decoded is None else (((va & ~0xFFF) + decoded[0]) & 0xFFFFFFFFFFFFFFFF, decoded[1])


def is_movz(word: int) -> tuple[str, int, int, int] | None:
    if (word & 0x7F800000) != 0x52800000:
        return None
    return ("X" if word & 0x80000000 else "W", (word >> 5) & 0xFFFF, (word >> 21) & 3, word & 0x1F)


def is_movk(word: int) -> tuple[str, int, int, int] | None:
    if (word & 0x7F800000) != 0x72800000:
        return None
    return ("X" if word & 0x80000000 else "W", (word >> 5) & 0xFFFF, (word >> 21) & 3, word & 0x1F)


def is_movn(word: int) -> tuple[str, int, int, int] | None:
    if (word & 0x7F800000) != 0x12800000:
        return None
    return ("X" if word & 0x80000000 else "W", (word >> 5) & 0xFFFF, (word >> 21) & 3, word & 0x1F)


def _decode_logical_immediate(n: int, immr: int, imms: int, width: int) -> int | None:
    # ARM ARM DecodeBitMasks, limited to valid logical-immediate encodings.
    combined = (n << 6) | ((~imms) & 0x3F)
    if combined == 0:
        return None
    length = combined.bit_length() - 1
    if length < 1 or (1 << length) > width:
        return None
    levels = (1 << length) - 1
    s, r = imms & levels, immr & levels
    if s == levels:
        return None
    element_bits = 1 << length
    element = (1 << (s + 1)) - 1
    element = ((element >> r) | (element << (element_bits - r))) & ((1 << element_bits) - 1)
    value = 0
    for bit in range(0, width, element_bits):
        value |= element << bit
    return value & ((1 << width) - 1)


def is_orr_imm(word: int) -> tuple[str, int, int, int] | None:
    if (word & 0x7F800000) != 0x32000000:
        return None
    width = 64 if word & 0x80000000 else 32
    n = (word >> 22) & 1
    if width == 32 and n:
        return None
    value = _decode_logical_immediate(n, (word >> 16) & 0x3F, (word >> 10) & 0x3F, width)
    if value is None:
        return None
    return ("X" if width == 64 else "W", word & 0x1F, (word >> 5) & 0x1F, value)


def is_and_imm(word: int) -> tuple[str, int, int, int] | None:
    # AND (immediate) has the same bitmask fields as ORR (immediate), but a
    # distinct opcode.  Keeping this decoder separate prevents ORR/AND mask
    # confusion from turning a clobber into a copied address.
    if (word & 0x7F800000) != 0x12000000:
        return None
    width = 64 if word & 0x80000000 else 32
    n = (word >> 22) & 1
    if width == 32 and n:
        return None
    value = _decode_logical_immediate(n, (word >> 16) & 0x3F, (word >> 10) & 0x3F, width)
    if value is None:
        return None
    return ("X" if width == 64 else "W", word & 0x1F, (word >> 5) & 0x1F, value)


def is_orr_reg(word: int) -> tuple[str, int, int, int, int, int] | None:
    if (word & 0xFF200000) not in (0x2A000000, 0xAA000000):
        return None
    if word & 0x1F == 31:
        return None
    shift = (word >> 22) & 3
    if shift == 3:
        return None
    width = "X" if word & 0x80000000 else "W"
    amount = (word >> 10) & 0x3F
    if width == "W" and amount >= 32:
        return None
    return (width, word & 0x1F, (word >> 5) & 0x1F, (word >> 16) & 0x1F, shift, amount)


def is_add_sub_imm(word: int) -> tuple[str, str, int, int, int] | None:
    # ADD/SUB (immediate); reject flag-setting aliases and ADDG/SUBG.
    if (word & 0x1F000000) not in (0x11000000, 0x51000000, 0x91000000, 0xD1000000):
        return None
    if word & 0x20000000 or word & 0x00800000:
        return None
    rd, rn = word & 0x1F, (word >> 5) & 0x1F
    if rd == 31:
        return None
    width = "X" if word & 0x80000000 else "W"
    op = "SUB" if word & 0x40000000 else "ADD"
    imm = (word >> 10) & 0xFFF
    if word & (1 << 22):
        imm <<= 12
    return op, width, imm, rn, rd


def is_add_sub_reg(word: int) -> tuple[str, str, int, int, int, int, int] | None:
    if (word & 0x1F200000) != 0x0B000000 or word & 0x20000000:
        return None
    rd = word & 0x1F
    if rd == 31:
        return None
    shift_type = (word >> 22) & 3
    if shift_type == 3:
        return None
    width = "X" if word & 0x80000000 else "W"
    amount = (word >> 10) & 0x3F
    if width == "W" and amount >= 32:
        return None
    return ("SUB" if word & 0x40000000 else "ADD", width, rd, (word >> 5) & 0x1F, (word >> 16) & 0x1F, shift_type, amount)


def is_add_sub_ext(word: int) -> tuple[str, str, int, int, int, int, int] | None:
    # UXTW/SXTW/UXTX/SXTX with exact option and shift.  Reserved encodings are
    # deliberately rejected.
    if (word & 0x1F200000) != 0x0B200000 or word & 0x20000000 or word & 0x00C00000:
        return None
    rd = word & 0x1F
    if rd == 31:
        return None
    width = "X" if word & 0x80000000 else "W"
    option = (word >> 13) & 7
    if width == "W" and option in (3, 7):
        return None
    amount = (word >> 10) & 7
    if amount > 4:
        return None
    return ("SUB" if word & 0x40000000 else "ADD", width, rd, (word >> 5) & 0x1F, (word >> 16) & 0x1F, option, amount)


def _mem_size(size: int) -> tuple[str, int] | None:
    return {0: ("B", 1), 1: ("H", 2), 2: ("W", 4), 3: ("X", 8)}.get(size)


def is_mem_unsigned(word: int) -> tuple[str, str, int, int, int] | None:
    group = word & 0xFFC00000
    forms = {
        0x39400000: ("LDR", "B", 1), 0x39000000: ("STR", "B", 1),
        0x79400000: ("LDR", "H", 2), 0x79000000: ("STR", "H", 2),
        0xB9400000: ("LDR", "W", 4), 0xB9000000: ("STR", "W", 4),
        0xF9400000: ("LDR", "X", 8), 0xF9000000: ("STR", "X", 8),
    }
    decoded = forms.get(group)
    if decoded is None:
        return None
    kind, width, scale = decoded
    return kind, width, ((word >> 10) & 0xFFF) * scale, (word >> 5) & 0x1F, word & 0x1F


def is_mem_unscaled(word: int) -> tuple[str, str, int, int, int] | None:
    opcode = word & 0xFFE00C00
    forms = {
        0x38000000: ("STR", "B", 1), 0x38400000: ("LDR", "B", 1),
        0x78000000: ("STR", "H", 2), 0x78400000: ("LDR", "H", 2),
        0xB8000000: ("STR", "W", 4), 0xB8400000: ("LDR", "W", 4),
        0xF8000000: ("STR", "X", 8), 0xF8400000: ("LDR", "X", 8),
    }
    decoded = forms.get(opcode)
    if decoded is None:
        return None
    kind, width, _ = decoded
    return kind, width, sign_extend((word >> 12) & 0x1FF, 9), (word >> 5) & 0x1F, word & 0x1F


def is_mem_index(word: int) -> tuple[str, str, int, int, int, str] | None:
    opcode = word & 0xFFC00C00
    forms = {
        0x38000400: ("STR", "B"), 0x38000C00: ("STR", "B"),
        0x38400400: ("LDR", "B"), 0x38400C00: ("LDR", "B"),
        0x78000400: ("STR", "H"), 0x78000C00: ("STR", "H"),
        0x78400400: ("LDR", "H"), 0x78400C00: ("LDR", "H"),
        0xB8000400: ("STR", "W"), 0xB8000C00: ("STR", "W"),
        0xB8400400: ("LDR", "W"), 0xB8400C00: ("LDR", "W"),
        0xF8000400: ("STR", "X"), 0xF8000C00: ("STR", "X"),
        0xF8400400: ("LDR", "X"), 0xF8400C00: ("LDR", "X"),
    }
    decoded = forms.get(opcode)
    if decoded is None:
        return None
    kind, width = decoded
    mode = "POSTINDEX" if (word & 0xC00) == 0x400 else "PREINDEX"
    return kind, width, sign_extend((word >> 12) & 0x1FF, 9), (word >> 5) & 0x1F, word & 0x1F, mode


def is_mem_reg_offset(word: int) -> tuple[str, str, int, int, int, int, int] | None:
    opcode = word & 0x3FE00C00
    if opcode not in (0x38200800, 0x38600800):
        return None
    decoded = _mem_size((word >> 30) & 3)
    if decoded is None:
        return None
    width, _ = decoded
    kind = "LDR" if opcode == 0x38600800 else "STR"
    option = (word >> 13) & 7
    if option not in (2, 3, 6, 7):
        return None
    scale = {"B": 0, "H": 1, "W": 2, "X": 3}[width] if (word >> 12) & 1 else 0
    return kind, width, (word >> 5) & 0x1F, (word >> 16) & 0x1F, option, scale, word & 0x1F


def is_atomic_or_exclusive(word: int) -> bool:
    # Keep the recognition conservative.  These classes are not decoded as
    # ordinary loads/stores and therefore cannot silently become writer paths.
    return (word & 0x3F000000) in (0x08000000, 0x88000000, 0xC8000000)


def shift_value(value: int, width: str, kind: int, amount: int) -> int | None:
    bits = 64 if width == "X" else 32
    if amount >= bits or kind == 3:
        return None
    mask = (1 << bits) - 1
    value &= mask
    if kind == 0:
        return (value << amount) & mask
    if kind == 1:
        return value >> amount
    signed = value - (1 << bits) if value & (1 << (bits - 1)) else value
    return (signed >> amount) & mask


def extend_value(value: int, option: int) -> int | None:
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


# ---------------------------------------------------------------------------
# Symbolic origin and bounded CFG/dataflow


@dataclass(frozen=True)
class Origin:
    """A register value in the deliberately small symbolic lattice."""

    kind: str
    value: int | None = None
    base: str | None = None
    offset: int | None = 0
    section: int | None = None
    source_va: int | None = None

    def describe(self) -> str:
        if self.kind == "CONSTANT" and self.value is not None:
            return fmt(self.value)
        if self.kind in {"BASE", "MC_BASE", "SHRM_BASE"}:
            suffix = "?" if self.offset is None else (f"+0x{self.offset:x}" if self.offset else "")
            return f"{self.base or self.kind}{suffix}"
        if self.kind in {"DCB_SECTION", "DCB_ARRAY", "DCB_DATA"}:
            suffix = "?" if self.offset is None else (f"+0x{self.offset:x}" if self.offset else "")
            prefix = "DCB_DATA" if self.kind == "DCB_DATA" else "DCB_SECTION"
            return f"{prefix}_{self.section if self.section is not None else 'UNKNOWN'}{suffix}"
        if self.kind == "ARGUMENT":
            return self.base or "ARGUMENT"
        return "UNKNOWN"


UNKNOWN = Origin("UNKNOWN")


def constant(value: int) -> Origin:
    return Origin("CONSTANT", value=value & 0xFFFFFFFFFFFFFFFF)


def argument(register: int) -> Origin:
    return Origin("ARGUMENT", base=f"X{register}")


def symbolic(base: str, offset: int | None = 0, *, kind: str = "BASE", source_va: int | None = None) -> Origin:
    return Origin(kind, base=base, offset=offset, source_va=source_va)


def dcb_origin(section: int, *, array: bool = False, source_va: int | None = None) -> Origin:
    return Origin("DCB_ARRAY" if array else "DCB_SECTION", section=section, source_va=source_va)


def dcb_data_origin(section: int, *, source_va: int | None = None) -> Origin:
    return Origin("DCB_DATA", section=section, source_va=source_va)


ADDRESS_ORIGIN_KINDS = frozenset({"BASE", "MC_BASE", "SHRM_BASE", "DCB_SECTION", "DCB_ARRAY"})


def _is_address_origin(value: Origin) -> bool:
    return value.kind in ADDRESS_ORIGIN_KINDS


def _is_dcb_data(value: Origin) -> bool:
    return value.kind == "DCB_DATA"


def _same_origin(a: Origin | None, b: Origin | None) -> bool:
    return a == b


def _with_offset(value: Origin, delta: int, *, source_va: int | None = None) -> Origin:
    if value.kind == "CONSTANT" and value.value is not None:
        return constant(value.value + delta)
    if _is_address_origin(value):
        offset = None if value.offset is None else value.offset + delta
        return replace(value, offset=offset, source_va=source_va or value.source_va)
    return UNKNOWN


def _combine_add(left: Origin, right: Origin, *, subtract: bool = False, source_va: int | None = None) -> Origin:
    if left.kind == "CONSTANT" and right.kind == "CONSTANT" and left.value is not None and right.value is not None:
        return constant(left.value - right.value if subtract else left.value + right.value)
    if _is_address_origin(left) and _is_address_origin(right):
        return UNKNOWN
    if not subtract and _is_address_origin(left) and right.kind == "CONSTANT" and right.value is not None:
        return _with_offset(left, right.value, source_va=source_va)
    if subtract and _is_address_origin(left) and right.kind == "CONSTANT" and right.value is not None:
        return _with_offset(left, -right.value, source_va=source_va)
    # An address plus any non-constant value is not retained.  This keeps the
    # lattice limited to the advertised X-width address +/- constant form and
    # avoids turning a runtime index or a second provenance into a pointer.
    return UNKNOWN


def _set_reg(regs: dict[int, Origin], reg: int, value: Origin) -> None:
    if reg == 31:
        regs.pop(reg, None)
    else:
        regs[reg] = value


def _kill_for_call(regs: dict[int, Origin]) -> None:
    # The static model does not assume a callee preserves any value needed by
    # the local proof.  Clearing all registers is conservative and makes direct
    # call boundaries explicit in hostile controls.
    regs.clear()


def _merge_regs(old: dict[int, Origin] | None, new: dict[int, Origin]) -> dict[int, Origin]:
    if old is None:
        return dict(new)
    merged: dict[int, Origin] = {}
    for reg in set(old) | set(new):
        if reg in old and reg in new and _same_origin(old[reg], new[reg]):
            merged[reg] = old[reg]
    return merged


def _classify_address_origin(value: Origin, site_va: int) -> Origin:
    if value.kind == "CONSTANT" and value.value is not None:
        address = value.value & 0xFFFFFFFFFFFFFFFF
        if MC_APERTURE_START <= address < MC_APERTURE_END:
            return symbolic(f"MC_STATIC_{address & 0xFFFFF000:08x}", 0, kind="MC_BASE", source_va=site_va)
    # Do not promote an address to SHRM/controller state based on a
    # site-specific exception; preserve the origin unless its owner is
    # independently established by the bounded lattice.
    return value


@dataclass
class FlowState:
    regs: dict[int, Origin]
    blocked: bool = False
    unsupported: set[str] | None = None
    dcb_sections: set[int] | None = None

    def clone(self) -> "FlowState":
        return FlowState(dict(self.regs), self.blocked, set(self.unsupported or ()), set(self.dcb_sections or ()))


def _decode_mem(word: int) -> tuple[str, str, int, int | None, int, int, str] | None:
    """Return kind,width,base,index-or-dest,offset,scale,form."""
    reg = is_mem_reg_offset(word)
    if reg is not None:
        kind, width, rn, rm, option, scale, rt = reg
        return kind, width, rn, rm, option, scale, f"REGISTER_OFFSET:{rt}"
    indexed = is_mem_index(word)
    if indexed is not None:
        kind, width, offset, rn, rt, mode = indexed
        return kind, width, rn, rt, offset, 0, mode
    unscaled = is_mem_unscaled(word)
    if unscaled is not None:
        kind, width, offset, rn, rt = unscaled
        return kind, width, rn, rt, offset, 0, "UNSCALED"
    unsigned = is_mem_unsigned(word)
    if unsigned is not None:
        kind, width, offset, rn, rt = unsigned
        return kind, width, rn, rt, offset, 0, "UNSIGNED"
    return None


def _memory_load_origin(base: Origin, offset: int, *, section_hint: int | None = None, va: int) -> Origin:
    if base.kind in {"DCB_SECTION", "DCB_ARRAY"}:
        section = base.section if base.section is not None else section_hint
        return dcb_data_origin(section if section is not None else -1, source_va=va)
    # Proximity to a section-directory reader is not a dataflow edge.  Do not
    # synthesize a DCB pointer from the hint; the caller records proximity as a
    # separate hypothesis-level discriminator.
    return UNKNOWN


def _is_nop(word: int) -> bool:
    return word in (0xD503201F, 0xD5033FDF)


def analyze_bounded_site(
    image: Image,
    site: Mapping[str, Any],
    *,
    section_hint: int | None = None,
    seed_origins: Mapping[int, Origin] | None = None,
    max_states: int = 512,
) -> dict[str, Any]:
    """Run a small CFG/dataflow over one dependency-provided site.

    Only the supplied ``loop_head_va``..``back_edge_va`` range is visited.
    The direct store itself is the observation point; no arbitrary executable
    or MMIO range is scanned.
    """
    # Dependency computed-address idioms do not carry a back-edge field.  The
    # shared normalizer keeps their two-instruction interval aligned and avoids
    # accidentally interpreting a decimal fallback as hexadecimal.
    head, end_exclusive, store_va = _site_bounds(site)
    end_edge = end_exclusive - 4
    addresses = list(range(head, end_edge + 4, 4))
    if store_va not in addresses:
        # Computed idioms can have an end edge after the store, but the range
        # must contain both the ADD and STR exact words.
        addresses.append(store_va)
        addresses.sort()
    allowed = set(addresses)
    initial = {reg: argument(reg) for reg in range(8)}
    if seed_origins:
        initial.update(seed_origins)
    states: dict[int, FlowState] = {head: FlowState(initial, False, set(), set())}
    queue = [head]
    visited = 0
    observations: list[dict[str, Any]] = []
    unsupported_reasons: set[str] = set()
    direct_calls: list[dict[str, Any]] = []
    branch_edges: list[dict[str, Any]] = []

    while queue and visited < max_states:
        va = queue.pop(0)
        state = states[va].clone()
        visited += 1
        word = image.word(va)
        if word is None:
            state.blocked = True
            state.unsupported.add("UNMAPPED_WORD")
            unsupported_reasons.add("UNMAPPED_WORD")
            continue
        next_addresses: list[int] = []
        direct_bl = decode_bl_target(word, va)
        if direct_bl is not None:
            args = {f"X{r}": state.regs[r].describe() for r in range(8) if r in state.regs}
            direct_calls.append({"va": fmt(va), "target": fmt(direct_bl), "arguments": args})
            _kill_for_call(state.regs)
            next_addresses = [va + 4]
        elif is_blr(word) is not None or is_br(word) is not None:
            state.blocked = True
            state.unsupported.add("INDIRECT_BRANCH_TARGET_OR_RUNTIME_ALIAS")
            unsupported_reasons.add("INDIRECT_BRANCH_TARGET_OR_RUNTIME_ALIAS")
            branch_edges.append({"va": fmt(va), "kind": "BLR" if is_blr(word) is not None else "BR", "target": "UNKNOWN"})
        elif is_ret(word):
            next_addresses = []
        else:
            branch = decode_b_target(word, va)
            if branch is not None:
                next_addresses.append(branch)
                # Conditional branches also have the fall-through edge.  The
                # unconditional B encoding is distinguished by bits 31:26.
                if (word & 0x7C000000) != 0x14000000:
                    next_addresses.append(va + 4)
                branch_edges.append({"va": fmt(va), "kind": "DIRECT_BRANCH", "target": fmt(branch)})
            else:
                next_addresses = [va + 4]

            # Address and scalar definitions.
            adr = adr_target(word, va)
            adrp = adrp_target(word, va)
            if adr is not None:
                _set_reg(state.regs, adr[1], constant(adr[0]))
            elif adrp is not None:
                _set_reg(state.regs, adrp[1], constant(adrp[0]))
            else:
                movz = is_movz(word)
                movk = is_movk(word)
                movn = is_movn(word)
                logical_imm = is_orr_imm(word)
                and_imm = is_and_imm(word)
                logical = is_orr_reg(word)
                add_imm = is_add_sub_imm(word)
                add_reg = is_add_sub_reg(word)
                add_ext = is_add_sub_ext(word)
                if movz is not None:
                    width, imm, hw, rd = movz
                    if width == "W" and hw > 1:
                        _set_reg(state.regs, rd, UNKNOWN)
                    else:
                        _set_reg(state.regs, rd, constant((imm << (16 * hw)) & (0xFFFFFFFF if width == "W" else 0xFFFFFFFFFFFFFFFF)))
                elif movn is not None:
                    width, imm, hw, rd = movn
                    if width == "W" and hw > 1:
                        _set_reg(state.regs, rd, UNKNOWN)
                    else:
                        mask = 0xFFFFFFFF if width == "W" else 0xFFFFFFFFFFFFFFFF
                        _set_reg(state.regs, rd, constant((~(imm << (16 * hw))) & mask))
                elif movk is not None:
                    width, imm, hw, rd = movk
                    old = state.regs.get(rd)
                    if old is None or old.kind != "CONSTANT" or old.value is None or (width == "W" and hw > 1):
                        _set_reg(state.regs, rd, UNKNOWN)
                    else:
                        mask = 0xFFFFFFFF if width == "W" else 0xFFFFFFFFFFFFFFFF
                        half = 0xFFFF << (16 * hw)
                        merged = (old.value & ~half) | (imm << (16 * hw))
                        _set_reg(state.regs, rd, constant(merged & mask))
                elif logical_imm is not None:
                    width, rd, rn, imm = logical_imm
                    source = constant(0) if rn == 31 else state.regs.get(rn, UNKNOWN)
                    if source.kind == "CONSTANT" and source.value is not None:
                        mask = 0xFFFFFFFF if width == "W" else 0xFFFFFFFFFFFFFFFF
                        _set_reg(state.regs, rd, constant((source.value | imm) & mask))
                    else:
                        _set_reg(state.regs, rd, UNKNOWN)
                elif and_imm is not None:
                    width, rd, rn, imm = and_imm
                    source = state.regs.get(rn, UNKNOWN)
                    if source.kind == "CONSTANT" and source.value is not None:
                        _set_reg(state.regs, rd, constant(source.value & imm))
                    else:
                        _set_reg(state.regs, rd, UNKNOWN)
                elif logical is not None:
                    width, rd, rn, rm, shift_kind, amount = logical
                    left = constant(0) if rn == 31 else state.regs.get(rn, UNKNOWN)
                    right = state.regs.get(rm, UNKNOWN)
                    shifted = None
                    if right.kind == "CONSTANT" and right.value is not None:
                        shifted = shift_value(right.value, width, shift_kind, amount)
                    if left.kind == "CONSTANT" and left.value is not None and shifted is not None:
                        mask = 0xFFFFFFFF if width == "W" else 0xFFFFFFFFFFFFFFFF
                        _set_reg(state.regs, rd, constant((left.value | shifted) & mask))
                    elif rn == 31 and _is_address_origin(right):
                        # An address-origin ORR is a pointer copy only in the
                        # architectural X-width LSL #0 form.  A shifted or
                        # W-width pointer is not retained in this lattice.
                        if width == "X" and shift_kind == 0 and amount == 0:
                            _set_reg(state.regs, rd, right)
                        else:
                            _set_reg(state.regs, rd, UNKNOWN)
                    elif rn == 31 and _is_dcb_data(right) and shift_kind == 0 and amount == 0:
                        # Data provenance may be copied through an exact ORR
                        # alias; it is not an address-origin exception.
                        _set_reg(state.regs, rd, right)
                    elif rn == 31 and rm in state.regs and state.regs[rm].kind == "CONSTANT" and shifted is not None:
                        _set_reg(state.regs, rd, constant(shifted))
                    else:
                        _set_reg(state.regs, rd, UNKNOWN)
                elif add_imm is not None:
                    op, width, imm, rn, rd = add_imm
                    left = state.regs.get(rn, UNKNOWN)
                    result = _combine_add(left, constant(imm), subtract=op == "SUB", source_va=va)
                    if width == "W" and _is_address_origin(left):
                        result = UNKNOWN
                    if width == "W" and result.kind == "CONSTANT" and result.value is not None:
                        result = constant(result.value & 0xFFFFFFFF)
                    _set_reg(state.regs, rd, _classify_address_origin(result, store_va))
                elif add_reg is not None:
                    op, width, rd, rn, rm, shift_kind, amount = add_reg
                    left, right = state.regs.get(rn, UNKNOWN), state.regs.get(rm, UNKNOWN)
                    if right.kind == "CONSTANT" and right.value is not None:
                        shifted = shift_value(right.value, width, shift_kind, amount)
                        right = UNKNOWN if shifted is None else constant(shifted)
                    else:
                        if _is_address_origin(right) and shift_kind == 0:
                            right = replace(right, offset=None if right.offset is None else right.offset << amount)
                        else:
                            right = UNKNOWN
                    result = _combine_add(left, right, subtract=op == "SUB", source_va=va)
                    if width == "W" and _is_address_origin(left):
                        result = UNKNOWN
                    if width == "W" and result.kind == "CONSTANT" and result.value is not None:
                        result = constant(result.value & 0xFFFFFFFF)
                    _set_reg(state.regs, rd, _classify_address_origin(result, store_va))
                elif add_ext is not None:
                    op, width, rd, rn, rm, option, amount = add_ext
                    left, right = state.regs.get(rn, UNKNOWN), state.regs.get(rm, UNKNOWN)
                    if right.kind == "CONSTANT" and right.value is not None:
                        extended = extend_value(right.value, option)
                        right = UNKNOWN if extended is None else constant(extended << amount)
                    else:
                        right = UNKNOWN
                    result = _combine_add(left, right, subtract=op == "SUB", source_va=va)
                    if width == "W" and _is_address_origin(left):
                        result = UNKNOWN
                    _set_reg(state.regs, rd, _classify_address_origin(result, store_va))
                else:
                    mem = _decode_mem(word)
                    if mem is not None:
                        kind, width, rn, index_or_rt, offset, scale, form = mem
                        base = state.regs.get(rn, UNKNOWN)
                        is_load = kind == "LDR"
                        if form.startswith("REGISTER_OFFSET:"):
                            rt = int(form.split(":", 1)[1])
                            index_register = index_or_rt if index_or_rt is not None else 31
                            index = state.regs.get(index_register, UNKNOWN)
                            option = offset
                            transformed = None
                            if index.kind == "CONSTANT" and index.value is not None:
                                extended = extend_value(index.value, option)
                                transformed = None if extended is None else extended << scale
                            elif _is_address_origin(index):
                                transformed = None
                            if transformed is not None:
                                target = _combine_add(base, constant(transformed), source_va=va)
                            elif _is_address_origin(base):
                                target = replace(base, offset=None, source_va=va)
                            else:
                                target = UNKNOWN
                            if is_load:
                                _set_reg(state.regs, rt, _memory_load_origin(target, 0, section_hint=section_hint, va=va))
                            else:
                                observations.append({"va": fmt(va), "word": fmt(word), "kind": "STR", "width": width, "target": target, "form": "REGISTER_OFFSET", "base_register": rn, "index_register": index_or_rt, "index_option": option, "index_scale": scale, "source_register": rt, "source": state.regs.get(rt, UNKNOWN)})
                        else:
                            rt = index_or_rt if index_or_rt is not None else 31
                            # POSTINDEX accesses the old base and writes back
                            # afterward; PREINDEX accesses the updated base.
                            effective_base = _with_offset(base, offset, source_va=va) if form == "PREINDEX" else base
                            target = effective_base
                            if is_load:
                                loaded = _memory_load_origin(effective_base, 0, section_hint=section_hint, va=va)
                                _set_reg(state.regs, rt, loaded)
                            else:
                                observations.append({"va": fmt(va), "word": fmt(word), "kind": "STR", "width": width, "target": target, "form": form, "base_register": rn, "offset": offset, "source_register": rt, "source": state.regs.get(rt, UNKNOWN)})
                            if form in {"POSTINDEX", "PREINDEX"}:
                                if is_load and rt == rn:
                                    _set_reg(state.regs, rn, UNKNOWN)
                                else:
                                    _set_reg(state.regs, rn, _with_offset(base, offset, source_va=va))
                    elif is_atomic_or_exclusive(word):
                        state.blocked = True
                        state.unsupported.add("EXCLUSIVE_AND_LSE_ATOMICS_UNSUPPORTED")
                        unsupported_reasons.add("EXCLUSIVE_AND_LSE_ATOMICS_UNSUPPORTED")
                    elif _is_nop(word):
                        pass
                    else:
                        # Unrecognized instructions are clobbers.  Do not let
                        # stale address origins cross a decoder boundary.
                        state.regs.clear()
                        state.blocked = True
                        state.unsupported.add("UNRECOGNIZED_AARCH64_INSTRUCTION_OR_MEMORY_FORM")
                        unsupported_reasons.add("UNRECOGNIZED_AARCH64_INSTRUCTION_OR_MEMORY_FORM")

        for observation in observations[-8:]:
            target = observation.get("target")
            if isinstance(target, Origin):
                observation["state_blocked"] = state.blocked
                observation["unsupported"] = sorted(state.unsupported or ())
                observation["target_origin"] = target.describe()
                observation["target_kind"] = target.kind
                observation["target_base"] = target.base
                observation["target_offset"] = target.offset
                source = observation.get("source")
                if isinstance(source, Origin):
                    observation["source_origin"] = source.describe()
                    observation["source_kind"] = source.kind
                    observation["source_section"] = source.section
                    observation.pop("source", None)
                observation["dcb_sections"] = sorted(state.dcb_sections or ())
                observation["site_va"] = store_va
                observation["symbolic_base_plus_offset"] = target.kind in ADDRESS_ORIGIN_KINDS
                observation.pop("target", None)

        for nxt in next_addresses:
            if nxt not in allowed:
                continue
            if len(states) > max_states:
                break
            merged = _merge_regs(states[nxt].regs if nxt in states else None, state.regs)
            if nxt not in states:
                states[nxt] = FlowState(merged, state.blocked, set(state.unsupported or ()), set(state.dcb_sections or ()))
                queue.append(nxt)
            else:
                previous = states[nxt]
                new_state = FlowState(merged, previous.blocked or state.blocked, set(previous.unsupported or ()) | set(state.unsupported or ()), set(previous.dcb_sections or ()) | set(state.dcb_sections or ()))
                if new_state.regs != previous.regs or new_state.blocked != previous.blocked or new_state.unsupported != previous.unsupported:
                    states[nxt] = new_state
                    queue.append(nxt)

    cfg_complete = not queue
    if not cfg_complete:
        # A positive observation from a truncated worklist is not a proof.  A
        # bounded state cap is an explicit fail-closed outcome, not a normal
        # completion with a smaller explored graph.
        unsupported_reasons.add("CFG_STATE_LIMIT_REACHED")

    # The observation list can contain repeated loop visits.  Keep one row per
    # instruction and merge the conservative path facts deterministically.
    by_va: dict[str, dict[str, Any]] = {}
    for row in observations:
        old = by_va.get(row["va"])
        if old is None:
            by_va[row["va"]] = row
        else:
            old["state_blocked"] = bool(old["state_blocked"] or row["state_blocked"])
            old["unsupported"] = sorted(set(old.get("unsupported", ())) | set(row.get("unsupported", ())))
            if old.get("target_origin") != row.get("target_origin"):
                old["target_origin"] = "UNKNOWN"
                old["target_kind"] = "UNKNOWN"
                old["target_offset"] = None
            if any(old.get(key) != row.get(key) for key in ("source_origin", "source_kind", "source_section")):
                old["source_origin"] = "UNKNOWN"
                old["source_kind"] = "UNKNOWN"
                old["source_section"] = None
    usable = [row for row in by_va.values() if not row.get("state_blocked")]
    if unsupported_reasons:
        for row in by_va.values():
            row["state_blocked"] = True
        usable = []
    labels: set[str] = set()
    for row in usable:
        if row.get("kind") == "STR" and row.get("source_kind") == "DCB_DATA":
            labels.add("DCB_CONSUMER_PATH")
        if row.get("target_kind") in {"MC_BASE", "SHRM_BASE"}:
            labels.add("MC_OR_SHRM_SYMBOLIC_TARGET")
    if unsupported_reasons:
        labels = {"INDIRECT_OR_UNSUPPORTED"}
    elif not usable:
        labels.add("NO_TARGET_WITHIN_MODEL")
    elif not labels:
        labels.add("NO_TARGET_WITHIN_MODEL")
    status = "SUPPORTED" if labels & {"DCB_CONSUMER_PATH", "MC_OR_SHRM_SYMBOLIC_TARGET"} else "UNKNOWN"
    if "INDIRECT_OR_UNSUPPORTED" in labels:
        status = "UNKNOWN"
    return {
        "site": {k: site[k] for k in sorted(site)},
        "store_va": fmt(store_va),
        "range": {"start": fmt(head), "end_exclusive": fmt(end_edge + 4), "size": end_edge + 4 - head},
        "discriminators": sorted(labels),
        "status": status,
        "current_destination": "UNKNOWN",
        "target_observations": sorted(by_va.values(), key=lambda row: row["va"]),
        "usable_target_observations": sorted(usable, key=lambda row: row["va"]),
        "unsupported_forms": sorted(unsupported_reasons),
        "direct_calls": sorted(direct_calls, key=lambda row: row["va"]),
        "branch_edges": sorted(branch_edges, key=lambda row: row["va"]),
        "cfg_states_visited": visited,
        "cfg_state_limit": max_states,
        "cfg_complete": cfg_complete,
        "writer_absence": "UNKNOWN",
    }


# ---------------------------------------------------------------------------
# Dependency and exact-image validation


def _parse_hex(value: Any, label: str) -> int:
    if not isinstance(value, str) or not value.lower().startswith("0x"):
        raise ComplementError(f"{label} is not a hexadecimal string")
    try:
        return int(value, 16)
    except ValueError as exc:
        raise ComplementError(f"{label} is not hexadecimal") from exc


def load_dependency_manifests(manifest_dir: Path = MANIFEST_DIR) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    manifests: dict[str, dict[str, Any]] = {}
    hashes: dict[str, str] = {}
    for name, (expected_size, expected_hash) in DEPENDENCY_SPECS.items():
        path = manifest_dir / name
        if not path.is_file():
            raise ComplementError(f"missing dependency manifest: {name}")
        raw = path.read_bytes()
        if len(raw) != expected_size or sha256(raw) != expected_hash:
            raise ComplementError(f"dependency manifest exact hash/size mismatch: {name}")
        try:
            manifest = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ComplementError(f"dependency is not JSON: {name}") from exc
        if not isinstance(manifest, dict):
            raise ComplementError(f"dependency root is not an object: {name}")
        manifests[name] = manifest
        hashes[name] = expected_hash
    _validate_dependency_semantics(manifests)
    return manifests, hashes


def _validate_dependency_semantics(manifests: Mapping[str, Mapping[str, Any]]) -> None:
    d019 = manifests["019-dcb-register-programming-20260826-01.manifest.json"]
    if d019.get("experiment_id") != "019-dcb-register-programming" or d019.get("mode") != MODE:
        raise ComplementError("Experiment 019 identity/mode semantic mismatch")
    if d019.get("dcb_image") != DCB_NAME or d019.get("dcb_image_sha256") != DCB_SHA256:
        raise ComplementError("Experiment 019 DCB input semantic mismatch")
    if d019.get("candidate_pair_array_count") != 28 or d019.get("ranked_target_reach") != "UNKNOWN":
        raise ComplementError("Experiment 019 candidate/unknown boundary changed")
    if d019.get("ranked_absolute_base_reached_scope") != "ABSOLUTE_TABLE_KEYS_ONLY":
        raise ComplementError("Experiment 019 absolute-key scope changed")
    blocks = d019.get("dcb", {}).get("blocks")
    if not isinstance(blocks, list) or len(blocks) != 4:
        raise ComplementError("Experiment 019 does not preserve four DCB blocks")
    for block in blocks:
        sections = block.get("sections") if isinstance(block, dict) else None
        if not isinstance(sections, dict):
            raise ComplementError("Experiment 019 DCB section map is malformed")
        for index in DCB_SECTIONS:
            section = sections.get(str(index))
            if not isinstance(section, dict) or section.get("kind") != "BASE_RELATIVE_OFFSET_PAIR_ARRAY":
                raise ComplementError(f"Experiment 019 section {index} semantic mismatch")
        hits = sections["7"].get("ranked_offset_hits")
        expected_hits = [{"key": "0x400", "value": "0x10000000"}, {"key": "0x404", "value": "0x10000000"}]
        if hits != expected_hits:
            raise ComplementError("Experiment 019 section-7 pinned keys changed")

    d020 = manifests["020-xbl-dcb-consumer-xref-20260826-01.manifest.json"]
    if d020.get("experiment_id") != "020-xbl-dcb-consumer-xref" or d020.get("mode") != MODE:
        raise ComplementError("Experiment 020 identity/mode semantic mismatch")
    if d020.get("image") != XBL_NAME or d020.get("image_sha256") != XBL_SHA256:
        raise ComplementError("Experiment 020 XBL input semantic mismatch")
    reg = d020.get("register_offset_store_census", {})
    reg_sites = reg.get("loop_sites")
    if reg.get("inside_backward_branch_loop") != 67 or not isinstance(reg_sites, list) or len(reg_sites) != 67:
        raise ComplementError("Experiment 020 exact 67-site contract changed")
    computed = d020.get("computed_address_store_census", {})
    if computed.get("idiom_sites") != 8 or computed.get("inside_backward_branch_loop") != 3 or len(computed.get("loop_sites", [])) != 3:
        raise ComplementError("Experiment 020 exact eight-idiom contract changed")
    false_negative = d020.get("known_narrow_model_false_negative", {})
    fn_range = false_negative.get("range", {})
    if (_parse_hex(fn_range.get("start"), "020 false-negative start") != FALSE_NEGATIVE_START or
            _parse_hex(fn_range.get("end_exclusive"), "020 false-negative end") != FALSE_NEGATIVE_END or
            false_negative.get("record_semantics") != "UNKNOWN"):
        raise ComplementError("Experiment 020 false-negative boundary changed")
    if not str(d020.get("next_discriminator", "")).startswith("MOV_SHIFT_EXTEND_LOAD_AWARE_CFG_DATAFLOW"):
        raise ComplementError("Experiment 020 next-stage discriminator changed")

    d021 = manifests["021-dcb-delivery-paths-20260826-01.manifest.json"]
    if d021.get("experiment_id") != "021-dcb-delivery-paths" or d021.get("mode") != MODE:
        raise ComplementError("Experiment 021 identity/mode semantic mismatch")
    if d021.get("image") != XBL_NAME or d021.get("image_sha256") != XBL_SHA256:
        raise ComplementError("Experiment 021 XBL input semantic mismatch")
    copy = d021.get("dcb_copy_paths", {})
    if copy.get("direct_bl_count") != 7 or copy.get("direct_b_count") != 0 or copy.get("unlabelled_direct_bl_count") != 2:
        raise ComplementError("Experiment 021 delivery-edge contract changed")
    if d021.get("delivery_conclusion", {}).get("global_delivery") != "UNKNOWN":
        raise ComplementError("Experiment 021 global delivery boundary changed")

    d024 = manifests["024-xbl-six-byte-walker-20260826-01.manifest.json"]
    if d024.get("experiment_id") != "024-xbl-six-byte-walker" or d024.get("mode") != MODE:
        raise ComplementError("Experiment 024 identity/mode semantic mismatch")
    if d024.get("inputs", {}).get("firmware", {}).get("sha256") != XBL_SHA256:
        raise ComplementError("Experiment 024 XBL input semantic mismatch")
    walker = d024.get("walker", {})
    if walker.get("range", {}).get("start") != fmt(WALKER_START) or walker.get("range", {}).get("end_exclusive") != fmt(WALKER_END):
        raise ComplementError("Experiment 024 resolved walker range changed")
    if d024.get("initializer_and_base_audit", {}).get("base_currentness") != "UNKNOWN":
        raise ComplementError("Experiment 024 current-base boundary changed")
    if not any("global DCB consumer/writer presence" in str(x) for x in d024.get("claims", {}).get("UNKNOWN", [])):
        raise ComplementError("Experiment 024 global consumer boundary changed")

    d025 = manifests["025-xbl-platform-query-binding-20260826-01.manifest.json"]
    if d025.get("experiment_id") != "025-xbl-platform-query-binding" or d025.get("mode") != MODE:
        raise ComplementError("Experiment 025 identity/mode semantic mismatch")
    if d025.get("inputs", {}).get("firmware", {}).get("sha256") != XBL_SHA256:
        raise ComplementError("Experiment 025 XBL input semantic mismatch")
    if d025.get("classification") != "CLASS C (TRANSFORM ONLY)":
        raise ComplementError("Experiment 025 classification changed")
    if d025.get("order_and_authority", {}).get("boot_order") != "UNKNOWN" or d025.get("order_and_authority", {}).get("base_preservation") != "UNKNOWN":
        raise ComplementError("Experiment 025 runtime authority boundary changed")
    if d025.get("platform_query", {}).get("helper_arguments", {}).get("indirect_call", {}).get("target") != "UNKNOWN_UNTIL_RUNTIME_OBJECT_BINDING":
        raise ComplementError("Experiment 025 BLR boundary changed")

    d026 = manifests["026-xbl-dispatch-order-slot-escape-20260826-01.manifest.json"]
    if d026.get("experiment_id") != "026-xbl-dispatch-order-slot-escape" or d026.get("mode") != MODE:
        raise ComplementError("Experiment 026 identity/mode semantic mismatch")
    if d026.get("inputs", {}).get("firmware", {}).get("sha256") != XBL_SHA256:
        raise ComplementError("Experiment 026 XBL input semantic mismatch")
    if d026.get("order_and_authority", {}).get("runtime_order") != "UNKNOWN" or d026.get("slot_escape", {}).get("writer_absence") != "UNKNOWN":
        raise ComplementError("Experiment 026 runtime/writer boundary changed")
    if d026.get("complementary_census", {}).get("writer_absence_claim") is not False:
        raise ComplementError("Experiment 026 writer-absence boundary changed")


def _recursive_ranges(value: Any, path: str = "") -> list[tuple[int, int, str]]:
    ranges: list[tuple[int, int, str]] = []
    if isinstance(value, dict):
        if "start" in value and "end_exclusive" in value:
            try:
                start, end = _parse_hex(value["start"], f"{path}.start"), _parse_hex(value["end_exclusive"], f"{path}.end_exclusive")
                if start < end:
                    ranges.append((start, end, path or "dependency-range"))
            except ComplementError:
                # Non-address metadata with a start/end pair is not a range;
                # only malformed hexadecimal dependency ranges are fatal when
                # they look like address strings.
                pass
        for key, child in value.items():
            ranges.extend(_recursive_ranges(child, f"{path}.{key}" if path else key))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            ranges.extend(_recursive_ranges(child, f"{path}[{index}]"))
    return ranges


def dependency_exclusion_ranges(manifests: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    ranges: list[tuple[int, int, str, str]] = []
    for name in ("024-xbl-six-byte-walker-20260826-01.manifest.json", "025-xbl-platform-query-binding-20260826-01.manifest.json", "026-xbl-dispatch-order-slot-escape-20260826-01.manifest.json"):
        experiment = name[:3]
        for start, end, path in _recursive_ranges(manifests[name]):
            # 024's resolved walker and all three complete caller-context
            # windows are explicitly excluded.  The other 024 data tables are
            # dependency facts, not new code claims.  Keep the exact ranges in
            # the public accounting even though none of the current 020 sites
            # overlaps the three caller windows.
            if experiment == "024" and not (
                _overlap(start, end, WALKER_START, WALKER_END)
                or (start, end) in WALKER_CALLER_CONTEXT_RANGES
            ):
                continue
            ranges.append((start, end, experiment, path))
    dedup = {(start, end, exp): (start, end, exp, path) for start, end, exp, path in ranges}
    return [
        {"start": fmt(start), "end_exclusive": fmt(end), "dependency": exp, "source": path}
        for start, end, exp, path in sorted(dedup.values(), key=lambda row: (row[0], row[1], row[2], row[3]))
    ]


def _overlap(start: int, end: int, other_start: int, other_end: int) -> bool:
    return start < other_end and other_start < end


def _site_bounds(site: Mapping[str, Any]) -> tuple[int, int, int]:
    """Return normalized ``(start, end_exclusive, store)`` for either site shape.

    Experiment 020 register-offset rows have loop-head/back-edge fields,
    while its non-loop computed-address rows only have ``add_va`` and
    ``store_va``.  Treating the latter as a one-idiom interval is intentional;
    it keeps the eight-idiom complement in the same exclusion accounting and
    prevents a missing optional field from changing the address base.
    """
    try:
        store = _parse_hex(site["store_va"], "site store")
        start_value = site.get("loop_head_va", site.get("add_va", site["store_va"]))
        end_value = site.get("back_edge_va", site["store_va"])
        start = _parse_hex(start_value, "site start")
        end = _parse_hex(end_value, "site end") + 4
    except (KeyError, TypeError, ValueError) as exc:
        raise ComplementError("site range shape is malformed") from exc
    if start % 4 or (end - 4) % 4 or store % 4 or start > end - 4:
        raise ComplementError("site range is not aligned or ordered")
    if not start <= store < end:
        raise ComplementError("site store is outside its normalized range")
    return start, end, store


def validate_site_exclusions(sites: Iterable[Mapping[str, Any]], exclusions: Sequence[Mapping[str, Any]]) -> None:
    for site in sites:
        start, end, store_va = _site_bounds(site)
        for exclusion in exclusions:
            left, right = _parse_hex(exclusion["start"], "exclusion start"), _parse_hex(exclusion["end_exclusive"], "exclusion end")
            if _overlap(start, end, left, right):
                # The 020 false-negative is required as a positive-control
                # boundary but is not a new semantic claim.
                if start == 0x148689DC and end == 0x14868A60 and exclusion.get("dependency") in {"024", "026"}:
                    continue
                # 020's site at 0x148688d8 is enclosed by the exact 025 main
                # initializer range, which 026 carries forward as an excluded
                # dependency range.  It is therefore accounted for but not
                # semantically re-claimed here.
                if store_va == 0x148688D8:
                    continue
                raise ComplementError(f"dependency exclusion overlaps site {fmt(start)}..{fmt(end)}")


def load_exact(path: Path, size: int, digest: str, label: str) -> bytes:
    if not path.is_file():
        raise ComplementError(f"missing exact input: {label}")
    data = path.read_bytes()
    actual = sha256(data)
    if len(data) != size or actual != digest:
        raise ComplementError(f"exact input mismatch: {label}")
    return data


def derive_computed_address_sites(image: Image) -> list[dict[str, Any]]:
    """Reproduce 020's exact eight ADD-register -> STR-immediate idioms.

    This is a syntactic walk over the exact executable PT_LOADs only; it is
    not a target-range scan.  The dependency's ``idiom_sites=8`` count is used
    as the acceptance contract by :func:`exact_site_sets`.
    """
    sites: list[dict[str, Any]] = []
    for segment in image.segments:
        if segment.flags not in (5, 7):
            continue
        words = {va: word for va, word in image.instructions(segment)}
        for va, word in sorted(words.items()):
            if (word & 0xFFE0FC00) != 0x8B000000:
                continue
            destination = word & 0x1F
            for ahead in range(va + 4, va + 4 * 6, 4):
                follower = words.get(ahead)
                if follower is None:
                    break
                if (follower & 0xFFFFFC00) in (0xB9000000, 0xF9000000) and ((follower >> 5) & 0x1F) == destination:
                    sites.append({
                        "segment": segment.kind,
                        "add_va": fmt(va),
                        "store_va": fmt(ahead),
                        "width": "X" if (follower & 0xFFFFFC00) == 0xF9000000 else "W",
                        "offset_register": (word >> 16) & 0x1F,
                        "base_register": (word >> 5) & 0x1F,
                    })
                    break
                # Replicate the dependency's overwrite stop rule.  An
                # intervening definition of the ADD destination invalidates
                # this local idiom rather than letting a stale definition
                # create a false site.
                if (follower & 0x1F) == destination:
                    break
    return sorted(sites, key=lambda row: (_parse_hex(row["store_va"], "computed store"), row))


def exact_site_sets(d020: Mapping[str, Any], image: Image | None = None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    register_sites = d020["register_offset_store_census"]["loop_sites"]
    computed_sites = d020["computed_address_store_census"]["loop_sites"]
    # Copy and canonicalize dependency supplied records without changing their
    # semantic content.
    register = [dict(row) for row in register_sites]
    computed = [dict(row) for row in computed_sites]
    if len(register) != 67 or len(computed) != 3:
        raise ComplementError("dependency site cardinality changed")
    if image is not None:
        derived = derive_computed_address_sites(image)
        if d020["computed_address_store_census"].get("idiom_sites") != len(derived) or len(derived) != 8:
            raise ComplementError("exact computed-address idiom set does not match Experiment 020")
        # The local eight-idiom derivation intentionally has no loop context.
        # For the three dependency records that are proven to be inside a
        # backward loop, merge the dependency's full loop-head/back-edge
        # metadata into the matching derived idiom.  Comparing the complete
        # identity fields first prevents a store-address coincidence from
        # silently attaching the wrong loop context.  The remaining five
        # idioms stay normalized to their local ADD..STR interval.
        derived_by_store: dict[str, list[dict[str, Any]]] = {}
        for row in derived:
            derived_by_store.setdefault(row["store_va"], []).append(dict(row))
        loop_stores: set[str] = set()
        merged_by_store: dict[str, dict[str, Any]] = {}
        identity_fields = ("segment", "add_va", "store_va", "width", "offset_register", "base_register")
        for dependency_row in computed:
            store = dependency_row.get("store_va")
            if not isinstance(store, str) or store in loop_stores:
                raise ComplementError("computed loop site store identity is duplicated or malformed")
            matches = derived_by_store.get(store, [])
            if len(matches) != 1:
                raise ComplementError("computed loop site does not match exactly one derived idiom")
            local = matches[0]
            if any(local.get(field) != dependency_row.get(field) for field in identity_fields):
                raise ComplementError("computed loop site identity mismatch")
            merged = dict(local)
            merged.update(dependency_row)
            loop_stores.add(store)
            merged_by_store[store] = merged
        if len(loop_stores) != len(computed):
            raise ComplementError("computed loop site accounting is incomplete")
        computed = []
        for local in derived:
            computed.append(merged_by_store.get(local["store_va"], local))
    stores = {row["store_va"] for row in register} | {row["store_va"] for row in computed}
    if len(stores) != 75:
        raise ComplementError("dependency site store identity is not unique")
    return sorted(register, key=lambda row: (_parse_hex(row["store_va"], "register store"), row)), sorted(computed, key=lambda row: (_parse_hex(row["store_va"], "computed store"), row))


def validate_dcb_image(data: bytes) -> dict[str, Any]:
    """Re-parse the four DCB blocks and section-7 key/value pins."""
    if sha256(data) != DCB_SHA256 or len(data) != DCB_SIZE:
        raise ComplementError("DCB exact hash/size mismatch")
    if data[:4] != b"\x7fELF" or data[4:6] != b"\x02\x01":
        raise ComplementError("DCB is not ELF64")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phent = struct.unpack_from("<H", data, 54)[0]
    phnum = struct.unpack_from("<H", data, 56)[0]
    blocks: list[dict[str, Any]] = []
    for i in range(phnum):
        off = phoff + i * phent
        if off + 56 > len(data):
            raise ComplementError("DCB program header exceeds image")
        typ, flags, file_off, va, _pa, file_size, mem_size, _al = struct.unpack_from("<IIQQQQQQ", data, off)
        if typ != 1 or file_size != 0x3404:
            continue
        block_index = len(blocks)
        if block_index >= len(DCB_BLOCK_FILE_OFFSETS) or file_off != DCB_BLOCK_FILE_OFFSETS[block_index]:
            raise ComplementError("DCB block file offset contract changed")
        if file_off + file_size > len(data):
            raise ComplementError("DCB block exceeds image")
        block = data[file_off : file_off + file_size]
        sections: dict[str, dict[str, Any]] = {}
        for section in DCB_SECTIONS:
            header = 0x0C + section * 4
            data_off, size = struct.unpack_from("<HH", block, header)
            if data_off < 0x64 or data_off + size > len(block):
                raise ComplementError(f"DCB section {section} range invalid")
            body = block[data_off : data_off + size]
            sections[str(section)] = {"data_offset": fmt(data_off), "size": size, "sha256": sha256(body)}
        sec7_off = int(sections["7"]["data_offset"], 16)
        sec7 = block[sec7_off : sec7_off + sections["7"]["size"]]
        hits: list[dict[str, str]] = []
        for pos in range(0, max(0, len(sec7) - 7), 8):
            key, value = struct.unpack_from("<II", sec7, pos)
            if key == 0 and value == 0:
                break
            if key in DCB_SECTION7_KEYS:
                hits.append({"key": fmt(key), "value": fmt(value)})
        if hits != [{"key": "0x00000400", "value": "0x10000000"}, {"key": "0x00000404", "value": "0x10000000"}]:
            raise ComplementError("DCB section-7 key/value pin mismatch")
        blocks.append({"block_index": block_index, "file_offset": fmt(file_off), "sha256": sha256(block), "sections": sections, "section7_hits": hits})
    if len(blocks) != 4:
        raise ComplementError("expected exactly four DCB blocks")
    if tuple(int(block["file_offset"], 16) for block in blocks) != DCB_BLOCK_FILE_OFFSETS:
        raise ComplementError("DCB block file offsets are not the exact four pinned values")
    return {"blocks": blocks, "block_file_offsets": [fmt(x) for x in DCB_BLOCK_FILE_OFFSETS], "sections": list(DCB_SECTIONS), "section7_keys": [fmt(x) for x in DCB_SECTION7_KEYS], "section7_value": fmt(DCB_SECTION7_VALUE)}


def _assert_exact_range(image: Image, start: int, end: int, digest: str, label: str) -> dict[str, Any]:
    data = image.slice(start, end)
    actual = sha256(data)
    if actual != digest:
        raise ComplementError(f"{label} exact range hash mismatch")
    return {"start": fmt(start), "end_exclusive": fmt(end), "file_offset": fmt(image.file_offset(start) or 0), "size": end - start, "sha256": actual}


def validate_setter(image: Image) -> dict[str, Any]:
    record = _assert_exact_range(image, SETTER_START, SETTER_END, SETTER_SHA256, "candidate setter")
    stores: list[dict[str, Any]] = []
    for va in range(SETTER_START, SETTER_END, 4):
        word = image.word(va)
        if word is None:
            raise ComplementError("candidate setter is not fully mapped")
        mem = is_mem_unsigned(word)
        if mem is not None and mem[0] == "STR":
            stores.append({"va": fmt(va), "kind": "STR", "width": mem[1], "base_register": f"X{mem[3]}", "offset": mem[2], "source_register": f"X{mem[4]}"})
    if len(stores) != 5:
        raise ComplementError("candidate setter store count changed")
    return {"range": record, "direct_caller": fmt(SETTER_CALLER), "stores": stores, "caller_range": {"start": fmt(SETTER_CALLER_RANGE[0]), "end_exclusive": fmt(SETTER_CALLER_RANGE[1]), "status": "BOUNDED_DIRECT_EDGE_ONLY"}}


def resolve_setter_caller(image: Image, setter: int = SETTER_START, caller_va: int = SETTER_CALLER, bounds: tuple[int, int] = SETTER_CALLER_RANGE) -> dict[str, Any]:
    start, end = bounds
    if not (start <= caller_va < end):
        raise ComplementError("setter caller is outside its bounded range")
    word = image.word(caller_va)
    target = None if word is None else decode_bl_target(word, caller_va)
    if target != setter:
        raise ComplementError("candidate setter direct caller target mismatch")
    direct_calls = [{"va": fmt(caller_va), "target": fmt(target), "kind": "BL"}]
    # The caller's arguments are loaded from a runtime object.  Record the
    # direct edge but leave all values UNKNOWN; this is a deliberate no-alias
    # boundary, not a missing implementation.
    return {"range": {"start": fmt(start), "end_exclusive": fmt(end), "size": end - start}, "direct_calls": direct_calls, "argument_origins": {f"X{i}": "UNKNOWN_RUNTIME_OBJECT_FIELD" for i in range(4)}, "status": "SUPPORTED_DIRECT_CALLER_EDGE_ARGUMENTS_UNKNOWN", "current_destination": "UNKNOWN"}


def _section_hints(d020: Mapping[str, Any]) -> dict[int, int]:
    hints: dict[int, int] = {}
    for row in d020.get("section_directory_readers", []):
        try:
            va = _parse_hex(row["offset_read_va"], "directory reader")
            section = int(row["section"])
        except (KeyError, TypeError, ValueError, ComplementError):
            continue
        hints[va] = section
    return hints


def _nearby_section_hint(site_va: int, hints: Mapping[int, int]) -> dict[str, int] | None:
    """Return an auditable proximity lead, never a dataflow conclusion.

    Ties are deterministic: nearest absolute distance, then the lowest reader
    VA, then the lowest section number.  The signed distance is ``site_va -
    reader_va`` so a negative value means the site precedes the reader.
    """
    candidates = [
        (abs(site_va - reader_va), reader_va, section)
        for reader_va, section in hints.items()
        if abs(site_va - reader_va) <= SECTION_READER_PROXIMITY_THRESHOLD and section in DCB_SECTIONS
    ]
    if not candidates:
        return None
    absolute_distance, reader_va, section = min(candidates, key=lambda item: (item[0], item[1], item[2]))
    return {
        "reader_va": reader_va,
        "section": section,
        "signed_distance": site_va - reader_va,
        "absolute_distance": absolute_distance,
    }


def analyze_sites(image: Image, register_sites: Sequence[Mapping[str, Any]], computed_sites: Sequence[Mapping[str, Any]], d020: Mapping[str, Any], exclusions: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    validate_site_exclusions([*register_sites, *computed_sites], exclusions)
    hints = _section_hints(d020)
    rows: list[dict[str, Any]] = []
    excluded_positive_control = {
        "range": {"start": fmt(FALSE_NEGATIVE_START), "end_exclusive": fmt(FALSE_NEGATIVE_END), "size": FALSE_NEGATIVE_END - FALSE_NEGATIVE_START},
        "store_va": fmt(0x14868A50),
        "discriminator": "INDIRECT_OR_UNSUPPORTED",
        "status": "EXCLUDED_DEPENDENCY_POSITIVE_CONTROL",
        "reason": "Experiment 024 resolved walker owns this context; 020 false-negative remains a boundary control only.",
    }
    excluded_dependency_sites: list[dict[str, Any]] = []
    for row in [*register_sites, *computed_sites]:
        store_va = _parse_hex(row["store_va"], "site store")
        if store_va == 0x14868A50:
            continue
        if store_va == 0x148688D8:
            excluded_dependency_sites.append({"store_va": fmt(store_va), "reason": "OVERLAPS_EXPERIMENT_025_MAIN_INITIALIZER_RANGE", "semantic_claim_here": False})
            continue
        hint = _nearby_section_hint(store_va, hints)
        result = analyze_bounded_site(image, row, section_hint=None if hint is None else hint["section"])
        # A nearby directory reader is not a dataflow/call edge.  Preserve the
        # lead as explicit candidate metadata without manufacturing a DCB
        # pointer or a DCB_CONSUMER_PATH result.
        if hint is not None:
            result["discriminators"] = sorted(set(result["discriminators"]) | {"SECTION_READER_PROXIMITY_ONLY"})
            result["status"] = "HYPOTHESIS"
            result["dcb_identity"] = {
                "section": hint["section"],
                "reader_va": fmt(hint["reader_va"]),
                "signed_distance": hint["signed_distance"],
                "absolute_distance": hint["absolute_distance"],
                "threshold": fmt(SECTION_READER_PROXIMITY_THRESHOLD),
                "identity": "SECTION_READER_PROXIMITY_ONLY",
                "current_runtime_pointer": "UNKNOWN",
                "link_proof": "NONE",
            }
        rows.append(result)
    rows.sort(key=lambda row: _parse_hex(row["store_va"], "result store"))
    counts: dict[str, int] = {}
    for row in rows:
        for discriminator in row["discriminators"]:
            counts[discriminator] = counts.get(discriminator, 0) + 1
    excluded_fn = any(_parse_hex(str(row["store_va"]), "register store") == 0x14868A50 for row in register_sites)
    return {"site_count": len(rows), "register_offset_site_count": len(register_sites) - len(excluded_dependency_sites) - int(excluded_fn), "computed_address_site_count": len(computed_sites), "excluded_dependency_sites": sorted(excluded_dependency_sites, key=lambda row: row["store_va"]), "results": rows, "discriminator_counts": dict(sorted(counts.items())), "positive_control": excluded_positive_control, "writer_absence": "UNKNOWN", "writer_absence_claim": False}


# ---------------------------------------------------------------------------
# Manifest construction and publication


def definition_of_done() -> dict[str, Any]:
    na = lambda artifact: {"status": "NOT_APPLICABLE", "reason": f"{artifact} is outside HOST_ONLY_READ_ONLY static scope; no device or persistent state was touched."}
    return {
        "date": "2026-08-26",
        "target": {"marketing_name": "A90 5G", "model": "SM-A908N", "soc": "SM8150", "soc_name": "Snapdragon 855", "binding": "PROVED_EXACT_FIRMWARE_INPUT_HASH"},
        "firmware": {"filename": XBL_NAME, "size": XBL_SIZE, "sha256": XBL_SHA256, "build": "UNKNOWN", "build_reason": "No build identifier is derived by this bounded decoder."},
        "precondition": {"status": "PROVED", "device_access": "none", "firmware_sha256": XBL_SHA256, "dcb_sha256": DCB_SHA256, "exact": "Use only the exact pinned XBL and xbl_config artifacts plus semantically validated Experiments 019, 020, 021, 024, 025, and 026."},
        "result": {"classification": "CLASS C (TRANSFORM ONLY)", "status": "BOUNDED_CONSUMER_WRITER_COMPLEMENT_UNKNOWN_GLOBAL", "proved": "Exact input/dependency identity, DCB section-7 pins, dependency site sets, bounded CFG/dataflow rules, exclusion boundaries, and symbolic target distinctions are pinned.", "supported": "No DCB consumer or MC/SHRM current destination is established; proximity-only leads remain explicitly non-destination hypotheses or UNKNOWN.", "unknown": "Runtime base/current destination, execution/order, indirect aliases, unsupported forms, protected-memory semantics, and global consumer/writer presence remain UNKNOWN."},
        "non_applicable_artifacts": {"boot": na("boot artifacts"), "dtb": na("DTB artifacts"), "kernel": na("kernel artifacts"), "research_kernel": na("research-kernel artifacts")},
        "live_repetitions": {"status": "NOT_APPLICABLE", "reason": "Host-only static analysis; no live device repetition."},
        "dmesg": {"status": "NOT_APPLICABLE", "reason": "No device boot or runtime action."},
        "log": {"status": "NOT_APPLICABLE", "reason": "No live runtime log was generated."},
        "rollback": {"status": "NOT_APPLICABLE", "reason": "No device, firmware, or persistent state was modified."},
        "recovery": {"status": "NOT_APPLICABLE", "reason": "No device action occurred."},
        "negative_controls": {"status": "PASS", "description": "Exact input/hash/ELF/dependency mismatch, semantic dependency mutation, exclusion overlap, decoder masks, clobbers/control flow, unsupported paths, symbolic-vs-current distinction, and no-clobber publication fail closed."},
        "deterministic_repetition_validation": {"repetition_count": 2, "repetition_unit": "fresh host manifest generations", "repetition_result": "BYTE_IDENTICAL", "validation_count": 7, "validation_checks": ["exact XBL and xbl_config size/SHA-256", "semantic dependency validation for 019/020/021/024/025/026", "exact 67 plus 8 dependency site set accounting", "024-026 overlap exclusion and 020 positive-control boundary", "bounded decoder/dataflow and unsupported-form gates", "synthetic hostile and exact-image focused tests", "O_EXCL/O_NOFOLLOW mode0644 and deterministic fresh publication"]},
        "reproducible_command_template": "python3 tools/sm8150_dcb_consumer_writer_complement.py --firmware-dir <exact-firmware-dir> --manifest-dir <public-manifest-dir> --output <public-manifest-path>",
        "tool_and_build": {"tool": "sm8150_dcb_consumer_writer_complement.py", "build": "UNKNOWN", "build_reason": "Python host transform; no firmware build is produced."},
    }


def build_manifest(firmware_dir: Path = FIRMWARE_DIR, manifest_dir: Path = MANIFEST_DIR) -> dict[str, Any]:
    xbl_data = load_exact(firmware_dir / XBL_NAME, XBL_SIZE, XBL_SHA256, XBL_NAME)
    dcb_data = load_exact(firmware_dir / DCB_NAME, DCB_SIZE, DCB_SHA256, DCB_NAME)
    image = Image(xbl_data)
    dependencies, dependency_hashes = load_dependency_manifests(manifest_dir)
    d019 = dependencies["019-dcb-register-programming-20260826-01.manifest.json"]
    d020 = dependencies["020-xbl-dcb-consumer-xref-20260826-01.manifest.json"]
    d021 = dependencies["021-dcb-delivery-paths-20260826-01.manifest.json"]
    d024 = dependencies["024-xbl-six-byte-walker-20260826-01.manifest.json"]
    d025 = dependencies["025-xbl-platform-query-binding-20260826-01.manifest.json"]
    d026 = dependencies["026-xbl-dispatch-order-slot-escape-20260826-01.manifest.json"]
    dcb = validate_dcb_image(dcb_data)
    register_sites, computed_sites = exact_site_sets(d020, image)
    exclusions = dependency_exclusion_ranges(dependencies)
    site_result = analyze_sites(image, register_sites, computed_sites, d020, exclusions)
    setter = validate_setter(image)
    caller = resolve_setter_caller(image)
    # The positive-control range is checked by the dependency and by this
    # experiment's exclusion record, without re-claiming its walker semantics.
    positive_control = d020["known_narrow_model_false_negative"]
    if _parse_hex(positive_control["range"]["start"], "positive control start") != FALSE_NEGATIVE_START:
        raise ComplementError("positive-control start changed")
    dependencies_public = {
        name: {"filename": name, "size": DEPENDENCY_SPECS[name][0], "sha256": dependency_hashes[name], "semantic_validation": "PASS"}
        for name in sorted(dependency_hashes)
    }
    result_rows = site_result["results"]
    claims = {
        "PROVED": [
            "Exact XBL and xbl_config artifacts are size/SHA-256 bound before analysis.",
            "Experiment 019 section identities {6,7,8,10,11,12} and section-7 keys 0x400/0x404 with value 0x10000000 are revalidated across all four DCB blocks.",
            "Experiment 020 supplies exactly 67 register-offset loop sites and eight computed-address idioms; this result analyzes all eight computed idioms, of which three are loop records.",
            "The Experiment 020 six-byte false-negative range and the Experiment 024 resolved walker are retained as an excluded positive-control boundary, not a new semantic claim.",
            "All ranges claimed by Experiments 025 and 026 are excluded from this experiment's semantic site model and remain dependency-only.",
            "All symbolic BASE+offset observations have current_destination UNKNOWN; no device, USB, SMC, MMIO, protected-memory, or runtime action is performed.",
            "Within this implemented bounded pass, result labels contain zero DCB_CONSUMER_PATH and zero MC_OR_SHRM_SYMBOLIC_TARGET; this is not a global absence claim.",
        ],
        "SUPPORTED": [
            "No DCB_CONSUMER_PATH or MC/SHRM current-destination result is promoted by this bounded pass; a nearby section-reader lead is recorded only as SECTION_READER_PROXIMITY_ONLY.",
            "Unresolved argument-derived addresses do not identify a controller or current DRAM destination; 0x146aea20 remains NO_TARGET_WITHIN_MODEL without a site-specific SHRM promotion.",
            "Experiment 021 direct delivery edges are included as dependency facts; unlabelled/indirect/other copy paths remain UNKNOWN.",
        ],
        "HYPOTHESIS": [
            "A nearby section-directory reader may be related to a bounded loop, but the absence of a proven dataflow/call edge leaves SECTION_READER_PROXIMITY_ONLY; this is not a DCB pointer, runtime alias, or writer identity.",
        ],
        "REFUTED": [],
        "UNKNOWN": [
            "Runtime execution, boot order, DCB section pointer/array alias, implicit base, current destination, register semantics, and post-boot mutation.",
            "BLR/BR targets, computed aliases, atomic/unrecognized instruction paths, and any path outside the dependency-provided exact site set.",
            "Whether any unrecognized or unsupported path writes a ranked MC target at runtime; this pass produces zero MC_OR_SHRM_SYMBOLIC_TARGET labels without claiming global absence.",
            "Global DCB consumer or writer presence/absence; this bounded result never claims global writer absence.",
        ],
    }
    return {
        "schema": SCHEMA,
        "experiment_id": EXPERIMENT_ID,
        "mode": MODE,
        "device_access": "none",
        "classification": "CLASS C (TRANSFORM ONLY)",
        "eligibility": "NOT_ELIGIBLE",
        "inputs": {"firmware": {"filename": XBL_NAME, "size": XBL_SIZE, "sha256": XBL_SHA256}, "dcb_image": {"filename": DCB_NAME, "size": DCB_SIZE, "sha256": DCB_SHA256, "block_file_offsets": dcb["block_file_offsets"], "sections": dcb["sections"], "blocks": dcb["blocks"]}, "dependencies": dependencies_public},
        "scope": {"site_source": "Experiment 020 dependency exact site sets only; eight idioms re-derived under the same bounded syntactic rule", "register_offset_sites": 67, "computed_address_idioms": 8, "computed_address_loop_sites": 3, "dcb_sections": list(DCB_SECTIONS), "section7_keys": [fmt(x) for x in DCB_SECTION7_KEYS], "never_scan_arbitrary_ranges": True, "global_writer_absence": "UNKNOWN", "writer_absence_claim": False},
        "dependency_exclusions": exclusions,
        "positive_control": {"source": "Experiment 020", "range": positive_control["range"], "store_va": positive_control["store_va"], "resolved_walker_exclusion": {"start": fmt(WALKER_START), "end_exclusive": fmt(WALKER_END), "owner": "Experiment 024", "semantic_claim_here": False}},
        "sites": result_rows,
        "site_summary": {k: site_result[k] for k in ("site_count", "register_offset_site_count", "computed_address_site_count", "discriminator_counts", "writer_absence", "writer_absence_claim")},
        "candidate_setter": setter,
        "candidate_setter_direct_caller": caller,
        "delivery_dependency": {"filename": "021-dcb-delivery-paths-20260826-01.manifest.json", "sha256": dependency_hashes["021-dcb-delivery-paths-20260826-01.manifest.json"], "direct_bl_count": d021["dcb_copy_paths"]["direct_bl_count"], "direct_b_count": d021["dcb_copy_paths"]["direct_b_count"], "locally_labelled_sections": d021["dcb_copy_paths"]["locally_labelled_sections"], "unlabelled_direct_bl_count": d021["dcb_copy_paths"]["unlabelled_direct_bl_count"], "global_delivery": "UNKNOWN"},
        "dependencies_semantic": {"019": {"candidate_pair_array_count": d019["candidate_pair_array_count"], "ranked_target_reach": d019["ranked_target_reach"], "section7_all_blocks": True}, "020": {"exact_register_offset_site_count": 67, "exact_computed_idiom_count": 8, "false_negative": "EXCLUDED_POSITIVE_CONTROL"}, "021": {"delivery": "UNKNOWN"}, "024": {"walker": "EXCLUDED_DEPENDENCY_ONLY", "base_currentness": d024["initializer_and_base_audit"]["base_currentness"]}, "025": {"classification": d025["classification"], "runtime_order": d025["order_and_authority"]["boot_order"], "base_preservation": d025["order_and_authority"]["base_preservation"]}, "026": {"runtime_order": d026["order_and_authority"]["runtime_order"], "writer_absence": d026["slot_escape"]["writer_absence"]}},
        "claims": claims,
        "boundary_bypass": {"status": "NOT_AUTHORIZED", "device": "none", "smc": "none", "mmio": "none", "protected_memory": "none", "reason": "Host-only read-only transform; no activation or live authority."},
        "definition_of_done": definition_of_done(),
    }


def write_no_clobber(path: Path, data: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, mode)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.chmod(path, mode)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--firmware-dir", type=Path, default=FIRMWARE_DIR)
    parser.add_argument("--manifest-dir", type=Path, default=MANIFEST_DIR)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    manifest = build_manifest(args.firmware_dir, args.manifest_dir)
    encoded = (json.dumps(manifest, sort_keys=True, indent=2, separators=(",", ": ")) + "\n").encode()
    write_no_clobber(args.output, encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
