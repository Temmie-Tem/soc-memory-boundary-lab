#!/usr/bin/env python3
"""Host-only structural cross-reference of the exact SDM855 XBL table/helper.

The analyzer consumes only the retained XBL bytes.  Stage 2 adds an explicit
AArch64 data-flow proof for the fixed helper code range that iterates the
Stage-1 u64 address table.  The analyzed code range is bounded, but its
runtime loops are zero-sentinel-only and have no independent hard iteration
cap.  Static callsites are reported as direct reachability evidence only; this
tool does not claim that either callsite executed on the retained boot.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]
FIRMWARE_DIR = REPO_ROOT / "evidence/private/004-live-firmware-readonly-20260825-01"
DEFAULT_XBL = FIRMWARE_DIR / "xbl--sdb1.bin"

XBL_SIZE = 4_194_304
XBL_SHA256 = "e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37"

TABLE_VADDR = 0x146B1218
TABLE_FILE_OFFSET = 0x630B8
TABLE_ENTRY_COUNT = 122
TABLE_BYTE_LENGTH = (TABLE_ENTRY_COUNT + 1) * 8
TABLE_TERMINATOR_VADDR = TABLE_VADDR + TABLE_ENTRY_COUNT * 8
TABLE_SHA256 = "d5042980f035d3d52974536115074940b4b1858cb30a47699e7553f1b200da07"

# The first 120 entries are exactly thirty repeated four-instance groups.
# These page bases are an evidence shape, not undocumented block/register
# names.  The output reports structure and coverage rather than inventing
# labels for the suffixes in those groups.
MC_INSTANCE_PAGE_BASES = (0x09260000, 0x092E0000, 0x09360000, 0x093E0000)
MC_GROUP_COUNT = 30
MC_GROUP_WIDTH = 4
MC_ADDRESS_COUNT = MC_GROUP_COUNT * MC_GROUP_WIDTH
GLOBAL_ADDRESS_COUNT = 2

HELPER_VADDR = 0x146AE138
HELPER_END_VADDR = 0x146AE18C
HELPER_FILE_OFFSET = 0x62318
HELPER_SIZE = HELPER_END_VADDR - HELPER_VADDR
HELPER_SHA256 = "f325a8bf4c8e9ff7c21a0d20752e742cd8e047422e9eff5c301bf3042a95e138"
LOCAL_BUFFER_VADDR = 0x146BF300
FILL_VALUE = 0xDEDEDEDE

DIRECT_CALLER_VADDRS = (0x146AE26C, 0x14839F44)
DIRECT_CALLER_FILE_OFFSETS = (0x6244C, 0x20F44)
DIRECT_CALLER_WORDS = (0x97FFFFB3, 0x97F9D07D)

HELPER_INSTRUCTION_WORDS = {
    HELPER_VADDR + 0x00: 0x529E6008,
    HELPER_VADDR + 0x04: 0x72A28D68,
    HELPER_VADDR + 0x08: 0x529BDBCB,
    HELPER_VADDR + 0x0C: 0xF0000009,
    HELPER_VADDR + 0x10: 0x2A1F03EA,
    HELPER_VADDR + 0x14: 0x72BBDBCB,
    HELPER_VADDR + 0x18: 0xAA0803EC,
    HELPER_VADDR + 0x1C: 0x91086129,
    HELPER_VADDR + 0x20: 0x14000003,
    HELPER_VADDR + 0x24: 0xB800458B,
    HELPER_VADDR + 0x28: 0x1100054A,
    HELPER_VADDR + 0x2C: 0xF86A592D,
    HELPER_VADDR + 0x30: 0xB5FFFFAD,
    HELPER_VADDR + 0x34: 0x2A1F03EB,
    HELPER_VADDR + 0x38: 0x14000004,
    HELPER_VADDR + 0x3C: 0xB940014A,
    HELPER_VADDR + 0x40: 0x1100056B,
    HELPER_VADDR + 0x44: 0xB800450A,
    HELPER_VADDR + 0x48: 0xF86B592A,
    HELPER_VADDR + 0x4C: 0xB5FFFF8A,
    HELPER_VADDR + 0x50: 0xD65F03C0,
}

TOP_CANDIDATES: tuple[dict[str, object], ...] = (
    {
        "key": "mc_plus_0x400",
        "label": "qhs_mc +0x400",
        "addresses": (0x09260400, 0x092E0400, 0x09360400, 0x093E0400),
    },
    {
        "key": "mc_plus_0x404",
        "label": "qhs_mc +0x404",
        "addresses": (0x09260404, 0x092E0404, 0x09360404, 0x093E0404),
    },
    {
        "key": "mccc_plus_0x118",
        "label": "qhs_mccc +0x118",
        "addresses": (0x09250118, 0x092D0118, 0x09350118, 0x093D0118),
    },
    {
        "key": "mc_plus_0x4d0",
        "label": "qhs_mc +0x4d0",
        "addresses": (0x092604D0, 0x092E04D0, 0x093604D0, 0x093E04D0),
    },
    {
        "key": "mccc_master_plus_0x294",
        "label": "qhs_mccc_master +0x294",
        "addresses": (0x090B0294,),
    },
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hex(value: int, width: int | None = None) -> str:
    return f"0x{value:0{width}x}" if width else f"0x{value:x}"


@dataclass(frozen=True)
class Segment:
    offset: int
    vaddr: int
    filesz: int
    memsz: int
    flags: int

    @property
    def executable(self) -> bool:
        return bool(self.flags & 1)  # PF_X


class ElfImage:
    """Minimal ELF64 mapper with strict PT_LOAD validation."""

    def __init__(self, data: bytes) -> None:
        if len(data) < 64:
            raise ValueError("ELF header is truncated")
        if data[:4] != b"\x7fELF":
            raise ValueError("input is not an ELF image")
        if data[4] != 2 or data[5] != 1:
            raise ValueError("input is not a little-endian ELF64 image")
        if data[6] != 1:
            raise ValueError("unsupported ELF identification version")
        self.data = data
        self.segments = self._parse_segments()

    def _parse_segments(self) -> list[Segment]:
        phoff = struct.unpack_from("<Q", self.data, 0x20)[0]
        phentsize = struct.unpack_from("<H", self.data, 0x36)[0]
        phnum = struct.unpack_from("<H", self.data, 0x38)[0]
        if phentsize < 56:
            raise ValueError("ELF64 program-header entry is too short")
        table_end = phoff + phentsize * phnum
        if phoff < 64 or table_end > len(self.data):
            raise ValueError("ELF64 program-header table is truncated")

        segments: list[Segment] = []
        for index in range(phnum):
            base = phoff + index * phentsize
            p_type, p_flags = struct.unpack_from("<II", self.data, base)
            p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz = struct.unpack_from(
                "<QQQQQ", self.data, base + 8
            )
            if p_type != 1:
                continue
            if p_memsz < p_filesz:
                raise ValueError("ELF64 PT_LOAD memory size is smaller than file size")
            if not p_filesz:
                continue
            if p_offset > len(self.data) or p_filesz > len(self.data) - p_offset:
                raise ValueError("ELF64 PT_LOAD crosses the input")
            segment = Segment(p_offset, p_vaddr, p_filesz, p_memsz, p_flags)
            # Ambiguous file or virtual mappings are unsafe for exact evidence,
            # even if two overlapping segments happen to contain equal bytes.
            for prior in segments:
                file_overlap = not (
                    segment.offset + segment.filesz <= prior.offset
                    or prior.offset + prior.filesz <= segment.offset
                )
                vaddr_overlap = not (
                    segment.vaddr + segment.filesz <= prior.vaddr
                    or prior.vaddr + prior.filesz <= segment.vaddr
                )
                if file_overlap or vaddr_overlap:
                    raise ValueError("overlapping file-backed PT_LOAD segments")
            segments.append(segment)
        if not segments:
            raise ValueError("ELF64 image has no file-backed PT_LOAD segment")
        return segments

    def _matches(self, vaddr: int, size: int) -> list[Segment]:
        if size < 0:
            raise ValueError("mapping size cannot be negative")
        return [
            segment
            for segment in self.segments
            if segment.vaddr <= vaddr
            and vaddr + size <= segment.vaddr + segment.filesz
        ]

    def segment_for_vaddr(self, vaddr: int, size: int = 1) -> Segment:
        matches = self._matches(vaddr, size)
        if not matches:
            raise ValueError(f"virtual address {_hex(vaddr)} is not file-backed")
        if len(matches) != 1:
            raise ValueError(f"virtual address {_hex(vaddr)} has ambiguous mapping")
        return matches[0]

    def vaddr_to_offset(self, vaddr: int, size: int = 1) -> int:
        matches = self._matches(vaddr, size)
        if not matches:
            raise ValueError(f"virtual address {_hex(vaddr)} is not file-backed")
        offsets = {segment.offset + vaddr - segment.vaddr for segment in matches}
        if len(offsets) != 1:
            raise ValueError(f"virtual address {_hex(vaddr)} has ambiguous mapping")
        return next(iter(offsets))

    def offset_to_vaddr(self, offset: int, size: int = 1) -> int:
        if size < 0:
            raise ValueError("mapping size cannot be negative")
        matches = [
            segment
            for segment in self.segments
            if segment.offset <= offset
            and offset + size <= segment.offset + segment.filesz
        ]
        if not matches:
            raise ValueError(f"file offset {_hex(offset)} is not PT_LOAD-backed")
        vaddrs = {segment.vaddr + offset - segment.offset for segment in matches}
        if len(vaddrs) != 1:
            raise ValueError(f"file offset {_hex(offset)} has ambiguous mapping")
        return next(iter(vaddrs))

    def read_vaddr(self, vaddr: int, size: int) -> bytes:
        offset = self.vaddr_to_offset(vaddr, size)
        return self.data[offset : offset + size]

    def u32(self, vaddr: int) -> int:
        return struct.unpack("<I", self.read_vaddr(vaddr, 4))[0]

    def u64(self, vaddr: int) -> int:
        return struct.unpack("<Q", self.read_vaddr(vaddr, 8))[0]

    def executable_words(self) -> Iterable[tuple[int, int, int]]:
        """Yield (virtual address, file offset, word) from executable PT_LOADs."""

        for segment in self.segments:
            if not segment.executable:
                continue
            end = segment.offset + segment.filesz
            # Find the first file offset whose mapped virtual address is
            # instruction-aligned.  Do this through the complete mapping
            # expression so segments whose file offset and VA have different
            # modulo-4 alignment remain correct.
            first = segment.offset
            while first < end and (
                segment.vaddr + first - segment.offset
            ) & 3:
                first += 1
            for file_offset in range(first, end - 3, 4):
                yield (
                    segment.vaddr + file_offset - segment.offset,
                    file_offset,
                    struct.unpack_from("<I", self.data, file_offset)[0],
                )


def _sign_extend(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def _decode_aarch64_bl(word: int, pc: int) -> int:
    if word & 0xFC000000 != 0x94000000:
        raise ValueError(f"{_hex(word, 8)} at {_hex(pc)} is not AArch64 BL")
    return pc + (_sign_extend(word & 0x03FFFFFF, 26) << 2)


def _decode_aarch64_b(word: int, pc: int) -> int:
    if word & 0xFC000000 != 0x14000000:
        raise ValueError(f"{_hex(word, 8)} at {_hex(pc)} is not AArch64 B")
    return pc + (_sign_extend(word & 0x03FFFFFF, 26) << 2)


def _decode_aarch64_cbnz(word: int, pc: int) -> tuple[int, int, int]:
    """Return (width_bits, Rt, target) for CBNZ."""

    if word & 0x7F000000 != 0x35000000:
        raise ValueError(f"{_hex(word, 8)} at {_hex(pc)} is not AArch64 CBNZ")
    width = 64 if (word >> 31) & 1 else 32
    register = word & 0x1F
    immediate = _sign_extend((word >> 5) & 0x7FFFF, 19) << 2
    return width, register, pc + immediate


def _decode_aarch64_adrp(word: int, pc: int) -> tuple[int, int]:
    if word & 0x9F000000 != 0x90000000:
        raise ValueError(f"{_hex(word, 8)} at {_hex(pc)} is not AArch64 ADRP")
    rd = word & 0x1F
    immlo = (word >> 29) & 0x3
    immhi = (word >> 5) & 0x7FFFF
    immediate = _sign_extend((immhi << 2) | immlo, 21) << 12
    return rd, (pc & ~0xFFF) + immediate


def _decode_aarch64_add_immediate(
    word: int, pc: int | None = None
) -> tuple[int, int, int]:
    """Return (Rd, Rn, immediate) for 64-bit non-setting ADD-immediate."""

    if word & 0x7F000000 != 0x11000000:
        raise ValueError(f"{_hex(word, 8)} is not AArch64 ADD-immediate")
    if not ((word >> 31) & 1) or (word >> 30) & 1 or (word >> 29) & 1:
        raise ValueError("ADD-immediate is not the required 64-bit non-setting form")
    rd = word & 0x1F
    rn = (word >> 5) & 0x1F
    immediate = (word >> 10) & 0xFFF
    if (word >> 22) & 1:
        immediate <<= 12
    return rd, rn, immediate


def _decode_aarch64_add_w_immediate(word: int) -> tuple[int, int, int]:
    """Return (Wd, Wn, immediate) for 32-bit non-setting ADD-immediate."""

    if word & 0x7F000000 != 0x11000000:
        raise ValueError(f"{_hex(word, 8)} is not AArch64 ADD-immediate")
    if (word >> 31) & 1 or (word >> 30) & 1 or (word >> 29) & 1:
        raise ValueError("ADD-immediate is not the required 32-bit non-setting form")
    rd = word & 0x1F
    rn = (word >> 5) & 0x1F
    immediate = (word >> 10) & 0xFFF
    if (word >> 22) & 1:
        immediate <<= 12
    return rd, rn, immediate


def _decode_aarch64_mov_wide(word: int) -> tuple[str, int, int, int, int]:
    """Return (MOVZ/MOVK, width_bits, Rd, imm16, shift_bits)."""

    opcode = word & 0x7F800000
    if opcode == 0x52800000:
        operation = "MOVZ"
    elif opcode == 0x72800000:
        operation = "MOVK"
    else:
        raise ValueError(f"{_hex(word, 8)} is not AArch64 MOVZ/MOVK")
    width = 64 if (word >> 31) & 1 else 32
    halfword = (word >> 21) & 0x3
    if width == 32 and halfword > 1:
        raise ValueError("32-bit MOV-wide shift exceeds 16 bits")
    return operation, width, word & 0x1F, (word >> 5) & 0xFFFF, halfword * 16


def _decode_aarch64_mov_register(word: int) -> tuple[int, int]:
    """Decode the 64-bit MOV Xd,Xn ORR alias used for X12."""

    if word & 0xFFE0FFE0 != 0xAA0003E0:
        raise ValueError(f"{_hex(word, 8)} is not MOV register alias")
    return word & 0x1F, (word >> 16) & 0x1F


def _decode_aarch64_ldr_register_offset(word: int) -> dict[str, object]:
    """Decode LDR Xt,[Xn,Wm,UXTW #3], the table-entry load form."""

    if word & 0xFFE0FC00 != 0xF8605800:
        raise ValueError(f"{_hex(word, 8)} is not 64-bit LDR register-offset")
    option = (word >> 13) & 0x7
    scale = (word >> 12) & 1
    if option != 0x2 or scale != 1:
        raise ValueError("LDR register-offset is not UXTW scaled by 8")
    return {
        "kind": "LDR",
        "width_bits": 64,
        "target_register": word & 0x1F,
        "base_register": (word >> 5) & 0x1F,
        "index_register": (word >> 16) & 0x1F,
        "index_width": 32,
        "extend": "UXTW",
        "scale": 3,
    }


def _decode_aarch64_ldr_unsigned_immediate(word: int) -> dict[str, object]:
    """Decode LDR Wt,[Xn,#imm], the MMIO read form."""

    if word & 0xFFC00000 != 0xB9400000:
        raise ValueError(f"{_hex(word, 8)} is not 32-bit LDR unsigned-immediate")
    return {
        "kind": "LDR",
        "width_bits": 32,
        "target_register": word & 0x1F,
        "base_register": (word >> 5) & 0x1F,
        "immediate": ((word >> 10) & 0xFFF) * 4,
    }


def _decode_aarch64_str_post_index(word: int) -> dict[str, object]:
    """Decode STR Wt,[Xn],#imm9, the local-buffer write form."""

    if word & 0xFFE00C00 != 0xB8000400:
        raise ValueError(f"{_hex(word, 8)} is not 32-bit STR post-index")
    if (word >> 10) & 0x3 != 1:
        raise ValueError("STR is not post-index addressing")
    return {
        "kind": "STR",
        "width_bits": 32,
        "source_register": word & 0x1F,
        "base_register": (word >> 5) & 0x1F,
        "immediate": _sign_extend((word >> 12) & 0x1FF, 9),
    }


def _decode_aarch64_memory_instruction(word: int) -> dict[str, object] | None:
    for decoder in (
        _decode_aarch64_ldr_register_offset,
        _decode_aarch64_ldr_unsigned_immediate,
        _decode_aarch64_str_post_index,
    ):
        try:
            return decoder(word)
        except ValueError:
            continue
    return None


def _validate_store_bases(
    store_bases: Iterable[int], table_pointer_registers: Iterable[int]
) -> None:
    observed = list(store_bases)
    if observed != [12, 8]:
        raise ValueError("identified store bases are not exactly X12 and X8")
    unsafe = set(observed) & set(table_pointer_registers)
    if unsafe:
        raise ValueError(
            "table-derived pointer is used as a store base: "
            + ", ".join(f"X{register}" for register in sorted(unsafe))
        )


def _helper_words(image: ElfImage) -> dict[int, int]:
    return {
        vaddr: image.u32(vaddr)
        for vaddr in range(HELPER_VADDR, HELPER_END_VADDR, 4)
    }


def parse_u64_table(image: ElfImage) -> dict[str, object]:
    """Validate the exact 122-entry u64 table and its inclusive hash."""

    file_offset = image.vaddr_to_offset(TABLE_VADDR, TABLE_BYTE_LENGTH)
    if file_offset != TABLE_FILE_OFFSET:
        raise ValueError(
            f"table VA {_hex(TABLE_VADDR)} maps to {_hex(file_offset)}, "
            f"expected {_hex(TABLE_FILE_OFFSET)}"
        )

    values: list[int] = []
    terminator_index: int | None = None
    for index in range(TABLE_ENTRY_COUNT + 1):
        value = image.u64(TABLE_VADDR + index * 8)
        if value == 0:
            terminator_index = index
            break
        # The exact table contains 32-bit, 4-byte-aligned MMIO addresses.  This
        # structural check catches accidental pointers and malformed entries
        # without assigning undocumented register semantics.
        if value >= (1 << 32) or value & 0x3:
            raise ValueError(
                f"table entry {index} is not a 32-bit aligned MMIO address: {_hex(value)}"
            )
        values.append(value)
    if terminator_index is None:
        raise ValueError("table has no u64 zero terminator within the pinned bound")
    if terminator_index != TABLE_ENTRY_COUNT:
        raise ValueError(
            f"table terminator index is {terminator_index}, expected {TABLE_ENTRY_COUNT}"
        )

    table_segment = image.segment_for_vaddr(TABLE_VADDR, TABLE_BYTE_LENGTH)
    table_bytes = image.read_vaddr(TABLE_VADDR, TABLE_BYTE_LENGTH)
    table_hash = sha256(table_bytes)
    if table_hash != TABLE_SHA256:
        raise ValueError(f"table SHA-256 mismatch: {table_hash}")

    return {
        "virtual_address": _hex(TABLE_VADDR),
        "file_offset": _hex(file_offset),
        "entry_count": len(values),
        "terminator_index": terminator_index,
        "terminator_virtual_address": _hex(TABLE_TERMINATOR_VADDR),
        "byte_length": len(table_bytes),
        "sha256": table_hash,
        "source_pt_load_pf_w": bool(table_segment.flags & 2),
        "all_entries_nonzero": all(values),
        "terminator_is_zero": image.u64(TABLE_TERMINATOR_VADDR) == 0,
        "values": tuple(values),
    }


def _expect_word(words: dict[int, int], address: int, expected: int) -> None:
    actual = words.get(address)
    if actual != expected:
        raise ValueError(
            f"helper instruction at {_hex(address)} is {_hex(actual or 0, 8)}, "
            f"expected {_hex(expected, 8)}"
        )


def validate_helper(
    image: ElfImage, table_values: Iterable[int] | None = None
) -> dict[str, object]:
    """Validate the bounded helper's exact AArch64 data flow."""

    file_offset = image.vaddr_to_offset(HELPER_VADDR, HELPER_SIZE)
    if file_offset != HELPER_FILE_OFFSET:
        raise ValueError(
            f"helper VA {_hex(HELPER_VADDR)} maps to {_hex(file_offset)}, "
            f"expected {_hex(HELPER_FILE_OFFSET)}"
        )
    helper_bytes = image.read_vaddr(HELPER_VADDR, HELPER_SIZE)
    helper_hash = sha256(helper_bytes)
    if helper_hash != HELPER_SHA256:
        raise ValueError(f"helper SHA-256 mismatch: {helper_hash}")

    words = _helper_words(image)
    if set(words) != set(HELPER_INSTRUCTION_WORDS):
        raise ValueError("bounded helper instruction range is incomplete")
    for address, expected in HELPER_INSTRUCTION_WORDS.items():
        _expect_word(words, address, expected)

    adrp_rd, table_page = _decode_aarch64_adrp(
        words[HELPER_VADDR + 0x0C], HELPER_VADDR + 0x0C
    )
    add_rd, add_rn, add_immediate = _decode_aarch64_add_immediate(
        words[HELPER_VADDR + 0x1C]
    )
    if (adrp_rd, table_page) != (9, 0x146B1000):
        raise ValueError("helper ADRP does not form the pinned table page")
    if (add_rd, add_rn, add_immediate) != (9, 9, 0x218):
        raise ValueError("helper ADD does not form the pinned table address")
    table_pointer = table_page + add_immediate
    if table_pointer != TABLE_VADDR:
        raise ValueError("helper table pointer differs from pinned table VA")

    local_z = _decode_aarch64_mov_wide(words[HELPER_VADDR])
    local_k = _decode_aarch64_mov_wide(words[HELPER_VADDR + 0x04])
    if local_z != ("MOVZ", 32, 8, 0xF300, 0) or local_k != (
        "MOVK",
        32,
        8,
        0x146B,
        16,
    ):
        raise ValueError("helper local-buffer MOVZ/MOVK encodings are unexpected")
    local_buffer = (local_z[3] << local_z[4]) | (local_k[3] << local_k[4])
    if local_buffer != LOCAL_BUFFER_VADDR:
        raise ValueError("helper local-buffer address differs from 0x146bf300")
    try:
        image.vaddr_to_offset(local_buffer, 4)
    except ValueError:
        local_buffer_file_backed = False
    else:
        raise ValueError("fixed destination unexpectedly has a file-bearing PT_LOAD")

    fill_z = _decode_aarch64_mov_wide(words[HELPER_VADDR + 0x08])
    fill_k = _decode_aarch64_mov_wide(words[HELPER_VADDR + 0x14])
    if fill_z != ("MOVZ", 32, 11, 0xDEDE, 0) or fill_k != (
        "MOVK",
        32,
        11,
        0xDEDE,
        16,
    ):
        raise ValueError("helper fill-value MOVZ/MOVK encodings are unexpected")
    fill_value = (fill_z[3] << fill_z[4]) | (fill_k[3] << fill_k[4])
    if fill_value != FILL_VALUE:
        raise ValueError("helper fill value differs from 0xdededede")

    alias_destination, alias_source = _decode_aarch64_mov_register(
        words[HELPER_VADDR + 0x18]
    )
    if (alias_destination, alias_source) != (12, 8):
        raise ValueError("helper first-loop buffer alias is not X12 <- X8")

    first_index = _decode_aarch64_add_w_immediate(words[HELPER_VADDR + 0x28])
    second_index = _decode_aarch64_add_w_immediate(words[HELPER_VADDR + 0x40])
    if first_index != (10, 10, 1) or second_index != (11, 11, 1):
        raise ValueError("helper loop index increments are unexpected")

    first_branch = _decode_aarch64_b(words[HELPER_VADDR + 0x20], HELPER_VADDR + 0x20)
    first_cbnz = _decode_aarch64_cbnz(
        words[HELPER_VADDR + 0x30], HELPER_VADDR + 0x30
    )
    second_branch = _decode_aarch64_b(words[HELPER_VADDR + 0x38], HELPER_VADDR + 0x38)
    second_cbnz = _decode_aarch64_cbnz(
        words[HELPER_VADDR + 0x4C], HELPER_VADDR + 0x4C
    )
    if first_branch != HELPER_VADDR + 0x2C:
        raise ValueError("first loop branch does not reach its table-entry test")
    if first_cbnz != (64, 13, HELPER_VADDR + 0x24):
        raise ValueError("first loop CBNZ does not guard its fill store")
    if second_branch != HELPER_VADDR + 0x48:
        raise ValueError("second loop branch does not reach its table-entry test")
    if second_cbnz != (64, 10, HELPER_VADDR + 0x3C):
        raise ValueError("second loop CBNZ does not guard its MMIO read")

    first_load = _decode_aarch64_ldr_register_offset(words[HELPER_VADDR + 0x2C])
    second_load = _decode_aarch64_ldr_register_offset(words[HELPER_VADDR + 0x48])
    first_store = _decode_aarch64_str_post_index(words[HELPER_VADDR + 0x24])
    mmio_read = _decode_aarch64_ldr_unsigned_immediate(words[HELPER_VADDR + 0x3C])
    second_store = _decode_aarch64_str_post_index(words[HELPER_VADDR + 0x44])
    expected_first_load = {
        "kind": "LDR",
        "width_bits": 64,
        "target_register": 13,
        "base_register": 9,
        "index_register": 10,
        "index_width": 32,
        "extend": "UXTW",
        "scale": 3,
    }
    expected_second_load = {
        "kind": "LDR",
        "width_bits": 64,
        "target_register": 10,
        "base_register": 9,
        "index_register": 11,
        "index_width": 32,
        "extend": "UXTW",
        "scale": 3,
    }
    expected_mmio_read = {
        "kind": "LDR",
        "width_bits": 32,
        "target_register": 10,
        "base_register": 10,
        "immediate": 0,
    }
    if first_load != expected_first_load:
        raise ValueError("first loop table-entry load has unexpected registers")
    if second_load != expected_second_load:
        raise ValueError("second loop table-entry load has unexpected registers")
    if mmio_read != expected_mmio_read:
        raise ValueError("MMIO read is not LDR W10,[X10]")
    if first_store != {
        "kind": "STR",
        "width_bits": 32,
        "source_register": 11,
        "base_register": 12,
        "immediate": 4,
    }:
        raise ValueError("first loop does not fill through X12 by four bytes")
    if second_store != {
        "kind": "STR",
        "width_bits": 32,
        "source_register": 10,
        "base_register": 8,
        "immediate": 4,
    }:
        raise ValueError("second loop does not store W10 through X8 by four bytes")

    memory_operations: list[dict[str, object]] = []
    for address, word in words.items():
        operation = _decode_aarch64_memory_instruction(word)
        if operation is not None:
            memory_operations.append({"virtual_address": _hex(address), **operation})
    if len(memory_operations) != 5:
        raise ValueError("bounded helper memory-operation inventory is incomplete")
    store_bases = [
        int(operation["base_register"])
        for operation in memory_operations
        if operation["kind"] == "STR"
    ]
    table_pointer_registers = {9, 10, 13}
    _validate_store_bases(store_bases, table_pointer_registers)
    if table_values is not None and LOCAL_BUFFER_VADDR in set(table_values):
        raise ValueError("fixed local destination is also present as a table address")

    return {
        "virtual_address": _hex(HELPER_VADDR),
        "end_exclusive": _hex(HELPER_END_VADDR),
        "file_offset": _hex(file_offset),
        "byte_length": HELPER_SIZE,
        "sha256": helper_hash,
        "analysis_range_bounded": True,
        "traversal_bound": "ZERO_SENTINEL_ONLY",
        "hard_iteration_limit": False,
        "static_pinned_entry_count": TABLE_ENTRY_COUNT,
        "instruction_pins_verified": True,
        "table_pointer": {
            "adrp_virtual_address": _hex(HELPER_VADDR + 0x0C),
            "adrp_page": _hex(table_page),
            "add_virtual_address": _hex(HELPER_VADDR + 0x1C),
            "add_immediate": _hex(add_immediate),
            "resolved_virtual_address": _hex(table_pointer),
            "cursor_register": "X9",
        },
        "destination_buffer": {
            "virtual_address": _hex(local_buffer),
            "fill_value": _hex(fill_value, 8),
            "file_backed": local_buffer_file_backed,
            "first_loop_store_base": "X12",
            "second_loop_store_base": "X8",
            "separate_from_table": True,
        },
        "first_loop": {
            "table_load_virtual_address": _hex(HELPER_VADDR + 0x2C),
            "table_load_width_bits": 64,
            "loaded_pointer_register": "X13",
            "index_register": "W10",
            "index_start": 0,
            "index_increment": 1,
            "terminates_on_zero": True,
            "fill_store_virtual_address": _hex(HELPER_VADDR + 0x24),
            "fill_store_source": "W11",
            "fill_store_base": "X12",
            "static_pinned_entry_count": TABLE_ENTRY_COUNT,
            "traversal_bound": "ZERO_SENTINEL_ONLY",
            "hard_iteration_limit": False,
        },
        "second_loop": {
            "table_load_virtual_address": _hex(HELPER_VADDR + 0x48),
            "table_load_width_bits": 64,
            "loaded_pointer_register": "X10",
            "index_register": "W11",
            "index_start": 0,
            "index_increment": 1,
            "terminates_on_zero": True,
            "mmio_read_virtual_address": _hex(HELPER_VADDR + 0x3C),
            "mmio_read": "LDR W10,[X10]",
            "result_store_virtual_address": _hex(HELPER_VADDR + 0x44),
            "result_store": "STR W10,[X8],#4",
            "static_pinned_entry_count": TABLE_ENTRY_COUNT,
            "traversal_bound": "ZERO_SENTINEL_ONLY",
            "hard_iteration_limit": False,
        },
        "memory_operations": memory_operations,
        "store_base_registers": [f"X{base}" for base in store_bases],
        "table_pointer_registers": ["X9", "X10", "X13"],
        "table_pointer_store_bases": [],
        "table_pointer_never_used_as_store_base": True,
        "static_direction": "TABLE_U64_POINTERS_READ_MMIO_VALUES_TO_SEPARATE_BUFFER",
    }


def find_direct_bl_callers(
    image: ElfImage, target: int = HELPER_VADDR
) -> list[dict[str, object]]:
    callers = []
    for virtual_address, file_offset, word in image.executable_words():
        try:
            resolved = _decode_aarch64_bl(word, virtual_address)
        except ValueError:
            continue
        if resolved == target:
            callers.append(
                {
                    "virtual_address": _hex(virtual_address),
                    "file_offset": _hex(file_offset),
                    "instruction_word": _hex(word, 8),
                    "target": _hex(resolved),
                }
            )
    return sorted(callers, key=lambda item: int(str(item["virtual_address"]), 16))


def validate_direct_bl_callers(image: ElfImage) -> list[dict[str, object]]:
    callers = find_direct_bl_callers(image)
    if len(callers) != len(DIRECT_CALLER_VADDRS):
        raise ValueError(
            f"helper direct BL caller cardinality is {len(callers)}, expected "
            f"{len(DIRECT_CALLER_VADDRS)}"
        )
    expected = {
        address: (offset, word)
        for address, offset, word in zip(
            DIRECT_CALLER_VADDRS, DIRECT_CALLER_FILE_OFFSETS, DIRECT_CALLER_WORDS
        )
    }
    for caller in callers:
        virtual_address = int(str(caller["virtual_address"]), 16)
        expected_offset, expected_word = expected.get(virtual_address, (None, None))
        if expected_offset is None:
            raise ValueError(f"unexpected helper direct BL caller at {_hex(virtual_address)}")
        if int(str(caller["file_offset"]), 16) != expected_offset:
            raise ValueError(f"caller {_hex(virtual_address)} has an unexpected file offset")
        if int(str(caller["instruction_word"]), 16) != expected_word:
            raise ValueError(f"caller {_hex(virtual_address)} has an unexpected BL encoding")
    return callers


def _validate_group_shape(values: tuple[int, ...]) -> dict[str, object]:
    if len(values) != TABLE_ENTRY_COUNT:
        raise ValueError(f"expected {TABLE_ENTRY_COUNT} nonzero entries")
    mc_groups: list[dict[str, object]] = []
    for group_index in range(MC_GROUP_COUNT):
        start = group_index * MC_GROUP_WIDTH
        group = values[start : start + MC_GROUP_WIDTH]
        if len(group) != MC_GROUP_WIDTH:
            raise ValueError("MC group is truncated")
        page_bases = tuple(value & ~0xFFFF for value in group)
        if page_bases != MC_INSTANCE_PAGE_BASES:
            raise ValueError(
                f"MC group {group_index} does not have four expected instance pages"
            )
        suffixes = {value & 0xFFFF for value in group}
        if len(suffixes) != 1:
            raise ValueError(f"MC group {group_index} does not share one suffix")
        mc_groups.append(
            {
                "index": group_index,
                "instance_count": MC_GROUP_WIDTH,
            }
        )

    globals_ = values[MC_ADDRESS_COUNT:]
    if len(globals_) != GLOBAL_ADDRESS_COUNT:
        raise ValueError("table does not end with the two expected global entries")
    if any(value & ~0xFFFF in MC_INSTANCE_PAGE_BASES for value in globals_):
        # Global addresses are deliberately not assigned names.  They must be
        # outside the four-instance MC page family to remain structural globals.
        raise ValueError("final two entries are not structurally global")
    return {
        "mc_group_count": len(mc_groups),
        "mc_group_instance_count": MC_GROUP_WIDTH,
        "mc_address_count": MC_ADDRESS_COUNT,
        "global_address_count": len(globals_),
        "total_nonzero_count": len(values),
        "mc_groups": mc_groups,
        "global_indices": [MC_ADDRESS_COUNT, MC_ADDRESS_COUNT + 1],
    }


def candidate_coverage(values: Iterable[int]) -> dict[str, object]:
    table_set = set(values)
    entries: list[dict[str, object]] = []
    for candidate in TOP_CANDIDATES:
        addresses = tuple(candidate["addresses"])  # type: ignore[arg-type]
        covered = tuple(address for address in addresses if address in table_set)
        missing = tuple(address for address in addresses if address not in table_set)
        entries.append(
            {
                "key": candidate["key"],
                "label": candidate["label"],
                "expected_count": len(addresses),
                "covered_count": len(covered),
                "covered_addresses": [_hex(value, 8) for value in covered],
                "missing_addresses": [_hex(value, 8) for value in missing],
                "all_expected_covered": not missing,
            }
        )
    mc_keys = {"mc_plus_0x400", "mc_plus_0x404", "mc_plus_0x4d0"}
    mc_candidates = {
        value
        for candidate in TOP_CANDIDATES
        if candidate["key"] in mc_keys
        for value in candidate["addresses"]  # type: ignore[union-attr]
    }
    excluded = {
        value
        for candidate in TOP_CANDIDATES
        if candidate["key"] not in mc_keys
        for value in candidate["addresses"]  # type: ignore[union-attr]
    }
    return {
        "candidates": entries,
        "mc_candidate_count": len(mc_candidates),
        "mc_candidates_all_covered": mc_candidates <= table_set,
        "excluded_candidate_count": len(excluded),
        "excluded_candidates_covered_count": len(excluded & table_set),
        "absence_scope": "table exclusion only; absence does not refute transform state",
    }


def shrm_plan_crosscheck(table_values: Iterable[int]) -> dict[str, object]:
    """Cross-check address lists without importing raw register values."""

    try:
        from tools.shrm_dump_decode import load_plan
    except ModuleNotFoundError as error:
        if error.name != "tools":
            raise
        from shrm_dump_decode import load_plan

    table_set = set(table_values)
    plans = load_plan()
    sets: list[dict[str, int]] = []
    union: set[int] = set()
    for index, plan in enumerate(plans):
        addresses = {word.register for word in plan.words}
        union.update(addresses)
        sets.append(
            {
                "set": index,
                "distinct_addresses": len(addresses),
                "table_intersection_count": len(addresses & table_set),
            }
        )
    return {
        "source": "tools.shrm_dump_decode.load_plan()",
        "sets": sets,
        "union": {
            "distinct_addresses": len(union),
            "table_intersection_count": len(union & table_set),
            "table_only_count": len(table_set - union),
            "shrm_union_only_count": len(union - table_set),
        },
        "claim_scope": "independent address-list convergence only; no semantic identity or writer attribution",
    }


def analyze(xbl_data: bytes) -> dict[str, object]:
    if len(xbl_data) != XBL_SIZE:
        raise ValueError(f"XBL size is {len(xbl_data)}, expected {XBL_SIZE}")
    image_hash = sha256(xbl_data)
    if image_hash != XBL_SHA256:
        raise ValueError(f"XBL SHA-256 mismatch: {image_hash}")
    image = ElfImage(xbl_data)
    table = parse_u64_table(image)
    values = table.pop("values")
    shape = _validate_group_shape(values)  # type: ignore[arg-type]
    coverage = candidate_coverage(values)  # type: ignore[arg-type]
    crosscheck = shrm_plan_crosscheck(values)  # type: ignore[arg-type]
    helper = validate_helper(image, values)  # type: ignore[arg-type]
    callers = validate_direct_bl_callers(image)
    helper["direct_caller_cardinality"] = len(callers)
    helper["direct_caller_word_pins_verified"] = True
    # Public JSON reports only addresses/offsets/targets.  The exact 32-bit
    # instruction words remain code/test pins and are not emitted as firmware
    # bytes in the public artifact.
    helper["direct_callers"] = [
        {
            "virtual_address": caller["virtual_address"],
            "file_offset": caller["file_offset"],
            "target": caller["target"],
            "word_pin_verified": True,
        }
        for caller in callers
    ]
    return {
        "schema": "sdm855-xbl-mc-snapshot-xref-public-v2",
        "stage": "STAGE_2_HELPER_DIRECTION_PROVED",
        "mode": "HOST_ONLY_READ_ONLY",
        "device_access": False,
        "smc_access": False,
        "mmio_access": False,
        "firmware_bytes_emitted": False,
        "input": {
            "filename": "xbl--sdb1.bin",
            "size": len(xbl_data),
            "sha256": image_hash,
            "pin_verified": True,
        },
        "elf": {
            "file_backed_pt_load_count": len(image.segments),
            "table_mapping_verified": True,
            "table_file_offset_verified": _hex(TABLE_FILE_OFFSET),
            "helper_mapping_verified": True,
            "direct_caller_mappings_verified": True,
        },
        "table": {
            **table,
            "grouping": shape,
            "candidate_coverage": coverage,
        },
        "helper": helper,
        "shrm_plan_crosscheck": crosscheck,
        "claims": {
            "PROVED": [
                "The exact pinned XBL contains a 122-address little-endian u64 table at VA 0x146b1218 mapped to file offset 0x630b8, followed by a u64 zero terminator; the inclusive table hash is pinned.",
                "The 122 nonzero entries have a deterministic structural grouping of 30 four-instance groups plus two global entries, without assigning undocumented suffix/register names.",
                "All four +0x400, all four +0x404, and all four +0x4d0 MC candidate addresses from Verification 012 are present in the exact table.",
                "The table excludes all four MCCC +0x118 candidates and the MCCC-master +0x294 candidate; this is table exclusion only.",
                "The exact table and tools.shrm_dump_decode.load_plan() independently converge at set0=100/430, set1=4/64, union=100, table-only=22, and SHRM-union-only=370 addresses.",
                "In the exact 0x54-byte helper range, the static control flow is constructed to issue a 32-bit load from each nonzero table-derived address and, if that load returns, issue a store of its result to the distinct output VA 0x146bf300; this does not prove successful runtime completion or a coherent snapshot.",
                "A complete scan of direct BL instructions in file-backed executable PT_LOADs finds exactly two direct callers to the helper, at 0x146ae26c and 0x14839f44; this is static direct-reachability evidence only.",
            ],
            "REFUTED": [
                "The exact 0x54-byte helper range itself programs/writes the candidate controller addresses: its table-derived pointer registers are load bases only, and its identified STR store bases are X12 and X8 (the fixed output-buffer aliases).",
                "The helper independently enforces a maximum of 122 iterations; its runtime traversal bound is zero-sentinel-only, although the exact on-disk pinned table has its terminator at index 122.",
            ],
            "UNKNOWN": [
                "Which code writes any listed registers, their bit semantics, post-boot writability/lock state, and the relation between these candidates and the measured GF(2) bank function or recovered row space.",
                "Whether the helper successfully executes or completes, including partial/sentinel output and whether any destination reflects a coherent, atomic, or current snapshot.",
                "Whether any helper path references this table on the current boot or retained boot and what runtime values any destination contains.",
                "Whether an MMIO read has side effects, faults, or other runtime behavior, and what mutable runtime table contents exist after loading.",
                "Any indirect BLR or tail-call reachability beyond the direct BL instructions scanned in file-backed executable PT_LOADs.",
                "Whether candidates absent from this table are transform state; table absence alone is not a refutation.",
            ],
        },
        "classification": "TABLE_DRIVEN_REGISTER_READ_COPY_PATH_WRITER_AND_TRANSFORM_RELATION_UNKNOWN",
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
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
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


# Small compatibility aliases for focused host-side callers.
Image = ElfImage
parse_table = parse_u64_table


if __name__ == "__main__":
    raise SystemExit(main())
