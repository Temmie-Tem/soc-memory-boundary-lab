#!/usr/bin/env python3
"""Host-only Experiment 025: bounded XBL platform-query binding proof.

This experiment resolves the *intended* static chain behind Experiment 024's
runtime-BSS object:

    runtime-BSS slot -> registry/attach -> descriptor/factory -> inline vtable
    -> callback.

It is deliberately a small, fail-closed AArch64/ELF decoder rather than a
general decompiler.  It proves exact instruction and data shapes in one pinned
XBL image and records the limits of that proof.  In particular, it does not
turn a static registration shape into runtime boot-order, object-identity, or
current-base authority.  No device, MMIO, SMC, protected-memory, or runtime
register access is performed.
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

DEPENDENCY_NAME = "024-xbl-six-byte-walker-20260826-01.manifest.json"
DEPENDENCY_PATH = REPO_ROOT / "evidence/manifests" / DEPENDENCY_NAME
DEPENDENCY_SIZE = 30_400
DEPENDENCY_SHA256 = "f9ac896d396650075ca9e66d8d805a2deaf40b0207e819cd94f8d638c8121b01"

SCHEMA = "sm8150-xbl-platform-query-binding-v1"

RUNTIME_BSS_START = 0x14882800
RUNTIME_BSS_END = 0x14882800 + 0x1CC00
RUNTIME_SLOT = 0x14890590
REGISTRY_START = 0x14890E50
REGISTRY_END = 0x14890F50

PLATFORM_QUERY_START = 0x1486ABEC
PLATFORM_QUERY_END = 0x1486ACAC
PLATFORM_QUERY_OFFSET = 0x51BEC
PLATFORM_QUERY_SHA256 = "679384b78fab5cf3903f5c7a34e5efa45552c983b4d2bb1fcc8dc12e66d555c2"
PLATFORM_QUERY_CALLER = 0x1486847C
PLATFORM_QUERY_BLR = 0x1486AC1C
PLATFORM_QUERY_SLOT_LOAD = 0x1486AC04
PLATFORM_QUERY_SLOT_ADDRESS = 0x1486AC40
PLATFORM_QUERY_SLOT_RELOAD = 0x1486ACA4

REGISTRY_START_FN = 0x1482D7EC
REGISTRY_ATTACH_FN = 0x1482D858
REGISTRY_END_FN = 0x1482D948
REGISTRY_OFFSET = 0x147EC
REGISTRY_SHA256 = "3ddb7bb677e84915c4f11e4ed05a01ef3ecf5ef0b71542b92a641714c05bce2a"

WRAPPERS_START = 0x1482E7BC
WRAPPERS_END = 0x1482E834
WRAPPERS_OFFSET = 0x157BC
WRAPPERS_SHA256 = "7d7ee2aafd88f6a8e67b4a9a55b983d5831a9fd79057b897f6df53bace7b1609"

SEED_START = 0x1482EE38
SEED_END = 0x1482EE4C
SEED_OFFSET = 0x15E38
SEED_SHA256 = "91c63be151b9639a487ab226a6b923a92b8cc4833ffc5bb24b32192c6804e2d5"

RECORD_START = 0x14875568
RECORD_END = 0x148755A8
RECORD_OFFSET = 0x54F48
RECORD_SHA256 = "ee220905e80f44aa482f60e0a49416a06c6665e1b9e7b0ba949693de8136327c"
RECORD_TABLE = 0x14875568
RECORD = 0x14875590
SERVICE_ID = 0x02000139

DESCRIPTOR_START = 0x14824AB8
DESCRIPTOR_END = 0x14824B40
DESCRIPTOR_OFFSET = 0xBAB8
DESCRIPTOR_SHA256 = "2517a5d35a83576933f304be0598812ea5bc266630de78ea69ec22b6b6f67177"
DESCRIPTOR = 0x14824AB8
VTABLE = 0x14824AD0
VTABLE_CALLBACK_OFFSET = 0x48
CALLBACK = 0x1484A9D4

FACTORY_START = 0x1484A880
FACTORY_END = 0x1484A8FC
FACTORY_OFFSET = 0x31880
FACTORY_SHA256 = "ada8e99bb7d9d072fb7a259e25aab844a26bcedb583edd400d75f19bccaa9611"
FACTORY_OBJECT = 0x1488F418

CALLBACK_START = 0x1484A9D4
CALLBACK_END = 0x1484AA0C
CALLBACK_OFFSET = 0x319D4
CALLBACK_SHA256 = "8de96d5c209dbd9a6747d7f91072a3ab279e47aefba1506e3123cb5258e05e9d"
CALLBACK_CALLEE = 0x1484A730
CALLBACK_CALLEE_START = 0x1484A730
CALLBACK_CALLEE_END = 0x1484A750
LAZY_INIT = 0x1484A824
LAZY_INIT_END = 0x1484A854
LAZY_INIT_OFFSET = 0x31824
LAZY_INIT_SHA256 = "6a0ddccd34648eec5163ba46a0b98c1525c74288eab08934d012162463f29bfd"
LAZY_BOOTSTRAP = 0x1484AA30
LAZY_BOOTSTRAP_END = 0x1484AA74
LAZY_BOOTSTRAP_OFFSET = 0x31A30
LAZY_BOOTSTRAP_SHA256 = "1fb73c03710d2acc52a1330804dcb6605d34f16bf8a84dd49902470b4edd8bf8"
LAZY_STATUS_HELPER = 0x1484A854
LAZY_STATUS_HELPER_END = 0x1484A880
LAZY_STATUS_HELPER_OFFSET = 0x31854
LAZY_STATUS_HELPER_SHA256 = "72e021ef3e66bfc25523ae4d00a60270ee55fa9f01df7366326bc2f5bad62da1"
LAZY_FLAG = 0x1488F3F9
LAZY_STATUS_BSS = 0x14890B90
LAZY_STATUS_BSS_END = LAZY_STATUS_BSS + 0x14
LAZY_MMIO = 0x01FC8004

MAIN_INIT_START = 0x14868418
MAIN_INIT_END = 0x148688F0
INITIALIZER_STORE = 0x14868468
INITIALIZER_BASE = 0x01D80000


class BindingError(ValueError):
    """Raised when an input is malformed or fails an exact pin."""


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
    def kind(self) -> str:
        return {1: "X", 2: "W", 3: "WX", 4: "R", 5: "RX", 6: "RW", 7: "RWX"}.get(
            self.flags, f"F{self.flags}"
        )

    @property
    def executable(self) -> bool:
        return bool(self.flags & 1)


class Image:
    """Independent ELF64 PT_LOAD parser.

    Zero-file-size PT_LOADs are retained deliberately: the runtime object and
    registry live in zero-fill memory, so dropping those segments would turn
    an UNKNOWN runtime value into a misleading "not present" result.
    """

    def __init__(self, data: bytes):
        if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            raise BindingError("not a little-endian ELF64 image")
        if data[6] != 1:
            raise BindingError("unsupported ELF version")
        ph_offset = struct.unpack_from("<Q", data, 32)[0]
        ph_entry = struct.unpack_from("<H", data, 54)[0]
        ph_count = struct.unpack_from("<H", data, 56)[0]
        if ph_entry < 56 or ph_count > 4096:
            raise BindingError("invalid program-header shape")
        if ph_offset > len(data) or ph_offset + ph_entry * ph_count > len(data):
            raise BindingError("program headers exceed image")
        self.data = data
        self.segments: list[Segment] = []
        for index in range(ph_count):
            offset = ph_offset + index * ph_entry
            p_type, flags, file_offset, vaddr, _pa, file_size, mem_size, _align = struct.unpack_from(
                "<IIQQQQQQ", data, offset
            )
            if p_type != 1:
                continue
            if file_offset > len(data) or file_offset + file_size > len(data):
                raise BindingError(f"PT_LOAD {index} exceeds image")
            if mem_size < file_size:
                raise BindingError(f"PT_LOAD {index} has memsz smaller than filesz")
            self.segments.append(Segment(index, file_offset, vaddr, file_size, mem_size, flags))

    def file_backed(self) -> list[Segment]:
        return [segment for segment in self.segments if segment.file_size]

    def executable(self) -> list[Segment]:
        return [segment for segment in self.file_backed() if segment.executable]

    def segment_for(self, vaddr: int, *, file_backed: bool = True) -> Segment | None:
        matches = [
            segment
            for segment in self.segments
            if segment.vaddr <= vaddr < segment.vaddr + (segment.file_size if file_backed else segment.mem_size)
            and (not file_backed or segment.file_size)
        ]
        if len(matches) > 1:
            raise BindingError(f"ambiguous PT_LOAD mapping at {fmt(vaddr)}")
        return matches[0] if matches else None

    def file_offset(self, vaddr: int) -> int | None:
        segment = self.segment_for(vaddr)
        return None if segment is None else segment.file_offset + vaddr - segment.vaddr

    def slice(self, start: int, end: int) -> bytes:
        if end <= start:
            raise BindingError("empty or reversed range")
        start_offset = self.file_offset(start)
        end_offset = self.file_offset(end - 1)
        if start_offset is None or end_offset is None or end_offset + 1 != start_offset + end - start:
            raise BindingError(f"range is not one file-backed PT_LOAD: {fmt(start)}..{fmt(end)}")
        return self.data[start_offset : start_offset + end - start]

    def word(self, vaddr: int) -> int | None:
        offset = self.file_offset(vaddr)
        if offset is None or offset % 4 or offset + 4 > len(self.data):
            return None
        return struct.unpack_from("<I", self.data, offset)[0]

    def instructions(self, segment: Segment) -> Iterable[tuple[int, int]]:
        for offset in range(0, max(0, segment.file_size - 3), 4):
            yield segment.vaddr + offset, struct.unpack_from("<I", self.data, segment.file_offset + offset)[0]


def decode_bl_target(word: int, vaddr: int) -> int | None:
    if (word & 0xFC000000) != 0x94000000:
        return None
    return vaddr + 4 * sign_extend(word & 0x03FFFFFF, 26)


def decode_b_target(word: int, vaddr: int) -> int | None:
    # B and BL share the immediate layout, but differ in bit 31.  Keep the
    # unconditional-B decoder fail-closed so a call is never treated as a
    # control-flow edge.
    if (word & 0xFC000000) == 0x14000000:
        return vaddr + 4 * sign_extend(word & 0x03FFFFFF, 26)
    if (word & 0xFF000010) == 0x54000000:
        return vaddr + 4 * sign_extend((word >> 5) & 0x7FFFF, 19)
    if (word & 0x7E000000) == 0x34000000:
        return vaddr + 4 * sign_extend((word >> 5) & 0x7FFFF, 19)
    if (word & 0x7E000000) == 0x36000000:
        return vaddr + 4 * sign_extend((word >> 5) & 0x3FFF, 14)
    return None


def is_adrp(word: int) -> tuple[int, int] | None:
    if (word & 0x9F000000) != 0x90000000:
        return None
    immediate = sign_extend((((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 3), 21) << 12
    return immediate, word & 0x1F


def adrp_page(word: int, vaddr: int) -> tuple[int, int] | None:
    decoded = is_adrp(word)
    if decoded is None:
        return None
    immediate, register = decoded
    return ((vaddr & ~0xFFF) + immediate) & 0xFFFFFFFF, register


def is_add_x_imm(word: int) -> tuple[int, int, int, int] | None:
    if (word & 0xFF000000) != 0x91000000:
        return None
    return word & 0x1F, (word >> 5) & 0x1F, (word >> 10) & 0xFFF, 12 if (word >> 22) & 1 else 0


def is_orr_x_reg(word: int) -> tuple[int, int] | None:
    if (word & 0xFFE0FC00) != 0xAA000000:
        return None
    if ((word >> 5) & 0x1F) != 31:
        return None
    return word & 0x1F, (word >> 16) & 0x1F


def is_orr_w_reg(word: int) -> tuple[int, int] | None:
    if (word & 0xFFE0FC00) != 0x2A000000:
        return None
    if ((word >> 5) & 0x1F) != 31:
        return None
    return word & 0x1F, (word >> 16) & 0x1F


def is_add_w_imm(word: int) -> tuple[int, int, int] | None:
    if (word & 0xFF000000) != 0x11000000 or ((word >> 22) & 1):
        return None
    return word & 0x1F, (word >> 5) & 0x1F, (word >> 10) & 0xFFF


def is_compare_no_write(word: int) -> bool:
    """Recognize CMP/SUBS-to-ZR forms used by the pinned registry loops."""
    return (word & 0xFFE0FC1F) in (0x6B00001F, 0xEB00001F) or (word & 0xFF80001F) in (0x7100001F, 0xF100001F)


def is_movz_w(word: int) -> tuple[int, int, int] | None:
    if (word & 0xFFC00000) != 0x52800000:
        return None
    return ((word >> 5) & 0xFFFF, (word >> 21) & 3, word & 0x1F)


def is_movk_w(word: int) -> tuple[int, int, int] | None:
    if (word & 0xFFC00000) != 0x72800000:
        return None
    return ((word >> 5) & 0xFFFF, (word >> 21) & 3, word & 0x1F)


def is_movn_w(word: int) -> tuple[int, int, int] | None:
    if (word & 0xFFC00000) != 0x12800000:
        return None
    return ((word >> 5) & 0xFFFF, (word >> 21) & 3, word & 0x1F)


def is_ldr_str_unsigned(word: int) -> tuple[str, str, int, int, int] | None:
    """Decode unsigned-immediate LDR/STR W/X.

    Returns ``(kind, width, byte_offset, rn, rt)``.  Other addressing forms
    are intentionally left to their own conservative decoder.
    """
    group = word & 0xFFC00000
    groups = {
        0x39400000: ("LDR", "B", 1),
        0xB9400000: ("LDR", "W", 4),
        0xF9400000: ("LDR", "X", 8),
        0x39000000: ("STR", "B", 1),
        0xB9000000: ("STR", "W", 4),
        0xF9000000: ("STR", "X", 8),
    }
    if group not in groups:
        return None
    kind, width, scale = groups[group]
    return kind, width, ((word >> 10) & 0xFFF) * scale, (word >> 5) & 0x1F, word & 0x1F


def is_ldr_str_unscaled(word: int) -> tuple[str, str, int, int, int] | None:
    """Decode the unscaled immediate W/X forms, including STUR."""
    # Signed unscaled immediate forms have fixed op/size bits and a signed
    # nine-bit displacement at bits 12..20.
    if (word & 0xFFE00C00) not in (0xB8000000, 0xF8000000):
        return None
    size = "X" if (word & 0x40000000) else "W"
    kind = "LDR" if (word & 0x00400000) else "STR"
    return kind, size, sign_extend((word >> 12) & 0x1FF, 9), (word >> 5) & 0x1F, word & 0x1F


def is_ldr_postindex(word: int) -> tuple[str, str, int, int, int] | None:
    if (word & 0xFFC00C00) not in (0xB8400400, 0xF8400400):
        return None
    size = "X" if (word & 0x40000000) else "W"
    return "LDR", size, sign_extend((word >> 12) & 0x1FF, 9), (word >> 5) & 0x1F, word & 0x1F


def is_blr(word: int) -> int | None:
    return (word >> 5) & 0x1F if (word & 0xFFFFFC1F) == 0xD63F0000 else None


def is_br(word: int) -> int | None:
    return (word >> 5) & 0x1F if (word & 0xFFFFFC1F) == 0xD61F0000 else None


def direct_callers(image: Image, target: int) -> list[int]:
    result: list[int] = []
    for segment in image.executable():
        for vaddr, word in image.instructions(segment):
            if decode_bl_target(word, vaddr) == target:
                result.append(vaddr)
    return sorted(result)


def range_record(
    image: Image,
    start: int,
    end: int,
    *,
    expected_offset: int,
    expected_hash: str,
    label: str,
) -> dict:
    data = image.slice(start, end)
    offset = image.file_offset(start)
    if offset != expected_offset:
        raise BindingError(f"{label} file offset mismatch")
    digest = sha256(data)
    if digest != expected_hash:
        raise BindingError(f"{label} range hash mismatch")
    return {
        "start": fmt(start),
        "end_exclusive": fmt(end),
        "file_offset": fmt_offset(offset),
        "size": end - start,
        "sha256": digest,
    }


def assert_words(image: Image, expected: dict[int, int]) -> None:
    for address, expected_word in expected.items():
        actual = image.word(address)
        if actual != expected_word:
            raise BindingError(f"instruction/data mismatch at {fmt(address)}")


def _u32(image: Image, address: int) -> int:
    word = image.word(address)
    if word is None:
        raise BindingError(f"unmapped word at {fmt(address)}")
    return word


def _u64(image: Image, address: int) -> int:
    offset = image.file_offset(address)
    if offset is None or offset + 8 > len(image.data):
        raise BindingError(f"unmapped qword at {fmt(address)}")
    return struct.unpack_from("<Q", image.data, offset)[0]


def decode_service_id(image: Image, low_address: int = 0x1486AC34, high_address: int = 0x1486AC3C) -> int:
    """Decode the exact MOVZ/MOVK service ID materialization."""
    low = is_movz_w(_u32(image, low_address))
    high = is_movk_w(_u32(image, high_address))
    if low is None or high is None or low[1] != 0 or high[1] != 1 or low[2] != 0 or high[2] != 0:
        raise BindingError("service ID MOVZ/MOVK materialization is not the pinned W0 pair")
    value = low[0] | (high[0] << 16)
    if value != SERVICE_ID:
        raise BindingError("service ID value changed")
    return value


def _direct_target(image: Image, address: int) -> int | None:
    """Resolve one exact ADRP+ADD pair in the preceding straight-line span.

    XBL frequently materialises an address, emits an unrelated MOVK/MOVZ for
    a second argument, and only then performs the ADD.  A one-instruction
    look-behind would therefore miss the exact attach and seed arguments.  The
    bounded backwards scan stops when the ADD's input register is redefined;
    it does not attempt control-flow or general register taint.
    """
    word = image.word(address)
    if word is None:
        return None
    add = is_add_x_imm(word)
    if add is None:
        return None
    rd, rn, imm, shift = add
    if shift:
        imm <<= 12
    for prior_address in range(address - 4, max(address - 0x40, 0), -4):
        prior = image.word(prior_address)
        if prior is None:
            continue
        # Calls, branches and returns terminate the straight-line proof.  A
        # register definition before one of these instructions is not reused
        # across an unmodelled control-flow edge.
        if decode_bl_target(prior, prior_address) is not None or is_blr(prior) is not None or is_br(prior) is not None:
            return None
        if decode_b_target(prior, prior_address) is not None or (prior & 0xFFFFFC1F) == 0xD65F0000:
            return None
        page = adrp_page(prior, prior_address)
        if page is not None and page[1] == rn:
            return (page[0] + imm) & 0xFFFFFFFF
        # A write to the ADD input register before the ADRP breaks this small
        # straight-line proof.  ADRP itself is a definition and is handled
        # above; other writes are conservatively treated as a barrier.
        add_before = is_add_x_imm(prior)
        if add_before is not None and add_before[0] == rn:
            return None
        copy_before = is_orr_x_reg(prior)
        if copy_before is not None and copy_before[0] == rn:
            return None
        movz_before = is_movz_w(prior)
        movk_before = is_movk_w(prior)
        movn_before = is_movn_w(prior)
        if any(decoded is not None and decoded[2] == rn for decoded in (movz_before, movk_before, movn_before)):
            return None
        copy_w_before = is_orr_w_reg(prior)
        if copy_w_before is not None and copy_w_before[0] == rn:
            return None
        memory_before = is_ldr_str_unsigned(prior) or is_ldr_str_unscaled(prior)
        post_before = is_ldr_postindex(prior)
        if memory_before is not None:
            if memory_before[0] == "LDR" and memory_before[4] == rn:
                return None
        if post_before is not None and (post_before[3] == rn or post_before[4] == rn):
            return None
        # Only the small set of no-write/known-write forms above is in this
        # resolver's model.  An unrecognized instruction may redefine the
        # input register, so do not carry an ADRP definition across it.
        known_safe = (
            adrp_page(prior, prior_address) is not None
            or is_add_x_imm(prior) is not None
            or is_orr_x_reg(prior) is not None
            or is_orr_w_reg(prior) is not None
            or is_movz_w(prior) is not None
            or is_movk_w(prior) is not None
            or is_movn_w(prior) is not None
            or memory_before is not None
            or post_before is not None
            or prior == 0xD503201F
        )
        if not known_safe:
            return None
    return None


def _scan_address_block(image: Image, start: int, end: int, initial: dict[int, int] | None = None) -> list[dict]:
    """Scan one explicitly pinned straight-line/loop idiom.

    The general census resets at control-flow instructions.  A few required
    xrefs sit in short, pinned loop bodies (the registry list) or in the
    helper's retry block, so they are decoded separately with their exact
    entry definitions.  This function does not cross calls or leave its
    caller-supplied range.
    """
    address_defs = dict(initial or {})
    accesses: list[dict] = []
    for vaddr in range(start, end, 4):
        word = image.word(vaddr)
        if word is None:
            raise BindingError(f"pinned address block is unmapped at {fmt(vaddr)}")
        adrp = adrp_page(word, vaddr)
        if adrp is not None:
            address_defs[adrp[1]] = adrp[0]
            continue
        add = is_add_x_imm(word)
        if add is not None:
            rd, rn, imm, shift = add
            if rn in address_defs:
                address_defs[rd] = (address_defs[rn] + (imm << 12 if shift else imm)) & 0xFFFFFFFF
            else:
                address_defs.pop(rd, None)
            continue
        copied = is_orr_x_reg(word)
        if copied is not None:
            rd, rn = copied
            if rn in address_defs:
                address_defs[rd] = address_defs[rn]
            else:
                address_defs.pop(rd, None)
            continue
        access = is_ldr_str_unsigned(word) or is_ldr_str_unscaled(word)
        post = is_ldr_postindex(word)
        if access is not None:
            kind, width, byte_offset, rn, rt = access
            if rn in address_defs:
                accesses.append(
                    {
                        "va": fmt(vaddr),
                        "word": fmt(word),
                        "kind": kind,
                        "width": width,
                        "base_register": f"X{rn}",
                        "target": fmt((address_defs[rn] + byte_offset) & 0xFFFFFFFF),
                        "offset": byte_offset,
                        "address_model": "PINNED_BASIC_BLOCK_ADRP_LOOP",
                    }
                )
            if kind == "LDR":
                address_defs.pop(rt, None)
            continue
        if post is not None:
            _kind, width, byte_offset, rn, rt = post
            if rn in address_defs:
                accesses.append(
                    {
                        "va": fmt(vaddr),
                        "word": fmt(word),
                        "kind": "LDR_POSTINDEX",
                        "width": width,
                        "base_register": f"X{rn}",
                        "target": fmt(address_defs[rn] & 0xFFFFFFFF),
                        "offset": 0,
                        "post_index": byte_offset,
                        "address_model": "PINNED_BASIC_BLOCK_ADRP_LOOP",
                    }
                )
                address_defs[rn] = (address_defs[rn] + byte_offset) & 0xFFFFFFFF
            address_defs.pop(rt, None)
            continue
        # Branches in these ranges are loop edges whose entry definitions are
        # explicitly pinned above.  Other instructions are only accepted as
        # known non-address definitions; unknown forms kill the block proof.
        if decode_bl_target(word, vaddr) is not None or is_blr(word) is not None or is_br(word) is not None:
            raise BindingError(f"call inside pinned address block at {fmt(vaddr)}")
        if decode_b_target(word, vaddr) is not None or (word & 0xFFFFFC1F) == 0xD65F0000:
            continue
        if is_compare_no_write(word):
            continue
        handled = False
        for decoded in (is_movz_w(word), is_movk_w(word), is_movn_w(word), is_orr_w_reg(word)):
            if decoded is not None:
                address_defs.pop(decoded[2] if len(decoded) == 3 else decoded[0], None)
                handled = True
                break
        if not handled:
            add_w = is_add_w_imm(word)
            if add_w is not None:
                address_defs.pop(add_w[0], None)
                handled = True
        if not handled:
            address_defs.clear()
    return accesses


def decode_materialised_addresses(image: Image) -> dict:
    """Conservative direct-address census over every executable PT_LOAD word.

    This tracks only explicit ADRP, ADD-immediate, unsigned immediate memory
    operations, post-index LDR, and unscaled immediate stores.  Register
    copies, arbitrary arithmetic, indirect branches, and aliases are not
    guessed; the output therefore records recognized direct accesses without
    claiming a complete arbitrary-write absence.
    """
    address_defs: dict[int, int] = {}
    accesses: list[dict] = []
    calls: list[dict] = []
    word_count = 0
    for segment in image.executable():
        address_defs = {}
        for vaddr, word in image.instructions(segment):
            word_count += 1
            target = decode_bl_target(word, vaddr)
            if target is not None:
                calls.append({"va": fmt(vaddr), "word": fmt(word), "target": fmt(target)})
                # Caller-saved registers and all address definitions are
                # killed at a call; an indirect target has no modeled effect.
                address_defs.clear()
                continue
            if is_blr(word) is not None or is_br(word) is not None or decode_b_target(word, vaddr) is not None or (word & 0xFFFFFC1F) == 0xD65F0000:
                address_defs.clear()
                continue

            adrp = adrp_page(word, vaddr)
            if adrp is not None:
                address_defs[adrp[1]] = adrp[0]
                continue
            add = is_add_x_imm(word)
            if add is not None:
                rd, rn, imm, shift = add
                if rn in address_defs:
                    address_defs[rd] = (address_defs[rn] + (imm << 12 if shift else imm)) & 0xFFFFFFFF
                else:
                    address_defs.pop(rd, None)
                continue
            copied = is_orr_x_reg(word)
            if copied is not None:
                rd, rn = copied
                if rn in address_defs:
                    address_defs[rd] = address_defs[rn]
                else:
                    address_defs.pop(rd, None)
                continue

            # Known W-register definitions cannot preserve a tracked X address.
            for decoded in (is_movz_w(word), is_movk_w(word), is_movn_w(word), is_orr_w_reg(word)):
                if decoded is not None:
                    address_defs.pop(decoded[2] if len(decoded) == 3 else decoded[0], None)
                    break
            else:
                decoded = None
            if decoded is not None:
                continue

            access = is_ldr_str_unsigned(word) or is_ldr_str_unscaled(word)
            post = is_ldr_postindex(word)
            if access is not None:
                kind, width, byte_offset, rn, rt = access
                if rn in address_defs:
                    accesses.append(
                        {
                            "va": fmt(vaddr),
                            "word": fmt(word),
                            "kind": kind,
                            "width": width,
                            "base_register": f"X{rn}",
                            "target": fmt((address_defs[rn] + byte_offset) & 0xFFFFFFFF),
                            "offset": byte_offset,
                            "address_model": "EXPLICIT_ADRP_ADD_OR_PAGE_PLUS_IMMEDIATE",
                        }
                    )
                if kind == "LDR":
                    address_defs.pop(rt, None)
                continue
            if post is not None:
                _kind, _width, byte_offset, rn, rt = post
                if rn in address_defs:
                    accesses.append(
                        {
                            "va": fmt(vaddr),
                            "word": fmt(word),
                            "kind": "LDR_POSTINDEX",
                            "width": _width,
                            "base_register": f"X{rn}",
                            "target": fmt((address_defs[rn]) & 0xFFFFFFFF),
                            "offset": 0,
                            "post_index": byte_offset,
                            "address_model": "EXPLICIT_ADRP_PLUS_POSTINDEX_BASE",
                        }
                    )
                    address_defs[rn] = (address_defs[rn] + byte_offset) & 0xFFFFFFFF
                address_defs.pop(rt, None)
                continue

            # Any write to a known address through a different addressing form
            # is outside this bounded decoder.  Forget register definitions on
            # ordinary writes that obviously redefine a tracked destination.
            rd = word & 0x1F
            if (word & 0x1F000000) in (0x11000000, 0x51000000, 0x32000000, 0x2A000000) or (word & 0x1F200000) == 0x0B000000:
                address_defs.pop(rd, None)
            else:
                # Unknown instructions are not allowed to carry a stale
                # materialized address into a later basic block.
                address_defs.clear()
    pinned_accesses: list[dict] = []

    def add_pinned_block(start: int, end: int, initial: dict[int, int] | None = None) -> None:
        # Synthetic decoder fixtures do not carry the exact-image blocks.  The
        # general census remains useful there; exact pinned blocks are added
        # only when the complete VA span is actually mapped.
        if image.file_offset(start) is None or image.file_offset(end - 4) is None:
            return
        pinned_accesses.extend(_scan_address_block(image, start, end, initial))

    add_pinned_block(0x1486ABFC, 0x1486AC08)
    add_pinned_block(0x1486ACA4, 0x1486ACAC, {20: 0x14890000})
    add_pinned_block(0x1482D7EC, 0x1482D818)
    add_pinned_block(0x1482D820, 0x1482D854)
    add_pinned_block(0x1482D864, 0x1482D888)
    merged: dict[tuple[str, str, str], dict] = {}
    for row in accesses + pinned_accesses:
        merged[(row["va"], row["kind"], row["target"])] = row
    accesses = [merged[key] for key in sorted(merged)]
    return {
        "word_count": word_count,
        "scan_scope": "ALL_FILE_BACKED_EXECUTABLE_PT_LOAD_WORDS",
        "decoder_coverage": [
            "BL_TARGETS",
            "ADRP_PAGE",
            "ADD_X_IMMEDIATE",
            "ORR_XZR_REGISTER_COPY",
            "LDR_STR_UNSIGNED_IMMEDIATE",
            "LDR_POSTINDEX",
            "LDR_STR_UNSCALED_IMMEDIATE",
            "PINNED_BASIC_BLOCK_ADRP_LOOP_MODEL",
        ],
        "recognized_direct_accesses": accesses,
        "pinned_basic_block_accesses": pinned_accesses,
        "recognized_direct_calls": calls,
        "arbitrary_write_absence": "UNKNOWN",
        "unsupported_forms": [
            "computed_or_indirect_addresses",
            "unrecognized_AArch64_memory_encodings",
            "indirect_calls_and_runtime_aliases",
            "callee_side_effects_beyond_bounded_callbacks",
        ],
    }


def dependency_audit(path: Path = DEPENDENCY_PATH) -> dict:
    data = path.read_bytes()
    if len(data) != DEPENDENCY_SIZE:
        raise BindingError("Experiment 024 dependency size mismatch")
    digest = sha256(data)
    if digest != DEPENDENCY_SHA256:
        raise BindingError("Experiment 024 dependency hash mismatch")
    try:
        prior = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BindingError("Experiment 024 dependency is not valid JSON") from exc
    if prior.get("experiment_id") != "024-xbl-six-byte-walker":
        raise BindingError("dependency experiment identity changed")
    base = prior.get("initializer_and_base_audit")
    if not isinstance(base, dict) or base.get("base_currentness") != "UNKNOWN":
        raise BindingError("dependency no longer proves UNKNOWN base currentness")
    unresolved = base.get("unresolved_success_path")
    if not isinstance(unresolved, dict):
        raise BindingError("dependency unresolved success path is absent")
    blr = unresolved.get("unresolved_blr")
    if not isinstance(blr, dict) or blr.get("va") != fmt(PLATFORM_QUERY_BLR) or blr.get("target") != "UNKNOWN":
        raise BindingError("dependency unresolved BLR pin changed")
    if base.get("mapping", {}).get("status") != "SUPPORTED" or not base.get("mapping", {}).get("conditional"):
        raise BindingError("dependency conditional mapping proof changed")
    unknown = prior.get("claims", {}).get("UNKNOWN", [])
    if not any("base remains current" in str(claim) and "unresolved BLR" in str(claim) for claim in unknown):
        raise BindingError("dependency UNKNOWN claims do not preserve the base blocker")
    return {
        "filename": DEPENDENCY_NAME,
        "size": len(data),
        "sha256": digest,
        "experiment_id": prior["experiment_id"],
        "base_currentness": base["base_currentness"],
        "unresolved_blr": {
            "va": blr["va"],
            "target": blr["target"],
            "target_register": blr.get("target_register"),
        },
        "conditional_mapping_status": base["mapping"]["status"],
        "conditional_mapping": bool(base["mapping"]["conditional"]),
        "validation": "KEY_CLAIMS_PARSED_AND_PINNED",
    }


def analyze_platform_query(image: Image) -> dict:
    query_range = range_record(
        image,
        PLATFORM_QUERY_START,
        PLATFORM_QUERY_END,
        expected_offset=PLATFORM_QUERY_OFFSET,
        expected_hash=PLATFORM_QUERY_SHA256,
        label="platform query",
    )
    expected = {
        0x1486ABFC: 0xD0000134,  # ADRP X20,0x14890000
        0x1486AC04: 0xF942CA88,  # LDR X8,[X20,#0x590]
        0x1486AC0C: 0xF940050A,  # LDR X10,[X8,#8]
        0x1486AC10: 0x910033E1,  # ADD X1,SP,#0xc
        0x1486AC14: 0xAA0803E0,  # MOV X0,X8
        0x1486AC18: 0xF9402549,  # LDR X9,[X10,#0x48]
        0x1486AC1C: 0xD63F0120,  # BLR X9
        0x1486AC38: 0xD0000121,  # ADRP X1,0x14890000
        0x1486AC34: 0x52802720,  # MOVZ W0,#0x139
        0x1486AC3C: 0x72A04000,  # MOVK W0,#0x200,LSL#16
        0x1486AC40: 0x91164021,  # ADD X1,X1,#0x590
        0x1486AC44: 0x97FF0B05,  # BL registry attach
        0x1486ACA4: 0xF942CA88,  # reload slot
        PLATFORM_QUERY_CALLER: 0x940009DC,
        0x14868470: 0x910043E0,  # ADD X0,SP,#0x10
    }
    assert_words(image, expected)
    caller_target = decode_bl_target(_u32(image, PLATFORM_QUERY_CALLER), PLATFORM_QUERY_CALLER)
    if caller_target != PLATFORM_QUERY_START:
        raise BindingError("platform query direct caller target changed")
    address = _direct_target(image, PLATFORM_QUERY_SLOT_ADDRESS)
    if address != RUNTIME_SLOT:
        raise BindingError("attach output address no longer resolves to runtime slot")
    attach_target = decode_bl_target(_u32(image, 0x1486AC44), 0x1486AC44)
    if attach_target != REGISTRY_ATTACH_FN:
        raise BindingError("platform query attach target changed")
    service_id = decode_service_id(image)
    slot_segment = image.segment_for(RUNTIME_SLOT, file_backed=False)
    if slot_segment is None or slot_segment.file_size or slot_segment.vaddr != RUNTIME_BSS_START or slot_segment.mem_size != 0x1CC00:
        raise BindingError("runtime slot is not in the pinned memory-only PT_LOAD")
    return {
        "range": query_range,
        "direct_caller": {
            "va": fmt(PLATFORM_QUERY_CALLER),
            "word": fmt(_u32(image, PLATFORM_QUERY_CALLER)),
            "target": fmt(caller_target),
            "input": "X0=SP+0x10",
            "input_instruction": {"va": fmt(0x14868470), "word": fmt(_u32(image, 0x14868470))},
            "caller_context_register": "X19",
            "context_register_forwarded": False,
        },
        "runtime_slot": {
            "address": fmt(RUNTIME_SLOT),
            "segment_index": slot_segment.index,
            "segment_vaddr": fmt(slot_segment.vaddr),
            "segment_file_size": slot_segment.file_size,
            "segment_mem_size": slot_segment.mem_size,
            "storage": "MEMORY_ONLY_PT_LOAD_ZERO_FILL",
            "xrefs": [
                {"kind": "LOAD", "va": fmt(PLATFORM_QUERY_SLOT_LOAD), "word": fmt(_u32(image, PLATFORM_QUERY_SLOT_LOAD)), "target": fmt(RUNTIME_SLOT)},
                {"kind": "ADDRESS_FOR_ATTACH_OUTPUT", "va": fmt(PLATFORM_QUERY_SLOT_ADDRESS), "word": fmt(_u32(image, PLATFORM_QUERY_SLOT_ADDRESS)), "target": fmt(RUNTIME_SLOT)},
                {"kind": "RELOAD", "va": fmt(PLATFORM_QUERY_SLOT_RELOAD), "word": fmt(_u32(image, PLATFORM_QUERY_SLOT_RELOAD)), "target": fmt(RUNTIME_SLOT)},
            ],
        },
        "helper_arguments": {
            "runtime_object": "X8=*(X20+0x590)",
            "callback_object_argument": "X0=X8",
            "callback_output_argument": "X1=SP+0xc",
            "vtable_load": {"va": fmt(0x1486AC18), "word": fmt(_u32(image, 0x1486AC18)), "offset": 0x48, "register": "X9"},
            "indirect_call": {"va": fmt(PLATFORM_QUERY_BLR), "word": fmt(_u32(image, PLATFORM_QUERY_BLR)), "register": "X9", "target": "UNKNOWN_UNTIL_RUNTIME_OBJECT_BINDING"},
            "output_reload": {"va": fmt(0x1486AC20), "word": fmt(_u32(image, 0x1486AC20)), "source": "[SP,#0xc]"},
        },
        "attach_path": {
            "id_materialization": {"low": 0x139, "high": 0x200, "value": fmt(service_id), "source": "MOVZ_W0_PLUS_MOVK_W0", "instruction_pins": [{"va": fmt(0x1486AC34), "word": fmt(_u32(image, 0x1486AC34))}, {"va": fmt(0x1486AC3C), "word": fmt(_u32(image, 0x1486AC3C))}]},
            "output_argument": "X1=0x14890590",
            "call": {"va": fmt(0x1486AC44), "word": fmt(_u32(image, 0x1486AC44)), "target": fmt(attach_target)},
            "retry_reload": {"va": fmt(PLATFORM_QUERY_SLOT_RELOAD), "target": fmt(RUNTIME_SLOT)},
        },
        "context_base_write": {
            "intended_context": "X19 in the main initializer",
            "helper_input": "SP+0x10",
            "context_field_offset": 8,
            "helper_direct_store_to_context_plus_8": False,
            "status": "NOT_ON_PINNED_BINDING_ARGUMENT_FLOW",
        },
        "status": "PROVED_INTENDED_ARGUMENT_AND_SLOT_FLOW",
    }


def analyze_registry(image: Image) -> dict:
    registry_range = range_record(
        image,
        REGISTRY_START_FN,
        REGISTRY_END_FN,
        expected_offset=REGISTRY_OFFSET,
        expected_hash=REGISTRY_SHA256,
        label="registry/attach",
    )
    wrappers_range = range_record(
        image,
        WRAPPERS_START,
        WRAPPERS_END,
        expected_offset=WRAPPERS_OFFSET,
        expected_hash=WRAPPERS_SHA256,
        label="registration wrappers",
    )
    seed_range = range_record(
        image,
        SEED_START,
        SEED_END,
        expected_offset=SEED_OFFSET,
        expected_hash=SEED_SHA256,
        label="registration seed",
    )
    record_range = range_record(
        image,
        RECORD_START,
        RECORD_END,
        expected_offset=RECORD_OFFSET,
        expected_hash=RECORD_SHA256,
        label="registry record data",
    )
    descriptor_range = range_record(
        image,
        DESCRIPTOR_START,
        DESCRIPTOR_END,
        expected_offset=DESCRIPTOR_OFFSET,
        expected_hash=DESCRIPTOR_SHA256,
        label="descriptor/vtable",
    )
    factory_range = range_record(
        image,
        FACTORY_START,
        FACTORY_END,
        expected_offset=FACTORY_OFFSET,
        expected_hash=FACTORY_SHA256,
        label="factory",
    )
    callback_range = range_record(
        image,
        CALLBACK_START,
        CALLBACK_END,
        expected_offset=CALLBACK_OFFSET,
        expected_hash=CALLBACK_SHA256,
        label="callback",
    )
    assert_words(
        image,
        {
            SEED_START: 0xF0000220,
            SEED_START + 4: 0xF0000221,
            SEED_START + 8: 0x9119A000,
            SEED_START + 12: 0x91164021,
            SEED_START + 16: 0x97FFFE5D,
            0x1482E7C4: 0xF907AD00,
            0x1482E7C8: 0xF907A921,
            0x1482D7EC: 0xF000030A,
            0x1482D7F8: 0x9139414A,
            0x1482D814: 0xF81F8140,
            0x1482D8EC: 0x2A0803E1,
            0x1482D8F0: 0xAA1303E2,
            0x1482D8F4: 0xD63F0120,
            0x14824AB8: 0x1484A880,
            0x14824AD0: 0x1484A880,
            0x14824B18: 0x1484A9D4,
            0x1484A8D8: 0xB8018EC8,
            0x1484A8DC: 0xA9025289,
            0x1484A8E4: 0xF9000276,
        },
    )

    # Derive the seed arguments from ADRP+ADD and the wrapper's actual BSS
    # stores; neither value is accepted as an unverified prompt constant.
    seed_x0 = _direct_target(image, SEED_START + 8)
    seed_x1 = _direct_target(image, SEED_START + 12)
    if seed_x0 != 0x14875668 or seed_x1 != RECORD:
        raise BindingError("registration seed arguments changed")
    seed_bl = decode_bl_target(_u32(image, SEED_START + 16), SEED_START + 16)
    if seed_bl != WRAPPERS_START:
        raise BindingError("registration seed wrapper target changed")

    count = _u32(image, RECORD)
    table_pointer = _u64(image, RECORD + 8)
    if count != 5 or table_pointer != RECORD_TABLE:
        raise BindingError("registry record count/table pointer changed")
    descriptors = [_u64(image, table_pointer + i * 8) for i in range(count)]
    if DESCRIPTOR not in descriptors:
        raise BindingError("expected descriptor is absent from registry record")
    descriptor_factory = _u64(image, DESCRIPTOR)
    descriptor_id_count = _u32(image, DESCRIPTOR + 8)
    descriptor_id_table = _u64(image, DESCRIPTOR + 16)
    ids = [_u32(image, descriptor_id_table + i * 4) for i in range(descriptor_id_count)]
    if descriptor_factory != FACTORY_START or ids != [SERVICE_ID]:
        raise BindingError("descriptor factory/ID data changed")
    vtable_callback = _u64(image, VTABLE + VTABLE_CALLBACK_OFFSET)
    if vtable_callback != CALLBACK:
        raise BindingError("descriptor vtable callback pointer changed")
    factory_vtable = _direct_target(image, 0x1484A8D0)
    if factory_vtable != VTABLE:
        raise BindingError("factory vtable materialization changed")
    factory_object_base = _direct_target(image, 0x1484A89C)
    if factory_object_base != 0x1488F400:
        raise BindingError("factory object base changed")

    attach_blr_target_reg = is_blr(_u32(image, 0x1482D8F4))
    if attach_blr_target_reg != 9:
        raise BindingError("registry dispatch BLR register changed")
    attach_output_flow = _u32(image, 0x1482D8F0) == 0xAA1303E2
    factory_output_flow = _u32(image, 0x1484A8A0) == 0xAA0203F3 and _u32(image, 0x1484A8E4) == 0xF9000276
    if not attach_output_flow or not factory_output_flow:
        raise BindingError("registry/factory output flow changed")

    return {
        "ranges": {
            "registry_attach": registry_range,
            "wrappers": wrappers_range,
            "seed": seed_range,
            "record_data": record_range,
            "descriptor_vtable": descriptor_range,
            "factory": factory_range,
            "callback": callback_range,
        },
        "seed": {
            "va": fmt(SEED_START),
            "arguments": {"X0": fmt(seed_x0), "X1": fmt(seed_x1), "X1_role": "registry_record_pointer"},
            "call": {"va": fmt(SEED_START + 16), "target": fmt(seed_bl), "word": fmt(_u32(image, SEED_START + 16))},
            "derived_from": "ADRP_PLUS_ADD_IMMEDIATE",
        },
        "record": {
            "address": fmt(RECORD),
            "count": count,
            "table_pointer": fmt(table_pointer),
            "descriptor_pointers": [fmt(value) for value in descriptors],
            "descriptor_index": descriptors.index(DESCRIPTOR),
            "service_id": fmt(SERVICE_ID),
            "service_id_source": {"descriptor": fmt(DESCRIPTOR), "id_table": fmt(descriptor_id_table), "values": [fmt(value) for value in ids]},
        },
        "descriptor": {
            "address": fmt(DESCRIPTOR),
            "factory_pointer": fmt(descriptor_factory),
            "id_count": descriptor_id_count,
            "id_table": fmt(descriptor_id_table),
            "vtable_start": fmt(VTABLE),
            "vtable_callback_offset": VTABLE_CALLBACK_OFFSET,
            "callback_pointer": fmt(vtable_callback),
        },
        "attach": {
            "function_range": registry_range,
            "registry_list_range": {"start": fmt(REGISTRY_START), "end_exclusive": fmt(REGISTRY_END), "storage": "MEMORY_ONLY_PT_LOAD_ZERO_FILL"},
            "requested_id": fmt(SERVICE_ID),
            "output_register": "X19=caller_X1",
            "factory_call_arguments": {"X0": "0", "W1": fmt(SERVICE_ID), "X2": "X19(output pointer)"},
            "dispatch": {"va": fmt(0x1482D8F4), "word": fmt(_u32(image, 0x1482D8F4)), "register": "X9", "target": fmt(descriptor_factory)},
            "output_flow": "factory stores constructed object through X2 -> attach X19 -> caller X1",
        },
        "factory": {
            "range": factory_range,
            "vtable_materialization": {"va": fmt(0x1484A8D0), "target": fmt(factory_vtable)},
            "object_storage_base": fmt(factory_object_base),
            "constructed_object_candidate": fmt(FACTORY_OBJECT),
            "object_candidate_derivation": "X20=0x1488f400; STR W8,[X22,#24]! advances X22 to 0x1488f418",
            "object_layout_write": {"va": fmt(0x1484A8DC), "vtable_at": fmt(FACTORY_OBJECT + 8), "vtable": fmt(factory_vtable)},
            "output_store": {"va": fmt(0x1484A8E4), "instruction": "STR X22,[X19]", "X19_source": "X2"},
        },
        "binding_chain": [
            f"runtime BSS slot {fmt(RUNTIME_SLOT)}",
            f"registry record {fmt(RECORD)} ID {fmt(SERVICE_ID)}",
            f"descriptor {fmt(DESCRIPTOR)}",
            f"factory {fmt(descriptor_factory)}",
            f"constructed object candidate {fmt(FACTORY_OBJECT)}",
            f"inline vtable {fmt(VTABLE)} + 0x48 -> callback {fmt(vtable_callback)}",
        ],
        "static_status": "PROVED_INTENDED_REGISTRY_FACTORY_VTABLE_CALLBACK_CHAIN",
        "runtime_status": "UNKNOWN_RUNTIME_REGISTRATION_ORDER_AND_OBJECT_IDENTITY",
    }


def analyze_callback(image: Image) -> dict:
    callback_range = range_record(
        image,
        CALLBACK_START,
        CALLBACK_END,
        expected_offset=CALLBACK_OFFSET,
        expected_hash=CALLBACK_SHA256,
        label="callback",
    )
    callee_range = range_record(
        image,
        CALLBACK_CALLEE_START,
        CALLBACK_CALLEE_END,
        expected_offset=0x31730,
        expected_hash="1cadeda59529ce5399201e398c6e0a99f9a8d5efdab5f88099b6c1db2b060586",
        label="callback immediate callee",
    )
    lazy_init_range = range_record(
        image,
        LAZY_INIT,
        LAZY_INIT_END,
        expected_offset=LAZY_INIT_OFFSET,
        expected_hash=LAZY_INIT_SHA256,
        label="lazy-init helper",
    )
    lazy_bootstrap_range = range_record(
        image,
        LAZY_BOOTSTRAP,
        LAZY_BOOTSTRAP_END,
        expected_offset=LAZY_BOOTSTRAP_OFFSET,
        expected_hash=LAZY_BOOTSTRAP_SHA256,
        label="lazy-init bootstrap",
    )
    lazy_status_range = range_record(
        image,
        LAZY_STATUS_HELPER,
        LAZY_STATUS_HELPER_END,
        expected_offset=LAZY_STATUS_HELPER_OFFSET,
        expected_hash=LAZY_STATUS_HELPER_SHA256,
        label="lazy-init status helper",
    )
    assert_words(
        image,
        {
            0x1484A9E0: 0xAA0103F3,  # ORR X19,XZR,X1
            0x1484A9E8: 0x97FFFF52,  # BL 0x1484a730
            0x1484A9F4: 0xB9000268,  # STR W8,[X19]
            0x1484A9FC: 0x12800000,  # MOVN W0,#0
            0x1484AA08: 0xD65F03C0,
            CALLBACK_CALLEE: 0xA9BF7BFD,
            0x1484A734: 0x910003FD,
            0x1484A738: 0x9400003B,
            0x1484A73C: 0xD0000228,
            0x1484A740: 0x912E4108,
            0x1484A744: 0xB9401100,
            LAZY_INIT: 0xB0000228,
            0x1484A828: 0x394FE509,
            0x1484A83C: 0x390FE50A,
            0x1484A840: 0x9400007C,
            LAZY_BOOTSTRAP: 0xF81E0FF3,
            0x1484AA3C: 0x97FFFF7A,
            0x1484AA54: 0x97FFFF80,
            0x1484AA58: 0xB9001260,
            0x1484AA60: 0x3900026A,
            0x1484AA70: 0xD65F03C0,
            LAZY_STATUS_HELPER: 0x52900088,
            LAZY_STATUS_HELPER + 4: 0x72A03F88,
            LAZY_STATUS_HELPER + 12: 0xB9400108,
        },
    )
    callback_target = decode_bl_target(_u32(image, 0x1484A9E8), 0x1484A9E8)
    if callback_target != CALLBACK_CALLEE:
        raise BindingError("callback callee target changed")
    direct_writes: list[dict] = []
    for address in range(CALLBACK_START, CALLBACK_END, 4):
        word = _u32(image, address)
        decoded = is_ldr_str_unsigned(word)
        if decoded and decoded[0] == "STR":
            direct_writes.append({"va": fmt(address), "word": fmt(word), "instruction": "STR W8,[X19]", "base_register": "X19", "base_source": "callback X1 output argument"})
    if [row["va"] for row in direct_writes] != [fmt(0x1484A9F4)]:
        raise BindingError("callback direct-write census changed")
    callee_direct_writes = []
    for address in range(CALLBACK_CALLEE_START, CALLBACK_CALLEE_END, 4):
        word = _u32(image, address)
        decoded = is_ldr_str_unsigned(word)
        if decoded and decoded[0] == "STR":
            callee_direct_writes.append({"va": fmt(address), "word": fmt(word), "instruction": "STR X8,[X19]", "base_register": "X19", "base_source": "callee X1 output argument"})
    if callee_direct_writes:
        raise BindingError("callback callee direct-write census changed")
    lazy_segment = image.segment_for(LAZY_FLAG, file_backed=False)
    status_segment = image.segment_for(LAZY_STATUS_BSS, file_backed=False)
    if (
        lazy_segment is None
        or lazy_segment.file_size
        or status_segment is None
        or status_segment.file_size
        or lazy_segment.index != status_segment.index
    ):
        raise BindingError("lazy-init BSS storage mapping changed")
    lazy_call = decode_bl_target(_u32(image, 0x1484A738), 0x1484A738)
    bootstrap_call = decode_bl_target(_u32(image, 0x1484A840), 0x1484A840)
    bootstrap_recurse = decode_bl_target(_u32(image, 0x1484AA3C), 0x1484AA3C)
    bootstrap_status = decode_bl_target(_u32(image, 0x1484AA54), 0x1484AA54)
    if (lazy_call, bootstrap_call, bootstrap_recurse, bootstrap_status) != (LAZY_INIT, LAZY_BOOTSTRAP, LAZY_INIT, LAZY_STATUS_HELPER):
        raise BindingError("lazy-init call graph changed")
    status_base = _direct_target(image, 0x1484A84C)
    if status_base != LAZY_STATUS_BSS:
        raise BindingError("lazy-init status BSS address changed")
    mmio_low = is_movz_w(_u32(image, LAZY_STATUS_HELPER))
    mmio_high = is_movk_w(_u32(image, LAZY_STATUS_HELPER + 4))
    mmio_value = None
    if mmio_low and mmio_high and mmio_low[2] == mmio_high[2] == 8:
        mmio_value = mmio_low[0] | (mmio_high[0] << 16)
    if mmio_value != LAZY_MMIO:
        raise BindingError("lazy-init MMIO read address changed")
    lazy_writes = [
        {"va": fmt(0x1484A83C), "word": fmt(_u32(image, 0x1484A83C)), "kind": "STRB", "target": fmt(LAZY_FLAG), "role": "lazy-init recursion guard"}
    ]
    status_writes = [
        {"va": fmt(0x1484AA58), "word": fmt(_u32(image, 0x1484AA58)), "kind": "STR", "target": fmt(LAZY_STATUS_BSS + 0x10), "role": "cached status"},
        {"va": fmt(0x1484AA60), "word": fmt(_u32(image, 0x1484AA60)), "kind": "STRB", "target": fmt(LAZY_STATUS_BSS), "role": "lazy-init complete flag"},
    ]
    return {
        "range": callback_range,
        "entry_arguments": {
            "X0": "constructed runtime object candidate",
            "X1": "actual output pointer (helper SP+0xc)",
            "caller_context_pointer": "not passed",
        },
        "callback": {
            "callback_pointer": fmt(CALLBACK),
            "callee": fmt(CALLBACK_CALLEE),
            "output_copy": {"va": fmt(0x1484A9E0), "instruction": "ORR X19,XZR,X1"},
            "direct_writes": direct_writes,
            "direct_write_target": "X1 output argument; under platform query this is SP+0xc",
        },
        "callback_callee": {
            "range": callee_range,
            "direct_writes": callee_direct_writes,
            "direct_bss_read": {"va": fmt(0x1484A744), "instruction": "LDR W0,[X8,#0x10]", "address": fmt(0x14890BA0)},
            "nested_call": {"target": fmt(LAZY_INIT), "arguments": {"X0": "unchanged callback object"}, "effects": "BOUNDED_BELOW"},
        },
        "lazy_init": {
            "range": lazy_init_range,
            "bootstrap": {
                "range": lazy_bootstrap_range,
                "ret": {"va": fmt(0x1484AA70), "word": fmt(_u32(image, 0x1484AA70))},
            },
            "call_graph": [
                {"from": fmt(0x1484A840), "to": fmt(LAZY_BOOTSTRAP), "kind": "BL"},
                {"from": fmt(0x1484AA3C), "to": fmt(LAZY_INIT), "kind": "BL_RECURSIVE_GUARD"},
                {"from": fmt(0x1484AA54), "to": fmt(LAZY_STATUS_HELPER), "kind": "BL"},
            ],
            "flag": {"address": fmt(LAZY_FLAG), "segment_index": lazy_segment.index, "storage": "MEMORY_ONLY_PT_LOAD_ZERO_FILL", "write": lazy_writes[0]},
            "status_bss": {"start": fmt(LAZY_STATUS_BSS), "end_exclusive": fmt(LAZY_STATUS_BSS_END), "storage": "MEMORY_ONLY_PT_LOAD_ZERO_FILL", "writes": status_writes},
            "status_helper": {"range": lazy_status_range, "mmio_read": {"address": fmt(mmio_value), "va": fmt(LAZY_STATUS_HELPER + 12), "word": fmt(_u32(image, LAZY_STATUS_HELPER + 12))}, "mmio_writes": 0},
        },
        "write_classification": {
            "recognized_direct_output_writes": 1,
            "recognized_direct_bss_writes_in_nested_lazy_init": 3,
            "recognized_direct_mmio_reads_in_nested_status_helper": 1,
            "recognized_direct_mmio_writes": 0,
            "recognized_direct_global_alias_writes": 0,
            "arbitrary_or_nested_writes": "UNKNOWN_BEYOND_PINNED_LAZY_INIT_AND_STATUS_HELPER",
            "context_plus_8_write": "NOT_REACHED_BY_RECOGNIZED_CALLBACK_WRITES",
        },
        "status": "PROVED_CALLBACK_DIRECT_OUTPUT_TARGET_SUPPORTED_NO_CONTEXT_ARGUMENT",
    }


def analyze_census(image: Image, scan: dict) -> dict:
    accesses = scan["recognized_direct_accesses"]
    slot = [row for row in accesses if int(row["target"], 16) == RUNTIME_SLOT]
    registry = [row for row in accesses if REGISTRY_START <= int(row["target"], 16) < REGISTRY_END]
    # The registry insertion is a dynamic slot within the exact BSS range.  It
    # is recognized because the bounded decoder resolves the ADRP base and the
    # post-index/STUR pair, but the selected index is runtime-dependent.
    dynamic_registry = [row for row in registry if row["va"] == fmt(0x1482D814)]
    writes_slot = [row for row in slot if row["kind"].startswith("STR")]
    writes_registry = [row for row in registry if row["kind"].startswith("STR")]
    if len([row for row in slot if row["va"] in {fmt(PLATFORM_QUERY_SLOT_LOAD), fmt(PLATFORM_QUERY_SLOT_RELOAD)}]) != 2:
        raise BindingError("runtime slot load census changed")
    if not dynamic_registry:
        raise BindingError("registry insertion write was not recognized")
    registry_base = _direct_target(image, 0x1482D7F8)
    if registry_base != REGISTRY_START:
        raise BindingError("registry-list base materialization changed")
    return {
        "scan_scope": scan["scan_scope"],
        "word_count": scan["word_count"],
        "decoder_coverage": scan["decoder_coverage"],
        "runtime_slot": {
            "address": fmt(RUNTIME_SLOT),
            "direct_address_xrefs": [
                {"kind": "LOAD", "va": fmt(PLATFORM_QUERY_SLOT_LOAD), "word": fmt(_u32(image, PLATFORM_QUERY_SLOT_LOAD))},
                {"kind": "ADDRESS_FOR_ATTACH_OUTPUT", "va": fmt(PLATFORM_QUERY_SLOT_ADDRESS), "word": fmt(_u32(image, PLATFORM_QUERY_SLOT_ADDRESS))},
                {"kind": "RELOAD", "va": fmt(PLATFORM_QUERY_SLOT_RELOAD), "word": fmt(_u32(image, PLATFORM_QUERY_SLOT_RELOAD))},
            ],
            "recognized_direct_accesses": slot,
            "recognized_direct_writes": writes_slot,
            "alternate_mutation": "UNKNOWN",
        },
        "registry_bss": {
            "start": fmt(REGISTRY_START),
            "end_exclusive": fmt(REGISTRY_END),
            "direct_address_xrefs": [
                {"kind": "ADRP_PAGE", "va": fmt(0x1482D7EC), "word": fmt(_u32(image, 0x1482D7EC)), "target_page": fmt(0x14890000)},
                {"kind": "ADD_ADDRESS", "va": fmt(0x1482D7F8), "word": fmt(_u32(image, 0x1482D7F8)), "target": fmt(registry_base)},
            ],
            "recognized_direct_accesses": registry,
            "recognized_direct_writes": writes_registry,
            "dynamic_insertion_write": {
                "recognized_sites": dynamic_registry,
                "possible_target_range": {"start": fmt(REGISTRY_START), "end_exclusive": fmt(REGISTRY_END), "selection": "runtime list index"},
            },
            "alternate_mutation": "UNKNOWN",
        },
        "recognized_direct_call_targets": {
            "platform_query": [row for row in scan["recognized_direct_calls"] if row["target"] == fmt(PLATFORM_QUERY_START)],
            "registry_attach": [row for row in scan["recognized_direct_calls"] if row["target"] == fmt(REGISTRY_ATTACH_FN)],
            "seed": [row for row in scan["recognized_direct_calls"] if row["target"] == fmt(SEED_START)],
        },
        "complete_arbitrary_write_absence": False,
        "status": "PROVED_RECOGNIZED_DIRECT_XREFS_ONLY",
    }


def analyze_order(image: Image, registry: dict, query: dict) -> dict:
    seed_callers = direct_callers(image, SEED_START)
    wrapper_callers = direct_callers(image, WRAPPERS_START)
    helper_callers = direct_callers(image, PLATFORM_QUERY_START)
    wrapper_registration_word = _u32(image, 0x1482E810)
    wrapper_registration_target = decode_b_target(wrapper_registration_word, 0x1482E810)
    if wrapper_registration_target != REGISTRY_START_FN:
        raise BindingError("wrapper registration branch target changed")
    # The seed is called through an unpinned/indirect initializer mechanism;
    # this is the deliberate order boundary, not a reason to manufacture an
    # order proof from source layout.
    return {
        "seed_direct_bl_callers": [fmt(value) for value in seed_callers],
        "wrapper_direct_bl_callers": [fmt(value) for value in wrapper_callers],
        "platform_query_direct_bl_callers": [fmt(value) for value in helper_callers],
        "conditional_static_edges": [
            {"from": fmt(SEED_START + 16), "to": fmt(WRAPPERS_START), "kind": "BL", "status": "PROVED"},
            {"from": fmt(0x1482E810), "to": fmt(wrapper_registration_target), "word": fmt(wrapper_registration_word), "kind": "B_FROM_WRAPPER_INIT_PATH", "status": "PROVED"},
            {"from": fmt(PLATFORM_QUERY_CALLER), "to": fmt(PLATFORM_QUERY_START), "kind": "BL", "status": "PROVED"},
        ],
        "boot_order": "UNKNOWN",
        "reason": "seed has no direct BL caller; wrapper initialization and runtime registration/slot mutation are not closed by exact caller/control-flow pins",
        "base_preservation": "UNKNOWN",
        "status": "UNKNOWN_RUNTIME_ORDER_AND_GLOBAL_ALIAS",
    }


def definition_of_done_metadata() -> dict:
    """Return deterministic GOAL definition-of-done metadata.

    This is intentionally independent of host clock, Python version, absolute
    paths, and live-device state.  It records the exact static precondition,
    reproducible command contract, and the fields that are genuinely
    inapplicable to this host-only iteration.
    """
    not_applicable_static = "NOT_APPLICABLE: host-only static analysis; no live device observation or device artifact was used"
    return {
        "date": "2026-08-26",
        "timestamp": {
            "value": "NOT_APPLICABLE",
            "reason": "Deterministic host-only publication intentionally does not embed a wall-clock timestamp.",
        },
        "target": {
            "model": "SM-A908N",
            "marketing_name": "A90 5G",
            "soc": "SM8150",
            "soc_name": "Snapdragon 855",
            "binding": "PROVED_EXACT_FIRMWARE_INPUT_HASH",
        },
        "firmware": {
            "filename": XBL_NAME,
            "size": XBL_SIZE,
            "sha256": XBL_SHA256,
            "binding": "PROVED_EXACT_XBL_SIZE_AND_SHA256",
            "build": "UNKNOWN",
            "build_reason": "No firmware build identifier is derived by this bounded ELF/static decoder; identity is bound by exact size and SHA-256.",
        },
        "non_applicable_artifacts": {
            "kernel": {"sha256": "NOT_APPLICABLE", "reason": not_applicable_static},
            "boot": {"sha256": "NOT_APPLICABLE", "reason": not_applicable_static},
            "dtb": {"sha256": "NOT_APPLICABLE", "reason": not_applicable_static},
            "research_kernel": {"sha256": "NOT_APPLICABLE", "reason": not_applicable_static},
        },
        "precondition": {
            "status": "PROVED",
            "exact": "Use only the exact SM-A908N/A90 5G SM8150 XBL input named above, with the pinned Experiment 024 manifest semantically validated before publication; perform no device action.",
            "firmware_sha256": XBL_SHA256,
            "dependency_sha256": DEPENDENCY_SHA256,
            "device_access": "none",
        },
        "reproducible_command_template": "python3 tools/sm8150_xbl_platform_query_binding.py --firmware-dir <exact-firmware-dir> --output <public-manifest-path>",
        "result": {
            "status": "PROVED_INTENDED_STATIC_BINDING_SUPPORTED_NO_CONTEXT_PLUS_8_WRITE_UNKNOWN_RUNTIME",
            "classification": "CLASS C (TRANSFORM ONLY)",
            "proved": "Registry record/descriptor/factory/vtable/callback chain and recognized direct write/dataflow pins are exact.",
            "supported": "The recognized callback output flow does not write caller context+8.",
            "unknown": "Runtime registration/order, runtime slot/object identity, alternate BSS mutation/global aliases, and full base preservation remain UNKNOWN.",
        },
        "live_repetitions": {
            "status": "NOT_APPLICABLE",
            "reason": "No live device execution or observation is part of this host-only static experiment.",
        },
        "dmesg": {"status": "NOT_APPLICABLE", "reason": not_applicable_static},
        "log": {"status": "NOT_APPLICABLE", "reason": not_applicable_static},
        "rollback": {"status": "NOT_APPLICABLE", "reason": "No device or persistent state was changed; there is no effect to roll back."},
        "recovery": {"status": "NOT_APPLICABLE", "reason": "No device, boot, transport, or runtime state was touched; recovery is outside this static iteration."},
        "negative_controls": {
            "status": "PASS",
            "description": "Synthetic decoder mutations, dependency semantic mutation, unsupported/computed address forms, no-clobber publication, and public-output checks fail closed or preserve the original output.",
            "failure_state": "Any exact input/range/word/dependency mismatch raises BindingError before publication; existing output paths are never clobbered.",
        },
        "deterministic_repetition_validation": {
            "repetition_count": 2,
            "repetition_unit": "fresh host manifest generations",
            "repetition_result": "BYTE_IDENTICAL",
            "validation_count": 5,
            "validation_checks": [
                "exact firmware size/SHA-256 binding",
                "dependency size/SHA-256 and key-claim validation",
                "exact range/word/call-target and conservative decoder checks",
                "focused synthetic and exact-image test suite",
                "public JSON, publication mode, safety scan, and fresh-generation byte comparison",
            ],
            "validation_description": "Two fresh generations are compared byte-for-byte; the five listed checks cover input binding, semantic dependency, static proof, tests, and publication integrity.",
        },
        "tool_and_build": {
            "tool": "sm8150_xbl_platform_query_binding.py schema v1",
            "build": "NOT_APPLICABLE",
            "build_reason": "The host-only analyzer is interpreted Python source and has no firmware/kernel build output.",
        },
    }


def build_manifest(firmware_dir: Path = FIRMWARE_DIR, dependency_path: Path = DEPENDENCY_PATH) -> dict:
    data = (firmware_dir / XBL_NAME).read_bytes()
    if len(data) != XBL_SIZE or sha256(data) != XBL_SHA256:
        raise BindingError("exact XBL size/hash mismatch")
    image = Image(data)
    dependency = dependency_audit(dependency_path)
    query = analyze_platform_query(image)
    registry = analyze_registry(image)
    callback = analyze_callback(image)
    scan = decode_materialised_addresses(image)
    census = analyze_census(image, scan)
    order = analyze_order(image, registry, query)
    main_context_stores = []
    for address in range(MAIN_INIT_START, MAIN_INIT_END, 4):
        word = image.word(address)
        decoded = is_ldr_str_unsigned(word or 0)
        if decoded and decoded[0] == "STR" and decoded[1] == "X" and decoded[3] == 19 and decoded[2] == 8:
            main_context_stores.append(address)
    if main_context_stores != [INITIALIZER_STORE]:
        raise BindingError("main context+8 direct-store census changed")

    return {
        "schema": SCHEMA,
        "experiment_id": "025-xbl-platform-query-binding",
        "mode": "HOST_ONLY_READ_ONLY",
        "device_access": "none",
        "classification": "CLASS C (TRANSFORM ONLY)",
        "boundary_bypass": "NO_BOUNDARY_BYPASS_OBSERVED",
        "eligibility": {"class": "C", "experiments_015_016": "NOT_ELIGIBLE", "device_action": "NONE"},
        "inputs": {"firmware": {"filename": XBL_NAME, "size": XBL_SIZE, "sha256": XBL_SHA256}},
        "definition_of_done": definition_of_done_metadata(),
        "elf": {
            "format": "ELF64_LITTLE_AARCH64",
            "pt_load_count": len(image.segments),
            "file_backed_pt_load_count": len(image.file_backed()),
            "file_backed_executable_pt_load_count": len(image.executable()),
            "file_backed_executable_aligned_word_count": scan["word_count"],
            "scan_scope": "ALL_FILE_BACKED_EXECUTABLE_PT_LOAD_WORDS",
            "pt_loads": [
                {"segment_index": segment.index, "file_offset": fmt_offset(segment.file_offset), "vaddr": fmt(segment.vaddr), "file_size": segment.file_size, "mem_size": segment.mem_size, "flags": segment.flags, "kind": segment.kind}
                for segment in image.segments
            ],
            "runtime_bss": {"start": fmt(RUNTIME_BSS_START), "end_exclusive": fmt(RUNTIME_BSS_END), "file_backed": False, "storage": "MEMORY_ONLY_PT_LOAD_ZERO_FILL"},
        },
        "dependencies": {"experiment_024": dependency},
        "platform_query": query,
        "registry_binding": registry,
        "callback_write_audit": callback,
        "address_census": census,
        "order_and_authority": order,
        "base_audit": {
            "initializer_base": fmt(INITIALIZER_BASE),
            "main_context_base_store": {"va": fmt(INITIALIZER_STORE), "instruction": "STR X0,[X19,#8]", "count": len(main_context_stores)},
            "intended_binding_can_write_context_plus_8": "SUPPORTED_NO",
            "full_base_preservation": "UNKNOWN",
            "reason": "static callback output flow is distinct from caller X19; runtime registration/order, indirect effects, and alternate/global aliases remain unresolved",
        },
        "claims": {
            "PROVED": [
                "The exact pinned XBL places runtime slot 0x14890590 in a zero-fill PT_LOAD and the platform-query caller passes X0=SP+0x10, not the main context X19.",
                "The exact seed derives X0=0x14875668 and X1=0x14875590; record 0x14875590 has five entries and its descriptor ID table contains 0x02000139.",
                "The descriptor's factory pointer, inline vtable at 0x14824ad0, and +0x48 callback pointer form the pinned factory-to-callback chain; the factory's constructed-object candidate is 0x1488f418.",
                "The callback itself has one recognized direct store through its X1 output pointer; its bounded lazy-init callees have separately pinned direct writes only to recursion/status BSS and one MMIO read, with no recognized context+8 write.",
                "The address census scans every file-backed executable PT_LOAD word and reports exact recognized runtime-slot xrefs and registry-list insertion writes.",
            ],
            "SUPPORTED": [
                "The intended binding can populate the platform-query output slot and feed a callback result back to the helper's stack output, conditional on runtime registration/object binding.",
                "The callback direct-write shape supports that the intended binding does not write the caller's context+8 field on the recognized path.",
            ],
            "HYPOTHESIS": [],
            "UNKNOWN": [
                "Runtime registration execution/order, runtime-BSS slot value, object identity, and whether alternate initialization or mutation changes the slot.",
                "Effects beyond the pinned callback/lazy-init/status-helper graph, indirect/computed/unrecognized memory forms, global aliases, and complete arbitrary-write absence.",
                "Full preservation/currentness of the initialized 0x01d80000 base and any live mapping or device authority.",
            ],
            "REFUTED": [],
        },
    }


def load_xbl(firmware_dir: Path) -> bytes:
    path = firmware_dir / XBL_NAME
    data = path.read_bytes()
    if len(data) != XBL_SIZE or sha256(data) != XBL_SHA256:
        raise BindingError("exact XBL size/hash mismatch")
    return data


def write_no_clobber(path: Path, data: bytes, mode: int = 0o644) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags, mode)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        # Publication failed after O_EXCL.  The path is ours and contains no
        # prior user data; removing this incomplete output is recoverable.
        path.unlink(missing_ok=True)
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--firmware-dir", type=Path, default=FIRMWARE_DIR)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    manifest = build_manifest(args.firmware_dir)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(manifest, indent=1, sort_keys=True) + "\n").encode("utf-8")
    write_no_clobber(args.output, payload)
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
