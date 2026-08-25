#!/usr/bin/env python3
"""Recover the exact SM8150 XBL raw-dump path covering SHRM snapshots.

Host-only and read-only.  The tool parses the retained A90 XBL bytes, proves
the structure and consumer of the ``SHRM_MEM.BIN`` dump descriptor, and checks
the bounded literal/call references in the embedded Xtensa SHRM image.  It
does not contact a device, execute firmware, read MMIO, issue an SMC, or emit
firmware bytes into the public manifest.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping


REPO_ROOT = Path(__file__).resolve().parents[1]
FIRMWARE_DIR = (
    REPO_ROOT / "evidence/private/004-live-firmware-readonly-20260825-01"
)
DEFAULT_XBL = FIRMWARE_DIR / "xbl--sdb1.bin"
DEFAULT_PRIVATE_OUTPUT = (
    REPO_ROOT
    / "evidence/private/verification-002-shrm-dump-export-20260825-01.json"
)
DEFAULT_PUBLIC_OUTPUT = (
    REPO_ROOT
    / "evidence/manifests/verification-002-shrm-dump-export-20260825-01.manifest.json"
)

XBL_SIZE = 4_194_304
XBL_SHA256 = "e73a07a0b5e3eb9e8db9199eda125ee29b218765f050f85dd934a556549ebe37"

SHRM_DUMP_BASE = 0x09060000
SHRM_DUMP_SIZE = 0x00010000
SHRM_DUMP_DESCRIPTION = "SHRM MEM region"
SHRM_DUMP_FILENAME = "SHRM_MEM.BIN"
SHRM_DUMP_DESCRIPTOR_VADDR = 0x14961990
PRIMARY_TABLE_VADDR = 0x14961730
PRIMARY_TABLE_COUNT = 0x1A
PRIMARY_TABLE_RECORD_SIZE = 0x20
PRIMARY_TABLE_SHA256 = (
    "5f075f4850460326b5e7ef08f43cbddcf4f5b88835bed9ab2908e18eee01a641"
)

RAW_DUMP_SOURCE_STRING = "boot_raw_partition_ramdump.c"
RAW_DUMP_SOURCE_VADDR = 0x14961150
RAW_DUMP_SUCCESS_STRING = "RawDump successfully, Reset the device"
RAW_DUMP_SUCCESS_VADDR = 0x1496116D

DLOAD_CALLER_START = 0x14902CB8
DLOAD_CALLER_END = 0x14902CE8
DLOAD_CALLER_SHA256 = (
    "9b4cc75011cd7be22a5f4bd3c1b5981172a710b0b00315a922679d8b41505741"
)
DLOAD_TO_CATALOG_CALL = 0x14902CC4
CATALOG_BUILDER_START = 0x14917740
CATALOG_BUILDER_END = 0x14917850
CATALOG_BUILDER_SHA256 = (
    "acbe214bd36145a85b1589aa304f70c0a2622f2a88ea045ff56835e1ad8ae8cd"
)
CATALOG_TO_CONSUMER_CALL = 0x1491777C
CATALOG_CONSUMER_START = 0x14917C60
CATALOG_CONSUMER_END = 0x14918120
CATALOG_CONSUMER_SHA256 = (
    "2fab065997d82497eb15a591cc0249f0ac59686306bf67c0eb7fff782e20f84a"
)
PRIMARY_LOOP_START = 0x14917CA8
PRIMARY_LOOP_END = 0x14917CF4
PRIMARY_LOOP_SHA256 = (
    "b7e02af33970d81ed6a38c643f96141ae88ad478efc53900317f4465f2138857"
)
PRIMARY_LOOP_REGISTER_CALL = 0x14917CDC
REGION_REGISTER_FUNCTION = 0x14917670

GATE_STRINGS = (
    "@ FMM Lock is On, Ramdump is not Allowed! Hard Reset...",
    "DebugLevel : %d, ForceUploadFlag : %d",
    "@ Debug level LOW && ram dump not allowed, skip dump summary !",
)

SHRM_BLOB_XBL_VADDR = 0x148BBE98
SHRM_BLOB_SIZE = 0x5CE0
SHRM_BLOB_SHA256 = (
    "421824b417ab28e6c0d1802c05d7ce5422e93b116973ce7f039321fb5a01a1fd"
)
SHRM_CODE_BASE = 0x28000
SHRM_WORKSPACE_LOCAL = 0x25100
SHRM_WORKSPACE_PHYSICAL = 0x09065100
SHRM_WORKSPACE_SIZE = 0xF00
SNAPSHOT_SET0_LOCAL = 0x25330
SNAPSHOT_SET1_LOCAL = 0x259E8
SNAPSHOT_SET0_PHYSICAL = 0x09065330
SNAPSHOT_SET1_PHYSICAL = 0x090659E8
SHRM_LITERAL_VADDR = 0x2819C
SHRM_HELPER_VADDR = 0x2D8DC

SHRM_CALLSITES: Mapping[str, Mapping[str, int | str]] = {
    "set0": {
        "function_entry": 0x287F4,
        "l32r_pc": 0x288A9,
        "direction_pc": 0x288AF,
        "call_pc": 0x288C4,
        "snapshot_local": SNAPSHOT_SET0_LOCAL,
        "snapshot_physical": SNAPSHOT_SET0_PHYSICAL,
        "register_word_count": 430,
        "function_stream": "conditional fatal/exception path",
    },
    "set1": {
        "function_entry": 0x28DBC,
        "l32r_pc": 0x28E15,
        "direction_pc": 0x28E1B,
        "call_pc": 0x28E30,
        "snapshot_local": SNAPSHOT_SET1_LOCAL,
        "snapshot_physical": SNAPSHOT_SET1_PHYSICAL,
        "register_word_count": 64,
        "function_stream": "conditional fatal/exception path",
    },
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sign_extend(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


@dataclass(frozen=True)
class Segment:
    offset: int
    vaddr: int
    filesz: int


class ElfImage:
    """Minimal ELF64 PT_LOAD mapper used without repository helper modules."""

    def __init__(self, data: bytes) -> None:
        if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            raise ValueError("input is not a little-endian ELF64 image")
        self.data = data
        self.segments = self._parse_segments()

    def _parse_segments(self) -> list[Segment]:
        phoff = struct.unpack_from("<Q", self.data, 0x20)[0]
        phentsize = struct.unpack_from("<H", self.data, 0x36)[0]
        phnum = struct.unpack_from("<H", self.data, 0x38)[0]
        if phentsize < 56:
            raise ValueError("ELF64 program-header entry is too short")
        result = []
        for index in range(phnum):
            base = phoff + index * phentsize
            if base + 56 > len(self.data):
                raise ValueError("ELF64 program-header table is truncated")
            p_type = struct.unpack_from("<I", self.data, base)[0]
            p_offset, p_vaddr, _p_paddr, p_filesz = struct.unpack_from(
                "<QQQQ", self.data, base + 8
            )
            if p_type == 1 and p_filesz:
                if p_offset + p_filesz > len(self.data):
                    raise ValueError("ELF64 load segment crosses the input")
                result.append(Segment(p_offset, p_vaddr, p_filesz))
        if not result:
            raise ValueError("ELF64 image has no file-backed PT_LOAD segment")
        return result

    def offset_to_vaddr(self, offset: int) -> int | None:
        for segment in self.segments:
            if segment.offset <= offset < segment.offset + segment.filesz:
                return segment.vaddr + offset - segment.offset
        return None

    def vaddr_to_offset(self, vaddr: int) -> int | None:
        for segment in self.segments:
            if segment.vaddr <= vaddr < segment.vaddr + segment.filesz:
                return segment.offset + vaddr - segment.vaddr
        return None

    def read_vaddr(self, vaddr: int, size: int) -> bytes:
        offset = self.vaddr_to_offset(vaddr)
        if offset is None:
            raise ValueError(f"virtual address 0x{vaddr:x} is not file-backed")
        segment = next(
            segment
            for segment in self.segments
            if segment.vaddr <= vaddr < segment.vaddr + segment.filesz
        )
        if vaddr + size > segment.vaddr + segment.filesz:
            raise ValueError("virtual read crosses a file-backed segment")
        return self.data[offset : offset + size]

    def u32(self, vaddr: int) -> int:
        return struct.unpack("<I", self.read_vaddr(vaddr, 4))[0]

    def u64(self, vaddr: int) -> int:
        return struct.unpack("<Q", self.read_vaddr(vaddr, 8))[0]

    def cstring(self, vaddr: int, limit: int = 256) -> str:
        offset = self.vaddr_to_offset(vaddr)
        if offset is None:
            raise ValueError(f"string pointer 0x{vaddr:x} is not file-backed")
        end = self.data.find(b"\0", offset, min(offset + limit, len(self.data)))
        if end < 0:
            raise ValueError(f"string at 0x{vaddr:x} is unterminated")
        return self.data[offset:end].decode("ascii")

    def unique_string_vaddr(self, value: str) -> int:
        needle = value.encode("ascii") + b"\0"
        hits = []
        cursor = 0
        while True:
            offset = self.data.find(needle, cursor)
            if offset < 0:
                break
            vaddr = self.offset_to_vaddr(offset)
            if vaddr is not None:
                hits.append(vaddr)
            cursor = offset + 1
        if len(hits) != 1:
            raise ValueError(f"expected one loaded string {value!r}, found {len(hits)}")
        return hits[0]


def _decode_aarch64_bl(word: int, pc: int) -> int:
    if word & 0xFC000000 != 0x94000000:
        raise ValueError(f"0x{word:08x} at 0x{pc:x} is not AArch64 BL")
    return pc + (_sign_extend(word & 0x03FFFFFF, 26) << 2)


def _decode_aarch64_adrp(word: int, pc: int) -> tuple[int, int]:
    if word & 0x9F000000 != 0x90000000:
        raise ValueError(f"0x{word:08x} at 0x{pc:x} is not AArch64 ADRP")
    rd = word & 0x1F
    immlo = (word >> 29) & 0x3
    immhi = (word >> 5) & 0x7FFFF
    immediate = _sign_extend((immhi << 2) | immlo, 21) << 12
    return rd, (pc & ~0xFFF) + immediate


def _decode_aarch64_add_immediate(word: int) -> tuple[int, int, int]:
    if word & 0x7F000000 != 0x11000000:
        raise ValueError(f"0x{word:08x} is not AArch64 ADD-immediate")
    rd = word & 0x1F
    rn = (word >> 5) & 0x1F
    immediate = (word >> 10) & 0xFFF
    if (word >> 22) & 1:
        immediate <<= 12
    return rd, rn, immediate


def _decode_aarch64_compare_immediate(word: int) -> tuple[int, int]:
    # CMP Xn,#imm is the SUBS-immediate alias with Rd == XZR.
    if word & 0x7F00001F != 0x7100001F:
        raise ValueError(f"0x{word:08x} is not AArch64 CMP-immediate")
    rn = (word >> 5) & 0x1F
    immediate = (word >> 10) & 0xFFF
    if (word >> 22) & 1:
        immediate <<= 12
    return rn, immediate


def _decode_xtensa_l32r(raw: bytes, pc: int) -> tuple[int, int]:
    if len(raw) != 3 or raw[0] & 0xF != 1:
        raise ValueError(f"bytes at 0x{pc:x} are not Xtensa L32R")
    register = (raw[0] >> 4) & 0xF
    immediate = _sign_extend(raw[1] | (raw[2] << 8), 16)
    literal = ((pc + 3) & ~3) + (immediate << 2)
    return register, literal


def _decode_xtensa_call0(raw: bytes, pc: int) -> int:
    if len(raw) != 3:
        raise ValueError("Xtensa CALL0 requires three bytes")
    word = raw[0] | (raw[1] << 8) | (raw[2] << 16)
    if word & 0x3F != 0x05:
        raise ValueError(f"bytes at 0x{pc:x} are not Xtensa CALL0")
    immediate = _sign_extend(word >> 6, 18)
    return (pc & ~3) + 4 + (immediate << 2)


def _find_all(data: bytes, needle: bytes) -> list[int]:
    result = []
    cursor = 0
    while True:
        offset = data.find(needle, cursor)
        if offset < 0:
            return result
        result.append(offset)
        cursor = offset + 1


def _read_dump_descriptor(image: ElfImage, vaddr: int) -> dict[str, object]:
    base, size, description_pointer, filename_pointer = struct.unpack(
        "<QQQQ", image.read_vaddr(vaddr, PRIMARY_TABLE_RECORD_SIZE)
    )
    return {
        "vaddr": vaddr,
        "base": base,
        "size": size,
        "description_pointer": description_pointer,
        "filename_pointer": filename_pointer,
        "description": image.cstring(description_pointer),
        "filename": image.cstring(filename_pointer),
    }


def _descriptor_is_plausible(image: ElfImage, vaddr: int) -> bool:
    try:
        record = _read_dump_descriptor(image, vaddr)
    except (UnicodeDecodeError, ValueError):
        return False
    return (
        0 < int(record["size"]) < 0x1_0000_0000
        and 0 <= int(record["base"]) < 0x1_0000_0000
        and bool(record["description"])
        and bool(record["filename"])
    )


def _discover_shrm_descriptor(image: ElfImage) -> dict[str, object]:
    description_vaddr = image.unique_string_vaddr(SHRM_DUMP_DESCRIPTION)
    filename_vaddr = image.unique_string_vaddr(SHRM_DUMP_FILENAME)
    packed = struct.pack(
        "<QQQQ",
        SHRM_DUMP_BASE,
        SHRM_DUMP_SIZE,
        description_vaddr,
        filename_vaddr,
    )
    offsets = _find_all(image.data, packed)
    loaded = [
        (offset, image.offset_to_vaddr(offset))
        for offset in offsets
        if image.offset_to_vaddr(offset) is not None
    ]
    if len(loaded) != 1:
        raise ValueError(f"expected one loaded SHRM dump descriptor, found {len(loaded)}")
    offset, vaddr = loaded[0]
    assert vaddr is not None
    record = _read_dump_descriptor(image, vaddr)
    record["file_offset"] = offset
    return record


def _discover_containing_table(
    image: ElfImage, descriptor_vaddr: int
) -> tuple[int, list[dict[str, object]]]:
    start = descriptor_vaddr
    while _descriptor_is_plausible(image, start - PRIMARY_TABLE_RECORD_SIZE):
        start -= PRIMARY_TABLE_RECORD_SIZE
    records = []
    cursor = start
    while _descriptor_is_plausible(image, cursor):
        records.append(_read_dump_descriptor(image, cursor))
        cursor += PRIMARY_TABLE_RECORD_SIZE
    if not records:
        raise ValueError("no dump descriptor table surrounds the SHRM record")
    return start, records


def _validate_exact_code(image: ElfImage) -> dict[str, object]:
    pins = (
        (DLOAD_CALLER_START, DLOAD_CALLER_END, DLOAD_CALLER_SHA256),
        (CATALOG_BUILDER_START, CATALOG_BUILDER_END, CATALOG_BUILDER_SHA256),
        (CATALOG_CONSUMER_START, CATALOG_CONSUMER_END, CATALOG_CONSUMER_SHA256),
        (PRIMARY_LOOP_START, PRIMARY_LOOP_END, PRIMARY_LOOP_SHA256),
    )
    verified = []
    for start, end, expected in pins:
        raw = image.read_vaddr(start, end - start)
        actual = sha256(raw)
        if actual != expected:
            raise ValueError(f"code pin at 0x{start:x} has SHA-256 {actual}, not {expected}")
        verified.append(
            {
                "start": f"0x{start:x}",
                "end_exclusive": f"0x{end:x}",
                "size": len(raw),
                "sha256": actual,
            }
        )

    call_chain = []
    for pc, expected_target, label in (
        (DLOAD_TO_CATALOG_CALL, CATALOG_BUILDER_START, "dload_path_to_catalog_builder"),
        (CATALOG_TO_CONSUMER_CALL, CATALOG_CONSUMER_START, "catalog_builder_to_consumer"),
        (PRIMARY_LOOP_REGISTER_CALL, REGION_REGISTER_FUNCTION, "table_loop_to_region_registrar"),
    ):
        word = image.u32(pc)
        target = _decode_aarch64_bl(word, pc)
        if target != expected_target:
            raise ValueError(
                f"{label} target is 0x{target:x}, expected 0x{expected_target:x}"
            )
        call_chain.append(
            {
                "label": label,
                "pc": f"0x{pc:x}",
                "word": f"0x{word:08x}",
                "target": f"0x{target:x}",
            }
        )

    adrp_register, table_page = _decode_aarch64_adrp(
        image.u32(PRIMARY_LOOP_START), PRIMARY_LOOP_START
    )
    add_rd, add_rn, page_offset = _decode_aarch64_add_immediate(
        image.u32(PRIMARY_LOOP_START + 4)
    )
    if not (adrp_register == add_rd == add_rn == 9):
        raise ValueError("primary dump loop does not preserve its table base in x9")
    table_vaddr = table_page + page_offset
    if table_vaddr != PRIMARY_TABLE_VADDR:
        raise ValueError(
            f"primary dump loop table is 0x{table_vaddr:x}, expected 0x{PRIMARY_TABLE_VADDR:x}"
        )

    stride_rd, stride_rn, stride = _decode_aarch64_add_immediate(
        image.u32(0x14917CD8)
    )
    count_register, count = _decode_aarch64_compare_immediate(
        image.u32(0x14917CC4)
    )
    if image.u32(0x14917CCC) != 0xA97F0901:
        raise ValueError("primary loop base/size LDP opcode changed")
    if image.u32(0x14917CD0) != 0xA9401103:
        raise ValueError("primary loop description/filename LDP opcode changed")
    if image.u32(0x14917CD4) != 0x320003E0:
        raise ValueError("primary loop mode argument is no longer w0=1")
    if (stride_rd, stride_rn, stride) != (21, 8, PRIMARY_TABLE_RECORD_SIZE):
        raise ValueError("primary dump loop record stride changed")
    if (count_register, count) != (27, PRIMARY_TABLE_COUNT):
        raise ValueError("primary dump loop record count changed")

    source_vaddr = image.unique_string_vaddr(RAW_DUMP_SOURCE_STRING)
    success_vaddr = image.unique_string_vaddr(RAW_DUMP_SUCCESS_STRING)
    if source_vaddr != RAW_DUMP_SOURCE_VADDR or success_vaddr != RAW_DUMP_SUCCESS_VADDR:
        raise ValueError("raw-dump source/message string address changed")
    gates = []
    for value in GATE_STRINGS:
        gates.append({"string": value, "vaddr": f"0x{image.unique_string_vaddr(value):x}"})

    return {
        "code_pins": verified,
        "call_chain": call_chain,
        "primary_loop": {
            "start": f"0x{PRIMARY_LOOP_START:x}",
            "table_vaddr": f"0x{table_vaddr:x}",
            "record_count": count,
            "record_stride": stride,
            "loads": [
                "x1=physical_base, x2=size",
                "x3=description_pointer, x4=filename_pointer",
            ],
            "registrar": f"0x{REGION_REGISTER_FUNCTION:x}",
            "mode_argument_w0": 1,
        },
        "module_evidence": {
            "source_string": RAW_DUMP_SOURCE_STRING,
            "source_string_vaddr": f"0x{source_vaddr:x}",
            "success_string": RAW_DUMP_SUCCESS_STRING,
            "success_string_vaddr": f"0x{success_vaddr:x}",
            "static_gate_strings": gates,
        },
    }


def _analyze_shrm_blob(image: ElfImage) -> dict[str, object]:
    blob = image.read_vaddr(SHRM_BLOB_XBL_VADDR, SHRM_BLOB_SIZE)
    actual = sha256(blob)
    if actual != SHRM_BLOB_SHA256:
        raise ValueError(f"embedded SHRM blob SHA-256 is {actual}, not the pin")

    def local_bytes(vaddr: int, size: int) -> bytes:
        offset = vaddr - SHRM_CODE_BASE
        if not 0 <= offset <= len(blob) - size:
            raise ValueError(f"SHRM local read 0x{vaddr:x}+0x{size:x} is outside blob")
        return blob[offset : offset + size]

    literal_hits = {}
    for value in (
        SHRM_WORKSPACE_LOCAL,
        SNAPSHOT_SET0_LOCAL,
        SNAPSHOT_SET1_LOCAL,
        SHRM_WORKSPACE_PHYSICAL,
        SNAPSHOT_SET0_PHYSICAL,
        SNAPSHOT_SET1_PHYSICAL,
    ):
        literal_hits[f"0x{value:x}"] = [
            f"0x{SHRM_CODE_BASE + offset:x}"
            for offset in _find_all(blob, struct.pack("<I", value))
        ]
    if literal_hits[f"0x{SHRM_WORKSPACE_LOCAL:x}"] != [f"0x{SHRM_LITERAL_VADDR:x}"]:
        raise ValueError("SHRM workspace literal is not unique at the pinned address")
    for value in (
        SNAPSHOT_SET0_LOCAL,
        SNAPSHOT_SET1_LOCAL,
        SHRM_WORKSPACE_PHYSICAL,
        SNAPSHOT_SET0_PHYSICAL,
        SNAPSHOT_SET1_PHYSICAL,
    ):
        if literal_hits[f"0x{value:x}"]:
            raise ValueError(f"unexpected direct SHRM snapshot literal 0x{value:x}")

    callsites = []
    for name, pin in SHRM_CALLSITES.items():
        l32r_pc = int(pin["l32r_pc"])
        direction_pc = int(pin["direction_pc"])
        call_pc = int(pin["call_pc"])
        register, literal_vaddr = _decode_xtensa_l32r(local_bytes(l32r_pc, 3), l32r_pc)
        literal_value = struct.unpack("<I", local_bytes(literal_vaddr, 4))[0]
        helper_target = _decode_xtensa_call0(local_bytes(call_pc, 3), call_pc)
        direction_raw = local_bytes(direction_pc, 2)
        if (register, literal_vaddr, literal_value) != (
            4,
            SHRM_LITERAL_VADDR,
            SHRM_WORKSPACE_LOCAL,
        ):
            raise ValueError(f"{name} no longer loads the section-16 workspace in a4")
        if direction_raw != bytes.fromhex("0c02"):
            raise ValueError(f"{name} direction setup is no longer movi.n a2,0")
        if helper_target != SHRM_HELPER_VADDR:
            raise ValueError(f"{name} helper target changed to 0x{helper_target:x}")
        callsites.append(
            {
                "name": name,
                "function_entry": f"0x{int(pin['function_entry']):x}",
                "function_stream": pin["function_stream"],
                "l32r_pc": f"0x{l32r_pc:x}",
                "workspace_literal_vaddr": f"0x{literal_vaddr:x}",
                "workspace_local_value": f"0x{literal_value:x}",
                "direction_pc": f"0x{direction_pc:x}",
                "direction_argument": 0,
                "helper_call_pc": f"0x{call_pc:x}",
                "helper_target": f"0x{helper_target:x}",
                "snapshot_local": f"0x{int(pin['snapshot_local']):x}",
                "snapshot_physical": f"0x{int(pin['snapshot_physical']):x}",
                "register_word_count": pin["register_word_count"],
            }
        )

    return {
        "xbl_virtual_address": f"0x{SHRM_BLOB_XBL_VADDR:x}",
        "size": len(blob),
        "sha256": actual,
        "xtensa_code_base": f"0x{SHRM_CODE_BASE:x}",
        "workspace": {
            "local_start": f"0x{SHRM_WORKSPACE_LOCAL:x}",
            "physical_start": f"0x{SHRM_WORKSPACE_PHYSICAL:x}",
            "size": SHRM_WORKSPACE_SIZE,
        },
        "direct_u32_literal_hits": literal_hits,
        "section16_read_callsites": callsites,
        "bounded_negative": (
            "The exact SHRM instruction blob contains no direct u32 literal for "
            "either snapshot destination or its physical address. This excludes "
            "a direct/literal consumer, not a dynamically derived pointer."
        ),
    }


def analyze(xbl_data: bytes) -> dict[str, object]:
    if len(xbl_data) != XBL_SIZE:
        raise ValueError(f"XBL size is {len(xbl_data)}, expected {XBL_SIZE}")
    actual_hash = sha256(xbl_data)
    if actual_hash != XBL_SHA256:
        raise ValueError(f"XBL SHA-256 is {actual_hash}, not the exact pin")
    image = ElfImage(xbl_data)

    descriptor = _discover_shrm_descriptor(image)
    table_vaddr, records = _discover_containing_table(
        image, int(descriptor["vaddr"])
    )
    if table_vaddr != PRIMARY_TABLE_VADDR or len(records) != PRIMARY_TABLE_COUNT:
        raise ValueError(
            f"primary table is 0x{table_vaddr:x}/{len(records)} records, expected "
            f"0x{PRIMARY_TABLE_VADDR:x}/{PRIMARY_TABLE_COUNT}"
        )
    table_raw = image.read_vaddr(
        table_vaddr, PRIMARY_TABLE_COUNT * PRIMARY_TABLE_RECORD_SIZE
    )
    table_hash = sha256(table_raw)
    if table_hash != PRIMARY_TABLE_SHA256:
        raise ValueError("primary dump table SHA-256 mismatch")
    shrm_indices = [
        index
        for index, record in enumerate(records)
        if int(record["vaddr"]) == int(descriptor["vaddr"])
    ]
    if shrm_indices != [19]:
        raise ValueError(f"SHRM descriptor indices are {shrm_indices}, expected [19]")

    code = _validate_exact_code(image)
    shrm_blob = _analyze_shrm_blob(image)

    dump_end = SHRM_DUMP_BASE + SHRM_DUMP_SIZE
    workspace_end = SHRM_WORKSPACE_PHYSICAL + SHRM_WORKSPACE_SIZE
    if not (
        SHRM_DUMP_BASE <= SHRM_WORKSPACE_PHYSICAL
        and workspace_end <= dump_end
        and SHRM_DUMP_BASE <= SNAPSHOT_SET0_PHYSICAL < dump_end
        and SHRM_DUMP_BASE <= SNAPSHOT_SET1_PHYSICAL < dump_end
    ):
        raise ValueError("SHRM raw-dump descriptor does not cover both snapshots")

    public_descriptor = {
        "table_vaddr": f"0x{table_vaddr:x}",
        "table_record_count": len(records),
        "table_record_size": PRIMARY_TABLE_RECORD_SIZE,
        "table_sha256": table_hash,
        "index": shrm_indices[0],
        "descriptor_vaddr": f"0x{int(descriptor['vaddr']):x}",
        "descriptor_file_offset": f"0x{int(descriptor['file_offset']):x}",
        "base": f"0x{int(descriptor['base']):08x}",
        "size": int(descriptor["size"]),
        "end_exclusive": f"0x{dump_end:08x}",
        "description": descriptor["description"],
        "filename": descriptor["filename"],
        "workspace_covered": True,
        "snapshot_set0_covered": True,
        "snapshot_set1_covered": True,
    }

    return {
        "raw_dump_descriptor": public_descriptor,
        "xbl_consumer": code,
        "embedded_shrm": shrm_blob,
        "claims": {
            "PROVED": [
                "Exact XBL contains a 26-record raw-dump table whose index 19 covers physical 0x09060000..0x0906ffff and names the output SHRM_MEM.BIN.",
                "The exact AArch64 loop loads each 32-byte record as physical base, size, description and filename, then calls the region registrar at 0x14917670.",
                "The static dload call chain is 0x14902cc4 -> 0x14917740 -> 0x14917c60; the consumer contains the 26-record loop at 0x14917ca8.",
                "The dump range contains the complete section-16 workspace and both staged snapshot destinations.",
                "The exact Xtensa blob uses one workspace-base literal through two direction-zero calls to helper 0x2d8dc and has no direct u32 literal for either derived snapshot destination.",
            ],
            "SUPPORTED": [
                "SHRM_MEM.BIN is a bootloader crash/download raw-dump export path, not a normal Android HLOS runtime interface.",
                "If the retail dump gates permit collection and SHRM state survives the reset path, this catalog is a safer observation candidate than another direct EL1 read.",
            ],
            "HYPOTHESIS": [
                "A successfully collected SHRM_MEM.BIN may retain the 430/64 staged controller words populated before the fatal reset.",
            ],
            "REFUTED": [
                "No firmware export path covers the protected SHRM snapshot workspace.",
                "The exact embedded SHRM blob itself contains a direct/literal HLOS mailbox consumer for either snapshot destination.",
            ],
            "UNKNOWN": [
                "Whether FMM/debug-level/token policy enables this dump path on the exact retail A90 state.",
                "Whether the snapshot helpers ran before a given reset and whether their data remains valid when XBL collects the region.",
                "Whether an existing SD/rawdump artifact contains SHRM_MEM.BIN and which transport exposes the catalog on this target.",
                "Whether any normal-boot HLOS-readable diagnostic or shared-memory interface exports the same words without entering the bootloader dump path.",
                "The runtime values, lock state and final-decode meaning of the staged controller words.",
            ],
        },
        "classification": "BOOTLOADER_RAWDUMP_EXPORT_PRESENT_HLOS_RUNTIME_EXPORT_UNPROVED",
    }


def build_manifests(
    xbl_path: Path, xbl_data: bytes
) -> tuple[dict[str, object], dict[str, object]]:
    common = {
        "schema": "sdm855-shrm-dump-export-inventory-v1",
        "mode": "HOST_ONLY_READ_ONLY",
        "device_access": False,
        "smc_access": False,
        "mmio_access": False,
        "firmware_bytes_emitted": False,
        "input": {
            "filename": xbl_path.name,
            "size": len(xbl_data),
            "sha256": sha256(xbl_data),
            "pin_verified": True,
        },
        **analyze(xbl_data),
    }
    public = copy.deepcopy(common)
    public["schema"] = "sdm855-shrm-dump-export-inventory-public-v1"
    private = copy.deepcopy(common)
    private["schema"] = "sdm855-shrm-dump-export-inventory-private-v1"
    private["input"]["path"] = str(xbl_path.resolve())
    return private, public


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _write_output(path: Path, data: bytes, mode: int, replace: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not replace:
        raise FileExistsError(f"refusing to replace {path}; pass --replace")
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists():
        raise FileExistsError(f"temporary output already exists: {temporary}")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _hex_lines(values: Iterable[str]) -> str:
    return ", ".join(values) if values else "none"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xbl", type=Path, default=DEFAULT_XBL)
    parser.add_argument("--private-output", type=Path, default=DEFAULT_PRIVATE_OUTPUT)
    parser.add_argument("--public-output", type=Path, default=DEFAULT_PUBLIC_OUTPUT)
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args(argv)

    xbl_data = args.xbl.read_bytes()
    private, public = build_manifests(args.xbl, xbl_data)
    descriptor = public["raw_dump_descriptor"]
    literals = public["embedded_shrm"]["direct_u32_literal_hits"]
    print(
        "PROVED: XBL raw-dump index "
        f"{descriptor['index']} covers {descriptor['base']}..{descriptor['end_exclusive']} "
        f"as {descriptor['filename']}"
    )
    print(
        "PROVED: primary consumer loop has "
        f"{descriptor['table_record_count']} records and calls "
        f"{public['xbl_consumer']['primary_loop']['registrar']}"
    )
    print(
        "PROVED: direct local destination literals: set0="
        f"{_hex_lines(literals[f'0x{SNAPSHOT_SET0_LOCAL:x}'])}, set1="
        f"{_hex_lines(literals[f'0x{SNAPSHOT_SET1_LOCAL:x}'])}"
    )
    print(f"CLASSIFICATION: {public['classification']}")

    if args.replace:
        _write_output(args.private_output, _json_bytes(private), 0o600, True)
        _write_output(args.public_output, _json_bytes(public), 0o644, True)
        print(f"wrote {args.private_output}")
        print(f"wrote {args.public_output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
