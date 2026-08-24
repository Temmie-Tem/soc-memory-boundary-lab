#!/usr/bin/env python3
"""Inventory fixed-size DCB blocks in the captured A90 xbl_config ELF.

Only structural metadata and hashes are emitted. Proprietary DCB bytes remain in
the Git-ignored private capture.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Sequence

try:
    from tools.a90_acm_snapshot import json_bytes, write_new
except ModuleNotFoundError:
    from a90_acm_snapshot import json_bytes, write_new


DCB_SIZE = 0x3404
DCB_HEADER_SIZE = 0x64
DCB_SECTION_COUNT = (DCB_HEADER_SIZE - 0x0C) // 4
REQUIRED_DSF_VERSION = 0x00650000
PT_LOAD = 1

LOADER_CONSUMED_SECTIONS = {
    0: {"destination": "xbl_context+0x2b0", "maximum_size": 0x77C},
    1: {"destination": "xbl_context+0x17b8", "maximum_size": 0x3DC},
    2: {"destination": "xbl_context+0x1b94", "maximum_size": 0x108},
    15: {"destination": "xbl_context+0x1c9c", "maximum_size": 0x200},
    16: {"destination": "0x09065100", "maximum_size": 0xF00},
}


@dataclass(frozen=True)
class LoadSegment:
    index: int
    file_offset: int
    virtual_address: int
    physical_address: int
    file_size: int
    memory_size: int
    flags: int
    alignment: int


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_elf64_load_segments(data: bytes) -> list[LoadSegment]:
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise ValueError("input is not ELF")
    if data[4] != 2 or data[5] != 1:
        raise ValueError("input is not little-endian ELF64")
    program_header_offset = struct.unpack_from("<Q", data, 32)[0]
    program_header_size = struct.unpack_from("<H", data, 54)[0]
    program_header_count = struct.unpack_from("<H", data, 56)[0]
    if program_header_size < 56 or program_header_count == 0:
        raise ValueError("ELF program-header table is invalid")
    table_end = program_header_offset + program_header_size * program_header_count
    if table_end > len(data):
        raise ValueError("ELF program-header table is truncated")

    result = []
    for index in range(program_header_count):
        offset = program_header_offset + index * program_header_size
        p_type, flags, file_offset, vaddr, paddr, file_size, memory_size, alignment = (
            struct.unpack_from("<IIQQQQQQ", data, offset)
        )
        if p_type != PT_LOAD:
            continue
        if file_offset + file_size > len(data):
            raise ValueError(f"ELF load segment {index} exceeds input")
        result.append(
            LoadSegment(
                index,
                file_offset,
                vaddr,
                paddr,
                file_size,
                memory_size,
                flags,
                alignment,
            )
        )
    return result


def parse_dcb(block: bytes) -> dict[str, object]:
    if len(block) != DCB_SIZE:
        raise ValueError(f"DCB block size is {len(block)}, expected {DCB_SIZE}")
    crc_field, used_size, dsf_version = struct.unpack_from("<III", block, 0)
    if used_size < DCB_HEADER_SIZE or used_size > DCB_SIZE:
        raise ValueError(f"DCB used-size field is invalid: {used_size}")
    if dsf_version != REQUIRED_DSF_VERSION:
        raise ValueError(
            f"DCB DSF version is 0x{dsf_version:08x}, "
            f"expected 0x{REQUIRED_DSF_VERSION:08x}"
        )

    sections = []
    for index in range(DCB_SECTION_COUNT):
        header_offset = 0x0C + index * 4
        data_offset, size = struct.unpack_from("<HH", block, header_offset)
        if data_offset == 0 and size == 0:
            continue
        if data_offset < DCB_HEADER_SIZE or data_offset + size > used_size:
            raise ValueError(
                f"DCB section {index} range is invalid: offset={data_offset} size={size}"
            )
        section = {
            "index": index,
            "header_offset": f"0x{header_offset:x}",
            "data_offset": f"0x{data_offset:x}",
            "size": size,
            "sha256": sha256(block[data_offset : data_offset + size]),
            "loader_consumption": LOADER_CONSUMED_SECTIONS.get(index),
        }
        if section["loader_consumption"] is not None:
            maximum = int(section["loader_consumption"]["maximum_size"])
            if size > maximum:
                raise ValueError(
                    f"DCB section {index} exceeds XBL loader maximum: {size} > {maximum}"
                )
        sections.append(section)

    return {
        "sha256": sha256(block),
        "crc_field": f"0x{crc_field:08x}",
        "used_size": used_size,
        "dsf_version": f"0x{dsf_version:08x}",
        "nonempty_section_count": len(sections),
        "sections": sections,
    }


def inventory(input_path: Path) -> dict[str, object]:
    data = input_path.read_bytes()
    loads = parse_elf64_load_segments(data)
    dcb_segments = [segment for segment in loads if segment.file_size == DCB_SIZE]
    if len(dcb_segments) != 4:
        raise ValueError(f"expected four 0x{DCB_SIZE:x}-byte DCB load segments")
    records = []
    for segment in dcb_segments:
        block = data[segment.file_offset : segment.file_offset + segment.file_size]
        records.append({"elf_segment": asdict(segment), "dcb": parse_dcb(block)})
    return {
        "schema": "sdm855-xbl-config-dcb-inventory-v1",
        "input_filename": input_path.name,
        "input_size": len(data),
        "input_sha256": sha256(data),
        "dcb_size": DCB_SIZE,
        "dcb_header_size": DCB_HEADER_SIZE,
        "dcb_segment_count": len(records),
        "xbl_loader_evidence": {
            "expected_size_decimal": 13316,
            "expected_size_hex": "0x3404",
            "required_dsf_version": f"0x{REQUIRED_DSF_VERSION:08x}",
            "shrm_copy_destination": "0x09065100",
            "loader_consumed_sections": LOADER_CONSUMED_SECTIONS,
        },
        "records": records,
        "claim_boundary": (
            "PROVED structural DCB blocks and XBL loader consumption; "
            "UNKNOWN semantic identity of each section and final address-map fields"
        ),
    }


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        default=root
        / "evidence/private/004-live-firmware-readonly-20260825-01/xbl_config--sdb2.bin",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=root / "evidence/manifests/004-xbl-dcb-inventory.json",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = inventory(args.input.resolve())
    write_new(args.output.resolve(), json_bytes(result), 0o644)
    print(args.output.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
