#!/usr/bin/env python3
"""Inventory the exact A90 XBL DCB, SHRM and ICB remapper pipeline.

The input firmware remains private.  The emitted JSON contains only structural
metadata, addresses, sizes and hashes needed to reproduce the analysis.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import struct
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Sequence

try:
    from tools.a90_acm_snapshot import json_bytes, write_new
    from tools.xbl_dcb_inventory import LoadSegment, parse_dcb, parse_elf64_load_segments
except ModuleNotFoundError:  # Direct execution from tools/.
    from a90_acm_snapshot import json_bytes, write_new
    from xbl_dcb_inventory import LoadSegment, parse_dcb, parse_elf64_load_segments


CFGL_MAGIC = b"CFGL"
CFGL_HEADER_SIZE = 0x10
CFGL_ENTRY_STRIDE = 0x28
DCB_NAME_RE = re.compile(
    r"^/(?P<hardware_id>[0-9A-Fa-f]{4})_"
    r"(?P<hardware_version>[0-9A-Fa-f]{4})_"
    r"(?P<physical_platform>[01])_dcb\.bin$"
)

DCB_SELECTOR_FORMAT = "/%04X_%04X_%01X_dcb.bin"
SOC_HW_VERSION_REGISTER = 0x01FC8000
PHYSICAL_PLATFORM_RUMI_VALUE = 0x0F

SHRM_CSR_BASE = 0x09050000
SHRM_MEMORY_BASE = 0x09060000
SHRM_MPU_BASE = 0x09102000
SHRM_SECTION16_DESTINATION = 0x09065100
SHRM_BLOBS = (
    {
        "name": "data",
        "virtual_address": 0x148BB630,
        "size": 0x868,
        "copy_function": 0x148AEB7C,
        "first_destination": 0x09062100,
    },
    {
        "name": "instruction",
        "virtual_address": 0x148BBE98,
        "size": 0x5CE0,
        "copy_function": 0x148AEBFC,
        "first_destination": 0x09068000,
    },
)

REMAPPER_TABLE_VADDR = 0x14874A38
REMAPPER_TABLE_COUNT = 13
REMAPPER_ENTRY_SIZE = 0x20

ICB_PROPERTY_SOURCE_VADDR = 0x14821FF0
ICB_PROPERTY_PATH = "/dev/icbcfg/boot"
ICB_PROPERTY_NAME = "icbcfg_info"
ICB_STRUCT_POINTER_TYPE = 0x12
ICB_DEVICE_ENTRY_SIZE = 0x28
ICB_SELECTED_LAYOUT = 1


@dataclass(frozen=True)
class CfglEntry:
    index: int
    descriptor_file_offset: int
    relative_data_offset: int
    data_file_offset: int
    data_size: int
    name: str


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def vaddr_to_file_offset(
    segments: Sequence[LoadSegment], virtual_address: int, size: int = 1
) -> int:
    if size < 0:
        raise ValueError("negative virtual-address read size")
    for segment in segments:
        start = segment.virtual_address
        end = start + segment.file_size
        if start <= virtual_address and virtual_address + size <= end:
            return segment.file_offset + virtual_address - start
    raise ValueError(
        f"virtual range 0x{virtual_address:x}+0x{size:x} is not file-backed"
    )


def file_offset_to_vaddr(
    segments: Sequence[LoadSegment], file_offset: int, size: int = 1
) -> int:
    for segment in segments:
        start = segment.file_offset
        end = start + segment.file_size
        if start <= file_offset and file_offset + size <= end:
            return segment.virtual_address + file_offset - start
    raise ValueError(f"file range 0x{file_offset:x}+0x{size:x} is not a load segment")


def read_vaddr(
    data: bytes,
    segments: Sequence[LoadSegment],
    virtual_address: int,
    size: int,
) -> bytes:
    offset = vaddr_to_file_offset(segments, virtual_address, size)
    return data[offset : offset + size]


def read_u32_vaddr(
    data: bytes, segments: Sequence[LoadSegment], virtual_address: int
) -> int:
    return struct.unpack("<I", read_vaddr(data, segments, virtual_address, 4))[0]


def read_u64_vaddr(
    data: bytes, segments: Sequence[LoadSegment], virtual_address: int
) -> int:
    return struct.unpack("<Q", read_vaddr(data, segments, virtual_address, 8))[0]


def read_c_string_vaddr(
    data: bytes,
    segments: Sequence[LoadSegment],
    virtual_address: int,
    maximum: int = 256,
) -> str:
    offset = vaddr_to_file_offset(segments, virtual_address, 1)
    end = data.find(b"\0", offset, min(len(data), offset + maximum))
    if end < 0:
        raise ValueError(f"unterminated string at virtual address 0x{virtual_address:x}")
    return data[offset:end].decode("ascii", errors="strict")


def unique_bytes_offset(data: bytes, needle: bytes) -> int:
    first = data.find(needle)
    if first < 0:
        raise ValueError(f"required byte sequence is absent: {needle!r}")
    if data.find(needle, first + 1) >= 0:
        raise ValueError(f"required byte sequence is not unique: {needle!r}")
    return first


def all_bytes_offsets(data: bytes, needle: bytes) -> list[int]:
    result = []
    cursor = 0
    while True:
        offset = data.find(needle, cursor)
        if offset < 0:
            return result
        result.append(offset)
        cursor = offset + 1


def djb2(text: str) -> int:
    value = 5381
    for byte in text.encode("ascii"):
        value = ((value * 33) + byte) & 0xFFFFFFFF
    return value


def parse_cfgl(data: bytes) -> dict[str, object]:
    base = unique_bytes_offset(data, CFGL_MAGIC)
    if base + CFGL_HEADER_SIZE > len(data):
        raise ValueError("truncated CFGL header")
    major, minor, entry_count = struct.unpack_from("<BBH", data, base + 4)
    payload_offset = struct.unpack_from("<I", data, base + 8)[0]
    if entry_count == 0 or payload_offset < CFGL_HEADER_SIZE:
        raise ValueError("invalid CFGL entry count or payload offset")
    if base + payload_offset > len(data):
        raise ValueError("CFGL payload offset exceeds input")

    entries: list[CfglEntry] = []
    for index in range(entry_count):
        descriptor = base + CFGL_HEADER_SIZE + index * CFGL_ENTRY_STRIDE
        if descriptor + 12 > base + payload_offset:
            raise ValueError(f"CFGL descriptor {index} is truncated")
        relative_offset, data_size, name_size = struct.unpack_from(
            "<III", data, descriptor
        )
        name_start = descriptor + 12
        name_end = name_start + name_size
        if name_end > base + payload_offset:
            raise ValueError(f"CFGL descriptor {index} name exceeds table")
        if name_end >= len(data) or data[name_end] != 0:
            raise ValueError(f"CFGL descriptor {index} name is not NUL terminated")
        name = data[name_start:name_end].decode("ascii", errors="strict")
        data_offset = base + relative_offset
        if relative_offset < payload_offset or data_offset + data_size > len(data):
            raise ValueError(f"CFGL descriptor {index} payload is out of range")
        entries.append(
            CfglEntry(
                index=index,
                descriptor_file_offset=descriptor,
                relative_data_offset=relative_offset,
                data_file_offset=data_offset,
                data_size=data_size,
                name=name,
            )
        )

    return {
        "file_offset": base,
        "major": major,
        "minor": minor,
        "entry_count": entry_count,
        "payload_offset": payload_offset,
        "entries": entries,
    }


def inventory_dcb_descriptors(xbl_config_data: bytes) -> dict[str, object]:
    cfgl = parse_cfgl(xbl_config_data)
    records: list[dict[str, object]] = []
    for entry in cfgl["entries"]:
        assert isinstance(entry, CfglEntry)
        match = DCB_NAME_RE.fullmatch(entry.name)
        if match is None:
            continue
        block = xbl_config_data[
            entry.data_file_offset : entry.data_file_offset + entry.data_size
        ]
        parsed = parse_dcb(block)
        section16 = next(
            item for item in parsed["sections"] if item["index"] == 16
        )
        records.append(
            {
                "name": entry.name,
                "selector": {
                    "hardware_id": f"0x{int(match.group('hardware_id'), 16):04x}",
                    "hardware_version": (
                        f"0x{int(match.group('hardware_version'), 16):04x}"
                    ),
                    "physical_platform": int(match.group("physical_platform")),
                },
                "descriptor": asdict(entry),
                "dcb_sha256": parsed["sha256"],
                "used_size": parsed["used_size"],
                "dsf_version": parsed["dsf_version"],
                "section16": {
                    "size": section16["size"],
                    "sha256": section16["sha256"],
                    "destination": f"0x{SHRM_SECTION16_DESTINATION:08x}",
                },
            }
        )
    if len(records) != 4:
        raise ValueError(f"expected four named DCB records, found {len(records)}")
    return {
        "cfgl": {
            key: value
            for key, value in cfgl.items()
            if key != "entries"
        },
        "entries": records,
    }


def parse_remapper_table(
    data: bytes, segments: Sequence[LoadSegment]
) -> list[dict[str, object]]:
    raw = read_vaddr(
        data,
        segments,
        REMAPPER_TABLE_VADDR,
        REMAPPER_TABLE_COUNT * REMAPPER_ENTRY_SIZE,
    )
    records = []
    for index in range(REMAPPER_TABLE_COUNT):
        channel_rank_mask, total_mib, region0, region1 = struct.unpack_from(
            "<QQQQ", raw, index * REMAPPER_ENTRY_SIZE
        )
        if channel_rank_mask == 0 or total_mib == 0:
            raise ValueError(f"remapper table entry {index} is empty")
        records.append(
            {
                "index": index,
                "channel_rank_mask": f"0x{channel_rank_mask:x}",
                "total_mib": total_mib,
                "total_bytes": total_mib << 20,
                "region0_base": f"0x{region0:x}",
                "region1_base": f"0x{region1:x}",
            }
        )
    return records


def layout1_register_offsets(mapping_slot_count: int) -> list[int]:
    if mapping_slot_count < 1:
        raise ValueError("mapping slot count must be positive")
    offsets = {0, 4, 8}
    for slot in range(1, mapping_slot_count):
        base = (slot - 1) * 0x10
        offsets.update({base + 0x0C, base + 0x10, base + 0x14, base + 0x18})
    return sorted(offsets)


def parse_icb_property(
    data: bytes, segments: Sequence[LoadSegment]
) -> dict[str, object]:
    source = read_vaddr(data, segments, ICB_PROPERTY_SOURCE_VADDR, 0x20)
    propbin_vaddr, struct_table_vaddr = struct.unpack_from("<QQ", source, 0)
    device_count = struct.unpack_from("<I", source, 0x10)[0]
    device_table_vaddr = struct.unpack_from("<Q", source, 0x18)[0]

    path_file_offset = unique_bytes_offset(data, ICB_PROPERTY_PATH.encode() + b"\0")
    path_vaddr = file_offset_to_vaddr(
        segments, path_file_offset, len(ICB_PROPERTY_PATH) + 1
    )
    expected_hash = djb2(ICB_PROPERTY_PATH)

    matching_entry: dict[str, int] | None = None
    for index in range(device_count):
        entry_vaddr = device_table_vaddr + index * ICB_DEVICE_ENTRY_SIZE
        entry = read_vaddr(data, segments, entry_vaddr, ICB_DEVICE_ENTRY_SIZE)
        name_pointer = struct.unpack_from("<Q", entry, 0)[0]
        name_hash, property_offset = struct.unpack_from("<II", entry, 8)
        if name_pointer == path_vaddr and name_hash == expected_hash:
            matching_entry = {
                "index": index,
                "virtual_address": entry_vaddr,
                "property_offset": property_offset,
            }
            break
    if matching_entry is None:
        raise ValueError("ICB DAL device entry was not found")

    property_vaddr = propbin_vaddr + matching_entry["property_offset"]
    property_header, struct_index = struct.unpack(
        "<II", read_vaddr(data, segments, property_vaddr, 8)
    )
    property_type = property_header >> 24
    name_offset = property_header & 0x003FFFFF
    string_table_offset = read_u32_vaddr(data, segments, propbin_vaddr + 4)
    property_name = read_c_string_vaddr(
        data, segments, propbin_vaddr + string_table_offset + name_offset
    )
    if property_type != ICB_STRUCT_POINTER_TYPE:
        raise ValueError(f"ICB property type is 0x{property_type:x}, expected 0x12")
    if property_name != ICB_PROPERTY_NAME:
        raise ValueError(f"unexpected ICB property name {property_name!r}")

    struct_entry_vaddr = struct_table_vaddr + struct_index * 0x10
    struct_size = read_u32_vaddr(data, segments, struct_entry_vaddr)
    root_vaddr = read_u64_vaddr(data, segments, struct_entry_vaddr + 8)
    root_count = read_u32_vaddr(data, segments, root_vaddr)
    record_pointer_table = read_u64_vaddr(data, segments, root_vaddr + 8)
    if root_count == 0:
        raise ValueError("ICB property contains no chip records")

    records = []
    for index in range(root_count):
        record_vaddr = read_u64_vaddr(
            data, segments, record_pointer_table + index * 8
        )
        record = read_vaddr(data, segments, record_vaddr, 0x50)
        family_id = struct.unpack_from("<I", record, 0)[0]
        version_policy = record[4]
        version_value = struct.unpack_from("<I", record, 8)[0]
        mapping_slot_count, channel_instance_count = struct.unpack_from(
            "<II", record, 0x18
        )
        table_entry_count, register_layout = struct.unpack_from("<II", record, 0x20)
        register_base_table = struct.unpack_from("<Q", record, 0x28)[0]
        auxiliary_table = struct.unpack_from("<Q", record, 0x30)[0]
        interval_table = struct.unpack_from("<Q", record, 0x38)[0]
        selector_mask_pointer = struct.unpack_from("<Q", record, 0x40)[0]
        selector_mask, selector_value = struct.unpack_from("<II", record, 0x48)
        register_bases = [
            read_u64_vaddr(data, segments, register_base_table + item * 8)
            for item in range(channel_instance_count)
        ]
        offsets = (
            layout1_register_offsets(mapping_slot_count)
            if register_layout == ICB_SELECTED_LAYOUT
            else []
        )
        records.append(
            {
                "index": index,
                "virtual_address": f"0x{record_vaddr:x}",
                "selector": {
                    "chip_family_id": f"0x{family_id:x}",
                    "version_policy_byte": version_policy,
                    "version_value": f"0x{version_value:x}",
                    "optional_mask_pointer": f"0x{selector_mask_pointer:x}",
                    "optional_mask": f"0x{selector_mask:x}",
                    "optional_value": f"0x{selector_value:x}",
                },
                "mapping_slot_count": mapping_slot_count,
                "channel_instance_count": channel_instance_count,
                "table_entry_count": table_entry_count,
                "register_layout": register_layout,
                "register_base_table": f"0x{register_base_table:x}",
                "auxiliary_table": f"0x{auxiliary_table:x}",
                "interval_table": f"0x{interval_table:x}",
                "register_bases": [
                    {
                        "address": f"0x{base:08x}",
                        "qhs_llcc_window": f"0x{base & ~0xFFFF:08x}",
                        "window_offset": f"0x{base & 0xFFFF:x}",
                    }
                    for base in register_bases
                ],
                "layout1_touched_offsets": [f"0x{offset:x}" for offset in offsets],
                "layout1_max_touched_offset": (
                    f"0x{max(offsets):x}" if offsets else None
                ),
            }
        )

    return {
        "dal_property_source": {
            "virtual_address": f"0x{ICB_PROPERTY_SOURCE_VADDR:x}",
            "property_binary": f"0x{propbin_vaddr:x}",
            "structure_pointer_table": f"0x{struct_table_vaddr:x}",
            "device_count": device_count,
            "device_table": f"0x{device_table_vaddr:x}",
        },
        "device": {
            "path": ICB_PROPERTY_PATH,
            "path_virtual_address": f"0x{path_vaddr:x}",
            "djb2_hash": f"0x{expected_hash:08x}",
            "entry_index": matching_entry["index"],
            "entry_virtual_address": f"0x{matching_entry['virtual_address']:x}",
            "property_offset": f"0x{matching_entry['property_offset']:x}",
        },
        "property": {
            "name": property_name,
            "type": f"0x{property_type:x}",
            "structure_index": struct_index,
            "structure_size_field": struct_size,
            "root_virtual_address": f"0x{root_vaddr:x}",
            "record_count": root_count,
            "record_pointer_table": f"0x{record_pointer_table:x}",
        },
        "records": records,
    }


def parse_tz_icb_crosscheck(
    data: bytes, segments: Sequence[LoadSegment]
) -> dict[str, object]:
    path_file_offset = unique_bytes_offset(data, ICB_PROPERTY_PATH.encode() + b"\0")
    path_vaddr = file_offset_to_vaddr(
        segments, path_file_offset, len(ICB_PROPERTY_PATH) + 1
    )
    device_prefix = struct.pack("<QI", path_vaddr, djb2(ICB_PROPERTY_PATH))
    device_file_offset = unique_bytes_offset(data, device_prefix)
    device_vaddr = file_offset_to_vaddr(segments, device_file_offset, 16)
    property_offset = struct.unpack_from("<I", data, device_file_offset + 12)[0]

    expected_bases = (0x09248080, 0x092C8080, 0x09348080, 0x093C8080)
    base_pattern = struct.pack("<QQQQ", *expected_bases)
    base_file_offset = unique_bytes_offset(data, base_pattern)
    base_table_vaddr = file_offset_to_vaddr(segments, base_file_offset, len(base_pattern))
    record_candidates = []
    for pointer_file_offset in all_bytes_offsets(data, struct.pack("<Q", base_table_vaddr)):
        candidate = pointer_file_offset - 0x28
        if candidate < 0 or candidate + 0x50 > len(data):
            continue
        record = data[candidate : candidate + 0x50]
        if struct.unpack_from("<I", record, 0)[0] != 0x56:
            continue
        if struct.unpack_from("<II", record, 0x18) != (6, 4):
            continue
        if struct.unpack_from("<II", record, 0x20) != (36, 1):
            continue
        record_candidates.append(candidate)
    if len(record_candidates) != 1:
        raise ValueError(
            f"expected one TrustZone ICB record, found {len(record_candidates)}"
        )
    record_file_offset = record_candidates[0]
    record_vaddr = file_offset_to_vaddr(segments, record_file_offset, 0x50)
    record = data[record_file_offset : record_file_offset + 0x50]
    family_id = struct.unpack_from("<I", record, 0)[0]
    version_value = struct.unpack_from("<I", record, 8)[0]
    mapping_slot_count, channel_instance_count = struct.unpack_from(
        "<II", record, 0x18
    )
    table_entry_count, register_layout = struct.unpack_from("<II", record, 0x20)
    if channel_instance_count != len(expected_bases) or register_layout != 1:
        raise ValueError("TrustZone ICB record has an unexpected layout")

    return {
        "device_path": ICB_PROPERTY_PATH,
        "device_path_virtual_address": f"0x{path_vaddr:x}",
        "device_entry_virtual_address": f"0x{device_vaddr:x}",
        "device_hash": f"0x{djb2(ICB_PROPERTY_PATH):08x}",
        "property_offset": f"0x{property_offset:x}",
        "record_virtual_address": f"0x{record_vaddr:x}",
        "chip_family_id": f"0x{family_id:x}",
        "version_value": f"0x{version_value:x}",
        "mapping_slot_count": mapping_slot_count,
        "channel_instance_count": channel_instance_count,
        "table_entry_count": table_entry_count,
        "register_layout": register_layout,
        "register_base_table": f"0x{base_table_vaddr:x}",
        "register_bases": [f"0x{base:08x}" for base in expected_bases],
        "claim_boundary": (
            "PROVED the separate TrustZone ELF carries the same icbcfg device "
            "identity and four-base record; UNKNOWN whether secure-world runtime "
            "invokes it or locks the registers"
        ),
    }


def inventory(
    xbl_path: Path, xbl_config_path: Path, tz_path: Path | None = None
) -> dict[str, object]:
    xbl_data = xbl_path.read_bytes()
    xbl_config_data = xbl_config_path.read_bytes()
    segments = parse_elf64_load_segments(xbl_data)
    dcb = inventory_dcb_descriptors(xbl_config_data)

    shrm_blobs = []
    for item in SHRM_BLOBS:
        blob = read_vaddr(
            xbl_data, segments, int(item["virtual_address"]), int(item["size"])
        )
        shrm_blobs.append(
            {
                "name": item["name"],
                "virtual_address": f"0x{int(item['virtual_address']):x}",
                "size": f"0x{int(item['size']):x}",
                "copy_function": f"0x{int(item['copy_function']):x}",
                "first_destination": f"0x{int(item['first_destination']):08x}",
                "size_decimal": len(blob),
                "sha256": sha256(blob),
            }
        )

    remapper = parse_remapper_table(xbl_data, segments)
    icb = parse_icb_property(xbl_data, segments)
    tz_crosscheck = None
    tz_input = None
    if tz_path is not None:
        tz_data = tz_path.read_bytes()
        tz_segments = parse_elf64_load_segments(tz_data)
        tz_crosscheck = parse_tz_icb_crosscheck(tz_data, tz_segments)
        tz_input = {
            "filename": tz_path.name,
            "size": len(tz_data),
            "sha256": sha256(tz_data),
        }

    return {
        "schema": "sdm855-xbl-memory-pipeline-inventory-v1",
        "inputs": {
            "xbl": {
                "filename": xbl_path.name,
                "size": len(xbl_data),
                "sha256": sha256(xbl_data),
            },
            "xbl_config": {
                "filename": xbl_config_path.name,
                "size": len(xbl_config_data),
                "sha256": sha256(xbl_config_data),
            },
            "trustzone": tz_input,
        },
        "dcb_selector": {
            "format": DCB_SELECTOR_FORMAT,
            "hardware_register": f"0x{SOC_HW_VERSION_REGISTER:08x}",
            "hardware_id_expression": "register[31:16]",
            "hardware_version_expression": "register[15:0] & 0xff00",
            "physical_platform_expression": (
                f"1 when platform_type != 0x{PHYSICAL_PLATFORM_RUMI_VALUE:x}; "
                "otherwise 0"
            ),
            "xbl_code_anchors": {
                "soc_register_read_and_state_store": "0x14839d74",
                "platform_selector": "0x14839cb4",
                "dcb_filename_and_load": "0x1489f97c",
            },
            "config": dcb,
        },
        "shrm": {
            "csr_base": f"0x{SHRM_CSR_BASE:08x}",
            "memory_base": f"0x{SHRM_MEMORY_BASE:08x}",
            "mpu_base": f"0x{SHRM_MPU_BASE:08x}",
            "section16_destination": f"0x{SHRM_SECTION16_DESTINATION:08x}",
            "section16_offset_in_shrm_memory": (
                f"0x{SHRM_SECTION16_DESTINATION - SHRM_MEMORY_BASE:x}"
            ),
            "clear_function": "0x148aedbc",
            "load_both_blobs_function": "0x148aeddc",
            "blobs": shrm_blobs,
            "instruction_set": "UNKNOWN",
        },
        "ddr_remapper": {
            "function": "0x1483a6dc",
            "error_string_virtual_address": "0x14820840",
            "table_virtual_address": f"0x{REMAPPER_TABLE_VADDR:x}",
            "entry_size": REMAPPER_ENTRY_SIZE,
            "entries": remapper,
            "icb_set_region_function": "0x14850694",
            "icb_property": icb,
            "trustzone_crosscheck": tz_crosscheck,
        },
        "claims": {
            "PROVED": [
                "CFGL binds the four DCB payloads to their exact selector filenames.",
                "XBL derives the first two selector fields from 0x01fc8000 and the final bit from platform type.",
                "DCB section 16 is copied into qhs_shrm_mem at 0x09065100.",
                "XBL installs embedded SHRM data and instruction blobs before using the DDR remapper.",
                "The remapper selects a topology row and programs four qhs_llcc windows through /dev/icbcfg/boot.",
                "The sole DAL chip record exposes register bases 0x09248080, 0x092c8080, 0x09348080 and 0x093c8080.",
                "The separate live TrustZone ELF carries the same icbcfg device identity and four-base register record.",
            ],
            "SUPPORTED": [
                "The four qhs_llcc register windows implement system-PA region placement/remapping used during DDR bring-up."
            ],
            "UNKNOWN": [
                "Which DCB was selected on the live handset until read-only SoC identity is captured.",
                "Whether section 16 or SHRM implements final channel/bank/row hashing rather than only training/control.",
                "Post-boot EL1 readability, writability, lock state and security-enforcement ordering of these registers.",
                "Whether TrustZone invokes its matching icbcfg record or locks the register windows at runtime.",
                "Any normal-RAM or protected-memory alias.",
            ],
        },
    }


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    private = root / "evidence/private/004-live-firmware-readonly-20260825-01"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xbl", type=Path, default=private / "xbl--sdb1.bin")
    parser.add_argument(
        "--xbl-config", type=Path, default=private / "xbl_config--sdb2.bin"
    )
    parser.add_argument("--tz", type=Path, default=private / "tz--sdd5.bin")
    parser.add_argument(
        "--output",
        type=Path,
        default=root / "evidence/manifests/006-xbl-memory-pipeline-inventory.json",
    )
    parser.add_argument(
        "--replace",
        action="store_true",
        help="replace an existing generated manifest atomically",
    )
    return parser


def atomic_replace(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists():
        raise FileExistsError(temporary)
    write_new(temporary, data, 0o644)
    os.replace(temporary, path)


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = inventory(args.xbl.resolve(), args.xbl_config.resolve(), args.tz.resolve())
    output = args.output.resolve()
    encoded = json_bytes(result)
    if args.replace:
        atomic_replace(output, encoded)
    else:
        write_new(output, encoded, 0o644)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
